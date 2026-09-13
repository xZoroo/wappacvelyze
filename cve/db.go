package cve

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/xZoroo/wappacvelyze/db"
)

// DefaultDatabaseURL is where the scheduled build publishes latest.json and the database.
const DefaultDatabaseURL = "https://github.com/xZoroo/wappacvelyze/releases/download/db/"

const (
	databaseManifestFile = "db-manifest.json"
	databaseBlobFile     = "wappacvelyze-db.json.gz"
	maxDatabaseBytes     = 256 << 20
)

// LoadDatabase returns the prebuilt database, refreshing the copy cached in cacheDir when it
// is older than maxAge and the published checksum changed. When a refresh fails but a cached
// copy exists, the stale copy is returned together with the error so callers can warn.
func LoadDatabase(
	ctx context.Context, client *http.Client, baseURL, cacheDir string, maxAge time.Duration,
) (*db.Database, error) {
	manifestPath := filepath.Join(cacheDir, databaseManifestFile)
	blobPath := filepath.Join(cacheDir, databaseBlobFile)
	cached, age, cacheErr := readManifest(manifestPath)
	if cacheErr == nil && age <= maxAge {
		return readDatabase(blobPath, cached.SHA256)
	}
	fresh, err := fetchManifest(ctx, client, baseURL)
	if err != nil {
		return staleDatabase(blobPath, cached, err)
	}
	if cached == nil || cached.SHA256 != fresh.SHA256 {
		if err := downloadDatabase(ctx, client, baseURL+fresh.Path, blobPath, fresh.SHA256); err != nil {
			return staleDatabase(blobPath, cached, err)
		}
	}
	encoded, err := json.Marshal(fresh)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(manifestPath, encoded); err != nil {
		return nil, fmt.Errorf("write database manifest: %w", err)
	}
	return readDatabase(blobPath, fresh.SHA256)
}

func staleDatabase(blobPath string, cached *db.Manifest, cause error) (*db.Database, error) {
	if cached == nil {
		return nil, cause
	}
	database, err := readDatabase(blobPath, cached.SHA256)
	if err != nil {
		return nil, cause
	}
	return database, fmt.Errorf("%w (using database built %s)", cause, cached.Built.Format("2006-01-02"))
}

func readManifest(path string) (*db.Manifest, time.Duration, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var manifest db.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, 0, fmt.Errorf("decode database manifest %s: %w", path, err)
	}
	return &manifest, time.Since(info.ModTime()), nil
}

func fetchManifest(ctx context.Context, client *http.Client, baseURL string) (*db.Manifest, error) {
	body, err := get(ctx, client, baseURL+"latest.json")
	if err != nil {
		return nil, err
	}
	var manifest db.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("decode database manifest: %w", err)
	}
	if manifest.Schema != db.SchemaVersion {
		return nil, fmt.Errorf("database schema %d is not supported by this build (want %d); update wappacvelyze",
			manifest.Schema, db.SchemaVersion)
	}
	return &manifest, nil
}

func downloadDatabase(ctx context.Context, client *http.Client, url, path, sha string) error {
	body, err := get(ctx, client, url)
	if err != nil {
		return err
	}
	if got := digest(body); got != sha {
		return fmt.Errorf("database checksum mismatch: manifest %s, downloaded %s", sha, got)
	}
	if err := writeFileAtomic(path, body); err != nil {
		return fmt.Errorf("write database: %w", err)
	}
	return nil
}

// readDatabase decodes the cached blob after verifying it still matches its manifest.
func readDatabase(path, sha string) (*db.Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read database: %w", err)
	}
	if got := digest(data); got != sha {
		return nil, errors.New("cached database does not match its manifest; run `wappacvelyze cache refresh`")
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decompress database: %w", err)
	}
	var database db.Database
	if err := json.NewDecoder(zr).Decode(&database); err != nil {
		return nil, fmt.Errorf("decode database: %w", err)
	}
	return &database, nil
}

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDatabaseBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	return body, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
