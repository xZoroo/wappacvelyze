package cve

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xZoroo/wappacvelyze/db"
)

type fakePublisher struct {
	blob     []byte
	manifest db.Manifest
	requests map[string]int
	broken   bool
}

func newFakePublisher(t *testing.T, built string) *fakePublisher {
	t.Helper()
	database := db.Database{Schema: db.SchemaVersion, Products: map[string]*db.Product{"f5:nginx": {}}, Sources: map[string]string{"built": built}}
	payload, _ := json.Marshal(database)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(payload)
	_ = zw.Close()
	p := &fakePublisher{blob: buf.Bytes(), requests: map[string]int{}}
	p.manifest = db.Manifest{Schema: db.SchemaVersion, Built: time.Now(), Path: "wappacvelyze-db.json.gz", SHA256: digest(p.blob), Bytes: int64(buf.Len())}
	return p
}

func (p *fakePublisher) serve(w http.ResponseWriter, r *http.Request) {
	p.requests[r.URL.Path]++
	if p.broken {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	switch r.URL.Path {
	case "/db/latest.json":
		_ = json.NewEncoder(w).Encode(p.manifest)
	case "/db/wappacvelyze-db.json.gz":
		_, _ = w.Write(p.blob)
	default:
		http.NotFound(w, r)
	}
}

func TestLoadDatabaseCachesByChecksum(t *testing.T) {
	publisher := newFakePublisher(t, "v1")
	srv := httptest.NewServer(http.HandlerFunc(publisher.serve))
	defer srv.Close()
	dir := t.TempDir()
	ctx := context.Background()
	base := srv.URL + "/db/"

	first, err := LoadDatabase(ctx, srv.Client(), base, dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if first.Products["f5:nginx"] == nil || first.Sources["built"] != "v1" {
		t.Fatalf("database = %+v", first)
	}
	if _, err := LoadDatabase(ctx, srv.Client(), base, dir, time.Hour); err != nil {
		t.Fatal(err)
	}
	if publisher.requests["/db/latest.json"] != 1 {
		t.Errorf("manifest fetched %d times within maxAge, want 1", publisher.requests["/db/latest.json"])
	}

	if _, err := LoadDatabase(ctx, srv.Client(), base, dir, 0); err != nil {
		t.Fatal(err)
	}
	if publisher.requests["/db/latest.json"] != 2 || publisher.requests["/db/wappacvelyze-db.json.gz"] != 1 {
		t.Errorf("unchanged checksum should not re-download: %v", publisher.requests)
	}

	*publisher = *newFakePublisher(t, "v2")
	second, err := LoadDatabase(ctx, srv.Client(), base, dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sources["built"] != "v2" || publisher.requests["/db/wappacvelyze-db.json.gz"] != 1 {
		t.Errorf("new checksum should re-download once: %v, %v", second.Sources, publisher.requests)
	}
}

func TestLoadDatabaseFallsBackToStaleCopy(t *testing.T) {
	publisher := newFakePublisher(t, "v1")
	srv := httptest.NewServer(http.HandlerFunc(publisher.serve))
	defer srv.Close()
	dir := t.TempDir()
	base := srv.URL + "/db/"
	if _, err := LoadDatabase(context.Background(), srv.Client(), base, dir, 0); err != nil {
		t.Fatal(err)
	}
	publisher.broken = true
	database, err := LoadDatabase(context.Background(), srv.Client(), base, dir, 0)
	if err == nil || database == nil || !strings.Contains(err.Error(), "using database built") {
		t.Fatalf("stale fallback: db=%v err=%v", database != nil, err)
	}
	if _, err := LoadDatabase(context.Background(), srv.Client(), base, t.TempDir(), 0); err == nil {
		t.Error("expected an error without any cached copy")
	}
}

func TestLoadDatabaseRejectsBadChecksumAndSchema(t *testing.T) {
	publisher := newFakePublisher(t, "v1")
	publisher.manifest.SHA256 = strings.Repeat("0", 64)
	srv := httptest.NewServer(http.HandlerFunc(publisher.serve))
	defer srv.Close()
	base := srv.URL + "/db/"
	if _, err := LoadDatabase(context.Background(), srv.Client(), base, t.TempDir(), 0); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("checksum mismatch: %v", err)
	}
	publisher.manifest = newFakePublisher(t, "v1").manifest
	publisher.manifest.Schema = db.SchemaVersion + 1
	if _, err := LoadDatabase(context.Background(), srv.Client(), base, t.TempDir(), 0); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Errorf("schema mismatch: %v", err)
	}
}

func TestReadDatabaseDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, databaseBlobFile)
	if err := os.WriteFile(path, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDatabase(path, digest([]byte("other"))); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("err = %v", err)
	}
	_ = fmt.Sprint
}
