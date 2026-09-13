// Command wappacvelyze-db builds the prebuilt vulnerability database: NVD records scoped to
// the products the fingerprint database can detect, enriched with CISA KEV, FIRST EPSS,
// exploit availability from Nuclei and Metasploit, release cycles from endoflife.date and
// JavaScript-library advisories from Retire.js.
package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/xZoroo/wappacvelyze/db"
)

const databaseFile = "wappacvelyze-db.json.gz"

func main() {
	out := flag.String("out", "dist/db", "directory to write latest.json and the database into")
	firstYear := flag.Int("first-year", DefaultSources().FirstYear, "earliest NVD feed year to ingest")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	sources := DefaultSources()
	sources.FirstYear = *firstYear
	if err := run(ctx, sources, *out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, sources Sources, out string) error {
	technologies, err := fingerprintProducts()
	if err != nil {
		return err
	}
	database := newDatabase(technologies)
	f := fetcher{client: &http.Client{Timeout: 10 * time.Minute}}
	if err := build(ctx, f, sources, database, technologyNames(technologies)); err != nil {
		return err
	}
	return write(database, out)
}

// fingerprintProducts maps each CPE-bearing technology name to its "vendor:product" key.
func fingerprintProducts() (map[string]string, error) {
	var raw struct {
		Apps map[string]struct {
			CPE string `json:"cpe"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(wappalyzer.GetRawFingerprints()), &raw); err != nil {
		return nil, fmt.Errorf("parse fingerprints: %w", err)
	}
	products := make(map[string]string, len(raw.Apps))
	for name, app := range raw.Apps {
		if key, _ := productKey(app.CPE); app.CPE != "" && key != "" {
			products[name] = key
		}
	}
	return products, nil
}

func technologyNames(products map[string]string) []string {
	names := make([]string, 0, len(products))
	for name := range products {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func newDatabase(technologies map[string]string) *db.Database {
	database := &db.Database{
		Schema:              db.SchemaVersion,
		Built:               time.Now().UTC().Truncate(time.Second),
		Sources:             map[string]string{},
		Products:            map[string]*db.Product{},
		Vulnerabilities:     map[string]*db.Vulnerability{},
		Libraries:           map[string]*db.Library{},
		TechnologyLibraries: map[string]string{},
	}
	for _, key := range technologies {
		database.Products[key] = &db.Product{Matches: map[string][]db.Match{}}
	}
	return database
}

func build(ctx context.Context, f fetcher, sources Sources, database *db.Database, technologies []string) error {
	kept := 0
	for year := sources.FirstYear; year <= sources.LastYear; year++ {
		n, err := ingestNVDFeed(ctx, f, fmt.Sprintf(sources.NVDFeed, year), database)
		if err != nil {
			return err
		}
		kept += n
		fmt.Fprintf(os.Stderr, "nvd %d: kept %d records\n", year, n)
	}
	database.Sources["nvd"] = fmt.Sprintf("feeds %d-%d, %d records", sources.FirstYear, sources.LastYear, kept)

	kev, err := ingestKEV(ctx, f, sources.KEV, database)
	if err != nil {
		return err
	}
	database.Sources["kev"] = kev
	epss, err := ingestEPSS(ctx, f, sources.EPSS, database)
	if err != nil {
		return err
	}
	database.Sources["epss"] = epss
	if err := ingestNuclei(ctx, f, sources.Nuclei, database); err != nil {
		return err
	}
	if err := ingestMetasploit(ctx, f, sources.Metasploit, database); err != nil {
		return err
	}
	database.Sources["exploits"] = "nuclei-templates, metasploit-framework"
	eol, err := ingestEndOfLife(ctx, f, sources.EndOfLife, database)
	if err != nil {
		return err
	}
	database.Sources["endoflife"] = eol
	if err := ingestRetire(ctx, f, sources.Retire, database, technologies); err != nil {
		return err
	}
	database.Sources["retirejs"] = "jsrepository-v4"
	return nil
}

// write stores the gzipped database and a manifest that names and checksums it.
func write(database *db.Database, out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(database)
	if err != nil {
		return fmt.Errorf("encode database: %w", err)
	}
	file, err := os.Create(filepath.Join(out, databaseFile))
	if err != nil {
		return err
	}
	digest := sha256.New()
	zw, err := gzip.NewWriterLevel(io2{file, digest}, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(payload); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	info, err := os.Stat(filepath.Join(out, databaseFile))
	if err != nil {
		return err
	}
	manifest := db.Manifest{
		Schema: db.SchemaVersion, Built: database.Built, Path: databaseFile,
		SHA256: hex.EncodeToString(digest.Sum(nil)), Bytes: info.Size(),
		Counts: db.Counts{
			Products: len(database.Products), Vulnerabilities: len(database.Vulnerabilities),
			Libraries: len(database.Libraries),
		},
		Sources: database.Sources,
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "latest.json"), append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes, %d products, %d vulnerabilities, %d libraries)\n",
		databaseFile, info.Size(), manifest.Counts.Products, manifest.Counts.Vulnerabilities,
		manifest.Counts.Libraries)
	return nil
}
