package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xZoroo/wappacvelyze/db"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const nvdFeed = `{"resultsPerPage":3,"format":"NVD_CVE","vulnerabilities":[
 {"cve":{"id":"CVE-2021-23017","published":"2021-05-25T13:15:00.000",
   "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.7,"baseSeverity":"HIGH"}}]},
   "references":[{"url":"https://nginx.org/advisory","tags":["Vendor Advisory"]}],
   "configurations":[{"nodes":[{"cpeMatch":[
     {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionStartIncluding":"0.6.18","versionEndExcluding":"1.20.1"},
     {"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}]}},
 {"cve":{"id":"CVE-2009-9999","configurations":[{"nodes":[{"cpeMatch":[
     {"vulnerable":true,"criteria":"cpe:2.3:a:php:php:5.2.0:*:*:*:*:*:*:*"}]}]}]}},
 {"cve":{"id":"CVE-2020-0001","configurations":[{"nodes":[{"cpeMatch":[
     {"vulnerable":true,"criteria":"cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"}]}]}]}}
]}`

const kevFeed = `{"catalogVersion":"2026.09.11","vulnerabilities":[{"cveID":"cve-2021-23017","vulnerabilityName":"nginx off-by-one","dateAdded":"2021-11-03","dueDate":"2022-05-03","requiredAction":"Apply updates","knownRansomwareCampaignUse":"Unknown"}]}`

const epssCSV = "#model_version:v2026.06.15,score_date:2026-09-12T12:00:22Z\ncve,epss,percentile\nCVE-2021-23017,0.91234,0.99\nCVE-2009-9999,0.001,0.1\n"

const nucleiFeed = "{\"ID\":\"CVE-2021-23017\",\"Info\":{\"Name\":\"x\"}}\n{\"ID\":\"CVE-2020-0001\"}\n"

const msfFeed = `{"exploit/x":{"references":["CVE-2021-23017","OSVDB-1"]},"exploit/y":{"references":["CVE-2009-9999"]}}`

const eolFeed = `{"generated_at":"2026-09-12T00:00:00Z","result":[{"name":"nginx",
 "identifiers":[{"type":"purl","id":"pkg:generic/nginx"},{"type":"cpe","id":"cpe:2.3:a:f5:nginx"}],
 "releases":[{"name":"1.31","releaseDate":"2026-05-13","isLts":false,"isEol":false,"eolFrom":null,"isMaintained":true,"latest":{"name":"1.31.5","date":"2026-09-02"}},
             {"name":"1.20","releaseDate":"2021-04-20","isEol":true,"eolFrom":"2022-05-24","isMaintained":false,"latest":{"name":"1.20.2","date":"2021-11-16"}}]},
 {"name":"other","identifiers":[{"type":"cpe","id":"cpe:2.3:a:nobody:cares"}],"releases":[]}]}`

const retireFeed = `{"jquery":{"npmname":"jquery","bowername":["jquery","jQuery"],"vulnerabilities":[{"below":"1.6.3","severity":"medium","identifiers":{"summary":"XSS with location.hash","CVE":["CVE-2011-4969"],"githubID":"GHSA-579v-mp3v-rrw5"},"info":["https://nvd.nist.gov/vuln/detail/CVE-2011-4969"]}]},
 "angularjs":{"npmname":"angular","vulnerabilities":[{"below":"1.8.0","severity":"high","identifiers":{"CVE":["CVE-2020-7676"]}}]},
 "moment":{"npmname":"moment","vulnerabilities":[{"atOrAbove":"2.18.0","below":"2.29.4","severity":"high","identifiers":{"CVE":["CVE-2022-31129"]}}]},
 "empty":{"vulnerabilities":[]}}`

func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/nvd-2021.json.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz(t, nvdFeed)) })
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(kevFeed)) })
	mux.HandleFunc("/epss.csv.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz(t, epssCSV)) })
	mux.HandleFunc("/cves.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(nucleiFeed)) })
	mux.HandleFunc("/msf.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(msfFeed)) })
	mux.HandleFunc("/eol.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(eolFeed)) })
	mux.HandleFunc("/retire.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(retireFeed)) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestBuildScopesAndEnriches(t *testing.T) {
	srv := fixtureServer(t)
	sources := Sources{
		NVDFeed: srv.URL + "/nvd-%d.json.gz", KEV: srv.URL + "/kev.json", EPSS: srv.URL + "/epss.csv.gz",
		Nuclei: srv.URL + "/cves.json", Metasploit: srv.URL + "/msf.json", EndOfLife: srv.URL + "/eol.json",
		Retire: srv.URL + "/retire.json", FirstYear: 2021, LastYear: 2021,
	}
	technologies := map[string]string{
		"Nginx": "f5:nginx", "PHP": "php:php", "jQuery": "jquery:jquery", "Moment.js": "moment:moment",
		"Angular": "angular:angular", "jQuery UI": "jquery:jquery_ui",
	}
	database := newDatabase(technologies)
	f := fetcher{client: srv.Client()}
	if err := build(context.Background(), f, sources, database, technologyNames(technologies)); err != nil {
		t.Fatal(err)
	}

	nginx := database.Products["f5:nginx"]
	if got := nginx.Matches["CVE-2021-23017"]; len(got) != 1 || got[0].VersionEndExcluding != "1.20.1" || got[0].Version != "*" {
		t.Errorf("nginx matches = %+v", got)
	}
	if got := database.Products["php:php"].Matches["CVE-2009-9999"]; len(got) != 1 || got[0].Version != "5.2.0" {
		t.Errorf("php matches = %+v", got)
	}
	if _, ok := database.Vulnerabilities["CVE-2020-0001"]; ok {
		t.Error("CVE for an unknown product was kept")
	}
	v := database.Vulnerabilities["CVE-2021-23017"]
	if v.Score != 7.7 || v.Severity != "HIGH" || v.Advisory != "https://nginx.org/advisory" {
		t.Errorf("vulnerability = %+v", v)
	}
	if v.KEV == nil || v.KEV.DateAdded != "2021-11-03" {
		t.Errorf("KEV not joined: %+v", v.KEV)
	}
	if v.EPSS != 0.91234 || v.EPSSPct != 0.99 {
		t.Errorf("EPSS = %v/%v", v.EPSS, v.EPSSPct)
	}
	if len(v.Exploits) != 2 || v.Exploits[0] != "nuclei" || v.Exploits[1] != "metasploit" {
		t.Errorf("exploits = %v", v.Exploits)
	}
	if nginx.Lifecycle == nil || len(nginx.Lifecycle.Cycles) != 2 || nginx.Lifecycle.Cycles[0].Latest != "1.31.5" || !nginx.Lifecycle.Cycles[1].EOL {
		t.Errorf("lifecycle = %+v", nginx.Lifecycle)
	}
	if database.TechnologyLibraries["jQuery"] != "jquery" || database.TechnologyLibraries["Moment.js"] != "moment" {
		t.Errorf("technology libraries = %v", database.TechnologyLibraries)
	}
	if _, ok := database.TechnologyLibraries["Angular"]; ok {
		t.Error("Angular was mapped to a Retire.js library despite the override")
	}
	if lib := database.Libraries["jquery"]; lib == nil || lib.Vulnerabilities[0].GHSA != "GHSA-579v-mp3v-rrw5" || lib.Vulnerabilities[0].Severity != "MEDIUM" {
		t.Errorf("jquery library = %+v", lib)
	}
	if _, ok := database.Libraries["empty"]; ok {
		t.Error("library without vulnerabilities was kept")
	}
	if database.Sources["kev"] != "2026.09.11" || database.Sources["epss"] == "" || database.Sources["endoflife"] == "" {
		t.Errorf("sources = %v", database.Sources)
	}
}

func TestWriteProducesVerifiableManifest(t *testing.T) {
	database := newDatabase(map[string]string{"Nginx": "f5:nginx"})
	database.Vulnerabilities["CVE-1"] = &db.Vulnerability{ID: "CVE-1"}
	dir := t.TempDir()
	if err := write(database, dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest db.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, manifest.Path))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(blob)) != manifest.Bytes || manifest.Counts.Vulnerabilities != 1 || manifest.Schema != db.SchemaVersion {
		t.Errorf("manifest = %+v (blob %d bytes)", manifest, len(blob))
	}
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	var decoded db.Database
	if err := json.NewDecoder(zr).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Products["f5:nginx"] == nil || decoded.Vulnerabilities["CVE-1"] == nil {
		t.Errorf("decoded = %+v", decoded)
	}
}

func TestProductKey(t *testing.T) {
	key, version := productKey(`cpe:2.3:a:F5:Nginx:1.0\:beta:*:*:*:*:*:*:*`)
	if key != "f5:nginx" || version != "1.0:beta" {
		t.Errorf("productKey = %q, %q", key, version)
	}
	if key, version := productKey("cpe:2.3:a:f5:nginx"); key != "f5:nginx" || version != "" {
		t.Errorf("product-level productKey = %q, %q", key, version)
	}
	if key, _ := productKey("nonsense"); key != "" {
		t.Errorf("malformed CPE gave key %q", key)
	}
}

// TestIngestRecordDedupesMatches proves a record processed twice (e.g. a retried year
// resuming after a partial read, or a feed that lists the same statement twice) never
// produces duplicate Match entries.
func TestIngestRecordDedupesMatches(t *testing.T) {
	database := newDatabase(map[string]string{"Nginx": "f5:nginx"})
	record := nvdRecord{ID: "CVE-2021-23017"}
	record.Configurations = []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	}{{Nodes: []struct {
		CPEMatch []struct {
			Vulnerable            bool   `json:"vulnerable"`
			Criteria              string `json:"criteria"`
			VersionStartIncluding string `json:"versionStartIncluding"`
			VersionStartExcluding string `json:"versionStartExcluding"`
			VersionEndIncluding   string `json:"versionEndIncluding"`
			VersionEndExcluding   string `json:"versionEndExcluding"`
		} `json:"cpeMatch"`
	}{{CPEMatch: []struct {
		Vulnerable            bool   `json:"vulnerable"`
		Criteria              string `json:"criteria"`
		VersionStartIncluding string `json:"versionStartIncluding"`
		VersionStartExcluding string `json:"versionStartExcluding"`
		VersionEndIncluding   string `json:"versionEndIncluding"`
		VersionEndExcluding   string `json:"versionEndExcluding"`
	}{{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.20.1"}}}}}}

	ingestRecord(record, database)
	ingestRecord(record, database) // simulates a retry re-processing the same record

	matches := database.Products["f5:nginx"].Matches["CVE-2021-23017"]
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want exactly one (deduped)", matches)
	}
}

// TestIngestNVDFeedWithRetryRecoversAndDoesNotDoubleCount simulates a year's feed that
// fails partway through streaming (as the 2026 feed did in CI) and confirms a retry
// completes the ingest without duplicating records already applied by the failed attempt.
func TestIngestNVDFeedWithRetryRecoversAndDoesNotDoubleCount(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		data := gz(t, nvdFeed)
		if attempts == 1 {
			// Write valid gzip framing but far short of the declared content, simulating a
			// connection that stalls mid-body the way the CI timeout did.
			w.Header().Set("Content-Length", "999999")
			_, _ = w.Write(data[:len(data)/2])
			return
		}
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	database := newDatabase(map[string]string{"Nginx": "f5:nginx", "PHP": "php:php"})
	n, err := ingestNVDFeedWithRetryBackoff(
		context.Background(), fetcher{client: srv.Client()}, srv.URL, database, 3, time.Millisecond,
	)
	if err != nil {
		t.Fatalf("ingestNVDFeedWithRetry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (one failure, one success)", attempts)
	}
	if n != 2 {
		t.Fatalf("kept = %d, want 2", n)
	}
	if matches := database.Products["f5:nginx"].Matches["CVE-2021-23017"]; len(matches) != 1 {
		t.Fatalf("nginx matches = %+v, want exactly one despite the retry", matches)
	}
}

// TestIngestNVDFeedWithRetryGivesUpAfterRepeatedFailure confirms it surfaces the error
// (rather than looping forever or silently succeeding) once retries are exhausted.
func TestIngestNVDFeedWithRetryGivesUpAfterRepeatedFailure(t *testing.T) {
	attempts := 0
	// A 200 with a truncated body models the observed bug (the connection succeeds, the
	// streaming decode fails partway through) without also triggering fetcher.open's own
	// connect-time retries, which a non-2xx status here would nest inside this one.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Length", "999999")
		_, _ = w.Write(gz(t, nvdFeed)[:4])
	}))
	defer srv2.Close()

	database := newDatabase(nil)
	_, err := ingestNVDFeedWithRetryBackoff(
		context.Background(), fetcher{client: srv2.Client()}, srv2.URL, database, 3, time.Millisecond,
	)
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}
