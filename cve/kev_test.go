package cve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const kevJSON = `{"catalogVersion":"2026.09.10","dateReleased":"2026-09-10T15:00:00.0000Z",
 "count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache",
 "product":"Log4j2","vulnerabilityName":"Apache Log4j2 Remote Code Execution Vulnerability",
 "dateAdded":"2021-12-10","shortDescription":"RCE via JNDI lookups.",
 "requiredAction":"Apply updates per vendor instructions.","dueDate":"2021-12-24",
 "knownRansomwareCampaignUse":"Known"}]}`

func TestLoadKEVCachesFeed(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		fmt.Fprint(w, kevJSON)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "kev.json")
	ctx := context.Background()

	catalog, err := LoadKEV(ctx, srv.Client(), srv.URL, path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := catalog.Lookup("cve-2021-44228")
	if !ok || entry.Product != "Log4j2" {
		t.Fatalf("Lookup = %+v, %v", entry, ok)
	}
	if !strings.HasSuffix(entry.URL, "CVE-2021-44228") {
		t.Errorf("entry URL = %q", entry.URL)
	}
	if _, ok := catalog.Lookup("CVE-2000-0001"); ok {
		t.Error("unexpected KEV hit")
	}

	if _, err := LoadKEV(ctx, srv.Client(), srv.URL, path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Errorf("requests = %d after fresh cache, want 1", requests)
	}
	if _, err := LoadKEV(ctx, srv.Client(), srv.URL, path, 0); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Errorf("requests = %d after expiry, want 2", requests)
	}
}

func TestLoadKEVFallsBackToStaleCache(t *testing.T) {
	healthy := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, kevJSON)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "kev.json")
	ctx := context.Background()

	if _, err := LoadKEV(ctx, srv.Client(), srv.URL, path, time.Hour); err != nil {
		t.Fatal(err)
	}
	healthy = false
	catalog, err := LoadKEV(ctx, srv.Client(), srv.URL, path, 0)
	if err == nil {
		t.Fatal("expected refresh error")
	}
	if catalog == nil || catalog.Len() != 1 {
		t.Fatalf("stale catalog not returned: %+v", catalog)
	}
}

func TestFetchKEVRejectsEmptyCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()
	if _, err := FetchKEV(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected error for empty catalog")
	}
}
