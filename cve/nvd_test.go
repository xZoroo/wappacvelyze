package cve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testCPE = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"

func nvdPageJSON(id string, total int) string {
	return fmt.Sprintf(`{"resultsPerPage":1,"startIndex":0,"totalResults":%d,"vulnerabilities":[
	  {"cve":{"id":%q,"published":"2021-05-25T13:15:00.000",
	    "descriptions":[{"lang":"es","value":"no"},{"lang":"en","value":"1-byte overwrite"}],
	    "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.7,"baseSeverity":"High"}}]},
	    "references":[{"url":"https://example.com/other","tags":["Third Party Advisory"]},
	                  {"url":"https://nginx.org/advisory","tags":["Vendor Advisory"]}],
	    "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[
	      {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
	       "versionStartIncluding":"0.6.18","versionEndExcluding":"1.20.1"}]}]}]}}]}`,
		total, id)
}

// nvdCVEJSON builds one CVE entry whose only applicability statement is match.
func nvdCVEJSON(id, match string) string {
	return fmt.Sprintf(`{"cve":{"id":%q,"configurations":[{"nodes":[{"cpeMatch":[%s]}]}]}}`,
		id, match)
}

func newTestNVD(t *testing.T, handler http.HandlerFunc) (*NVDClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewNVDClient(srv.Client(), "")
	c.BaseURL = srv.URL
	c.retryDelay = time.Millisecond
	return c, srv
}

func TestVulnerabilitiesForPaginatesAndParses(t *testing.T) {
	requests := 0
	c, _ := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.URL.Query().Get("cpeName"); got != testCPE {
			t.Errorf("cpeName = %q, want %q", got, testCPE)
		}
		if r.URL.Query().Get("startIndex") == "0" {
			fmt.Fprint(w, nvdPageJSON("CVE-2021-23017", 2))
			return
		}
		fmt.Fprint(w, nvdPageJSON("CVE-2019-20372", 2))
	})

	vulns, err := c.VulnerabilitiesFor(context.Background(), testCPE)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Errorf("requests = %d, want 2", requests)
	}
	if len(vulns) != 2 || vulns[0].ID != "CVE-2021-23017" || vulns[1].ID != "CVE-2019-20372" {
		t.Fatalf("vulns = %+v", vulns)
	}
	v := vulns[0]
	if v.Severity != "HIGH" || v.Score != 7.7 {
		t.Errorf("severity/score = %q/%v, want HIGH/7.7", v.Severity, v.Score)
	}
	if v.Description != "1-byte overwrite" {
		t.Errorf("description = %q", v.Description)
	}
	if v.Advisory != "https://nginx.org/advisory" {
		t.Errorf("advisory = %q, want vendor advisory", v.Advisory)
	}
	if v.URL != NVDDetailURL+"CVE-2021-23017" {
		t.Errorf("url = %q", v.URL)
	}
	if v.AffectedRange != ">= 0.6.18, < 1.20.1" {
		t.Errorf("affected range = %q", v.AffectedRange)
	}
}

func TestVulnerabilitiesForDropsInapplicableRecords(t *testing.T) {
	wildcard := `"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"`
	entries := strings.Join([]string{
		nvdCVEJSON("CVE-UNSCOPED", `{"vulnerable":true,`+wildcard+`}`),
		nvdCVEJSON("CVE-EXACT", `{"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}`),
		nvdCVEJSON("CVE-FIXED", `{"vulnerable":true,`+wildcard+`,"versionEndExcluding":"1.17.0"}`),
		nvdCVEJSON("CVE-OTHER", `{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}`),
	}, ",")
	c, _ := newTestNVD(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"totalResults":4,"vulnerabilities":[%s]}`, entries)
	})
	vulns, err := c.VulnerabilitiesFor(context.Background(), testCPE)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].ID != "CVE-EXACT" || vulns[0].AffectedRange != "== 1.18.0" {
		t.Fatalf("vulns = %+v, want only CVE-EXACT", vulns)
	}
}

func TestVulnerabilitiesForEmpty(t *testing.T) {
	c, _ := newTestNVD(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`)
	})
	vulns, err := c.VulnerabilitiesFor(context.Background(), testCPE)
	if err != nil {
		t.Fatal(err)
	}
	if vulns == nil || len(vulns) != 0 {
		t.Fatalf("vulns = %#v, want empty non-nil slice", vulns)
	}
}

func TestVulnerabilitiesForSendsAPIKey(t *testing.T) {
	c, _ := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apiKey"); got != "secret" {
			t.Errorf("apiKey header = %q", got)
		}
		fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
	})
	c.APIKey = "secret"
	if _, err := c.VulnerabilitiesFor(context.Background(), testCPE); err != nil {
		t.Fatal(err)
	}
}

func TestVulnerabilitiesForRetriesThrottling(t *testing.T) {
	requests := 0
	c, _ := newTestNVD(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := c.VulnerabilitiesFor(context.Background(), testCPE)
	if err == nil || !strings.Contains(err.Error(), "NVD_API_KEY") {
		t.Fatalf("err = %v, want rate limit guidance", err)
	}
	if requests != nvdMaxAttempts {
		t.Errorf("requests = %d, want %d", requests, nvdMaxAttempts)
	}
}

func TestVulnerabilitiesForReportsRejection(t *testing.T) {
	requests := 0
	c, _ := newTestNVD(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("message", "Invalid cpeName")
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.VulnerabilitiesFor(context.Background(), testCPE)
	if err == nil || !strings.Contains(err.Error(), "Invalid cpeName") {
		t.Fatalf("err = %v, want NVD message", err)
	}
	if requests != 1 {
		t.Errorf("requests = %d, want 1 (no retry on rejection)", requests)
	}
}
