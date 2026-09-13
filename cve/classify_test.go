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

	"github.com/xZoroo/wappacvelyze/detect"
)

var nginx = detect.Technology{
	Name:    "Nginx",
	Version: "1.18.0",
	CPE:     "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
}

func TestComparableVersion(t *testing.T) {
	tests := []struct {
		name       string
		tech       detect.Technology
		wantReason string
	}{
		{name: "ok", tech: nginx},
		{name: "no version", tech: detect.Technology{Name: "X", CPE: nginx.CPE}, wantReason: "version not disclosed"},
		{name: "coarse", tech: detect.Technology{Name: "PHP", Version: "8"}, wantReason: "too coarse"},
		{name: "not comparable", tech: detect.Technology{Name: "X", Version: "1.x"}, wantReason: "not comparable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, reason := comparableVersion(tt.tech)
			if (v == nil) != (tt.wantReason != "") || !strings.Contains(reason, tt.wantReason) {
				t.Errorf("comparableVersion = %v, %q; want reason containing %q", v, reason, tt.wantReason)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	vulns := []Vulnerability{{ID: "CVE-2021-A", Score: 5.3}, {ID: "CVE-2021-B", Score: 9.8}}
	kev := &KEVCatalog{Vulnerabilities: []KEVEntry{{CVEID: "CVE-2021-A"}}}

	current := Classify(nginx, testCPE, nil, kev, nil)
	if current.Status != StatusCurrent || len(current.Vulnerabilities) != 0 {
		t.Errorf("current = %+v", current)
	}
	outdated := Classify(nginx, testCPE, nil, nil, &LifecycleInfo{Cycle: "1.18", Latest: "1.18.1", Behind: true})
	if outdated.Status != StatusOutdated || outdated.Lifecycle == nil {
		t.Errorf("outdated = %+v", outdated)
	}
	eol := Classify(nginx, testCPE, nil, nil, &LifecycleInfo{Cycle: "1.18", EOL: true})
	if eol.Status != StatusUnsupported {
		t.Errorf("eol = %+v", eol)
	}
	if withVulns := Classify(nginx, testCPE, vulns, nil, &LifecycleInfo{EOL: true}); withVulns.Status != StatusVulnerable {
		t.Errorf("vulnerabilities should outrank EOL: %+v", withVulns)
	}

	vulnerable := Classify(nginx, testCPE, vulns, nil, nil)
	if vulnerable.Status != StatusVulnerable {
		t.Errorf("status = %q, want vulnerable", vulnerable.Status)
	}
	if vulnerable.Vulnerabilities[0].ID != "CVE-2021-B" {
		t.Errorf("highest score not first: %+v", vulnerable.Vulnerabilities)
	}

	critical := Classify(nginx, testCPE, vulns, kev, nil)
	if critical.Status != StatusCritical {
		t.Errorf("status = %q, want critical", critical.Status)
	}
	top := critical.Vulnerabilities[0]
	if top.ID != "CVE-2021-A" || top.KEV == nil {
		t.Errorf("KEV entry not first: %+v", critical.Vulnerabilities)
	}
	if vulns[0].KEV != nil {
		t.Error("Classify mutated its input")
	}
}

func TestOrderingPrefersExploitationSignals(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "CVE-SCORE", Score: 9.9},
		{ID: "CVE-EPSS", Score: 5.0, EPSS: 0.9},
		{ID: "CVE-EXPLOIT", Score: 4.0, Exploits: []string{"nuclei"}},
		{ID: "CVE-KEV", Score: 3.0, KEV: &KEVEntry{CVEID: "CVE-KEV"}},
	}
	got := Classify(nginx, testCPE, vulns, nil, nil)
	var order []string
	for _, v := range got.Vulnerabilities {
		order = append(order, v.ID)
	}
	if strings.Join(order, ",") != "CVE-KEV,CVE-EXPLOIT,CVE-EPSS,CVE-SCORE" {
		t.Errorf("order = %v", order)
	}
	if got.Status != StatusCritical {
		t.Errorf("status = %q, want critical from a pre-set KEV entry", got.Status)
	}
}

func TestStatusRankAndParse(t *testing.T) {
	ordered := []Status{StatusCurrent, StatusOutdated, StatusUnknown, StatusUnsupported, StatusVulnerable, StatusCritical}
	for i := 1; i < len(ordered); i++ {
		if ordered[i].Rank() <= ordered[i-1].Rank() {
			t.Errorf("%s should rank above %s", ordered[i], ordered[i-1])
		}
	}
	if s, err := ParseStatus("Unsupported"); err != nil || s != StatusUnsupported {
		t.Errorf("ParseStatus = %q, %v", s, err)
	}
	if s, err := ParseStatus("Critical"); err != nil || s != StatusCritical {
		t.Errorf("ParseStatus = %q, %v", s, err)
	}
	if _, err := ParseStatus("bogus"); err == nil {
		t.Error("ParseStatus accepted bogus")
	}
}

func TestAssessUsesCacheBeforeNVD(t *testing.T) {
	requests := 0
	c, _ := newTestNVD(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		fmt.Fprint(w, nvdPageJSON("CVE-2021-23017", 1))
	})
	cache, err := OpenCache(filepath.Join(t.TempDir(), "nvd.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a := &Assessor{NVD: c, Cache: cache}

	for i := range 2 {
		got, err := a.Assess(context.Background(), nginx)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != StatusVulnerable || got.CPEName != testCPE {
			t.Fatalf("pass %d: %+v", i, got)
		}
	}
	if requests != 1 {
		t.Errorf("requests = %d, want 1 (second assess served from cache)", requests)
	}
}

func TestAssessSkipsLookupWithoutVersion(t *testing.T) {
	a := &Assessor{}
	got, err := a.Assess(context.Background(), detect.Technology{Name: "Nginx", CPE: nginx.CPE})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusUnknown || got.Reason != "version not disclosed" {
		t.Errorf("got %+v", got)
	}
}

func TestAssessReportsLookupFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewNVDClient(srv.Client(), "")
	c.BaseURL = srv.URL
	got, err := (&Assessor{NVD: c}).Assess(context.Background(), nginx)
	if err == nil {
		t.Fatal("expected lookup error")
	}
	if got.Status != StatusUnknown || got.Reason != "lookup failed" {
		t.Errorf("got %+v", got)
	}
}
