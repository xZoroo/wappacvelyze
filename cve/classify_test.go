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

func TestLookupKey(t *testing.T) {
	tests := []struct {
		name       string
		tech       detect.Technology
		wantCPE    string
		wantReason string
	}{
		{name: "ok", tech: nginx, wantCPE: testCPE},
		{name: "no version", tech: detect.Technology{Name: "X", CPE: nginx.CPE},
			wantReason: "version not disclosed"},
		{name: "no cpe", tech: detect.Technology{Name: "X", Version: "1.0"},
			wantReason: "no CPE mapping"},
		{name: "coarse", tech: detect.Technology{Name: "PHP", Version: "8", CPE: nginx.CPE},
			wantReason: "too coarse"},
		{name: "bad cpe", tech: detect.Technology{Name: "X", Version: "1.0", CPE: "cpe:/a:x"},
			wantReason: "malformed"},
		{name: "not comparable", tech: detect.Technology{Name: "X", Version: "1.x", CPE: nginx.CPE},
			wantReason: "not comparable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpeName, reason := lookupKey(tt.tech)
			if cpeName != tt.wantCPE {
				t.Errorf("cpe = %q, want %q", cpeName, tt.wantCPE)
			}
			if !strings.Contains(reason, tt.wantReason) {
				t.Errorf("reason = %q, want containing %q", reason, tt.wantReason)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	vulns := []Vulnerability{{ID: "CVE-2021-A", Score: 5.3}, {ID: "CVE-2021-B", Score: 9.8}}
	kev := &KEVCatalog{Vulnerabilities: []KEVEntry{{CVEID: "CVE-2021-A"}}}

	current := Classify(nginx, testCPE, nil, kev)
	if current.Status != StatusCurrent || len(current.Vulnerabilities) != 0 {
		t.Errorf("current = %+v", current)
	}

	vulnerable := Classify(nginx, testCPE, vulns, nil)
	if vulnerable.Status != StatusVulnerable {
		t.Errorf("status = %q, want vulnerable", vulnerable.Status)
	}
	if vulnerable.Vulnerabilities[0].ID != "CVE-2021-B" {
		t.Errorf("highest score not first: %+v", vulnerable.Vulnerabilities)
	}

	critical := Classify(nginx, testCPE, vulns, kev)
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

func TestStatusRankAndParse(t *testing.T) {
	if StatusCritical.Rank() <= StatusVulnerable.Rank() ||
		StatusVulnerable.Rank() <= StatusUnknown.Rank() ||
		StatusUnknown.Rank() <= StatusCurrent.Rank() {
		t.Error("ranks not strictly ordered")
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
