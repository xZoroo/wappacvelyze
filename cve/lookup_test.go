package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xZoroo/wappacvelyze/db"
	"github.com/xZoroo/wappacvelyze/detect"
)

func testDatabase() *db.Database {
	return &db.Database{
		Schema: db.SchemaVersion,
		Products: map[string]*db.Product{
			"f5:nginx": {
				Matches: map[string][]db.Match{
					"CVE-2021-23017": {{Version: "*", VersionStartIncluding: "0.6.18", VersionEndExcluding: "1.20.1"}},
					"CVE-2019-20372": {{Version: "1.18.0"}},
					"CVE-FIXED":      {{Version: "*", VersionEndExcluding: "1.17.0"}},
					"CVE-UNSCOPED":   {{Version: "*"}},
				},
				Lifecycle: &db.Lifecycle{Product: "nginx", Cycles: []db.Cycle{
					{Name: "1.18", Latest: "1.18.0", EOL: true, EOLFrom: "2021-04-20"},
					{Name: "1.31", Latest: "1.31.5", Maintained: true},
					{Name: "1", Latest: "1.31.5"},
				}},
			},
		},
		Vulnerabilities: map[string]*db.Vulnerability{
			"CVE-2021-23017": {ID: "CVE-2021-23017", Score: 7.7, Severity: "HIGH", EPSS: 0.9, Exploits: []string{"nuclei"},
				KEV: &db.KEV{Name: "nginx off-by-one", DateAdded: "2021-11-03"}},
			"CVE-2019-20372": {ID: "CVE-2019-20372", Score: 5.3, Severity: "MEDIUM"},
			"CVE-FIXED":      {ID: "CVE-FIXED"},
			"CVE-UNSCOPED":   {ID: "CVE-UNSCOPED"},
		},
		Libraries: map[string]*db.Library{
			"jquery": {NPM: "jquery", Vulnerabilities: []db.LibraryVulnerability{
				{Below: "1.6.3", Severity: "MEDIUM", CVEs: []string{"CVE-2011-4969"}, Info: []string{"https://x/1"}},
				{AtOrAbove: "1.2.0", Below: "3.5.0", Severity: "MEDIUM", GHSA: "GHSA-gxr4-xjj5-5px2", Summary: "XSS in html()"},
				{AtOrAbove: "1.0.0", Below: "4.0.0", Severity: "LOW", Summary: "EOL", Info: []string{"https://x/eol"}},
			}},
		},
		TechnologyLibraries: map[string]string{"jQuery": "jquery"},
	}
}

func TestDatabaseVulnerabilitiesApplyRangesLocally(t *testing.T) {
	database := testDatabase()
	target, err := productFromCPEName(testCPE)
	if err != nil {
		t.Fatal(err)
	}
	vulns := databaseVulnerabilities(database, database.Products["f5:nginx"], target)
	var ids []string
	for _, v := range vulns {
		ids = append(ids, v.ID+" "+v.AffectedRange)
	}
	want := []string{"CVE-2019-20372 == 1.18.0", "CVE-2021-23017 >= 0.6.18, < 1.20.1"}
	if len(ids) != 2 || ids[0] != want[0] || ids[1] != want[1] {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	v := vulns[1]
	if v.KEV == nil || v.KEV.URL == "" || v.EPSS != 0.9 || v.Exploits[0] != "nuclei" || v.URL != NVDDetailURL+"CVE-2021-23017" {
		t.Errorf("enrichment lost: %+v", v)
	}
}

func TestLifecycleFor(t *testing.T) {
	entry := testDatabase().Products["f5:nginx"]
	tests := []struct {
		version      string
		cycle        string
		eol, behind  bool
		wantLifecyle bool
	}{
		{"1.18.0", "1.18", true, false, true},
		{"1.31.2", "1.31", false, true, true},
		{"1.31.5", "1.31", false, false, true},
		{"1.30.0", "1", false, true, true},
		{"2.0.0", "", false, false, false},
	}
	for _, tt := range tests {
		v, _ := parseVersion(tt.version)
		got := lifecycleFor(entry, v, tt.version)
		if (got != nil) != tt.wantLifecyle {
			t.Errorf("%s: lifecycle presence = %v", tt.version, got != nil)
			continue
		}
		if got != nil && (got.Cycle != tt.cycle || got.EOL != tt.eol || got.Behind != tt.behind) {
			t.Errorf("%s: got %+v", tt.version, got)
		}
	}
}

func TestLibraryVulnerabilities(t *testing.T) {
	database := testDatabase()
	v, _ := parseVersion("1.5.0")
	vulns := libraryVulnerabilities(database, "jQuery", v)
	if len(vulns) != 3 {
		t.Fatalf("got %d vulnerabilities: %+v", len(vulns), vulns)
	}
	if vulns[0].ID != "CVE-2011-4969" || vulns[0].AffectedRange != "< 1.6.3" || vulns[0].URL != NVDDetailURL+"CVE-2011-4969" {
		t.Errorf("cve entry = %+v", vulns[0])
	}
	if vulns[1].ID != "GHSA-gxr4-xjj5-5px2" || vulns[1].URL != "https://github.com/advisories/GHSA-gxr4-xjj5-5px2" {
		t.Errorf("ghsa entry = %+v", vulns[1])
	}
	if vulns[2].ID != "RETIREJS-JQUERY-3" || vulns[2].URL != "https://x/eol" {
		t.Errorf("fallback entry = %+v", vulns[2])
	}
	v, _ = parseVersion("3.7.1")
	if got := libraryVulnerabilities(database, "jQuery", v); len(got) != 1 || got[0].ID != "RETIREJS-JQUERY-3" {
		t.Errorf("3.7.1 = %+v", got)
	}
	if got := libraryVulnerabilities(database, "Unknown", v); got != nil {
		t.Errorf("unmapped technology = %+v", got)
	}
}

func TestAssessUsesDatabaseWithoutNetwork(t *testing.T) {
	requests := 0
	c, _ := newTestNVD(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	})
	a := &Assessor{DB: testDatabase(), NVD: c}

	got, err := a.Assess(context.Background(), nginx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusCritical || got.Vulnerabilities[0].ID != "CVE-2021-23017" || got.Lifecycle == nil || !got.Lifecycle.EOL {
		t.Errorf("nginx 1.18.0 = %+v", got)
	}

	current, _ := a.Assess(context.Background(), detect.Technology{Name: "Nginx", Version: "1.31.5", CPE: nginx.CPE})
	if current.Status != StatusCurrent || current.Lifecycle == nil || current.Lifecycle.Behind {
		t.Errorf("nginx 1.31.5 = %+v", current)
	}
	outdated, _ := a.Assess(context.Background(), detect.Technology{Name: "Nginx", Version: "1.31.2", CPE: nginx.CPE})
	if outdated.Status != StatusOutdated || outdated.Lifecycle.Latest != "1.31.5" {
		t.Errorf("nginx 1.31.2 = %+v", outdated)
	}

	jquery, _ := a.Assess(context.Background(), detect.Technology{Name: "jQuery", Version: "1.5.0"})
	if jquery.Status != StatusVulnerable || len(jquery.Vulnerabilities) != 3 {
		t.Errorf("jquery 1.5.0 = %+v", jquery)
	}
	if requests != 0 {
		t.Errorf("NVD was queried %d times despite the database", requests)
	}

	other, err := a.Assess(context.Background(), detect.Technology{Name: "Other", Version: "1.0", CPE: "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"})
	if err == nil || other.Status != StatusUnknown || requests == 0 {
		t.Errorf("product outside the database should fall back to NVD: %+v, %v", other, err)
	}
}

func TestMergeVulnerabilitiesKeepsFirst(t *testing.T) {
	merged := mergeVulnerabilities(
		[]Vulnerability{{ID: "CVE-1", EPSS: 0.5}},
		[]Vulnerability{{ID: "CVE-1"}, {ID: "GHSA-x"}},
	)
	if len(merged) != 2 || merged[0].EPSS != 0.5 || merged[1].ID != "GHSA-x" {
		t.Errorf("merged = %+v", merged)
	}
}

var _ = httptest.NewServer
