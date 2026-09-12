package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xZoroo/wappacvelyze/cve"
	"github.com/xZoroo/wappacvelyze/detect"
)

func TestRunVersionAndUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != exitOK {
		t.Fatalf("version exit = %d", code)
	}
	if !strings.Contains(out.String(), versionString()) {
		t.Errorf("version output = %q", out.String())
	}
	if code := run([]string{"bogus"}, &out, &errOut); code != exitError {
		t.Errorf("unknown command exit = %d, want %d", code, exitError)
	}
	if code := run(nil, &out, &errOut); code != exitError {
		t.Errorf("no command exit = %d, want %d", code, exitError)
	}
}

func TestParseScanOptionsValidates(t *testing.T) {
	var errOut bytes.Buffer
	if _, err := parseScanOptions(nil, &errOut); err == nil {
		t.Error("accepted no targets")
	}
	if _, err := parseScanOptions([]string{"--format", "xml", "a.com"}, &errOut); err == nil {
		t.Error("accepted bad format")
	}
	if _, err := parseScanOptions([]string{"--fail-on", "unknown", "a.com"}, &errOut); err == nil {
		t.Error("accepted --fail-on unknown")
	}
	opts, err := parseScanOptions([]string{"--fail-on", "critical", "--no-cve", "a.com"}, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if opts.failOn != cve.StatusCritical || !opts.noCVE || len(opts.urls) != 1 {
		t.Errorf("opts = %+v", opts)
	}
}

func TestReadTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "# comment\nexample.com\n\n  https://b.example  \n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	urls, err := readTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 2 || urls[0] != "example.com" || urls[1] != "https://b.example" {
		t.Errorf("urls = %q", urls)
	}
}

func TestExitCode(t *testing.T) {
	vulnerable := scanResult{URL: "a", Technologies: []cve.Assessment{{Status: cve.StatusVulnerable}}}
	failed := scanResult{URL: "b", Error: "boom"}

	if got := exitCode([]scanResult{vulnerable}, ""); got != exitOK {
		t.Errorf("no threshold: %d", got)
	}
	if got := exitCode([]scanResult{vulnerable}, cve.StatusVulnerable); got != exitFindings {
		t.Errorf("threshold met: %d", got)
	}
	if got := exitCode([]scanResult{vulnerable}, cve.StatusCritical); got != exitOK {
		t.Errorf("threshold not met: %d", got)
	}
	if got := exitCode([]scanResult{failed, vulnerable}, cve.StatusVulnerable); got != exitError {
		t.Errorf("scan error should win: %d", got)
	}
}

func TestDetail(t *testing.T) {
	tech := detect.Technology{Name: "Nginx", Version: "1.18.0"}
	kev := &cve.KEVEntry{CVEID: "CVE-2021-1", URL: "https://cisa/kev"}
	tests := []struct {
		name string
		a    cve.Assessment
		want []string
	}{
		{"current", cve.Assessment{Technology: tech, Status: cve.StatusCurrent}, []string{"no known CVEs"}},
		{"unknown", cve.Assessment{Technology: tech, Status: cve.StatusUnknown, Reason: "why"},
			[]string{"why"}},
		{"vulnerable", cve.Assessment{Technology: tech, Status: cve.StatusVulnerable,
			Vulnerabilities: []cve.Vulnerability{
				{ID: "CVE-2021-1", Severity: "HIGH", Score: 7.7, URL: "https://nvd/1"},
				{ID: "CVE-2021-2", URL: "https://nvd/2"},
			}}, []string{"CVE-2021-1 HIGH 7.7", "(+1 more)", "https://nvd/1"}},
		{"critical", cve.Assessment{Technology: tech, Status: cve.StatusCritical,
			Vulnerabilities: []cve.Vulnerability{{ID: "CVE-2021-1", URL: "https://nvd/1", KEV: kev}}},
			[]string{"CVE-2021-1", "https://cisa/kev"}},
	}
	for _, tt := range tests {
		got := detail(tt.a)
		for _, want := range tt.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: detail = %q, want containing %q", tt.name, got, want)
			}
		}
	}
}

func TestWriteTableAlignsColumns(t *testing.T) {
	results := []scanResult{{URL: "https://a.example", Technologies: []cve.Assessment{
		{Technology: detect.Technology{Name: "Nginx", Version: "1.18.0"}, Status: cve.StatusCurrent},
		{Technology: detect.Technology{Name: "WordPress"}, Status: cve.StatusUnknown, Reason: "r"},
	}}, {URL: "https://b.example", Error: "boom"}}
	var out bytes.Buffer
	if err := writeTable(&out, results, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 7 {
		t.Fatalf("got %d lines:\n%s", len(lines), out.String())
	}
	nginx, wordpress := lines[2], lines[3]
	if strings.Index(nginx, "1.18.0") != strings.Index(wordpress, "—") {
		t.Errorf("version column misaligned:\n%s", out.String())
	}
	if !strings.Contains(lines[6], "error: boom") {
		t.Errorf("error line = %q", lines[6])
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Error("ANSI codes emitted with color disabled")
	}
}
