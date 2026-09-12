package detect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestDetector(t *testing.T) *Detector {
	t.Helper()
	d, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func findTech(techs []Technology, name string) (Technology, bool) {
	for _, tech := range techs {
		if tech.Name == name {
			return tech, true
		}
	}
	return Technology{}, false
}

func TestAnalyzeExtractsVersionsAndCPEs(t *testing.T) {
	d := newTestDetector(t)
	headers := http.Header{
		"Server":       {"nginx/1.24.0"},
		"X-Powered-By": {"PHP/8.1.12"},
	}
	body := []byte(`<html><head><meta name="generator" content="WordPress 6.4.1"></head></html>`)

	techs := d.Analyze(headers, body)

	tests := []struct{ name, version, cpe string }{
		{"Nginx", "1.24.0", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
		{"PHP", "8.1.12", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"},
		{"WordPress", "6.4.1", "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		got, ok := findTech(techs, tt.name)
		if !ok {
			t.Errorf("%s not detected; got %+v", tt.name, techs)
			continue
		}
		if got.Version != tt.version {
			t.Errorf("%s version = %q, want %q", tt.name, got.Version, tt.version)
		}
		if got.CPE != tt.cpe {
			t.Errorf("%s CPE = %q, want %q", tt.name, got.CPE, tt.cpe)
		}
	}
	if nginx, _ := findTech(techs, "Nginx"); nginx.Icon != "Nginx.svg" {
		t.Errorf("Nginx icon = %q, want Nginx.svg", nginx.Icon)
	}
}

func TestAnalyzeWithoutVersion(t *testing.T) {
	d := newTestDetector(t)
	techs := d.Analyze(http.Header{"Server": {"nginx"}}, nil)
	got, ok := findTech(techs, "Nginx")
	if !ok {
		t.Fatalf("Nginx not detected; got %+v", techs)
	}
	if got.Version != "" {
		t.Errorf("version = %q, want empty", got.Version)
	}
}

func TestAnalyzeSortsByName(t *testing.T) {
	d := newTestDetector(t)
	headers := http.Header{"Server": {"nginx/1.24.0"}, "X-Powered-By": {"PHP/8.1.12"}}
	techs := d.Analyze(headers, nil)
	for i := 1; i < len(techs); i++ {
		if techs[i-1].Name > techs[i].Name {
			t.Fatalf("not sorted: %q before %q", techs[i-1].Name, techs[i].Name)
		}
	}
}

func TestScanFetchesTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != UserAgent {
			t.Errorf("User-Agent = %q, want %q", ua, UserAgent)
		}
		w.Header().Set("Server", "nginx/1.24.0")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	d := newTestDetector(t)
	techs, err := d.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got, ok := findTech(techs, "Nginx")
	if !ok || got.Version != "1.24.0" {
		t.Fatalf("got %+v, want Nginx 1.24.0", techs)
	}
}

func TestScanRejectsBadTargets(t *testing.T) {
	d := newTestDetector(t)
	for _, target := range []string{"", "ftp://example.com", "https://"} {
		if _, err := d.Scan(context.Background(), target); err == nil {
			t.Errorf("Scan(%q) succeeded, want error", target)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"example.com", "https://example.com"},
		{" example.com/path?q=1 ", "https://example.com/path?q=1"},
		{"http://example.com", "http://example.com"},
	}
	for _, tt := range tests {
		got, err := NormalizeURL(tt.in)
		if err != nil {
			t.Errorf("NormalizeURL(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
