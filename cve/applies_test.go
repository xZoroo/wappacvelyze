package cve

import "testing"

func TestProductFromCPEName(t *testing.T) {
	p, err := productFromCPEName(`cpe:2.3:a:F5:Nginx:1.0\+rc1:*:*:*:*:*:*:*`)
	if err != nil {
		t.Fatal(err)
	}
	if p.vendor != "f5" || p.product != "nginx" || p.version.Original() != "1.0+rc1" {
		t.Errorf("product = %+v", p)
	}
	if _, err := productFromCPEName("cpe:2.3:a:f5:nginx:1.x:*:*:*:*:*:*:*"); err == nil {
		t.Error("accepted non-comparable version")
	}
}

func TestCPEMatchApplies(t *testing.T) {
	nginx118, err := productFromCPEName(testCPE)
	if err != nil {
		t.Fatal(err)
	}
	wildcard := "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
	tests := []struct {
		name    string
		match   nvdCPEMatch
		want    string
		applies bool
	}{
		{"unbounded wildcard ignored", nvdCPEMatch{Vulnerable: true, Criteria: wildcard}, "", false},
		{"not vulnerable", nvdCPEMatch{Criteria: wildcard, VersionEndExcluding: "2.0"}, "", false},
		{"other product", nvdCPEMatch{Vulnerable: true,
			Criteria: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", VersionEndExcluding: "9.0"}, "", false},
		{"exact version", nvdCPEMatch{Vulnerable: true,
			Criteria: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}, "== 1.18.0", true},
		{"exact other version", nvdCPEMatch{Vulnerable: true,
			Criteria: "cpe:2.3:a:f5:nginx:1.18.1:*:*:*:*:*:*:*"}, "", false},
		{"inside range", nvdCPEMatch{Vulnerable: true, Criteria: wildcard,
			VersionStartIncluding: "0.6.18", VersionEndExcluding: "1.20.1"},
			">= 0.6.18, < 1.20.1", true},
		{"below range", nvdCPEMatch{Vulnerable: true, Criteria: wildcard,
			VersionStartExcluding: "1.18.0"}, "", false},
		{"above range", nvdCPEMatch{Vulnerable: true, Criteria: wildcard,
			VersionEndIncluding: "1.17.9"}, "", false},
		{"upper bound only", nvdCPEMatch{Vulnerable: true, Criteria: wildcard,
			VersionEndIncluding: "1.18.0"}, "<= 1.18.0", true},
		{"unparseable bound", nvdCPEMatch{Vulnerable: true, Criteria: wildcard,
			VersionEndIncluding: "n/a"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.match.applies(nginx118)
			if ok != tt.applies || got != tt.want {
				t.Errorf("applies = %q, %v; want %q, %v", got, ok, tt.want, tt.applies)
			}
		})
	}
}
