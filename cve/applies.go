package cve

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/go-version"
)

// product identifies the vendor, product and concrete version being assessed.
type product struct {
	vendor  string
	product string
	version *version.Version
}

var cpeUnescape = regexp.MustCompile(`\\(.)`)

// productFromCPEName reads the vendor, product and version out of a versioned CPE name.
func productFromCPEName(cpeName string) (product, error) {
	fields := splitCPE(cpeName)
	if len(fields) != cpeFieldCount {
		return product{}, fmt.Errorf("malformed CPE 2.3 name %q", cpeName)
	}
	v, err := parseVersion(cpeUnescape.ReplaceAllString(fields[cpeVersionIndex], "$1"))
	if err != nil {
		return product{}, err
	}
	return product{
		vendor:  strings.ToLower(fields[3]),
		product: strings.ToLower(fields[4]),
		version: v,
	}, nil
}

// parseVersion accepts the dotted, optionally pre-release version numbers found in
// fingerprints and NVD applicability statements.
func parseVersion(s string) (*version.Version, error) {
	v, err := version.NewVersion(s)
	if err != nil {
		return nil, fmt.Errorf("version %q is not comparable: %w", s, err)
	}
	return v, nil
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// applies reports whether the match criteria covers p and describes the affected range.
// A wildcard criteria with no version bounds is ignored: NVD carries many old records
// whose applicability was never scoped, and they would flag every version ever released.
func (m nvdCPEMatch) applies(p product) (string, bool) {
	fields := splitCPE(m.Criteria)
	if !m.Vulnerable || len(fields) != cpeFieldCount {
		return "", false
	}
	if strings.ToLower(fields[3]) != p.vendor || strings.ToLower(fields[4]) != p.product {
		return "", false
	}
	criteriaVersion := cpeUnescape.ReplaceAllString(fields[cpeVersionIndex], "$1")
	if criteriaVersion != "*" {
		v, err := parseVersion(criteriaVersion)
		if err != nil || !v.Equal(p.version) {
			return "", false
		}
		return "== " + criteriaVersion, true
	}
	return m.rangeApplies(p.version)
}

func (m nvdCPEMatch) rangeApplies(v *version.Version) (string, bool) {
	bounds := []struct {
		raw string
		op  string
		ok  func(cmp int) bool
	}{
		{m.VersionStartIncluding, ">=", func(c int) bool { return c >= 0 }},
		{m.VersionStartExcluding, ">", func(c int) bool { return c > 0 }},
		{m.VersionEndIncluding, "<=", func(c int) bool { return c <= 0 }},
		{m.VersionEndExcluding, "<", func(c int) bool { return c < 0 }},
	}
	var parts []string
	for _, b := range bounds {
		if b.raw == "" {
			continue
		}
		limit, err := parseVersion(b.raw)
		if err != nil || !b.ok(v.Compare(limit)) {
			return "", false
		}
		parts = append(parts, b.op+" "+b.raw)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, ", "), true
}

// applicableRange scans every applicability statement of the CVE for one that covers p.
func (c nvdCVE) applicableRange(p product) (string, bool) {
	for _, config := range c.Configurations {
		for _, node := range config.Nodes {
			for _, m := range node.CPEMatch {
				if affected, ok := m.applies(p); ok {
					return affected, true
				}
			}
		}
	}
	return "", false
}
