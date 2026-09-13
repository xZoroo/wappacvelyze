package cve

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/xZoroo/wappacvelyze/db"
)

// LifecycleInfo places a detected version within its product's release cycles.
type LifecycleInfo struct {
	Cycle      string `json:"cycle"`
	Latest     string `json:"latest,omitempty"`
	LatestDate string `json:"latest_date,omitempty"`
	EOL        bool   `json:"eol"`
	EOLFrom    string `json:"eol_from,omitempty"`
	Maintained bool   `json:"maintained"`
	// Behind is true when a newer release exists in the same cycle.
	Behind bool `json:"behind"`
}

// databaseProduct returns the prebuilt record for a technology's CPE, if any.
func databaseProduct(database *db.Database, cpe string) *db.Product {
	if database == nil || cpe == "" {
		return nil
	}
	fields := splitCPE(cpe)
	if len(fields) < 5 {
		return nil
	}
	return database.Products[strings.ToLower(fields[3])+":"+strings.ToLower(fields[4])]
}

// databaseVulnerabilities evaluates a product's stored applicability statements against
// the detected version, exactly as the live NVD path does.
func databaseVulnerabilities(database *db.Database, entry *db.Product, target product) []Vulnerability {
	vulns := []Vulnerability{}
	for id, matches := range entry.Matches {
		record := database.Vulnerabilities[id]
		if record == nil {
			continue
		}
		for _, m := range matches {
			criteria := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
				target.vendor, target.product, cpeEscaper.Replace(m.Version))
			match := nvdCPEMatch{
				Vulnerable: true, Criteria: criteria,
				VersionStartIncluding: m.VersionStartIncluding, VersionStartExcluding: m.VersionStartExcluding,
				VersionEndIncluding: m.VersionEndIncluding, VersionEndExcluding: m.VersionEndExcluding,
			}
			if affected, ok := match.applies(target); ok {
				vulns = append(vulns, fromDatabase(record, affected))
				break
			}
		}
	}
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].ID < vulns[j].ID })
	return vulns
}

func fromDatabase(record *db.Vulnerability, affected string) Vulnerability {
	v := Vulnerability{
		ID: record.ID, Severity: record.Severity, Score: record.Score, Published: record.Published,
		URL: NVDDetailURL + record.ID, Advisory: record.Advisory, AffectedRange: affected,
		EPSS: record.EPSS, EPSSPercentile: record.EPSSPct, Exploits: record.Exploits,
	}
	if record.KEV != nil {
		v.KEV = &KEVEntry{
			CVEID: record.ID, VulnerabilityName: record.KEV.Name, DateAdded: record.KEV.DateAdded,
			DueDate: record.KEV.DueDate, RequiredAction: record.KEV.RequiredAction,
			KnownRansomwareUse: record.KEV.Ransomware, URL: kevCatalogURL + url.QueryEscape(record.ID),
		}
	}
	return v
}

// lifecycleFor finds the release cycle a version belongs to ("8.1.12" → cycle "8.1") and
// whether that cycle is end-of-life or has a newer release.
func lifecycleFor(entry *db.Product, detected *version.Version, raw string) *LifecycleInfo {
	if entry == nil || entry.Lifecycle == nil {
		return nil
	}
	var best *db.Cycle
	for i := range entry.Lifecycle.Cycles {
		cycle := &entry.Lifecycle.Cycles[i]
		if raw == cycle.Name || strings.HasPrefix(raw, cycle.Name+".") {
			if best == nil || len(cycle.Name) > len(best.Name) {
				best = cycle
			}
		}
	}
	if best == nil {
		return nil
	}
	info := &LifecycleInfo{
		Cycle: best.Name, Latest: best.Latest, LatestDate: best.LatestDate,
		EOL: best.EOL, EOLFrom: best.EOLFrom, Maintained: best.Maintained,
	}
	if latest, err := parseVersion(best.Latest); err == nil && detected.LessThan(latest) {
		info.Behind = true
	}
	return info
}

// libraryVulnerabilities matches a JavaScript library version against Retire.js ranges.
func libraryVulnerabilities(database *db.Database, technology string, detected *version.Version) []Vulnerability {
	if database == nil {
		return nil
	}
	key := database.TechnologyLibraries[technology]
	library := database.Libraries[key]
	if library == nil {
		return nil
	}
	var vulns []Vulnerability
	for i, lv := range library.Vulnerabilities {
		if !inLibraryRange(detected, lv) {
			continue
		}
		vulns = append(vulns, libraryVulnerability(key, i, lv))
	}
	return vulns
}

func inLibraryRange(detected *version.Version, lv db.LibraryVulnerability) bool {
	if lv.AtOrAbove != "" {
		lower, err := parseVersion(lv.AtOrAbove)
		if err != nil || detected.LessThan(lower) {
			return false
		}
	}
	if lv.Below != "" {
		upper, err := parseVersion(lv.Below)
		if err != nil || !detected.LessThan(upper) {
			return false
		}
	}
	return lv.AtOrAbove != "" || lv.Below != ""
}

func libraryVulnerability(key string, index int, lv db.LibraryVulnerability) Vulnerability {
	v := Vulnerability{Severity: lv.Severity, Description: lv.Summary}
	switch {
	case len(lv.CVEs) > 0:
		v.ID = lv.CVEs[0]
		v.URL = NVDDetailURL + v.ID
	case lv.GHSA != "":
		v.ID = lv.GHSA
		v.URL = "https://github.com/advisories/" + lv.GHSA
	default:
		v.ID = fmt.Sprintf("RETIREJS-%s-%d", strings.ToUpper(key), index+1)
		if len(lv.Info) > 0 {
			v.URL = lv.Info[0]
		}
	}
	if len(lv.Info) > 0 {
		v.Advisory = lv.Info[0]
	}
	var bounds []string
	if lv.AtOrAbove != "" {
		bounds = append(bounds, ">= "+lv.AtOrAbove)
	}
	if lv.Below != "" {
		bounds = append(bounds, "< "+lv.Below)
	}
	v.AffectedRange = strings.Join(bounds, ", ")
	return v
}

// mergeVulnerabilities keeps the first occurrence of each ID; NVD records come first so
// their EPSS and KEV data win over a Retire.js duplicate.
func mergeVulnerabilities(lists ...[]Vulnerability) []Vulnerability {
	seen := map[string]bool{}
	merged := []Vulnerability{}
	for _, list := range lists {
		for _, v := range list {
			if !seen[v.ID] {
				seen[v.ID] = true
				merged = append(merged, v)
			}
		}
	}
	return merged
}
