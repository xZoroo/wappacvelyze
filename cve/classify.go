package cve

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/xZoroo/wappacvelyze/db"
	"github.com/xZoroo/wappacvelyze/detect"
)

// Status is the security verdict for a detected technology version.
type Status string

const (
	// StatusCurrent means no CVE applies and, when release data exists, the version is the
	// newest in a maintained cycle.
	StatusCurrent Status = "current"
	// StatusOutdated means no CVE applies but a newer release exists in the same cycle.
	StatusOutdated Status = "outdated"
	// StatusUnknown means no lookup was possible; Assessment.Reason says why.
	StatusUnknown Status = "unknown"
	// StatusUnsupported means the release cycle is end-of-life, so fixes will not come.
	StatusUnsupported Status = "unsupported"
	// StatusVulnerable means at least one CVE applies to the detected version.
	StatusVulnerable Status = "vulnerable"
	// StatusCritical means an applicable CVE is on CISA's Known Exploited Vulnerabilities list.
	StatusCritical Status = "critical"
)

var statusRank = map[Status]int{
	StatusCurrent: 0, StatusOutdated: 1, StatusUnknown: 2,
	StatusUnsupported: 3, StatusVulnerable: 4, StatusCritical: 5,
}

// Rank orders statuses by urgency, from current (0) to critical (5).
func (s Status) Rank() int {
	return statusRank[s]
}

// ParseStatus accepts a status name as typed on the command line.
func ParseStatus(s string) (Status, error) {
	status := Status(strings.ToLower(s))
	if _, ok := statusRank[status]; ok {
		return status, nil
	}
	return "", fmt.Errorf("unknown status %q (want current, outdated, unknown, unsupported, vulnerable or critical)", s)
}

// Assessment is the security status of one detected technology.
type Assessment struct {
	Technology      detect.Technology `json:"technology"`
	Status          Status            `json:"status"`
	Reason          string            `json:"reason,omitempty"`
	CPEName         string            `json:"cpe_name,omitempty"`
	Lifecycle       *LifecycleInfo    `json:"lifecycle,omitempty"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities,omitempty"`
}

// Assessor resolves detected technologies to security statuses. It prefers the prebuilt
// database and falls back to live NVD lookups for products the database lacks. Any field
// may be nil.
type Assessor struct {
	DB    *db.Database
	NVD   *NVDClient
	KEV   *KEVCatalog
	Cache *Cache
}

// Assess looks up CVEs and release status for t. When a live lookup fails the assessment
// is returned as StatusUnknown alongside the error so callers can report both.
func (a *Assessor) Assess(ctx context.Context, t detect.Technology) (Assessment, error) {
	detected, reason := comparableVersion(t)
	if reason != "" {
		return Assessment{Technology: t, Status: StatusUnknown, Reason: reason}, nil
	}
	var vulns []Vulnerability
	var lifecycle *LifecycleInfo
	cpeName := ""
	entry := databaseProduct(a.DB, t.CPE)
	library := a.DB != nil && a.DB.Libraries[a.DB.TechnologyLibraries[t.Name]] != nil
	switch {
	case t.CPE == "" && !library:
		return Assessment{Technology: t, Status: StatusUnknown, Reason: "no CPE mapping for this technology"}, nil
	case t.CPE != "":
		name, err := CPEWithVersion(t.CPE, t.Version)
		if err != nil {
			return Assessment{Technology: t, Status: StatusUnknown, Reason: err.Error()}, nil
		}
		cpeName = name
		target, err := productFromCPEName(cpeName)
		if err != nil {
			return Assessment{Technology: t, Status: StatusUnknown, Reason: err.Error()}, nil
		}
		if entry != nil {
			vulns = databaseVulnerabilities(a.DB, entry, target)
			lifecycle = lifecycleFor(entry, detected, t.Version)
		} else if a.NVD != nil {
			vulns, err = a.vulnerabilities(ctx, cpeName)
			if err != nil {
				failed := Assessment{Technology: t, Status: StatusUnknown, Reason: "lookup failed", CPEName: cpeName}
				return failed, err
			}
		} else if !library {
			return Assessment{Technology: t, Status: StatusUnknown, Reason: "not in the vulnerability database", CPEName: cpeName}, nil
		}
	}
	if library {
		vulns = mergeVulnerabilities(vulns, libraryVulnerabilities(a.DB, t.Name, detected))
	}
	return Classify(t, cpeName, vulns, a.KEV, lifecycle), nil
}

func (a *Assessor) vulnerabilities(ctx context.Context, cpeName string) ([]Vulnerability, error) {
	if a.Cache != nil {
		if vulns, ok := a.Cache.Get(cpeName); ok {
			return vulns, nil
		}
	}
	vulns, err := a.NVD.VulnerabilitiesFor(ctx, cpeName)
	if err != nil {
		return nil, err
	}
	if a.Cache != nil {
		if err := a.Cache.Put(cpeName, vulns); err != nil {
			return nil, err
		}
	}
	return vulns, nil
}

// comparableVersion returns the parsed version or the reason no verdict is possible.
// Single-segment versions such as "8" match every 8.x advisory and would produce false
// alarms, so they are treated as undisclosed.
func comparableVersion(t detect.Technology) (*version.Version, string) {
	switch {
	case t.Version == "":
		return nil, "version not disclosed"
	case !strings.Contains(t.Version, "."):
		return nil, fmt.Sprintf("version %q is too coarse to match advisories", t.Version)
	}
	detected, err := parseVersion(t.Version)
	if err != nil {
		return nil, err.Error()
	}
	return detected, ""
}

// Classify derives a status from applicable vulnerabilities, the KEV catalog and release
// data. Vulnerabilities are ordered most urgent first: exploited in the wild, then with a
// public exploit, then by EPSS probability, then by CVSS score.
func Classify(
	t detect.Technology, cpeName string, vulns []Vulnerability, kev *KEVCatalog, lifecycle *LifecycleInfo,
) Assessment {
	a := Assessment{Technology: t, Status: StatusCurrent, CPEName: cpeName, Lifecycle: lifecycle}
	if len(vulns) == 0 {
		switch {
		case lifecycle != nil && lifecycle.EOL:
			a.Status = StatusUnsupported
		case lifecycle != nil && lifecycle.Behind:
			a.Status = StatusOutdated
		}
		return a
	}
	a.Status = StatusVulnerable
	a.Vulnerabilities = make([]Vulnerability, len(vulns))
	for i, v := range vulns {
		if v.KEV == nil && kev != nil {
			if entry, ok := kev.Lookup(v.ID); ok {
				v.KEV = &entry
			}
		}
		if v.KEV != nil {
			a.Status = StatusCritical
		}
		a.Vulnerabilities[i] = v
	}
	sort.SliceStable(a.Vulnerabilities, func(i, j int) bool {
		return moreUrgent(a.Vulnerabilities[i], a.Vulnerabilities[j])
	})
	return a
}

func moreUrgent(a, b Vulnerability) bool {
	if (a.KEV != nil) != (b.KEV != nil) {
		return a.KEV != nil
	}
	if (len(a.Exploits) > 0) != (len(b.Exploits) > 0) {
		return len(a.Exploits) > 0
	}
	if a.EPSS != b.EPSS {
		return a.EPSS > b.EPSS
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.ID > b.ID
}
