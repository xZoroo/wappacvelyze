package cve

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/xZoroo/wappacvelyze/detect"
)

// Status is the security verdict for a detected technology version.
type Status string

const (
	// StatusCurrent means the version was checked and no CVE applies to it.
	StatusCurrent Status = "current"
	// StatusUnknown means no lookup was possible; Assessment.Reason says why.
	StatusUnknown Status = "unknown"
	// StatusVulnerable means at least one CVE applies to the detected version.
	StatusVulnerable Status = "vulnerable"
	// StatusCritical means an applicable CVE is on CISA's Known Exploited Vulnerabilities list.
	StatusCritical Status = "critical"
)

// Rank orders statuses by urgency, from current (0) to critical (3).
func (s Status) Rank() int {
	switch s {
	case StatusCritical:
		return 3
	case StatusVulnerable:
		return 2
	case StatusUnknown:
		return 1
	default:
		return 0
	}
}

// ParseStatus accepts a status name as typed on the command line.
func ParseStatus(s string) (Status, error) {
	status := Status(strings.ToLower(s))
	switch status {
	case StatusCurrent, StatusUnknown, StatusVulnerable, StatusCritical:
		return status, nil
	}
	return "", fmt.Errorf("unknown status %q (want current, unknown, vulnerable or critical)", s)
}

// Assessment is the security status of one detected technology.
type Assessment struct {
	Technology      detect.Technology `json:"technology"`
	Status          Status            `json:"status"`
	Reason          string            `json:"reason,omitempty"`
	CPEName         string            `json:"cpe_name,omitempty"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities,omitempty"`
}

// Assessor resolves detected technologies to security statuses. KEV and Cache may be nil.
type Assessor struct {
	NVD   *NVDClient
	KEV   *KEVCatalog
	Cache *Cache
}

// Assess looks up CVEs for t. When the lookup itself fails the assessment is returned as
// StatusUnknown alongside the error so callers can report both.
func (a *Assessor) Assess(ctx context.Context, t detect.Technology) (Assessment, error) {
	cpeName, reason := lookupKey(t)
	if reason != "" {
		return Assessment{Technology: t, Status: StatusUnknown, Reason: reason}, nil
	}
	vulns, err := a.vulnerabilities(ctx, cpeName)
	if err != nil {
		failed := Assessment{Technology: t, Status: StatusUnknown, Reason: "lookup failed", CPEName: cpeName}
		return failed, err
	}
	return Classify(t, cpeName, vulns, a.KEV), nil
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

// lookupKey returns the versioned CPE name to query, or the reason no lookup is possible.
// Single-segment versions such as "8" match every 8.x advisory and would produce false
// alarms, so they are treated as undisclosed.
func lookupKey(t detect.Technology) (string, string) {
	switch {
	case t.Version == "":
		return "", "version not disclosed"
	case t.CPE == "":
		return "", "no CPE mapping for this technology"
	case !strings.Contains(t.Version, "."):
		return "", fmt.Sprintf("version %q is too coarse to match advisories", t.Version)
	}
	if _, err := parseVersion(t.Version); err != nil {
		return "", err.Error()
	}
	cpeName, err := CPEWithVersion(t.CPE, t.Version)
	if err != nil {
		return "", err.Error()
	}
	return cpeName, ""
}

// Classify derives a status from NVD results and the KEV catalog. Vulnerabilities are
// ordered most urgent first: exploited in the wild, then by CVSS score.
func Classify(t detect.Technology, cpeName string, vulns []Vulnerability, kev *KEVCatalog) Assessment {
	a := Assessment{Technology: t, Status: StatusCurrent, CPEName: cpeName}
	if len(vulns) == 0 {
		return a
	}
	a.Status = StatusVulnerable
	a.Vulnerabilities = make([]Vulnerability, len(vulns))
	for i, v := range vulns {
		if kev != nil {
			if entry, ok := kev.Lookup(v.ID); ok {
				v.KEV = &entry
				a.Status = StatusCritical
			}
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
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.ID > b.ID
}
