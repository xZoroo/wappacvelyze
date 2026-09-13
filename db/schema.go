// Package db defines the prebuilt vulnerability database that a scheduled job publishes
// and the CLI and browser extension download, so end users never query rate-limited
// APIs. Field names are shared with the extension's TypeScript types.
package db

import "time"

// SchemaVersion changes whenever the JSON layout changes incompatibly.
const SchemaVersion = 1

// Manifest is the small file clients fetch first; it names and checksums the database.
type Manifest struct {
	Schema  int               `json:"schema"`
	Built   time.Time         `json:"built"`
	Path    string            `json:"path"`
	SHA256  string            `json:"sha256"`
	Bytes   int64             `json:"bytes"`
	Counts  Counts            `json:"counts"`
	Sources map[string]string `json:"sources"`
}

type Counts struct {
	Products        int `json:"products"`
	Vulnerabilities int `json:"vulnerabilities"`
	Libraries       int `json:"libraries"`
}

// Database is the decompressed payload. Products are keyed by "vendor:product" taken
// from the fingerprint database's CPE names; vulnerabilities are keyed by CVE ID.
type Database struct {
	Schema          int                       `json:"schema"`
	Built           time.Time                 `json:"built"`
	Sources         map[string]string         `json:"sources"`
	Products        map[string]*Product       `json:"products"`
	Vulnerabilities map[string]*Vulnerability `json:"vulnerabilities"`
	Libraries       map[string]*Library       `json:"libraries"`
	// TechnologyLibraries maps a fingerprint technology name to a Libraries key.
	TechnologyLibraries map[string]string `json:"technology_libraries"`
}

// Product collects everything known about one vendor:product pair.
type Product struct {
	// Matches holds, per CVE, the NVD applicability statements that name this product.
	Matches   map[string][]Match `json:"matches"`
	Lifecycle *Lifecycle         `json:"lifecycle,omitempty"`
}

// Match mirrors an NVD cpeMatch entry with the product implied by its parent.
type Match struct {
	Version               string `json:"version"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type Vulnerability struct {
	ID        string   `json:"id"`
	Published string   `json:"published,omitempty"`
	Score     float64  `json:"score,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Advisory  string   `json:"advisory,omitempty"`
	KEV       *KEV     `json:"kev,omitempty"`
	EPSS      float64  `json:"epss,omitempty"`
	EPSSPct   float64  `json:"epss_percentile,omitempty"`
	Exploits  []string `json:"exploits,omitempty"`
}

// KEV is the subset of a CISA Known Exploited Vulnerabilities entry worth shipping.
type KEV struct {
	Name           string `json:"name"`
	DateAdded      string `json:"dateAdded"`
	DueDate        string `json:"dueDate,omitempty"`
	RequiredAction string `json:"requiredAction,omitempty"`
	Ransomware     string `json:"ransomware,omitempty"`
}

// Lifecycle is a product's release cycles from endoflife.date.
type Lifecycle struct {
	Product string  `json:"product"`
	Cycles  []Cycle `json:"cycles"`
}

type Cycle struct {
	Name        string `json:"name"`
	ReleaseDate string `json:"releaseDate,omitempty"`
	Latest      string `json:"latest,omitempty"`
	LatestDate  string `json:"latestDate,omitempty"`
	EOL         bool   `json:"eol"`
	EOLFrom     string `json:"eolFrom,omitempty"`
	Maintained  bool   `json:"maintained"`
	LTS         bool   `json:"lts,omitempty"`
}

// Library is a Retire.js entry for a JavaScript library.
type Library struct {
	NPM             string                 `json:"npm,omitempty"`
	Vulnerabilities []LibraryVulnerability `json:"vulnerabilities"`
}

type LibraryVulnerability struct {
	AtOrAbove string   `json:"atOrAbove,omitempty"`
	Below     string   `json:"below,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	CVEs      []string `json:"cves,omitempty"`
	GHSA      string   `json:"ghsa,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Info      []string `json:"info,omitempty"`
}
