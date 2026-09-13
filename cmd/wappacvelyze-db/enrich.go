package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/xZoroo/wappacvelyze/db"
)

// ingestKEV marks database vulnerabilities that CISA lists as exploited in the wild.
func ingestKEV(ctx context.Context, f fetcher, url string, database *db.Database) (string, error) {
	body, err := f.open(ctx, url)
	if err != nil {
		return "", err
	}
	defer body.Close()
	var feed struct {
		CatalogVersion  string `json:"catalogVersion"`
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VulnerabilityName string `json:"vulnerabilityName"`
			DateAdded         string `json:"dateAdded"`
			DueDate           string `json:"dueDate"`
			RequiredAction    string `json:"requiredAction"`
			Ransomware        string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(body).Decode(&feed); err != nil {
		return "", fmt.Errorf("decode KEV: %w", err)
	}
	if len(feed.Vulnerabilities) == 0 {
		return "", fmt.Errorf("KEV catalog is empty")
	}
	for _, entry := range feed.Vulnerabilities {
		if v := database.Vulnerabilities[strings.ToUpper(entry.CVEID)]; v != nil {
			v.KEV = &db.KEV{
				Name:           entry.VulnerabilityName,
				DateAdded:      entry.DateAdded,
				DueDate:        entry.DueDate,
				RequiredAction: entry.RequiredAction,
				Ransomware:     entry.Ransomware,
			}
		}
	}
	return feed.CatalogVersion, nil
}

// ingestEPSS attaches FIRST's exploitation probabilities. The CSV starts with a comment
// line naming the model version and score date, which becomes the source label.
func ingestEPSS(ctx context.Context, f fetcher, url string, database *db.Database) (string, error) {
	body, err := f.openGzip(ctx, url)
	if err != nil {
		return "", err
	}
	defer body.Close()
	reader := bufio.NewReader(body)
	label, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read EPSS header: %w", err)
	}
	label = strings.TrimSpace(strings.TrimPrefix(label, "#"))
	records := csv.NewReader(reader)
	if _, err := records.Read(); err != nil { // column header
		return "", fmt.Errorf("read EPSS columns: %w", err)
	}
	for {
		row, err := records.Read()
		if err == io.EOF {
			return label, nil
		}
		if err != nil {
			return "", fmt.Errorf("read EPSS row: %w", err)
		}
		v := database.Vulnerabilities[row[0]]
		if v == nil || len(row) < 3 {
			continue
		}
		v.EPSS, _ = strconv.ParseFloat(row[1], 64)
		v.EPSSPct, _ = strconv.ParseFloat(row[2], 64)
	}
}

// ingestNuclei flags CVEs that have a ProjectDiscovery Nuclei template (newline-delimited JSON).
func ingestNuclei(ctx context.Context, f fetcher, url string, database *db.Database) error {
	body, err := f.open(ctx, url)
	if err != nil {
		return err
	}
	defer body.Close()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var entry struct {
			ID string `json:"ID"`
		}
		if json.Unmarshal(scanner.Bytes(), &entry) == nil {
			addExploit(database, entry.ID, "nuclei")
		}
	}
	return scanner.Err()
}

var cveReference = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ingestMetasploit flags CVEs referenced by a Metasploit module.
func ingestMetasploit(ctx context.Context, f fetcher, url string, database *db.Database) error {
	body, err := f.open(ctx, url)
	if err != nil {
		return err
	}
	defer body.Close()
	var modules map[string]struct {
		References []string `json:"references"`
	}
	if err := json.NewDecoder(body).Decode(&modules); err != nil {
		return fmt.Errorf("decode Metasploit metadata: %w", err)
	}
	for _, module := range modules {
		for _, ref := range module.References {
			if cveReference.MatchString(ref) {
				addExploit(database, ref, "metasploit")
			}
		}
	}
	return nil
}

func addExploit(database *db.Database, id, source string) {
	v := database.Vulnerabilities[strings.ToUpper(id)]
	if v == nil {
		return
	}
	for _, existing := range v.Exploits {
		if existing == source {
			return
		}
	}
	v.Exploits = append(v.Exploits, source)
}

// ingestEndOfLife attaches release cycles to products whose CPE endoflife.date lists.
func ingestEndOfLife(ctx context.Context, f fetcher, url string, database *db.Database) (string, error) {
	body, err := f.open(ctx, url)
	if err != nil {
		return "", err
	}
	defer body.Close()
	var feed struct {
		GeneratedAt string `json:"generated_at"`
		Result      []struct {
			Name        string `json:"name"`
			Identifiers []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"identifiers"`
			Releases []struct {
				Name        string `json:"name"`
				ReleaseDate string `json:"releaseDate"`
				IsLTS       bool   `json:"isLts"`
				IsEOL       bool   `json:"isEol"`
				EOLFrom     string `json:"eolFrom"`
				Maintained  bool   `json:"isMaintained"`
				Latest      *struct {
					Name string `json:"name"`
					Date string `json:"date"`
				} `json:"latest"`
			} `json:"releases"`
		} `json:"result"`
	}
	if err := json.NewDecoder(body).Decode(&feed); err != nil {
		return "", fmt.Errorf("decode endoflife.date: %w", err)
	}
	for _, product := range feed.Result {
		lifecycle := &db.Lifecycle{Product: product.Name}
		for _, release := range product.Releases {
			cycle := db.Cycle{
				Name: release.Name, ReleaseDate: release.ReleaseDate, EOL: release.IsEOL,
				EOLFrom: release.EOLFrom, Maintained: release.Maintained, LTS: release.IsLTS,
			}
			if release.Latest != nil {
				cycle.Latest, cycle.LatestDate = release.Latest.Name, release.Latest.Date
			}
			lifecycle.Cycles = append(lifecycle.Cycles, cycle)
		}
		for _, identifier := range product.Identifiers {
			if identifier.Type != "cpe" {
				continue
			}
			if key, _ := productKey(identifier.ID); database.Products[key] != nil {
				database.Products[key].Lifecycle = lifecycle
			}
		}
	}
	return feed.GeneratedAt, nil
}

// ingestRetire loads the Retire.js repository and links fingerprint technologies to
// libraries by name (e.g. "jQuery" → "jquery", "Moment.js" → "moment").
func ingestRetire(ctx context.Context, f fetcher, url string, database *db.Database, technologies []string) error {
	body, err := f.open(ctx, url)
	if err != nil {
		return err
	}
	defer body.Close()
	var repository map[string]struct {
		NPMName         nameList `json:"npmname"`
		BowerName       nameList `json:"bowername"`
		Vulnerabilities []struct {
			AtOrAbove   string   `json:"atOrAbove"`
			Below       string   `json:"below"`
			Severity    string   `json:"severity"`
			Info        []string `json:"info"`
			Identifiers struct {
				Summary  string   `json:"summary"`
				CVE      []string `json:"CVE"`
				GitHubID string   `json:"githubID"`
			} `json:"identifiers"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(body).Decode(&repository); err != nil {
		return fmt.Errorf("decode Retire.js repository: %w", err)
	}
	byKey := map[string]string{}
	byAlias := map[string]string{}
	for name, library := range repository {
		if len(library.Vulnerabilities) == 0 {
			continue
		}
		byKey[slug(name)] = name
		entry := &db.Library{NPM: library.NPMName.first()}
		for _, v := range library.Vulnerabilities {
			entry.Vulnerabilities = append(entry.Vulnerabilities, db.LibraryVulnerability{
				AtOrAbove: v.AtOrAbove, Below: v.Below, Severity: strings.ToUpper(v.Severity),
				CVEs: v.Identifiers.CVE, GHSA: v.Identifiers.GitHubID,
				Summary: v.Identifiers.Summary, Info: v.Info,
			})
		}
		database.Libraries[name] = entry
		for _, alias := range append(append([]string{}, library.NPMName...), library.BowerName...) {
			if alias != "" {
				byAlias[slug(alias)] = name
			}
		}
	}
	for _, technology := range technologies {
		if name, ok := libraryOverrides[technology]; ok {
			if name != "" {
				database.TechnologyLibraries[technology] = name
			}
			continue
		}
		if name := matchLibrary(technology, byKey, byAlias); name != "" {
			database.TechnologyLibraries[technology] = name
		}
	}
	return nil
}

// libraryOverrides pins technologies whose npm names collide with a different product
// (npm "angular" is AngularJS 1.x, not Angular) or whose slug is ambiguous.
var libraryOverrides = map[string]string{
	"Angular":   "",
	"jQuery UI": "jquery-ui",
}

// matchLibrary prefers a library whose own name matches over one that merely lists the
// name as an npm or Bower alias.
func matchLibrary(technology string, byKey, byAlias map[string]string) string {
	candidates := []string{slug(technology), strings.TrimSuffix(slug(technology), "js")}
	for _, lookup := range []map[string]string{byKey, byAlias} {
		for _, candidate := range candidates {
			if name, ok := lookup[candidate]; ok {
				return name
			}
		}
	}
	return ""
}

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	return nonAlphanumeric.ReplaceAllString(strings.ToLower(s), "")
}

// nameList accepts the Retire.js convention of a single name or a list of names.
type nameList []string

func (n *nameList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*n = nameList{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*n = many
	return nil
}

func (n nameList) first() string {
	if len(n) == 0 {
		return ""
	}
	return n[0]
}
