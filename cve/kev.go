package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultKEVURL is the CISA Known Exploited Vulnerabilities catalog feed.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// kevCatalogURL is the human-readable catalog, searchable by CVE ID.
const kevCatalogURL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext="

// KEVEntry records that CISA has confirmed a CVE is exploited in the wild.
type KEVEntry struct {
	CVEID              string `json:"cveID"`
	VendorProject      string `json:"vendorProject"`
	Product            string `json:"product"`
	VulnerabilityName  string `json:"vulnerabilityName"`
	DateAdded          string `json:"dateAdded"`
	ShortDescription   string `json:"shortDescription"`
	RequiredAction     string `json:"requiredAction"`
	DueDate            string `json:"dueDate"`
	KnownRansomwareUse string `json:"knownRansomwareCampaignUse"`
	URL                string `json:"url,omitempty"`
}

// KEVCatalog indexes the CISA catalog by CVE ID.
type KEVCatalog struct {
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`

	once  sync.Once
	index map[string]KEVEntry
}

// Lookup reports whether id is in the catalog, matching case-insensitively.
func (k *KEVCatalog) Lookup(id string) (KEVEntry, bool) {
	k.once.Do(func() {
		k.index = make(map[string]KEVEntry, len(k.Vulnerabilities))
		for _, e := range k.Vulnerabilities {
			e.URL = kevCatalogURL + url.QueryEscape(e.CVEID)
			k.index[strings.ToUpper(e.CVEID)] = e
		}
	})
	e, ok := k.index[strings.ToUpper(id)]
	return e, ok
}

// Len returns the number of catalog entries.
func (k *KEVCatalog) Len() int {
	return len(k.Vulnerabilities)
}

// FetchKEV downloads the catalog from feedURL.
func FetchKEV(ctx context.Context, client *http.Client, feedURL string) (*KEVCatalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build KEV request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch KEV catalog: %s", resp.Status)
	}
	var catalog KEVCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode KEV catalog: %w", err)
	}
	if len(catalog.Vulnerabilities) == 0 {
		return nil, errors.New("KEV catalog is empty; the feed format may have changed")
	}
	return &catalog, nil
}

// LoadKEV returns the catalog cached at cachePath when it is younger than maxAge and
// otherwise downloads a fresh copy. If the download fails but a stale cache exists, the
// stale catalog is returned together with the error so callers can warn and continue.
func LoadKEV(
	ctx context.Context, client *http.Client, feedURL, cachePath string, maxAge time.Duration,
) (*KEVCatalog, error) {
	cached, age, cacheErr := readKEVCache(cachePath)
	if cacheErr == nil && age <= maxAge {
		return cached, nil
	}
	fresh, err := FetchKEV(ctx, client, feedURL)
	if err != nil {
		if cached != nil {
			return cached, fmt.Errorf("%w (using copy cached %s ago)", err, age.Round(time.Minute))
		}
		return nil, err
	}
	data, err := json.Marshal(fresh)
	if err != nil {
		return nil, fmt.Errorf("encode KEV cache: %w", err)
	}
	if err := writeFileAtomic(cachePath, data); err != nil {
		return nil, fmt.Errorf("write KEV cache: %w", err)
	}
	return fresh, nil
}

func readKEVCache(path string) (*KEVCatalog, time.Duration, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var catalog KEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, 0, fmt.Errorf("decode KEV cache %s: %w", path, err)
	}
	return &catalog, time.Since(info.ModTime()), nil
}
