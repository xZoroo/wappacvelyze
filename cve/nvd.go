package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DefaultNVDBaseURL is the NVD CVE API 2.0 endpoint.
const DefaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDDetailURL prefixes a CVE ID to form its public NVD page.
const NVDDetailURL = "https://nvd.nist.gov/vuln/detail/"

const (
	userAgent       = "github.com/xZoroo/wappacvelyze/0.1"
	nvdPageSize     = 2000
	nvdWindow       = 30 * time.Second
	nvdPublicBudget = 5
	nvdKeyedBudget  = 50
	nvdRetryDelay   = 6 * time.Second
	nvdMaxAttempts  = 3
)

var errThrottled = errors.New("NVD rate limit reached")

// Vulnerability is a published CVE that applies to a detected technology version.
type Vulnerability struct {
	ID            string    `json:"id"`
	Severity      string    `json:"severity,omitempty"`
	Score         float64   `json:"score,omitempty"`
	Description   string    `json:"description,omitempty"`
	Published     string    `json:"published,omitempty"`
	URL           string    `json:"url"`
	Advisory      string    `json:"advisory,omitempty"`
	AffectedRange string    `json:"affected_range,omitempty"`
	KEV           *KEVEntry `json:"kev,omitempty"`
	// EPSS is FIRST's probability of exploitation within 30 days, when the database has it.
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	// Exploits names public exploit sources ("nuclei", "metasploit") that cover the CVE.
	Exploits []string `json:"exploits,omitempty"`
}

// NVDClient queries the NVD CVE API, pacing requests to stay within its rate limit.
type NVDClient struct {
	HTTP       *http.Client
	BaseURL    string
	APIKey     string
	limiter    *limiter
	retryDelay time.Duration
}

// NewNVDClient builds a client. Without an API key NVD allows 5 requests per 30 seconds;
// with one it allows 50.
func NewNVDClient(client *http.Client, apiKey string) *NVDClient {
	budget := nvdPublicBudget
	if apiKey != "" {
		budget = nvdKeyedBudget
	}
	return &NVDClient{
		HTTP:       client,
		BaseURL:    DefaultNVDBaseURL,
		APIKey:     apiKey,
		limiter:    newLimiter(budget, nvdWindow),
		retryDelay: nvdRetryDelay,
	}
}

// VulnerabilitiesFor returns every CVE that applies to the concrete version in cpeName.
// NVD pre-filters by version server-side; each result is re-checked locally so that
// unscoped wildcard records do not flag every version. The result is never nil: an empty
// slice means no known CVE applies.
func (c *NVDClient) VulnerabilitiesFor(
	ctx context.Context, cpeName string,
) ([]Vulnerability, error) {
	target, err := productFromCPEName(cpeName)
	if err != nil {
		return nil, err
	}
	vulns := []Vulnerability{}
	for start := 0; ; {
		page, err := c.fetchPage(ctx, cpeName, start)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Vulnerabilities {
			affected, ok := item.CVE.applicableRange(target)
			if !ok {
				continue
			}
			v := item.CVE.toVulnerability()
			v.AffectedRange = affected
			vulns = append(vulns, v)
		}
		start += len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || start >= page.TotalResults {
			return vulns, nil
		}
	}
}

func (c *NVDClient) fetchPage(ctx context.Context, cpeName string, start int) (*nvdPage, error) {
	req, err := c.newRequest(ctx, cpeName, start)
	if err != nil {
		return nil, err
	}
	for attempt := 1; ; attempt++ {
		if err := c.limiter.wait(ctx); err != nil {
			return nil, err
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("query NVD for %s: %w", cpeName, err)
		}
		page, err := decodePage(resp, cpeName)
		if !errors.Is(err, errThrottled) || attempt >= nvdMaxAttempts {
			return page, err
		}
		if err := sleep(ctx, c.retryDelay); err != nil {
			return nil, err
		}
	}
}

func (c *NVDClient) newRequest(ctx context.Context, cpeName string, start int) (*http.Request, error) {
	query := url.Values{}
	query.Set("cpeName", cpeName)
	query.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
	query.Set("startIndex", strconv.Itoa(start))
	endpoint := c.BaseURL + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build NVD request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	return req, nil
}

// decodePage parses an NVD response. NVD signals throttling with HTTP 403 and reports
// rejected queries in a "message" header.
func decodePage(resp *http.Response, cpeName string) (*nvdPage, error) {
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var page nvdPage
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			return nil, fmt.Errorf("decode NVD response for %s: %w", cpeName, err)
		}
		return &page, nil
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return nil, fmt.Errorf("%w (HTTP %d) querying %s; set NVD_API_KEY to raise the limit",
			errThrottled, resp.StatusCode, cpeName)
	default:
		reason := resp.Header.Get("message")
		if reason == "" {
			reason = resp.Status
		}
		return nil, fmt.Errorf("NVD rejected query for %s: %s", cpeName, reason)
	}
}

type nvdPage struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []nvdCPEMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// nvdMetric carries baseSeverity at the top level for CVSS v2 and inside cvssData for
// v3 and later.
type nvdMetric struct {
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

func (c nvdCVE) toVulnerability() Vulnerability {
	v := Vulnerability{
		ID:        c.ID,
		Published: c.Published,
		URL:       NVDDetailURL + c.ID,
		Advisory:  c.advisory(),
	}
	v.Score, v.Severity = c.cvss()
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			v.Description = d.Value
			break
		}
	}
	return v
}

// cvss returns the score from the newest CVSS version NVD has recorded.
func (c nvdCVE) cvss() (float64, string) {
	for _, metrics := range [][]nvdMetric{c.Metrics.V40, c.Metrics.V31, c.Metrics.V30, c.Metrics.V2} {
		if len(metrics) == 0 {
			continue
		}
		m := metrics[0]
		severity := m.CVSSData.BaseSeverity
		if severity == "" {
			severity = m.BaseSeverity
		}
		return m.CVSSData.BaseScore, strings.ToUpper(severity)
	}
	return 0, ""
}

// advisory picks the most authoritative reference: a vendor advisory, then a patch, then
// whatever NVD lists first.
func (c nvdCVE) advisory() string {
	for _, tag := range []string{"Vendor Advisory", "Patch", ""} {
		for _, ref := range c.References {
			if tag == "" || slices.Contains(ref.Tags, tag) {
				return ref.URL
			}
		}
	}
	return ""
}
