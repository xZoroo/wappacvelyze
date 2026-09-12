// Package detect identifies web technologies and their versions from HTTP responses
// using the wappalyzergo fingerprint engine.
package detect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// UserAgent is sent with every scan request.
const UserAgent = "github.com/xZoroo/wappacvelyze/0.1"

// MaxBodyBytes caps how much of a response body is fingerprinted.
const MaxBodyBytes = 5 << 20

// Technology is a web technology detected on a target.
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	CPE        string   `json:"cpe,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Website    string   `json:"website,omitempty"`
	Icon       string   `json:"icon,omitempty"`
}

// Detector fingerprints HTTP responses.
type Detector struct {
	engine *wappalyzer.Wappalyze
	client *http.Client
}

// New loads the embedded fingerprint database. A nil client uses a 15 second timeout.
func New(client *http.Client) (*Detector, error) {
	engine, err := wappalyzer.New()
	if err != nil {
		return nil, fmt.Errorf("load fingerprint database: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Detector{engine: engine, client: client}, nil
}

// Scan fetches rawURL and fingerprints the response. A URL without a scheme is fetched
// over HTTPS. Redirects are followed and the final response is analyzed.
func (d *Detector) Scan(ctx context.Context, rawURL string) ([]Technology, error) {
	target, err := NormalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", target, err)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", target, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", target, err)
	}
	return d.Analyze(resp.Header, body), nil
}

// Analyze fingerprints an already fetched response without touching the network.
// Results are sorted by name.
func (d *Detector) Analyze(headers http.Header, body []byte) []Technology {
	known := d.engine.GetFingerprints().Apps
	found := d.engine.FingerprintWithInfo(headers, body)
	techs := make([]Technology, 0, len(found))
	for key, info := range found {
		name, version := splitKey(key, known)
		techs = append(techs, Technology{
			Name:       name,
			Version:    version,
			CPE:        info.CPE,
			Categories: info.Categories,
			Website:    info.Website,
			Icon:       info.Icon,
		})
	}
	sort.Slice(techs, func(i, j int) bool { return techs[i].Name < techs[j].Name })
	return techs
}

// splitKey separates wappalyzergo's "Name:version" result keys. A key that is itself a
// fingerprint name carries no version, even if the name contains a colon.
func splitKey(key string, known map[string]*wappalyzer.Fingerprint) (string, string) {
	if _, ok := known[key]; ok {
		return key, ""
	}
	i := strings.LastIndex(key, ":")
	if i < 0 {
		return key, ""
	}
	return key[:i], key[i+1:]
}

// NormalizeURL validates a scan target, defaulting to the https scheme.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty target URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse target %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("target %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("target %q: missing host", raw)
	}
	return u.String(), nil
}
