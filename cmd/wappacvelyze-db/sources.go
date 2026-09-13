package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Sources lists every feed the builder reads; tests point them at local servers.
type Sources struct {
	NVDFeed    string // printf pattern with the year, e.g. .../nvdcve-2.0-%d.json.gz
	KEV        string
	EPSS       string
	Nuclei     string
	Metasploit string
	EndOfLife  string
	Retire     string
	FirstYear  int
	LastYear   int
}

func DefaultSources() Sources {
	return Sources{
		NVDFeed:    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz",
		KEV:        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		EPSS:       "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
		Nuclei:     "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
		Metasploit: "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
		EndOfLife:  "https://endoflife.date/api/v1/products/full",
		Retire:     "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json",
		FirstYear:  2002,
		LastYear:   time.Now().UTC().Year(),
	}
}

const userAgent = "wappacvelyze-db/0.1 (+https://github.com/xZoroo/wappacvelyze)"

type fetcher struct {
	client *http.Client
}

// open returns the response body for url, retrying transient failures a few times.
func (f fetcher) open(ctx context.Context, url string) (io.ReadCloser, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := f.client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
		if err == nil {
			resp.Body.Close()
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		lastErr = fmt.Errorf("fetch %s: %w", url, err)
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 5 * time.Second):
			}
		}
	}
	return nil, lastErr
}

// openGzip opens url and transparently decompresses it when it is gzip-encoded.
func (f fetcher) openGzip(ctx context.Context, url string) (io.ReadCloser, error) {
	body, err := f.open(ctx, url)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(body)
	if err != nil {
		body.Close()
		return nil, fmt.Errorf("decompress %s: %w", url, err)
	}
	return struct {
		io.Reader
		io.Closer
	}{zr, body}, nil
}
