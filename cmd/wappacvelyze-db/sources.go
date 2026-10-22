package main

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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

// newHTTPClient speaks HTTP/1.1 only. NVD's feeds are served through Cloudflare, which
// resets HTTP/2 streams after roughly 90 seconds; the larger yearly feeds download slowly
// enough to hit that on every attempt (stream ID 1 of a brand-new connection included),
// while the same download over HTTP/1.1 completes.
//
// The ALPN list must be replaced too: a clone of http.DefaultTransport inherits
// NextProtos ["h2", "http/1.1"], so the server would still negotiate HTTP/2 and send
// frames that an HTTP/1-only transport reads as a malformed response.
func newHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	transport.Protocols = &protocols
	transport.TLSClientConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
	return &http.Client{Timeout: timeout, Transport: transport}
}

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

// downloadAttempts bounds resume requests, not restarts: each one continues from the last
// byte received, so a flaky server only has to keep up long enough to make progress.
const downloadAttempts = 20

var downloadBackoff = 2 * time.Second

// download fetches url into a temporary file, resuming with a Range request whenever the
// connection drops mid-body. NVD's Cloudflare edge does not cache the feeds and drops slow
// transfers at random points (curl over HTTP/1.1 sees it too), so restarting from zero can
// fail indefinitely on a large feed while resuming always makes progress. The caller removes
// the file.
func (f fetcher) download(ctx context.Context, url string) (path string, err error) {
	file, err := os.CreateTemp("", "wappacvelyze-feed-*")
	if err != nil {
		return "", err
	}
	defer func() {
		file.Close()
		if err != nil {
			os.Remove(file.Name())
		}
	}()
	var have int64
	for attempt := 1; ; attempt++ {
		total, err := f.appendRange(ctx, url, file, &have)
		if err == nil && have == total {
			return file.Name(), nil
		}
		if err == nil {
			err = fmt.Errorf("received %d of %d bytes", have, total)
		}
		if attempt == downloadAttempts {
			return "", fmt.Errorf("download %s: %w", url, err)
		}
		fmt.Fprintf(os.Stderr, "%s: connection dropped at %d bytes (%v), resuming\n", url, have, err)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(downloadBackoff):
		}
	}
}

// appendRange requests the bytes after *have, appends them to file and returns the
// resource's full size.
func (f fetcher) appendRange(ctx context.Context, url string, file *os.File, have *int64) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	if *have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", *have))
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var total int64
	switch resp.StatusCode {
	case http.StatusOK: // a fresh start, or a server that ignored the Range header
		if err := file.Truncate(0); err != nil {
			return 0, err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return 0, err
		}
		*have = 0
		total = resp.ContentLength
	case http.StatusPartialContent:
		total, err = rangeTotal(resp.Header.Get("Content-Range"), *have)
		if err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if total < 0 {
		return 0, errors.New("server did not report the size")
	}
	n, err := io.Copy(file, resp.Body)
	*have += n
	return total, err
}

// rangeTotal returns the full size from a Content-Range header, checking it resumes at start.
func rangeTotal(header string, start int64) (int64, error) {
	var first, last, total int64
	if _, err := fmt.Sscanf(header, "bytes %d-%d/%d", &first, &last, &total); err != nil || first != start {
		return 0, fmt.Errorf("unexpected Content-Range %q for offset %d", header, start)
	}
	return total, nil
}
