package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xZoroo/wappacvelyze/cve"
	"github.com/xZoroo/wappacvelyze/detect"
)

type scanOptions struct {
	format      string
	targetsFile string
	failOn      cve.Status
	apiKey      string
	cacheDir    string
	dbURL       string
	timeout     time.Duration
	noCVE       bool
	noDB        bool
	noColor     bool
	urls        []string
}

type scanResult struct {
	URL          string           `json:"url"`
	Error        string           `json:"error,omitempty"`
	Technologies []cve.Assessment `json:"technologies"`
}

func runScan(args []string, stdout, stderr io.Writer) int {
	opts, err := parseScanOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	detector, err := detect.New(&http.Client{Timeout: opts.timeout})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	assessor, err := newAssessor(ctx, opts, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}

	results := scanAll(ctx, detector, assessor, opts.urls, stderr)

	if opts.format == "json" {
		err = writeJSON(stdout, results)
	} else {
		err = writeTable(stdout, results, colorEnabled(stdout, opts.noColor))
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	return exitCode(results, opts.failOn)
}

func parseScanOptions(args []string, stderr io.Writer) (*scanOptions, error) {
	o := &scanOptions{}
	var failOn string
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.format, "format", "table", "output format: table or json")
	fs.StringVar(&o.targetsFile, "targets", "", "file with one URL per line (# comments allowed)")
	fs.StringVar(&failOn, "fail-on", "",
		"exit 1 when any technology reaches this status: vulnerable or critical")
	fs.StringVar(&o.apiKey, "nvd-api-key", os.Getenv("NVD_API_KEY"),
		"NVD API key; raises the rate limit from 5 to 50 requests per 30s (env NVD_API_KEY)")
	fs.StringVar(&o.cacheDir, "cache-dir", defaultCacheDir(), "directory for the vulnerability database and caches")
	fs.StringVar(&o.dbURL, "db-url", cve.DefaultDatabaseURL, "base URL of the prebuilt vulnerability database")
	fs.BoolVar(&o.noDB, "no-db", false, "skip the prebuilt database and query NVD live for every technology")
	fs.DurationVar(&o.timeout, "timeout", 15*time.Second, "per-request HTTP timeout")
	fs.BoolVar(&o.noCVE, "no-cve", false, "detect technologies only; skip CVE lookups")
	fs.BoolVar(&o.noColor, "no-color", false, "disable colored output (also honours NO_COLOR)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wappacvelyze scan [options] <url>...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	o.urls = fs.Args()
	if o.targetsFile != "" {
		more, err := readTargets(o.targetsFile)
		if err != nil {
			return nil, err
		}
		o.urls = append(o.urls, more...)
	}
	if len(o.urls) == 0 {
		return nil, errors.New("no targets: pass URLs or --targets <file>")
	}
	if o.format != "table" && o.format != "json" {
		return nil, fmt.Errorf("unknown --format %q (want table or json)", o.format)
	}
	if failOn != "" {
		status, err := cve.ParseStatus(failOn)
		if err != nil {
			return nil, err
		}
		if status.Rank() < cve.StatusOutdated.Rank() || status == cve.StatusUnknown {
			return nil, fmt.Errorf("--fail-on must be outdated, unsupported, vulnerable or critical, got %q", failOn)
		}
		o.failOn = status
	}
	return o, nil
}

// readTargets loads one URL per line, ignoring blank lines and # comments.
func readTargets(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets: %w", err)
	}
	var urls []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	return urls, nil
}

// newAssessor prepares lookups, or returns nil when --no-cve is set. The prebuilt database
// is preferred; when it cannot be fetched the scan continues with live NVD lookups. Stale
// copies are used with a warning rather than aborting.
func newAssessor(ctx context.Context, opts *scanOptions, stderr io.Writer) (*cve.Assessor, error) {
	if opts.noCVE {
		return nil, nil
	}
	if err := requireCacheDir(opts.cacheDir); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	assessor := &cve.Assessor{NVD: cve.NewNVDClient(client, opts.apiKey)}
	if !opts.noDB {
		database, err := cve.LoadDatabase(ctx, client, opts.dbURL, opts.cacheDir, dbMaxAge)
		if err != nil {
			fmt.Fprintln(stderr, "warning:", err)
		}
		assessor.DB = database
	}
	kev, err := cve.LoadKEV(ctx, client, cve.DefaultKEVURL, filepath.Join(opts.cacheDir, kevFile), kevMaxAge)
	if err != nil {
		if kev == nil && assessor.DB == nil {
			return nil, err
		}
		if kev == nil {
			fmt.Fprintln(stderr, "warning:", err)
		}
	}
	assessor.KEV = kev
	cache, err := cve.OpenCache(filepath.Join(opts.cacheDir, nvdFile), nvdTTL)
	if err != nil {
		return nil, err
	}
	assessor.Cache = cache
	return assessor, nil
}

func scanAll(
	ctx context.Context, detector *detect.Detector, assessor *cve.Assessor, urls []string,
	stderr io.Writer,
) []scanResult {
	results := make([]scanResult, 0, len(urls))
	for _, target := range urls {
		if ctx.Err() != nil {
			break
		}
		techs, err := detector.Scan(ctx, target)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			results = append(results, scanResult{URL: target, Error: err.Error()})
			continue
		}
		results = append(results, scanResult{
			URL:          target,
			Technologies: assessAll(ctx, assessor, techs, stderr),
		})
	}
	return results
}

// assessAll classifies each technology, most urgent first.
func assessAll(
	ctx context.Context, assessor *cve.Assessor, techs []detect.Technology, stderr io.Writer,
) []cve.Assessment {
	out := make([]cve.Assessment, 0, len(techs))
	for _, tech := range techs {
		if assessor == nil {
			out = append(out, cve.Assessment{
				Technology: tech, Status: cve.StatusUnknown, Reason: "CVE lookup skipped",
			})
			continue
		}
		assessment, err := assessor.Assess(ctx, tech)
		if err != nil {
			fmt.Fprintf(stderr, "warning: %s: %v\n", tech.Name, err)
		}
		out = append(out, assessment)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Status.Rank() > out[j].Status.Rank()
	})
	return out
}

// exitCode reports errors first, then whether any finding meets the --fail-on threshold.
func exitCode(results []scanResult, failOn cve.Status) int {
	for _, r := range results {
		if r.Error != "" {
			return exitError
		}
	}
	if failOn == "" {
		return exitOK
	}
	for _, r := range results {
		for _, a := range r.Technologies {
			if a.Status.Rank() >= failOn.Rank() {
				return exitFindings
			}
		}
	}
	return exitOK
}
