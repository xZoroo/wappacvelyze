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
	"time"

	"github.com/xZoroo/wappacvelyze/cve"
)

const (
	kevFile   = "kev.json"
	nvdFile   = "nvd.json"
	kevMaxAge = 24 * time.Hour
	nvdTTL    = 24 * time.Hour
)

// defaultCacheDir is empty when the OS cache directory is unknown; the caches then
// require an explicit --cache-dir rather than falling back to a world-writable temp dir.
func defaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "wappacvelyze")
}

func requireCacheDir(dir string) error {
	if dir == "" {
		return errors.New("no user cache directory available; pass --cache-dir")
	}
	return nil
}

func runCache(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cache", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cacheDir := fs.String("cache-dir", defaultCacheDir(), "directory holding the NVD and KEV caches")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wappacvelyze cache [options] <path|clear|refresh>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if err := requireCacheDir(*cacheDir); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	switch fs.Arg(0) {
	case "path":
		fmt.Fprintln(stdout, *cacheDir)
		return exitOK
	case "clear":
		return cacheClear(*cacheDir, stdout, stderr)
	case "refresh":
		return cacheRefresh(*cacheDir, stdout, stderr)
	default:
		fs.Usage()
		return exitError
	}
}

func cacheClear(dir string, stdout, stderr io.Writer) int {
	for _, name := range []string{kevFile, nvdFile} {
		err := os.Remove(filepath.Join(dir, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
	}
	fmt.Fprintln(stdout, "cache cleared:", dir)
	return exitOK
}

func cacheRefresh(dir string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := &http.Client{Timeout: 60 * time.Second}
	kev, err := cve.LoadKEV(ctx, client, cve.DefaultKEVURL, filepath.Join(dir, kevFile), 0)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "KEV catalog %s: %d entries (released %s)\n",
		kev.CatalogVersion, kev.Len(), kev.DateReleased)
	return exitOK
}
