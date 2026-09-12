package cve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCacheRoundTripAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvd.json")
	c, err := OpenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("k"); ok {
		t.Fatal("hit on empty cache")
	}
	vulns := []Vulnerability{{ID: "CVE-1", URL: "u", Score: 9.8}}
	if err := c.Put("k", vulns); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("k")
	if !ok || len(got) != 1 || got[0].ID != "CVE-1" {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	got[0].ID = "mutated"
	if again, _ := c.Get("k"); again[0].ID != "CVE-1" {
		t.Error("Get returned shared slice")
	}

	reopened, err := OpenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reopened.Get("k"); !ok || got[0].Score != 9.8 {
		t.Fatalf("reopened Get = %+v, %v", got, ok)
	}
}

func TestCacheExpiresEntries(t *testing.T) {
	c, err := OpenCache(filepath.Join(t.TempDir(), "nvd.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c.entries["old"] = cacheEntry{StoredAt: time.Now().Add(-2 * time.Hour)}
	if _, ok := c.Get("old"); ok {
		t.Fatal("expired entry served")
	}
	if err := c.Put("new", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.entries["old"]; ok {
		t.Error("expired entry not pruned on Put")
	}
}

func TestOpenCacheRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvd.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := OpenCache(path, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "cache clear") {
		t.Fatalf("err = %v, want corrupt-cache guidance", err)
	}
}

func TestCacheClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvd.json")
	c, err := OpenCache(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Put("k", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cache file still present: %v", err)
	}
	if err := c.Clear(); err != nil {
		t.Errorf("second Clear: %v", err)
	}
}
