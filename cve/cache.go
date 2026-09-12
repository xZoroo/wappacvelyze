package cve

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Cache persists NVD lookups so repeated scans of the same technology version stay
// within the API rate limit. Entries are keyed by versioned CPE name and expire after ttl.
type Cache struct {
	path    string
	ttl     time.Duration
	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	StoredAt        time.Time       `json:"stored_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// OpenCache loads the cache at path, starting empty when the file does not exist.
func OpenCache(path string, ttl time.Duration) (*Cache, error) {
	c := &Cache{path: path, ttl: ttl, entries: map[string]cacheEntry{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read NVD cache: %w", err)
	}
	if err := json.Unmarshal(data, &c.entries); err != nil {
		return nil, fmt.Errorf("NVD cache %s is corrupt (%v); run `wappacvelyze cache clear`",
			path, err)
	}
	return c, nil
}

// Get returns an unexpired lookup for key.
func (c *Cache) Get(key string) ([]Vulnerability, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Since(e.StoredAt) > c.ttl {
		return nil, false
	}
	return slices.Clone(e.Vulnerabilities), true
}

// Put stores a lookup result, drops expired entries and persists the cache to disk.
func (c *Cache) Put(key string, vulns []Vulnerability) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if time.Since(e.StoredAt) > c.ttl {
			delete(c.entries, k)
		}
	}
	c.entries[key] = cacheEntry{StoredAt: time.Now(), Vulnerabilities: slices.Clone(vulns)}
	data, err := json.Marshal(c.entries)
	if err != nil {
		return fmt.Errorf("encode NVD cache: %w", err)
	}
	if err := writeFileAtomic(c.path, data); err != nil {
		return fmt.Errorf("write NVD cache: %w", err)
	}
	return nil
}

// Clear discards every entry and removes the cache file.
func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]cacheEntry{}
	if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove NVD cache: %w", err)
	}
	return nil
}

// writeFileAtomic replaces path in one rename so a crash never leaves a partial file. The
// temporary file is created exclusively with a random name, so a pre-planted symlink
// cannot redirect the write.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
