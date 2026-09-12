// Command gen-extension-data writes the fingerprint database, category names and runtime
// collection rules that the browser extension bundles. They come from the same
// wappalyzergo release the CLI uses, so both surfaces detect identically.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-extension-data <output-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	engine, err := wappalyzer.New()
	if err != nil {
		return fmt.Errorf("load fingerprints: %w", err)
	}
	var db struct {
		Apps map[string]map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal([]byte(wappalyzer.GetRawFingerprints()), &db); err != nil {
		return fmt.Errorf("parse fingerprints: %w", err)
	}
	for _, app := range db.Apps {
		for _, key := range []string{"description", "icon", "css"} {
			delete(app, key)
		}
	}
	files := map[string]any{
		"technologies.json":  db.Apps,
		"categories.json":    wappalyzer.GetCategoriesMapping(),
		"runtime-rules.json": engine.RuntimeRules(),
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, value := range files {
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("encode %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
