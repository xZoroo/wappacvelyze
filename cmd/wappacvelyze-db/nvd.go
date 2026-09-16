package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/xZoroo/wappacvelyze/db"
)

// nvdRecord holds the fields of an NVD 2.0 feed entry that the database keeps.
type nvdRecord struct {
	ID        string `json:"id"`
	Published string `json:"published"`
	Metrics   struct {
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
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdMetric struct {
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// ingestNVDFeed streams one yearly feed, keeping every CVE whose applicability statements
// name a product in the database. Feeds are hundreds of megabytes decompressed, so the
// vulnerabilities array is decoded one element at a time.
func ingestNVDFeed(ctx context.Context, f fetcher, url string, database *db.Database) (int, error) {
	body, err := f.openGzip(ctx, url)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	dec := json.NewDecoder(body)
	if err := seekArray(dec, "vulnerabilities"); err != nil {
		return 0, fmt.Errorf("%s: %w", url, err)
	}
	kept := 0
	for dec.More() {
		if ctx.Err() != nil {
			return kept, ctx.Err()
		}
		var item struct {
			CVE nvdRecord `json:"cve"`
		}
		if err := dec.Decode(&item); err != nil {
			return kept, fmt.Errorf("%s: decode record: %w", url, err)
		}
		if ingestRecord(item.CVE, database) {
			kept++
		}
	}
	return kept, nil
}

// seekArray advances the decoder to just inside the array stored under key at the top level.
func seekArray(dec *json.Decoder, key string) error {
	if _, err := dec.Token(); err != nil { // opening brace
		return err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if tok == key {
			if _, err := dec.Token(); err != nil { // opening bracket
				return err
			}
			return nil
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return fmt.Errorf("key %q not found", key)
}

// ingestRecord attaches the record's matches to any product it names.
func ingestRecord(record nvdRecord, database *db.Database) bool {
	matched := false
	for _, configuration := range record.Configurations {
		for _, node := range configuration.Nodes {
			for _, m := range node.CPEMatch {
				key, version := productKey(m.Criteria)
				product, ok := database.Products[key]
				if !m.Vulnerable || !ok {
					continue
				}
				match := db.Match{
					Version:               version,
					VersionStartIncluding: m.VersionStartIncluding,
					VersionStartExcluding: m.VersionStartExcluding,
					VersionEndIncluding:   m.VersionEndIncluding,
					VersionEndExcluding:   m.VersionEndExcluding,
				}
				// A feed can list the same applicability statement twice, and a retried
				// (possibly partially ingested) year must not double it either.
				if !slices.Contains(product.Matches[record.ID], match) {
					product.Matches[record.ID] = append(product.Matches[record.ID], match)
				}
				matched = true
			}
		}
	}
	if matched && database.Vulnerabilities[record.ID] == nil {
		database.Vulnerabilities[record.ID] = toVulnerability(record)
	}
	return matched
}

func toVulnerability(record nvdRecord) *db.Vulnerability {
	v := &db.Vulnerability{ID: record.ID, Published: record.Published, Advisory: advisory(record)}
	for _, metrics := range [][]nvdMetric{record.Metrics.V40, record.Metrics.V31, record.Metrics.V30, record.Metrics.V2} {
		if len(metrics) == 0 {
			continue
		}
		v.Score = metrics[0].CVSSData.BaseScore
		v.Severity = strings.ToUpper(metrics[0].CVSSData.BaseSeverity)
		if v.Severity == "" {
			v.Severity = strings.ToUpper(metrics[0].BaseSeverity)
		}
		break
	}
	return v
}

func advisory(record nvdRecord) string {
	for _, tag := range []string{"Vendor Advisory", "Patch", ""} {
		for _, ref := range record.References {
			if tag == "" || slices.Contains(ref.Tags, tag) {
				return ref.URL
			}
		}
	}
	return ""
}

// productKey reduces a CPE 2.3 name to its "vendor:product" key and version field. The
// version is empty for product-level names such as endoflife.date's identifiers.
func productKey(cpe string) (string, string) {
	fields := splitCPE(cpe)
	if len(fields) < 5 || fields[0] != "cpe" || fields[1] != "2.3" {
		return "", ""
	}
	version := ""
	if len(fields) > 5 {
		version = unescape(fields[5])
	}
	return strings.ToLower(fields[3]) + ":" + strings.ToLower(fields[4]), version
}

func splitCPE(s string) []string {
	var fields []string
	var field strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == ':':
			fields = append(fields, field.String())
			field.Reset()
			continue
		}
		field.WriteRune(r)
	}
	return append(fields, field.String())
}

func unescape(s string) string {
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if r == '\\' && !escaped {
			escaped = true
			continue
		}
		escaped = false
		b.WriteRune(r)
	}
	return b.String()
}
