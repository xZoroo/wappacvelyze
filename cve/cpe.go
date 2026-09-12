// Package cve resolves detected technology versions to known vulnerabilities using the
// NVD CVE API and CISA's Known Exploited Vulnerabilities catalog.
package cve

import (
	"fmt"
	"strings"
)

const (
	cpeFieldCount   = 13
	cpeVersionIndex = 5
)

// cpeEscaper quotes the characters a CPE 2.3 formatted string reserves. Alphanumerics,
// hyphen, period and underscore are literal.
var cpeEscaper = strings.NewReplacer(
	`\`, `\\`, `!`, `\!`, `"`, `\"`, `#`, `\#`, `$`, `\$`, `%`, `\%`, `&`, `\&`, `'`, `\'`,
	`(`, `\(`, `)`, `\)`, `*`, `\*`, `+`, `\+`, `,`, `\,`, `/`, `\/`, `:`, `\:`, `;`, `\;`,
	`<`, `\<`, `=`, `\=`, `>`, `\>`, `?`, `\?`, `@`, `\@`, `[`, `\[`, `]`, `\]`, `^`, `\^`,
	"`", "\\`", `{`, `\{`, `|`, `\|`, `}`, `\}`, `~`, `\~`,
)

// CPEWithVersion returns the CPE 2.3 name for one concrete version of the product that
// cpe describes, escaping version characters as the formatted-string binding requires.
func CPEWithVersion(cpe, version string) (string, error) {
	fields := splitCPE(cpe)
	if len(fields) != cpeFieldCount || fields[0] != "cpe" || fields[1] != "2.3" {
		return "", fmt.Errorf("malformed CPE 2.3 name %q", cpe)
	}
	fields[cpeVersionIndex] = cpeEscaper.Replace(version)
	return strings.Join(fields, ":"), nil
}

// splitCPE splits on colons that are not backslash-escaped, keeping escapes intact.
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
