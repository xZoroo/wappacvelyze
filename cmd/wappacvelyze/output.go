package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xZoroo/wappacvelyze/cve"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiBoldRed = "\x1b[1;31m"
)

var tableHeader = []string{"TECHNOLOGY", "VERSION", "STATUS", "DETAILS"}

type palette struct{ enabled bool }

func (p palette) paint(code, s string) string {
	if !p.enabled || code == "" || s == "" {
		return s
	}
	return code + s + ansiReset
}

func statusStyle(s cve.Status) (label, code string) {
	switch s {
	case cve.StatusCurrent:
		return "CURRENT", ansiGreen
	case cve.StatusVulnerable:
		return "VULNERABLE", ansiRed
	case cve.StatusCritical:
		return "CRITICAL (KEV)", ansiBoldRed
	default:
		return "UNKNOWN", ansiYellow
	}
}

// colorEnabled follows the NO_COLOR convention and only colors interactive terminals.
func colorEnabled(w io.Writer, disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func writeJSON(w io.Writer, results []scanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func writeTable(w io.Writer, results []scanResult, color bool) error {
	bw := bufio.NewWriter(w)
	p := palette{enabled: color}
	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(bw)
		}
		fmt.Fprintln(bw, p.paint(ansiBold, r.URL))
		switch {
		case r.Error != "":
			fmt.Fprintf(bw, "  %s\n", p.paint(ansiRed, "error: "+r.Error))
		case len(r.Technologies) == 0:
			fmt.Fprintf(bw, "  %s\n", p.paint(ansiDim, "no technologies detected"))
		default:
			writeRows(bw, r.Technologies, p)
		}
	}
	return bw.Flush()
}

func writeRows(w io.Writer, techs []cve.Assessment, p palette) {
	rows := make([][]string, len(techs))
	for i, a := range techs {
		rows[i] = tableRow(a)
	}
	widths := columnWidths(append([][]string{tableHeader}, rows...))
	fmt.Fprintf(w, "  %s\n", p.paint(ansiDim, joinPadded(tableHeader, widths)))
	for i, a := range techs {
		_, code := statusStyle(a.Status)
		detailCode := ""
		if a.Status.Rank() < cve.StatusVulnerable.Rank() {
			detailCode = ansiDim
		}
		cells := rows[i]
		fmt.Fprintf(w, "  %s  %s  %s  %s\n",
			pad(cells[0], widths[0]),
			pad(cells[1], widths[1]),
			p.paint(code, pad(cells[2], widths[2])),
			p.paint(detailCode, cells[3]))
	}
}

func tableRow(a cve.Assessment) []string {
	version := a.Technology.Version
	if version == "" {
		version = "—"
	}
	label, _ := statusStyle(a.Status)
	return []string{printable(a.Technology.Name), printable(version), label, printable(detail(a))}
}

// printable drops control characters so a server cannot smuggle terminal escape
// sequences into the table through a crafted version string or header.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// detail summarises the most urgent CVE with a link that confirms it, or explains why
// no verdict was possible.
func detail(a cve.Assessment) string {
	switch a.Status {
	case cve.StatusCurrent:
		return "no known CVEs"
	case cve.StatusUnknown:
		return a.Reason
	}
	top := a.Vulnerabilities[0]
	summary := top.ID
	if top.Severity != "" {
		summary += fmt.Sprintf(" %s %.1f", top.Severity, top.Score)
	}
	if more := len(a.Vulnerabilities) - 1; more > 0 {
		summary += fmt.Sprintf(" (+%d more)", more)
	}
	link := top.URL
	if top.KEV != nil {
		link = top.KEV.URL
	}
	return summary + "  " + link
}

func columnWidths(rows [][]string) []int {
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	return widths
}

func joinPadded(cells []string, widths []int) string {
	padded := make([]string, len(cells))
	for i, cell := range cells {
		padded[i] = pad(cell, widths[i])
	}
	return strings.TrimRight(strings.Join(padded, "  "), " ")
}

func pad(s string, width int) string {
	return s + strings.Repeat(" ", width-utf8.RuneCountInString(s))
}
