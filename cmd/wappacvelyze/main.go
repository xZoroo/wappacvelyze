// Command wappacvelyze detects the technologies behind a website and reports which
// detected versions have known vulnerabilities.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// Version is the CLI release identifier. It is overridden by the module version when
// the binary was built with `go install ...@<version>`.
var Version = "0.1.0-dev"

const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "cache":
		return runCache(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "wappacvelyze", versionString())
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return exitError
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: wappacvelyze <command> [options]

Commands:
  scan [options] <url>...         Detect technologies and look up known CVEs
  cache [options] <path|clear|refresh>
                                  Manage the on-disk NVD and CISA KEV caches
  version                         Print the version

Exit status: 0 on success, 1 when --fail-on is met, 2 on error.
Run "wappacvelyze scan -h" or "wappacvelyze cache -h" for options.
`)
}

func versionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return Version
	}
	return info.Main.Version
}
