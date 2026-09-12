# WappaCVElyze

Detect the technologies behind a website — and find out whether the *versions* you're
looking at have known vulnerabilities.

Wappalyzer-style tools tell you a site runs Nginx or WordPress. WappaCVElyze tells you it
runs **Nginx 1.18.0**, that this version is affected by **CVE-2021-23017**, and links you to
the NVD record and vendor advisory that confirm it. Results are color-coded so the answer
is readable at a glance:

| Status | Meaning |
|---|---|
| 🟢 **CURRENT** | Version detected; no published CVE applies to it |
| 🟡 **UNKNOWN** | Technology detected but no verdict possible (version not disclosed, no CPE mapping, version too coarse) |
| 🔴 **VULNERABLE** | At least one CVE in the National Vulnerability Database applies to this exact version |
| 🚨 **CRITICAL (KEV)** | An applicable CVE is on CISA's Known Exploited Vulnerabilities catalog — it is being exploited in the wild |

```
$ wappacvelyze scan https://example-shop.test

https://example-shop.test
  TECHNOLOGY          VERSION  STATUS          DETAILS
  Apache HTTP Server  2.4.49   CRITICAL (KEV)  CVE-2021-42013 CRITICAL 9.8 (+68 more)  https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2021-42013
  PHP                 8.1.12   CRITICAL (KEV)  CVE-2024-4577 CRITICAL 9.8 (+33 more)   https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2024-4577
  WordPress           6.4.1    VULNERABLE      CVE-2024-31210 HIGH 7.6 (+2 more)       https://nvd.nist.gov/vuln/detail/CVE-2024-31210
  jQuery              3.6.0    CURRENT         no known CVEs
  MySQL               —        UNKNOWN         version not disclosed
```

The project ships as a **command-line tool** today. A **browser extension** that shows the
same verdicts in a popup is the next milestone — see [Browser extension](#browser-extension-planned).

---

## Contents

- [Installation](#installation)
- [Using the CLI](#using-the-cli)
- [How it works](#how-it-works)
- [Browser extension (planned)](#browser-extension-planned)
- [Project layout](#project-layout)
- [Development](#development)
- [Limitations](#limitations)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Installation

You need **Go 1.25 or newer** (`go version`). Any of the following gives you a
`wappacvelyze` command you can run by name from any directory, like `ls` or `whoami`.

### Option A — `go install` (one command)

```sh
go install github.com/xZoroo/wappacvelyze/cmd/wappacvelyze@latest
```

Go compiles the tool and drops the binary in `$(go env GOPATH)/bin` (usually `~/go/bin`).
If `wappacvelyze` isn't found afterwards, that directory isn't on your `PATH` yet — see
[Putting the binary on your PATH](#putting-the-binary-on-your-path).

> While the repository is private, tell Go to fetch it over git instead of the public
> module proxy: `export GOPRIVATE=github.com/xZoroo` (and make sure `git` can
> authenticate to GitHub, e.g. via `gh auth login`).

### Option B — clone and build

```sh
git clone https://github.com/xZoroo/wappacvelyze.git
cd wappacvelyze
make build            # or: go build -o wappacvelyze ./cmd/wappacvelyze
./wappacvelyze version
```

That produces a single self-contained binary, `./wappacvelyze`, in the repository root.
To run it by name from anywhere, either install it into your Go bin directory:

```sh
make install          # or: go install ./cmd/wappacvelyze
```

…or copy the binary somewhere already on your `PATH`:

```sh
sudo mv wappacvelyze /usr/local/bin/          # system-wide
# or, without sudo:
mkdir -p ~/bin && mv wappacvelyze ~/bin/      # then add ~/bin to PATH as shown below
```

### Putting the binary on your PATH

Add the Go bin directory (or `~/bin`) to your shell's `PATH` once, then open a new terminal:

```sh
# zsh (macOS default)
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc

# bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
```

Verify with `which wappacvelyze` and `wappacvelyze version`.

---

## Using the CLI

```
wappacvelyze scan [options] <url>...
wappacvelyze cache [options] <path|clear|refresh>
wappacvelyze version
```

### Scan one or more sites

```sh
wappacvelyze scan https://example.com
wappacvelyze scan example.com other.example         # https:// is assumed
wappacvelyze scan --targets urls.txt                # one URL per line, # comments allowed
```

### Machine-readable output

```sh
wappacvelyze scan --format json https://example.com | jq .
```

Each technology carries its verdict, the versioned CPE that was checked, and every
applicable CVE with score, severity, affected version range, NVD link, vendor advisory,
and — when present — the CISA KEV entry:

```json
[
  {
    "url": "https://example.com",
    "technologies": [
      {
        "technology": {
          "name": "WordPress",
          "version": "6.4.1",
          "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
          "categories": ["CMS", "Blogs"],
          "website": "https://wordpress.org"
        },
        "status": "vulnerable",
        "cpe_name": "cpe:2.3:a:wordpress:wordpress:6.4.1:*:*:*:*:*:*:*",
        "vulnerabilities": [
          {
            "id": "CVE-2024-31210",
            "severity": "HIGH",
            "score": 7.6,
            "published": "2024-04-04T15:15:38.417",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-31210",
            "advisory": "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-x79f-xrjv-jx5r",
            "affected_range": ">= 6.4.0, < 6.4.3"
          }
        ]
      },
      {
        "technology": { "name": "MySQL", "categories": ["Databases"] },
        "status": "unknown",
        "reason": "version not disclosed"
      }
    ]
  }
]
```

(Trimmed for brevity; each vulnerability also includes an English `description`, and
KEV hits carry a `kev` object with CISA's vulnerability name, date added, due date, and
required action.)

### Use it as a CI / pipeline gate

```sh
wappacvelyze scan --targets prod-hosts.txt --fail-on critical
wappacvelyze scan --fail-on vulnerable https://staging.example
```

Exit status:

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding reached the `--fail-on` threshold (or no threshold set) |
| `1` | At least one technology reached the `--fail-on` status |
| `2` | Error — bad arguments, a target could not be fetched, or CVE data was unavailable |

### All `scan` options

| Flag | Default | Purpose |
|---|---|---|
| `--format table\|json` | `table` | Output format |
| `--targets <file>` | | Read additional URLs from a file |
| `--fail-on vulnerable\|critical` | | Exit `1` if any technology reaches this status |
| `--no-cve` | `false` | Detect technologies only; skip all CVE lookups (no network calls to NVD/CISA) |
| `--nvd-api-key <key>` | `$NVD_API_KEY` | NVD API key; raises the rate limit from 5 to 50 requests per 30 s |
| `--cache-dir <dir>` | OS cache dir | Where NVD results and the KEV catalog are cached |
| `--timeout <duration>` | `15s` | Per-request HTTP timeout when fetching targets |
| `--no-color` | `false` | Disable ANSI colors (also honours the `NO_COLOR` environment variable) |

### NVD API key

Without a key, NVD allows **5 requests per 30 seconds**; the tool paces itself and retries,
so large scans are slow but work. A free key raises that to 50 — request one at
<https://nvd.nist.gov/developers/request-an-api-key> and export it:

```sh
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Caching

Lookups are cached for 24 hours so repeated scans of the same technology version never hit
the network twice:

```sh
wappacvelyze cache path       # print the cache directory
wappacvelyze cache refresh    # re-download the CISA KEV catalog now
wappacvelyze cache clear      # delete cached NVD results and the KEV catalog
```

The default location is `~/Library/Caches/wappacvelyze` on macOS,
`~/.cache/wappacvelyze` on Linux, and `%LocalAppData%\wappacvelyze` on Windows.

---

## How it works

```
 URL ──▶ fetch ──▶ fingerprint ──▶ version + CPE ──▶ NVD ──▶ applicability ──▶ KEV ──▶ verdict
                  (wappalyzergo)                    (API 2.0)   re-check       (CISA)
```

1. **Fetch.** The target is requested once over HTTP(S), following redirects. Only the
   final response's headers and first 5 MB of body are analysed; no JavaScript is executed.

2. **Fingerprint.** The response is matched against the [Wappalyzer fingerprint
   database](https://github.com/enthec/webappanalyzer) via the
   [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) engine. Patterns such
   as `Server: nginx/1.24.0` or `<meta name="generator" content="WordPress 6.4.1">` capture
   the **version**, and most server-side technologies carry a **CPE** identifier — the
   naming scheme NVD uses (`cpe:2.3:a:f5:nginx:*:…`).

3. **Build the versioned CPE.** The captured version is spliced into the CPE
   (`cpe:2.3:a:f5:nginx:1.24.0:…`). No version → `UNKNOWN`. No CPE → `UNKNOWN`. A
   single-number version such as `PHP 8` → `UNKNOWN` ("too coarse"), because matching it
   against every 8.x advisory would produce false alarms.

4. **Query NVD.** The versioned CPE is sent to the NVD CVE API 2.0, which returns every
   CVE whose applicability statements cover that version.

5. **Re-check applicability locally.** NVD holds many old records whose affected-product
   criteria were never scoped (`wordpress:wordpress:*` with no version bounds), and they
   would flag every version ever released. Each returned CVE's configurations are therefore
   re-evaluated against the detected version: exact-version matches and bounded ranges
   count, unbounded wildcards do not. The matching range is kept as `affected_range`.

6. **Cross-reference CISA KEV.** Every applicable CVE ID is looked up in CISA's Known
   Exploited Vulnerabilities catalog (cached locally, refreshed daily). A hit promotes the
   verdict to `CRITICAL`.

7. **Rank.** Within a technology, vulnerabilities are ordered KEV first, then by CVSS score.
   Within a scan, technologies are ordered by urgency so the worst news is at the top.

---

## Browser extension (planned)

The second deliverable is a Manifest V3 extension for Chrome, Edge, and Firefox that shows
the same verdicts when you click its toolbar icon on any page. It is **not built yet**; this
section documents the intended design so the CLI's data model can serve as its contract.

**What you'll see.** A popup listing detected technologies grouped by category (Web server,
CMS, JavaScript framework, CDN, …). Each row shows a status dot, the technology name, its
version, a badge (`Current` / `Unknown` / `CVE-2024-4577` / `KEV · CVE-2021-44228`), and a
link to the NVD record or CISA entry. Rows sort `Critical → Vulnerable → Unknown → Current`;
categories with nothing above `Unknown` collapse by default.

**How it will work.**

- A **content script** collects the DOM-side evidence the fingerprint database needs:
  `<meta>` tags, `<script src>` URLs, and JavaScript globals such as `jQuery.fn.jquery`.
  Because it runs inside the rendered page it can see versions the passive CLI cannot.
- A **background service worker** captures response headers (`Server`, `X-Powered-By`,
  cookies), runs the fingerprint engine, and performs the same NVD → applicability → KEV
  pipeline as the CLI, with the cache held in `chrome.storage.local` because MV3 workers
  are short-lived.
- The **popup** is a rendering layer over the same JSON shape the CLI emits with
  `--format json`; the four statuses and their meanings are identical.

---

## Project layout

```
cmd/wappacvelyze/   CLI: argument parsing, table/JSON rendering, cache subcommands
detect/             Technology detection — thin wrapper over wappalyzergo
cve/                NVD API client, CISA KEV loader, applicability check, cache, classifier
Makefile            build / install / test shortcuts
```

The upstream projects this design was distilled from (`wappalyzer`, `wappalyzergo`,
`webanalyze`, `webappanalyzer`) are kept as untracked reference checkouts next to this
code and are excluded via `.gitignore`.

---

## Development

```sh
make test     # go test ./...
make vet      # go vet ./...
make fmt      # gofmt -w
make build    # ./wappacvelyze
```

Tests are self-contained: NVD and CISA responses are served by in-process test servers, and
fingerprinting is exercised against synthetic headers and HTML. No network access is needed.

To try the full pipeline against something guaranteed to light up red, point the scanner at
a local server that advertises old versions:

```sh
python3 -c '
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(s):
        s.send_response(200); s.send_header("Server","Apache/2.4.49")
        s.send_header("X-Powered-By","PHP/8.1.12"); s.end_headers(); s.wfile.write(b"<html></html>")
HTTPServer(("127.0.0.1",8765),H).serve_forever()' &
wappacvelyze scan http://127.0.0.1:8765
```

---

## Limitations

- **Passive detection only.** The CLI does not run JavaScript, so technologies that only
  reveal themselves at runtime (and their versions) can be missed. The browser extension
  will close that gap.
- **A version is not always disclosed.** Hardened servers strip version tokens; the tool
  reports `UNKNOWN` rather than guessing. `UNKNOWN` is not a clean bill of health.
- **CPE naming drift.** NVD sometimes files a product under more than one vendor
  (older nginx CVEs use `nginx:nginx`, newer ones `f5:nginx`); the fingerprint database
  carries one CPE per technology, so CVEs filed under an alias can be missed.
- **NVD data quality.** Applicability statements are curated by hand and are occasionally
  wrong or missing; treat a red result as "go read the advisory", not as proof of
  exploitability.
- **Rate limits.** Without an NVD API key, scanning many distinct technology versions is
  slow by design (5 requests / 30 s).

---

## License

[MIT](LICENSE). The fingerprint database bundled through wappalyzergo originates from
[enthec/webappanalyzer](https://github.com/enthec/webappanalyzer), which is GPL-3.0 licensed.

## Acknowledgements

- [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) by ProjectDiscovery —
  the Go fingerprint engine this tool builds on.
- [webappanalyzer](https://github.com/enthec/webappanalyzer) by Enthec — the community
  continuation of the Wappalyzer fingerprint database.
- [NVD](https://nvd.nist.gov/) (NIST) and the [CISA Known Exploited Vulnerabilities
  catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for vulnerability data.
