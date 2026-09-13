# WappaCVElyze

Detect the technologies behind a website — and find out whether the *versions* you're
looking at have known vulnerabilities.

Wappalyzer-style tools tell you a site runs Nginx or WordPress. WappaCVElyze tells you it
runs **Nginx 1.18.0**, that this version is affected by **CVE-2021-23017**, and links you to
the NVD record and vendor advisory that confirm it. Results are color-coded so the answer
is readable at a glance:

| Status | Meaning |
|---|---|
| 🟢 **CURRENT** | No CVE applies and, where release data exists, this is the newest release of a maintained cycle |
| 🟡 **OUTDATED** | No CVE applies, but a newer release exists in the same cycle |
| 🟡 **UNKNOWN** | Technology detected but no verdict possible (version not disclosed, no CPE or library mapping, version too coarse) |
| 🟠 **UNSUPPORTED (EOL)** | The release cycle is end-of-life — no CVE matches yet, but fixes will not come |
| 🔴 **VULNERABLE** | At least one CVE applies to this exact version; rows are ordered exploited → public exploit → EPSS → CVSS |
| 🚨 **CRITICAL (KEV)** | An applicable CVE is on CISA's Known Exploited Vulnerabilities catalog — it is being exploited in the wild |

```
$ wappacvelyze scan https://example-shop.test

https://example-shop.test
  TECHNOLOGY          VERSION  STATUS          DETAILS
  Apache HTTP Server  2.4.49   CRITICAL (KEV)  CVE-2021-41773 CRITICAL 9.8 · EPSS 100% · exploit: nuclei, metasploit (+68 more)  https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2021-41773
  PHP                 8.1.12   CRITICAL (KEV)  CVE-2024-4577 CRITICAL 9.8 · EPSS 100% · exploit: nuclei, metasploit (+33 more)   https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2024-4577
  WordPress           6.4.1    VULNERABLE      CVE-2024-4439 HIGH 7.2 · EPSS 71% · exploit: nuclei (+2 more)  https://nvd.nist.gov/vuln/detail/CVE-2024-4439
  Nginx               1.31.3   OUTDATED        no known CVEs · latest 1.31.5 (cycle 1.31)
  jQuery              3.7.1    CURRENT         no known CVEs
  MySQL               —        UNKNOWN         version not disclosed
```

The project ships as a **command-line tool** and a **browser extension** (Chrome, Edge,
Firefox) that shows the same verdicts in a popup — see [Browser extension](#browser-extension).

---

## Contents

- [Installation](#installation)
- [Using the CLI](#using-the-cli)
- [How it works](#how-it-works)
- [Browser extension](#browser-extension)
- [Project layout](#project-layout)
- [Development](#development)
- [Limitations](#limitations)
- [Privacy](#privacy)
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
| `--fail-on outdated\|unsupported\|vulnerable\|critical` | | Exit `1` if any technology reaches this status |
| `--no-cve` | `false` | Detect technologies only; skip all CVE lookups (no network calls to NVD/CISA) |
| `--nvd-api-key <key>` | `$NVD_API_KEY` | NVD API key for live lookups of products the database lacks; raises the rate limit from 5 to 50 requests per 30 s |
| `--db-url <url>` | GitHub release | Base URL of the prebuilt vulnerability database (`latest.json` + `wappacvelyze-db.json.gz`) |
| `--no-db` | `false` | Skip the prebuilt database and query NVD live for every technology |
| `--cache-dir <dir>` | OS cache dir | Where the database, NVD results and the KEV catalog are cached |
| `--timeout <duration>` | `15s` | Per-request HTTP timeout when fetching targets |
| `--no-color` | `false` | Disable ANSI colors (also honours the `NO_COLOR` environment variable) |

### The vulnerability database

Verdicts come from a **prebuilt database** rather than live API calls. A scheduled GitHub
Actions job (`.github/workflows/db.yml`, daily) runs `cmd/wappacvelyze-db`, which:

1. streams NVD's 2.0 bulk feeds (no API key needed) and keeps every CVE whose
   applicability statements name one of the ~310 CPE products the fingerprint database
   can detect, with their version ranges;
2. joins CISA KEV (exploited in the wild), FIRST EPSS (probability of exploitation in the
   next 30 days), and exploit availability from ProjectDiscovery's Nuclei templates and
   Metasploit's module metadata;
3. attaches release cycles from endoflife.date (latest release, end-of-life) via each
   product's CPE identifier;
4. imports Retire.js's JavaScript-library advisories and links them to fingerprint names
   (jQuery, Bootstrap, Lodash, Moment.js, Next.js, …);
5. publishes `latest.json` (schema, build time, SHA-256, counts, sources) and
   `wappacvelyze-db.json.gz` (about 1.5 MB) as assets of the rolling `db` GitHub release.

Clients fetch `latest.json` once a day, download the blob only when its checksum changed,
verify it, and match versions locally. Products outside the database fall back to a live
NVD query. Rebuild it yourself with `go run ./cmd/wappacvelyze-db -out dist/db` and point
`--db-url` at any static host serving those two files.

### NVD API key

Only live fallback lookups touch NVD. Without a key, NVD allows **5 requests per 30
seconds**; the tool paces itself and retries. A free key raises that to 50 — request one at
<https://nvd.nist.gov/developers/request-an-api-key> and export it:

```sh
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Caching

The database, the KEV catalog and live NVD results are cached for 24 hours:

```sh
wappacvelyze cache path       # print the cache directory
wappacvelyze cache refresh    # re-download the database and the CISA KEV catalog now
wappacvelyze cache clear      # delete everything cached
```

The default location is `~/Library/Caches/wappacvelyze` on macOS,
`~/.cache/wappacvelyze` on Linux, and `%LocalAppData%\wappacvelyze` on Windows.

---

## How it works

```
 URL ──▶ fetch ──▶ fingerprint ──▶ version + CPE ──▶ database ──▶ applicability ──▶ verdict
                  (wappalyzergo)                    (or live NVD)   re-check      + release cycle
                                                                                 + KEV / EPSS / exploits
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

4. **Look up the product.** The prebuilt database holds every NVD applicability statement
   for the product; only products it lacks are sent to the NVD CVE API 2.0 live.

5. **Re-check applicability locally.** NVD holds many old records whose affected-product
   criteria were never scoped (`wordpress:wordpress:*` with no version bounds), and they
   would flag every version ever released. Each returned CVE's configurations are therefore
   re-evaluated against the detected version: exact-version matches and bounded ranges
   count, unbounded wildcards do not. The matching range is kept as `affected_range`.

6. **Cross-reference CISA KEV.** Every applicable CVE ID is checked against CISA's Known
   Exploited Vulnerabilities catalog. A hit promotes the verdict to `CRITICAL`.

7. **Place the version in its release cycle.** With no applicable CVE, endoflife.date data
   decides between `CURRENT` (newest release of a maintained cycle), `OUTDATED` (a newer
   release exists) and `UNSUPPORTED` (the cycle is end-of-life).

8. **Rank.** Within a technology, vulnerabilities are ordered exploited-in-the-wild first,
   then those with a public Nuclei or Metasploit exploit, then by EPSS probability, then by
   CVSS score. Within a scan, technologies are ordered by urgency so the worst news is at
   the top.

---

## Browser extension

The extension shows the same verdicts as the CLI when you click its toolbar icon on any
page — and because it runs inside the rendered page it also sees JavaScript-only evidence
(`jQuery.fn.jquery`, `React.version`, …) that a passive HTTP scan cannot.

**What you see.** A popup listing detected technologies grouped by category. Each row has the
technology's logo, its name (linked to its website), the detected version, a badge
(`Current` / `Unknown` / `CVE-2024-4577` / `KEV · CVE-2021-44228`), and for red or critical
rows the CVSS score, affected version range, and links to the NVD record or CISA KEV entry
and the vendor advisory. Rows sort `Critical → Vulnerable → Unknown → Current`. The toolbar
badge shows how many technologies are vulnerable or critical.

### Build it

Building needs Node 22+, Go 1.25+ and `tar` (Go generates the fingerprint data from the
same wappalyzergo release the CLI uses, so both surfaces detect identically; a build script
then downloads the technology logos the database references from
[enthec/webappanalyzer](https://github.com/enthec/webappanalyzer), keeping those under 16 KB
— larger or missing logos fall back to a letter tile). Both the data and the logos are
generated into `extension/src/generated/` and never committed:

```sh
make extension        # = cd extension && npm ci && npm run build
```

This produces `extension/dist/` for Chrome and Edge and `extension/dist-firefox/` for
Firefox (identical code; only the manifest's background declaration differs).

### Load it

- **Chrome / Edge / Brave:** open `chrome://extensions`, turn on *Developer mode*, click
  *Load unpacked*, and pick `extension/dist`.
- **Firefox (140+):** open `about:debugging#/runtime/this-firefox`, click *Load Temporary
  Add-on…*, and pick `extension/dist-firefox/manifest.json`. Firefox treats host permissions
  as optional in Manifest V3 — grant them from the extension's settings so headers and
  cookies can be observed. Firefox support is untested so far.

Then browse anywhere and click the toolbar icon. *Rescan page* re-collects the current
page; the half-circle / sun / moon button cycles the appearance between following the
system, light and dark; the gear opens the options page where you can pick the appearance,
store an NVD API key (only used for live lookups of products the database lacks), point the
extension at a self-hosted copy of the vulnerability database, and clear the CVE cache. Framework globals such as `next.version` often appear seconds after the page is
idle, so the page script keeps sampling for 25 seconds and the popup updates live.

### How it works

Three scripts cooperate, and the verdict pipeline is the CLI's, ported to TypeScript
(`extension/src/lib/`):

- **`page.js`** runs in the page's own JavaScript world and reads the globals and DOM
  properties the fingerprint database asks about. It never receives data from the extension.
- **`content.js`** runs in the isolated world, collects `<meta>` tags, script sources, inline
  scripts, DOM evidence and the page script's observations, and sends them to the worker.
  Everything from the page is treated as untrusted input and only ever regex-matched or
  rendered as text.
- **`background.js`** (service worker) records response headers as pages load, reads
  cookies, runs detection, then assesses each technology against the prebuilt vulnerability
  database (downloaded once a day, SHA-256 verified, kept in the Cache API) with live NVD
  as the fallback for products it lacks. Per-tab results live in `chrome.storage.session`
  and are cleared when the tab navigates or closes.

Permissions: `webRequest` and `<all_urls>` to observe response headers on every site,
`cookies` for cookie-based fingerprints, `storage`/`unlimitedStorage` for the database and
caches, `tabs` to map results to tabs. Nothing is sent anywhere except the daily database
download from GitHub, the CISA KEV feed, and — only for products the database lacks — an
NVD query; the extension has no server of its own.

---

## Project layout

```
cmd/wappacvelyze/        CLI: argument parsing, table/JSON rendering, cache subcommands
cmd/wappacvelyze-db/     Builds the prebuilt vulnerability database from NVD, KEV, EPSS, …
cmd/gen-extension-data/  Exports the fingerprint database for the extension
db/                      Database schema shared by the builder, the CLI and the extension
detect/                  Technology detection — thin wrapper over wappalyzergo
cve/                     Database loader, NVD API client, KEV loader, applicability check, classifier
extension/               Browser extension (TypeScript, Manifest V3)
  src/lib/               Detection engine and CVE pipeline, mirroring detect/ and cve/
  src/{background,content,page,popup,options}.ts
  test/                  vitest suites
  store/                 Store listing assets and text (icons, screenshots, Chrome listing)
Makefile                 build / install / test / extension shortcuts
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

cd extension
npm run data       # regenerate src/generated/ from wappalyzergo (needs Go)
npm test           # vitest
npm run typecheck  # tsc --noEmit
npm run lint       # oxlint
npm run build      # dist/ and dist-firefox/
```

Tests are self-contained: NVD and CISA responses are served by in-process test servers (Go)
or mocked `fetch` (TypeScript), and fingerprinting is exercised against synthetic headers,
HTML and JavaScript globals using the real fingerprint database. No network access is needed.

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

- **The CLI is passive.** It does not run JavaScript, so technologies that only reveal
  themselves at runtime (and their versions) can be missed; the browser extension sees them.
- **A version is not always disclosed.** Hardened servers strip version tokens; the tool
  reports `UNKNOWN` rather than guessing. `UNKNOWN` is not a clean bill of health.
- **CPE naming drift.** NVD sometimes files a product under more than one vendor
  (older nginx CVEs use `nginx:nginx`, newer ones `f5:nginx`); the fingerprint database
  carries one CPE per technology, so CVEs filed under an alias can be missed.
- **NVD data quality.** Applicability statements are curated by hand and are occasionally
  wrong or missing; treat a red result as "go read the advisory", not as proof of
  exploitability.
- **Rate limits.** Only products missing from the prebuilt database are looked up live;
  without an NVD API key those lookups are paced at 5 requests / 30 s.
- **Regex cost in the extension.** Fingerprints are regular expressions run against page
  content inside the browser, where the regex engine backtracks. Inputs are capped, bare
  quantifiers are bounded the same way wappalyzergo does, and detection stops after a
  3-second budget, but a deliberately pathological page can still make a scan of itself
  slow or incomplete (the popup then shows partial results). The CLI's Go regex engine is
  linear-time and unaffected.

## Privacy

The extension processes page content locally, keeps results only per tab, and contacts
only public vulnerability-data services — never with the site you were visiting. See
[PRIVACY.md](PRIVACY.md) for the full policy, including every network request, what is
stored where, and why each permission is needed.

## Security notes

- Nothing observed on a page leaves the browser or the machine. The only outbound requests
  are to NVD (a versioned CPE name) and CISA (the public KEV feed).
- Page content is untrusted input everywhere: the extension only regex-matches it, never
  renders it as HTML, validates page-script observations against the fingerprint rule set,
  and only links to `http(s)` URLs. Captured headers and cookies are limited to the names
  fingerprints actually read, bound to the page they came from, and kept only in
  session storage until the tab navigates or closes.
- The CLI strips control characters from anything a server can influence before printing
  to the terminal, verifies TLS, caps response bodies at 5 MB, verifies the database against
  the SHA-256 in its manifest before use, and writes its caches with exclusive temporary
  files in the user's cache directory only.
- Store the NVD API key in the `NVD_API_KEY` environment variable rather than on the command
  line, where other local users could read it from the process list.

---

## License

[MIT](LICENSE). The fingerprint database bundled through wappalyzergo originates from
[enthec/webappanalyzer](https://github.com/enthec/webappanalyzer), which is GPL-3.0 licensed.

## Acknowledgements

- [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) by ProjectDiscovery —
  the Go fingerprint engine this tool builds on.
- [webappanalyzer](https://github.com/enthec/webappanalyzer) by Enthec — the community
  continuation of the Wappalyzer fingerprint database.
- [NVD](https://nvd.nist.gov/) (NIST) for CVE records and applicability data. This product
  uses the NVD API but is not endorsed or certified by the NVD.
- The [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CC0).
- [EPSS](https://www.first.org/epss/) scores by FIRST.
- [endoflife.date](https://endoflife.date/) (MIT) for release cycles and end-of-life dates.
- [Retire.js](https://github.com/RetireJS/retire.js) (Apache-2.0) for JavaScript-library advisories.
- [ProjectDiscovery nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT)
  and the [Metasploit Framework](https://github.com/rapid7/metasploit-framework) (BSD-3-Clause)
  for exploit availability.
