# Privacy Policy — WappaCVElyze

*Effective 13 September 2026. Applies to the WappaCVElyze browser extension and command-line tool.*

WappaCVElyze identifies the technologies behind the websites you visit and checks whether
the detected versions have known vulnerabilities. It is open source, has no server of its
own, no accounts, no analytics and no telemetry, and it never sells or shares data. This
document describes exactly what it processes, what leaves your browser, and why.

## Summary

- Everything the extension observes about a page is processed **inside your browser** and
  is never transmitted anywhere.
- The only outbound requests are for **public vulnerability data**: a daily download of a
  prebuilt database from GitHub, the CISA Known Exploited Vulnerabilities feed, and — only
  for products the database does not cover — a query to NIST's NVD API containing the
  product name and version, never the site you were visiting.
- Results are kept **per tab** and discarded when the tab navigates or closes.

## What the extension processes locally

To detect technologies, the extension reads the following from pages you visit. All of it
stays on your device and is used only for pattern matching against the technology
fingerprint database bundled with the extension:

| Data | Why | Kept where, for how long |
|---|---|---|
| HTTP response headers of the page (only header names the fingerprint database references, e.g. `Server`, `X-Powered-By`) | Servers announce software and versions in headers | In session storage for the tab, until the tab navigates or closes |
| Cookie **names and values** (only cookie names the fingerprint database references) | Some technologies are identified by the cookies they set | In memory during detection only; never stored |
| Page HTML, `<meta>` tags, script URLs, inline script text (size-capped) | Fingerprints match markup and script references | In memory during detection only; never stored |
| Selected JavaScript globals (e.g. `jQuery.fn.jquery`, `next.version`) and DOM attributes named by the fingerprint rules | Frameworks expose their version at runtime | In memory during detection only; never stored |
| The page URL's origin | To associate headers with the page they came from and to label results | In session storage for the tab, until the tab navigates or closes |

What is kept per tab is the **result**: technology names, detected versions, verdicts and
the vulnerability details shown in the popup. Page content itself is not retained.

## What leaves your browser, and to whom

The extension makes network requests only to the services below. Each sees your IP address
and the extension's User-Agent, as any HTTPS request does.

| Request | Destination | What is sent | When |
|---|---|---|---|
| Vulnerability database (`latest.json`, `wappacvelyze-db.json.gz`) | GitHub Releases for this project (or a URL you configure) | Nothing about you or your browsing | About once every 24 hours |
| Known Exploited Vulnerabilities catalog | CISA (`cisa.gov`) | Nothing about you or your browsing | About once every 24 hours |
| CVE lookup for a product the database does not cover | NIST NVD API (`nvd.nist.gov`) | The product's CPE name and version (e.g. `cpe:2.3:a:f5:nginx:1.18.0`), plus your NVD API key if you chose to configure one | Only when such a product is detected; results cached for 24 hours |

The site you were visiting is **never** included in any request. Technology logos are
bundled with the extension and are not fetched from the network.

Privacy policies of those services: [GitHub](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement),
[NIST](https://www.nist.gov/privacy-policy), [CISA](https://www.cisa.gov/privacy-policy).

## What is stored on your device

| Item | Storage | Retention |
|---|---|---|
| Settings: appearance, optional NVD API key, optional database URL | `chrome.storage.local` | Until you change them or uninstall |
| Vulnerability database | Browser Cache API (extension origin) | Replaced when a newer build is published; removed on uninstall |
| Cached NVD lookup results and KEV catalog | `chrome.storage.local` | 24 hours, or until you press *Clear CVE cache* in Settings |
| Per-tab results | `chrome.storage.session` | Until the tab navigates or closes, or the browser exits |

The NVD API key is stored only in your browser's extension storage and is sent only to
`nvd.nist.gov`. It is not synced between devices.

## Permissions and why they are needed

| Permission | Purpose |
|---|---|
| `webRequest` and host access to all sites (`<all_urls>`) | Observe the response headers of pages you load — the most reliable source of server software versions — and fetch the public vulnerability data described above |
| `cookies` | Read cookies for the current site so cookie-based fingerprints can match |
| `tabs` | Associate results with the tab they belong to and show the badge count |
| `storage`, `unlimitedStorage` | Keep settings, the vulnerability database and the 24-hour caches |

The extension does not modify pages, block or alter requests, read your browsing history,
or run on pages other than those you visit.

## Your choices

- **Disable CVE lookups for uncovered products** by not configuring an NVD API key; the
  extension still queries NVD anonymously for those products. To avoid NVD entirely, use the
  command-line tool with `--no-cve`, or self-host the database and keep it complete.
- **Clear cached data** at any time with *Clear CVE cache* in Settings.
- **Remove everything** by uninstalling the extension; the browser deletes its storage.

## Command-line tool

The `wappacvelyze` CLI fetches the URLs you give it, downloads the same public vulnerability
data, and caches it in your operating system's cache directory. It sends nothing else and
collects nothing about you.

## Changes and contact

Changes to this policy are made in this repository, where the full history is public. The
version that applies is the one published with the extension release you are using.
Questions or concerns: open an issue at <https://github.com/xZoroo/wappacvelyze/issues>.
