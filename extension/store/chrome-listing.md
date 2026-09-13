# Chrome Web Store listing — copy-paste reference

Package: `npm run build && npm run package:chrome` → `dist-artifacts/wappacvelyze-chrome-<version>.zip`
(upload that zip; the `browser_specific_settings` key in the manifest is Firefox-only and Chrome ignores it with a warning).

## Store listing

**Name:** WappaCVElyze

**Summary** (132 characters max):
See the technologies behind any site with their versions, colour-coded by known CVEs, end-of-life and active exploitation.

**Description:**
WappaCVElyze identifies the web technologies behind the page you are on — server software, CMS, frameworks, JavaScript libraries — and, unlike a plain technology detector, shows the detected version and whether that version is safe.

Each technology gets a verdict:
• Current — newest release of a maintained cycle, no known CVE
• Outdated — no known CVE, but a newer release exists
• End of life — the release cycle no longer receives fixes
• Vulnerable — a CVE applies to this exact version, with the affected range, CVSS, EPSS exploitation probability and public-exploit flags
• Critical — the CVE is on CISA's Known Exploited Vulnerabilities catalog

Every red row links to the NVD record, the CISA entry and the vendor advisory that confirm it.

Verdicts come from a small database built daily from public sources (NVD, CISA KEV, FIRST EPSS, endoflife.date, Retire.js, Nuclei and Metasploit exploit indexes) and downloaded once a day. Page content is analysed locally and never leaves your browser; the site you visit is never sent anywhere.

Open source (MIT): https://github.com/xZoroo/wappacvelyze — a command-line scanner with the same verdicts is included.

**Category:** Developer Tools · **Language:** English

**Store icon:** `chrome-icon-128.png` (128×128, 96 px mark with 16 px padding)
**Screenshots (1280×800):** `chrome-screenshot-1-verdicts.png`, `chrome-screenshot-2-dark.png`, `chrome-screenshot-3-outdated.png`
**Small promo tile (440×280):** `chrome-promo-440x280.png`

**Homepage URL:** https://github.com/xZoroo/wappacvelyze
**Support URL:** https://github.com/xZoroo/wappacvelyze/issues

## Privacy tab

**Single purpose:** Identify the technologies and versions used by the current website and show whether those versions have known vulnerabilities.

**Permission justifications**

| Permission | Justification |
|---|---|
| `webRequest` | Reads the response headers of pages the user loads (e.g. `Server`, `X-Powered-By`), the most reliable source of server software versions. Never blocks or modifies requests. |
| Host permissions (`<all_urls>`) | Detection must work on whichever site the user is viewing, and the response-header observation above requires host access. Also used to download the public vulnerability database from GitHub. |
| `cookies` | Some technologies are identified by the cookies they set; only cookie names referenced by the fingerprint database are read, in memory, and never stored or transmitted. |
| `tabs` | Associates results with the tab they belong to and shows the badge count on the toolbar icon. |
| `storage`, `unlimitedStorage` | Stores settings, the ~1.5 MB vulnerability database and 24-hour lookup caches locally. |

**Remote code:** No — the extension bundles all code; only data (the vulnerability database and public vulnerability feeds) is fetched.

**Data usage disclosures:** Website content is processed locally to detect technologies and is not collected, transmitted or stored beyond the per-tab result. No personally identifiable information, health, financial, authentication, personal communications, location, web history, user activity or other data is collected. Certify: data is not sold, not used for purposes unrelated to the item's core functionality, and not used for creditworthiness or lending.

**Privacy policy URL:** https://github.com/xZoroo/wappacvelyze/blob/main/PRIVACY.md

## Submission steps

1. https://chrome.google.com/webstore/devconsole — one-time developer registration ($5).
2. New item → upload the zip → fill the Store listing, Privacy and Distribution tabs from this file → Submit for review.
3. Reviews for extensions with broad host permissions typically take a few days; expect a request for the privacy justification if anything is unclear.
