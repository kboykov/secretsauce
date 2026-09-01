# SecretSauce

A browser extension that detects exposed secrets, API keys and API endpoints on any page you visit, keeps a deduplicated per-host log across sessions, and bundles the OSINT lookups you reach for next (DNS, history, subdomains, web check, Wayback Machine). One codebase, shipped for Chrome (MV3) and Firefox (MV2).

![Chrome](https://img.shields.io/badge/Chrome-MV3-blue) ![Firefox](https://img.shields.io/badge/Firefox-MV2-orange) ![Tests](https://img.shields.io/badge/tests-node%20--test-green) ![Deps](https://img.shields.io/badge/dependencies-0-lightgrey)

## What it does

**Scanning (content script)**
- **Endpoints** from DOM attributes (`a[href]`, `form[action]`, `script[src]`, `data-*`, htmx `hx-*` …), inline scripts, same-site JS/JSON bundles, and the browser's own network history (Performance API), including URLs requested after page load.
- **Call-site aware detection**: `fetch()`, `axios.*`, `$.ajax`, `xhr.open`, generic HTTP clients, Express-style routes, `new WebSocket(...)`. Methods come from the call when known and are guessed from the nearest verb otherwise.
- **Template paths**: `` `/api/users/${id}` `` is captured as `/api/users/{id}` instead of being dropped.
- **Secrets** via 116 rules (`src/rules/secrets.json`) plus a tuned high-entropy heuristic, with false-positive filtering for placeholders, digests, identifiers and integrity hashes.
- **SPA aware**: rescans on route changes (URL polling plus `popstate` / `hashchange` / Navigation API).
- **Persistent host log**: findings are merged into `chrome.storage.local` per hostname with occurrence counts, first/last seen, pages and sources, quota-safe.

**App (full-page tab)**
- Endpoints and Secrets views with search (supports `-term` exclusion), method / severity chips, source-kind filter, rule filter, sorting, expand-all, incremental rendering for thousands of results.
- Per-finding actions: copy, copy as cURL, open, **dismiss** (per-host false-positive list you can review and restore).
- **Hosts** view: every stored host with counts, severity breakdown, open / delete.
- **Settings**: toggle external-script fetching, subdomain scope, entropy heuristic, SPA rescans, excluded hosts (`*.example.com`), per-rule enable/disable, theme, badge colouring, data wipe.
- **Export**: JSON (full report), CSV (endpoints / secrets), TXT (URLs / secrets / both).
- **Recon**: SecurityTrails DNS, A-record history and subdomains, web-check.xyz, and a Wayback Machine CDX table with type filters, an "interesting URLs" toggle, copy / export.
- **Rail and drawer layout**: a 56px rail holds the sections (with live count badges), Rescan, Export and theme; a collapsible target drawer shows host, scan status, a severity ledger and coverage figures. Press `B` or click the logo to toggle it; the state is remembered and it auto-collapses on narrow windows.
- Dark and light themes, keyboard shortcuts (`/` search, `R` rescan, `B` drawer, `Alt+1…9` sections, `Alt+Shift+S` opens the app from any tab).
- Toolbar badge coloured by the highest severity found on the tab.

## Repository layout

```
src/                      ← the Chrome extension, loadable as-is (no build step)
├── manifest.json         Chrome MV3 manifest
├── shared.js             SS namespace: storage wrappers, hostname helpers, host-log merge
├── detect.js             SSDetect: pure detection engine (secrets, entropy, endpoints)
├── content.js            Content script: orchestrates scanning, persists results
├── background.js         Cross-browser background (feature-detects MV2/MV3 APIs)
├── app.html / app.css    Full-page app shell + design system
├── app/
│   ├── ui.js             DOM helpers, icons, toasts, clipboard, downloads
│   ├── findings.js       Live + stored merge, filters, sorting, CSV
│   ├── render.js         Cards, tables, incremental lists
│   ├── recon.js          Embedded tools + Wayback Machine
│   └── main.js           Controller: state, polling, settings, hosts, export
├── rules/secrets.json    Detection rules
├── rules/frame_rules.json  declarativeNetRequest rules (Chrome only)
└── icons/

manifests/firefox.json    Firefox MV2 manifest (swapped in by the build)
build.mjs                 Zero-dependency build → dist/chrome, dist/firefox (+ zips)
test/                     node --test suites for the detection engine and rules
dev/                      Preview harness (mock chrome API) + screenshot script
docs/IMPROVEMENTS.md      Review notes and roadmap
releases/                 Signed Firefox releases
```

The content script, background and app all load `shared.js` (and the content script also `detect.js`) as plain classic scripts, so there is no bundler and no duplication between browsers.

## Install

### Chrome (development)
1. Clone the repo.
2. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the **`src/`** folder.
3. Edit files in `src/` and hit reload on the extensions page.

### Firefox
```bash
node build.mjs            # → dist/firefox/  and  dist/secretsauce-firefox-<version>.zip
```
- Temporary: `about:debugging` → **This Firefox** → **Load Temporary Add-on** → pick `dist/firefox/manifest.json`.
- Signed release: install the `.xpi` from [`releases/`](releases/) via `about:addons` → gear → **Install Add-on From File**. To publish a new version, upload `dist/secretsauce-firefox-<version>.zip` to AMO.

### Build script
```bash
node build.mjs                    # build both targets and zips into dist/
node build.mjs --watch            # rebuild on change
node build.mjs --set-version 1.5.0
npm test                          # detection + rules test-suite
```
The build validates that both manifests share a version and that every referenced file exists.

## Usage

Open any page and click the toolbar icon (or press `Alt+Shift+S`). The app opens next to the page and starts showing results as the scan progresses. Everything you see is the merge of the live tab scan with the saved log for that hostname, so revisiting a site accumulates knowledge over time. Use **Rescan** to re-run against the current page state; if the page was loaded before the extension was installed, Rescan injects the scanner for you.

Findings never leave the browser. The recon tabs open third-party sites (SecurityTrails, web-check.xyz, archive.org) with the target hostname in the URL, and the Chrome build strips `X-Frame-Options` / CSP on those two frame hosts only so they can be embedded.

## Development

```bash
node dev/preview-server.mjs        # http://127.0.0.1:4173/preview.html — the real app with a mocked chrome.* API
node dev/screenshot.mjs            # headless screenshots of every view into dev/screenshots/ (needs playwright-core)
```
Preview scenarios: `?scenario=full|scanning|stored|empty&theme=dark|light&host=example.com`.

### Adding a detection rule
Append to `src/rules/secrets.json`:
```json
{ "id": "vendor_token", "name": "Vendor API Token", "severity": "high", "regex": "\\bvt_[A-Za-z0-9]{40}\\b" }
```
- Regexes are JavaScript syntax. A leading `(?i)` is translated to the `i` flag.
- If the credential is a capture group after some context (e.g. `password\s*=\s*['"]([^'"]+)`), the group is reported; otherwise the whole match is.
- Run `npm test` — it compiles every rule, checks for duplicate ids and runs known-format samples.

## Chrome vs Firefox

| | Chrome | Firefox |
|---|---|---|
| Manifest | V3 (`src/manifest.json`) | V2 (`manifests/firefox.json`) |
| Background | Service worker (`importScripts('shared.js')`) | Event page (`scripts: [shared.js, background.js]`) |
| Toolbar API | `chrome.action` | `chrome.browserAction` |
| Injection | `chrome.scripting.executeScript` | `chrome.tabs.executeScript` |
| Frame header stripping | `declarativeNetRequest` | `webRequest` blocking listener |

All of the above is feature-detected inside `background.js`; there is no per-browser source.

## License

MIT
