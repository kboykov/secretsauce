# SecretSauce

A browser extension that automatically detects exposed API endpoints and secrets on any web page you visit, with built-in OSINT and recon tabs for deeper target investigation. Available for both Chrome and Firefox.

![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-blue) ![Manifest V3](https://img.shields.io/badge/Manifest-V3-green) ![Firefox Extension](https://img.shields.io/badge/Firefox-Extension-orange) ![Manifest V2](https://img.shields.io/badge/Manifest-V2-yellow)

## Project Status

SecretSauce is currently in an actively usable prototype state with a growing suite of recon tabs alongside the core scanning engine.

- Current focus: reliable same-host discovery, persistent hostname-scoped aggregation, a full-page review workflow, and integrated OSINT lookups
- Working today: live scanning, SPA route rescans, hostname-based deduplicated logs, host-scoped export, reopening the app against previously scanned data, and one-click access to DNS records, historical data, subdomains, web health checks, and Wayback Machine URL enumeration
- Current UX model: the Endpoints and Secrets tabs show the merged deduplicated result set for the current hostname by combining the live tab scan with the saved hostname log; all recon tabs are automatically scoped to the same hostname
- Recommended workflow: keep the extension reloaded in Developer mode while iterating so content script and service worker changes are always current

## Features

### Core Scanning
- **Endpoint Detection** - discovers API endpoints via DOM scanning (`a[href]`, `form[action]`, `iframe[src]`, etc.), inline script pattern matching with `new URL()` resolution, and regex analysis of fetched external JS/JSON files
- **Secret Detection** - scans page content and scripts against 60+ regex patterns covering AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, and more
- **Persistent Finding Log** - all discovered secrets and endpoints are appended to durable hostname-scoped `chrome.storage.local` logs, deduplicated across scans, and kept across page navigations and browser restarts
- **Full-Page App** - clicking the extension icon opens a dedicated tab with a sidebar layout; no cramped popup
- **Live Polling** - results update in real time as scripts are fetched and scanned
- **Filter & Search** - filter endpoints by HTTP method, filter secrets by severity (critical / high / medium / low)
- **Export** - download the current scan plus the current hostname log as a JSON file, or as a plain-text file (one URL or secret value per line)
- **Badge Counter** - secret count shown on the extension icon

### OSINT & Recon Tabs
- **DNS Records** — opens SecurityTrails DNS record view for the current hostname directly inside the app
- **Historical Data** — opens SecurityTrails A-record history for the current hostname
- **Subdomains** — opens SecurityTrails subdomain enumeration for the root domain
- **Web Check** — opens a web-check.xyz health and security report for the current hostname
- **Wayback Machine** — queries the Wayback Machine CDX API and renders all archived URLs for the current hostname in a filterable, sortable data table with per-row copy and bulk export

## Wayback Machine Tab

The Wayback Machine tab fetches up to 10,000 archived URLs from `web.archive.org` for the current hostname on first open and presents them in an interactive table.

**Columns:** URL · MIME type · First seen · Last seen · Snapshot count

**Toolbar controls:**
- Full-text search — filters by URL and MIME type simultaneously
- MIME type dropdown — `text/html` is always listed first, followed by all other types alphabetically
- Sort selector — first seen (newest/oldest), last seen (newest/oldest), URL (A–Z / Z–A), snapshot count (most/fewest)
- URL count indicator showing the number of currently visible rows
- **Copy all URLs** — copies the filtered URL list to the clipboard
- **Export TXT** — downloads the filtered URL list as a `.txt` file (one URL per line)

Filters and sort reset automatically when switching to a different hostname. Data is cached for the session so re-opening the tab does not re-fetch.

## Detection Approach

### Endpoints
1. DOM element scan - `a[href]`, `form[action]`, `iframe[src]`, `script[src]`, `link[href]`, `img[src]`, `source/video/audio[src]`; all resolved via `new URL(attr, location.href)` and filtered to the current hostname
2. Inline script scan - six regex patterns (absolute URLs, `../`/`./` relative paths, `api/`-prefix paths, fetch/XHR calls, URL property assignments) with full `new URL` resolution
3. External script scan - fetches all `<script src>` and lazy-chunk URLs, runs the same regex suite against the full text

### Secrets
Patterns loaded from `rules/secrets.json` (62 rules). Each match is filtered for false positives (template literals, placeholder strings, repeated characters, variable-name shapes).

### Persistent Logging
Live per-tab scan data is stored under `scan_<tabId>` for the active page, while background-managed `findings_log_host_v1_<hostname>` entries keep a deduplicated history of secrets and endpoints for each hostname. Secret log entries are deduplicated by value and endpoint log entries are deduplicated by method + URL, with occurrence counts, timestamps, sources, and page URLs merged into each record.

### Current App Behavior
- The `Endpoints` and `Secrets` tabs are hostname-scoped, not page-scoped
- Reopening the app falls back to the saved hostname log when a live content-script connection is unavailable
- Export includes the current live scan, the current hostname log, and the merged hostname-level finding set
- All recon tabs (DNS, Historical Data, Subdomains, Web Check, Wayback Machine) are automatically scoped to the hostname of the page being scanned

## Installation

### Chrome
1. Clone the repo
2. Go to `chrome://extensions`, enable **Developer mode**
3. Click **Load unpacked** and select the repo root folder

### Firefox

**Option A — Install signed release (recommended)**
1. Download `secretsauce-1.3.0.xpi` from the [`releases/`](releases/) folder
2. In Firefox go to `about:addons` → gear icon → **Install Add-on From File** and select the `.xpi`

**Option B — Load unpacked for development**
1. Clone the repo
2. Go to `about:debugging` → **This Firefox** → **Load Temporary Add-on**
3. Select any file inside the `secretsauce-firefox/` folder (e.g. `manifest.json`)

## File Structure

```
/                             Chrome extension (Manifest V3)
├── manifest.json             Extension manifest (MV3)
├── background.js             Service worker - opens app tab, manages badge, merges hostname logs
├── content.js                Content script - DOM scan, inline scan, external JS fetch & regex
├── app.html / app.js         Full-page results app + hostname log summary/export
├── app.css                   Carbon/Midnight dark theme
├── rules/secrets.json        Secret detection patterns
└── icons/                    PNG icons (16, 48, 128)

secretsauce-firefox/          Firefox extension (Manifest V2)
├── manifest.json             Extension manifest (MV2) with gecko settings
├── background.js             Background script using browserAction API
├── content.js                Content script (identical behaviour)
├── app.html / app.js         Full-page results app (DOM-safe, no innerHTML)
├── app.css                   Carbon/Midnight dark theme
├── rules/secrets.json        Secret detection patterns
└── icons/                    PNG icons (16, 48, 128)

releases/
└── secretsauce-1.3.0.xpi    Signed Firefox release
```

## Tabs Overview

| Tab | Type | Data source |
|-----|------|-------------|
| Endpoints | Live + stored | Content script + `chrome.storage.local` |
| Secrets | Live + stored | Content script + `chrome.storage.local` |
| DNS Records | Embedded | SecurityTrails |
| Historical Data | Embedded | SecurityTrails |
| Subdomains | Embedded | SecurityTrails |
| Web Check | Embedded | web-check.xyz |
| Wayback Machine | Fetched + rendered | Wayback Machine CDX API |

## Usage

Navigate to any page and click the SecretSauce icon in the toolbar. The app tab opens and begins scanning immediately. Use **Rescan** to re-run on the current page state. Switch to any recon tab to pull up external intelligence for the same hostname without leaving the app.

## Firefox vs Chrome — Key Differences

| | Chrome | Firefox |
|---|---|---|
| Manifest | V3 | V2 |
| Background | Service worker | Persistent background script |
| Toolbar API | `chrome.action` | `chrome.browserAction` |
| Script injection | `chrome.scripting.executeScript` | `chrome.tabs.executeScript` |
| Min version | — | 140.0 (desktop) / 142.0 (Android) |
