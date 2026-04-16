# SecretSauce

A Chrome extension that automatically detects exposed API endpoints and secrets on any web page you visit.

![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-blue) ![Manifest V3](https://img.shields.io/badge/Manifest-V3-green)

## Project Status

SecretSauce is currently in an actively usable prototype state.

- Current focus: reliable same-host discovery, persistent hostname-scoped aggregation, and a full-page review workflow
- Working today: live scanning, SPA route rescans, hostname-based deduplicated logs, host-scoped export, and reopening the app against previously scanned data
- Current UX model: the Endpoints and Secrets tabs show the merged deduplicated result set for the current hostname by combining the live tab scan with the saved hostname log
- Recommended workflow: keep the extension reloaded in Developer mode while iterating so content script and service worker changes are always current

## Features

- **Endpoint Detection** - discovers API endpoints via DOM scanning (`a[href]`, `form[action]`, `iframe[src]`, etc.), inline script pattern matching with `new URL()` resolution, and regex analysis of fetched external JS/JSON files
- **Secret Detection** - scans page content and scripts against 60+ regex patterns covering AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, and more
- **Persistent Finding Log** - all discovered secrets and endpoints are appended to durable hostname-scoped `chrome.storage.local` logs, deduplicated across scans, and kept across page navigations and browser restarts
- **Full-Page App** - clicking the extension icon opens a dedicated tab with a sidebar layout; no cramped popup
- **Live Polling** - results update in real time as scripts are fetched and scanned
- **Filter & Search** - filter endpoints by HTTP method, filter secrets by severity (critical / high / medium / low)
- **Export** - download the current scan plus the current hostname log as a JSON file
- **Badge Counter** - secret count shown on the extension icon

## Detection Approach

### Endpoints
1. DOM element scan - `a[href]`, `form[action]`, `iframe[src]`, `script[src]`, `link[href]`, `img[src]`, `source/video/audio[src]`; all resolved via `new URL(attr, location.href)` and filtered to the current hostname
2. Inline script scan - six regex patterns (absolute URLs, `../`/`./` relative paths, `api/`-prefix paths, fetch/XHR calls, URL property assignments) with full `new URL` resolution
3. External script scan - fetches all `<script src>` and lazy-chunk URLs, runs the same regex suite against the full text

### Secrets
Patterns loaded from `rules/secrets.json` (62 rules). Each match is filtered for false positives (template literals, placeholder strings, repeated characters, variable-name shapes).

### Persistent Logging
Live per-tab scan data is still stored under `scan_<tabId>` for the active page, while background-managed `findings_log_host_v1_<hostname>` entries keep a deduplicated history of secrets and endpoints for each hostname. Secret log entries are deduplicated by value and endpoint log entries are deduplicated by method + URL, with occurrence counts, timestamps, sources, and page URLs merged into each record.

### Current App Behavior
- The visible `Endpoints` and `Secrets` tabs are hostname-scoped, not page-scoped
- Reopening the app can fall back to the saved hostname log when a live content-script connection is unavailable
- Export includes the current live scan, the current hostname log, and the merged hostname-level finding set

## Installation

1. Clone the repo
2. Go to `chrome://extensions`, enable **Developer mode**
3. Click **Load unpacked** and select the repo folder

## File Structure

```
manifest.json         Extension manifest (MV3)
background.js         Service worker - opens app tab, manages badge, merges hostname logs
content.js            Content script - DOM scan, inline scan, external JS fetch & regex
app.html / app.js     Full-page results app + hostname log summary/export
app.css               Carbon/Midnight dark theme
rules/secrets.json    Secret detection patterns
icons/                PNG icons (16, 48, 128)
```

## Usage

Navigate to any page and click the SecretSauce icon in the toolbar. The app tab opens and begins scanning immediately. Use **Rescan** to re-run on the current page state.
