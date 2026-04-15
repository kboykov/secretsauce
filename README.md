# SecretSauce

A Chrome extension that automatically detects exposed API endpoints and secrets on any web page you visit.

![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-blue) ![Manifest V3](https://img.shields.io/badge/Manifest-V3-green)

## Features

- **Endpoint Detection** — discovers API endpoints via DOM scanning (`a[href]`, `form[action]`, `iframe[src]`, etc.), inline script pattern matching with `new URL()` resolution, and regex analysis of fetched external JS/JSON files
- **Secret Detection** — scans page content and scripts against 60+ regex patterns covering AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, and more
- **Full-Page App** — clicking the extension icon opens a dedicated tab with a sidebar layout; no cramped popup
- **Live Polling** — results update in real time as scripts are fetched and scanned
- **Filter & Search** — filter endpoints by HTTP method, filter secrets by severity (critical / high / medium / low)
- **Export** — download all findings as a JSON file
- **Badge Counter** — secret count shown on the extension icon

## Detection Approach

### Endpoints
1. DOM element scan — `a[href]`, `form[action]`, `iframe[src]`, `script[src]`, `link[href]`, `img[src]`, `source/video/audio[src]`; all resolved via `new URL(attr, location.href)` and filtered to the current hostname
2. Inline script scan — six regex patterns (absolute URLs, `../`/`./` relative paths, `api/`-prefix paths, fetch/XHR calls, URL property assignments) with full `new URL` resolution
3. External script scan — fetches all `<script src>` and lazy-chunk URLs, runs the same regex suite against the full text

### Secrets
Patterns loaded from `rules/secrets.json` (62 rules). Each match is filtered for false positives (template literals, placeholder strings, repeated characters, variable-name shapes).

## Installation

1. Clone the repo
2. Run `python generate-icons.py` to generate the PNG icons
3. Go to `chrome://extensions`, enable **Developer mode**
4. Click **Load unpacked** and select the repo folder

## File Structure

```
manifest.json         Extension manifest (MV3)
background.js         Service worker — opens app tab on icon click, manages badge
content.js            Content script — DOM scan, inline scan, external JS fetch & regex
app.html / app.js     Full-page results app
app.css               Carbon/Midnight dark theme
rules/secrets.json    Secret detection patterns
icons/                PNG icons (16, 48, 128)
generate-icons.py     Icon generator (stdlib only, no dependencies)
```

## Usage

Navigate to any page and click the SecretSauce icon in the toolbar. The app tab opens and begins scanning immediately. Use **Rescan** to re-run on the current page state.
