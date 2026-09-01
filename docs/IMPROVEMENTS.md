# SecretSauce — review notes, changes and roadmap

_Written during the v1.4.0 refactor (September 2026)._

## 1. What was wrong before

| # | Finding | Impact | Status |
|---|---------|--------|--------|
| 1 | Chrome and Firefox trees were ~3.5k lines of near-identical code, hand-synced. | Every fix had to be made twice; the Chrome tree was already behind (v1.0.0 vs v1.3.0). | **Fixed** — single `src/`, cross-browser `background.js`, `build.mjs` swaps manifests. |
| 2 | SPA route detection wrapped `history.pushState` inside the content-script isolated world. Page code never calls that wrapper. | Route changes in React/Vue/Angular apps never triggered a rescan; only back/forward and hash changes did. | **Fixed** — URL polling + `popstate`/`hashchange`/Navigation API. |
| 3 | `aws_access_key_id` rule had a leading alternation group, so `match[1]` was `"AKIA"`, which the false-positive filter rejected (`length < 8`). | AWS access key IDs were **never** reported. | **Fixed** — rule made non-capturing; the engine now falls back to the full match when group 1 is a prefix of it. Covered by tests. |
| 4 | Secret search only matched the *source URL*. | Typing a rule name or part of a value returned nothing. | **Fixed** — search covers name, value, rule id, source; supports `-term` exclusion. |
| 5 | Dedup via `Array.prototype.some` on every add, and every regex recompiled per `ingest()` call. | O(n²) on pages with thousands of endpoints; noticeable CPU on large bundles. | **Fixed** — `Set`/`Map` keyed dedup; rules compiled once per scan. |
| 6 | `rules/secrets.json`, `app.html`, `app.js`, `app.css` were `web_accessible_resources` for `<all_urls>`. | Any site could fetch them and fingerprint the extension (and read the rule set). | **Fixed** — rules are delivered by the background over messaging; no web-accessible resources at all. |
| 7 | No fetch timeout on external scripts. | One hanging CDN request stalled the scan indefinitely (spinner forever). | **Fixed** — 15 s `AbortController` timeout per file, progress reported (`12/40 scripts`). |
| 8 | `getRootDomain()` took the last two labels. | `shop.example.co.uk` was scoped to `co.uk` → every `.co.uk` site was "same-site". | **Fixed** — multi-label suffix list (ccTLD SLDs + common hosting suffixes). |
| 9 | High-entropy detector flagged SRI hashes (`sha384-…`), ids, digests. | Noise in the Secrets tab. | **Fixed** — label-aware skipping, digest-length hex requires a credential-ish label, JWT-shaped values left to the JWT rule. |
| 10 | Broad path regex re-reported URLs already found by call-site patterns with a *different guessed method*. | Duplicate cards (`GET /x` and `POST /x`) for one call. | **Fixed** — explicit-method matches claim the URL; broad patterns can't re-add it. |
| 11 | Every poll (900 ms) re-created the entire card list with `innerHTML`. | DOM churn with thousands of cards; innerHTML also blocks AMO review, which is why Firefox had a separate DOM-safe copy. | **Fixed** — DOM-built cards everywhere, incremental rendering (80 per chunk, IntersectionObserver). |
| 12 | No way to dismiss false positives or manage stored hosts; storage grew silently. | Findings lists filled with noise; no visibility into what was stored. | **Fixed** — per-host dismiss list with review/restore; Hosts view; data controls in Settings. |
| 13 | `parseNetworkEntry` had `initiator === 'fetch' ? 'GET' : 'GET'`. | Dead code, method always GET (Performance API doesn't expose it). | Cleaned up; still GET by design (see roadmap item on `webRequest`). |
| 14 | `openai_api_key` (`sk-[A-Za-z0-9_-]{40,}`) also matched Anthropic keys. | Same value reported under two names. | **Fixed** — OpenAI rule anchored on the `T3BlbkFJ` marker; a separate medium-severity "sk-…" catch-all excludes known prefixes. |

## 2. What was added

- **Detection**: 36 new rules (Groq, Perplexity, Discord, Doppler, Postman, Pulumi, Grafana, New Relic, Notion, Airtable, Databricks, GitHub `ghu_`, Slack app/config tokens, Sourcegraph, age, Azure AD client secret, Fastly, Stripe `whsec_`, Dropbox, HubSpot, Okta, Terraform Cloud, NuGet, PyPI, RubyGems, Brevo, DigitalOcean OAuth, LaunchDarkly, S3 bucket refs, Firebase RTDB URLs, private IPs, Sentry DSN…). Template-literal paths, WebSocket/EventSource URLs, htmx and `data-*` attributes, `modulepreload`/manifest links, dynamically loaded chunks seen via the Performance API, statement-bounded parameter extraction.
- **App**: dismiss/restore, Hosts manager, Settings (scan scope, excluded hosts, per-rule toggles, theme, badge), copy as cURL, open endpoint, mask values, CSV export, chips with counts, "Interesting" Wayback filter, MIME family filter, sticky table headers, keyboard shortcuts, light theme, toast feedback, incremental lists.
- **Platform**: `Alt+Shift+S` command, app tab reuse (no duplicate tabs per page), severity-coloured badge, settings-aware content script, `INJECT_CONTENT` handled by the background so the app never touches browser-specific APIs.
- **Engineering**: `detect.js` is pure and unit-tested (50 tests: rules compile, samples match, FP filters, endpoint parsing, host-log merge). Zero-dependency build with zip writer, `--watch`, `--set-version`, manifest validation. Preview harness with a mocked `chrome` API and a Playwright screenshot script for design iteration.

## 3. Roadmap — proposed next features

Ordered by value ÷ effort. Items marked ★ are the ones I'd do first.

### Detection quality
1. ★ **Real request capture via `webRequest`/`declarativeNetRequest` feedback** — record method, status and content-type of actual XHR/fetch calls made by the page (the Performance API gives URLs only). This yields true methods for network-observed endpoints and lets you mark endpoints as *confirmed live*.
2. ★ **Source-map awareness** — when a bundle ships `//# sourceMappingURL`, fetch the map and scan `sourcesContent`. Unminified sources expose far more routes and comments than the bundle.
3. **Secret verification (opt-in, per rule)** — TruffleHog-style liveness checks for a whitelist of providers with harmless read-only endpoints (GitHub `/user`, Stripe `/v1/balance`, Slack `auth.test`, AWS STS `GetCallerIdentity`). Must be explicit per click, never automatic, with a clear warning that it contacts the provider. Show `verified / revoked / unknown` badges.
4. **Rule metadata** — add `tags` (cloud, payments, ci, ai…), `confidence`, `docs` URL and `examples` to each rule; the tests already validate samples, so examples can live in the rule file and feed both docs and tests.
5. **GraphQL introspection** — when a `/graphql` endpoint is found, offer a one-click introspection query and render types/queries/mutations (many targets leave it enabled).
6. **Swagger/OpenAPI discovery** — probe well-known paths (`/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/api-docs`) on the target origin and import documented endpoints with methods and parameters.
7. **JS-string decoding** — detect base64/hex-encoded URLs and keys inside bundles (decode candidates ≥ 24 chars and re-run the rules).
8. **Cookie & storage inspection** — read `document.cookie` names, `localStorage`/`sessionStorage` keys on the page (content script can) and flag JWTs / tokens stored client-side.
9. **Per-rule allowlists** — regex allowlist per rule id (e.g. ignore `AKIA` values that appear in docs pages), configurable in Settings.

### Workflow
10. ★ **Diff view / "new since last visit"** — the host log already stores `firstSeen`; surface a *New* filter and a badge count of findings first seen in the current scan so return visits show only deltas.
11. ★ **Notes & tags on findings** — attach free-text notes and status (`todo / confirmed / false-positive / reported`) per finding; export includes them. Turns the extension into a lightweight recon notebook.
12. **Scope profiles** — named scopes (in-scope domains, excluded hosts, rule set) switchable from the sidebar; ideal for bug-bounty programs.
13. **Cross-host view** — an "All hosts" mode in Endpoints/Secrets to search across every stored log (e.g. find every host where a given key appears).
14. **Right-click context menu** — "Scan this link with SecretSauce" / "Open SecretSauce for this tab".
15. **Import** — load a previous JSON export (or a Burp/ZAP URL list) into a host log.
16. **Burp/ZAP hand-off** — "Send to proxy" via a configurable local HTTP endpoint, or an export in Burp's site-map XML.
17. **Nuclei / ffuf wordlists** — export endpoints as path-only wordlists and parameters as `param=FUZZ` templates.

### Platform
18. **Firefox MV3** — Firefox 140+ supports MV3 (`background.scripts` event page, `declarativeNetRequest`). The main cost is that MV3 host permissions are optional in Firefox, so first-run must request `<all_urls>`. Worth doing before AMO deprecates MV2.
19. **Options page / side panel** — Chrome's `sidePanel` API would let findings sit next to the page instead of in a separate tab.
20. **Storage on IndexedDB** — `chrome.storage.local` is fine up to a few MB; long-running engagements with many hosts would benefit from IndexedDB with per-host records and LRU eviction.
21. **Web Worker scanning** — move regex execution off the page's main thread (content scripts can spawn a worker from a blob) so heavy bundles don't jank the tab.
22. **CI** — GitHub Action running `npm test` and `node build.mjs`, attaching zips to releases; `web-ext lint` for the Firefox build.

### Design polish still open
- Overview/dashboard landing (top endpoints, recently seen). The drawer's severity ledger and coverage list now carry the summary.
- Virtualised list instead of chunked appends for 10k+ rows.
- Column chooser and resizable columns in tables.
- Reduced-motion media query for the pulse/spin animations.

## 4. Sidebar redesign (v1.4.0, Impeccable-assisted)

The original single column (brand, stats tiles, nav, buttons) became an icon rail plus a collapsible target drawer. The rail keeps sections, counts and actions always reachable; the drawer holds host, status, a proportional severity ledger and coverage figures, and can be hidden (`B`) or peeked on hover. Audit fixes landed in the same release: AA contrast on every token pair, keyboard-operable cards with `aria-expanded`, `aria-pressed`/`aria-current` state, reduced-motion alternatives, coarse-pointer hit areas, rem type scale, `color-mix` tints so light mode derives from the same tokens, and removal of accent rails and em-dash copy. Direction contract: `.impeccable/surfaces/src-app-html.md`.

## 5. Known limitations
- Network-observed endpoints have no method (browser Performance API limitation) — see roadmap item 1.
- Embedded recon tools depend on third parties allowing framing after header stripping; sites that frame-bust in JS will still refuse. The "open in new tab" link is always available.
- The high-entropy heuristic is deliberately conservative (min 24 chars, 3 character classes). It will miss short tokens; named rules are the primary signal.
- `all_frames` is off: iframes are not scanned. Turning it on multiplies content-script instances and needs per-frame result merging; a good candidate for an opt-in setting.
