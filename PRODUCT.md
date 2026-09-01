# PRODUCT.md — SecretSauce

_Product truth for design and engineering work. Recorded September 2026 from the repository, the README and the maintainer's decisions in session; items marked "unconfirmed" were inferred and should be corrected by the maintainer._

## What it is
SecretSauce is a browser extension (Chrome MV3, Firefox MV2) that scans the page a researcher is looking at for exposed secrets, API keys and API endpoints, keeps a deduplicated per-host log across sessions, and puts the follow-up OSINT lookups (DNS, history, subdomains, web check, Wayback Machine) one click away in a full-page app tab.

## Who uses it
Security researchers, bug-bounty hunters and application-security engineers doing reconnaissance on a target they are authorised to test. They keep the app tab open for long stretches beside the page under test, on desktop browsers, usually in low-light or dark-themed environments (unconfirmed: mobile Firefox is supported by the manifest but is not a primary scene).

## The job
Turn "I'm on this page" into "here is everything this host leaks, and here is where to dig next" with no configuration. Speed of triage matters more than expression: a finding must read (severity, method, path, where it came from) in one glance, and noise must be dismissible.

## Surfaces
- **App tab** (`src/app.html`): the primary surface. Operate mode. Rail of sections and actions, collapsible target drawer, findings lists, recon panels, hosts manager, settings.
- **Toolbar badge**: secret count coloured by highest severity.
- **Content script**: invisible; scans and persists.

## Brand commitments
- Name and mark: "SecretSauce", chili-orange gradient square mark (`#ff5d5d` → `#ff9f43`) used only for the logo and the host letter mark.
- Visual system: graphite dark theme by default with a full light theme; tokens live at the top of `src/app.css` and every component colour derives from them (`color-mix` tints). Severity (critical/high/medium/low) and HTTP method hues are semantic and never double as the accent.
- Type: system UI sans for interface text, monospace for hosts, paths, values and code. No display face.
- Tone: plain, specific, active-voice copy. Controls name the action. No em-dash cadence, no emoji as icons.

## Constraints
- No bundler, no runtime dependencies; classic scripts loaded in order. Chrome loads `src/` unpacked; `build.mjs` produces the Firefox build.
- No `innerHTML` with dynamic data (AMO review). Icons are static SVG.
- Findings never leave the browser. Recon tabs embed third-party sites with the hostname in the URL; nothing else is sent anywhere.
- Keyboard operable throughout; WCAG AA contrast on every token pair in both themes; `prefers-reduced-motion` respected.

## Decisions on record
- 2026-09: Sidebar redesigned as icon rail + collapsible target drawer (chosen by the maintainer from three structures; no concept roll because the surface's visual world was already established in code). Nothing from the previous sidebar was protected.
- 2026-09: Audit fixes accepted wholesale ("Fix all impeccable, remove all AI slop patterns").
