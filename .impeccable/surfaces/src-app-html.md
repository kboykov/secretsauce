---
version: 1
slug: "src-app-html"
primary_target: "src/app.html"
related_targets: ["src/app.css","src/app/main.js"]
---

# Surface brief: SecretSauce app (src/app.html)

Scope: the full-page findings app opened from the toolbar. Visitor mode: Operate. This brief covers the sidebar redesign (September 2026); the main panels keep their incumbent composition.

Audience: security researchers and bug-bounty hunters triaging one target at a time, often with the app tab open for hours beside the page under test.
Job: see the target's state at a glance, switch between findings and recon sections fast, and rescan or export without hunting.
Constraints: extension page, no bundler, no innerHTML with dynamic data, existing graphite token system and both themes stay; keyboard operable; Chrome MV3 + Firefox MV2.

Decisions from the user (Sept 2026): structure = icon rail + context drawer; nothing in the old sidebar is protected; drawer collapses to the rail with state remembered.

## Direction contract

THESIS: Navigation and actions are a permanent 56px rail; everything about the target is a drawer you can dismiss. Refuses the category default of one tall column mixing brand, stats, nav and buttons.

OWN-WORLD: Existing graphite tokens. Rail: icon buttons with tabular count badges, active state as a filled accent-soft square, thin separators between Findings / Recon / Manage / Actions. Drawer: host header (gradient letter mark, mono host, page URL), one status line with pulse dot, a severity ledger of four proportional bars, a coverage list of label/value rows. No cards inside the drawer, no rails on anything.

STORY: The operator lands, reads host + status + severity in one glance, clicks a rail icon to work, and pins the drawer shut when the findings need the width.

FIRST VIEWPORT: Rail left edge full height; drawer 244px beside it; findings fill the rest. Rescan (primary, accent fill) and Export (menu opens rightward) sit at the rail's foot with theme and drawer-pin above them.

FORM: Icon rail + context drawer, user-chosen from three structures; no seed roll (local extension of an established surface).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance.
