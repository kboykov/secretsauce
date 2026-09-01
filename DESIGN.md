---
name: SecretSauce
description: Graphite dark-first triage console for a recon browser extension; one accent, semantic severity and method hues, mono for everything a machine wrote.
colors:
  graphite-bg: "#0b0d11"
  graphite-bg-side: "#0e1116"
  graphite-surface: "#12161c"
  graphite-surface-2: "#171c24"
  graphite-surface-3: "#1e242e"
  hairline: "#222933"
  hairline-2: "#2d3542"
  decorative-stroke: "#3a4453"
  ink: "#e8ecf3"
  ink-2: "#a6b0c0"
  ink-3: "#8591a5"
  ink-4: "#7b869a"
  accent-periwinkle: "#7aa2ff"
  on-accent: "#0b0d11"
  link-sky: "#6fc3ff"
  brand-chili: "#ff5d5d"
  brand-orange: "#ff9f43"
  on-brand: "#ffffff"
  sev-critical: "#ff6b6b"
  sev-high: "#ff9f43"
  sev-medium: "#f7c948"
  sev-low: "#3ddc97"
  sev-none: "#8591a5"
  method-get: "#6fc3ff"
  method-post: "#3ddc97"
  method-put: "#f7c948"
  method-patch: "#c99cff"
  method-delete: "#ff6b6b"
  method-other: "#9aa4b5"
  highlight-fg: "#f7c948"
typography:
  headline:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 700
    lineHeight: 1.5
    letterSpacing: "-0.01em"
  title:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: 1.5
  title-small:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 700
    lineHeight: 1.5
  body:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.5
  body-small:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.5
  caption:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif"
    fontSize: "0.719rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif"
    fontSize: "0.656rem"
    fontWeight: 700
    lineHeight: 1.5
    letterSpacing: "0.05em"
  mono:
    fontFamily: "'Cascadia Code', 'JetBrains Mono', 'Fira Code', ui-monospace, Consolas, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.5
  mono-small:
    fontFamily: "'Cascadia Code', 'JetBrains Mono', 'Fira Code', ui-monospace, Consolas, monospace"
    fontSize: "0.719rem"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  bar: "3px"
  chip: "4px"
  pill: "5px"
  code: "6px"
  control: "7px"
  field: "8px"
  card: "10px"
  round: "999px"
spacing:
  "4": "4px"
  "6": "6px"
  "7": "7px"
  "8": "8px"
  "10": "10px"
  "12": "12px"
  "14": "14px"
  "16": "16px"
  "20": "20px"
components:
  button-primary:
    backgroundColor: "{colors.accent-periwinkle}"
    textColor: "{colors.on-accent}"
    typography: "{typography.body-small}"
    rounded: "{rounded.field}"
    padding: "7px 12px"
  button-secondary:
    backgroundColor: "{colors.graphite-surface-2}"
    textColor: "{colors.ink}"
    typography: "{typography.body-small}"
    rounded: "{rounded.field}"
    padding: "7px 12px"
  button-secondary-hover:
    backgroundColor: "{colors.graphite-surface-3}"
    textColor: "{colors.ink}"
  button-danger:
    backgroundColor: "{colors.graphite-surface-2}"
    textColor: "{colors.sev-critical}"
    rounded: "{rounded.field}"
    padding: "7px 12px"
  button-toolbar:
    backgroundColor: "{colors.graphite-surface}"
    textColor: "{colors.ink-2}"
    typography: "{typography.body-small}"
    rounded: "{rounded.control}"
    padding: "5px 9px"
    height: "30px"
  button-toolbar-hover:
    backgroundColor: "{colors.graphite-surface-2}"
    textColor: "{colors.ink}"
  button-icon:
    backgroundColor: "{colors.graphite-surface}"
    textColor: "{colors.ink-3}"
    rounded: "{rounded.control}"
    size: "30px"
  button-icon-hover:
    backgroundColor: "{colors.graphite-surface-2}"
    textColor: "{colors.ink}"
  rail-nav:
    backgroundColor: "transparent"
    textColor: "{colors.ink-3}"
    rounded: "{rounded.card}"
    size: "40px"
  rail-nav-hover:
    backgroundColor: "{colors.graphite-surface-2}"
    textColor: "{colors.ink}"
  rail-nav-active:
    backgroundColor: "color-mix(in srgb, #7aa2ff 14%, transparent)"
    textColor: "{colors.accent-periwinkle}"
  rail-action-primary:
    backgroundColor: "{colors.accent-periwinkle}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.card}"
    size: "40px"
  chip-filter:
    backgroundColor: "{colors.graphite-surface}"
    textColor: "{colors.ink-2}"
    typography: "{typography.caption}"
    rounded: "{rounded.round}"
    padding: "3px 9px"
    height: "26px"
  chip-filter-on:
    backgroundColor: "color-mix(in srgb, #7aa2ff 14%, transparent)"
    textColor: "{colors.accent-periwinkle}"
  pill-method:
    backgroundColor: "color-mix(in srgb, #6fc3ff 14%, transparent)"
    textColor: "{colors.method-get}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "2px 7px"
    width: "52px"
  tag:
    backgroundColor: "{colors.graphite-surface-3}"
    textColor: "{colors.ink-2}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "1px 6px"
  card:
    backgroundColor: "{colors.graphite-surface}"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.card}"
    padding: "9px 6px 9px 14px"
  card-body:
    backgroundColor: "{colors.graphite-surface}"
    textColor: "{colors.ink-2}"
    padding: "12px 14px 14px"
  input-search:
    backgroundColor: "{colors.graphite-surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body-small}"
    rounded: "{rounded.field}"
    padding: "0 10px"
    height: "32px"
  input-select:
    backgroundColor: "{colors.graphite-surface}"
    textColor: "{colors.ink-2}"
    typography: "{typography.body-small}"
    rounded: "{rounded.field}"
    padding: "0 26px 0 10px"
    height: "32px"
  code-block:
    backgroundColor: "{colors.graphite-bg}"
    textColor: "{colors.ink-2}"
    typography: "{typography.mono-small}"
    rounded: "{rounded.code}"
    padding: "8px 10px"
  menu:
    backgroundColor: "{colors.graphite-surface-2}"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.card}"
    padding: "6px"
    width: "280px"
  toast:
    backgroundColor: "{colors.graphite-surface-3}"
    textColor: "{colors.ink}"
    typography: "{typography.body-small}"
    rounded: "{rounded.round}"
    padding: "9px 14px"
  drawer:
    backgroundColor: "{colors.graphite-bg-side}"
    textColor: "{colors.ink-2}"
    padding: "16px 16px 12px"
    width: "244px"
  rail:
    backgroundColor: "{colors.graphite-bg-side}"
    textColor: "{colors.ink-3}"
    padding: "10px 0"
    width: "56px"
---

# Design System: SecretSauce

## Overview

**Creative North Star: "The Graphite Console"**

SecretSauce is an operator's console, not a dashboard. It sits open for hours beside a page under test, so the world is built for sustained low-light reading: near-black graphite ground, four steps of ink, one cool periwinkle accent, and a set of semantic hues (severity, HTTP method) that mean the same thing everywhere they appear. Nothing decorates. Every colour is derived from a token at the top of `src/app.css`, and every soft fill or soft border is that token mixed down with `color-mix`, so the light theme is the same system relit, not a second design.

Density is high and even. The interface reads as a 13px body over a 16px root, with a small ramp downward (12, 11.5, 10.5px) for controls, captions and labels, and a single step up (17px) for the panel headline. Structure is carried by 1px hairlines and one-step surface changes; shadows appear only under things that float. The spatial spine is fixed: a 56px icon rail on the left edge full height, a 244px target drawer that can be dismissed, and findings filling the rest.

Recorded in scan mode from the shipped build (September 2026). PRODUCT.md's decision on record explains why this file carries no concept-seed key: the sidebar was "chosen by the maintainer from three structures; no concept roll because the surface's visual world was already established in code." The system below is what that code does, not what was planned.

**Key Characteristics:**
- Dark-first graphite with a complete light theme driven by the same token names under `[data-theme="light"]`.
- One accent (periwinkle) for focus, selection, active state and the single primary action; severity and method hues are semantic and never stand in for it.
- System UI sans for interface text; monospace for anything a machine produced (hosts, paths, values, code, keys). No display face.
- Depth by hairline and surface step; shadow only on floating layers (open card, menu, overlay drawer, toast).
- Static inline SVG icons, 16-unit grid, 1.5 stroke, `currentColor`.
- Motion is short (140–200ms), eased-out, and limited to transform and opacity; fully collapsed under `prefers-reduced-motion`.

## Colors

A near-black graphite ground stepped upward in five surfaces, a four-rung ink ladder, one cool accent, and two semantic hue families that carry meaning rather than brand.

### Primary
- **Accent Periwinkle** (`accent-periwinkle`): the only brand-neutral accent. Focus rings (`outline: 2px solid`), caret, text selection at 35%, the active rail button (14% tint fill + accent icon), pinned drawer toggle, toggled toolbar buttons, the search field's focus glow (3px ring at 22%), the checked switch, and the Rescan primary button. Light theme relights it to `#2f5fe0`.
- **Link Sky** (`link-sky`): endpoint paths, source URLs, link-buttons. Distinct from the accent so a wall of paths never reads as a wall of controls. It is intentionally the same hue as `method-get`. Light: `#1668d1`.

### Secondary (brand mark only)
- **Brand Chili → Brand Orange** (`brand-chili` → `brand-orange`, `linear-gradient(135deg)`): the logo square and the 36px host letter mark in the drawer head. Nowhere else. White (`on-brand`) sits on it.

### Tertiary (semantic hues)
- **Severity**: `sev-critical` coral, `sev-high` orange, `sev-medium` gold, `sev-low` mint, `sev-none` slate. Used for severity pills, rail badges (solid fill with `graphite-bg` text), drawer ledger bars, coverage counts that exceed zero, the `.hot` table row link, and the danger button's text. `sev-low` doubles as the "live" status dot and the "copied" confirmation because both mean "good, present now".
- **HTTP method**: `method-get` sky, `method-post` mint, `method-put` gold, `method-patch` violet, `method-delete` coral, `method-other` slate. Method pills, method filter chips, and the `{param}` template tag (violet).
- **Highlight** (`highlight-fg` on a 22% gold tint): the matched substring inside a context snippet. Light theme darkens the foreground to `#6e5400`.
- Light-theme values for every semantic hue are darkened for AA on white: critical `#c9302c`, high `#b85c00`, medium `#8a6a00`, low `#127a51`, patch `#6d32d1`, other `#5b6678`, none `#5f6a7d`.

### Neutral
- **Graphite ground** (`graphite-bg`): the page and panel-header background, sticky table heads, and the recessed background of code blocks inside cards. Light: `#f4f6fa`.
- **Side ground** (`graphite-bg-side`): rail, drawer, and recon bar; one step lighter than the page so the spine reads as a separate plane without a shadow. Light: `#ffffff`.
- **Surface / Surface-2 / Surface-3** (`graphite-surface`, `-2`, `-3`): cards, inputs and toolbar buttons rest on Surface; menus and hovered controls step to Surface-2; badges, tags, switches and toasts sit on Surface-3. Hover is always exactly one step up. Light: `#ffffff` / `#f2f4f8` / `#e9edf3`.
- **Hairline / Hairline-2** (`hairline`, `hairline-2`): every 1px border at rest and on hover respectively; also the scrollbar thumb. Light: `#e1e6ee` / `#cfd6e1`.
- **Decorative Stroke** (`decorative-stroke`): idle status dot, hovered scrollbar thumb, hovered secondary-button border. Never text. Light: `#c3cad6`.
- **Ink ladder** (`ink`, `ink-2`, `ink-3`, `ink-4`): primary ink for names, counts and headlines; secondary ink is the body default; muted ink for captions, hosts, table heads, tags and idle icons (≥ 5:1); quiet ink for kv keys, footers and placeholders (≥ 4.5:1). Light: `#141a24` / `#3f4a5c` / `#5f6a7d` / `#66717f`.

### Named Rules
**The Derived Tint Rule.** No soft colour is hand-picked. A soft fill is its hue at `--tint` (14% dark, 12% light) over transparent; a soft border is the hue at `--tint-border` (32% dark, 36% light) or a per-component 28–45%. Change the hue and the tint follows.

**The Semantic Hue Rule.** Severity and method hues mean severity and method. They never colour a control that is not about severity or method, and the accent never colours a finding.

**The Brand Mark Rule.** The chili-orange gradient appears on exactly two things: the logo and the host letter mark. It is not a button, a heading colour, or a highlight.

**The Stroke Is Not Ink Rule.** `decorative-stroke` and the two hairlines are for lines and dots only; text uses the four inks, each of which clears AA in both themes.

## Typography

**Display Font:** none. The system has no display face by commitment.
**Body Font:** system-ui (with -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif)
**Label/Mono Font:** Cascadia Code (with JetBrains Mono, Fira Code, ui-monospace, Consolas, monospace)

**Character:** Plain and native. The sans disappears into the browser; the mono announces "this string came from the target". Weight does the hierarchy work (400 / 600 / 700 / 800), not size.

### Hierarchy
- **Headline** (700, 17px, `letter-spacing: -0.01em`, `text-wrap: balance`): the panel title, one per panel, paired baseline-aligned with a tabular count in muted 12px.
- **Title** (600, 14px): empty-state titles. **Title-small** (700, 13px): settings card headings; the host name in the drawer is the same size at 600 in mono.
- **Body** (400, 13px, line-height 1.5, `ink-2`): the default. Names and values that must be found fast step up to `ink` at 600.
- **Body-small** (12px): controls, table cells, toolbar buttons, menu item names (600), secondary buttons (600).
- **Caption** (11.5px): status line, ledger rows, coverage rows, chips, setting descriptions, table URLs, sub-copy in menus.
- **Label** (700, 10.5px, uppercase, `letter-spacing: 0.05em`; `0.08em` on drawer section heads, `0.04em` on pills): table column heads, key/value keys, "Context" and other data-group labels, the drawer's "Severity" / "Coverage" heads, method and severity pills, tags. Always a label over data, never a lead-in over a headline.
- **Mono** (12px) and **Mono-small** (11.5px): endpoint URLs, source links, code blocks, chips, textareas, `kbd`.

### Named Rules
**The Two Faces Rule.** Interface text is the system sans; anything the target emitted (host, path, value, source URL, snippet, param name) is mono. Nothing else is mono, and nothing is a third face.

**The Tabular Numbers Rule.** Every count, badge, ledger figure and date uses `font-variant-numeric: tabular-nums` so columns of numbers stay still while data changes.

**The Weight Ladder Rule.** Hierarchy inside a row is weight and ink, not size: 600 `ink` for the thing you scan for, 400 `ink-2` or `ink-3` for the rest.

## Layout

The app is a fixed three-column grid at full viewport height (`100dvh`, body `overflow: hidden`; every panel scrolls internally): `56px 244px 1fr`. Column one is the rail, always present. Column two is the target drawer; when pinned shut (`data-drawer="closed"`) the grid becomes `56px 1fr` and the drawer leaves layout entirely. Column three is the main panel: a sticky panel header (`14px 20px 10px`, hairline below, page background) over a scrolling list (`14px 20px 24px`, 6px gap between cards) or a sticky-head table (cells `7px 14px`, heads `9px 14px`).

Spacing rhythm is a 2px-based ladder with 4, 6, 7, 8, 10, 12, 14, 16 and 20 in use. 4 is icon-to-icon inside a group; 6–8 is gap between controls and inside chips; 10 is the gap inside a row and between rail buttons and separators; 12–14 is the gap between sections inside a card or drawer; 16 is the drawer's inner padding; 20 is the main panel's horizontal gutter. Settings use a responsive grid `repeat(auto-fit, minmax(340px, 1fr))`, gap 14, max width 1200px.

Responsive behaviour is subtractive; nothing re-flows into a new composition:
- **Initial state** (JS): the drawer opens by default at viewport width ≥ 1000px and remembers its state in `localStorage` (`ss-drawer`).
- **≤ 900px**: key/value grids in card bodies go from `96px 1fr` to a single column.
- **≤ 760px**: the drawer never takes layout width. Open, it overlays the main panel at `left: 56px`, `width: min(260px, 100vw - 56px)`, with the pop shadow; a click outside dismisses it.
- **≤ 640px**: row tags hide (they return inside the expanded body), card actions show only on the open card, endpoint URLs wrap (`overflow-wrap: anywhere`, line-height 1.35), the panel header and list tighten to `12px 14px 8px` and `10px 12px 20px`.
- **`pointer: coarse`**: icon buttons grow to 40px, every text control gets `min-height: 40px`, rail buttons pad to `11px 9px`, and hover-revealed card actions become always visible.

**The Rail Constant Rule.** The 56px rail is on screen at every width and in every drawer state; navigation and the primary action never move into a header or a hamburger.

## Elevation & Depth

Hybrid, border-first. Surfaces at rest are flat: a 1px `hairline` border on a one-step surface change is what separates a card from the list, a control from its bar, the rail from the page. Hover raises the border to `hairline-2` and the fill by one surface step; it does not add a shadow. Shadows are reserved for layers that float above the document plane, and the system has exactly two.

### Shadow Vocabulary
- **Lift** (`box-shadow: 0 6px 18px -10px rgb(0 0 0 / .65), 0 1px 2px rgb(0 0 0 / .3)`; light: `0 6px 18px -12px rgb(20 26 36 / .35), 0 1px 2px rgb(20 26 36 / .08)`): the open (expanded) card only. Says "this one is active" without changing its colour.
- **Pop** (`box-shadow: 0 18px 36px -14px rgb(0 0 0 / .6), 0 2px 6px rgb(0 0 0 / .35)`; light: `0 18px 36px -16px rgb(20 26 36 / .35), 0 2px 6px rgb(20 26 36 / .1)`): menus, the toast, and the drawer whenever it overlays (peek, or open below 760px).
- **Focus glow** (`0 0 0 3px color-mix(in srgb, accent 22%, transparent)`): the search field on `:focus-within`; the same 3px ring in the status colour sits under the live and scanning status dots.

Z-order is small and fixed: table heads 1, drawer overlay 20, rail 21, menus 30, toast 100.

### Named Rules
**The Border-First Rule.** Depth at rest is a hairline and a surface step. A shadow means the element is floating over other content; if it is in the flow, it has no shadow.

**The One Step Up Rule.** Hover and open states move exactly one rung: `hairline → hairline-2`, `surface → surface-2`, `surface-2 → surface-3`. No element jumps two steps.

## Shapes

Softly rounded rectangles on a tight radius ladder, scaled to element size. 3px for hairline-thick things (ledger bars, highlight marks); 4px for inline chips and the focus-ring corner; 5px for pills, tags and `kbd`; 6px (`--r-sm`) for code blocks; 7px for 30px controls (toolbar buttons, icon buttons, menu items, rule rows); 8px for 32px fields and secondary buttons; 10px (`--r`) for cards, menus, 40px rail buttons and the host letter mark; 999px for filter chips, count badges, the "load more" affordance, switches and the toast. Circles are reserved for status and severity dots (8px) and the switch thumb.

Borders are 1px everywhere and never thicker, with two deliberate exceptions: the rail badge wears a 2px ring in the side-ground colour to cut it out of the icon beneath, and `kbd` has a 2px bottom border as a key-cap. The "load more" control is the only dashed border. Rail separators are 22px wide, 1px hairlines. Method pills carry a fixed `min-width: 52px` and severity pills `64px` so a column of them aligns.

## Components

### Buttons
Quiet at rest, one step louder on hover, accent only for the single primary action per surface.
- **Shape:** 8px on 30–32px bar buttons; 7px on 30px toolbar and icon buttons; 10px on 40px rail buttons.
- **Primary** (`button-primary`, `rail-action-primary`): accent fill, `on-accent` text, transparent border; hover `filter: brightness(1.06)`. Only Rescan (rail foot) and the occasional settings action use it.
- **Secondary** (`button-secondary`): Surface-2 fill, `hairline-2` border, `ink` 600 12px, `7px 12px`; hover Surface-3 + `decorative-stroke` border; active `translateY(1px)`.
- **Danger** (`button-danger`): same anatomy with `sev-critical` text and a 32% critical-tint border; hover 10% critical fill.
- **Toolbar** (`button-toolbar`): Surface fill, `hairline` border, `ink-2` text, `5px 9px`, `min-height: 30px`; may carry a 999px Surface-3 count badge; toggled state = 14% accent fill + 40% accent border + `ink` text; disabled at 45% opacity.
- **Icon** (`button-icon`): 30px square (28px inside cards and table cells, 40px under coarse pointer), `ink-3` icon; `.ghost` drops the border and fill; toggled state matches toolbar but tints the icon accent; `.danger-hover` turns critical on hover; `.copied` turns `sev-low` with a 40% low border.
- **Spinning**: the `refresh` icon rotates (`spin .8s linear infinite`); under reduced motion the button instead takes a 35% accent fill and the icon dims to 55%.
- **Focus:** global `:focus-visible` = 2px accent outline, 2px offset, 4px corner. Card rows pull it inside (`outline-offset: -3px`).

### Chips
- **Filter chip** (`chip-filter`): 999px, `hairline` border on Surface, `ink-2` 11.5px, `3px 9px`, `min-height: 26px`, with a 10.5px 700 tabular count in `ink-3`. Each chip declares its own `--chip` hue (accent by default, severity or method by class).
- **Selected** (`chip-filter-on`, `aria-pressed="true"`): 14% `--chip` fill, 45% `--chip` border, text and count in `--chip`. The "All" chip keeps `ink` text when selected.
- **Inline chip** (`.chip`): mono 11.5px, 4px radius, Surface-3 fill, `hairline` border, for param names and similar lists.

### Pills and Tags
- **Method / severity pill** (`pill-method`): 10.5px 800 uppercase `0.04em`, `2px 7px`, 5px radius, 14% hue fill, 28% hue border, hue text; methods in mono at `min-width: 52px`, severities in sans at `64px`. `other` falls back to Surface-3 and a plain hairline.
- **Tag** (`tag`): 10.5px, `1px 6px`, 5px, Surface-3 + hairline, `ink-2`. Variants recolour text and use an 8% fill / 30% border of their hue: `.tpl` violet mono (`{param}`), `.live` mint.

### Cards / Containers
- **Corner Style:** 10px.
- **Background:** Surface with a 1px `hairline` border; hover `hairline-2`; open `hairline-2` + Lift shadow; ignored cards sit at 55% opacity (90% on hover).
- **Anatomy:** a 42px-min head row (`9px 6px 9px 14px`, 10px gaps: pill, mono URL with `ink-3` host and `link-sky` path, tags, then a 6px-gap action group and a chevron that rotates 90° when open). Actions fade in on hover, focus-within or open (always visible under coarse pointer). The body is separated by a hairline, padded `12px 14px 14px`, 12px gaps, and holds `kv` grids (`96px 1fr`, 7px × 14px gaps, label keys), recessed code blocks on the page ground at 6px radius, and a context snippet clamped to 96px with a fade-out gradient until expanded (520px, scrollable).
- **Static card** (settings): `16px 18px` padding, 12px gaps, 13px 700 heading.

### Inputs / Fields
- **Search** (`input-search`): 32px tall (30px `.compact`), 8px radius, Surface + hairline, leading 16px search icon in `ink-3`, placeholder `ink-4`. Focus-within: accent border + 3px 22% accent glow. Keyboard `/` focuses it, Escape clears.
- **Select / text input** (`input-select`): same box at `ink-2`; select draws its own 4px chevron from two gradients in `ink-3`; hover `hairline-2`; focus accent border with the outline offset collapsed to 0. Numeric inputs are 90px, right-aligned, tabular.
- **Textarea:** mono 12px, `8px 10px`, vertical resize only.
- **Switch:** 34×20px (28×16px inside rule rows) 999px track on Surface-3 with `hairline-2`; 14px `ink-3` thumb; checked = accent track and `on-accent` thumb translated 14px; the hidden checkbox's `:focus-visible` puts the 2px accent outline on the track.

### Navigation
- **Rail** (`rail`): 56px column, side ground, right hairline, 4px between 40px buttons, grouped Findings / Recon / Manage / Actions with 22px hairline separators. Icons are 17px viewBox-16 SVGs at 1.5 stroke in `ink-3`; hover Surface-2 + `ink`; active (`rail-nav-active`) is a filled 14% accent square with an accent icon at 1.75 stroke. Count badges are 17px 999px pills, 10px 700 tabular, Surface-3 with a 2px side-ground ring; severity badges take the solid severity colour with page-ground text.
- **Rail foot**: drawer toggle (hover peeks, click pins, key `B`; pinned = accent icon), theme toggle, Export (opens a `position: fixed` menu to the right, anchored to the button so the rail keeps its own scroll), then Rescan (primary, key `R`).
- **Drawer** (`drawer`): 244px docked, 260px when overlaying, side ground, right hairline, `16px 16px 12px`, 14px gaps. Contents top to bottom: host header (36px gradient letter mark, 13px 600 mono host, 11.5px `ink-3` URL, both single-line ellipsised); one status line (8px dot with state colour and pulse, 600 `ink` state word, `ink-3` detail; the provenance sentence lives in the line's `title` and an `aria-describedby` sr-only span so there is one visible line); a "Severity" label head over a four-row ledger (`56px 1fr 30px` grid, 6px bars at 3px radius filled by `transform: scaleX(var(--fill))` in the severity hue, tabular counts); a "Coverage" label head over hairline-separated key/value rows; a quiet footer with the brand word. No cards inside the drawer.
- **Mobile treatment:** below 760px the drawer overlays with the Pop shadow and dismisses on outside click; the rail is unchanged.

### Menu
280px min, Surface-2 with `hairline-2`, 10px radius, 6px padding, Pop shadow, `rise .14s`. Items are full-width 7px-radius rows (`8px 10px`) with a 12px 600 `ink` name over an 11.5px `ink-3` description; hover Surface-3.

### Toast
Fixed bottom-centre (22px), 999px, Surface-3 + `hairline-2`, Pop shadow, 12px `ink` text with a 16px icon in `sev-low` (success) or `sev-critical` (error); enters by 12px rise + fade over 180ms.

### Empty state
Centred column, `64px 20px`, a 56px 16px-radius Surface tile holding a 1.4-stroke icon, 14px 600 title, 12px sub-copy at 420px max.

### Motion
One timing token for state (`--t: .15s ease-out`) on background, border-color, color, transform and opacity. Entrances are eased-out and short: drawer in `.2s cubic-bezier(.16, 1, .3, 1)` from `translateX(-10px)` + fade; drawer out `.16s cubic-bezier(.4, 0, 1, 1)`; menu `rise .14s cubic-bezier(.2, .8, .2, 1)` from 4px; ledger fill `.35s cubic-bezier(.2, .8, .2, 1)`; status pulse 1.2s (scanning) / 1.6s (waiting) opacity to 35%. Only transform and opacity animate on layout-level elements. Under `prefers-reduced-motion: reduce` every duration collapses to `.01ms`, iteration count to 1, pulsing dots become static 45% rings, and the JS skips the drawer's closing animation.

## Do's and Don'ts

### Do:
- **Do** derive every soft fill and soft border with `color-mix(in srgb, <hue> var(--tint|--tint-border), transparent)` from a named token; add the light-theme value under `[data-theme="light"]` in the same commit.
- **Do** use `ink` at 600 for the one thing in a row the operator scans for, and `ink-2`/`ink-3` at 400 for everything else.
- **Do** set mono on any string that came from the target (host, path, value, source, snippet, param) and `tabular-nums` on any number that changes.
- **Do** separate at rest with a 1px `hairline` and a one-step surface change; reserve Lift for the open card and Pop for menus, overlays and the toast.
- **Do** keep icons as static inline SVG on the 16-unit grid, 1.5 stroke, `currentColor`, and add new ones to the `ICONS` map in `src/app/ui.js`.
- **Do** give every control a `:focus-visible` treatment that resolves to the 2px accent outline, and 40px hit targets under `pointer: coarse`.
- **Do** animate only transform and opacity for entrances, at 140–200ms eased-out, and check the `prefers-reduced-motion` branch.

### Don't:
- **Don't** use a severity or method hue on anything that is not a severity or a method, and don't use the accent to mark a finding.
- **Don't** put the chili-orange gradient anywhere but the logo and the host letter mark.
- **Don't** introduce a display face, a second sans, or a third family; the commitment is system-ui plus one mono.
- **Don't** add a shadow to an element in the document flow, or a hover state that adds one.
- **Don't** use `decorative-stroke` or either hairline as a text colour.
- **Don't** place cards inside the drawer or move navigation off the rail; the drawer is lists and rows, the rail is the only nav.
- **Don't** set `innerHTML` with dynamic data; build with `el()` and `textContent`.
