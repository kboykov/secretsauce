// SecretSauce app — controller: state, data loading, panels, settings, hosts.
// Load order (app.html): shared.js → app/ui.js → app/findings.js → app/render.js → app/recon.js → app/main.js

(function (root) {
  'use strict';

  const SS = root.SS;
  const api = SS.api;
  const { $, el, clear, icon, copyText, download, toast, formatNumber, debounce, bindMenu } = root.UI;
  const F = root.Findings;
  const Render = root.Render;
  const Recon = root.Recon;

  // ─── State ────────────────────────────────────────────────────────────────
  const params = new URLSearchParams(location.search);
  const state = {
    targetTabId: parseInt(params.get('tab'), 10) || null,
    currentHost: String(params.get('host') || '').trim().toLowerCase(),
    currentPageUrl: String(params.get('url') || '').trim(),
    liveSecrets: [],
    liveEndpoints: [],
    allSecrets: [],
    allEndpoints: [],
    isScanning: false,
    progress: null,
    lastScanTime: null,
    hostLog: SS.createEmptyHostLog(''),
    hostLoadToken: 0,
    ignored: { secrets: new Set(), endpoints: new Set() },
    settings: SS.normalizeSettings(null),
    rules: [],
    activeTab: 'endpoints',
    masked: false,
    pollTimer: null,
    favKey: '',
    favSrc: '',
    ep: { search: '', method: '', kind: '', sort: 'recent', showIgnored: false, expandAll: false, open: new Set(), ctxOpen: new Set() },
    sec: { search: '', severity: '', rule: '', sort: 'severity', showIgnored: false, expandAll: false, open: new Set(), ctxOpen: new Set() },
  };
  state.scanKey = SS.getScanKey(state.targetTabId);

  const manifest = api.runtime.getManifest ? api.runtime.getManifest() : { version: '' };

  // ─── Theme ────────────────────────────────────────────────────────────────
  const mediaDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function applyTheme() {
    const pref = state.settings.theme || 'system';
    const resolved = pref === 'system' ? (mediaDark && !mediaDark.matches ? 'light' : 'dark') : pref;
    document.documentElement.dataset.theme = resolved;
    const btn = $('btn-theme');
    if (btn) {
      clear(btn);
      btn.append(icon(resolved === 'dark' ? 'sun' : 'moon', 14));
      btn.title = `Theme: ${pref}${pref === 'system' ? ` (${resolved})` : ''}. Click to switch.`;
    }
  }
  mediaDark?.addEventListener?.('change', applyTheme);

  // ─── Status / sidebar ─────────────────────────────────────────────────────
  function setDetail(text) {
    const status = $('status-pill');
    status.title = text;
    const sr = $('status-detail');
    if (sr) sr.textContent = text;
  }

  function setStatus(kind, text, sub = '') {
    const pill = $('status-pill');
    pill.dataset.kind = kind;
    $('status-text').textContent = text;
    $('status-sub').textContent = sub;
  }

  function updateStatus() {
    updateProgress();
    if (state.isScanning) {
      const p = state.progress;
      const sub = p && p.sourcesTotal ? `${p.sourcesDone}/${p.sourcesTotal} scripts` : 'page & inline scripts';
      setStatus('scanning', 'Scanning', sub);
      setDetail(state.currentHost ? `Live scan of ${state.currentHost} in progress` : 'Scanning…');
      return;
    }
    if (state.liveSecrets.length || state.liveEndpoints.length) {
      setStatus('live', 'Live', state.lastScanTime ? `updated ${SS.timeAgo(state.lastScanTime)}` : 'scan complete');
      setDetail(state.lastScanTime ? `Last scan ${SS.timeAgo(state.lastScanTime)} · merged with stored log` : 'Live scan complete');
      return;
    }
    const storedAt = state.hostLog.stats?.updatedAt || state.hostLog.updatedAt || null;
    if (storedAt) {
      setStatus('stored', 'Stored', `saved ${SS.timeAgo(storedAt)}`);
      setDetail(`Showing saved findings for ${state.currentHost || 'host'} (no live tab connection)`);
      return;
    }
    if (state.targetTabId) {
      setStatus('waiting', 'Waiting', 'no data from tab yet');
      setDetail('Waiting for the content script. Press Rescan if nothing appears.');
    } else {
      setStatus('idle', 'Idle', state.currentHost ? 'no saved findings' : 'no host');
      setDetail(state.currentHost ? `No saved findings yet for ${state.currentHost}` : 'Open SecretSauce from a page tab to start scanning.');
    }
  }

  // ─── Target favicon ───────────────────────────────────────────────────────
  // The tile mirrors the icon the target tab is actually showing. Both Chrome
  // and Firefox expose it as tab.favIconUrl (via the "tabs" permission), but it
  // can arrive late or change mid-navigation, so we retry on every target
  // refresh until one renders and also react to tabs.onUpdated.
  let favToken = 0;

  function renderMonogram() {
    const fav = $('target-fav');
    const letter = (state.currentHost || '?').replace(/^www\./, '').charAt(0).toUpperCase();
    if (fav.dataset.icon !== 'true' && fav.textContent === letter) return;
    clear(fav);
    fav.dataset.icon = 'false';
    fav.textContent = letter;
  }

  function renderFavicon(src, token) {
    const img = new Image();
    img.alt = '';
    img.decoding = 'async';
    img.referrerPolicy = 'no-referrer';
    img.addEventListener('load', () => {
      if (token !== favToken) return;
      const fav = $('target-fav');
      clear(fav);
      fav.dataset.icon = 'true';
      fav.append(img);
      state.favSrc = src;
    });
    // A 404 or blocked icon leaves favSrc empty so the next refresh retries.
    img.addEventListener('error', () => { if (token === favToken) state.favSrc = ''; });
    img.src = src;
  }

  async function updateFavicon(force) {
    const fav = $('target-fav');
    const key = `${state.targetTabId || ''}|${state.currentHost}`;
    if (key !== state.favKey) {
      state.favKey = key;
      state.favSrc = '';
      renderMonogram();
    } else if (!force && fav.dataset.icon === 'true') {
      return;
    }
    if (!state.targetTabId) return;
    const token = ++favToken;
    const tab = await SS.tabsGet(state.targetTabId);
    if (token !== favToken) return;
    const src = String(tab?.favIconUrl || '');
    // Ignore privileged schemes (chrome://, moz-extension://…) the page can't load.
    if (!/^(https?:|data:image\/)/i.test(src)) {
      state.favSrc = '';
      renderMonogram();
      return;
    }
    if (src !== state.favSrc) renderFavicon(src, token);
  }

  function updateTarget() {
    const host = state.currentHost || 'No host';
    $('target-host').textContent = host;
    $('target-host').title = host;
    $('target-url').textContent = state.currentPageUrl || (state.currentHost ? `https://${state.currentHost}/` : 'No page in context');
    $('target-url').title = state.currentPageUrl || '';
    updateFavicon();
    document.title = state.currentHost ? `${state.currentHost} · SecretSauce` : 'SecretSauce';
  }

  function updateStats() {
    const visibleSecrets = state.allSecrets.filter(s => !state.ignored.secrets.has(s.value));
    const visibleEndpoints = state.allEndpoints.filter(e => !state.ignored.endpoints.has(SS.endpointIdentity(e)));
    const sev = F.severityCounts(visibleSecrets);
    $('stat-endpoints').textContent = formatNumber(visibleEndpoints.length);
    $('stat-secrets').textContent = formatNumber(visibleSecrets.length);
    const crit = $('stat-critical');
    crit.textContent = formatNumber(sev.critical + sev.high);
    crit.dataset.level = sev.critical ? 'critical' : sev.high ? 'high' : 'none';
    $('stat-pages').textContent = formatNumber(state.hostLog.stats?.pageCount || 0);
    $('nav-badge-endpoints').textContent = formatNumber(visibleEndpoints.length);
    const secBadge = $('nav-badge-secrets');
    secBadge.textContent = formatNumber(visibleSecrets.length);
    secBadge.dataset.level = sev.critical ? 'critical' : sev.high ? 'high' : visibleSecrets.length ? 'medium' : 'none';

    // Severity ledger: bars are proportional to the largest bucket so the
    // shape of the distribution reads before the numbers do.
    const max = Math.max(1, ...SS.SEVERITIES.map(s => sev[s]));
    for (const s of SS.SEVERITIES) {
      $(`led-${s}`).textContent = formatNumber(sev[s]);
      $(`bar-${s}`).style.setProperty("--fill", String(sev[s] / max));
      $(`led-${s}`).closest('.ledger-row').dataset.empty = sev[s] ? 'false' : 'true';
    }
  }

  function updateProgress() {
    const p = state.progress;
    const el = $('stat-scripts');
    if (!el) return;
    if (p && p.sourcesTotal) el.textContent = state.isScanning ? `${p.sourcesDone} / ${p.sourcesTotal}` : formatNumber(p.sourcesTotal);
    else el.textContent = state.isScanning ? '…' : '0';
  }

  // ─── Drawer (target panel) ────────────────────────────────────────────────
  const DRAWER_KEY = 'ss-drawer';
  let peekTimer = null;

  function drawerOpen() {
    return $('app').dataset.drawer !== 'closed';
  }

  function setDrawer(open, { persist = true, animate = true } = {}) {
    const app = $('app');
    const drawer = $('drawer');
    const btn = $('btn-drawer');
    drawer.classList.remove('peek');
    const finish = () => {
      drawer.classList.remove('closing');
      app.dataset.drawer = open ? 'open' : 'closed';
    };
    const reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (!open && animate && app.dataset.drawer !== 'closed' && !reduce) {
      drawer.classList.add('closing');
      let done = false;
      const once = () => { if (!done) { done = true; finish(); } };
      drawer.addEventListener('animationend', once, { once: true });
      setTimeout(once, 260); // safety: never leave the drawer stuck if the animation is skipped
    } else finish();
    btn.setAttribute('aria-pressed', open ? 'true' : 'false');
    btn.title = open ? 'Hide the target panel (B)' : 'Show the target panel (B)';
    btn.setAttribute('aria-label', btn.title);
    if (persist) { try { localStorage.setItem(DRAWER_KEY, open ? 'open' : 'closed'); } catch (_) {} }
  }

  function initDrawer() {
    let stored = null;
    try { stored = localStorage.getItem(DRAWER_KEY); } catch (_) {}
    setDrawer(stored ? stored === 'open' : window.innerWidth >= 1000, { persist: false, animate: false });

    // Hover the toggle to peek at the collapsed drawer; click to pin it open or shut.
    const drawer = $('drawer');
    const toggle = $('btn-drawer');
    let armed = true;
    const peek = () => { if (armed && !drawerOpen() && !drawer.classList.contains('peek')) drawer.classList.add('peek'); };
    const unpeek = () => { clearTimeout(peekTimer); peekTimer = setTimeout(() => drawer.classList.remove('peek'), 220); };

    toggle.addEventListener('click', () => { setDrawer(!drawerOpen()); armed = false; });
    toggle.addEventListener('pointermove', () => { clearTimeout(peekTimer); peek(); });
    toggle.addEventListener('mouseleave', () => { armed = true; unpeek(); });
    drawer.addEventListener('mouseenter', () => clearTimeout(peekTimer));
    drawer.addEventListener('mouseleave', unpeek);

    // Overlay modes (peek, or open on a narrow window): a click outside dismisses.
    document.querySelector('.main').addEventListener('pointerdown', () => {
      if (drawer.classList.contains('peek')) drawer.classList.remove('peek');
      else if (drawerOpen() && window.innerWidth <= 760) setDrawer(false);
    });
  }

  // ─── Merge & render ───────────────────────────────────────────────────────
  function rebuild() {
    const merged = F.buildMerged({ hostLog: state.hostLog, liveSecrets: state.liveSecrets, liveEndpoints: state.liveEndpoints, currentPageUrl: state.currentPageUrl });
    state.allSecrets = merged.secrets;
    state.allEndpoints = merged.endpoints;
    updateStats();
    renderEndpoints();
    renderSecrets();
  }

  function openUrl(url) {
    try { api.tabs.create({ url, active: false }); } catch (_) { window.open(url, '_blank', 'noopener'); }
  }

  function chipBar(container, entries, active, onPick, formatLabel) {
    clear(container);
    const total = entries.reduce((n, [, c]) => n + c, 0);
    if (!total && !active) return;
    const all = el('button', { class: 'chip-btn all', type: 'button', 'aria-pressed': active === '' ? 'true' : 'false' }, el('span', { text: 'All' }), el('b', { text: formatNumber(total) }));
    all.addEventListener('click', () => onPick(''));
    container.append(all);
    for (const [value, count] of entries) {
      if (!count) continue;
      const btn = el('button', { class: `chip-btn ${value.toLowerCase()}`, type: 'button', dataset: { value }, 'aria-pressed': active === value ? 'true' : 'false' },
        el('span', { text: formatLabel ? formatLabel(value) : value }), el('b', { text: formatNumber(count) }));
      btn.addEventListener('click', () => onPick(active === value ? '' : value));
      container.append(btn);
    }
  }

  function renderEndpoints() {
    const s = state.ep;
    const base = state.allEndpoints;
    const filtered = F.filterEndpoints(base, { search: s.search, method: s.method, kind: s.kind, ignored: state.ignored.endpoints, showIgnored: s.showIgnored, currentHost: state.currentHost });
    const list = F.sortEndpoints(filtered, s.sort, state.currentHost);

    const counts = F.methodCounts(F.filterEndpoints(base, { search: s.search, kind: s.kind, ignored: state.ignored.endpoints, showIgnored: s.showIgnored, currentHost: state.currentHost }));
    const order = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    chipBar($('ep-method-chips'), order.filter(m => counts[m]).map(m => [m, counts[m]]), s.method, v => { s.method = v; renderEndpoints(); });

    $('ep-count').textContent = list.length ? `${formatNumber(list.length)} endpoint${list.length === 1 ? '' : 's'}` : '';
    $('btn-ep-expand').disabled = list.length === 0;
    $('btn-ep-expand').querySelector('span').textContent = s.expandAll ? 'Collapse all' : 'Expand all';
    $('ep-show-ignored').setAttribute('aria-pressed', s.showIgnored ? 'true' : 'false');
    $('ep-show-ignored').querySelector('b').textContent = formatNumber(state.ignored.endpoints.size);

    const emptyEl = $('ep-empty');
    if (!list.length) {
      Render.renderList($('ep-list'), [], () => null, { emptyEl });
      if (!state.allEndpoints.length) {
        Render.emptyState(emptyEl, state.isScanning
          ? { icon: 'route', title: 'Scanning for endpoints…', sub: 'DOM attributes, inline scripts and same-site bundles are being analysed.' }
          : { icon: 'route', title: 'No endpoints detected', sub: state.currentHost ? `Nothing stored for ${state.currentHost} yet. Try Rescan.` : 'Open SecretSauce from a page tab.' });
      } else if (s.showIgnored) {
        Render.emptyState(emptyEl, { icon: 'ban', title: 'No dismissed endpoints', sub: 'Endpoints you dismiss appear here.' });
      } else {
        Render.emptyState(emptyEl, { icon: 'filter', title: 'No endpoints match the filter', sub: 'Adjust the search, method or source filter.' });
      }
      return;
    }
    emptyEl.classList.add('hidden');

    Render.renderList($('ep-list'), list, endpoint => Render.endpointCard(endpoint, {
      currentHost: state.currentHost,
      open: s.expandAll || s.open.has(SS.endpointIdentity(endpoint)),
      ctxOpen: s.ctxOpen.has(SS.endpointIdentity(endpoint)),
      ignored: state.ignored.endpoints.has(SS.endpointIdentity(endpoint)),
      onToggle: (key, isOpen) => {
        if (s.expandAll) { s.expandAll = false; list.forEach(e => s.open.add(SS.endpointIdentity(e))); $('btn-ep-expand').querySelector('span').textContent = 'Expand all'; }
        isOpen ? s.open.add(key) : s.open.delete(key);
      },
      onToggleCtx: (key, v) => v ? s.ctxOpen.add(key) : s.ctxOpen.delete(key),
      onIgnore: (key, ignore) => setIgnored('endpoints', key, ignore),
      onOpenUrl: openUrl,
    }), { emptyEl, chunk: 80 });
  }

  function renderSecrets() {
    const s = state.sec;
    const filteredNoSev = F.filterSecrets(state.allSecrets, { search: s.search, ruleId: s.rule, ignored: state.ignored.secrets, showIgnored: s.showIgnored });
    const filtered = s.severity ? filteredNoSev.filter(x => x.severity === s.severity) : filteredNoSev;
    const list = F.sortSecrets(filtered, s.sort);

    const counts = F.severityCounts(filteredNoSev);
    chipBar($('sec-sev-chips'), SS.SEVERITIES.map(sev => [sev, counts[sev]]), s.severity, v => { s.severity = v; renderSecrets(); }, v => v.charAt(0).toUpperCase() + v.slice(1));

    // Rule dropdown reflects rules present in the current result set
    const ruleSel = $('sec-rule');
    const present = new Map();
    for (const sec of state.allSecrets) for (const id of (sec.ids || [sec.id])) present.set(id, (present.get(id) || 0) + 1);
    const keep = ruleSel.value;
    while (ruleSel.options.length > 1) ruleSel.remove(1);
    [...present.entries()].sort((a, b) => b[1] - a[1]).forEach(([id, n]) => {
      const rule = state.rules.find(r => r.id === id);
      ruleSel.append(el('option', { value: id, text: `${rule ? rule.name : id} (${n})` }));
    });
    ruleSel.value = [...ruleSel.options].some(o => o.value === keep) ? keep : '';
    if (ruleSel.value !== s.rule) s.rule = ruleSel.value;

    $('sec-count').textContent = list.length ? `${formatNumber(list.length)} secret${list.length === 1 ? '' : 's'}` : '';
    $('btn-sec-expand').disabled = list.length === 0;
    $('btn-sec-expand').querySelector('span').textContent = s.expandAll ? 'Collapse all' : 'Expand all';
    $('sec-show-ignored').setAttribute('aria-pressed', s.showIgnored ? 'true' : 'false');
    $('sec-show-ignored').querySelector('b').textContent = formatNumber(state.ignored.secrets.size);
    const maskBtn = $('btn-sec-mask');
    clear(maskBtn);
    maskBtn.append(icon(state.masked ? 'eyeOff' : 'eye', 14));
    maskBtn.title = state.masked ? 'Values are masked. Click to reveal them.' : 'Mask secret values for screenshots and demos';
    maskBtn.setAttribute('aria-label', maskBtn.title);
    maskBtn.setAttribute('aria-pressed', state.masked ? 'true' : 'false');

    const emptyEl = $('sec-empty');
    if (!list.length) {
      Render.renderList($('sec-list'), [], () => null, { emptyEl });
      if (!state.allSecrets.length) {
        Render.emptyState(emptyEl, state.isScanning
          ? { icon: 'key', title: 'Scanning for secrets…', sub: `${state.rules.length || 'All'} detection rules plus the entropy heuristic are running.` }
          : { icon: 'party', title: 'No secrets detected', sub: state.currentHost ? `Nothing found on ${state.currentHost} so far.` : 'Open SecretSauce from a page tab.' });
      } else if (s.showIgnored) {
        Render.emptyState(emptyEl, { icon: 'ban', title: 'No dismissed secrets', sub: 'Secrets you mark as false positives appear here.' });
      } else {
        Render.emptyState(emptyEl, { icon: 'filter', title: 'No secrets match the filter' });
      }
      return;
    }
    emptyEl.classList.add('hidden');

    Render.renderList($('sec-list'), list, secret => Render.secretCard(secret, {
      open: s.expandAll || s.open.has(secret.value),
      ctxOpen: s.ctxOpen.has(secret.value),
      ignored: state.ignored.secrets.has(secret.value),
      masked: state.masked,
      onToggle: (key, isOpen) => {
        if (s.expandAll) { s.expandAll = false; list.forEach(x => s.open.add(x.value)); $('btn-sec-expand').querySelector('span').textContent = 'Expand all'; }
        isOpen ? s.open.add(key) : s.open.delete(key);
      },
      onToggleCtx: (key, v) => v ? s.ctxOpen.add(key) : s.ctxOpen.delete(key),
      onIgnore: (key, ignore) => setIgnored('secrets', key, ignore),
    }), { emptyEl, chunk: 80 });
  }

  // ─── Ignore list ──────────────────────────────────────────────────────────
  async function loadIgnored() {
    const key = SS.getIgnoreKey(state.currentHost);
    if (!key) { state.ignored = { secrets: new Set(), endpoints: new Set() }; return; }
    const stored = (await SS.storageGet(key))[key] || {};
    state.ignored = { secrets: new Set(stored.secrets || []), endpoints: new Set(stored.endpoints || []) };
  }

  async function saveIgnored() {
    const key = SS.getIgnoreKey(state.currentHost);
    if (!key) return;
    await SS.storageSet({ [key]: { secrets: [...state.ignored.secrets], endpoints: [...state.ignored.endpoints], updatedAt: Date.now() } }).catch(() => {});
  }

  function setIgnored(kind, key, ignore) {
    const set = state.ignored[kind];
    ignore ? set.add(key) : set.delete(key);
    saveIgnored();
    updateStats();
    kind === 'secrets' ? renderSecrets() : renderEndpoints();
    toast(ignore ? 'Dismissed. Review it under Dismissed.' : 'Restored', 'success');
  }

  // ─── Data loading ─────────────────────────────────────────────────────────
  function setContext(url, hostname) {
    const nextUrl = String(url || '').trim();
    if (nextUrl) state.currentPageUrl = nextUrl;
    const nextHost = String(hostname || SS.getHostname(nextUrl) || '').toLowerCase();
    updateTarget();
    if (!nextHost || nextHost === state.currentHost) return false;
    state.currentHost = nextHost;
    state.hostLog = SS.createEmptyHostLog(nextHost);
    state.ep.open.clear(); state.sec.open.clear();
    Recon.setHost(nextHost);
    updateTarget();
    return true;
  }

  function applyLive(data) {
    if (!data) {
      state.liveSecrets = [];
      state.liveEndpoints = [];
      state.isScanning = false;
      state.progress = null;
      updateStatus();
      rebuild();
      return false;
    }
    const hostChanged = setContext(data.url, data.hostname);
    // Skip the merge + re-render when the poll returned the same payload shape.
    const signature = `${data.scanId || ''}|${(data.secrets || []).length}|${(data.endpoints || []).length}|${data.complete ? 1 : 0}`;
    const unchanged = !hostChanged && signature === state.liveSignature;
    state.liveSignature = signature;
    state.liveSecrets = data.secrets || [];
    state.liveEndpoints = data.endpoints || [];
    state.isScanning = !data.complete;
    state.progress = data.progress || null;
    state.lastScanTime = data.scanTime || state.lastScanTime;
    updateStatus();
    if (!unchanged) rebuild();
    return hostChanged;
  }

  async function readLive() {
    if (!state.targetTabId) return null;
    try {
      const resp = await SS.tabsSendMessage(state.targetTabId, { type: 'GET_RESULTS' }, 1200);
      if (resp) return resp;
    } catch (_) {}
    const stored = await SS.storageGet(state.scanKey);
    return stored[state.scanKey] || null;
  }

  async function loadHostLog() {
    const host = state.currentHost;
    if (!host) { state.hostLog = SS.createEmptyHostLog(''); return; }
    const token = ++state.hostLoadToken;
    const key = SS.getHostLogKey(host);
    const [items] = await Promise.all([SS.storageGet(key), loadIgnored()]);
    if (token !== state.hostLoadToken || host !== state.currentHost) return;
    state.hostLog = items[key] || SS.createEmptyHostLog(host);
    if (!state.hostLog.hostname) state.hostLog.hostname = host;
  }

  async function refresh() {
    const data = await readLive();
    const hostChanged = applyLive(data);
    if (hostChanged || !state.hostLog.hostname || state.hostLog.hostname !== state.currentHost) {
      await loadHostLog();
      updateStatus();
      rebuild();
    }
  }

  function startPolling() {
    clearInterval(state.pollTimer);
    const deadline = Date.now() + 120_000;
    state.pollTimer = setInterval(async () => {
      await refresh();
      if (!state.isScanning || Date.now() > deadline) {
        clearInterval(state.pollTimer);
        $('btn-rescan').classList.remove('spinning');
        if (state.isScanning) { state.isScanning = false; updateStatus(); }
      }
    }, 900);
  }

  async function rescan() {
    if (!state.targetTabId) return toast('No page tab in context. Open SecretSauce from a page.', 'info');
    $('btn-rescan').classList.add('spinning');
    state.liveSecrets = [];
    state.liveEndpoints = [];
    state.isScanning = true;
    state.progress = null;
    updateStatus();
    rebuild();
    try {
      await SS.tabsSendMessage(state.targetTabId, { type: 'RESCAN' }, 1500);
    } catch (_) {
      // Content script not present (page loaded before install / extension reload) → inject.
      try {
        const resp = await SS.sendMessage({ type: 'INJECT_CONTENT', tabId: state.targetTabId });
        if (!resp?.ok) throw new Error(resp?.error || 'inject failed');
      } catch (err) {
        $('btn-rescan').classList.remove('spinning');
        state.isScanning = false;
        updateStatus();
        toast(`Cannot scan this tab: ${String(err?.message || err).replace(/^Error:\s*/, '')}`, 'error');
        return;
      }
    }
    startPolling();
  }

  // ─── Hosts panel ──────────────────────────────────────────────────────────
  async function loadHosts() {
    const all = await SS.storageGet(null);
    const hosts = [];
    // Chrome reports usage directly; Firefox lacks getBytesInUse, so estimate.
    let bytes = await new Promise(resolve => {
      try { api.storage.local.getBytesInUse(null, n => resolve(api.runtime.lastError ? null : n)); } catch (_) { resolve(null); }
    });
    if (bytes == null) bytes = Object.values(all).reduce((n, v) => n + JSON.stringify(v).length, 0);
    for (const [key, value] of Object.entries(all)) {
      if (!key.startsWith(SS.HOST_LOG_PREFIX)) continue;
      const hostname = value?.hostname || SS.hostFromLogKey(key);
      hosts.push({
        hostname,
        stats: value?.stats || SS.summarizeHostLog(value),
        severityCounts: F.severityCounts(value?.secrets || []),
        updatedAt: value?.updatedAt || value?.stats?.updatedAt || 0,
      });
    }
    hosts.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    const q = ($('hosts-search').value || '').trim().toLowerCase();
    const shown = q ? hosts.filter(h => h.hostname.includes(q)) : hosts;

    $('nav-badge-hosts').textContent = formatNumber(hosts.length);
    const hostsStat = $('stat-hosts');
    if (hostsStat) hostsStat.textContent = formatNumber(hosts.length);
    const totals = hosts.reduce((acc, h) => ({ e: acc.e + h.stats.uniqueEndpoints, s: acc.s + h.stats.uniqueSecrets }), { e: 0, s: 0 });
    $('hosts-summary').textContent = hosts.length
      ? `${formatNumber(hosts.length)} host${hosts.length === 1 ? '' : 's'} · ${formatNumber(totals.e)} endpoints · ${formatNumber(totals.s)} secrets · ~${(bytes / 1024).toFixed(0)} KB stored`
      : '';
    const storageEl = $('storage-usage');
    if (storageEl) storageEl.textContent = `${(bytes / 1024).toFixed(0)} KB used across ${formatNumber(hosts.length)} host logs`;

    const emptyEl = $('hosts-empty');
    if (!shown.length) {
      clear($('hosts-table'));
      Render.emptyState(emptyEl, hosts.length ? { icon: 'filter', title: 'No hosts match' } : { icon: 'hosts', title: 'No stored hosts yet', sub: 'Every scanned hostname keeps a deduplicated log here.' });
      return;
    }
    emptyEl.classList.add('hidden');
    Render.hostsTable($('hosts-table'), shown, {
      currentHost: state.currentHost,
      onOpen: hostname => { location.href = `app.html?${new URLSearchParams({ host: hostname })}`; },
      onDelete: async hostname => {
        if (!confirm(`Delete all stored findings for ${hostname}? This cannot be undone.`)) return;
        await SS.storageRemove([SS.getHostLogKey(hostname), SS.getIgnoreKey(hostname)]);
        toast(`Deleted stored data for ${hostname}`, 'success');
        if (hostname === state.currentHost) { state.hostLog = SS.createEmptyHostLog(hostname); await loadIgnored(); rebuild(); updateStatus(); }
        loadHosts();
      },
    });
  }

  // ─── Settings panel ───────────────────────────────────────────────────────
  function fillSettingsForm() {
    const s = state.settings;
    document.querySelectorAll('[data-setting]').forEach(input => {
      const key = input.dataset.setting;
      if (input.type === 'checkbox') input.checked = !!s[key];
      else input.value = Array.isArray(s[key]) ? s[key].join('\n') : (s[key] ?? '');
    });
    $('about-version').textContent = manifest.version ? `v${manifest.version}` : '';
    $('brand-version').textContent = manifest.version ? `v${manifest.version}` : '';
    renderRules();
  }

  const persistSettings = debounce(async () => {
    state.settings = await SS.saveSettings(state.settings);
    applyTheme();
    toast('Settings saved. They apply to the next scan.', 'success');
  }, 250);

  function bindSettingsForm() {
    document.querySelectorAll('[data-setting]').forEach(input => {
      input.addEventListener('change', () => {
        const key = input.dataset.setting;
        if (input.type === 'checkbox') state.settings[key] = input.checked;
        else if (input.type === 'number') state.settings[key] = Number(input.value);
        else if (input.tagName === 'TEXTAREA') state.settings[key] = input.value.split(/[\n,]/).map(v => v.trim()).filter(Boolean);
        else state.settings[key] = input.value;
        persistSettings();
      });
    });
    $('rules-search').addEventListener('input', debounce(renderRules, 80));
    $('btn-rules-all').addEventListener('click', () => { state.settings.disabledRules = []; renderRules(); persistSettings(); });
    $('btn-rules-none').addEventListener('click', () => { state.settings.disabledRules = state.rules.map(r => r.id); renderRules(); persistSettings(); });
    $('btn-clear-host-data').addEventListener('click', async () => {
      if (!state.currentHost) return toast('No host in context', 'info');
      if (!confirm(`Delete stored findings and dismissals for ${state.currentHost}?`)) return;
      await SS.storageRemove([SS.getHostLogKey(state.currentHost), SS.getIgnoreKey(state.currentHost)]);
      state.hostLog = SS.createEmptyHostLog(state.currentHost);
      state.ignored = { secrets: new Set(), endpoints: new Set() };
      rebuild(); updateStatus(); loadHosts();
      toast(`Cleared ${state.currentHost}`, 'success');
    });
    $('btn-clear-all-data').addEventListener('click', async () => {
      if (!confirm('Delete ALL stored findings for every host, plus dismissals? Settings are kept.')) return;
      const all = await SS.storageGet(null);
      const keys = Object.keys(all).filter(k => k.startsWith(SS.HOST_LOG_PREFIX) || k.startsWith(SS.IGNORE_PREFIX) || k === SS.LAST_APP_CONTEXT_KEY);
      await SS.storageRemove(keys);
      state.hostLog = SS.createEmptyHostLog(state.currentHost);
      state.ignored = { secrets: new Set(), endpoints: new Set() };
      rebuild(); updateStatus(); loadHosts();
      toast('All stored findings deleted', 'success');
    });
  }

  function renderRules() {
    Render.rulesList($('rules-list'), state.rules, new Set(state.settings.disabledRules), (id, enabled) => {
      const set = new Set(state.settings.disabledRules);
      enabled ? set.delete(id) : set.add(id);
      state.settings.disabledRules = [...set];
      $('rules-summary').textContent = `${state.rules.length - set.size} of ${state.rules.length} rules enabled`;
      persistSettings();
    }, $('rules-search').value);
    $('rules-summary').textContent = `${state.rules.length - state.settings.disabledRules.length} of ${state.rules.length} rules enabled`;
  }

  // ─── Export ───────────────────────────────────────────────────────────────
  function visibleSecrets() {
    return F.sortSecrets(F.filterSecrets(state.allSecrets, { search: state.sec.search, ruleId: state.sec.rule, severity: state.sec.severity, ignored: state.ignored.secrets, showIgnored: state.sec.showIgnored }), state.sec.sort);
  }
  function visibleEndpoints() {
    return F.sortEndpoints(F.filterEndpoints(state.allEndpoints, { ...state.ep, ignored: state.ignored.endpoints, currentHost: state.currentHost }), state.ep.sort, state.currentHost);
  }

  function exportAs(format) {
    const host = state.currentHost || SS.getHostname(state.currentPageUrl) || 'export';
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const endpoints = state.allEndpoints.filter(e => !state.ignored.endpoints.has(SS.endpointIdentity(e)));
    const secrets = state.allSecrets.filter(s => !state.ignored.secrets.has(s.value));
    switch (format) {
      case 'json':
        return download(`secretsauce-${host}-${stamp}.json`, JSON.stringify({
          exportedAt: new Date().toISOString(),
          version: manifest.version,
          hostname: host,
          currentScan: { url: state.currentPageUrl, scanTime: state.lastScanTime, complete: !state.isScanning, secrets: state.liveSecrets, endpoints: state.liveEndpoints },
          hostLog: state.hostLog,
          dismissed: { secrets: [...state.ignored.secrets], endpoints: [...state.ignored.endpoints] },
          mergedFindings: { secrets, endpoints },
        }, null, 2), 'application/json');
      case 'csv-endpoints':
        return download(`secretsauce-${host}-endpoints-${stamp}.csv`, F.endpointsCsv(endpoints), 'text/csv');
      case 'csv-secrets':
        return download(`secretsauce-${host}-secrets-${stamp}.csv`, F.secretsCsv(secrets), 'text/csv');
      case 'txt-urls':
        return download(`secretsauce-${host}-urls-${stamp}.txt`, endpoints.map(e => e.url || F.endpointDisplayUrl(e, '')).filter(Boolean).join('\n'));
      case 'txt-secrets':
        return download(`secretsauce-${host}-secrets-${stamp}.txt`, secrets.map(s => s.value).filter(Boolean).join('\n'));
      case 'txt-all':
        return download(`secretsauce-${host}-${stamp}.txt`, [...endpoints.map(e => e.url || F.endpointDisplayUrl(e, '')), ...secrets.map(s => s.value)].filter(Boolean).join('\n'));
      default:
        return null;
    }
  }

  // ─── Tabs ─────────────────────────────────────────────────────────────────
  function showTab(tab) {
    state.activeTab = tab;
    document.querySelectorAll('.nav-btn').forEach(btn => {
      const isActive = btn.dataset.tab === tab;
      btn.classList.toggle('active', isActive);
      if (isActive) btn.setAttribute('aria-current', 'page'); else btn.removeAttribute('aria-current');
    });
    document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id === `panel-${tab}`));
    if (Recon.IFRAME_TABS.includes(tab) || tab === 'wayback') Recon.showTab(tab);
    if (tab === 'hosts') loadHosts();
    try { history.replaceState(null, '', `#${tab}`); } catch (_) {}
  }

  // ─── Events ───────────────────────────────────────────────────────────────
  function bindEvents() {
    document.querySelectorAll('.nav-btn').forEach(btn => btn.addEventListener('click', () => showTab(btn.dataset.tab)));

    $('btn-rescan').addEventListener('click', rescan);
    $('btn-theme').addEventListener('click', () => {
      const order = ['system', 'dark', 'light'];
      state.settings.theme = order[(order.indexOf(state.settings.theme) + 1) % order.length];
      applyTheme();
      fillSettingsForm();
      SS.saveSettings(state.settings).catch(() => {});
    });
    bindMenu($('btn-export'), $('menu-export'));
    $('menu-export').querySelectorAll('[data-export]').forEach(item => item.addEventListener('click', () => exportAs(item.dataset.export)));

    // Endpoints toolbar
    $('ep-search').addEventListener('input', debounce(e => { state.ep.search = e.target.value; renderEndpoints(); }, 100));
    $('ep-kind').addEventListener('change', e => { state.ep.kind = e.target.value; renderEndpoints(); });
    $('ep-sort').addEventListener('change', e => { state.ep.sort = e.target.value; renderEndpoints(); });
    $('ep-show-ignored').addEventListener('click', () => { state.ep.showIgnored = !state.ep.showIgnored; renderEndpoints(); });
    $('btn-ep-expand').addEventListener('click', () => { state.ep.expandAll = !state.ep.expandAll; if (!state.ep.expandAll) state.ep.open.clear(); renderEndpoints(); });
    $('btn-ep-copy-all').addEventListener('click', () => {
      const urls = visibleEndpoints().map(e => e.url || F.endpointDisplayUrl(e, '')).filter(Boolean);
      if (!urls.length) return toast('Nothing to copy', 'info');
      copyText(urls.join('\n'), null).then(() => toast(`Copied ${formatNumber(urls.length)} URLs`, 'success'));
    });

    // Secrets toolbar
    $('sec-search').addEventListener('input', debounce(e => { state.sec.search = e.target.value; renderSecrets(); }, 100));
    $('sec-rule').addEventListener('change', e => { state.sec.rule = e.target.value; renderSecrets(); });
    $('sec-sort').addEventListener('change', e => { state.sec.sort = e.target.value; renderSecrets(); });
    $('sec-show-ignored').addEventListener('click', () => { state.sec.showIgnored = !state.sec.showIgnored; renderSecrets(); });
    $('btn-sec-expand').addEventListener('click', () => { state.sec.expandAll = !state.sec.expandAll; if (!state.sec.expandAll) state.sec.open.clear(); renderSecrets(); });
    $('btn-sec-mask').addEventListener('click', () => { state.masked = !state.masked; renderSecrets(); });
    $('btn-sec-copy-all').addEventListener('click', () => {
      const values = visibleSecrets().map(s => s.value).filter(Boolean);
      if (!values.length) return toast('Nothing to copy', 'info');
      copyText(values.join('\n'), null).then(() => toast(`Copied ${formatNumber(values.length)} values`, 'success'));
    });

    // Hosts
    $('hosts-search').addEventListener('input', debounce(loadHosts, 100));
    $('btn-hosts-refresh').addEventListener('click', loadHosts);

    // Keyboard shortcuts
    document.addEventListener('keydown', event => {
      const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName);
      if (event.key === '/' && !inField) {
        event.preventDefault();
        const search = document.querySelector('.panel.active .search input');
        search?.focus();
        search?.select();
      } else if (event.key === 'Escape' && inField && event.target.classList.contains('s-input')) {
        event.target.value = '';
        event.target.dispatchEvent(new Event('input'));
        event.target.blur();
      } else if (event.key === 'r' && !inField && !event.metaKey && !event.ctrlKey) {
        rescan();
      } else if (event.key === 'b' && !inField && !event.metaKey && !event.ctrlKey) {
        setDrawer(!drawerOpen());
      } else if (/^[1-9]$/.test(event.key) && !inField && event.altKey) {
        const buttons = [...document.querySelectorAll('.nav-btn')];
        const target = buttons[parseInt(event.key, 10) - 1];
        if (target) { event.preventDefault(); showTab(target.dataset.tab); }
      }
    });

    // Live updates from storage (content script persists progressively)
    api.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== 'local') return;
      const hostKey = SS.getHostLogKey(state.currentHost);
      if (hostKey && changes[hostKey]) {
        state.hostLog = changes[hostKey].newValue || SS.createEmptyHostLog(state.currentHost);
        updateStatus();
        rebuild();
      }
      const ignoreKey = SS.getIgnoreKey(state.currentHost);
      if (ignoreKey && changes[ignoreKey]) {
        const v = changes[ignoreKey].newValue || {};
        state.ignored = { secrets: new Set(v.secrets || []), endpoints: new Set(v.endpoints || []) };
        rebuild();
      }
      if (changes[SS.SETTINGS_KEY]) {
        state.settings = SS.normalizeSettings(changes[SS.SETTINGS_KEY].newValue);
        applyTheme();
      }
      if (state.scanKey && changes[state.scanKey]) {
        const next = changes[state.scanKey].newValue || null;
        if (next) {
          const hostChanged = applyLive(next);
          if (hostChanged) loadHostLog().then(() => { updateStatus(); rebuild(); });
          if (!next.complete) startPolling();
          else $('btn-rescan').classList.remove('spinning');
        }
      }
    });
  }

  // ─── Init ─────────────────────────────────────────────────────────────────
  async function init() {
    state.settings = await SS.getSettings();
    applyTheme();
    initDrawer();
    bindEvents();
    Recon.bind();
    bindSettingsForm();

    SS.sendMessage({ type: 'GET_RULES' }).then(resp => { state.rules = resp?.rules || []; fillSettingsForm(); renderSecrets(); }).catch(() => fillSettingsForm());

    updateTarget();

    if (state.targetTabId) {
      const tab = await SS.tabsGet(state.targetTabId);
      if (tab?.url) setContext(tab.url, SS.getHostname(tab.url));
    }

    if (state.targetTabId && api.tabs?.onUpdated?.addListener) {
      api.tabs.onUpdated.addListener((tabId, changeInfo) => {
        if (tabId !== state.targetTabId) return;
        if (!('favIconUrl' in changeInfo) && !changeInfo.url && changeInfo.status !== 'complete') return;
        updateFavicon(true);
      });
    }
    Recon.setHost(state.currentHost);
    await loadHostLog();
    await refresh();
    updateStatus();
    if (state.isScanning) startPolling();

    const initialTab = location.hash.replace('#', '');
    showTab(document.querySelector(`.nav-btn[data-tab="${initialTab}"]`) ? initialTab : 'endpoints');
    loadHosts();
  }

  init().catch(err => {
    console.error('[SecretSauce] app init failed', err);
    toast('App failed to initialise. See the console for details.', 'error');
  });

  root.SSApp = { state, rescan, showTab, exportAs };
})(globalThis);
