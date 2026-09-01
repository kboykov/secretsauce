// SecretSauce — Content Script
// Runs after shared.js and detect.js (see manifest content_scripts order).
// Author: K. Boykov

(function () {
  'use strict';

  if (window.__secretSauceInitialized) return;
  window.__secretSauceInitialized = true;

  const SS = globalThis.SS;
  const D = globalThis.SSDetect;
  if (!SS || !D) {
    console.warn('[SecretSauce] shared modules missing, content script not started');
    return;
  }

  // ─── State ────────────────────────────────────────────────────────────────
  let settings = SS.normalizeSettings(null);
  let compiledRules = [];
  let myTabId = null;

  let foundSecrets = [];
  let foundEndpoints = [];
  let secretKeys = new Set();       // D.secretKey() for every reported secret
  let knownSecretValues = new Set(); // values already attributed to a named rule
  let endpointKeys = new Set();     // method:url for every reported endpoint

  let pendingSecrets = [];
  let pendingEndpoints = [];
  let pendingEndpointKeys = new Set();

  let scanComplete = false;
  let currentScanId = null;
  let lastObservedUrl = location.href;
  let sourcesTotal = 0;
  let sourcesDone = 0;
  let routeTimer = null;
  let routePoller = null;
  let scanning = false;

  const observedNetworkEndpoints = new Map();

  // ─── Helpers ──────────────────────────────────────────────────────────────
  const pageCtx = () => ({ pageUrl: location.href, pageHost: location.hostname.toLowerCase() });

  function createScanId() {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  function isStaleScan(scanId) {
    return scanId !== currentScanId;
  }

  function addSecret(secret) {
    const key = D.secretKey(secret.id, secret.value, secret.source);
    if (secretKeys.has(key)) return false;
    secretKeys.add(key);
    knownSecretValues.add(secret.value);
    foundSecrets.push(secret);
    pendingSecrets.push(secret);
    return true;
  }

  function addEndpoint(endpoint) {
    const key = `${endpoint.method}:${endpoint.url}`;
    const isNew = !endpointKeys.has(key);
    if (isNew) {
      endpointKeys.add(key);
      foundEndpoints.push(endpoint);
    }
    // Always log new (key, source) pairs so the host log learns every source.
    const pendingKey = `${key}|${endpoint.source}`;
    if (!pendingEndpointKeys.has(pendingKey)) {
      pendingEndpointKeys.add(pendingKey);
      pendingEndpoints.push(endpoint);
    }
    return isNew;
  }

  function resetScanState() {
    foundSecrets = [];
    foundEndpoints = [];
    secretKeys = new Set();
    knownSecretValues = new Set();
    endpointKeys = new Set();
    pendingSecrets = [];
    pendingEndpoints = [];
    pendingEndpointKeys = new Set();
    scanComplete = false;
    sourcesTotal = 0;
    sourcesDone = 0;
    currentScanId = createScanId();
    lastObservedUrl = location.href;
    // Network history survives route changes inside the same document.
    for (const endpoint of observedNetworkEndpoints.values()) addEndpoint({ ...endpoint });
  }

  // ─── DOM endpoint collection ──────────────────────────────────────────────
  const DOM_SOURCES = [
    ['a[href]', 'href', 'GET'],
    ['form[action]', 'action', null],
    ['iframe[src]', 'src', 'GET'],
    ['script[src]', 'src', 'GET'],
    ['link[href]', 'href', 'GET'],
    ['img[src]', 'src', 'GET'],
    ['source[src],video[src],audio[src],track[src]', 'src', 'GET'],
    ['[data-url],[data-href],[data-src],[data-action],[data-endpoint],[data-api]', null, 'GET'],
    ['[hx-get],[hx-post],[hx-put],[hx-delete],[hx-patch]', null, null],
  ];

  function collectDomEndpoints() {
    const found = [];
    const ctx = pageCtx();

    const tryAdd = (rawAttr, method, el) => {
      if (!rawAttr) return;
      const context = el ? D.formatContextSnippet(el.outerHTML).slice(0, 900) : '';
      const endpoint = D.resolveCandidate(rawAttr.trim(), {
        ...ctx, includeSubdomains: false, kind: 'dom', method: method || 'GET', source: location.href, context,
      });
      if (endpoint) found.push(endpoint);
    };

    for (const [selector, attr, method] of DOM_SOURCES) {
      let nodes;
      try { nodes = document.querySelectorAll(selector); } catch (_) { continue; }
      nodes.forEach(el => {
        if (attr) {
          const m = method || (el.getAttribute('method') || 'GET').toUpperCase();
          tryAdd(el.getAttribute(attr) || (attr === 'action' ? location.pathname : ''), m, el);
          return;
        }
        // data-* / htmx style attributes
        for (const name of el.getAttributeNames()) {
          const lower = name.toLowerCase();
          if (/^data-(?:url|href|src|action|endpoint|api)$/.test(lower)) tryAdd(el.getAttribute(name), 'GET', el);
          const hx = lower.match(/^hx-(get|post|put|delete|patch)$/);
          if (hx) tryAdd(el.getAttribute(name), hx[1].toUpperCase(), el);
        }
      });
    }
    return found;
  }

  // ─── Inline script endpoint collection ────────────────────────────────────
  function scanInlineScripts() {
    const found = [];
    const ctx = pageCtx();
    const candidates = new Map();

    document.querySelectorAll('script:not([src])').forEach(script => {
      const text = script.textContent || '';
      if (text.trim()) D.collectInlineCandidates(text, candidates);
    });

    candidates.forEach((context, candidate) => {
      const endpoint = D.resolveCandidate(candidate, {
        ...ctx, includeSubdomains: false, kind: 'inline', method: 'GET', source: location.href, context,
      });
      if (endpoint) found.push(endpoint);
    });
    return found;
  }

  // ─── Network history (Performance API) ────────────────────────────────────
  function parseNetworkEntry(entry) {
    if (!entry?.name) return null;
    const initiator = String(entry.initiatorType || 'resource').trim().toLowerCase();
    return D.resolveCandidate(entry.name, {
      ...pageCtx(),
      includeSubdomains: settings.includeSubdomains,
      kind: `network-${initiator || 'resource'}`,
      method: 'GET',
      source: location.href,
      context: `Observed in network history via ${initiator || 'resource'} timing entry`,
    });
  }

  function ingestNetworkHistory(entries = [], { persistAfter = true } = {}) {
    let changed = false;
    for (const entry of entries) {
      const endpoint = parseNetworkEntry(entry);
      if (!endpoint) continue;
      const key = `${endpoint.method}:${endpoint.url}`;
      if (!observedNetworkEndpoints.has(key)) observedNetworkEndpoints.set(key, endpoint);
      if (addEndpoint(endpoint)) changed = true;
    }
    if (changed && persistAfter) void persist();
  }

  function installNetworkObserver() {
    try {
      if (typeof performance?.getEntriesByType === 'function') {
        ingestNetworkHistory(performance.getEntriesByType('resource'), { persistAfter: false });
      }
    } catch (_) {}

    if (typeof PerformanceObserver !== 'function') return;
    const handler = list => ingestNetworkHistory(list.getEntries(), { persistAfter: true });
    try {
      new PerformanceObserver(handler).observe({ type: 'resource', buffered: true });
    } catch (_) {
      try { new PerformanceObserver(handler).observe({ entryTypes: ['resource'] }); } catch (_2) {}
    }
  }

  // ─── External source collection ───────────────────────────────────────────
  function collectSources() {
    const ctx = { ...pageCtx(), includeSubdomains: settings.includeSubdomains };
    const urls = new Set();

    document.querySelectorAll('script[src]').forEach(el => {
      try {
        const u = new URL(el.src, location.href);
        if (/^https?:$/.test(u.protocol) && SS.isSameSite(u.hostname, ctx.pageHost, ctx.includeSubdomains)) urls.add(u.href);
      } catch (_) {}
    });

    document.querySelectorAll('link[href]').forEach(el => {
      const h = el.getAttribute('href') || '';
      const rel = (el.getAttribute('rel') || '').toLowerCase();
      if (/\.(m?js|json)(\?|$)/i.test(h) || rel.includes('modulepreload') || rel === 'manifest') {
        try {
          const u = new URL(h, location.href);
          if (/^https?:$/.test(u.protocol) && SS.isSameSite(u.hostname, ctx.pageHost, ctx.includeSubdomains)) urls.add(u.href);
        } catch (_) {}
      }
    });

    const inline = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
    for (const url of D.collectScriptUrlsFromText(inline, ctx)) urls.add(url);

    // Scripts observed loading through the network (dynamic import(), lazy chunks)
    try {
      for (const entry of performance.getEntriesByType('resource')) {
        if (entry.initiatorType !== 'script' && !/\.m?js(\?|$)/i.test(entry.name)) continue;
        try {
          const u = new URL(entry.name);
          if (/^https?:$/.test(u.protocol) && SS.isSameSite(u.hostname, ctx.pageHost, ctx.includeSubdomains)) urls.add(u.href);
        } catch (_) {}
      }
    } catch (_) {}

    return Array.from(urls).slice(0, settings.maxExternalScripts);
  }

  async function fetchText(url, timeoutMs = 15000) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
      const res = await fetch(url, { credentials: 'omit', cache: 'force-cache', signal: controller?.signal });
      if (!res.ok) return null;
      const ct = res.headers.get('content-type') || '';
      if (ct && !/javascript|ecmascript|json|text|manifest/i.test(ct)) return null;
      const t = await res.text();
      return t.length > 6_000_000 ? t.slice(0, 6_000_000) : t;
    } catch (_) {
      return null;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  // ─── Persist ──────────────────────────────────────────────────────────────
  async function pushPendingFindingsToLog(scanTime) {
    if (!pendingSecrets.length && !pendingEndpoints.length) return;
    const secretsToLog = pendingSecrets;
    const endpointsToLog = pendingEndpoints;
    pendingSecrets = [];
    pendingEndpoints = [];
    try {
      await SS.sendMessage({
        type: 'LOG_FINDINGS',
        scanId: currentScanId,
        pageUrl: location.href,
        scanTime,
        secrets: secretsToLog,
        endpoints: endpointsToLog,
      });
    } catch (error) {
      console.warn('[SecretSauce] persistent log:', error);
      pendingSecrets = secretsToLog.concat(pendingSecrets);
      pendingEndpoints = endpointsToLog.concat(pendingEndpoints);
    }
  }

  function stripContext(items) {
    return items.map(({ context, ...rest }) => rest);
  }

  async function persist() {
    const scanId = currentScanId;
    if (!myTabId || isStaleScan(scanId)) return;
    const scanTime = Date.now();
    const key = SS.getScanKey(myTabId);
    const payload = {
      url: location.href,
      hostname: location.hostname.toLowerCase(),
      secrets: foundSecrets,
      endpoints: foundEndpoints,
      complete: scanComplete,
      scanning,
      scanTime,
      scanId,
      progress: { sourcesTotal, sourcesDone },
    };
    try {
      await SS.storageSet({ [key]: payload });
    } catch (_) {
      // Quota exceeded: retry without context strings so complete:true still lands.
      try {
        await SS.storageSet({ [key]: { ...payload, secrets: stripContext(foundSecrets), endpoints: stripContext(foundEndpoints) } });
      } catch (_2) {}
    }
    if (isStaleScan(scanId)) return;
    await pushPendingFindingsToLog(scanTime);
    SS.sendMessage({
      type: 'UPDATE_BADGE',
      secretCount: foundSecrets.length,
      highestSeverity: SS.highestSeverity(foundSecrets),
    }).catch(() => {});
  }

  // ─── Scan ─────────────────────────────────────────────────────────────────
  function ingest(content, source) {
    const ctx = pageCtx();
    D.detectSecrets(content, source, compiledRules, { known: secretKeys }).forEach(s => {
      // detectSecrets already deduped against secretKeys; register the rest.
      knownSecretValues.add(s.value);
      foundSecrets.push(s);
      pendingSecrets.push(s);
    });
    if (settings.highEntropy) {
      D.detectHighEntropySecrets(content, source, { knownValues: knownSecretValues }).forEach(s => {
        const key = D.secretKey(s.id, s.value, s.source);
        if (secretKeys.has(key)) return;
        secretKeys.add(key);
        foundSecrets.push(s);
        pendingSecrets.push(s);
      });
    }
    D.detectEndpoints(content, source, { ...ctx, includeSubdomains: settings.includeSubdomains }).forEach(addEndpoint);
  }

  async function runScan(scanId = currentScanId) {
    if (isStaleScan(scanId)) return;
    scanning = true;

    // Phase 1a: DOM elements — browser-resolved, exact hostname (fast, high signal)
    collectDomEndpoints().forEach(addEndpoint);
    if (isStaleScan(scanId)) return;

    // Phase 1b: inline scripts with URL resolution
    scanInlineScripts().forEach(addEndpoint);
    if (isStaleScan(scanId)) return;

    // Phase 1c: full HTML via regex (secrets + remaining endpoint patterns)
    ingest(document.documentElement.outerHTML, location.href);
    await persist();
    if (isStaleScan(scanId)) return;

    // Phase 2: external JS/JSON files (batched)
    if (settings.fetchExternalScripts) {
      const urls = collectSources();
      sourcesTotal = urls.length;
      const BATCH = 4;
      for (let i = 0; i < urls.length; i += BATCH) {
        await Promise.all(urls.slice(i, i + BATCH).map(async url => {
          const text = await fetchText(url);
          if (isStaleScan(scanId)) return;
          if (text) ingest(text, url);
          sourcesDone++;
        }));
        if (isStaleScan(scanId)) return;
        await persist();
        if (isStaleScan(scanId)) return;
      }
    }

    if (isStaleScan(scanId)) return;
    scanComplete = true;
    scanning = false;
    await persist();
  }

  function restartScan() {
    resetScanState();
    const scanId = currentScanId;
    persist().then(() => runScan(scanId));
  }

  // ─── SPA navigation ───────────────────────────────────────────────────────
  // Content scripts live in an isolated world, so patching history.pushState
  // here never sees the page's own calls. Poll the URL instead and also listen
  // for the events that do cross worlds (popstate / hashchange / navigate).
  function scheduleRouteRescan() {
    clearTimeout(routeTimer);
    routeTimer = setTimeout(() => {
      if (location.href === lastObservedUrl) return;
      lastObservedUrl = location.href;
      if (settings.autoRescanOnRoute) restartScan();
    }, 350);
  }

  function installNavigationObserver() {
    window.addEventListener('popstate', scheduleRouteRescan);
    window.addEventListener('hashchange', scheduleRouteRescan);
    try { window.navigation?.addEventListener('navigatesuccess', scheduleRouteRescan); } catch (_) {}
    clearInterval(routePoller);
    routePoller = setInterval(() => {
      if (location.href !== lastObservedUrl) scheduleRouteRescan();
    }, 600);
  }

  // ─── Messages ─────────────────────────────────────────────────────────────
  SS.api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || typeof msg !== 'object') return false;

    if (msg.type === 'GET_RESULTS') {
      sendResponse({
        url: location.href,
        hostname: location.hostname.toLowerCase(),
        secrets: foundSecrets,
        endpoints: foundEndpoints,
        complete: scanComplete,
        scanning,
        scanTime: Date.now(),
        scanId: currentScanId,
        progress: { sourcesTotal, sourcesDone },
      });
      return false;
    }

    if (msg.type === 'RESCAN') {
      loadInit().then(() => restartScan()).catch(() => restartScan());
      sendResponse({ ok: true });
      return false;
    }

    if (msg.type === 'PING') {
      sendResponse({ ok: true, scanId: currentScanId });
      return false;
    }

    return false;
  });

  // ─── Init ─────────────────────────────────────────────────────────────────
  async function loadInit() {
    const resp = await SS.sendMessage({ type: 'GET_INIT' });
    if (!resp) throw new Error('no init response');
    settings = SS.normalizeSettings(resp.settings);
    compiledRules = D.compileRules(resp.rules || [], settings.disabledRules);
    if (resp.tabId) myTabId = resp.tabId;
    return resp;
  }

  async function init() {
    try {
      await loadInit();
    } catch (e) {
      console.warn('[SecretSauce] init:', e);
      return;
    }
    if (SS.isHostExcluded(location.hostname, settings)) return;
    resetScanState();
    installNetworkObserver();
    installNavigationObserver();
    runScan(currentScanId);
  }

  init();
})();
