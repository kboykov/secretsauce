// SecretSauce — Content Script
// Author: K. Boykov

(function () {
  'use strict';

  if (window.__secretSauceInitialized) return;
  window.__secretSauceInitialized = true;

  // ─── State ────────────────────────────────────────────────────────────────
  let secretPatterns = [];
  let foundSecrets   = [];
  let foundEndpoints = [];
  let scanComplete   = false;
  let myTabId        = null;

  // ─── Endpoint detection ───────────────────────────────────────────────────
  //
  // We use a layered approach:
  //   1. High-signal: explicit call context  (fetch, axios, XHR, jQuery, route)
  //   2. Medium-signal: named properties     (url:, endpoint:, baseUrl:, …)
  //   3. Broad sweep: any quoted path string (filtered aggressively afterwards)
  //
  // The broad sweep uses the original bookmarklet regex but enhanced.

  // Patterns in order of specificity. urlGroup/methodGroup are 1-based.
  const EP = [
    // fetch('/path') / fetch("api/v1/…") / fetch("https://…")
    {
      re: /\bfetch\s*\(\s*['"`]((?:https?:\/\/[^\s'"`]{4,}|\/[^\s'"`]{1,500}|(?:api|rest|graphql|gql|rpc|v\d+|service|services)\/[^\s'"`]{1,300}))[`'"]/g,
      kind: 'fetch',
    },
    // axios.get/post/… ('/path')
    {
      re: /\baxios\s*\.\s*(?:request|get|post|put|delete|patch|head|options)\s*\(\s*['"`]((?:https?:\/\/[^\s'"`]{4,}|\/[^\s'"`]{1,500}|(?:api|rest|graphql|gql|rpc|v\d+|service|services)\/[^\s'"`]{1,300}))[`'"]/g,
      kind: 'axios',
    },
    // $.get/post/ajax('/path')
    {
      re: /\$\s*\.\s*(?:ajax|get|post|put|delete|patch)\s*\(\s*['"`]((?:https?:\/\/[^\s'"`]{4,}|\/[^\s'"`]{1,500}))[`'"]/g,
      kind: 'jquery',
    },
    // xhr.open('METHOD', '/path')
    {
      re: /\.open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"`]\s*,\s*['"`]((?:https?:\/\/[^\s'"`]{4,}|\/[^\s'"`]{1,500}))[`'"]/g,
      kind: 'xhr', urlGroup: 2, methodGroup: 1,
    },
    // router/app.get/post/…('/path', …)  — Express/Koa/Hapi route defs
    {
      re: /(?:router|app|server|Route)\s*\.\s*(?:get|post|put|delete|patch|use|all)\s*\(\s*['"`](\/[^\s'"`]{1,300})[`'"]/g,
      kind: 'route',
    },
    // url: '/path'  endpoint: '/path'  baseUrl: '…'  apiUrl: '…'
    {
      re: /(?:url|URL|endpoint|uri|URI|baseUrl|baseURL|apiUrl|apiURL|actionUrl|requestUrl|action)\s*[:=]\s*['"`]((?:https?:\/\/[^\s'"`]{4,}|\/[^\s'"`]{1,500}|(?:api|rest|graphql|gql|rpc|v\d+|service|services)\/[^\s'"`]{1,300}))[`'"]/g,
      kind: 'property',
    },
    // API-prefix paths without a leading slash: "api/v1/users", "graphql/query"
    {
      re: /['"`]((?:api|rest|graphql|gql|rpc|v\d+|service|services)\/[^\s'"`<>\\]{2,})[`'"]/gi,
      kind: 'apiprefix',
    },
    // Broad: any quoted string starting with /
    {
      re: /['"`](\/[a-zA-Z0-9_\-\.~][a-zA-Z0-9_\-\.~\/]*(?:\?[^\s'"`]{0,200})?)[`'"]/g,
      kind: 'path',
    },
    // Full absolute URLs in strings
    {
      re: /['"`](https?:\/\/[^\s'"`<>\\]{4,})[`'"]/g,
      kind: 'absolute',
    },
  ];

  // ─── Root-domain filter ───────────────────────────────────────────────────
  // Only endpoints on the current site's root domain are surfaced.
  // e.g. on api.example.com → root is example.com; filters out cdn.otherdomain.com

  function isSameDomain(hostname) {
    return hostname === location.hostname;
  }

  // Static asset false-positive filters (applied to path only, NOT to absolute URLs)
  const STATIC_DIR_RE = /^\/(img|image|images|static|assets|dist|build|fonts?|icons?|media|svg|uploads?|thumbs?|avatars?|vendor|node_modules|bower_components|__webpack|_next|\.next|nuxt)\b/i;
  const STATIC_EXT_RE = /\.(?:png|jpe?g|gif|svg|webp|ico|bmp|avif|woff2?|ttf|eot|otf|otc|css|scss|less|map|pdf|zip|gz|tar|exe|dmg|apk)(?:\?.*)?$/i;
  // JS/TS file paths that are asset references, not endpoints
  const SCRIPT_ASSET_RE = /\.(?:min\.js|bundle\.js|chunk\.[a-f0-9]+\.js|[a-f0-9]{8,}\.js)(?:\?.*)?$/i;
  // Obvious non-API single-segment paths (too common in CSS/HTML)
  const SINGLE_NOISE_RE = /^\/(?:index|home|main|app|root|default|base|page|layout|wrapper|container)$/i;

  function isEndpointFP(path, kind) {
    if (!path || path.length < 2 || path === '/') return true;
    if (STATIC_DIR_RE.test(path)) return true;
    if (STATIC_EXT_RE.test(path)) return true;
    // DOM/inline candidates are already browser-resolved, skip script-asset check
    if (kind !== 'dom' && kind !== 'inline') {
      if (SCRIPT_ASSET_RE.test(path)) return true;
    }
    // For the broad 'path' pattern, require at least one slash beyond root
    // OR match a known API-style prefix — this keeps single roots like /login
    // but kills noise like /*, /#, etc.
    if (kind === 'path') {
      if (path.length < 4) return true;        // /a/b minimum
      if (/^\/[#?*]/.test(path)) return true;  // /#hash, /?, /*
      if (SINGLE_NOISE_RE.test(path)) return true;
    }
    return false;
  }

  // ─── Utility ──────────────────────────────────────────────────────────────

  function truncate(str, len = 120) {
    return str.length > len ? str.slice(0, len) + '…' : str;
  }

  function isDupSecret(s) {
    return foundSecrets.some(x => x.id === s.id && x.value === s.value && x.source === s.source);
  }

  function isDupEndpoint(ep) {
    return foundEndpoints.some(x => x.path === ep.path && x.method === ep.method);
  }

  // ─── DOM endpoint collection ──────────────────────────────────────────────
  // Mirrors the bookmarklet: queries all element types that carry URLs,
  // resolves them through new URL(), filters to current hostname.

  function collectDomEndpoints() {
    const found = [];
    const seen  = new Set();

    const tryAdd = (rawAttr, method) => {
      if (!rawAttr) return;
      const val = rawAttr.trim();
      if (!val || val.startsWith('#') || val.startsWith('javascript:') ||
          val.startsWith('data:') || val.startsWith('mailto:') || val.startsWith('tel:')) return;
      try {
        const u    = new URL(val, location.href);
        if (u.hostname !== location.hostname) return;
        const path = u.pathname.replace(/\/+$/, '') || '/';
        if (isEndpointFP(path, 'dom')) return;
        const key  = `${method}:${path}`;
        if (seen.has(key)) return;
        seen.add(key);
        found.push({ path, query: u.search.slice(1), method, params: [], kind: 'dom', source: location.href });
      } catch (_) {}
    };

    // Same 9 selectors the bookmarklet uses
    document.querySelectorAll('a[href]').forEach(el =>
      tryAdd(el.getAttribute('href'), 'GET'));
    document.querySelectorAll('form[action]').forEach(el =>
      tryAdd(el.getAttribute('action') || location.pathname, (el.getAttribute('method') || 'GET').toUpperCase()));
    document.querySelectorAll('iframe[src]').forEach(el =>
      tryAdd(el.getAttribute('src'), 'GET'));
    document.querySelectorAll('script[src]').forEach(el =>
      tryAdd(el.getAttribute('src'), 'GET'));
    document.querySelectorAll('link[href]').forEach(el =>
      tryAdd(el.getAttribute('href'), 'GET'));
    document.querySelectorAll('img[src]').forEach(el =>
      tryAdd(el.getAttribute('src'), 'GET'));
    document.querySelectorAll('source[src],video[src],audio[src]').forEach(el =>
      tryAdd(el.getAttribute('src'), 'GET'));

    return found;
  }

  // ─── Inline script endpoint collection ───────────────────────────────────
  // Ports the bookmarklet's inline-script approach:
  // runs patterns on script:not([src]) text, then resolves every candidate
  // through new URL(candidate, location.href) so ../api/v1 etc. are captured.

  const INLINE_PATTERNS = [
    // Unquoted absolute URLs (bookmarklet pattern 1 — no surrounding quotes needed)
    /https?:\/\/[^\s"'`<>\\]{4,}/g,
    // Quoted relative paths including ../ and ./
    /["'`]((?:\/|\.\.\/|\.\/)[^"'`\s<>\\]{2,})["'`]/g,
    // Quoted API-prefix paths without leading slash: "api/v1/users", "graphql/query"
    /["'`]((?:api|rest|graphql|gql|rpc|v\d+|service|services)\/[^"'`\s<>\\]{2,})["'`]/gi,
    // Quoted /api-prefix paths: "/api/v1/…"
    /["'`](\/(?:api|rest|graphql|gql|rpc|v\d+|service|services)[^"'`\s<>\\]*)["'`]/gi,
    // HTTP method calls: fetch("…"), axios.get("…"), open("METHOD","…"), post("…") etc.
    /(?:fetch|axios(?:\.\w+)?|open|post|get|put|delete|patch)\s*\(\s*["'`]([^"'`]{2,})["'`]/gi,
    // URL property assignments: url: "…", endpoint = "…", baseURL: "…"
    /(?:url|endpoint|uri|path|baseURL|baseUrl|apiUrl|actionUrl)\s*[:=]\s*["'`]([^"'`]{2,})["'`]/gi,
  ];

  function scanInlineScripts() {
    const found = [];
    const seen  = new Set();
    const candidates = new Set();

    document.querySelectorAll('script:not([src])').forEach(script => {
      const text = script.textContent || '';
      if (!text.trim()) return;

      INLINE_PATTERNS.forEach(re => {
        re.lastIndex = 0;
        let match;
        while ((match = re.exec(text)) !== null) {
          const val = (match[1] || match[0] || '').trim();
          if (!val) continue;
          // Quick pre-filter identical to bookmarklet
          if (val.startsWith('data:') || val.startsWith('javascript:') ||
              val.startsWith('#') || val === '/' || /^[a-zA-Z0-9_-]+$/.test(val)) continue;
          candidates.add(val);
        }
      });
    });

    candidates.forEach(candidate => {
      try {
        const u    = new URL(candidate, location.href);
        if (u.hostname !== location.hostname) return;
        const path = u.pathname.replace(/\/+$/, '') || '/';
        if (isEndpointFP(path, 'inline')) return;
        const key  = `GET:${path}`;
        if (seen.has(key)) return;
        seen.add(key);
        found.push({ path, query: u.search.slice(1), method: 'GET', params: [], kind: 'inline', source: location.href });
      } catch (_) {}
    });

    return found;
  }

  // ─── Tab ID ───────────────────────────────────────────────────────────────

  function fetchTabId() {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, resp => {
        resolve(chrome.runtime.lastError ? null : (resp?.tabId ?? null));
      });
    });
  }

  // ─── Secret patterns ──────────────────────────────────────────────────────

  function loadPatterns() {
    return fetch(chrome.runtime.getURL('rules/secrets.json')).then(r => r.json());
  }

  // ─── Source collection ────────────────────────────────────────────────────

  function collectSources() {
    const urls = new Set();

    document.querySelectorAll('script[src]').forEach(el => {
      try { urls.add(new URL(el.src, location.href).href); } catch (_) {}
    });

    // JSON/JS link tags
    document.querySelectorAll('[href]').forEach(el => {
      const h = el.getAttribute('href') || '';
      if (/\.(js|json)(\?|$)/i.test(h)) {
        try { urls.add(new URL(h, location.href).href); } catch (_) {}
      }
    });

    // Webpack/Vite lazy chunk URLs embedded in inline JS
    const inline = Array.from(document.querySelectorAll('script:not([src])'))
      .map(s => s.textContent).join('\n');
    const chunkRe = /['"`]([^'"`\s]{4,}\.(?:js|json)(?:\?[^'"`\s]*)?)['"`]/g;
    let m;
    while ((m = chunkRe.exec(inline)) !== null) {
      try {
        const u = new URL(m[1], location.href);
        if (u.origin === location.origin) urls.add(u.href);
      } catch (_) {}
    }

    return Array.from(urls);
  }

  // ─── Fetch text ───────────────────────────────────────────────────────────

  async function fetchText(url) {
    try {
      const res = await fetch(url, { credentials: 'omit', cache: 'force-cache' });
      if (!res.ok) return null;
      const ct = res.headers.get('content-type') || '';
      if (ct && !/javascript|json|text/i.test(ct)) return null;
      const t = await res.text();
      return t.length > 6_000_000 ? t.slice(0, 6_000_000) : t;
    } catch (_) { return null; }
  }

  // ─── Secret detection ─────────────────────────────────────────────────────

  // Values that are clearly placeholders / variable names, not real credentials
  const FP_VALUE = [
    /\$\{/, /\{\{/, /<[A-Z_]{3,}>/, /\.\.\./,
    /(?:YOUR|INSERT|REPLACE|CHANGE|ENTER|PLACEHOLDER|EXAMPLE|SAMPLE|DUMMY|FAKE)[_\-]/i,
    /\*{4,}/, /x{6,}/i, /0{12,}/,
  ];

  function isSecretFP(value) {
    if (!value || value.length < 8) return true;
    for (const re of FP_VALUE) if (re.test(value)) return true;
    if (/^(.)\1{10,}$/.test(value)) return true; // all same char
    if (/^[a-z_]{3,30}$/.test(value)) return true; // looks like a variable name
    if (/^[A-Z_]{3,30}$/.test(value)) return true; // looks like a constant name
    if (/<\/?[a-z]+[^>]*>/i.test(value)) return true; // HTML tags
    return false;
  }

  function detectSecrets(content, source) {
    const found = [];
    for (const pat of secretPatterns) {
      let re;
      try { re = new RegExp(pat.regex, 'gm'); } catch (_) { continue; }

      let match, hits = 0;
      while ((match = re.exec(content)) !== null && hits < 30) {
        hits++;
        const value = (match[1] || match[0]).trim();
        if (isSecretFP(value)) continue;

        const start   = Math.max(0, match.index - 80);
        const end     = Math.min(content.length, match.index + match[0].length + 80);
        const context = content.slice(start, end).replace(/[\r\n\t]+/g, ' ').trim();

        const s = { id: pat.id, name: pat.name, severity: pat.severity,
                    value, context, source, timestamp: Date.now() };
        if (!isDupSecret(s)) found.push(s);
        if (found.length >= 500) return found;
      }
    }
    return found;
  }

  // ─── Endpoint detection ───────────────────────────────────────────────────

  // Extract parameter names from the code window around an endpoint match
  function extractParams(content, idx) {
    const win = content.slice(Math.max(0, idx - 150), Math.min(content.length, idx + 500));
    const params = new Set();

    // URL query string
    const qs = win.match(/\?([a-zA-Z0-9_%+\-]+=(?:[^&'"`\s]*)(?:&[a-zA-Z0-9_%+\-]+=(?:[^&'"`\s]*))*)/);
    if (qs) qs[1].split('&').forEach(pair => {
      const k = decodeURIComponent(pair.split('=')[0]);
      if (/^[a-zA-Z_][a-zA-Z0-9_]{1,39}$/.test(k)) params.add(k);
    });

    // params/body/data/payload object keys
    const objRe = /(?:params|body|data|payload|query|qs|fields)\s*:\s*\{([^}]{1,400})\}/g;
    let om;
    while ((om = objRe.exec(win)) !== null) {
      const kRe = /(['"]?)([a-zA-Z_][a-zA-Z0-9_]{1,39})\1\s*:/g;
      let km;
      while ((km = kRe.exec(om[1])) !== null) {
        const k = km[2];
        if (!/^(?:true|false|null|undefined|const|let|var|if|else|return|new|this|function|async|await|class|import|export)$/.test(k))
          params.add(k);
      }
    }

    // URLSearchParams({ key: val })
    const uspRe = /URLSearchParams\s*\(\s*\{([^}]{1,400})\}/g;
    let um;
    while ((um = uspRe.exec(win)) !== null) {
      const kRe2 = /(['"]?)([a-zA-Z_][a-zA-Z0-9_]{1,39})\1\s*:/g;
      let km2;
      while ((km2 = kRe2.exec(um[1])) !== null) params.add(km2[2]);
    }

    return Array.from(params).slice(0, 20);
  }

  function guessMethod(kind, content, idx) {
    const snip = content.slice(Math.max(0, idx - 120), idx + 40).toUpperCase();
    for (const m of ['POST','PUT','DELETE','PATCH','HEAD','OPTIONS'])
      if (snip.includes(m)) return m;
    return 'GET';
  }

  function detectEndpoints(content, source) {
    const found = [];
    const seen  = new Set();

    for (const pat of EP) {
      // Re-create the regex fresh for each source to reset lastIndex
      const re = new RegExp(pat.re.source, 'gm');
      let match;
      let validHits = 0; // count only accepted endpoints, not all matches

      while ((match = re.exec(content)) !== null) {
        const uG   = pat.urlGroup    ?? 1;
        const mG   = pat.methodGroup ?? null;
        let   raw  = match[uG];
        if (!raw) continue;

        // For absolute URLs: filter cross-domain, then normalise to path-only
        if (raw.startsWith('http')) {
          let u;
          try { u = new URL(raw); } catch { continue; }
          if (!isSameDomain(u.hostname)) continue;
          raw = u.pathname + u.search; // convert to relative form
        }

        const qIdx  = raw.indexOf('?');
        const path  = (qIdx >= 0 ? raw.slice(0, qIdx) : raw).replace(/\/+$/, '') || '/';
        const query = qIdx >= 0 ? raw.slice(qIdx + 1) : '';

        if (isEndpointFP(path, pat.kind)) continue;

        const method   = mG ? match[mG].toUpperCase() : guessMethod(pat.kind, content, match.index);
        const dedupKey = `${method}:${path}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);

        const params = extractParams(content, match.index);
        found.push({ path, query, method, params, kind: pat.kind, source });

        validHits++;
        if (validHits >= 200) break; // cap per-pattern per-file
      }

      if (found.length >= 2000) break; // total cap
    }

    return found;
  }

  // ─── Persist ──────────────────────────────────────────────────────────────

  async function persist() {
    if (!myTabId) return;
    await chrome.storage.local.set({
      [`scan_${myTabId}`]: {
        url:       location.href,
        secrets:   foundSecrets,
        endpoints: foundEndpoints,
        complete:  scanComplete,
        scanTime:  Date.now(),
      }
    });
    chrome.runtime.sendMessage({ type: 'UPDATE_BADGE', secretCount: foundSecrets.length });
  }

  // ─── Scan ─────────────────────────────────────────────────────────────────

  function ingest(content, source) {
    detectSecrets(content, source).forEach(s => {
      if (!isDupSecret(s)) foundSecrets.push(s);
    });
    detectEndpoints(content, source).forEach(e => {
      if (!isDupEndpoint(e)) foundEndpoints.push(e);
    });
  }

  async function runScan() {
    // Phase 1a: DOM elements — browser-resolved, exact hostname (fast, high signal)
    collectDomEndpoints().forEach(e => {
      if (!isDupEndpoint(e)) foundEndpoints.push(e);
    });

    // Phase 1b: Inline scripts — bookmarklet approach with new URL() resolution
    scanInlineScripts().forEach(e => {
      if (!isDupEndpoint(e)) foundEndpoints.push(e);
    });

    // Phase 1c: Full HTML + inline scripts via regex (secrets + remaining endpoint patterns)
    ingest(document.documentElement.innerHTML, location.href);
    await persist();

    // Phase 2: External JS/JSON files (async, batched)
    const urls = collectSources();
    const BATCH = 4;
    for (let i = 0; i < urls.length; i += BATCH) {
      await Promise.all(
        urls.slice(i, i + BATCH).map(async url => {
          const text = await fetchText(url);
          if (text) ingest(text, url);
        })
      );
      await persist();
    }

    scanComplete = true;
    await persist();
  }

  // ─── Message handler ──────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
    if (msg.type === 'GET_RESULTS') {
      sendResponse({ url: location.href, secrets: foundSecrets,
                     endpoints: foundEndpoints, complete: scanComplete, scanTime: Date.now() });
      return true;
    }
    if (msg.type === 'RESCAN') {
      foundSecrets = []; foundEndpoints = []; scanComplete = false;
      persist().then(() => runScan());
      sendResponse({ ok: true });
      return true;
    }
  });

  // ─── Init ─────────────────────────────────────────────────────────────────

  async function init() {
    try {
      [secretPatterns, myTabId] = await Promise.all([loadPatterns(), fetchTabId()]);
    } catch (e) {
      console.warn('[SecretSauce] init:', e);
      return;
    }
    runScan();
  }

  init();
})();
