// SecretSauce — shared runtime helpers
// Loaded (as a classic script) by the content script, the background script and
// the app page. Everything is attached to globalThis.SS so the same file works in
// Chrome MV3 service workers (importScripts), Firefox MV2 background pages and
// ordinary <script> tags.

(function (root) {
  'use strict';

  const api = root.chrome || root.browser;

  // ─── Storage keys & limits ────────────────────────────────────────────────
  const HOST_LOG_PREFIX = 'findings_log_host_v1_';
  const IGNORE_PREFIX = 'ignored_v1_';
  const SCAN_PREFIX = 'scan_';
  const LAST_APP_CONTEXT_KEY = 'last_app_context_v1';
  const SETTINGS_KEY = 'settings_v1';

  const LOG_LIMITS = {
    secrets: 4000,
    endpoints: 4000,
    contexts: 1,
    sources: 24,
    pages: 40,
    params: 40,
    queries: 12,
    rules: 12,
    kinds: 12,
  };

  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
  const SEVERITIES = ['critical', 'high', 'medium', 'low'];

  const DEFAULT_SETTINGS = {
    theme: 'system',            // 'system' | 'dark' | 'light'
    highEntropy: true,          // run the heuristic high-entropy detector
    fetchExternalScripts: true, // download and scan same-site JS/JSON files
    includeSubdomains: true,    // treat *.root-domain as in scope for script fetching
    maxExternalScripts: 120,    // hard cap per page scan
    autoRescanOnRoute: true,    // rescan on SPA route changes
    excludedHosts: [],          // hostnames (or *.suffix) never scanned
    disabledRules: [],          // rule ids switched off
    badgeSeverityColor: true,   // colour the toolbar badge by highest severity
  };

  // ─── Promise wrappers around the callback-style extension API ─────────────
  function lastErr() {
    return api?.runtime?.lastError || null;
  }

  function storageGet(keys) {
    return new Promise(resolve => {
      try {
        api.storage.local.get(keys, items => resolve(items || {}));
      } catch (_) {
        resolve({});
      }
    });
  }

  function storageSet(values) {
    return new Promise((resolve, reject) => {
      try {
        api.storage.local.set(values, () => {
          const err = lastErr();
          err ? reject(err) : resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function storageRemove(keys) {
    return new Promise(resolve => {
      try {
        api.storage.local.remove(keys, () => resolve());
      } catch (_) {
        resolve();
      }
    });
  }

  function sendMessage(message) {
    return new Promise((resolve, reject) => {
      try {
        api.runtime.sendMessage(message, response => {
          const err = lastErr();
          err ? reject(err) : resolve(response);
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function tabsSendMessage(tabId, message, timeoutMs = 1500) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
      try {
        api.tabs.sendMessage(tabId, message, response => {
          clearTimeout(timer);
          const err = lastErr();
          err ? reject(err) : resolve(response);
        });
      } catch (err) {
        clearTimeout(timer);
        reject(err);
      }
    });
  }

  function tabsGet(tabId) {
    return new Promise(resolve => {
      if (!tabId) return resolve(null);
      try {
        api.tabs.get(tabId, tab => resolve(lastErr() ? null : tab));
      } catch (_) {
        resolve(null);
      }
    });
  }

  function isQuotaError(err) {
    const msg = String(err?.message || err || '');
    return /quota/i.test(msg);
  }

  // ─── Settings ─────────────────────────────────────────────────────────────
  function normalizeSettings(raw) {
    const s = { ...DEFAULT_SETTINGS, ...(raw || {}) };
    s.excludedHosts = uniqueStrings((s.excludedHosts || []).map(h => String(h).toLowerCase()));
    s.disabledRules = uniqueStrings(s.disabledRules || []);
    s.maxExternalScripts = Math.max(0, Math.min(1000, Number(s.maxExternalScripts) || 0));
    if (!['system', 'dark', 'light'].includes(s.theme)) s.theme = 'system';
    return s;
  }

  async function getSettings() {
    const items = await storageGet(SETTINGS_KEY);
    return normalizeSettings(items[SETTINGS_KEY]);
  }

  async function saveSettings(settings) {
    const normalized = normalizeSettings(settings);
    await storageSet({ [SETTINGS_KEY]: normalized });
    return normalized;
  }

  function isHostExcluded(hostname, settings) {
    const host = String(hostname || '').toLowerCase();
    if (!host) return false;
    for (const rule of settings?.excludedHosts || []) {
      if (!rule) continue;
      if (rule.startsWith('*.')) {
        const bare = rule.slice(2);
        if (host === bare || host.endsWith('.' + bare)) return true;
      } else if (rule === host) {
        return true;
      }
    }
    return false;
  }

  // ─── Hostname helpers ─────────────────────────────────────────────────────
  // Common multi-label public suffixes so getRootDomain('a.b.co.uk') → 'b.co.uk'.
  const MULTI_LABEL_TLDS = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'com.br', 'net.br', 'org.br', 'gov.br',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'firm.in',
    'co.za', 'org.za', 'net.za', 'gov.za',
    'com.mx', 'org.mx', 'gob.mx',
    'com.ar', 'com.co', 'com.pe', 'com.ve', 'com.tr', 'com.tw', 'com.hk', 'com.sg', 'com.my',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'co.kr', 'or.kr', 'ne.kr', 'go.kr',
    'co.il', 'org.il', 'ac.il',
    'com.ua', 'org.ua', 'net.ua',
    'com.pl', 'net.pl', 'org.pl',
    'co.id', 'or.id', 'ac.id', 'go.id',
    'com.eg', 'com.sa', 'com.ph', 'com.pk', 'com.ng', 'com.bd', 'com.vn',
    'github.io', 'gitlab.io', 'herokuapp.com', 'vercel.app', 'netlify.app', 'pages.dev',
    'web.app', 'firebaseapp.com', 'azurewebsites.net', 'cloudfront.net', 'amazonaws.com',
    'appspot.com', 'blogspot.com', 'wordpress.com', 'workers.dev', 'onrender.com', 'fly.dev',
  ]);

  function getHostname(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (_) {
      return '';
    }
  }

  function getRootDomain(hostname) {
    const host = String(hostname || '').trim().toLowerCase();
    if (!host || /^[\d.]+$/.test(host) || host.includes(':')) return host; // IPv4 / IPv6
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_LABEL_TLDS.has(lastTwo)) return parts.slice(-3).join('.');
    return lastTwo;
  }

  // True when `hostname` is the page host or shares its registrable root domain.
  function isSameSite(hostname, pageHostname, includeSubdomains = true) {
    const host = String(hostname || '').toLowerCase();
    const page = String(pageHostname || '').toLowerCase();
    if (!host || !page) return false;
    if (host === page) return true;
    if (!includeSubdomains) return false;
    const root = getRootDomain(page);
    return host === root || host.endsWith('.' + root);
  }

  function normalizeUrl(url) {
    if (!url) return '';
    try {
      const parsed = new URL(url);
      parsed.hash = '';
      return parsed.href;
    } catch (_) {
      return String(url).trim();
    }
  }

  // ─── Generic helpers ──────────────────────────────────────────────────────
  function uniqueStrings(values, limit) {
    const out = [];
    const seen = new Set();
    for (const value of values || []) {
      const normalized = String(value ?? '').trim();
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      out.push(normalized);
      if (limit && out.length >= limit) break;
    }
    return out;
  }

  function trunc(value, length = 120) {
    const text = String(value ?? '');
    return text.length > length ? `${text.slice(0, length)}…` : text;
  }

  function timeAgo(ts) {
    if (!ts) return '';
    const delta = Math.floor((Date.now() - ts) / 1000);
    if (delta < 5) return 'just now';
    if (delta < 60) return `${delta}s ago`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
  }

  function chooseSeverity(current, next) {
    const currentRank = SEVERITY_RANK[current] ?? 99;
    const nextRank = SEVERITY_RANK[next] ?? 99;
    return nextRank < currentRank ? next : current;
  }

  function highestSeverity(items) {
    let best = null;
    for (const item of items || []) {
      const sev = item?.severity;
      if (!(sev in SEVERITY_RANK)) continue;
      if (best === null || SEVERITY_RANK[sev] < SEVERITY_RANK[best]) best = sev;
    }
    return best;
  }

  // ─── Host log (persistent, hostname-scoped findings) ─────────────────────
  function getHostLogKey(hostname) {
    const normalized = String(hostname || '').trim().toLowerCase();
    return normalized ? `${HOST_LOG_PREFIX}${encodeURIComponent(normalized)}` : '';
  }

  function hostFromLogKey(key) {
    if (!key || !key.startsWith(HOST_LOG_PREFIX)) return '';
    try {
      return decodeURIComponent(key.slice(HOST_LOG_PREFIX.length));
    } catch (_) {
      return key.slice(HOST_LOG_PREFIX.length);
    }
  }

  function getIgnoreKey(hostname) {
    const normalized = String(hostname || '').trim().toLowerCase();
    return normalized ? `${IGNORE_PREFIX}${encodeURIComponent(normalized)}` : '';
  }

  function getScanKey(tabId) {
    return tabId ? `${SCAN_PREFIX}${tabId}` : '';
  }

  function createEmptyHostLog(hostname = '') {
    return {
      version: 1,
      hostname,
      updatedAt: null,
      secrets: [],
      endpoints: [],
      stats: { uniqueSecrets: 0, uniqueEndpoints: 0, pageCount: 0, updatedAt: null },
    };
  }

  function summarizeHostLog(log) {
    const pageSet = new Set();
    for (const secret of log?.secrets || []) for (const page of secret.pageUrls || []) pageSet.add(page);
    for (const endpoint of log?.endpoints || []) for (const page of endpoint.pageUrls || []) pageSet.add(page);
    return {
      uniqueSecrets: (log?.secrets || []).length,
      uniqueEndpoints: (log?.endpoints || []).length,
      pageCount: pageSet.size,
      updatedAt: log?.updatedAt || null,
    };
  }

  function buildEndpointUrl(endpoint, pageUrl) {
    const explicit = normalizeUrl(endpoint?.url || endpoint?.absoluteUrl);
    if (explicit) return explicit;
    const path = String(endpoint?.path || '').trim();
    if (!path) return '';
    const query = String(endpoint?.query || '').trim();
    try {
      const base = new URL(pageUrl || 'https://example.invalid/');
      return new URL(query ? `${path}?${query}` : path, `${base.origin}/`).href;
    } catch (_) {
      return query ? `${path}?${query}` : path;
    }
  }

  function endpointIdentity(endpoint) {
    const method = String(endpoint?.method || 'GET').toUpperCase();
    const url = String(endpoint?.url || '').trim();
    const path = String(endpoint?.path || '').trim();
    return `${method}:${url || path}`;
  }

  function hostOf(url) {
    try { return new URL(url).hostname; } catch (_) { return ''; }
  }

  function mergeSecrets(existing, incoming, pageUrl, scanTime) {
    const map = new Map((existing || []).map(s => [s.key, { ...s }]));
    for (const secret of incoming || []) {
      const value = String(secret?.value || '').trim();
      if (!value) continue;
      const prior = map.get(value);
      if (!prior) {
        map.set(value, {
          key: value,
          value,
          name: secret.name || 'Unknown Secret',
          severity: secret.severity || 'medium',
          ids: uniqueStrings([secret.id], LOG_LIMITS.rules),
          names: uniqueStrings([secret.name], LOG_LIMITS.rules),
          sources: uniqueStrings([secret.source], LOG_LIMITS.sources),
          pageUrls: uniqueStrings([pageUrl], LOG_LIMITS.pages),
          contexts: uniqueStrings([secret.context], LOG_LIMITS.contexts),
          firstSeen: scanTime,
          lastSeen: scanTime,
          occurrences: 1,
        });
        continue;
      }
      prior.lastSeen = scanTime;
      prior.occurrences = (prior.occurrences || 0) + 1;
      prior.name = secret.name || prior.name;
      prior.severity = chooseSeverity(prior.severity, secret.severity || prior.severity);
      prior.ids = uniqueStrings([...(prior.ids || []), secret.id], LOG_LIMITS.rules);
      prior.names = uniqueStrings([...(prior.names || []), secret.name], LOG_LIMITS.rules);
      prior.sources = uniqueStrings([...(prior.sources || []), secret.source], LOG_LIMITS.sources);
      prior.pageUrls = uniqueStrings([...(prior.pageUrls || []), pageUrl], LOG_LIMITS.pages);
      prior.contexts = uniqueStrings([...(prior.contexts || []), secret.context], LOG_LIMITS.contexts);
    }
    return Array.from(map.values())
      .sort((a, b) =>
        (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99) ||
        (b.lastSeen || 0) - (a.lastSeen || 0))
      .slice(0, LOG_LIMITS.secrets);
  }

  function mergeEndpoints(existing, incoming, pageUrl, scanTime) {
    const map = new Map((existing || []).map(e => [e.key, { ...e }]));
    for (const endpoint of incoming || []) {
      const method = String(endpoint?.method || 'GET').toUpperCase();
      const url = buildEndpointUrl(endpoint, pageUrl);
      if (!url && !endpoint?.path) continue;
      const key = `${method}:${url || endpoint?.path || ''}`;
      const prior = map.get(key);
      if (!prior) {
        map.set(key, {
          key,
          method,
          url,
          path: endpoint.path || '/',
          host: hostOf(url),
          querySamples: uniqueStrings([endpoint.query], LOG_LIMITS.queries),
          params: uniqueStrings(endpoint.params || [], LOG_LIMITS.params),
          kinds: uniqueStrings([endpoint.kind], LOG_LIMITS.kinds),
          sources: uniqueStrings([endpoint.source], LOG_LIMITS.sources),
          pageUrls: uniqueStrings([pageUrl], LOG_LIMITS.pages),
          contexts: uniqueStrings([endpoint.context], LOG_LIMITS.contexts),
          firstSeen: scanTime,
          lastSeen: scanTime,
          occurrences: 1,
        });
        continue;
      }
      prior.lastSeen = scanTime;
      prior.occurrences = (prior.occurrences || 0) + 1;
      prior.url = url || prior.url;
      prior.path = endpoint.path || prior.path;
      prior.host = prior.host || hostOf(url);
      prior.querySamples = uniqueStrings([...(prior.querySamples || []), endpoint.query], LOG_LIMITS.queries);
      prior.params = uniqueStrings([...(prior.params || []), ...(endpoint.params || [])], LOG_LIMITS.params);
      prior.kinds = uniqueStrings([...(prior.kinds || []), endpoint.kind], LOG_LIMITS.kinds);
      prior.sources = uniqueStrings([...(prior.sources || []), endpoint.source], LOG_LIMITS.sources);
      prior.pageUrls = uniqueStrings([...(prior.pageUrls || []), pageUrl], LOG_LIMITS.pages);
      prior.contexts = uniqueStrings([...(prior.contexts || []), endpoint.context], LOG_LIMITS.contexts);
    }
    return Array.from(map.values())
      .sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
      .slice(0, LOG_LIMITS.endpoints);
  }

  root.SS = {
    api,
    HOST_LOG_PREFIX, IGNORE_PREFIX, SCAN_PREFIX, LAST_APP_CONTEXT_KEY, SETTINGS_KEY,
    LOG_LIMITS, SEVERITY_RANK, SEVERITIES, DEFAULT_SETTINGS,
    storageGet, storageSet, storageRemove, sendMessage, tabsSendMessage, tabsGet, isQuotaError,
    normalizeSettings, getSettings, saveSettings, isHostExcluded,
    getHostname, getRootDomain, isSameSite, normalizeUrl,
    uniqueStrings, trunc, timeAgo, chooseSeverity, highestSeverity,
    getHostLogKey, hostFromLogKey, getIgnoreKey, getScanKey,
    createEmptyHostLog, summarizeHostLog, buildEndpointUrl, endpointIdentity,
    mergeSecrets, mergeEndpoints,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
