// SecretSauce - Background Service Worker
// Author: K. Boykov

const HOST_LOG_PREFIX = 'findings_log_host_v1_';
const LAST_APP_CONTEXT_KEY = 'last_app_context_v1';
const LOG_LIMITS = {
  secrets: 4000,
  endpoints: 4000,
  contexts: 4,
  sources: 24,
  pages: 40,
  params: 40,
  queries: 12,
  rules: 12,
  kinds: 12,
};

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
let logWriteQueue = Promise.resolve();

function storageGet(key) {
  return new Promise(resolve => {
    chrome.storage.local.get(key, items => resolve(items[key]));
  });
}

function storageSet(values) {
  return new Promise(resolve => {
    chrome.storage.local.set(values, resolve);
  });
}

function getHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_) {
    return '';
  }
}

function getHostLogKey(hostname) {
  const normalized = String(hostname || '').trim().toLowerCase();
  return normalized ? `${HOST_LOG_PREFIX}${encodeURIComponent(normalized)}` : '';
}

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

function chooseSeverity(currentSeverity, nextSeverity) {
  const currentRank = SEVERITY_RANK[currentSeverity] ?? 99;
  const nextRank = SEVERITY_RANK[nextSeverity] ?? 99;
  return nextRank < currentRank ? nextSeverity : currentSeverity;
}

function createEmptyHostLog(hostname = '') {
  return {
    version: 1,
    hostname,
    updatedAt: null,
    secrets: [],
    endpoints: [],
    stats: {
      uniqueSecrets: 0,
      uniqueEndpoints: 0,
      pageCount: 0,
      updatedAt: null,
    },
  };
}

function summarizeHostLog(log) {
  const pageSet = new Set();

  for (const secret of log.secrets || []) {
    for (const page of secret.pageUrls || []) pageSet.add(page);
  }
  for (const endpoint of log.endpoints || []) {
    for (const page of endpoint.pageUrls || []) pageSet.add(page);
  }

  return {
    uniqueSecrets: (log.secrets || []).length,
    uniqueEndpoints: (log.endpoints || []).length,
    pageCount: pageSet.size,
    updatedAt: log.updatedAt || null,
  };
}

function mergeSecrets(existingSecrets, incomingSecrets, pageUrl, scanTime) {
  const map = new Map((existingSecrets || []).map(secret => [secret.key, { ...secret }]));

  for (const secret of incomingSecrets || []) {
    const value = String(secret?.value || '').trim();
    if (!value) continue;

    const key = value;
    const prior = map.get(key);

    if (!prior) {
      map.set(key, {
        key,
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
    map.set(key, prior);
  }

  return Array.from(map.values())
    .sort((a, b) =>
      (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99) ||
      (b.lastSeen || 0) - (a.lastSeen || 0)
    )
    .slice(0, LOG_LIMITS.secrets);
}

function mergeEndpoints(existingEndpoints, incomingEndpoints, pageUrl, scanTime) {
  const map = new Map((existingEndpoints || []).map(endpoint => [endpoint.key, { ...endpoint }]));

  for (const endpoint of incomingEndpoints || []) {
    const method = String(endpoint?.method || 'GET').toUpperCase();
    const url = buildEndpointUrl(endpoint, pageUrl);
    const key = `${method}:${url || endpoint?.path || ''}`;
    if (!url && !endpoint?.path) continue;

    const prior = map.get(key);
    if (!prior) {
      map.set(key, {
        key,
        method,
        url,
        path: endpoint.path || '/',
        host: (() => { try { return new URL(url).hostname; } catch (_) { return ''; } })(),
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
    prior.host = prior.host || (() => { try { return new URL(url).hostname; } catch (_) { return ''; } })();
    prior.querySamples = uniqueStrings([...(prior.querySamples || []), endpoint.query], LOG_LIMITS.queries);
    prior.params = uniqueStrings([...(prior.params || []), ...(endpoint.params || [])], LOG_LIMITS.params);
    prior.kinds = uniqueStrings([...(prior.kinds || []), endpoint.kind], LOG_LIMITS.kinds);
    prior.sources = uniqueStrings([...(prior.sources || []), endpoint.source], LOG_LIMITS.sources);
    prior.pageUrls = uniqueStrings([...(prior.pageUrls || []), pageUrl], LOG_LIMITS.pages);
    prior.contexts = uniqueStrings([...(prior.contexts || []), endpoint.context], LOG_LIMITS.contexts);
    map.set(key, prior);
  }

  return Array.from(map.values())
    .sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
    .slice(0, LOG_LIMITS.endpoints);
}

function queueLogWrite(task) {
  logWriteQueue = logWriteQueue.catch(() => null).then(task);
  return logWriteQueue;
}

async function tabsGet(tabId) {
  if (!tabId) return null;
  return new Promise(resolve => {
    chrome.tabs.get(tabId, tab => {
      resolve(chrome.runtime.lastError ? null : tab);
    });
  });
}

function parseAppContext(url) {
  try {
    const parsed = new URL(url || '');
    if (parsed.origin !== chrome.runtime.getURL('').replace(/\/$/, '')) return null;
    if (!parsed.pathname.endsWith('/app.html')) return null;
    const tabId = parseInt(parsed.searchParams.get('tab'), 10) || null;
    const hostname = (parsed.searchParams.get('host') || '').trim().toLowerCase();
    const pageUrl = parsed.searchParams.get('url') || '';
    return { tabId, hostname, pageUrl };
  } catch (_) {
    return null;
  }
}

async function resolveActionContext(tab) {
  const appContext = parseAppContext(tab?.url || '');
  if (!appContext) {
    const hostname = getHostname(tab?.url || '');
    return { targetTabId: tab?.id ?? null, hostname, pageUrl: tab?.url || '' };
  }

  const targetTab = await tabsGet(appContext.tabId);
  if (targetTab?.url) {
    return {
      targetTabId: targetTab.id,
      hostname: getHostname(targetTab.url) || appContext.hostname,
      pageUrl: targetTab.url,
    };
  }

  const lastContext = (await storageGet(LAST_APP_CONTEXT_KEY)) || {};
  return {
    targetTabId: appContext.tabId || lastContext.tabId || null,
    hostname: appContext.hostname || lastContext.hostname || '',
    pageUrl: appContext.pageUrl || lastContext.pageUrl || '',
  };
}

async function rememberAppContext(context) {
  await storageSet({
    [LAST_APP_CONTEXT_KEY]: {
      tabId: context.targetTabId || null,
      hostname: context.hostname || '',
      pageUrl: context.pageUrl || '',
      updatedAt: Date.now(),
    },
  });
}

async function mergeFindingsLog(message, sender) {
  const pageUrl = String(message?.pageUrl || sender?.tab?.url || '').trim();
  const hostname = String(message?.hostname || getHostname(pageUrl)).trim().toLowerCase();
  const scanTime = Number(message?.scanTime) || Date.now();
  const secrets = Array.isArray(message?.secrets) ? message.secrets : [];
  const endpoints = Array.isArray(message?.endpoints) ? message.endpoints : [];

  if (!hostname) {
    return { hostname: '', stats: createEmptyHostLog('').stats };
  }

  const storageKey = getHostLogKey(hostname);
  const existing = (await storageGet(storageKey)) || createEmptyHostLog(hostname);
  const nextLog = {
    version: 1,
    hostname,
    updatedAt: scanTime,
    secrets: existing.secrets,
    endpoints: existing.endpoints,
  };

  if (secrets.length || endpoints.length) {
    nextLog.secrets = mergeSecrets(existing.secrets, secrets, pageUrl, scanTime);
    nextLog.endpoints = mergeEndpoints(existing.endpoints, endpoints, pageUrl, scanTime);
  }

  nextLog.stats = summarizeHostLog(nextLog);
  await storageSet({
    [storageKey]: nextLog,
    [LAST_APP_CONTEXT_KEY]: {
      tabId: sender.tab?.id ?? null,
      hostname,
      pageUrl,
      updatedAt: scanTime,
    },
  });

  return { hostname, storageKey, stats: nextLog.stats };
}

chrome.action.onClicked.addListener(async tab => {
  const context = await resolveActionContext(tab);
  await rememberAppContext(context);

  const params = new URLSearchParams();
  if (context.targetTabId) params.set('tab', String(context.targetTabId));
  if (context.hostname) params.set('host', context.hostname);
  if (context.pageUrl) params.set('url', context.pageUrl);

  chrome.tabs.create({ url: chrome.runtime.getURL(`app.html?${params.toString()}`) });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_TAB_ID') {
    sendResponse({ tabId: sender.tab?.id ?? null });
    return true;
  }

  if (message.type === 'UPDATE_BADGE') {
    const tabId = sender.tab?.id;
    if (!tabId) return false;
    const count = message.secretCount || 0;
    const text = count > 0 ? (count > 99 ? '99+' : String(count)) : '';
    chrome.action.setBadgeText({ text, tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#e53e3e', tabId });
    chrome.action.setBadgeTextColor({ color: '#ffffff', tabId });
    return false;
  }

  if (message.type === 'LOG_FINDINGS') {
    queueLogWrite(() => mergeFindingsLog(message, sender))
      .then(payload => sendResponse({ ok: true, ...payload }))
      .catch(error => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  return false;
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ text: '', tabId });
    chrome.storage.local.remove(`scan_${tabId}`);
  }
});

chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.local.remove(`scan_${tabId}`);
});
