// SecretSauce - Full-Page App Script
// Author: K. Boykov

'use strict';

const searchParams = new URLSearchParams(location.search);
const targetTabId = parseInt(searchParams.get('tab'), 10) || null;
const HOST_LOG_PREFIX = 'findings_log_host_v1_';
const SCAN_STORAGE_KEY = targetTabId ? `scan_${targetTabId}` : null;

let currentHost = String(searchParams.get('host') || '').trim().toLowerCase();
let currentPageUrl = String(searchParams.get('url') || '').trim();
let liveSecrets = [];
let liveEndpoints = [];
let allSecrets = [];
let allEndpoints = [];
let isScanning = false;
let lastScanTime = null;
let pollTimer = null;
let hostLoadToken = 0;
let hostLog = createEmptyHostLog(currentHost);
let expandAllEndpoints = false;
let expandAllSecrets = false;
let endpointOpenKeys = new Set();
let secretOpenKeys = new Set();
let endpointContextOpenKeys = new Set();
let secretContextOpenKeys = new Set();

const $ = id => document.getElementById(id);
const pageUrlEl = $('page-url');
const countEpEl = $('count-endpoints');
const countSecEl = $('count-secrets');
const badgeEpEl = $('tab-badge-endpoints');
const badgeSecEl = $('tab-badge-secrets');
const statusEl = $('status-text');
const spinnerEl = $('spinner');
const epListEl = $('ep-list');
const secListEl = $('sec-list');
const epEmptyEl = $('ep-empty');
const secEmptyEl = $('sec-empty');
const epSearchEl = $('ep-search');
const epMethodEl = $('ep-filter-method');
const secSearchEl = $('sec-search');
const secSevEl = $('sec-filter-sev');
const footerEl = $('footer-last-scan');
const footerLogEl = $('footer-log-stats');
const rescanBtn = $('btn-rescan');
const exportBtn = $('btn-export');
const expandEndpointsBtn = $('btn-expand-endpoints');
const expandSecretsBtn = $('btn-expand-secrets');

const METHOD_CLS = {
  GET: 'method-GET',
  POST: 'method-POST',
  PUT: 'method-PUT',
  DELETE: 'method-DELETE',
  PATCH: 'method-PATCH',
  HEAD: 'method-HEAD',
  OPTIONS: 'method-OPTIONS',
};

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function esc(value) {
  const text = String(value ?? '');
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function trunc(value, length = 120) {
  const text = String(value ?? '');
  return text.length > length ? `${text.slice(0, length)}...` : text;
}

function timeAgo(ts) {
  if (!ts) return '';
  const delta = Math.floor((Date.now() - ts) / 1000);
  if (delta < 5) return 'just now';
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  return `${Math.floor(delta / 3600)}h ago`;
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

function uniqueStrings(values) {
  const out = [];
  const seen = new Set();
  for (const value of values || []) {
    const normalized = String(value ?? '').trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
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
  for (const secret of log?.secrets || []) {
    (secret.pageUrls || []).forEach(page => pageSet.add(page));
  }
  for (const endpoint of log?.endpoints || []) {
    (endpoint.pageUrls || []).forEach(page => pageSet.add(page));
  }
  return {
    uniqueSecrets: (log?.secrets || []).length,
    uniqueEndpoints: (log?.endpoints || []).length,
    pageCount: pageSet.size,
    updatedAt: log?.updatedAt || null,
  };
}

function endpointIdentity(endpoint) {
  const method = String(endpoint?.method || 'GET').toUpperCase();
  const url = String(endpoint?.url || '').trim();
  const path = String(endpoint?.path || '').trim();
  return `${method}:${url || path}`;
}

function endpointQuery(endpoint) {
  return String(endpoint?.query || (endpoint?.querySamples || [])[0] || '').trim();
}

function endpointDisplayUrl(endpoint) {
  const explicit = String(endpoint?.url || '').trim();
  if (explicit) {
    try {
      const parsed = new URL(explicit);
      if (currentHost && parsed.hostname === currentHost) {
        return `${parsed.pathname || '/'}${parsed.search}`;
      }
      return parsed.href;
    } catch (_) {
      return explicit;
    }
  }

  const path = String(endpoint?.path || '/').trim() || '/';
  const query = endpointQuery(endpoint);
  return query ? `${path}?${query}` : path;
}

function betterSeverity(left, right) {
  return (SEV_RANK[right] ?? 99) < (SEV_RANK[left] ?? 99) ? right : left;
}

function normalizeLogSecret(secret) {
  return {
    id: (secret.ids || [])[0] || 'host-log',
    name: secret.name || (secret.names || [])[0] || 'Unknown Secret',
    severity: secret.severity || 'medium',
    value: secret.value,
    context: (secret.contexts || [])[0] || '',
    source: (secret.sources || [])[0] || (secret.pageUrls || [])[0] || '',
    timestamp: secret.lastSeen || secret.firstSeen || null,
    occurrences: secret.occurrences || 1,
    sources: uniqueStrings([...(secret.sources || []), ...(secret.pageUrls || [])]),
    pageUrls: uniqueStrings(secret.pageUrls || []),
    contexts: uniqueStrings(secret.contexts || []),
    names: uniqueStrings([secret.name, ...(secret.names || [])]),
  };
}

function normalizeLiveSecret(secret) {
  return {
    id: secret.id || 'live-scan',
    name: secret.name || 'Unknown Secret',
    severity: secret.severity || 'medium',
    value: secret.value,
    context: secret.context || '',
    source: secret.source || currentPageUrl || '',
    timestamp: secret.timestamp || Date.now(),
    occurrences: 1,
    sources: uniqueStrings([secret.source || currentPageUrl || '']),
    pageUrls: uniqueStrings([currentPageUrl]),
    contexts: uniqueStrings([secret.context || '']),
    names: uniqueStrings([secret.name || 'Unknown Secret']),
  };
}

function mergeSecretEntry(base, incoming) {
  return {
    ...base,
    ...incoming,
    name: incoming.name || base.name,
    severity: betterSeverity(base.severity || 'low', incoming.severity || base.severity || 'low'),
    context: incoming.context || base.context,
    source: incoming.source || base.source,
    timestamp: Math.max(base.timestamp || 0, incoming.timestamp || 0) || incoming.timestamp || base.timestamp || null,
    occurrences: Math.max(base.occurrences || 1, incoming.occurrences || 1),
    sources: uniqueStrings([...(base.sources || []), ...(incoming.sources || []), incoming.source, base.source]),
    pageUrls: uniqueStrings([...(base.pageUrls || []), ...(incoming.pageUrls || [])]),
    contexts: uniqueStrings([...(base.contexts || []), ...(incoming.contexts || []), incoming.context, base.context]),
    names: uniqueStrings([...(base.names || []), ...(incoming.names || []), incoming.name, base.name]),
  };
}

function normalizeLogEndpoint(endpoint) {
  return {
    method: endpoint.method || 'GET',
    path: endpoint.path || '/',
    url: endpoint.url || '',
    query: (endpoint.querySamples || [])[0] || '',
    params: endpoint.params || [],
    kind: (endpoint.kinds || [])[0] || 'host-log',
    source: (endpoint.sources || [])[0] || (endpoint.pageUrls || [])[0] || '',
    context: (endpoint.contexts || [])[0] || '',
    rawMatch: endpoint.url || endpoint.path || '',
    timestamp: endpoint.lastSeen || endpoint.firstSeen || null,
    occurrences: endpoint.occurrences || 1,
    sources: uniqueStrings([...(endpoint.sources || []), ...(endpoint.pageUrls || [])]),
    pageUrls: uniqueStrings(endpoint.pageUrls || []),
    querySamples: uniqueStrings(endpoint.querySamples || []),
    kinds: uniqueStrings(endpoint.kinds || []),
  };
}

function normalizeLiveEndpoint(endpoint) {
  return {
    method: endpoint.method || 'GET',
    path: endpoint.path || '/',
    url: endpoint.url || '',
    query: endpoint.query || '',
    params: endpoint.params || [],
    kind: endpoint.kind || 'live-scan',
    source: endpoint.source || currentPageUrl || '',
    context: endpoint.context || '',
    rawMatch: endpoint.rawMatch || endpoint.url || endpoint.path || '',
    timestamp: Date.now(),
    occurrences: 1,
    sources: uniqueStrings([endpoint.source || currentPageUrl || '']),
    pageUrls: uniqueStrings([currentPageUrl]),
    querySamples: uniqueStrings([endpoint.query || '']),
    kinds: uniqueStrings([endpoint.kind || 'live-scan']),
  };
}

function mergeEndpointEntry(base, incoming) {
  return {
    ...base,
    ...incoming,
    method: incoming.method || base.method,
    path: incoming.path || base.path,
    url: incoming.url || base.url,
    query: incoming.query || base.query,
    params: uniqueStrings([...(base.params || []), ...(incoming.params || [])]),
    kind: incoming.kind || base.kind,
    source: incoming.source || base.source,
    context: incoming.context || base.context,
    rawMatch: incoming.rawMatch || base.rawMatch,
    timestamp: Math.max(base.timestamp || 0, incoming.timestamp || 0) || incoming.timestamp || base.timestamp || null,
    occurrences: Math.max(base.occurrences || 1, incoming.occurrences || 1),
    sources: uniqueStrings([...(base.sources || []), ...(incoming.sources || []), incoming.source, base.source]),
    pageUrls: uniqueStrings([...(base.pageUrls || []), ...(incoming.pageUrls || [])]),
    querySamples: uniqueStrings([...(base.querySamples || []), ...(incoming.querySamples || []), incoming.query, base.query]),
    kinds: uniqueStrings([...(base.kinds || []), ...(incoming.kinds || []), incoming.kind, base.kind]),
  };
}

function renderCtx(context, highlight) {
  if (!context) return '';
  if (!highlight) return esc(context);
  const idx = context.indexOf(highlight);
  if (idx === -1) return esc(context);
  return esc(context.slice(0, idx)) +
    `<mark class="ctx-hi">${esc(context.slice(idx, idx + highlight.length))}</mark>` +
    esc(context.slice(idx + highlight.length));
}

function rebuildMergedFindings() {
  const secretsByValue = new Map();
  for (const secret of hostLog.secrets || []) {
    const normalized = normalizeLogSecret(secret);
    secretsByValue.set(normalized.value, normalized);
  }
  for (const secret of liveSecrets || []) {
    const normalized = normalizeLiveSecret(secret);
    const prior = secretsByValue.get(normalized.value);
    secretsByValue.set(normalized.value, prior ? mergeSecretEntry(prior, normalized) : normalized);
  }
  allSecrets = Array.from(secretsByValue.values());

  const endpointsByKey = new Map();
  for (const endpoint of hostLog.endpoints || []) {
    const normalized = normalizeLogEndpoint(endpoint);
    endpointsByKey.set(endpointIdentity(normalized), normalized);
  }
  for (const endpoint of liveEndpoints || []) {
    const normalized = normalizeLiveEndpoint(endpoint);
    const key = endpointIdentity(normalized);
    const prior = endpointsByKey.get(key);
    endpointsByKey.set(key, prior ? mergeEndpointEntry(prior, normalized) : normalized);
  }
  allEndpoints = Array.from(endpointsByKey.values());

  countEpEl.textContent = allEndpoints.length;
  countSecEl.textContent = allSecrets.length;
  badgeEpEl.textContent = allEndpoints.length;
  badgeSecEl.textContent = allSecrets.length;

  renderEndpoints();
  renderSecrets();
}

function updateStoredSummary() {
  const stats = hostLog.stats || summarizeHostLog(hostLog);
  const pageWord = stats.pageCount === 1 ? 'page' : 'pages';
  if (currentHost) {
    footerLogEl.textContent = `${currentHost}: ${stats.uniqueEndpoints} endpoints / ${stats.uniqueSecrets} secrets across ${stats.pageCount} ${pageWord}`;
  } else {
    footerLogEl.textContent = `Log: ${stats.uniqueEndpoints} endpoints / ${stats.uniqueSecrets} secrets across ${stats.pageCount} ${pageWord}`;
  }
}

function updateExpandButton(button, expandAll, count) {
  if (!button) return;
  button.disabled = count === 0;
  button.textContent = expandAll && count > 0 ? 'Collapse all' : 'Expand all';
}

function updateStatusText() {
  if (isScanning) {
    spinnerEl.classList.remove('hidden');
    statusEl.textContent = 'Scanning...';
    footerEl.textContent = currentHost ? `Scanning ${currentHost}` : 'Scanning...';
    return;
  }

  spinnerEl.classList.add('hidden');
  if (liveSecrets.length || liveEndpoints.length) {
    statusEl.textContent = 'Complete';
    footerEl.textContent = lastScanTime ? `Live scan updated ${timeAgo(lastScanTime)}` : 'Live scan complete';
    return;
  }

  const storedUpdatedAt = hostLog.stats?.updatedAt || hostLog.updatedAt || null;
  if (storedUpdatedAt) {
    statusEl.textContent = 'Stored results';
    footerEl.textContent = `Showing saved ${currentHost || 'host'} findings (${timeAgo(storedUpdatedAt)})`;
    return;
  }

  statusEl.textContent = targetTabId ? 'Waiting...' : 'Stored results';
  footerEl.textContent = currentHost ? `No saved findings yet for ${currentHost}` : 'Waiting for scan...';
}

function applyHostLog(log) {
  hostLog = log || createEmptyHostLog(currentHost);
  if (!hostLog.hostname && currentHost) hostLog.hostname = currentHost;
  updateStoredSummary();
  updateStatusText();
  rebuildMergedFindings();
}

function setCurrentContext(url) {
  const nextUrl = String(url || '').trim();
  if (nextUrl) {
    currentPageUrl = nextUrl;
    pageUrlEl.textContent = nextUrl;
  } else if (currentPageUrl) {
    pageUrlEl.textContent = currentPageUrl;
  } else if (currentHost) {
    pageUrlEl.textContent = currentHost;
  }

  const nextHost = getHostname(nextUrl || currentPageUrl);
  if (!nextHost || nextHost === currentHost) return false;

  currentHost = nextHost;
  hostLog = createEmptyHostLog(currentHost);
  updateStoredSummary();
  return true;
}

function copyText(text, btn, label = 'Copy') {
  navigator.clipboard.writeText(text).then(() => {
    if (!btn) return;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = label;
      btn.classList.remove('copied');
    }, 1500);
  }).catch(() => {});
}

function renderEndpoints() {
  const search = epSearchEl.value.trim().toLowerCase();
  const method = epMethodEl.value.toUpperCase();

  const list = allEndpoints
    .filter(endpoint => {
      if (method && (endpoint.method || 'GET').toUpperCase() !== method) return false;
      if (!search) return true;
      return endpointDisplayUrl(endpoint).toLowerCase().includes(search);
    })
    .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

  Array.from(epListEl.children).forEach(child => { if (child !== epEmptyEl) child.remove(); });

  if (list.length === 0) {
    updateExpandButton(expandEndpointsBtn, expandAllEndpoints, 0);
    epEmptyEl.classList.remove('hidden');
    epEmptyEl.querySelector('.empty-title').textContent =
      allEndpoints.length === 0
        ? (isScanning ? 'Scanning for endpoints...' : 'No endpoints detected')
        : 'No endpoints match the filter';
    epEmptyEl.querySelector('.empty-sub').textContent =
      allEndpoints.length === 0 && !isScanning
        ? (currentHost ? `No stored endpoints yet for ${currentHost}.` : 'Try pressing Rescan.')
        : '';
    return;
  }

  epEmptyEl.classList.add('hidden');
  updateExpandButton(expandEndpointsBtn, expandAllEndpoints, list.length);

  list.forEach(endpoint => {
    const methodName = (endpoint.method || 'GET').toUpperCase();
    const cls = METHOD_CLS[methodName] || 'method-unknown';
    const queryValue = endpointQuery(endpoint);
    const hasParams = (endpoint.params || []).length > 0;
    const hasContext = !!endpoint.context;
    const sourceCount = (endpoint.sources || []).length;
    const pageCount = (endpoint.pageUrls || []).length;
    const key = endpointIdentity(endpoint);
    const displayUrl = endpointDisplayUrl(endpoint);
    const copyValue = endpoint.url || displayUrl;
    const isOpen = expandAllEndpoints || endpointOpenKeys.has(key);
    const isContextOpen = endpointContextOpenKeys.has(key);

    const card = document.createElement('div');
    card.className = `ep-card${isOpen ? ' open' : ''}`;
    card.innerHTML = `
      <div class="ep-row">
        <span class="badge ${esc(cls)}">${esc(methodName)}</span>
        <span class="ep-path" title="${esc(displayUrl)}">${esc(displayUrl)}</span>
        <button class="cp-btn ep-cp">Copy</button>
        <svg class="chevron" width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M3 2l4 3-4 3" stroke="currentColor" stroke-width="1.3"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="ep-body">
        ${endpoint.url ? `<div class="kv"><span class="kv-k">URL</span><span class="kv-v" title="${esc(endpoint.url)}">${esc(trunc(endpoint.url, 200))}</span></div>` : ''}
        <div class="kv"><span class="kv-k">Source</span><span class="kv-v" title="${esc(endpoint.source)}">${esc(trunc(endpoint.source, 200))}</span></div>
        ${queryValue ? `<div class="kv"><span class="kv-k">Query</span><span class="kv-v mono">${esc(queryValue)}</span></div>` : ''}
        ${hasParams ? `<div class="kv"><span class="kv-k">Params</span></div><div class="chips">${endpoint.params.map(param => `<span class="chip">${esc(param)}</span>`).join('')}</div>` : ''}
        <div class="kv"><span class="kv-k">Seen</span><span class="kv-v">${esc(String(endpoint.occurrences || 1))} times on ${esc(String(pageCount || 1))} pages (${esc(String(sourceCount || 1))} sources)</span></div>
        ${hasContext ? `<div class="field"><div class="field-head"><div class="field-label">Context</div><button class="cp-btn ctx-toggle">${isContextOpen ? 'Collapse context' : 'Expand context'}</button></div><div class="field-ctx${isContextOpen ? ' expanded' : ''}">${renderCtx(endpoint.context, endpoint.rawMatch || endpoint.url || endpoint.path)}</div></div>` : ''}
      </div>`;

    card.querySelector('.ep-row').addEventListener('click', event => {
      if (event.target.classList.contains('ep-cp')) return;
      if (expandAllEndpoints) {
        expandAllEndpoints = false;
        endpointOpenKeys = new Set(list.map(item => endpointIdentity(item)));
        endpointOpenKeys.delete(key);
        card.classList.remove('open');
        updateExpandButton(expandEndpointsBtn, expandAllEndpoints, list.length);
        return;
      }

      if (endpointOpenKeys.has(key)) {
        endpointOpenKeys.delete(key);
      } else {
        endpointOpenKeys.add(key);
      }
      card.classList.toggle('open');
    });
    card.querySelector('.ep-cp').addEventListener('click', event => {
      event.stopPropagation();
      copyText(copyValue, event.currentTarget);
    });
    card.querySelector('.ctx-toggle')?.addEventListener('click', event => {
      event.stopPropagation();
      const button = event.currentTarget;
      const contextEl = card.querySelector('.field-ctx');
      if (!contextEl) return;

      if (endpointContextOpenKeys.has(key)) {
        endpointContextOpenKeys.delete(key);
        contextEl.classList.remove('expanded');
        button.textContent = 'Expand context';
      } else {
        endpointContextOpenKeys.add(key);
        contextEl.classList.add('expanded');
        button.textContent = 'Collapse context';
      }
    });

    epListEl.appendChild(card);
  });
}

function renderSecrets() {
  const search = secSearchEl.value.trim().toLowerCase();
  const severity = secSevEl.value.toLowerCase();

  const list = allSecrets
    .filter(secret => {
      if (severity && (secret.severity || '').toLowerCase() !== severity) return false;
      if (!search) return true;
      return String(secret.source || '').toLowerCase().includes(search);
    })
    .sort((left, right) =>
      (SEV_RANK[left.severity] ?? 9) - (SEV_RANK[right.severity] ?? 9) ||
      (right.timestamp || 0) - (left.timestamp || 0)
    );

  Array.from(secListEl.children).forEach(child => { if (child !== secEmptyEl) child.remove(); });

  if (list.length === 0) {
    updateExpandButton(expandSecretsBtn, expandAllSecrets, 0);
    secEmptyEl.classList.remove('hidden');
    const none = allSecrets.length === 0;
    secEmptyEl.querySelector('.empty-icon').textContent = none ? '*' : '?';
    secEmptyEl.querySelector('.empty-title').textContent =
      none ? (isScanning ? 'Scanning for secrets...' : 'No secrets detected') : 'No secrets match the filter';
    secEmptyEl.querySelector('.empty-sub').textContent =
      none && !isScanning
        ? (currentHost ? `No stored secrets yet for ${currentHost}.` : 'Nothing found on this page.')
        : '';
    return;
  }

  secEmptyEl.classList.add('hidden');
  updateExpandButton(expandSecretsBtn, expandAllSecrets, list.length);

  list.forEach(secret => {
    const severityName = (secret.severity || 'medium').toLowerCase();
    const sourceCount = (secret.sources || []).length;
    const pageCount = (secret.pageUrls || []).length;

    const key = secret.value;
    const isOpen = expandAllSecrets || secretOpenKeys.has(key);
    const isContextOpen = secretContextOpenKeys.has(key);

    const card = document.createElement('div');
    card.className = `sec-card${isOpen ? ' open' : ''}`;
    card.innerHTML = `
      <div class="sec-row">
        <span class="sev-badge sev-${esc(severityName)}">${esc(severityName)}</span>
        <span class="sec-name">${esc(secret.name)}</span>
        <button class="cp-btn sec-cp">Copy</button>
        <svg class="chevron" width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M3 2l4 3-4 3" stroke="currentColor" stroke-width="1.3"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="sec-preview">${esc(trunc(secret.value, 90))}</div>
      <div class="sec-body">
        <div class="field">
          <div class="field-label">Value</div>
          <div class="field-row">
            <div class="field-val">${esc(secret.value)}</div>
            <button class="cp-btn" data-a="val">Copy</button>
          </div>
        </div>
        ${secret.context ? `<div class="field"><div class="field-head"><div class="field-label">Context</div><button class="cp-btn ctx-toggle">${isContextOpen ? 'Collapse context' : 'Expand context'}</button></div><div class="field-ctx${isContextOpen ? ' expanded' : ''}">${renderCtx(secret.context, secret.value)}</div></div>` : ''}
        <div class="field">
          <div class="field-label">Source</div>
          <div class="field-row">
            <div class="field-url" title="${esc(secret.source)}">${esc(trunc(secret.source, 200))}</div>
            <button class="cp-btn" data-a="url">Copy URL</button>
          </div>
        </div>
        <div class="kv"><span class="kv-k">Seen</span><span class="kv-v">${esc(String(secret.occurrences || 1))} times on ${esc(String(pageCount || 1))} pages (${esc(String(sourceCount || 1))} sources)</span></div>
        ${secret.timestamp ? `<div class="sec-time">${timeAgo(secret.timestamp)}</div>` : ''}
      </div>`;

    card.querySelector('.sec-row').addEventListener('click', event => {
      if (event.target.classList.contains('sec-cp')) return;
      if (expandAllSecrets) {
        expandAllSecrets = false;
        secretOpenKeys = new Set(list.map(item => item.value));
        secretOpenKeys.delete(key);
        card.classList.remove('open');
        updateExpandButton(expandSecretsBtn, expandAllSecrets, list.length);
        return;
      }

      if (secretOpenKeys.has(key)) {
        secretOpenKeys.delete(key);
      } else {
        secretOpenKeys.add(key);
      }
      card.classList.toggle('open');
    });
    card.querySelector('.sec-cp').addEventListener('click', event => {
      event.stopPropagation();
      copyText(secret.value, event.currentTarget);
    });
    card.querySelector('.ctx-toggle')?.addEventListener('click', event => {
      event.stopPropagation();
      const button = event.currentTarget;
      const contextEl = card.querySelector('.field-ctx');
      if (!contextEl) return;

      if (secretContextOpenKeys.has(key)) {
        secretContextOpenKeys.delete(key);
        contextEl.classList.remove('expanded');
        button.textContent = 'Expand context';
      } else {
        secretContextOpenKeys.add(key);
        contextEl.classList.add('expanded');
        button.textContent = 'Collapse context';
      }
    });
    card.querySelectorAll('.sec-body .cp-btn[data-a]').forEach(button => {
      button.addEventListener('click', () => {
        if (button.dataset.a === 'val') {
          copyText(secret.value, button, 'Copy');
        } else {
          copyText(secret.source || currentPageUrl || currentHost, button, 'Copy URL');
        }
      });
    });

    secListEl.appendChild(card);
  });
}

function applyData(data) {
  if (!data) {
    liveSecrets = [];
    liveEndpoints = [];
    isScanning = false;
    lastScanTime = hostLog.stats?.updatedAt || hostLog.updatedAt || null;
    if (currentPageUrl) {
      pageUrlEl.textContent = currentPageUrl;
    } else if (currentHost) {
      pageUrlEl.textContent = currentHost;
    }
    updateStatusText();
    rebuildMergedFindings();
    return false;
  }

  const hostChanged = setCurrentContext(data.url || currentPageUrl);
  liveSecrets = data.secrets || [];
  liveEndpoints = data.endpoints || [];
  isScanning = !data.complete;
  lastScanTime = data.scanTime || lastScanTime;
  updateStatusText();
  rebuildMergedFindings();
  return hostChanged;
}

function msgContentScript() {
  return new Promise((resolve, reject) => {
    if (!targetTabId) return reject(new Error('no tabId'));
    const timeout = setTimeout(() => reject(new Error('timeout')), 1200);
    chrome.tabs.sendMessage(targetTabId, { type: 'GET_RESULTS' }, response => {
      clearTimeout(timeout);
      chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(response);
    });
  });
}

function readStorage() {
  return new Promise(resolve => {
    if (!SCAN_STORAGE_KEY) return resolve(null);
    chrome.storage.local.get(SCAN_STORAGE_KEY, items => {
      resolve(items[SCAN_STORAGE_KEY] || null);
    });
  });
}

function readHostLog(hostname = currentHost) {
  return new Promise(resolve => {
    const key = getHostLogKey(hostname);
    if (!key) return resolve(createEmptyHostLog(hostname));
    chrome.storage.local.get(key, items => {
      resolve(items[key] || createEmptyHostLog(hostname));
    });
  });
}

async function loadHostLog(hostname = currentHost) {
  const normalized = String(hostname || '').trim().toLowerCase();
  if (!normalized) {
    applyHostLog(createEmptyHostLog(''));
    return;
  }

  const token = ++hostLoadToken;
  const log = await readHostLog(normalized);
  if (token !== hostLoadToken) return;
  if (normalized !== currentHost) return;
  applyHostLog(log);
}

async function loadData() {
  let data = null;

  if (targetTabId) {
    try {
      const response = await msgContentScript();
      if (response) data = response;
    } catch (_) {}
  }

  if (!data && targetTabId) {
    data = await readStorage();
  }

  const hostChanged = applyData(data);
  if (currentHost && (hostChanged || !hostLog.hostname || hostLog.hostname !== currentHost)) {
    await loadHostLog(currentHost);
  } else if (currentHost && !hostLog.stats?.updatedAt) {
    await loadHostLog(currentHost);
  }
}

async function triggerRescan() {
  if (!targetTabId) return;
  rescanBtn.classList.add('spinning');
  liveSecrets = [];
  liveEndpoints = [];
  isScanning = true;
  updateStatusText();
  rebuildMergedFindings();

  try {
    await new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(targetTabId, { type: 'RESCAN' }, response => {
        chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(response);
      });
    });
  } catch (_) {
    try {
      await chrome.scripting.executeScript({ target: { tabId: targetTabId }, files: ['content.js'] });
    } catch (error) {
      console.warn('[SecretSauce] inject failed:', error);
    }
  }

  startPolling();
}

function startPolling() {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    await loadData();
    if (!isScanning) {
      clearInterval(pollTimer);
      rescanBtn.classList.remove('spinning');
    }
  }, 900);
}

function exportResults() {
  const hostname = currentHost || getHostname(currentPageUrl) || 'export';
  const payload = {
    exportedAt: new Date().toISOString(),
    hostname,
    currentScan: {
      url: currentPageUrl || pageUrlEl.textContent || '',
      scanTime: lastScanTime,
      complete: !isScanning,
      secrets: liveSecrets,
      endpoints: liveEndpoints,
    },
    hostLog,
    mergedFindings: {
      secrets: allSecrets,
      endpoints: allEndpoints,
    },
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const anchor = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob),
    download: `secretsauce-${hostname}-${Date.now()}.json`,
  });
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

document.querySelectorAll('.nav-btn').forEach(button => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach(item => item.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(panel => panel.classList.remove('active'));
    button.classList.add('active');
    $(`tab-${button.dataset.tab}`).classList.add('active');
  });
});

rescanBtn.addEventListener('click', triggerRescan);
exportBtn.addEventListener('click', exportResults);
expandEndpointsBtn.addEventListener('click', () => {
  if (expandEndpointsBtn.disabled) return;
  expandAllEndpoints = !expandAllEndpoints;
  if (!expandAllEndpoints) endpointOpenKeys.clear();
  renderEndpoints();
});
expandSecretsBtn.addEventListener('click', () => {
  if (expandSecretsBtn.disabled) return;
  expandAllSecrets = !expandAllSecrets;
  if (!expandAllSecrets) secretOpenKeys.clear();
  renderSecrets();
});
epSearchEl.addEventListener('input', renderEndpoints);
epMethodEl.addEventListener('change', renderEndpoints);
secSearchEl.addEventListener('input', renderSecrets);
secSevEl.addEventListener('change', renderSecrets);

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local') return;

  const currentHostKey = getHostLogKey(currentHost);
  if (currentHostKey && changes[currentHostKey]) {
    applyHostLog(changes[currentHostKey].newValue || createEmptyHostLog(currentHost));
  }

  if (SCAN_STORAGE_KEY && changes[SCAN_STORAGE_KEY]) {
    const next = changes[SCAN_STORAGE_KEY].newValue || null;
    const hostChanged = applyData(next);
    if (hostChanged) {
      void loadHostLog(currentHost);
    }
    if (!next || !next.complete) startPolling();
    if (next?.complete) rescanBtn.classList.remove('spinning');
  }
});

(async () => {
  if (currentPageUrl) {
    pageUrlEl.textContent = currentPageUrl;
  } else if (currentHost) {
    pageUrlEl.textContent = currentHost;
  }

  if (targetTabId) {
    try {
      const tab = await new Promise(resolve => chrome.tabs.get(targetTabId, currentTab => resolve(currentTab)));
      if (tab?.url) {
        currentPageUrl = tab.url;
        pageUrlEl.textContent = tab.url;
        const nextHost = getHostname(tab.url);
        if (nextHost) currentHost = nextHost;
      }
    } catch (_) {}
  }

  if (currentHost) {
    await loadHostLog(currentHost);
  } else {
    applyHostLog(createEmptyHostLog(''));
  }

  await loadData();

  if (!targetTabId && currentHost) {
    statusEl.textContent = 'Stored results';
    spinnerEl.classList.add('hidden');
  }

  if (isScanning) startPolling();
})();
