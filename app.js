// SecretSauce — Full-Page App Script
// Author: K. Boykov

'use strict';

// ─── Read tab ID from URL ──────────────────────────────────────────────────────
const targetTabId = parseInt(new URLSearchParams(location.search).get('tab'), 10) || null;

// ─── State ────────────────────────────────────────────────────────────────────
let allSecrets   = [];
let allEndpoints = [];
let isScanning   = false;
let lastScanTime = null;
let pollTimer    = null;

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const $          = id => document.getElementById(id);
const pageUrlEl  = $('page-url');
const countEpEl  = $('count-endpoints');
const countSecEl = $('count-secrets');
const badgeEpEl  = $('tab-badge-endpoints');
const badgeSecEl = $('tab-badge-secrets');
const statusEl   = $('status-text');
const spinnerEl  = $('spinner');
const epListEl   = $('ep-list');
const secListEl  = $('sec-list');
const epEmptyEl  = $('ep-empty');
const secEmptyEl = $('sec-empty');
const epSearchEl = $('ep-search');
const epMethodEl = $('ep-filter-method');
const secSearchEl= $('sec-search');
const secSevEl   = $('sec-filter-sev');
const footerEl   = $('footer-last-scan');
const rescanBtn  = $('btn-rescan');
const exportBtn  = $('btn-export');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function esc(s) {
  s = String(s ?? '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
          .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function trunc(s, n = 120) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function timeAgo(ts) {
  if (!ts) return '';
  const d = Math.floor((Date.now() - ts) / 1000);
  if (d < 5)    return 'just now';
  if (d < 60)   return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  return `${Math.floor(d / 3600)}h ago`;
}

function copyText(text, btn, label = 'Copy') {
  navigator.clipboard.writeText(text).then(() => {
    if (!btn) return;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = label; btn.classList.remove('copied'); }, 1500);
  }).catch(() => {});
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

// ─── Tab switching ─────────────────────────────────────────────────────────────

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    $(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

// ─── Render endpoints ──────────────────────────────────────────────────────────

const METHOD_CLS = {
  GET:'method-GET', POST:'method-POST', PUT:'method-PUT',
  DELETE:'method-DELETE', PATCH:'method-PATCH',
  HEAD:'method-HEAD', OPTIONS:'method-OPTIONS',
};

function renderEndpoints() {
  const search = epSearchEl.value.trim().toLowerCase();
  const method = epMethodEl.value.toUpperCase();

  const list = allEndpoints.filter(ep => {
    if (method && (ep.method || 'GET') !== method) return false;
    if (search) {
      const hay = `${ep.path} ${ep.source} ${(ep.params || []).join(' ')}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  Array.from(epListEl.children).forEach(c => { if (c !== epEmptyEl) c.remove(); });

  if (list.length === 0) {
    epEmptyEl.classList.remove('hidden');
    epEmptyEl.querySelector('.empty-title').textContent =
      allEndpoints.length === 0
        ? (isScanning ? 'Scanning for endpoints…' : 'No endpoints detected')
        : 'No endpoints match the filter';
    epEmptyEl.querySelector('.empty-sub').textContent =
      allEndpoints.length === 0 && !isScanning ? 'Try pressing Rescan.' : '';
    return;
  }
  epEmptyEl.classList.add('hidden');

  list.forEach(ep => {
    const m    = (ep.method || 'GET').toUpperCase();
    const cls  = METHOD_CLS[m] || 'method-unknown';
    const hasP = ep.params && ep.params.length > 0;
    const hasQ = !!ep.query;
    const hasCtx = !!ep.context;

    const card = document.createElement('div');
    card.className = 'ep-card';
    card.innerHTML = `
      <div class="ep-row">
        <span class="badge ${esc(cls)}">${esc(m)}</span>
        <span class="ep-path" title="${esc(ep.path)}">${esc(ep.path)}</span>
        <button class="cp-btn ep-cp">Copy</button>
        <svg class="chevron" width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M3 2l4 3-4 3" stroke="currentColor" stroke-width="1.3"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="ep-body">
        <div class="kv"><span class="kv-k">Source</span><span class="kv-v" title="${esc(ep.source)}">${esc(trunc(ep.source, 200))}</span></div>
        ${hasQ ? `<div class="kv"><span class="kv-k">Query</span><span class="kv-v mono">${esc(ep.query)}</span></div>` : ''}
        ${hasP ? `
          <div class="kv"><span class="kv-k">Params</span></div>
          <div class="chips">${ep.params.map(p => `<span class="chip">${esc(p)}</span>`).join('')}</div>
        ` : ''}
        ${hasCtx ? `
        <div class="field">
          <div class="field-label">Context</div>
          <div class="field-ctx">${renderCtx(ep.context, ep.rawMatch || ep.path)}</div>
        </div>` : ''}
      </div>`;

    card.querySelector('.ep-row').addEventListener('click', e => {
      if (e.target.classList.contains('ep-cp')) return;
      card.classList.toggle('open');
    });
    card.querySelector('.ep-cp').addEventListener('click', e => {
      e.stopPropagation();
      copyText(ep.path, e.currentTarget);
    });

    epListEl.appendChild(card);
  });
}

// ─── Render secrets ────────────────────────────────────────────────────────────

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function renderSecrets() {
  const search = secSearchEl.value.trim().toLowerCase();
  const sev    = secSevEl.value.toLowerCase();

  const list = allSecrets
    .filter(s => {
      if (sev && (s.severity || '').toLowerCase() !== sev) return false;
      if (search && !`${s.name} ${s.value} ${s.source}`.toLowerCase().includes(search)) return false;
      return true;
    })
    .sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));

  Array.from(secListEl.children).forEach(c => { if (c !== secEmptyEl) c.remove(); });

  if (list.length === 0) {
    secEmptyEl.classList.remove('hidden');
    const none = allSecrets.length === 0;
    secEmptyEl.querySelector('.empty-icon').textContent = none ? '🎉' : '🔍';
    secEmptyEl.querySelector('.empty-title').textContent =
      none ? (isScanning ? 'Scanning for secrets…' : 'No secrets detected') : 'No secrets match the filter';
    secEmptyEl.querySelector('.empty-sub').textContent =
      none && !isScanning ? 'Nothing found on this page.' : '';
    return;
  }
  secEmptyEl.classList.add('hidden');

  list.forEach(s => {
    const sv = (s.severity || 'medium').toLowerCase();
    const card = document.createElement('div');
    card.className = 'sec-card';
    card.innerHTML = `
      <div class="sec-row">
        <span class="sev-badge sev-${esc(sv)}">${esc(sv)}</span>
        <span class="sec-name">${esc(s.name)}</span>
        <button class="cp-btn sec-cp">Copy</button>
        <svg class="chevron" width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M3 2l4 3-4 3" stroke="currentColor" stroke-width="1.3"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="sec-preview">${esc(trunc(s.value, 90))}</div>
      <div class="sec-body">
        <div class="field">
          <div class="field-label">Value</div>
          <div class="field-row">
            <div class="field-val">${esc(s.value)}</div>
            <button class="cp-btn" data-a="val">Copy</button>
          </div>
        </div>
        ${s.context ? `
        <div class="field">
          <div class="field-label">Context</div>
          <div class="field-ctx">${renderCtx(s.context, s.value)}</div>
        </div>` : ''}
        <div class="field">
          <div class="field-label">Source</div>
          <div class="field-row">
            <div class="field-url" title="${esc(s.source)}">${esc(trunc(s.source, 200))}</div>
            <button class="cp-btn" data-a="url">Copy URL</button>
          </div>
        </div>
        ${s.timestamp ? `<div class="sec-time">${timeAgo(s.timestamp)}</div>` : ''}
      </div>`;

    card.querySelector('.sec-row').addEventListener('click', e => {
      if (e.target.classList.contains('sec-cp')) return;
      card.classList.toggle('open');
    });
    card.querySelector('.sec-cp').addEventListener('click', e => {
      e.stopPropagation(); copyText(s.value, e.currentTarget);
    });
    card.querySelectorAll('.sec-body .cp-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        btn.dataset.a === 'val' ? copyText(s.value, btn, 'Copy') : copyText(s.source, btn, 'Copy URL');
      });
    });

    secListEl.appendChild(card);
  });
}

// ─── Update UI state ───────────────────────────────────────────────────────────

function applyData(data) {
  if (!data) {
    spinnerEl.classList.remove('hidden');
    statusEl.textContent = 'Waiting…';
    return;
  }

  allSecrets   = data.secrets   || [];
  allEndpoints = data.endpoints || [];
  isScanning   = !data.complete;
  lastScanTime = data.scanTime || null;

  if (data.url) pageUrlEl.textContent = data.url;

  countEpEl.textContent  = allEndpoints.length;
  countSecEl.textContent = allSecrets.length;
  badgeEpEl.textContent  = allEndpoints.length;
  badgeSecEl.textContent = allSecrets.length;

  if (isScanning) {
    spinnerEl.classList.remove('hidden');
    statusEl.textContent = 'Scanning…';
  } else {
    spinnerEl.classList.add('hidden');
    statusEl.textContent = 'Complete';
    if (lastScanTime) footerEl.textContent = 'Scanned ' + timeAgo(lastScanTime);
  }

  renderEndpoints();
  renderSecrets();
}

// ─── Data loading ──────────────────────────────────────────────────────────────

function msgContentScript() {
  return new Promise((resolve, reject) => {
    if (!targetTabId) return reject(new Error('no tabId'));
    const tid = setTimeout(() => reject(new Error('timeout')), 1200);
    chrome.tabs.sendMessage(targetTabId, { type: 'GET_RESULTS' }, resp => {
      clearTimeout(tid);
      chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(resp);
    });
  });
}

function readStorage() {
  return new Promise(resolve => {
    if (!targetTabId) return resolve(null);
    chrome.storage.local.get(`scan_${targetTabId}`, items => {
      resolve(items[`scan_${targetTabId}`] || null);
    });
  });
}

async function loadData() {
  if (!targetTabId) return;
  try {
    const resp = await msgContentScript();
    if (resp) { applyData(resp); return; }
  } catch (_) {}
  const stored = await readStorage();
  applyData(stored);
}

// ─── Rescan ────────────────────────────────────────────────────────────────────

async function triggerRescan() {
  if (!targetTabId) return;
  rescanBtn.classList.add('spinning');
  allSecrets = []; allEndpoints = []; isScanning = true;
  spinnerEl.classList.remove('hidden');
  statusEl.textContent = 'Scanning…';
  renderEndpoints();
  renderSecrets();

  try {
    await new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(targetTabId, { type: 'RESCAN' }, r => {
        chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(r);
      });
    });
  } catch (_) {
    try {
      await chrome.scripting.executeScript({ target: { tabId: targetTabId }, files: ['content.js'] });
    } catch (e) { console.warn('[SecretSauce] inject failed:', e); }
  }

  startPolling();
}

// ─── Polling ───────────────────────────────────────────────────────────────────

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

// ─── Export ────────────────────────────────────────────────────────────────────

function exportResults() {
  const host = (() => { try { return new URL(pageUrlEl.textContent).hostname; } catch { return 'export'; } })();
  const blob = new Blob(
    [JSON.stringify({ exportedAt: new Date().toISOString(), url: pageUrlEl.textContent, secrets: allSecrets, endpoints: allEndpoints }, null, 2)],
    { type: 'application/json' }
  );
  const a = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob),
    download: `secretsauce-${host}-${Date.now()}.json`,
  });
  document.body.appendChild(a); a.click(); a.remove();
}

// ─── Events ────────────────────────────────────────────────────────────────────

rescanBtn.addEventListener('click', triggerRescan);
exportBtn.addEventListener('click', exportResults);
epSearchEl.addEventListener('input', renderEndpoints);
epMethodEl.addEventListener('change', renderEndpoints);
secSearchEl.addEventListener('input', renderSecrets);
secSevEl.addEventListener('change', renderSecrets);

// ─── Init ──────────────────────────────────────────────────────────────────────

(async () => {
  if (!targetTabId) {
    statusEl.textContent = 'No tab — click the extension icon on a page.';
    spinnerEl.classList.add('hidden');
    return;
  }

  // Try to get the URL from the active tab
  try {
    const tab = await new Promise(resolve => chrome.tabs.get(targetTabId, t => resolve(t)));
    if (tab?.url) pageUrlEl.textContent = tab.url;
  } catch (_) {}

  await loadData();
  if (isScanning) startPolling();
})();
