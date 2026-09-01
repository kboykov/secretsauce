// SecretSauce — Background (Chrome MV3 service worker / Firefox MV2 event page)
// One file for both browsers: every API difference is feature-detected below.
// Author: K. Boykov

/* global importScripts */
if (typeof globalThis.SS === 'undefined' && typeof importScripts === 'function') {
  importScripts('shared.js');
}

(function () {
  'use strict';

  const SS = globalThis.SS;
  const api = SS.api;
  const action = api.action || api.browserAction;
  const isMV3 = !!api.action;

  // ─── Rules cache ──────────────────────────────────────────────────────────
  let rulesPromise = null;

  function loadRules() {
    if (!rulesPromise) {
      rulesPromise = fetch(api.runtime.getURL('rules/secrets.json'))
        .then(r => r.json())
        .then(rules => (Array.isArray(rules) ? rules : []))
        .catch(err => {
          console.warn('[SecretSauce] rules load failed:', err);
          rulesPromise = null;
          return [];
        });
    }
    return rulesPromise;
  }

  // ─── Storage helpers with quota fallback ──────────────────────────────────
  async function pruneOldestHostLogs(keepKey) {
    const all = await SS.storageGet(null);
    const hostKeys = Object.keys(all)
      .filter(k => k.startsWith(SS.HOST_LOG_PREFIX) && k !== keepKey)
      .map(k => ({ key: k, updatedAt: all[k]?.updatedAt || 0 }))
      .sort((a, b) => a.updatedAt - b.updatedAt);
    if (!hostKeys.length) return;
    const toRemove = hostKeys.slice(0, Math.max(1, Math.floor(hostKeys.length / 2))).map(x => x.key);
    await SS.storageRemove(toRemove);
  }

  async function storageSetQuotaSafe(values, hostKey) {
    try {
      await SS.storageSet(values);
    } catch (err) {
      if (!SS.isQuotaError(err)) throw err;
      await pruneOldestHostLogs(hostKey);
      try {
        await SS.storageSet(values);
      } catch (err2) {
        if (!SS.isQuotaError(err2)) throw err2;
        // Last resort: strip all contexts from the log entry and retry.
        const stripped = {};
        for (const [k, v] of Object.entries(values)) {
          if (k.startsWith(SS.HOST_LOG_PREFIX) && Array.isArray(v?.secrets)) {
            stripped[k] = {
              ...v,
              secrets: v.secrets.map(s => ({ ...s, contexts: [] })),
              endpoints: v.endpoints.map(e => ({ ...e, contexts: [] })),
            };
          } else {
            stripped[k] = v;
          }
        }
        await SS.storageSet(stripped).catch(() => {});
      }
    }
  }

  // ─── Findings log merge (serialised) ──────────────────────────────────────
  let logWriteQueue = Promise.resolve();

  function queueLogWrite(task) {
    logWriteQueue = logWriteQueue.catch(() => null).then(task);
    return logWriteQueue;
  }

  async function mergeFindingsLog(message, sender) {
    const pageUrl = String(message?.pageUrl || sender?.tab?.url || '').trim();
    const hostname = String(message?.hostname || SS.getHostname(pageUrl)).trim().toLowerCase();
    const scanTime = Number(message?.scanTime) || Date.now();
    const secrets = Array.isArray(message?.secrets) ? message.secrets : [];
    const endpoints = Array.isArray(message?.endpoints) ? message.endpoints : [];

    if (!hostname) return { hostname: '', stats: SS.createEmptyHostLog('').stats };

    const storageKey = SS.getHostLogKey(hostname);
    const existing = (await SS.storageGet(storageKey))[storageKey] || SS.createEmptyHostLog(hostname);
    const nextLog = {
      version: 1,
      hostname,
      updatedAt: scanTime,
      secrets: existing.secrets || [],
      endpoints: existing.endpoints || [],
    };

    if (secrets.length || endpoints.length) {
      nextLog.secrets = SS.mergeSecrets(existing.secrets, secrets, pageUrl, scanTime);
      nextLog.endpoints = SS.mergeEndpoints(existing.endpoints, endpoints, pageUrl, scanTime);
    }
    nextLog.stats = SS.summarizeHostLog(nextLog);

    await storageSetQuotaSafe({
      [storageKey]: nextLog,
      [SS.LAST_APP_CONTEXT_KEY]: {
        tabId: sender?.tab?.id ?? null,
        hostname,
        pageUrl,
        updatedAt: scanTime,
      },
    }, storageKey);

    return { hostname, storageKey, stats: nextLog.stats };
  }

  // ─── Badge ────────────────────────────────────────────────────────────────
  const BADGE_COLORS = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    none: '#64748b',
  };

  async function updateBadge(tabId, count, severity) {
    if (!tabId) return;
    const settings = await SS.getSettings();
    const text = count > 0 ? (count > 99 ? '99+' : String(count)) : '';
    const color = settings.badgeSeverityColor ? (BADGE_COLORS[severity] || BADGE_COLORS.none) : '#e53e3e';
    try { action.setBadgeText({ text, tabId }); } catch (_) {}
    try { action.setBadgeBackgroundColor({ color, tabId }); } catch (_) {}
    if (typeof action.setBadgeTextColor === 'function') {
      try { action.setBadgeTextColor({ color: severity === 'medium' ? '#1a1a1a' : '#ffffff', tabId }); } catch (_) {}
    }
  }

  // ─── Content script injection (Rescan on pages loaded before install) ─────
  function injectContentScript(tabId) {
    const files = ['shared.js', 'detect.js', 'content.js'];
    if (api.scripting?.executeScript) {
      return api.scripting.executeScript({ target: { tabId }, files });
    }
    // MV2: tabs.executeScript runs one file at a time, in order.
    return files.reduce((chain, file) => chain.then(() => new Promise((resolve, reject) => {
      api.tabs.executeScript(tabId, { file }, () => {
        const err = api.runtime.lastError;
        err ? reject(err) : resolve();
      });
    })), Promise.resolve());
  }

  // ─── Opening the app ──────────────────────────────────────────────────────
  function appUrl(params) {
    const qs = params.toString();
    return api.runtime.getURL(`app.html${qs ? `?${qs}` : ''}`);
  }

  function parseAppContext(url) {
    try {
      const parsed = new URL(url || '');
      if (parsed.origin !== api.runtime.getURL('').replace(/\/$/, '')) return null;
      if (!parsed.pathname.endsWith('/app.html')) return null;
      return {
        tabId: parseInt(parsed.searchParams.get('tab'), 10) || null,
        hostname: (parsed.searchParams.get('host') || '').trim().toLowerCase(),
        pageUrl: parsed.searchParams.get('url') || '',
      };
    } catch (_) {
      return null;
    }
  }

  async function resolveActionContext(tab) {
    const appContext = parseAppContext(tab?.url || '');
    if (!appContext) {
      return { targetTabId: tab?.id ?? null, hostname: SS.getHostname(tab?.url || ''), pageUrl: tab?.url || '' };
    }
    const targetTab = await SS.tabsGet(appContext.tabId);
    if (targetTab?.url) {
      return { targetTabId: targetTab.id, hostname: SS.getHostname(targetTab.url) || appContext.hostname, pageUrl: targetTab.url };
    }
    const lastContext = (await SS.storageGet(SS.LAST_APP_CONTEXT_KEY))[SS.LAST_APP_CONTEXT_KEY] || {};
    return {
      targetTabId: appContext.tabId || lastContext.tabId || null,
      hostname: appContext.hostname || lastContext.hostname || '',
      pageUrl: appContext.pageUrl || lastContext.pageUrl || '',
    };
  }

  function queryTabs(queryInfo) {
    return new Promise(resolve => {
      try { api.tabs.query(queryInfo, tabs => resolve(api.runtime.lastError ? [] : (tabs || []))); } catch (_) { resolve([]); }
    });
  }

  async function openApp(tab) {
    const context = await resolveActionContext(tab);
    await SS.storageSet({
      [SS.LAST_APP_CONTEXT_KEY]: {
        tabId: context.targetTabId || null,
        hostname: context.hostname || '',
        pageUrl: context.pageUrl || '',
        updatedAt: Date.now(),
      },
    }).catch(() => {});

    const params = new URLSearchParams();
    if (context.targetTabId) params.set('tab', String(context.targetTabId));
    if (context.hostname) params.set('host', context.hostname);
    if (context.pageUrl) params.set('url', context.pageUrl);
    const url = appUrl(params);

    // Re-use an app tab that already targets this page tab instead of stacking duplicates.
    const existing = (await queryTabs({ url: api.runtime.getURL('app.html') + '*' }))
      .find(t => parseAppContext(t.url)?.tabId === context.targetTabId && context.targetTabId);
    if (existing) {
      api.tabs.update(existing.id, { url, active: true });
      if (existing.windowId != null) api.windows?.update(existing.windowId, { focused: true });
      return;
    }
    api.tabs.create({ url, index: tab?.index != null ? tab.index + 1 : undefined });
  }

  action.onClicked.addListener(tab => { openApp(tab); });

  if (api.commands?.onCommand) {
    api.commands.onCommand.addListener(command => {
      if (command !== 'open-secretsauce') return;
      queryTabs({ active: true, currentWindow: true }).then(tabs => openApp(tabs[0]));
    });
  }

  // ─── Messages ─────────────────────────────────────────────────────────────
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message !== 'object') return false;

    switch (message.type) {
      case 'GET_TAB_ID':
        sendResponse({ tabId: sender.tab?.id ?? null });
        return false;

      case 'GET_INIT':
        Promise.all([loadRules(), SS.getSettings()])
          .then(([rules, settings]) => sendResponse({ tabId: sender.tab?.id ?? null, rules, settings }))
          .catch(error => sendResponse({ tabId: sender.tab?.id ?? null, rules: [], settings: null, error: String(error) }));
        return true;

      case 'GET_RULES':
        loadRules().then(rules => sendResponse({ rules })).catch(() => sendResponse({ rules: [] }));
        return true;

      case 'UPDATE_BADGE': {
        const tabId = sender.tab?.id;
        if (tabId) updateBadge(tabId, message.secretCount || 0, message.highestSeverity || 'none');
        return false;
      }

      case 'LOG_FINDINGS':
        queueLogWrite(() => mergeFindingsLog(message, sender))
          .then(payload => sendResponse({ ok: true, ...payload }))
          .catch(error => sendResponse({ ok: false, error: String(error) }));
        return true;

      case 'INJECT_CONTENT': {
        const tabId = Number(message.tabId);
        if (!tabId) { sendResponse({ ok: false, error: 'no tabId' }); return false; }
        injectContentScript(tabId)
          .then(() => sendResponse({ ok: true }))
          .catch(error => sendResponse({ ok: false, error: String(error?.message || error) }));
        return true;
      }

      case 'OPEN_APP_FOR_TAB': {
        SS.tabsGet(Number(message.tabId)).then(tab => { openApp(tab); sendResponse({ ok: !!tab }); });
        return true;
      }

      default:
        return false;
    }
  });

  // ─── Tab lifecycle ────────────────────────────────────────────────────────
  api.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status !== 'loading') return;
    try { action.setBadgeText({ text: '', tabId }); } catch (_) {}
    SS.storageRemove(SS.getScanKey(tabId));
  });

  api.tabs.onRemoved.addListener(tabId => {
    SS.storageRemove(SS.getScanKey(tabId));
  });

  // ─── Firefox MV2: strip frame-busting headers for embedded recon tools ────
  // Chrome does the same through declarativeNetRequest (rules/frame_rules.json).
  if (!isMV3 && api.webRequest?.onHeadersReceived && !api.declarativeNetRequest) {
    try {
      api.webRequest.onHeadersReceived.addListener(
        info => {
          const headers = (info.responseHeaders || []).filter(h => {
            const name = h.name.toLowerCase();
            return name !== 'x-frame-options' && name !== 'content-security-policy';
          });
          return { responseHeaders: headers };
        },
        {
          urls: [
            '*://securitytrails.com/*', '*://*.securitytrails.com/*',
            '*://web-check.xyz/*', '*://*.web-check.xyz/*',
          ],
          types: ['sub_frame'],
        },
        ['blocking', 'responseHeaders'],
      );
    } catch (err) {
      console.warn('[SecretSauce] webRequest listener failed:', err);
    }
  }
})();
