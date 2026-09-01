// SecretSauce app — findings model: merges the live tab scan with the persistent
// host log, and provides filtering / sorting / export helpers.

(function (root) {
  'use strict';

  const SS = root.SS;

  const KIND_LABELS = {
    dom: 'DOM', inline: 'Inline JS', fetch: 'fetch()', axios: 'axios', jquery: 'jQuery', xhr: 'XHR',
    websocket: 'WebSocket', 'http-client': 'HTTP client', route: 'Route', property: 'Config', apiprefix: 'API path',
    path: 'Path literal', absolute: 'Absolute URL', 'host-log': 'Stored', 'live-scan': 'Live',
  };

  function kindLabel(kind) {
    if (!kind) return 'Unknown';
    if (kind.startsWith('network-')) return `Network · ${kind.slice(8)}`;
    return KIND_LABELS[kind] || kind;
  }

  // Coarse family used for the kind filter dropdown.
  function kindFamily(kind) {
    if (!kind) return 'other';
    if (kind === 'dom') return 'dom';
    if (kind === 'inline' || kind === 'path' || kind === 'absolute' || kind === 'apiprefix' || kind === 'property') return 'static';
    if (kind.startsWith('network-')) return 'network';
    if (['fetch', 'axios', 'jquery', 'xhr', 'websocket', 'http-client', 'route'].includes(kind)) return 'code';
    return 'other';
  }

  const KIND_FAMILY_LABELS = { code: 'API calls in code', network: 'Observed network', dom: 'DOM attributes', static: 'String literals', other: 'Other' };

  function betterSeverity(left, right) {
    return (SS.SEVERITY_RANK[right] ?? 99) < (SS.SEVERITY_RANK[left] ?? 99) ? right : left;
  }

  // ─── Secrets ──────────────────────────────────────────────────────────────
  function normalizeLogSecret(secret) {
    return {
      id: (secret.ids || [])[0] || 'host-log',
      ids: SS.uniqueStrings(secret.ids || []),
      name: secret.name || (secret.names || [])[0] || 'Unknown Secret',
      severity: secret.severity || 'medium',
      value: secret.value,
      context: (secret.contexts || [])[0] || '',
      source: (secret.sources || [])[0] || (secret.pageUrls || [])[0] || '',
      timestamp: secret.lastSeen || secret.firstSeen || null,
      firstSeen: secret.firstSeen || null,
      occurrences: secret.occurrences || 1,
      sources: SS.uniqueStrings([...(secret.sources || []), ...(secret.pageUrls || [])]),
      pageUrls: SS.uniqueStrings(secret.pageUrls || []),
      contexts: SS.uniqueStrings(secret.contexts || []),
      names: SS.uniqueStrings([secret.name, ...(secret.names || [])]),
      live: false,
    };
  }

  function normalizeLiveSecret(secret, currentPageUrl) {
    return {
      id: secret.id || 'live-scan',
      ids: SS.uniqueStrings([secret.id]),
      name: secret.name || 'Unknown Secret',
      severity: secret.severity || 'medium',
      value: secret.value,
      context: secret.context || '',
      source: secret.source || currentPageUrl || '',
      timestamp: secret.timestamp || Date.now(),
      firstSeen: secret.timestamp || null,
      occurrences: 1,
      sources: SS.uniqueStrings([secret.source || currentPageUrl || '']),
      pageUrls: SS.uniqueStrings([currentPageUrl]),
      contexts: SS.uniqueStrings([secret.context || '']),
      names: SS.uniqueStrings([secret.name || 'Unknown Secret']),
      live: true,
    };
  }

  function mergeSecretEntry(base, incoming) {
    return {
      ...base,
      ...incoming,
      ids: SS.uniqueStrings([...(base.ids || []), ...(incoming.ids || [])]),
      name: incoming.name || base.name,
      severity: betterSeverity(base.severity || 'low', incoming.severity || base.severity || 'low'),
      context: incoming.context || base.context,
      source: incoming.source || base.source,
      timestamp: Math.max(base.timestamp || 0, incoming.timestamp || 0) || null,
      firstSeen: Math.min(base.firstSeen || Infinity, incoming.firstSeen || Infinity) === Infinity ? null : Math.min(base.firstSeen || Infinity, incoming.firstSeen || Infinity),
      occurrences: Math.max(base.occurrences || 1, incoming.occurrences || 1),
      sources: SS.uniqueStrings([...(base.sources || []), ...(incoming.sources || []), incoming.source, base.source]),
      pageUrls: SS.uniqueStrings([...(base.pageUrls || []), ...(incoming.pageUrls || [])]),
      contexts: SS.uniqueStrings([...(base.contexts || []), ...(incoming.contexts || []), incoming.context, base.context]),
      names: SS.uniqueStrings([...(base.names || []), ...(incoming.names || []), incoming.name, base.name]),
      live: base.live || incoming.live,
    };
  }

  // ─── Endpoints ────────────────────────────────────────────────────────────
  function normalizeLogEndpoint(endpoint) {
    return {
      method: endpoint.method || 'GET',
      path: endpoint.path || '/',
      url: endpoint.url || '',
      host: endpoint.host || SS.getHostname(endpoint.url || ''),
      query: (endpoint.querySamples || [])[0] || '',
      params: endpoint.params || [],
      kind: (endpoint.kinds || [])[0] || 'host-log',
      source: (endpoint.sources || [])[0] || (endpoint.pageUrls || [])[0] || '',
      context: (endpoint.contexts || [])[0] || '',
      rawMatch: endpoint.url || endpoint.path || '',
      timestamp: endpoint.lastSeen || endpoint.firstSeen || null,
      firstSeen: endpoint.firstSeen || null,
      occurrences: endpoint.occurrences || 1,
      sources: SS.uniqueStrings([...(endpoint.sources || []), ...(endpoint.pageUrls || [])]),
      pageUrls: SS.uniqueStrings(endpoint.pageUrls || []),
      querySamples: SS.uniqueStrings(endpoint.querySamples || []),
      kinds: SS.uniqueStrings(endpoint.kinds || []),
      templated: /\{[A-Za-z0-9_]+\}/.test(endpoint.path || ''),
      live: false,
    };
  }

  function normalizeLiveEndpoint(endpoint, currentPageUrl) {
    return {
      method: endpoint.method || 'GET',
      path: endpoint.path || '/',
      url: endpoint.url || '',
      host: endpoint.host || SS.getHostname(endpoint.url || ''),
      query: endpoint.query || '',
      params: endpoint.params || [],
      kind: endpoint.kind || 'live-scan',
      source: endpoint.source || currentPageUrl || '',
      context: endpoint.context || '',
      rawMatch: endpoint.rawMatch || endpoint.url || endpoint.path || '',
      timestamp: Date.now(),
      firstSeen: null,
      occurrences: 1,
      sources: SS.uniqueStrings([endpoint.source || currentPageUrl || '']),
      pageUrls: SS.uniqueStrings([currentPageUrl]),
      querySamples: SS.uniqueStrings([endpoint.query || '']),
      kinds: SS.uniqueStrings([endpoint.kind || 'live-scan']),
      templated: !!endpoint.templated || /\{[A-Za-z0-9_]+\}/.test(endpoint.path || ''),
      live: true,
    };
  }

  function mergeEndpointEntry(base, incoming) {
    return {
      ...base,
      ...incoming,
      method: incoming.method || base.method,
      path: incoming.path || base.path,
      url: incoming.url || base.url,
      host: incoming.host || base.host,
      query: incoming.query || base.query,
      params: SS.uniqueStrings([...(base.params || []), ...(incoming.params || [])]),
      kind: incoming.kind || base.kind,
      source: incoming.source || base.source,
      context: incoming.context || base.context,
      rawMatch: incoming.rawMatch || base.rawMatch,
      timestamp: Math.max(base.timestamp || 0, incoming.timestamp || 0) || null,
      firstSeen: base.firstSeen || incoming.firstSeen || null,
      occurrences: Math.max(base.occurrences || 1, incoming.occurrences || 1),
      sources: SS.uniqueStrings([...(base.sources || []), ...(incoming.sources || []), incoming.source, base.source]),
      pageUrls: SS.uniqueStrings([...(base.pageUrls || []), ...(incoming.pageUrls || [])]),
      querySamples: SS.uniqueStrings([...(base.querySamples || []), ...(incoming.querySamples || []), incoming.query, base.query]),
      kinds: SS.uniqueStrings([...(base.kinds || []), ...(incoming.kinds || []), incoming.kind, base.kind]),
      templated: base.templated || incoming.templated,
      live: base.live || incoming.live,
    };
  }

  function buildMerged({ hostLog, liveSecrets, liveEndpoints, currentPageUrl }) {
    const secretsByValue = new Map();
    for (const secret of hostLog?.secrets || []) {
      const normalized = normalizeLogSecret(secret);
      secretsByValue.set(normalized.value, normalized);
    }
    for (const secret of liveSecrets || []) {
      const normalized = normalizeLiveSecret(secret, currentPageUrl);
      const prior = secretsByValue.get(normalized.value);
      secretsByValue.set(normalized.value, prior ? mergeSecretEntry(prior, normalized) : normalized);
    }

    const endpointsByKey = new Map();
    for (const endpoint of hostLog?.endpoints || []) {
      const normalized = normalizeLogEndpoint(endpoint);
      endpointsByKey.set(SS.endpointIdentity(normalized), normalized);
    }
    for (const endpoint of liveEndpoints || []) {
      const normalized = normalizeLiveEndpoint(endpoint, currentPageUrl);
      const key = SS.endpointIdentity(normalized);
      const prior = endpointsByKey.get(key);
      endpointsByKey.set(key, prior ? mergeEndpointEntry(prior, normalized) : normalized);
    }

    return { secrets: Array.from(secretsByValue.values()), endpoints: Array.from(endpointsByKey.values()) };
  }

  // ─── Display helpers ──────────────────────────────────────────────────────
  function endpointQuery(endpoint) {
    return String(endpoint?.query || (endpoint?.querySamples || [])[0] || '').trim();
  }

  // { hostPrefix, pathText } — host prefix is shown dimmed when the endpoint
  // lives on a different subdomain than the page.
  function endpointDisplay(endpoint, currentHost) {
    const explicit = String(endpoint?.url || '').trim();
    if (explicit) {
      const m = explicit.match(/^((?:https?|wss?):\/\/[^/?#]+)(.*)$/i);
      if (m) {
        const host = m[1].replace(/^(?:https?|wss?):\/\//i, '').toLowerCase();
        const rest = m[2] || '/';
        if (currentHost && host === currentHost && /^https?:$/i.test(m[1].split('//')[0])) return { hostPrefix: '', pathText: rest };
        return { hostPrefix: m[1], pathText: rest };
      }
      return { hostPrefix: '', pathText: explicit };
    }
    const path = String(endpoint?.path || '/').trim() || '/';
    const query = endpointQuery(endpoint);
    return { hostPrefix: '', pathText: query ? `${path}?${query}` : path };
  }

  function endpointDisplayUrl(endpoint, currentHost) {
    const { hostPrefix, pathText } = endpointDisplay(endpoint, currentHost);
    return `${hostPrefix}${pathText}`;
  }

  function toCurl(endpoint) {
    const method = (endpoint.method || 'GET').toUpperCase();
    const url = endpoint.url || endpointDisplayUrl(endpoint, '');
    const parts = ['curl', '-i'];
    if (method !== 'GET') parts.push('-X', method);
    parts.push(`'${url.replace(/'/g, "'\\''")}'`);
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      const body = {};
      for (const p of endpoint.params || []) body[p] = '';
      parts.push('-H', "'Content-Type: application/json'", '-d', `'${JSON.stringify(body)}'`);
    }
    return parts.join(' ');
  }

  // ─── Filtering / sorting ──────────────────────────────────────────────────
  function matchesSearch(haystacks, search) {
    if (!search) return true;
    const terms = search.toLowerCase().split(/\s+/).filter(Boolean);
    const text = haystacks.filter(Boolean).join(' ').toLowerCase();
    return terms.every(term => term.startsWith('-') ? !text.includes(term.slice(1)) : text.includes(term));
  }

  function filterEndpoints(list, { search = '', method = '', kind = '', ignored = new Set(), showIgnored = false, currentHost = '' } = {}) {
    return list.filter(endpoint => {
      const key = SS.endpointIdentity(endpoint);
      if (!showIgnored && ignored.has(key)) return false;
      if (showIgnored && !ignored.has(key)) return false;
      if (method && (endpoint.method || 'GET').toUpperCase() !== method) return false;
      if (kind && !(endpoint.kinds || [endpoint.kind]).some(k => kindFamily(k) === kind)) return false;
      return matchesSearch([
        endpointDisplayUrl(endpoint, currentHost), endpoint.url, endpoint.path,
        (endpoint.params || []).join(' '), endpoint.source, (endpoint.kinds || []).join(' '), endpoint.method,
      ], search);
    });
  }

  function filterSecrets(list, { search = '', severity = '', ruleId = '', ignored = new Set(), showIgnored = false } = {}) {
    return list.filter(secret => {
      if (!showIgnored && ignored.has(secret.value)) return false;
      if (showIgnored && !ignored.has(secret.value)) return false;
      if (severity && (secret.severity || '').toLowerCase() !== severity) return false;
      if (ruleId && !(secret.ids || [secret.id]).includes(ruleId)) return false;
      return matchesSearch([secret.name, secret.value, secret.source, (secret.ids || []).join(' '), (secret.names || []).join(' ')], search);
    });
  }

  const METHOD_ORDER = { GET: 0, POST: 1, PUT: 2, PATCH: 3, DELETE: 4, HEAD: 5, OPTIONS: 6 };

  function sortEndpoints(list, sort = 'recent', currentHost = '') {
    const copy = list.slice();
    switch (sort) {
      case 'path':
        return copy.sort((a, b) => endpointDisplayUrl(a, currentHost).localeCompare(endpointDisplayUrl(b, currentHost)));
      case 'method':
        return copy.sort((a, b) => (METHOD_ORDER[a.method] ?? 9) - (METHOD_ORDER[b.method] ?? 9) || endpointDisplayUrl(a, currentHost).localeCompare(endpointDisplayUrl(b, currentHost)));
      case 'seen':
        return copy.sort((a, b) => (b.occurrences || 0) - (a.occurrences || 0));
      case 'recent':
      default:
        return copy.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0) || endpointDisplayUrl(a, currentHost).localeCompare(endpointDisplayUrl(b, currentHost)));
    }
  }

  function sortSecrets(list, sort = 'severity') {
    const copy = list.slice();
    switch (sort) {
      case 'recent':
        return copy.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      case 'name':
        return copy.sort((a, b) => String(a.name).localeCompare(String(b.name)));
      case 'severity':
      default:
        return copy.sort((a, b) =>
          (SS.SEVERITY_RANK[a.severity] ?? 9) - (SS.SEVERITY_RANK[b.severity] ?? 9) ||
          (b.timestamp || 0) - (a.timestamp || 0));
    }
  }

  function severityCounts(secrets) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const s of secrets) if (s.severity in counts) counts[s.severity]++;
    return counts;
  }

  function methodCounts(endpoints) {
    const counts = {};
    for (const e of endpoints) {
      const m = (e.method || 'GET').toUpperCase();
      counts[m] = (counts[m] || 0) + 1;
    }
    return counts;
  }

  // ─── Export ───────────────────────────────────────────────────────────────
  function endpointsCsv(list) {
    const header = ['method', 'url', 'path', 'query', 'params', 'kinds', 'occurrences', 'pages', 'sources', 'firstSeen', 'lastSeen'];
    const rows = list.map(e => [
      e.method, e.url, e.path, endpointQuery(e), (e.params || []).join(' '), (e.kinds || []).join(' '),
      e.occurrences || 1, (e.pageUrls || []).join(' '), (e.sources || []).join(' '),
      e.firstSeen ? new Date(e.firstSeen).toISOString() : '', e.timestamp ? new Date(e.timestamp).toISOString() : '',
    ]);
    return root.UI.toCsv(rows, header);
  }

  function secretsCsv(list) {
    const header = ['severity', 'rule', 'name', 'value', 'occurrences', 'pages', 'sources', 'firstSeen', 'lastSeen'];
    const rows = list.map(s => [
      s.severity, (s.ids || []).join(' '), s.name, s.value, s.occurrences || 1,
      (s.pageUrls || []).join(' '), (s.sources || []).join(' '),
      s.firstSeen ? new Date(s.firstSeen).toISOString() : '', s.timestamp ? new Date(s.timestamp).toISOString() : '',
    ]);
    return root.UI.toCsv(rows, header);
  }

  root.Findings = {
    kindLabel, kindFamily, KIND_FAMILY_LABELS,
    buildMerged, endpointQuery, endpointDisplay, endpointDisplayUrl, toCurl,
    filterEndpoints, filterSecrets, sortEndpoints, sortSecrets, severityCounts, methodCounts,
    endpointsCsv, secretsCsv,
  };
})(globalThis);
