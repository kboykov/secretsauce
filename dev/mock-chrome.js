// Dev-only: a minimal in-memory `chrome` API so src/app.html can be opened in a
// plain browser tab (dev/preview.html) for design work and screenshots.
(function () {
  const params = new URLSearchParams(location.search);
  const scenario = params.get('scenario') || 'full';
  const now = Date.now();
  const host = params.get('host') || 'app.acme-corp.com';
  const pageUrl = `https://${host}/dashboard/settings`;

  const listeners = { storage: [], runtime: [] };
  const store = {};
  let rules = [];

  function rnd(seed) { let x = seed; return () => (x = (x * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff; }
  const r = rnd(42);
  const pick = arr => arr[Math.floor(r() * arr.length)];

  // ── sample data (synthetic; prefixes joined at runtime so push protection does not flag them) ──
  const paths = ['/api/v1/users', '/api/v1/users/{id}', '/api/v2/orders?status=open&page=2', '/graphql', '/api/auth/login', '/api/auth/refresh',
    '/api/v1/invoices/{invoiceId}/pdf', '/rest/products?category=shoes&sort=price', '/api/v1/admin/users', '/api/internal/feature-flags',
    '/api/v1/search?q=test&limit=20', '/api/v1/uploads', '/api/v1/webhooks', '/api/v1/settings/notifications', '/health', '/metrics',
    '/api/v1/teams/{teamId}/members', '/api/v1/reports/export?format=csv', '/oauth/token', '/api/v1/payments/intent'];
  const methods = ['GET', 'GET', 'GET', 'POST', 'POST', 'PUT', 'PATCH', 'DELETE'];
  const kinds = ['fetch', 'axios', 'xhr', 'dom', 'inline', 'network-fetch', 'network-xmlhttprequest', 'path', 'property', 'websocket'];
  const sources = [`https://${host}/static/js/main.8f3a1c.js`, `https://${host}/static/js/vendor.2b9d.js`, pageUrl, `https://cdn.${host.split('.').slice(-2).join('.')}/app/chunk-settings.js`];

  const liveEndpoints = paths.map((p, i) => {
    const method = i === 1 ? 'GET' : i === 4 ? 'POST' : i === 8 ? 'DELETE' : pick(methods);
    const [path, query = ''] = p.split('?');
    const kind = i === 19 ? 'websocket' : pick(kinds);
    const urlHost = i % 5 === 0 ? `api.${host.split('.').slice(-2).join('.')}` : host;
    return {
      path, query, method, params: query ? query.split('&').map(x => x.split('=')[0]) : (method === 'POST' ? ['email', 'password'] : []),
      kind, source: pick(sources), templated: /\{/.test(path),
      url: `${kind === 'websocket' ? 'wss' : 'https'}://${urlHost}${path}${query ? '?' + query : ''}`,
      rawMatch: path,
      context: `  async function load${i}() {\n    const res = await fetch("${path}${query ? '?' + query : ''}", {\n      method: "${method}",\n      headers: { Authorization: "Bearer " + token }\n    });\n    return res.json();\n  }`,
    };
  });

  const liveSecrets = [
    { id: 'aws_access_key_id', name: 'AWS Access Key ID', severity: 'critical', value: 'AKIAIOSFODNN7EXAMPLE', source: sources[0] },
    { id: 'stripe_live_secret', name: 'Stripe Live Secret Key', severity: 'critical', value: ['sk_live_', '51H8f3aKc9dQ2Lm7Np4Rs6Tu8Vw0Xy2Za4'].join(''), source: sources[0] },
    { id: 'github_classic_pat', name: 'GitHub Classic Personal Access Token', severity: 'critical', value: 'ghp_' + 'aB3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6', source: sources[3] },
    { id: 'google_api_key', name: 'Google API Key', severity: 'high', value: ['AIza', 'SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY'].join(''), source: pageUrl },
    { id: 'jwt_token', name: 'JSON Web Token (JWT)', severity: 'high', value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.dQw4w9WgXcQ_x7Kz9Lm2Np5Rs8Tu1Vw4Xy7Za0Bc3', source: sources[1] },
    { id: 'slack_webhook', name: 'Slack Incoming Webhook URL', severity: 'high', value: ['https://hooks.slack.com/services/', 'T0000000AB/B0000000CD/AbCdEfGhIjKlMnOpQrStUvWx'].join(''), source: sources[1] },
    { id: 'sentry_dsn', name: 'Sentry DSN', severity: 'low', value: 'https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o12345.ingest.us.sentry.io/4507', source: sources[0] },
    { id: 'high-entropy', name: 'High Entropy String', severity: 'medium', value: 'q7Zp2Lm9Xk4Vb8Nr3Tw6Yh1Jd5Fg0SaQ', source: sources[2] },
    { id: 'generic_api_key', name: 'Generic API Key (contextual)', severity: 'medium', value: 'k9Lm2Np5Rs8Tu1Vw4Xy7Za0Bc3De6Fg9Hj', source: sources[3] },
    { id: 'stripe_publishable_key', name: 'Stripe Publishable Key (client-side)', severity: 'low', value: ['pk_live_', '51H8f3aKc9dQ2Lm7Np4Rs6Tu8Vw0Xy2Za4'].join(''), source: pageUrl },
  ].map((s, i) => ({ ...s, timestamp: now - i * 60_000, context: `    const config = {\n      apiKey: "${s.value}",\n      region: "eu-west-1",\n      debug: false\n    };` }));

  const HOST_LOG_PREFIX = 'findings_log_host_v1_';
  function hostLog(hostname, secretsN, endpointsN, ageMin) {
    const log = { version: 1, hostname, updatedAt: now - ageMin * 60_000, secrets: [], endpoints: [] };
    for (let i = 0; i < secretsN; i++) {
      const s = liveSecrets[i % liveSecrets.length];
      log.secrets.push({ key: s.value + i, value: s.value + (i ? i : ''), name: s.name, severity: s.severity, ids: [s.id], names: [s.name], sources: [s.source], pageUrls: [`https://${hostname}/p${i}`], contexts: [s.context], firstSeen: now - 86_400_000 * 3, lastSeen: now - ageMin * 60_000, occurrences: 1 + i });
    }
    for (let i = 0; i < endpointsN; i++) {
      const e = liveEndpoints[i % liveEndpoints.length];
      log.endpoints.push({ key: `${e.method}:${e.url}`, method: e.method, url: e.url.replace(host, hostname), path: e.path, host: hostname, querySamples: [e.query], params: e.params, kinds: [e.kind], sources: [e.source], pageUrls: [`https://${hostname}/p${i % 4}`], contexts: [e.context], firstSeen: now - 86_400_000 * 2, lastSeen: now - ageMin * 60_000, occurrences: 1 + (i % 7) });
    }
    log.stats = { uniqueSecrets: log.secrets.length, uniqueEndpoints: log.endpoints.length, pageCount: 4, updatedAt: log.updatedAt };
    return log;
  }

  if (scenario !== 'empty') {
    store[`${HOST_LOG_PREFIX}${encodeURIComponent(host)}`] = hostLog(host, 4, 12, 35);
    store[`${HOST_LOG_PREFIX}shop.example.co.uk`] = hostLog('shop.example.co.uk', 2, 31, 240);
    store[`${HOST_LOG_PREFIX}staging.internal.dev`] = hostLog('staging.internal.dev', 7, 88, 1500);
    store[`${HOST_LOG_PREFIX}docs.acme-corp.com`] = hostLog('docs.acme-corp.com', 0, 9, 4000);
    store['scan_7'] = { url: pageUrl, hostname: host, secrets: liveSecrets, endpoints: liveEndpoints, complete: scenario !== 'scanning', scanning: scenario === 'scanning', scanTime: now - 4000, progress: { sourcesTotal: 41, sourcesDone: scenario === 'scanning' ? 17 : 41 } };
  }
  store['settings_v1'] = { theme: params.get('theme') || 'dark' };

  const lastError = undefined;
  const chrome = {
    runtime: {
      lastError,
      getManifest: () => ({ version: '1.4.0-dev' }),
      getURL: p => `../src/${p}`,
      sendMessage(msg, cb) {
        setTimeout(() => {
          if (msg.type === 'GET_RULES') cb({ rules });
          else if (msg.type === 'INJECT_CONTENT') cb({ ok: true });
          else cb({ ok: true });
        }, 30);
      },
      onMessage: { addListener() {} },
    },
    storage: {
      local: {
        get(keys, cb) {
          setTimeout(() => {
            if (keys === null || keys === undefined) return cb({ ...store });
            const list = Array.isArray(keys) ? keys : [keys];
            const out = {};
            for (const k of list) if (k in store) out[k] = store[k];
            cb(out);
          }, 10);
        },
        set(values, cb) {
          const changes = {};
          for (const [k, v] of Object.entries(values)) { changes[k] = { oldValue: store[k], newValue: v }; store[k] = v; }
          setTimeout(() => { cb && cb(); listeners.storage.forEach(fn => fn(changes, 'local')); }, 5);
        },
        remove(keys, cb) {
          const list = Array.isArray(keys) ? keys : [keys];
          const changes = {};
          for (const k of list) { changes[k] = { oldValue: store[k] }; delete store[k]; }
          setTimeout(() => { cb && cb(); listeners.storage.forEach(fn => fn(changes, 'local')); }, 5);
        },
      },
      onChanged: { addListener(fn) { listeners.storage.push(fn); } },
    },
    tabs: {
      get(id, cb) { setTimeout(() => cb(id === 7 ? { id: 7, url: pageUrl, index: 0 } : undefined), 5); },
      sendMessage(id, msg, cb) {
        setTimeout(() => {
          if (id !== 7 || scenario === 'stored') { chrome.runtime.lastError = { message: 'no receiver' }; cb(undefined); chrome.runtime.lastError = undefined; return; }
          if (msg.type === 'GET_RESULTS') cb(store['scan_7']);
          else cb({ ok: true });
        }, 20);
      },
      create(opts) { window.open(opts.url, '_blank'); },
      update() {},
      query(q, cb) { cb([]); },
    },
    windows: { update() {} },
  };
  window.chrome = chrome;

  // Mock the Wayback CDX API so the table can be previewed offline.
  const realFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    if (url.startsWith('https://web.archive.org/')) {
      const rows = [['original', 'mimetype', 'timestamp', 'endtimestamp', 'groupcount', 'uniqcount']];
      const mimes = ['text/html', 'text/html', 'application/javascript', 'application/json', 'text/css', 'image/png', 'application/pdf', 'text/plain'];
      const wbPaths = ['/', '/login', '/api/v1/users', '/api/v2/config.json', '/static/js/app.min.js', '/robots.txt', '/backup/db.sql.zip', '/.env', '/admin/', '/docs/whitepaper.pdf', '/assets/logo.png', '/sitemap.xml', '/wp-admin/', '/api/internal/debug', '/swagger.json'];
      for (let i = 0; i < 260; i++) {
        const p = wbPaths[i % wbPaths.length] + (i >= wbPaths.length ? `?v=${i}` : '');
        const y = 2014 + (i % 11);
        rows.push([`https://${host}${p}`, mimes[i % mimes.length], `${y}0${1 + (i % 9)}1${i % 9}120000`, `${y + 1}0${1 + (i % 9)}0${i % 9}120000`, String(1 + (i * 7) % 90), String(1 + i % 12)]);
      }
      return Promise.resolve(new Response(JSON.stringify(rows), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    }
    return realFetch(input, init);
  };

  fetch('../src/rules/secrets.json').then(r => r.json()).then(j => { rules = j; }).catch(() => {});
})();
