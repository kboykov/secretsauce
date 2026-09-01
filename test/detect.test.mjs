import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SS, D, secretsIn, endpointsIn } from './helpers.mjs';

// ─── hostname helpers ───────────────────────────────────────────────────────
test('getRootDomain handles multi-label public suffixes', () => {
  assert.equal(SS.getRootDomain('app.example.com'), 'example.com');
  assert.equal(SS.getRootDomain('www.shop.example.co.uk'), 'example.co.uk');
  assert.equal(SS.getRootDomain('foo.github.io'), 'foo.github.io');
  assert.equal(SS.getRootDomain('localhost'), 'localhost');
  assert.equal(SS.getRootDomain('10.0.0.1'), '10.0.0.1');
});

test('isSameSite respects includeSubdomains', () => {
  assert.equal(SS.isSameSite('api.example.com', 'www.example.com', true), true);
  assert.equal(SS.isSameSite('api.example.com', 'www.example.com', false), false);
  assert.equal(SS.isSameSite('example.com', 'www.example.com', true), true);
  assert.equal(SS.isSameSite('notexample.com', 'www.example.com', true), false);
  assert.equal(SS.isSameSite('evil-example.com', 'example.com', true), false);
});

test('isHostExcluded supports exact and wildcard rules', () => {
  const settings = { excludedHosts: ['bank.example', '*.internal.corp'] };
  assert.equal(SS.isHostExcluded('bank.example', settings), true);
  assert.equal(SS.isHostExcluded('www.bank.example', settings), false);
  assert.equal(SS.isHostExcluded('git.internal.corp', settings), true);
  assert.equal(SS.isHostExcluded('internal.corp', settings), true);
  assert.equal(SS.isHostExcluded('example.com', settings), false);
});

// ─── secrets ────────────────────────────────────────────────────────────────
test('detects an AWS access key id', () => {
  const hits = secretsIn('const cfg = { accessKeyId: "AKIAIOSFODNN7EXAMPLE1" };');
  assert.ok(hits.some(h => h.id === 'aws_access_key_id'), JSON.stringify(hits));
});

test('detects GitHub and Stripe style tokens', () => {
  const text = `
    const gh = "ghp_${'a'.repeat(30)}Zz1234";
    const stripe = "sk_live_${'4eC39HqLyjWDarjtT1zdp7dc'}";
  `;
  const ids = new Set(secretsIn(text).map(h => h.id));
  assert.ok(ids.has('github_classic_pat'));
  assert.ok(ids.has('stripe_live_secret'));
});

test('OpenAI project keys are recognised and Anthropic keys are not double-counted', () => {
  const openai = `sk-proj-${'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2'}T3BlbkFJ${'W3x4Y5z6A7b8C9d0E1f2G3h4I5j6K7l8'}`;
  const anthropic = `sk-ant-api03-${'x'.repeat(0)}${'Ab1'.repeat(32)}`;
  const hits = secretsIn(`a="${openai}"; b="${anthropic}";`);
  const openaiHits = hits.filter(h => h.value === openai).map(h => h.id);
  const anthropicHits = hits.filter(h => h.value === anthropic).map(h => h.id);
  assert.deepEqual(openaiHits, ['openai_api_key']);
  assert.deepEqual(anthropicHits, ['anthropic_api_key']);
});

test('placeholders and variable-name shapes are filtered', () => {
  assert.equal(D.isSecretFP('YOUR_API_KEY_HERE_123456'), true);
  assert.equal(D.isSecretFP('xxxxxxxxxxxxxxxx'), true);
  assert.equal(D.isSecretFP('${process.env.KEY}'), true);
  assert.equal(D.isSecretFP('sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'), true);
  assert.equal(D.isSecretFP('AKIAIOSFODNN7EXAMPLE1'), false);
});

test('secret detection dedupes across repeated calls via the known set', () => {
  const known = new Set();
  const text = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";';
  const first = D.detectSecrets(text, 'a.js', D.compileRules([{ id: 'gh', name: 'GH', severity: 'high', regex: 'ghp_[A-Za-z0-9]{36}' }]), { known });
  const second = D.detectSecrets(text, 'a.js', D.compileRules([{ id: 'gh', name: 'GH', severity: 'high', regex: 'ghp_[A-Za-z0-9]{36}' }]), { known });
  assert.equal(first.length, 1);
  assert.equal(second.length, 0);
});

test('high-entropy detector skips integrity hashes and ids but keeps random tokens', () => {
  const token = 'q7Zp2Lm9Xk4Vb8Nr3Tw6Yh1Jd5Fg0Sa'; // mixed case + digits, 32 chars
  const text = `
    <script integrity="sha384-Rm4Gz7Qx9Lp2Vt6Nk1Wc3Yb8Hd5Jf0Sa7Ee2Tq9Ui4Oo6Pp1"></script>
    const userId = "9Lp2Vt6Nk1Wc3Yb8Hd5Jf0Sa7Ee2Tq9U";
    const apiKey = "${token}";
  `;
  const hits = D.detectHighEntropySecrets(text, 'x.js');
  const values = hits.map(h => h.value);
  assert.ok(values.includes(token), values.join(','));
  assert.ok(!values.some(v => v.startsWith('sha384')));
  assert.ok(!values.includes('9Lp2Vt6Nk1Wc3Yb8Hd5Jf0Sa7Ee2Tq9U'));
});

// ─── endpoints ──────────────────────────────────────────────────────────────
test('fetch/axios/xhr calls are detected with methods', () => {
  const text = `
    fetch("/api/v1/users?page=2");
    axios.post('/api/v1/login', { body: { username: u, password: p } });
    xhr.open("DELETE", "/api/v1/items/42");
    const socket = new WebSocket("wss://example.com/live");
  `;
  const eps = endpointsIn(text);
  const byPath = Object.fromEntries(eps.map(e => [e.path, e]));
  assert.equal(byPath['/api/v1/users'].method, 'GET');
  assert.deepEqual(byPath['/api/v1/users'].params, ['page']);
  assert.equal(byPath['/api/v1/login'].method, 'POST');
  assert.ok(byPath['/api/v1/login'].params.includes('username'));
  assert.equal(byPath['/api/v1/items/42'].method, 'DELETE');
  assert.equal(byPath['/live'].kind, 'websocket');
  assert.equal(byPath['/live'].url, 'wss://example.com/live');
});

test('template literal paths are normalised to {param} placeholders', () => {
  const text = 'fetch(`/api/users/${user.id}/orders?limit=${n}`);';
  const eps = endpointsIn(text);
  assert.equal(eps.length, 1);
  assert.equal(eps[0].path, '/api/users/{id}/orders');
  assert.equal(eps[0].url, 'https://example.com/api/users/{id}/orders?limit={n}');
  assert.equal(eps[0].templated, true);
});

test('off-site URLs and static assets are ignored', () => {
  const text = `
    fetch("https://www.googletagmanager.com/gtm.js?id=GTM-1");
    const img = "/images/logo.png";
    const css = "/static/app.css";
    const api = "https://api.example.com/v2/profile";
  `;
  const eps = endpointsIn(text);
  const urls = eps.map(e => e.url);
  assert.deepEqual(urls, ['https://api.example.com/v2/profile']);
});

test('subdomain scope can be disabled', () => {
  const eps = endpointsIn('fetch("https://api.example.com/v2/profile")', { includeSubdomains: false });
  assert.equal(eps.length, 0);
});

test('endpoint false-positive filter', () => {
  assert.equal(D.isEndpointFP('/', 'path'), true);
  assert.equal(D.isEndpointFP('/json', 'path'), true);
  assert.equal(D.isEndpointFP('/1.2.3', 'path'), true);
  assert.equal(D.isEndpointFP('/_next/static/chunk.js', 'fetch'), true);
  assert.equal(D.isEndpointFP('/api/v1/users', 'path'), false);
  assert.equal(D.isEndpointFP('/login', 'dom'), false);
});

test('resolveCandidate handles relative candidates from DOM attributes', () => {
  const ctx = { pageUrl: 'https://example.com/app/index.html', pageHost: 'example.com', kind: 'dom', source: 'https://example.com/app/index.html' };
  const ep = D.resolveCandidate('../api/search?q=1', ctx);
  assert.equal(ep.url, 'https://example.com/api/search?q=1');
  assert.equal(ep.path, '/api/search');
  assert.equal(D.resolveCandidate('javascript:void(0)', ctx), null);
  assert.equal(D.resolveCandidate('https://cdn.other.com/x', ctx), null);
});

// ─── host log merge ─────────────────────────────────────────────────────────
test('mergeSecrets aggregates occurrences, pages and severity', () => {
  const t1 = 1000, t2 = 2000;
  const first = SS.mergeSecrets([], [{ id: 'r1', name: 'Rule', severity: 'medium', value: 'abc', source: 's1', context: 'c1' }], 'https://h/p1', t1);
  const second = SS.mergeSecrets(first, [{ id: 'r2', name: 'Rule2', severity: 'critical', value: 'abc', source: 's2', context: 'c2' }], 'https://h/p2', t2);
  assert.equal(second.length, 1);
  assert.equal(second[0].occurrences, 2);
  assert.equal(second[0].severity, 'critical');
  assert.deepEqual(second[0].pageUrls, ['https://h/p1', 'https://h/p2']);
  assert.deepEqual(second[0].sources, ['s1', 's2']);
  assert.equal(second[0].firstSeen, t1);
  assert.equal(second[0].lastSeen, t2);
});

test('mergeEndpoints keys on method + url and collects params', () => {
  const log = SS.mergeEndpoints([], [
    { method: 'get', path: '/api/a', query: 'x=1', params: ['x'], kind: 'fetch', source: 's' },
    { method: 'GET', path: '/api/a', query: 'y=2', params: ['y'], kind: 'dom', source: 's2' },
  ], 'https://example.com/page', 5);
  // different query strings → different URLs → two entries
  assert.equal(log.length, 2);
  const merged = SS.mergeEndpoints(log, [{ method: 'GET', url: 'https://example.com/api/a?x=1', params: ['z'], kind: 'xhr', source: 's3' }], 'https://example.com/other', 9);
  const entry = merged.find(e => e.url === 'https://example.com/api/a?x=1');
  assert.equal(entry.occurrences, 2);
  assert.deepEqual(entry.params.sort(), ['x', 'z']);
  assert.deepEqual(entry.kinds, ['fetch', 'xhr']);
});
