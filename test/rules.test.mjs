import { test } from 'node:test';
import assert from 'node:assert/strict';
import { D, RULES, secretsIn } from './helpers.mjs';

test('every rule has id, name, severity and a JS-compatible regex', () => {
  const ids = new Set();
  for (const rule of RULES) {
    assert.ok(rule.id, 'rule without id');
    assert.ok(!ids.has(rule.id), `duplicate rule id ${rule.id}`);
    ids.add(rule.id);
    assert.ok(rule.name, `${rule.id}: missing name`);
    assert.ok(['critical', 'high', 'medium', 'low'].includes(rule.severity), `${rule.id}: bad severity ${rule.severity}`);
    const src = rule.regex.startsWith('(?i)') ? rule.regex.slice(4) : rule.regex;
    assert.doesNotThrow(() => new RegExp(src, 'gm'), `${rule.id}: invalid regex`);
    assert.ok(!/\(\?[^:=!<]/.test(src), `${rule.id}: contains a non-JS inline flag`);
  }
  assert.equal(D.compileRules(RULES).length, RULES.length, 'some rules failed to compile');
});

test('no rule matches the empty string or trivially short input', () => {
  for (const rule of D.compileRules(RULES)) {
    rule.re.lastIndex = 0;
    assert.equal(rule.re.test(''), false, `${rule.id} matches empty string`);
    rule.re.lastIndex = 0;
    assert.equal(rule.re.test('abc'), false, `${rule.id} matches "abc"`);
  }
});

// Known-format samples (all synthetic) → expected rule id. Literals are split and
// joined at runtime (j) so hosting push-protection scanners do not read them as live keys.
const j = (...parts) => parts.join('');
const SAMPLES = [
  ['aws_access_key_id', j('AKIA', 'IOSFODNN7EXAMPLE1')],
  // Prefixes are joined at runtime so hosting-side push protection does not mistake these synthetic samples for live credentials.
  ['slack_bot_token', j('xox', 'b-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx')],
  ['slack_webhook', j('https://hooks.slack.com/services/', 'T0000000AB/B0000000CD/AbCdEfGhIjKlMnOpQrStUvWx')],
  ['github_fine_grained', `github_pat_${'A'.repeat(22)}_${'b'.repeat(59)}`],
  ['gitlab_token', j('glpa', 't-AbCdEfGhIjKlMnOpQrSt')],
  ['google_api_key', j('AIza', 'SyA-abcdefghijklmnopqrstuvwxyz0123456')],
  ['sendgrid_api_key', `SG.${'a'.repeat(22)}.${'b'.repeat(43)}`],
  ['telegram_bot_token', j('1234', '56789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ')],
  ['jwt_token', `eyJ${'a'.repeat(20)}.eyJ${'b'.repeat(20)}.${'c'.repeat(30)}`],
  ['mongodb_conn_string', j('mong', 'odb+srv://admin:s3cretPassw0rd@cluster0.mongodb.net/db')],
  ['npm_auth_token', `npm_${'A'.repeat(36)}`],
  ['digitalocean_token', `dop_v1_${'a'.repeat(64)}`],
  ['openai_api_key', `sk-${'A1b2C3d4E5f6G7h8I9j0K1l2'}T3BlbkFJ${'W3x4Y5z6A7b8C9d0E1f2G3h4'}`],
  ['anthropic_api_key', `sk-ant-api03-${'Ab1'.repeat(32)}`],
  ['groq_api_key', `gsk_${'aB1'.repeat(17)}c`],
  ['perplexity_api_key', `pplx-${'aB1'.repeat(16)}`],
  ['discord_webhook', `https://discord.com/api/webhooks/123456789012345678/${'aB1'.repeat(22)}`],
  ['sentry_dsn', `https://${'a'.repeat(32)}@o12345.ingest.us.sentry.io/4507`],
  ['doppler_token', `dp.st.${'aB1'.repeat(14)}`],
  ['postman_api_key', `PMAK-${'a'.repeat(24)}-${'b'.repeat(34)}`],
  ['newrelic_user_key', `NRAK-${'A'.repeat(27)}`],
  ['databricks_token', `dapi${'a'.repeat(32)}`],
  ['github_user_server_token', `ghu_${'A'.repeat(36)}`],
  ['age_secret_key', `AGE-SECRET-KEY-1${'Q'.repeat(58)}`],
  ['stripe_webhook_secret', `whsec_${'A'.repeat(32)}`],
  ['pypi_token', `pypi-AgEIcHlwaS5vcmc${'A'.repeat(60)}`],
  ['terraform_cloud_token', `${'A'.repeat(14)}.atlasv1.${'B'.repeat(64)}`],
  ['hubspot_pat', j('pat-', 'na1-12345678-1234-1234-1234-123456789012')],
  ['s3_bucket_url', j('http', 's://my-company-backups.s3.eu-west-1.amazonaws.com/dump.sql')],
  ['firebase_database_url', j('http', 's://my-app-default-rtdb.firebaseio.com')],
];

for (const [expectedId, sample] of SAMPLES) {
  test(`rule ${expectedId} matches its sample`, () => {
    const hits = secretsIn(`const v = "${sample}";`);
    assert.ok(hits.some(h => h.id === expectedId), `expected ${expectedId}, got ${hits.map(h => h.id).join(',') || 'nothing'}`);
  });
}

test('benign frontend code produces no named-rule hits', () => {
  const text = `
    import React from 'react';
    const styles = { color: '#38bdf8', background: 'rgba(0,0,0,.5)' };
    export const API_BASE = '/api/v1';
    const password = 'password';
    const id = '3fa85f64-5717-4562-b3fc-2c963f66afa6';
    fetch(API_BASE + '/users').then(r => r.json());
    const sha = 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';
  `;
  const hits = secretsIn(text);
  assert.deepEqual(hits.map(h => h.id), []);
});
