// Loads the classic-script modules into globalThis for Node tests.
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function run(file) {
  const code = fs.readFileSync(path.join(ROOT, 'src', file), 'utf8');
  vm.runInThisContext(code, { filename: file });
}

if (!globalThis.SS) run('shared.js');
if (!globalThis.SSDetect) run('detect.js');

export const SS = globalThis.SS;
export const D = globalThis.SSDetect;
export const RULES = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'rules', 'secrets.json'), 'utf8'));
export const compiled = D.compileRules(RULES);

export function secretsIn(text, source = 'https://example.com/app.js') {
  return D.detectSecrets(text, source, compiled);
}

export function endpointsIn(text, opts = {}) {
  return D.detectEndpoints(text, 'https://example.com/app.js', {
    pageUrl: 'https://example.com/home',
    pageHost: 'example.com',
    includeSubdomains: true,
    ...opts,
  });
}
