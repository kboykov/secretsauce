// Dev-only: renders the app preview in headless Chrome and saves screenshots to
// dev/screenshots/. Uses the Playwright package from node_modules or the npx cache.
//   node dev/screenshot.mjs [tab ...]      (default: endpoints secrets hosts settings wayback)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createServer } from './preview-server.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'dev', 'screenshots');
fs.mkdirSync(OUT, { recursive: true });

function loadPlaywright() {
  const require = createRequire(import.meta.url);
  if (process.env.PW_PATH) return require(process.env.PW_PATH);
  for (const name of ['playwright', 'playwright-core']) {
    try { return require(name); } catch (_) {}
  }
  const npx = path.join(os.homedir(), '.npm', '_npx');
  if (fs.existsSync(npx)) {
    for (const dir of fs.readdirSync(npx)) {
      for (const name of ['playwright', 'playwright-core']) {
        const candidate = path.join(npx, dir, 'node_modules', name);
        if (fs.existsSync(candidate)) return require(candidate);
      }
    }
  }
  throw new Error('playwright not found — run: npm i -D playwright  (or npx -y playwright --version once)');
}

const { chromium } = loadPlaywright();
const tabs = process.argv.slice(2).length ? process.argv.slice(2) : ['endpoints', 'secrets', 'hosts', 'settings', 'wayback'];

const server = createServer();
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const errors = [];

async function shoot(name, query, tab, { width = 1440, height = 900, action } = {}) {
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
  page.on('pageerror', err => errors.push(`${name}: ${err.message}`));
  page.on('console', msg => { if (msg.type() === 'error') errors.push(`${name}: console ${msg.text()}`); });
  await page.goto(`http://127.0.0.1:${port}/preview.html?tab=7&${query}#${tab}`);
  await page.waitForTimeout(700);
  if (action) await action(page);
  await page.waitForTimeout(250);
  await page.screenshot({ path: path.join(OUT, `${name}.png`) });
  await page.close();
  console.log('✔', name);
}

for (const tab of tabs) {
  await shoot(`${tab}-dark`, 'scenario=full&theme=dark', tab, {
    action: async page => {
      if (tab === 'endpoints') await page.locator('#ep-list .card').nth(1).locator('.card-row').click();
      if (tab === 'secrets') await page.locator('#sec-list .card').nth(0).locator('.card-row').click();
    },
  });
}
await shoot('endpoints-light', 'scenario=full&theme=light', 'endpoints', {
  action: async page => { await page.locator('#ep-list .card').nth(0).locator('.card-row').click(); },
});
await shoot('secrets-light', 'scenario=full&theme=light', 'secrets');
await shoot('scanning-dark', 'scenario=scanning&theme=dark', 'endpoints');
await shoot('empty-dark', 'scenario=empty&theme=dark', 'secrets');
await shoot('narrow-dark', 'scenario=full&theme=dark', 'endpoints', { width: 960, height: 760 });
await shoot('rail-closed-dark', 'scenario=full&theme=dark', 'secrets', {
  action: async page => { await page.locator('#btn-drawer').click(); await page.waitForTimeout(300); await page.mouse.move(700, 400); await page.waitForTimeout(300); },
});
await shoot('rail-peek-dark', 'scenario=full&theme=dark', 'endpoints', {
  action: async page => { await page.locator('#btn-drawer').click(); await page.waitForTimeout(300); await page.mouse.move(700, 400); await page.waitForTimeout(300); await page.locator('#btn-drawer').hover(); const b = await page.locator('#btn-drawer').boundingBox(); await page.mouse.move(b.x + 21, b.y + 21); await page.waitForTimeout(350); },
});
await shoot('mobile-dark', 'scenario=full&theme=dark', 'endpoints', { width: 390, height: 780 });
await shoot('export-menu-dark', 'scenario=full&theme=dark', 'endpoints', {
  action: async page => { await page.locator('#btn-export').click(); },
});

await browser.close();
server.close();

if (errors.length) {
  console.error('\nPage errors:');
  for (const e of errors) console.error(' ✖', e);
  process.exit(1);
}
