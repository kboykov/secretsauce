#!/usr/bin/env node
// SecretSauce build script — zero dependencies.
//
//   node build.mjs                 build dist/chrome and dist/firefox (+ zips)
//   node build.mjs --watch         rebuild whenever src/ or manifests/ change
//   node build.mjs --set-version 1.5.0
//                                  bump the version in both manifests, then build
//
// `src/` is itself a loadable Chrome extension (no build needed while developing).
// The Firefox build swaps in manifests/firefox.json and drops Chrome-only files.

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(ROOT, 'src');
const DIST = path.join(ROOT, 'dist');
const FIREFOX_MANIFEST = path.join(ROOT, 'manifests', 'firefox.json');
const CHROME_MANIFEST = path.join(SRC, 'manifest.json');

const CHROME_ONLY = new Set(['rules/frame_rules.json']);
const SKIP_ALWAYS = new Set(['.DS_Store', 'Thumbs.db']);

const args = process.argv.slice(2);
const watch = args.includes('--watch');
const versionIdx = args.indexOf('--set-version');

// ─── helpers ────────────────────────────────────────────────────────────────
function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

function walk(dir, base = dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_ALWAYS.has(entry.name)) continue;
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(abs, base, out);
    else out.push(path.relative(base, abs).split(path.sep).join('/'));
  }
  return out;
}

function rmrf(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

function copyTree(files, from, to, { skip = new Set() } = {}) {
  for (const rel of files) {
    if (skip.has(rel)) continue;
    const dest = path.join(to, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(from, rel), dest);
  }
}

// ─── minimal zip writer (deflate) ───────────────────────────────────────────
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
  const time = ((date.getHours() & 31) << 11) | ((date.getMinutes() & 63) << 5) | ((date.getSeconds() >> 1) & 31);
  const day = (((date.getFullYear() - 1980) & 127) << 9) | (((date.getMonth() + 1) & 15) << 5) | (date.getDate() & 31);
  return { time, day };
}

function zipDirectory(dir, zipFile) {
  const files = walk(dir).sort();
  const locals = [];
  const centrals = [];
  let offset = 0;
  const now = dosDateTime(new Date());

  for (const rel of files) {
    const data = fs.readFileSync(path.join(dir, rel));
    const name = Buffer.from(rel, 'utf8');
    const deflated = zlib.deflateRawSync(data, { level: 9 });
    const useDeflate = deflated.length < data.length;
    const payload = useDeflate ? deflated : data;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(data);

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);           // version needed
    local.writeUInt16LE(0x0800, 6);       // flags: UTF-8 names
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(now.time, 10);
    local.writeUInt16LE(now.day, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);         // version made by
    central.writeUInt16LE(20, 6);         // version needed
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(now.time, 12);
    central.writeUInt16LE(now.day, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(payload.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);         // extra
    central.writeUInt16LE(0, 32);         // comment
    central.writeUInt16LE(0, 34);         // disk
    central.writeUInt16LE(0, 36);         // internal attrs
    central.writeUInt32LE(0, 38);         // external attrs
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);

    locals.push(local, payload);
    centrals.push(central);
    offset += local.length + payload.length;
  }

  const centralSize = centrals.reduce((n, b) => n + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  fs.writeFileSync(zipFile, Buffer.concat([...locals, ...centrals, end]));
}

// ─── build ──────────────────────────────────────────────────────────────────
function validate(chromeManifest, firefoxManifest) {
  const problems = [];
  if (chromeManifest.version !== firefoxManifest.version) {
    problems.push(`version mismatch: chrome ${chromeManifest.version} vs firefox ${firefoxManifest.version}`);
  }
  const srcFiles = new Set(walk(SRC));
  const referenced = new Set();
  for (const m of [chromeManifest, firefoxManifest]) {
    for (const cs of m.content_scripts || []) for (const f of cs.js || []) referenced.add(f);
    for (const f of m.background?.scripts || []) referenced.add(f);
    if (m.background?.service_worker) referenced.add(m.background.service_worker);
    for (const r of m.declarative_net_request?.rule_resources || []) referenced.add(r.path);
    for (const icon of Object.values(m.icons || {})) referenced.add(icon);
  }
  for (const f of referenced) if (!srcFiles.has(f)) problems.push(`manifest references missing file: ${f}`);
  const html = fs.readFileSync(path.join(SRC, 'app.html'), 'utf8');
  for (const m of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
    const ref = m[1];
    if (/^(?:https?:|#|data:)/.test(ref)) continue;
    if (!srcFiles.has(ref)) problems.push(`app.html references missing file: ${ref}`);
  }
  if (problems.length) {
    for (const p of problems) console.error('  ✖ ' + p);
    throw new Error('validation failed');
  }
}

function build() {
  const started = Date.now();
  const chromeManifest = readJson(CHROME_MANIFEST);
  const firefoxManifest = readJson(FIREFOX_MANIFEST);
  validate(chromeManifest, firefoxManifest);

  const files = walk(SRC);
  const version = chromeManifest.version;

  rmrf(DIST);
  fs.mkdirSync(DIST, { recursive: true });

  // Chrome: verbatim copy of src/
  const chromeDir = path.join(DIST, 'chrome');
  copyTree(files, SRC, chromeDir);

  // Firefox: swap manifest, drop Chrome-only resources
  const firefoxDir = path.join(DIST, 'firefox');
  copyTree(files, SRC, firefoxDir, { skip: new Set([...CHROME_ONLY, 'manifest.json']) });
  writeJson(path.join(firefoxDir, 'manifest.json'), firefoxManifest);

  zipDirectory(chromeDir, path.join(DIST, `secretsauce-chrome-${version}.zip`));
  zipDirectory(firefoxDir, path.join(DIST, `secretsauce-firefox-${version}.zip`));

  console.log(`✔ built v${version} → dist/chrome, dist/firefox (+ zips) in ${Date.now() - started}ms`);
}

if (versionIdx !== -1) {
  const next = args[versionIdx + 1];
  if (!/^\d+\.\d+\.\d+$/.test(next || '')) {
    console.error('--set-version expects x.y.z');
    process.exit(1);
  }
  for (const file of [CHROME_MANIFEST, FIREFOX_MANIFEST]) {
    const m = readJson(file);
    m.version = next;
    writeJson(file, m);
  }
  console.log(`✔ version set to ${next}`);
}

try {
  build();
} catch (err) {
  console.error('✖ build failed:', err.message);
  if (!watch) process.exit(1);
}

if (watch) {
  let timer = null;
  const trigger = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      try { build(); } catch (err) { console.error('✖ build failed:', err.message); }
    }, 150);
  };
  fs.watch(SRC, { recursive: true }, trigger);
  fs.watch(path.dirname(FIREFOX_MANIFEST), trigger);
  console.log('… watching src/ and manifests/ for changes (Ctrl+C to stop)');
}
