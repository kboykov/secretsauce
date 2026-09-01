// SecretSauce app — DOM helpers and icon set. No innerHTML with dynamic data
// anywhere in the app (AMO-friendly); icons are static SVG parsed via DOMParser.

(function (root) {
  'use strict';

  const $ = id => document.getElementById(id);

  // el('div', { class: 'x', text: 'hi', title: 't', dataset: {a: 1}, on: { click: fn } }, child, ...)
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key === 'on') for (const [evt, fn] of Object.entries(value)) node.addEventListener(evt, fn);
      else if (key === 'style') Object.assign(node.style, value);
      else if (key in node && typeof node[key] !== 'function' && key !== 'title' && key !== 'href') node[key] = value;
      else node.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  // ─── Icons (16×16, stroke = currentColor) ─────────────────────────────────
  const ICONS = {
    search: '<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5 14 14"/>',
    copy: '<rect x="5.5" y="5.5" width="8" height="8" rx="1.5"/><path d="M10.5 5.5V3.5a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"/>',
    check: '<path d="m3 8.5 3 3 7-7"/>',
    external: '<path d="M6.5 3.5H4a1.5 1.5 0 0 0-1.5 1.5v7A1.5 1.5 0 0 0 4 13.5h7a1.5 1.5 0 0 0 1.5-1.5V9.5"/><path d="M9.5 2.5h4v4M13.5 2.5 8 8"/>',
    chevron: '<path d="m6 4 4 4-4 4"/>',
    more: '<circle cx="3.5" cy="8" r="1" fill="currentColor"/><circle cx="8" cy="8" r="1" fill="currentColor"/><circle cx="12.5" cy="8" r="1" fill="currentColor"/>',
    x: '<path d="M4 4l8 8M12 4l-8 8"/>',
    trash: '<path d="M3 4.5h10M6.5 4.5v-1a1 1 0 0 1 1-1h1a1 1 0 0 1 1 1v1M4.5 4.5l.7 8a1 1 0 0 0 1 .9h3.6a1 1 0 0 0 1-.9l.7-8"/>',
    eye: '<path d="M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8Z"/><circle cx="8" cy="8" r="2"/>',
    eyeOff: '<path d="M2.5 2.5l11 11M6.6 6.7A2 2 0 0 0 9.3 9.4M4.2 4.4C2.5 5.6 1.5 8 1.5 8s2.5 4.5 6.5 4.5c1.2 0 2.3-.4 3.2-.9M6.6 3.7c.5-.1.9-.2 1.4-.2 4 0 6.5 4.5 6.5 4.5s-.7 1.3-2 2.5"/>',
    refresh: '<path d="M13 8a5 5 0 1 1-1.5-3.6"/><path d="M13 2.5v3.3H9.7"/>',
    download: '<path d="M8 2.5v8M5 7.5l3 3 3-3"/><path d="M3 13.5h10"/>',
    upload: '<path d="M8 10.5v-8M5 5.5l3-3 3 3"/><path d="M3 13.5h10"/>',
    moon: '<path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7Z"/>',
    sun: '<circle cx="8" cy="8" r="3"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1"/>',
    settings: '<circle cx="8" cy="8" r="2.2"/><path d="M8 1.8v1.7M8 12.5v1.7M1.8 8h1.7M12.5 8h1.7M3.6 3.6l1.2 1.2M11.2 11.2l1.2 1.2M3.6 12.4l1.2-1.2M11.2 4.8l1.2-1.2"/>',
    hosts: '<rect x="2" y="2.5" width="12" height="4.5" rx="1.2"/><rect x="2" y="9" width="12" height="4.5" rx="1.2"/><circle cx="11.5" cy="4.75" r=".8" fill="currentColor"/><circle cx="11.5" cy="11.25" r=".8" fill="currentColor"/>',
    key: '<circle cx="5.5" cy="10.5" r="3"/><path d="M7.6 8.4 13.5 2.5M11 5l2 2M9.5 6.5 11.5 8.5"/>',
    route: '<circle cx="3.5" cy="12.5" r="1.5"/><circle cx="12.5" cy="3.5" r="1.5"/><path d="M5 12.5h4a3 3 0 0 0 0-6H7a3 3 0 0 1 0-6h4"/>',
    dns: '<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12"/>',
    clock: '<circle cx="8" cy="8" r="6"/><path d="M8 4.5V8l2.5 1.5"/>',
    network: '<circle cx="8" cy="3" r="1.6"/><circle cx="3" cy="13" r="1.6"/><circle cx="13" cy="13" r="1.6"/><path d="M8 4.6V8M8 8 3.9 11.6M8 8l4.1 3.6"/>',
    shield: '<path d="M8 1.8 2.8 4v3.7c0 3 2.2 5.4 5.2 6.5 3-1.1 5.2-3.5 5.2-6.5V4L8 1.8Z"/><path d="m5.8 8 1.6 1.6 3-3.2"/>',
    archive: '<path d="M8 2.5A5.5 5.5 0 1 0 13 6.4"/><path d="M8 5v3l2.2 1.6"/><path d="M11 1.5h3v3"/>',
    filter: '<path d="M2 3.5h12L9.5 9v4l-3 1V9L2 3.5Z"/>',
    info: '<circle cx="8" cy="8" r="6"/><path d="M8 7.2v4M8 5v.2"/>',
    warning: '<path d="M8 2.5 14 13H2L8 2.5Z"/><path d="M8 6.5v3M8 11.5v.2"/>',
    ban: '<circle cx="8" cy="8" r="6"/><path d="m4 4 8 8"/>',
    undo: '<path d="M3 6.5h6.5a3.5 3.5 0 0 1 0 7H6"/><path d="M5.5 4 3 6.5 5.5 9"/>',
    code: '<path d="m5.5 4.5-3.5 3.5 3.5 3.5M10.5 4.5l3.5 3.5-3.5 3.5"/>',
    terminal: '<rect x="2" y="3" width="12" height="10" rx="1.5"/><path d="m4.5 6 2.5 2-2.5 2M8.5 10.5h3"/>',
    bolt: '<path d="M9 1.5 3.5 9h4L7 14.5 12.5 7h-4L9 1.5Z"/>',
    layers: '<path d="M8 2 14 5.2 8 8.4 2 5.2 8 2Z"/><path d="m2 8.2 6 3.2 6-3.2M2 11.2l6 3.2 6-3.2"/>',
    sparkle: '<path d="M8 2v3M8 11v3M2 8h3M11 8h3M4.2 4.2l1.5 1.5M10.3 10.3l1.5 1.5M4.2 11.8l1.5-1.5M10.3 5.7l1.5-1.5"/>',
    link: '<path d="M6.5 9.5 9.5 6.5"/><path d="M7 4.5 8.5 3a3 3 0 0 1 4.5 4.5L11.5 9M9 11.5 7.5 13A3 3 0 0 1 3 8.5L4.5 7"/>',
    globe: '<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2a9 9 0 0 1 0 12M8 2a9 9 0 0 0 0 12"/>',
    tag: '<path d="M2.5 2.5h5l6 6-5 5-6-6v-5Z"/><circle cx="5.5" cy="5.5" r="1" fill="currentColor"/>',
    plus: '<path d="M8 3v10M3 8h10"/>',
    minus: '<path d="M3 8h10"/>',
    expand: '<path d="M3 6.5V3h3.5M13 6.5V3H9.5M3 9.5V13h3.5M13 9.5V13H9.5"/>',
    collapse: '<path d="M6.5 3v3.5H3M9.5 3v3.5H13M6.5 13V9.5H3M9.5 13V9.5H13"/>',
    inbox: '<path d="M2.5 9.5 4 3.5h8l1.5 6v3a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1v-3Z"/><path d="M2.5 9.5H6l.8 1.5h2.4l.8-1.5h3.5"/>',
    party: '<path d="M3 13 5.5 5l5.5 5.5L3 13Z"/><path d="M8.5 3.5 9 2M11.5 4.5l1.5-1M12.5 8H14M9.5 6.5l1-1"/>',
  };

  const parser = new DOMParser();

  function icon(name, size = 16, cls = '') {
    const body = ICONS[name] || ICONS.info;
    const markup = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
    const doc = parser.parseFromString(markup, 'image/svg+xml');
    const svg = document.importNode(doc.documentElement, true);
    svg.setAttribute('class', `icon${cls ? ' ' + cls : ''}`);
    svg.setAttribute('aria-hidden', 'true');
    return svg;
  }

  // Icon button: <button class="ibtn" title=…><svg/></button>
  function iconButton(name, { title, cls = '', onClick, label } = {}) {
    const btn = el('button', { class: `ibtn${cls ? ' ' + cls : ''}`, type: 'button', title: title || label || '', 'aria-label': label ? null : (title || name) }, icon(name, 14));
    if (label) btn.append(el('span', { text: label }));
    if (onClick) btn.addEventListener('click', onClick);
    return btn;
  }

  // ─── Feedback ─────────────────────────────────────────────────────────────
  let toastTimer = null;
  function toast(message, kind = 'info') {
    let host = $('toast');
    if (!host) {
      host = el('div', { id: 'toast', class: 'toast', role: 'status' });
      document.body.append(host);
    }
    clear(host);
    host.append(icon(kind === 'error' ? 'warning' : kind === 'success' ? 'check' : 'info', 14), el('span', { text: message }));
    host.className = `toast show ${kind}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => host.classList.remove('show'), 2200);
  }

  function copyText(text, btn, label) {
    return navigator.clipboard.writeText(String(text ?? '')).then(() => {
      if (!btn) { toast('Copied to clipboard', 'success'); return; }
      const original = label ?? btn.dataset.label ?? btn.textContent;
      btn.dataset.label = original;
      btn.classList.add('copied');
      const textNode = btn.querySelector('span');
      if (textNode) textNode.textContent = 'Copied';
      else if (!btn.querySelector('svg')) btn.textContent = 'Copied';
      setTimeout(() => {
        btn.classList.remove('copied');
        if (textNode) textNode.textContent = original;
        else if (!btn.querySelector('svg')) btn.textContent = original;
      }, 1400);
    }).catch(() => toast('Clipboard unavailable', 'error'));
  }

  function download(filename, content, mime = 'text/plain') {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = el('a', { href: url, download: filename });
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // Context snippet with the matched value highlighted.
  function highlight(context, needle) {
    const frag = document.createDocumentFragment();
    const text = String(context || '');
    if (!text) return frag;
    const idx = needle ? text.indexOf(needle) : -1;
    if (idx === -1) {
      frag.append(document.createTextNode(text));
      return frag;
    }
    frag.append(document.createTextNode(text.slice(0, idx)));
    frag.append(el('mark', { class: 'hl', text: text.slice(idx, idx + needle.length) }));
    frag.append(document.createTextNode(text.slice(idx + needle.length)));
    return frag;
  }

  function formatDate(ts) {
    if (!ts) return '—';
    try {
      return new Date(ts).toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    } catch (_) {
      return String(ts);
    }
  }

  function formatNumber(n) {
    return Number(n || 0).toLocaleString();
  }

  function debounce(fn, ms = 120) {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), ms);
    };
  }

  function csvEscape(value) {
    const text = String(value ?? '');
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function toCsv(rows, header) {
    return [header, ...rows].map(r => r.map(csvEscape).join(',')).join('\r\n');
  }

  function maskValue(value) {
    const text = String(value || '');
    if (text.length <= 10) return '•'.repeat(text.length);
    return `${text.slice(0, 4)}${'•'.repeat(Math.min(24, text.length - 8))}${text.slice(-4)}`;
  }

  // Simple popover menu management: [data-menu] buttons toggle #<id>.
  function closeMenus(except) {
    document.querySelectorAll('.menu.open').forEach(m => { if (m !== except) m.classList.remove('open'); });
  }
  document.addEventListener('click', event => {
    if (!event.target.closest('.menu') && !event.target.closest('[data-menu]')) closeMenus();
  });
  document.addEventListener('keydown', event => { if (event.key === 'Escape') closeMenus(); });

  function bindMenu(button, menu) {
    button.addEventListener('click', event => {
      event.stopPropagation();
      const willOpen = !menu.classList.contains('open');
      closeMenus(menu);
      if (willOpen && menu.classList.contains('right')) {
        // Fixed-position flyout so the rail keeps its own scroll without clipping the menu.
        const r = button.getBoundingClientRect();
        menu.style.left = `${Math.round(r.right + 10)}px`;
        menu.style.bottom = `${Math.max(8, Math.round(window.innerHeight - r.bottom))}px`;
      }
      menu.classList.toggle('open', willOpen);
    });
    menu.addEventListener('click', () => menu.classList.remove('open'));
  }

  root.UI = { $, el, clear, icon, iconButton, ICONS, toast, copyText, download, highlight, formatDate, formatNumber, debounce, csvEscape, toCsv, maskValue, bindMenu, closeMenus };
})(globalThis);
