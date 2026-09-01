// SecretSauce app — recon tabs: embedded third-party tools and the Wayback
// Machine CDX table.

(function (root) {
  'use strict';

  const { $, el, clear, icon, iconButton, copyText, download, toast, formatNumber, debounce } = root.UI;
  const SS = root.SS;
  const Render = root.Render;

  const IFRAME_TABS = ['dns', 'history', 'subdomains', 'webcheck'];

  let currentHost = '';
  const wb = { rows: [], host: '', loading: false, error: '' };

  function toolUrl(tab, host) {
    if (!host) return '';
    switch (tab) {
      case 'dns': return `https://securitytrails.com/domain/${host}/dns`;
      case 'history': return `https://securitytrails.com/domain/${host}/history/a`;
      case 'subdomains': return `https://securitytrails.com/list/apex_domain/${SS.getRootDomain(host)}`;
      case 'webcheck': return `https://web-check.xyz/check/${host}`;
      default: return '';
    }
  }

  function setHost(host) {
    const next = String(host || '').toLowerCase();
    if (next === currentHost) return;
    currentHost = next;
    for (const tab of IFRAME_TABS) {
      const frame = $(`iframe-${tab}`);
      if (frame) { frame.removeAttribute('src'); frame.dataset.loadedHost = ''; }
    }
    if (wb.host !== next) { wb.rows = []; wb.host = ''; wb.error = ''; }
  }

  // ─── Embedded tool tabs ───────────────────────────────────────────────────
  function showIframeTab(tab) {
    const frame = $(`iframe-${tab}`);
    const placeholder = $(`placeholder-${tab}`);
    const link = $(`recon-link-${tab}`);
    const url = toolUrl(tab, currentHost);
    if (!frame) return;

    if (!url) {
      Render.emptyState(placeholder, { icon: 'globe', title: 'No host in context', sub: 'Open SecretSauce from a page tab to load recon data for its hostname.' });
      frame.classList.add('hidden');
      if (link) { link.textContent = 'n/a'; link.removeAttribute('href'); }
      return;
    }
    placeholder.classList.add('hidden');
    frame.classList.remove('hidden');
    if (link) { link.textContent = url; link.href = url; }
    if (frame.dataset.loadedHost !== currentHost) {
      frame.src = url;
      frame.dataset.loadedHost = currentHost;
    }
  }

  function reloadIframeTab(tab) {
    const frame = $(`iframe-${tab}`);
    if (frame && frame.src) frame.src = frame.src;
  }

  // ─── Wayback Machine ──────────────────────────────────────────────────────
  function formatWbTs(ts) {
    if (!ts || ts.length < 8) return ts || 'n/a';
    return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
  }

  function mimeFamily(mime) {
    const m = String(mime || '');
    if (m === 'text/html' || m === 'application/xhtml+xml') return 'html';
    if (/javascript|ecmascript/.test(m)) return 'js';
    if (/json|xml|yaml|csv|plain/.test(m)) return 'data';
    if (/^image\//.test(m)) return 'img';
    if (/css/.test(m)) return 'css';
    if (/pdf|zip|octet|msword|excel|powerpoint|gzip|tar/.test(m)) return 'file';
    return 'other';
  }

  const INTERESTING_RE = /\.(?:json|xml|yaml|yml|env|bak|old|sql|log|conf|config|ini|zip|tar|gz|7z|rar|txt|csv|xls[x]?|doc[x]?|pdf|map)(?:\?|$)|\/(?:api|admin|backup|config|\.git|\.env|wp-admin|phpinfo|debug|swagger|graphql|internal|private|staging|dev|test)\b/i;

  function visibleRows() {
    const search = ($('wb-search').value || '').trim().toLowerCase();
    const mime = $('wb-filter-mime').value;
    const interesting = $('wb-interesting')?.getAttribute('aria-pressed') === 'true';
    let rows = wb.rows;
    if (mime) rows = rows.filter(r => mime.startsWith('family:') ? mimeFamily(r[1]) === mime.slice(7) : r[1] === mime);
    if (interesting) rows = rows.filter(r => INTERESTING_RE.test(r[0] || ''));
    if (search) {
      const terms = search.split(/\s+/).filter(Boolean);
      rows = rows.filter(r => {
        const text = `${r[0] || ''} ${r[1] || ''}`.toLowerCase();
        return terms.every(t => t.startsWith('-') ? !text.includes(t.slice(1)) : text.includes(t));
      });
    }
    return rows;
  }

  function sortedRows(rows) {
    const [colStr, dir] = ($('wb-sort').value || '2-desc').split('-');
    const col = parseInt(colStr, 10);
    const sign = dir === 'asc' ? 1 : -1;
    return rows.slice().sort((a, b) => {
      const av = a[col] || '';
      const bv = b[col] || '';
      if (col === 4 || col === 5) return sign * ((parseInt(av, 10) || 0) - (parseInt(bv, 10) || 0));
      if (col === 2 || col === 3) return av < bv ? -sign : av > bv ? sign : 0; // YYYYMMDDhhmmss strings
      return sign * av.localeCompare(bv);
    });
  }

  function populateMimeFilter() {
    const sel = $('wb-filter-mime');
    const keep = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    const families = {};
    const mimes = new Map();
    for (const r of wb.rows) {
      const m = r[1] || '';
      if (!m) continue;
      mimes.set(m, (mimes.get(m) || 0) + 1);
      const f = mimeFamily(m);
      families[f] = (families[f] || 0) + 1;
    }
    const famGroup = el('optgroup', { label: 'By type' });
    for (const [f, label] of [['html', 'HTML pages'], ['js', 'JavaScript'], ['data', 'Data (JSON/XML/text)'], ['css', 'CSS'], ['img', 'Images'], ['file', 'Documents & archives'], ['other', 'Other']]) {
      if (families[f]) famGroup.append(el('option', { value: `family:${f}`, text: `${label} (${formatNumber(families[f])})` }));
    }
    sel.append(famGroup);
    const mimeGroup = el('optgroup', { label: 'Exact MIME' });
    const sorted = [...mimes.entries()].sort((a, b) => (a[0] === 'text/html' ? -1 : b[0] === 'text/html' ? 1 : b[1] - a[1]));
    for (const [m, n] of sorted) mimeGroup.append(el('option', { value: m, text: `${m} (${formatNumber(n)})` }));
    sel.append(mimeGroup);
    sel.value = [...sel.options].some(o => o.value === keep) ? keep : '';
  }

  function renderWayback() {
    const emptyEl = $('wb-empty');
    const scrollEl = $('wb-scroll');
    const tbody = $('wb-tbody');
    const countEl = $('wb-count');

    if (!wb.host) {
      scrollEl.classList.add('hidden');
      countEl.textContent = '';
      if (wb.loading) Render.emptyState(emptyEl, { icon: 'archive', title: 'Loading archive…', sub: `Fetching up to 10,000 archived URLs for ${currentHost}` });
      else if (wb.error) Render.emptyState(emptyEl, { icon: 'warning', title: 'Failed to load Wayback data', sub: wb.error });
      else if (!currentHost) Render.emptyState(emptyEl, { icon: 'archive', title: 'No host in context', sub: 'Open SecretSauce from a page tab to query the Wayback Machine.' });
      return;
    }

    const rows = sortedRows(visibleRows());
    countEl.textContent = rows.length ? `${formatNumber(rows.length)} of ${formatNumber(wb.rows.length)} URLs` : '';

    if (!rows.length) {
      scrollEl.classList.add('hidden');
      if (!wb.rows.length) Render.emptyState(emptyEl, { icon: 'archive', title: 'No archive data', sub: `The Wayback Machine has no records for ${wb.host}.` });
      else Render.emptyState(emptyEl, { icon: 'filter', title: 'No URLs match the filter' });
      return;
    }

    emptyEl.classList.add('hidden');
    scrollEl.classList.remove('hidden');
    clear(tbody);

    // Rows are cheap <tr>s; render in chunks to keep 10k rows snappy.
    let index = 0;
    const CHUNK = 400;
    const more = el('tr', { class: 'wb-more' }, el('td', { colSpan: 6 }, el('button', { class: 'load-more', type: 'button' })));
    const moreBtn = more.querySelector('button');
    const renderChunk = () => {
      const frag = document.createDocumentFragment();
      const end = Math.min(rows.length, index + CHUNK);
      for (; index < end; index++) {
        const row = rows[index];
        const url = row[0] || '';
        const mime = row[1] || '';
        const fam = mimeFamily(mime);
        const tr = el('tr', { class: INTERESTING_RE.test(url) ? 'hot' : '' },
          el('td', { class: 'wb-url' }, el('a', { class: 'mono', href: url, target: '_blank', rel: 'noopener noreferrer', title: url, text: url })),
          el('td', {}, el('span', { class: `tag mime ${fam}`, text: mime || 'n/a', title: mime })),
          el('td', { class: 'date', text: formatWbTs(row[2]) }),
          el('td', { class: 'date', text: formatWbTs(row[3]) }),
          el('td', { class: 'num', text: formatNumber(row[4] || 0) }),
          el('td', { class: 'act' },
            iconButton('copy', { title: 'Copy URL', onClick: e => copyText(url, null) }),
            iconButton('archive', { title: 'Open latest snapshot', onClick: () => window.open(`https://web.archive.org/web/2/${url}`, '_blank', 'noopener') })));
        frag.append(tr);
      }
      tbody.insertBefore(frag, more.parentNode === tbody ? more : null);
      if (index >= rows.length) more.remove();
      else {
        moreBtn.textContent = `Show more (${formatNumber(rows.length - index)} remaining)`;
        if (more.parentNode !== tbody) tbody.append(more);
      }
    };
    moreBtn.addEventListener('click', renderChunk);
    renderChunk();
  }

  async function loadWayback(force = false) {
    if (!currentHost) { wb.rows = []; wb.host = ''; renderWayback(); return; }
    if (wb.host === currentHost && !force) { renderWayback(); return; }
    if (wb.loading) return;

    wb.loading = true;
    wb.error = '';
    wb.rows = [];
    wb.host = '';
    renderWayback();

    const host = currentHost;
    const apiUrl = `https://web.archive.org/web/timemap/json?url=${encodeURIComponent('https://' + host)}&matchType=prefix&collapse=urlkey&output=json&fl=original%2Cmimetype%2Ctimestamp%2Cendtimestamp%2Cgroupcount%2Cuniqcount&filter=!statuscode%3A%5B45%5D..&limit=10000`;

    try {
      const res = await fetch(apiUrl, { cache: 'no-store' });
      if (!res.ok) throw new Error(`Wayback API returned HTTP ${res.status}`);
      const text = await res.text();
      const json = text.trim() ? JSON.parse(text) : [];
      if (currentHost !== host) return; // host changed while loading
      wb.rows = Array.isArray(json) ? json.slice(1) : [];
      wb.host = host;
      populateMimeFilter();
      renderWayback();
    } catch (err) {
      wb.error = String(err?.message || err);
      renderWayback();
    } finally {
      wb.loading = false;
    }
  }

  function showTab(tab) {
    if (IFRAME_TABS.includes(tab)) showIframeTab(tab);
    else if (tab === 'wayback') loadWayback();
  }

  function bind() {
    const rerender = debounce(renderWayback, 80);
    $('wb-search').addEventListener('input', rerender);
    $('wb-filter-mime').addEventListener('change', renderWayback);
    $('wb-sort').addEventListener('change', renderWayback);
    $('wb-interesting').addEventListener('click', function () { const on = this.getAttribute('aria-pressed') !== 'true'; this.setAttribute('aria-pressed', on ? 'true' : 'false'); renderWayback(); });
    $('btn-wb-reload').addEventListener('click', () => loadWayback(true));
    $('btn-wb-copy').addEventListener('click', () => {
      const urls = visibleRows().map(r => r[0]).filter(Boolean);
      if (!urls.length) return toast('Nothing to copy', 'info');
      copyText(urls.join('\n'), null).then(() => toast(`Copied ${formatNumber(urls.length)} URLs`, 'success'));
    });
    $('btn-wb-export').addEventListener('click', () => {
      const urls = visibleRows().map(r => r[0]).filter(Boolean);
      if (!urls.length) return toast('Nothing to export', 'info');
      download(`wayback-${wb.host || 'export'}-${Date.now()}.txt`, urls.join('\n'));
    });
    for (const tab of IFRAME_TABS) {
      $(`btn-recon-reload-${tab}`)?.addEventListener('click', () => reloadIframeTab(tab));
    }
  }

  root.Recon = { setHost, showTab, bind, IFRAME_TABS, toolUrl, loadWayback };
})(globalThis);
