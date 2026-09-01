// SecretSauce app — card / table rendering. Pure DOM construction, no innerHTML.

(function (root) {
  'use strict';

  const { el, clear, icon, iconButton, copyText, highlight, formatDate, formatNumber, maskValue } = root.UI;
  const SS = root.SS;
  const F = root.Findings;

  const METHOD_CLASS = { GET: 'get', POST: 'post', PUT: 'put', DELETE: 'delete', PATCH: 'patch', HEAD: 'other', OPTIONS: 'other' };

  function pill(text, cls) {
    return el('span', { class: `pill ${cls}`, text });
  }

  function tag(text, cls = '', title = '') {
    return el('span', { class: `tag${cls ? ' ' + cls : ''}`, text, title });
  }

  function kv(label, ...values) {
    return [el('dt', { text: label }), el('dd', {}, ...values)];
  }

  function urlList(urls, max = 5) {
    const list = el('ul', { class: 'url-list' });
    urls.slice(0, max).forEach(u => list.append(el('li', {}, el('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: u, title: u }))));
    if (urls.length > max) list.append(el('li', { class: 'muted', text: `+${urls.length - max} more` }));
    return list;
  }

  function seenSummary(item) {
    const parts = [
      `${formatNumber(item.occurrences || 1)}×`,
      `${formatNumber((item.pageUrls || []).length || 1)} page${(item.pageUrls || []).length === 1 ? '' : 's'}`,
      `${formatNumber((item.sources || []).length || 1)} source${(item.sources || []).length === 1 ? '' : 's'}`,
    ];
    const dates = [];
    if (item.firstSeen) dates.push(`first ${formatDate(item.firstSeen)}`);
    if (item.timestamp) dates.push(`last ${formatDate(item.timestamp)}`);
    return el('span', {}, parts.join(' · '), dates.length ? el('span', { class: 'muted', text: `. ${dates.join(', ')}` }) : null);
  }

  // Card header: an expand button (the readable part of the row) plus sibling
  // actions, so keyboard users can open a finding without hitting an action.
  let cardSeq = 0;
  function cardHead(card, rowChildren, actions, { open, onToggle }) {
    const bodyId = `card-body-${++cardSeq}`;
    const row = el('button', { class: 'card-row', type: 'button', 'aria-expanded': open ? 'true' : 'false', 'aria-controls': bodyId }, ...rowChildren);
    row.addEventListener('click', () => {
      const isOpen = card.classList.toggle('open');
      row.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      onToggle?.(isOpen);
    });
    const head = el('div', { class: 'card-head' }, row, actions, icon('chevron', 12, 'chevron'));
    return { head, bodyId };
  }

  function contextBlock(context, needle, { open, onToggle }) {
    const body = el('pre', { class: `ctx-body${open ? ' expanded' : ''}` }, highlight(context, needle));
    const toggle = el('button', { class: 'tbtn', type: 'button', text: open ? 'Collapse' : 'Expand' });
    toggle.addEventListener('click', event => {
      event.stopPropagation();
      const expanded = body.classList.toggle('expanded');
      toggle.textContent = expanded ? 'Collapse' : 'Expand';
      onToggle?.(expanded);
    });
    const copyBtn = iconButton('copy', { title: 'Copy context', cls: 'tbtn-icon', onClick: e => { e.stopPropagation(); copyText(context, null); } });
    return el('div', { class: 'ctx' },
      el('div', { class: 'ctx-head' }, el('span', { class: 'label', text: 'Context' }), el('span', { class: 'ctx-actions' }, copyBtn, toggle)),
      body);
  }

  // ─── Endpoint card ────────────────────────────────────────────────────────
  function endpointCard(endpoint, opts) {
    const { currentHost, open, ctxOpen, ignored, onToggle, onToggleCtx, onIgnore, onOpenUrl } = opts;
    const method = (endpoint.method || 'GET').toUpperCase();
    const methodCls = METHOD_CLASS[method] || 'other';
    const key = SS.endpointIdentity(endpoint);
    const { hostPrefix, pathText } = F.endpointDisplay(endpoint, currentHost);
    const fullUrl = endpoint.url || `${hostPrefix}${pathText}`;
    const query = F.endpointQuery(endpoint);
    const params = endpoint.params || [];
    const kinds = endpoint.kinds && endpoint.kinds.length ? endpoint.kinds : [endpoint.kind];

    const card = el('article', { class: `card ep${open ? ' open' : ''}${ignored ? ' ignored' : ''}`, dataset: { key } });

    const urlEl = el('span', { class: 'ep-url', title: fullUrl },
      hostPrefix ? el('span', { class: 'ep-host', text: hostPrefix }) : null,
      el('span', { class: 'ep-path', text: pathText }));

    const tags = el('span', { class: 'tags' });
    tags.append(tag(F.kindLabel(kinds[0]), 'kind', kinds.map(F.kindLabel).join(', ')));
    if (kinds.length > 1) tags.append(tag(`+${kinds.length - 1}`, 'kind', kinds.slice(1).map(F.kindLabel).join(', ')));
    if (endpoint.templated) tags.append(tag('{param}', 'tpl', 'Templated path: parameters normalised'));
    if (params.length) tags.append(tag(`${params.length} param${params.length === 1 ? '' : 's'}`, 'params', params.join(', ')));
    if (endpoint.live) tags.append(tag('live', 'live', 'Seen in the current tab scan'));
    if ((endpoint.occurrences || 1) > 1) tags.append(tag(`×${formatNumber(endpoint.occurrences)}`, 'count', 'Occurrences across scans'));

    const actions = el('span', { class: 'card-actions' },
      iconButton('copy', { title: 'Copy URL', onClick: e => { e.stopPropagation(); copyText(fullUrl, null); } }),
      iconButton('terminal', { title: 'Copy as cURL', onClick: e => { e.stopPropagation(); copyText(F.toCurl(endpoint), null); } }),
      /^https?:/i.test(fullUrl) && !endpoint.templated
        ? iconButton('external', { title: 'Open in new tab', onClick: e => { e.stopPropagation(); onOpenUrl?.(fullUrl); } })
        : null,
      iconButton(ignored ? 'undo' : 'ban', { title: ignored ? 'Restore' : 'Dismiss (mark as noise)', cls: 'danger-hover', onClick: e => { e.stopPropagation(); onIgnore?.(key, !ignored); } }),
    );

    const { head, bodyId } = cardHead(card, [pill(method, `method ${methodCls}`), urlEl, tags], actions, { open, onToggle: isOpen => onToggle?.(key, isOpen) });

    const dl = el('dl', { class: 'kv' });
    dl.append(...kv('URL', el('code', { class: 'mono wrap', text: fullUrl })));
    if (query) dl.append(...kv('Query', el('code', { class: 'mono wrap', text: query })));
    if (params.length) dl.append(...kv('Params', el('span', { class: 'chips' }, ...params.map(p => el('code', { class: 'chip', text: p })))));
    dl.append(...kv('Detected via', el('span', { class: 'tags' }, ...kinds.map(k => tag(F.kindLabel(k), 'kind')))));
    dl.append(...kv('Source', el('a', { class: 'src', href: endpoint.source, target: '_blank', rel: 'noopener noreferrer', text: endpoint.source || 'n/a', title: endpoint.source })));
    if ((endpoint.pageUrls || []).length) dl.append(...kv('Pages', urlList(endpoint.pageUrls)));
    dl.append(...kv('Seen', seenSummary(endpoint)));

    const body = el('div', { class: 'card-body', id: bodyId }, dl);
    if (endpoint.context) {
      body.append(contextBlock(endpoint.context, endpoint.rawMatch || endpoint.url || endpoint.path, { open: ctxOpen, onToggle: v => onToggleCtx?.(key, v) }));
    }

    card.append(head, body);
    return card;
  }

  // ─── Secret card ──────────────────────────────────────────────────────────
  function secretCard(secret, opts) {
    const { open, ctxOpen, ignored, masked, onToggle, onToggleCtx, onIgnore } = opts;
    const severity = (secret.severity || 'medium').toLowerCase();
    const key = secret.value;
    const shown = masked ? maskValue(secret.value) : secret.value;
    const ruleIds = secret.ids && secret.ids.length ? secret.ids : [secret.id];

    const card = el('article', { class: `card sec sev-${severity}${open ? ' open' : ''}${ignored ? ' ignored' : ''}`, dataset: { key } });

    const tags = el('span', { class: 'tags' });
    if (ruleIds.length > 1) tags.append(tag(`${ruleIds.length} rules`, 'kind', ruleIds.join(', ')));
    if (secret.live) tags.append(tag('live', 'live', 'Seen in the current tab scan'));
    if ((secret.occurrences || 1) > 1) tags.append(tag(`×${formatNumber(secret.occurrences)}`, 'count', 'Occurrences across scans'));

    const actions = el('span', { class: 'card-actions' },
      iconButton('copy', { title: 'Copy value', onClick: e => { e.stopPropagation(); copyText(secret.value, null); } }),
      iconButton(ignored ? 'undo' : 'ban', { title: ignored ? 'Restore' : 'Dismiss (false positive)', cls: 'danger-hover', onClick: e => { e.stopPropagation(); onIgnore?.(key, !ignored); } }),
    );

    const { head, bodyId } = cardHead(card, [
      pill(severity, `sev ${severity}`),
      el('span', { class: 'sec-main' },
        el('span', { class: 'sec-name', text: secret.name }),
        el('code', { class: 'sec-preview mono', text: shown, title: masked ? 'Value masked. Use the eye button to reveal it.' : '' })),
      tags,
    ], actions, { open, onToggle: isOpen => onToggle?.(key, isOpen) });

    const dl = el('dl', { class: 'kv' });
    dl.append(...kv('Value', el('code', { class: 'mono wrap value', text: shown })));
    dl.append(...kv('Rule', el('span', { class: 'tags' }, ...ruleIds.map(id => tag(id, 'kind')))));
    dl.append(...kv('Source', el('a', { class: 'src', href: secret.source, target: '_blank', rel: 'noopener noreferrer', text: secret.source || 'n/a', title: secret.source })));
    if ((secret.pageUrls || []).length) dl.append(...kv('Pages', urlList(secret.pageUrls)));
    dl.append(...kv('Seen', seenSummary(secret)));

    const body = el('div', { class: 'card-body', id: bodyId }, dl);
    if (secret.context) {
      body.append(contextBlock(secret.context, secret.value, { open: ctxOpen, onToggle: v => onToggleCtx?.(key, v) }));
    }

    card.append(head, body);
    return card;
  }

  // ─── Incremental list rendering ───────────────────────────────────────────
  // Renders `chunk` cards at a time; a sentinel at the bottom renders more when
  // scrolled into view (IntersectionObserver) or clicked.
  const observers = new WeakMap();

  function renderList(container, items, buildCard, { chunk = 100, emptyEl } = {}) {
    const previous = observers.get(container);
    if (previous) { previous.disconnect(); observers.delete(container); }

    const scrollTop = container.scrollTop;
    Array.from(container.children).forEach(child => { if (child !== emptyEl) child.remove(); });
    if (!items.length) return;

    let rendered = 0;
    const sentinel = el('button', { class: 'load-more', type: 'button' });

    const renderChunk = () => {
      const frag = document.createDocumentFragment();
      const end = Math.min(items.length, rendered + chunk);
      for (; rendered < end; rendered++) frag.append(buildCard(items[rendered]));
      container.insertBefore(frag, sentinel);
      if (rendered >= items.length) {
        sentinel.remove();
        observer.disconnect();
        observers.delete(container);
      } else {
        sentinel.textContent = `Show more (${formatNumber(items.length - rendered)} remaining)`;
      }
    };

    const observer = new IntersectionObserver(entries => {
      if (entries.some(e => e.isIntersecting)) renderChunk();
    }, { root: container, rootMargin: '400px' });
    observers.set(container, observer);

    sentinel.addEventListener('click', renderChunk);
    container.append(sentinel);
    observer.observe(sentinel);
    renderChunk();
    if (scrollTop) container.scrollTop = scrollTop; // keep the reader's place across re-renders
  }

  function emptyState(node, { icon: iconName, title, sub }) {
    clear(node);
    node.append(
      el('div', { class: 'empty-icon' }, icon(iconName || 'inbox', 28)),
      el('div', { class: 'empty-title', text: title || '' }),
      sub ? el('div', { class: 'empty-sub', text: sub }) : null,
    );
    node.classList.remove('hidden');
  }

  // ─── Hosts table ──────────────────────────────────────────────────────────
  function severityDots(counts) {
    const wrap = el('span', { class: 'sev-dots' });
    for (const sev of SS.SEVERITIES) {
      if (!counts[sev]) continue;
      wrap.append(el('span', { class: `dot ${sev}`, title: `${counts[sev]} ${sev}` }, el('b', { text: formatNumber(counts[sev]) })));
    }
    if (!wrap.children.length) wrap.append(el('span', { class: 'muted', text: '—' }));
    return wrap;
  }

  function hostsTable(container, hosts, { onOpen, onDelete, currentHost }) {
    clear(container);
    if (!hosts.length) return;
    const table = el('table', { class: 'table' },
      el('thead', {}, el('tr', {},
        el('th', { text: 'Host' }), el('th', { text: 'Endpoints', class: 'num' }), el('th', { text: 'Secrets', class: 'num' }),
        el('th', { text: 'Severity' }), el('th', { text: 'Pages', class: 'num' }), el('th', { text: 'Last updated' }), el('th', { text: '', class: 'act' }))));
    const tbody = el('tbody');
    for (const host of hosts) {
      const isCurrent = host.hostname === currentHost;
      const tr = el('tr', { class: isCurrent ? 'current' : '' },
        el('td', {}, el('button', { class: 'link-btn mono', type: 'button', text: host.hostname, on: { click: () => onOpen?.(host.hostname) } }), isCurrent ? tag('current', 'live') : null),
        el('td', { class: 'num', text: formatNumber(host.stats.uniqueEndpoints) }),
        el('td', { class: 'num', text: formatNumber(host.stats.uniqueSecrets) }),
        el('td', {}, severityDots(host.severityCounts)),
        el('td', { class: 'num', text: formatNumber(host.stats.pageCount) }),
        el('td', { class: 'muted', text: host.updatedAt ? `${SS.timeAgo(host.updatedAt)} · ${formatDate(host.updatedAt)}` : '—' }),
        el('td', { class: 'act' },
          iconButton('external', { title: 'Open findings', onClick: () => onOpen?.(host.hostname) }),
          iconButton('trash', { title: 'Delete stored data for this host', cls: 'danger-hover', onClick: () => onDelete?.(host.hostname) })));
      tbody.append(tr);
    }
    table.append(tbody);
    container.append(table);
  }

  // ─── Rules list (settings) ────────────────────────────────────────────────
  function rulesList(container, rules, disabled, onToggle, filterText = '') {
    clear(container);
    const q = filterText.trim().toLowerCase();
    const groups = { critical: [], high: [], medium: [], low: [] };
    for (const rule of rules) {
      if (q && !`${rule.id} ${rule.name}`.toLowerCase().includes(q)) continue;
      (groups[rule.severity] || groups.medium).push(rule);
    }
    for (const sev of SS.SEVERITIES) {
      if (!groups[sev].length) continue;
      const list = el('div', { class: 'rule-list' });
      for (const rule of groups[sev].sort((a, b) => a.name.localeCompare(b.name))) {
        const input = el('input', { type: 'checkbox', checked: !disabled.has(rule.id) });
        input.addEventListener('change', () => onToggle?.(rule.id, input.checked));
        list.append(el('label', { class: `rule${disabled.has(rule.id) ? ' off' : ''}`, title: rule.regex },
          input, el('span', { class: 'switch' }), el('span', { class: 'rule-name', text: rule.name }), el('code', { class: 'rule-id mono', text: rule.id })));
      }
      container.append(el('div', { class: 'rule-group' }, el('div', { class: 'rule-group-head' }, pill(sev, `sev ${sev}`), el('span', { class: 'muted', text: `${groups[sev].length} rules` })), list));
    }
    if (!container.children.length) container.append(el('div', { class: 'muted pad', text: 'No rules match.' }));
  }

  root.Render = { pill, tag, endpointCard, secretCard, renderList, emptyState, hostsTable, rulesList, severityDots };
})(globalThis);
