/* ============================================================
   ENTERPRISE DLP — Dashboard Client
   ============================================================ */

'use strict';

// ── Constants ────────────────────────────────────────────────

const MAX_LIVE_ROWS  = 500;
const TIMELINE_BINS  = 60;

// ── State ────────────────────────────────────────────────────

let liveEvents      = [];   // dashboard live feed
let logEvents       = [];   // event log page data
let activeFilter    = 'ALL';
let searchQuery     = '';
let socket          = null;

const stats = { BLOCK: 0, QUARANTINE: 0, ENCRYPT: 0, ALERT: 0, ALLOW: 0, TOTAL: 0 };
let timelineHistory = [];

// ── DOM helpers ──────────────────────────────────────────────

const $  = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

// ── Formatters ───────────────────────────────────────────────

function fmtDateTime(iso) {
  try {
    const d = new Date(iso);
    const date = d.toLocaleDateString('en-US', { month: 'short', day: '2-digit' });
    const time = d.toLocaleTimeString('en-US', { hour12: false });
    const ms   = String(d.getMilliseconds()).padStart(3, '0');
    return `${date} ${time}.${ms}`;
  } catch { return iso; }
}

function escHtml(s) {
  return String(s || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function buildTagsHTML(ev) {
  const details = ev.details || '';
  if (!details) return '<span style="color:var(--txt-dim)">—</span>';

  // "CLASSIFICATION — human description" format
  const dashMatch = details.match(/^([A-Z][A-Z0-9_]+)\s*[—–\-]\s*([\s\S]*)/);
  if (dashMatch) {
    const tag  = dashMatch[1];
    const desc = dashMatch[2].trim();
    return `<span class="tag tag-${escHtml(tag)}">${escHtml(tag)}</span>`
         + (desc ? ` <span class="detail-text">${escHtml(desc)}</span>` : '');
  }

  // Fallback: comma-separated classification names (legacy)
  return details.split(',')
    .map(t => t.trim()).filter(Boolean)
    .map(t => `<span class="tag tag-${escHtml(t)}">${escHtml(t)}</span>`)
    .join('');
}

function buildRow(ev, isNew) {
  const tr = document.createElement('tr');
  if (isNew) tr.classList.add('new-row');
  const typeStr = ev.type || 'ENDPOINT';
  tr.innerHTML = `
    <td class="time-cell">${escHtml(fmtDateTime(ev.time))}</td>
    <td><span class="type-chip type-${escHtml(typeStr)}">${escHtml(typeStr)}</span></td>
    <td><span class="badge badge-${escHtml(ev.action)}">${escHtml(ev.action)}</span></td>
    <td class="source-cell" title="${escHtml(ev.source)}">${escHtml(ev.source || '—')}</td>
    <td class="details-cell" title="${escHtml(ev.details)}">${buildTagsHTML(ev)}</td>
  `;
  return tr;
}

// ── Stats ────────────────────────────────────────────────────

function applyStats(data) {
  ['BLOCK','QUARANTINE','ENCRYPT','ALERT','ALLOW','TOTAL'].forEach(k => {
    if (data[k] !== undefined) stats[k] = data[k];
  });
  renderStats();
}

function renderStats() {
  animateCounter('cnt-block',      stats.BLOCK);
  animateCounter('cnt-quarantine', stats.QUARANTINE);
  animateCounter('cnt-encrypt',    stats.ENCRYPT);
  animateCounter('cnt-alert',      stats.ALERT);
  animateCounter('cnt-allow',      stats.ALLOW);
  animateCounter('total-count',    stats.TOTAL, false);
}

function animateCounter(id, newVal, doBump = true) {
  const el = $(id);
  if (!el) return;
  const old = parseInt(el.textContent, 10) || 0;
  if (newVal === old) return;
  el.textContent = newVal;
  if (doBump && newVal > old) {
    el.classList.remove('bump');
    void el.offsetWidth;
    el.classList.add('bump');
  }
}

// ── Timeline ─────────────────────────────────────────────────

function pushTimeline(action) {
  timelineHistory.push(action);
  if (timelineHistory.length > TIMELINE_BINS) timelineHistory.shift();
  renderTimeline();
}

function renderTimeline() {
  const chart = $('timeline-chart');
  if (!chart) return;
  chart.innerHTML = '';

  const padding = TIMELINE_BINS - timelineHistory.length;
  for (let i = 0; i < padding; i++) {
    const bar = document.createElement('div');
    bar.className = 'tl-bar empty';
    bar.style.height = '15%';
    chart.appendChild(bar);
  }

  timelineHistory.forEach(action => {
    const bar = document.createElement('div');
    bar.className = 'tl-bar ' + (action || 'empty').toLowerCase();
    bar.style.height = '100%';
    bar.title = action || '—';
    chart.appendChild(bar);
  });
}

// ── Dashboard live feed ───────────────────────────────────────

function matchesFilter(ev) {
  if (activeFilter !== 'ALL' && ev.action !== activeFilter) return false;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    return (ev.source  || '').toLowerCase().includes(q) ||
           (ev.details || '').toLowerCase().includes(q) ||
           (ev.type    || '').toLowerCase().includes(q);
  }
  return true;
}

function renderDashboardTable() {
  const tbody     = $('events-body');
  const emptyRow  = $('empty-row');
  const filtered  = liveEvents.filter(matchesFilter);

  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

  if (filtered.length === 0) {
    tbody.appendChild(emptyRow);
    $('row-count').textContent  = '0 events shown';
    $('filter-label').textContent = `Filter: ${activeFilter}`;
    return;
  }

  filtered.forEach(ev => tbody.appendChild(buildRow(ev, false)));

  $('row-count').textContent    = `${filtered.length} event${filtered.length !== 1 ? 's' : ''} shown`;
  $('filter-label').textContent = `Filter: ${activeFilter}`;
}

function prependLiveEvent(ev) {
  const emptyRow = $('empty-row');
  const tbody    = $('events-body');

  if (emptyRow.parentNode === tbody) tbody.removeChild(emptyRow);

  liveEvents.unshift(ev);
  if (liveEvents.length > MAX_LIVE_ROWS) liveEvents.pop();

  if (!matchesFilter(ev)) {
    // Count actual DOM rows — accurate whether showing live or API-fetched results
    const shown = tbody.children.length;
    $('row-count').textContent = `${shown} event${shown !== 1 ? 's' : ''} shown`;
    return;
  }

  const tr = buildRow(ev, true);
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > MAX_LIVE_ROWS) tbody.removeChild(tbody.lastChild);

  const shown = tbody.children.length;
  $('row-count').textContent = `${shown} event${shown !== 1 ? 's' : ''} shown`;
}

// ── Event Log page ───────────────────────────────────────────

function loadEventLog() {
  const action = $('log-action-select').value;
  const limit  = $('log-limit-select').value;
  $('log-count').textContent = 'Loading...';

  fetch(`/api/logs?limit=${limit}&action=${action}`)
    .then(r => r.json())
    .then(rows => {
      logEvents = rows;
      renderLogTable();
      $('log-last-refresh').textContent =
        'Refreshed at ' + new Date().toLocaleTimeString('en-US', { hour12: false });
    })
    .catch(() => {
      $('log-count').textContent = 'Error loading events';
    });
}

function renderLogTable() {
  const tbody    = $('log-body');
  const emptyRow = $('log-empty-row');

  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

  if (logEvents.length === 0) {
    tbody.appendChild(emptyRow);
    $('log-count').textContent = '0 events';
    return;
  }

  logEvents.forEach(ev => tbody.appendChild(buildRow(ev, false)));
  $('log-count').textContent =
    `${logEvents.length} event${logEvents.length !== 1 ? 's' : ''}`;
}

function exportCSV() {
  if (logEvents.length === 0) {
    alert('No events to export. Load the Event Log first.');
    return;
  }
  const headers = ['Timestamp','Channel','Action','Source','Classification'];
  const rows = logEvents.map(ev =>
    [ev.time, ev.type, ev.action, ev.source, ev.details]
      .map(v => `"${String(v || '').replace(/"/g, '""')}"`)
      .join(',')
  );
  const csv  = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `dlp-events-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function prependLogEvent(ev) {
  logEvents.unshift(ev);

  const logPage = $('page-events');
  if (!logPage || !logPage.classList.contains('active')) return;

  const actionFilter = $('log-action-select').value;
  if (actionFilter && actionFilter !== 'ALL' && ev.action !== actionFilter) return;

  const tbody    = $('log-body');
  const emptyRow = $('log-empty-row');

  if (emptyRow.parentNode === tbody) tbody.removeChild(emptyRow);

  const tr = buildRow(ev, true);
  tbody.insertBefore(tr, tbody.firstChild);

  const limit = parseInt($('log-limit-select').value, 10) || 500;
  while (tbody.children.length > limit) tbody.removeChild(tbody.lastChild);

  const shown = tbody.children.length;
  $('log-count').textContent = `${shown} event${shown !== 1 ? 's' : ''}`;
  $('log-last-refresh').textContent = 'Live · ' + new Date().toLocaleTimeString('en-US', { hour12: false });
}

// ── Event Log controls ────────────────────────────────────────

function bindEventLogControls() {
  $('log-refresh-btn').addEventListener('click', loadEventLog);
  $('log-export-btn').addEventListener('click', exportCSV);
  $('log-action-select').addEventListener('change', loadEventLog);
  $('log-limit-select').addEventListener('change', loadEventLog);
}

// ── Dashboard filter + search ────────────────────────────────

function fetchAndRenderFiltered(action) {
  const tbody    = $('events-body');
  const emptyRow = $('empty-row');
  $('row-count').textContent    = 'Loading…';
  $('filter-label').textContent = `Filter: ${action}`;

  fetch(`/api/logs?limit=500&action=${action}`)
    .then(r => r.json())
    .then(rows => {
      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      if (rows.length === 0) {
        tbody.appendChild(emptyRow);
        $('row-count').textContent = '0 events shown';
        return;
      }
      rows.forEach(ev => tbody.appendChild(buildRow(ev, false)));
      $('row-count').textContent =
        `${rows.length} event${rows.length !== 1 ? 's' : ''} shown`;
    })
    .catch(() => renderDashboardTable());
}

function bindDashboardControls() {
  $('filter-group').addEventListener('click', e => {
    const btn = e.target.closest('.filter-btn');
    if (!btn) return;
    $$('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    if (activeFilter === 'ALL') {
      renderDashboardTable();
    } else {
      fetchAndRenderFiltered(activeFilter);
    }
  });

  $('search-input').addEventListener('input', () => {
    searchQuery = $('search-input').value.trim();
    renderDashboardTable();
  });
}

// ── Navigation ───────────────────────────────────────────────

function bindNav() {
  $$('.nav-item').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const section = link.dataset.section;

      $$('.nav-item').forEach(l => l.classList.remove('active'));
      link.classList.add('active');

      $$('.page').forEach(p => p.classList.remove('active'));
      const page = document.getElementById('page-' + section);
      if (page) page.classList.add('active');

      if (section === 'config') loadConfig();
      if (section === 'events') loadEventLog();
    });
  });
}

// ── Config page ──────────────────────────────────────────────

let _cfg = { watch_paths: [], keywords: [], trusted_ips: [], quarantine_path: '', db: '' };

function _renderEditList(id, arr) {
  const el = $(id);
  el.innerHTML = '';
  arr.forEach((val, i) => {
    const row = document.createElement('div');
    row.className = 'cfg-editrow';
    row.innerHTML =
      `<span class="cfg-editrow-val">${escHtml(val)}</span>` +
      `<button class="cfg-editrow-del" data-i="${i}" title="Remove">×</button>`;
    el.appendChild(row);
  });
  el.querySelectorAll('.cfg-editrow-del').forEach(btn =>
    btn.addEventListener('click', () => {
      arr.splice(parseInt(btn.dataset.i, 10), 1);
      _renderEditList(id, arr);
    })
  );
}

function _renderChips(id, arr, colorClass) {
  const el = $(id);
  el.innerHTML = '';
  arr.forEach((val, i) => {
    const chip = document.createElement('span');
    chip.className = 'cfg-chip ' + (colorClass || 'cfg-chip-yellow');
    chip.innerHTML =
      `${escHtml(val)}<button class="cfg-chip-del" data-i="${i}" title="Remove">×</button>`;
    el.appendChild(chip);
  });
  el.querySelectorAll('.cfg-chip-del').forEach(btn =>
    btn.addEventListener('click', () => {
      arr.splice(parseInt(btn.dataset.i, 10), 1);
      _renderChips(id, arr, colorClass);
    })
  );
}

function loadConfig() {
  fetch('/api/config')
    .then(r => r.json())
    .then(data => {
      _cfg.watch_paths     = data.watch_paths     || [];
      _cfg.keywords        = data.keywords        || [];
      _cfg.trusted_ips     = data.trusted_ips     || [];
      _cfg.quarantine_path = data.quarantine_path || '';
      _cfg.db              = data.db              || '';

      _renderEditList('cfg-paths-list', _cfg.watch_paths);
      _renderChips('cfg-kw-list', _cfg.keywords, 'cfg-chip-yellow');
      _renderChips('cfg-ip-list', _cfg.trusted_ips, 'cfg-chip-blue');

      $('cfg-quarantine-input').value = _cfg.quarantine_path;
      $('cfg-db').textContent         = _cfg.db || '—';
    })
    .catch(() => {
      $('cfg-db').textContent = 'Could not load configuration.';
    });
}

function saveConfig() {
  const btn    = $('cfg-save-btn');
  const status = $('cfg-status');
  btn.disabled    = true;
  btn.textContent = 'Saving…';

  const payload = {
    watch_paths:     _cfg.watch_paths,
    keywords:        _cfg.keywords,
    trusted_ips:     _cfg.trusted_ips,
    quarantine_path: $('cfg-quarantine-input').value.trim(),
  };

  fetch('/api/config', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  })
    .then(r => r.json())
    .then(d => {
      if (d.ok) {
        status.textContent = 'Saved successfully';
        status.className   = 'cfg-status cfg-status-ok';
      } else {
        status.textContent = 'Error: ' + (d.error || 'Unknown');
        status.className   = 'cfg-status cfg-status-err';
      }
    })
    .catch(() => {
      status.textContent = 'Save failed — check server';
      status.className   = 'cfg-status cfg-status-err';
    })
    .finally(() => {
      btn.disabled    = false;
      btn.textContent = 'Save Changes';
      setTimeout(() => { status.textContent = ''; status.className = 'cfg-status'; }, 3500);
    });
}

function bindConfigControls() {
  $('cfg-save-btn').addEventListener('click', saveConfig);

  $('cfg-path-add').addEventListener('click', () => {
    const v = $('cfg-path-input').value.trim();
    if (v && !_cfg.watch_paths.includes(v)) {
      _cfg.watch_paths.push(v);
      _renderEditList('cfg-paths-list', _cfg.watch_paths);
      $('cfg-path-input').value = '';
    }
  });
  $('cfg-path-input').addEventListener('keydown', e => { if (e.key === 'Enter') $('cfg-path-add').click(); });

  $('cfg-kw-add').addEventListener('click', () => {
    const v = $('cfg-kw-input').value.trim().toLowerCase();
    if (v && !_cfg.keywords.includes(v)) {
      _cfg.keywords.push(v);
      _renderChips('cfg-kw-list', _cfg.keywords, 'cfg-chip-yellow');
      $('cfg-kw-input').value = '';
    }
  });
  $('cfg-kw-input').addEventListener('keydown', e => { if (e.key === 'Enter') $('cfg-kw-add').click(); });

  $('cfg-ip-add').addEventListener('click', () => {
    const v = $('cfg-ip-input').value.trim();
    if (v && !_cfg.trusted_ips.includes(v)) {
      _cfg.trusted_ips.push(v);
      _renderChips('cfg-ip-list', _cfg.trusted_ips, 'cfg-chip-blue');
      $('cfg-ip-input').value = '';
    }
  });
  $('cfg-ip-input').addEventListener('keydown', e => { if (e.key === 'Enter') $('cfg-ip-add').click(); });
}

// ── Socket.IO ───────────────────────────────────────────────

function connectSocket() {
  socket = io({ transports: ['websocket', 'polling'] });

  socket.on('connect', () => {
    $('conn-dot').className   = 'conn-dot connected';
    $('conn-label').textContent = 'Connected';
    $('live-badge').classList.remove('offline');
  });

  socket.on('disconnect', () => {
    $('conn-dot').className   = 'conn-dot disconnected';
    $('conn-label').textContent = 'Disconnected';
    $('live-badge').classList.add('offline');
  });

  socket.on('connect_error', () => {
    $('conn-dot').className   = 'conn-dot disconnected';
    $('conn-label').textContent = 'Error';
  });

  socket.on('dlp_event', ev => {
    prependLiveEvent(ev);
    pushTimeline(ev.action);
    const k = ev.action;
    if (stats[k] !== undefined) { stats[k]++; stats.TOTAL++; renderStats(); }
    prependLogEvent(ev);
  });

  socket.on('stats_update', data => {
    applyStats(data);
  });
}

// ── Bootstrap ────────────────────────────────────────────────

function init() {
  renderTimeline();
  bindNav();
  bindDashboardControls();
  bindEventLogControls();
  bindConfigControls();

  // Load dashboard history
  fetch('/api/logs?limit=500')
    .then(r => r.json())
    .then(rows => {
      liveEvents = rows;
      rows.forEach(ev => pushTimeline(ev.action));
      renderDashboardTable();
    })
    .catch(() => {});

  // Load stats
  fetch('/api/stats')
    .then(r => r.json())
    .then(data => applyStats(data))
    .catch(() => {});

  // Connect WebSocket
  connectSocket();
}

document.addEventListener('DOMContentLoaded', init);
