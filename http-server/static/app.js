'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let apiKey = localStorage.getItem('ssrfbox_key') || '';
let ws = null;
let interactions = [];
let filteredInteractions = [];
let stats = { dns: 0, http: 0, smtp: 0, ldap: 0 };
const DOMAIN = window.location.hostname;

// ── Auth ───────────────────────────────────────────────────────────────────
function login() {
  apiKey = document.getElementById('api-key-input').value.trim();
  if (!apiKey) return showAuthError('Introduce una API key');
  localStorage.setItem('ssrfbox_key', apiKey);
  bootstrap();
}

function showAuthError(msg) {
  const el = document.getElementById('auth-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

// ── Bootstrap ──────────────────────────────────────────────────────────────
async function bootstrap() {
  try {
    const resp = await apiFetch('/api/stats');
    if (resp.status === 403) { showAuthError('API key incorrecta'); return; }
    const data = await resp.json();
    document.getElementById('auth-gate').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');
    updateStats(data.by_type, data.total);
    await loadInteractions();
    connectWS();
    setupPayloadTypeListener();
  } catch (e) {
    showAuthError('Error conectando con el servidor: ' + e.message);
  }
}

// ── API helpers ────────────────────────────────────────────────────────────
function apiFetch(path, opts = {}) {
  opts.headers = { ...(opts.headers || {}), 'X-API-Key': apiKey };
  if (opts.body && typeof opts.body === 'object') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  return fetch(path, opts);
}

// ── Interactions ───────────────────────────────────────────────────────────
async function loadInteractions() {
  const resp = await apiFetch('/api/interactions?limit=500');
  const data = await resp.json();
  interactions = data.interactions || [];
  applyFilters();
}

function renderFeed() {
  const feed = document.getElementById('interactions-feed');
  feed.innerHTML = '';
  const toShow = filteredInteractions.slice(0, 300);
  for (const i of toShow) {
    feed.appendChild(buildRow(i, false));
  }
  document.getElementById('total-count').textContent = interactions.length + ' interacciones';
}

function buildRow(i, isNew) {
  const row = document.createElement('div');
  row.className = 'interaction-row' + (isNew ? ' new' : '');
  row.onclick = () => showDetail(i);

  const typeDisplay = i.type || 'http';
  const path = i.path || i.query_name || i.raw_data || '—';
  const time = new Date(i.timestamp).toLocaleTimeString('es', { hour12: false });

  row.innerHTML = `
    <span class="badge-type ${typeDisplay}">${typeDisplay.toUpperCase()}</span>
    <span class="interaction-ip">${truncate(i.source_ip || '—', 14)}</span>
    <span class="interaction-path" title="${escHtml(path)}">${escHtml(truncate(path, 60))}</span>
    <span class="interaction-time">${time}</span>
    ${i.decoded_data ? `<span class="interaction-decoded">⬡ ${escHtml(truncate(i.decoded_data, 80))}</span>` : ''}
  `;
  return row;
}

function applyFilters() {
  const uuid = document.getElementById('filter-uuid').value.trim().toLowerCase();
  const type = document.getElementById('filter-type').value;
  filteredInteractions = interactions.filter(i => {
    if (uuid && !(i.uuid || '').toLowerCase().includes(uuid)) return false;
    if (type && i.type !== type) return false;
    return true;
  });
  renderFeed();
}

function clearFilters() {
  document.getElementById('filter-uuid').value = '';
  document.getElementById('filter-type').value = '';
  applyFilters();
}

async function deleteUUID() {
  const uuid = document.getElementById('filter-uuid').value.trim();
  if (!uuid) { alert('Introduce un UUID en el filtro primero'); return; }
  if (!confirm('Borrar todas las interacciones de UUID: ' + uuid)) return;
  await apiFetch('/api/interactions/' + uuid, { method: 'DELETE' });
  interactions = interactions.filter(i => i.uuid !== uuid);
  applyFilters();
}

// ── Detail panel ───────────────────────────────────────────────────────────
function showDetail(i) {
  const detail = document.getElementById('interaction-detail');
  detail.classList.remove('hidden');
  document.getElementById('payload-output').classList.add('hidden');

  const headers = tryParseJSON(i.headers);
  const content = {
    id:           i.id,
    uuid:         i.uuid,
    type:         i.type,
    timestamp:    i.timestamp,
    source_ip:    i.source_ip,
    path:         i.path,
    method:       i.method,
    query_name:   i.query_name,
    query_type:   i.query_type,
    user_agent:   i.user_agent,
    decoded_data: i.decoded_data,
    headers:      headers,
    body:         i.body,
    raw_data:     i.raw_data,
  };
  document.getElementById('detail-content').textContent = JSON.stringify(content, null, 2);
}

function closeDetail() {
  document.getElementById('interaction-detail').classList.add('hidden');
}

// ── Stats ──────────────────────────────────────────────────────────────────
function updateStats(byType, total) {
  stats = { ...stats, ...(byType || {}) };
  for (const t of ['dns', 'http', 'smtp', 'ldap']) {
    const el = document.querySelector(`#stat-${t} .num`);
    if (el) el.textContent = stats[t] || 0;
  }
  document.getElementById('total-count').textContent = (total || interactions.length) + ' interacciones';
}

// ── WebSocket ──────────────────────────────────────────────────────────────
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const wsURL = `${proto}://${location.host}/ws?apikey=${encodeURIComponent(apiKey)}`;
  ws = new WebSocket(wsURL);

  ws.onopen = () => {
    document.getElementById('status-dot').className = 'dot connected';
    document.getElementById('status-text').textContent = 'Conectado';
  };

  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.event === 'new_interaction' && msg.interaction) {
        onNewInteraction(msg.interaction);
      }
    } catch (_) {}
  };

  ws.onclose = () => {
    document.getElementById('status-dot').className = 'dot disconnected';
    document.getElementById('status-text').textContent = 'Reconectando...';
    setTimeout(connectWS, 3000);
  };

  ws.onerror = () => ws.close();
}

function onNewInteraction(i) {
  interactions.unshift(i);
  stats[i.type] = (stats[i.type] || 0) + 1;
  updateStats(null, interactions.length);
  applyFilters();

  // Highlight latest row
  const feed = document.getElementById('interactions-feed');
  if (feed.firstChild) {
    const newRow = buildRow(i, true);
    feed.insertBefore(newRow, feed.firstChild);
    if (document.getElementById('auto-scroll').checked) {
      feed.scrollTop = 0;
    }
  }
}

// ── Payload generator ──────────────────────────────────────────────────────
function setupPayloadTypeListener() {
  document.getElementById('payload-type').addEventListener('change', function () {
    document.getElementById('rebind-extra').classList.toggle('hidden', this.value !== 'rebind');
    document.getElementById('bypass-extra').classList.toggle('hidden', this.value !== 'bypass');
  });
}

async function generatePayload() {
  const type = document.getElementById('payload-type').value;
  const params = { domain: DOMAIN };

  if (type === 'rebind') {
    params.public_ip = document.getElementById('public-ip').value || '1.1.1.1';
    params.private_ip = document.getElementById('private-ip').value || '169.254.169.254';
  }
  if (type === 'bypass') {
    params.target = document.getElementById('bypass-target').value || '127.0.0.1';
  }

  try {
    const resp = await apiFetch('/api/generate', {
      method: 'POST',
      body: { type, params },
    });
    const data = await resp.json();
    if (data.error) { alert(data.error); return; }
    renderPayloads(data);

    // If rebinding, also create the rebind config on the server
    if (type === 'rebind' && data.uuid) {
      await apiFetch('/api/rebind', {
        method: 'POST',
        body: {
          uuid: data.uuid,
          public_ip: params.public_ip,
          private_ip: params.private_ip,
          switch_after: 1,
        },
      });
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

function renderPayloads(data) {
  const output = document.getElementById('payload-output');
  const list = document.getElementById('payload-list');
  document.getElementById('payload-uuid-badge').textContent = data.uuid || '';
  output.classList.remove('hidden');
  document.getElementById('interaction-detail').classList.add('hidden');

  list.innerHTML = '';

  if (data.rebind_setup) {
    const info = document.createElement('div');
    info.className = 'payload-item';
    info.innerHTML = `<div class="payload-desc"><b>Setup DNS Rebinding:</b><br>${
      Object.entries(data.rebind_setup).map(([k,v]) => `<b>${k}:</b> ${escHtml(v)}`).join('<br>')
    }</div>`;
    list.appendChild(info);
  }

  for (const p of (data.payloads || [])) {
    const item = document.createElement('div');
    item.className = 'payload-item';
    item.innerHTML = `
      <div class="payload-text" title="Click para copiar" onclick="copyText('${escHtml(p.payload)}')">${escHtml(p.payload)}</div>
      <div class="payload-desc">${escHtml(p.description)}</div>
      <div class="payload-technique">${escHtml(p.technique)}</div>
    `;
    list.appendChild(item);
  }
}

// ── Export ─────────────────────────────────────────────────────────────────
async function exportJSON() {
  const uuid = document.getElementById('filter-uuid').value.trim();
  const type = document.getElementById('filter-type').value;
  const data = filteredInteractions;
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `ssrf-box-${Date.now()}.json`);
}

async function exportCSV() {
  const uuid = document.getElementById('filter-uuid').value.trim();
  const type = document.getElementById('filter-type').value;
  let url = '/api/export?';
  if (uuid) url += 'uuid=' + encodeURIComponent(uuid) + '&';
  if (type) url += 'type=' + encodeURIComponent(type);
  window.open(url + '&apikey=' + encodeURIComponent(apiKey));
}

function downloadBlob(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

// ── Utils ──────────────────────────────────────────────────────────────────
function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function escHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function tryParseJSON(s) {
  if (!s) return null;
  try { return JSON.parse(s); } catch (_) { return s; }
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => {
    const toast = document.createElement('div');
    toast.textContent = 'Copiado';
    toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#58a6ff;color:#000;padding:6px 14px;border-radius:4px;font-size:12px;z-index:9999;';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 1500);
  });
}

// ── Init ───────────────────────────────────────────────────────────────────
if (apiKey) {
  bootstrap();
} else {
  document.getElementById('api-key-input').focus();
  document.getElementById('api-key-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') login();
  });
}
