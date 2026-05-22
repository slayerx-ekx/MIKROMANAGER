'use strict';

// ===== AUTH CHECK =====
const token = localStorage.getItem('token');
if (!token) { window.location.href = '/login'; }

// ===== API =====
async function api(path, opts = {}) {
  try {
    const res = await fetch('/api/v1' + path, {
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      ...opts
    });
    if (res.status === 401) { localStorage.clear(); window.location.href = '/login'; return null; }
    return await res.json();
  } catch (e) {
    console.error('API error:', path, e);
    return null;
  }
}

// ===== UTILS =====
let debTimer;
function debounceLoadPPP() { clearTimeout(debTimer); debTimer = setTimeout(() => loadPPP(1), 500); }

function fmtDate(d) {
  if (!d) return '-';
  try { return new Date(d).toLocaleString('id-ID', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }); }
  catch(e) { return d; }
}

function showToast(msg, type) {
  type = type || 'success';
  const t = document.getElementById('toast');
  const inner = document.getElementById('toast-inner');
  inner.className = 'toast-inner toast-' + type;
  document.getElementById('toast-icon').textContent = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
  document.getElementById('toast-msg').textContent = msg;
  t.className = '';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = 'toast-hidden'; }, 3500);
}

function doLogout() {
  if (!confirm('Yakin ingin keluar?')) return;
  localStorage.clear();
  window.location.href = '/login';
}

// ===== NAVIGATION =====
const ALL_PAGES = ['dashboard','routers','users','monitoring','traffic','ping','sync','logs'];
const PAGE_INFO = {
  dashboard: ['Dashboard','Overview sistem monitoring'],
  routers: ['Management Router','Kelola data router Mikrotik'],
  monitoring: ['PPPOE Management','Data pelanggan PPPoE berbasis interface server'],
  traffic: ['Traffic Monitor','Monitoring bandwidth realtime'],
  ping: ['Network Ping','Test konektivitas dari router'],
  sync: ['Sync Settings','Pengaturan sinkronisasi otomatis'],
  logs: ['Sync Logs','Riwayat sinkronisasi'],
  users: ['User Management','Kelola akun dan hak akses pengguna']
};

function showPage(name) {
  ALL_PAGES.forEach(function(p) {
    var el = document.getElementById('page-' + p);
    var nav = document.getElementById('nav-' + p);
    if (el) el.style.display = 'none';
    if (nav) nav.classList.remove('active');
  });
  var pg = document.getElementById('page-' + name);
  var nv = document.getElementById('nav-' + name);
  if (pg) pg.style.display = '';
  if (nv) nv.classList.add('active');
  var info = PAGE_INFO[name] || [name, ''];
  document.getElementById('page-title').textContent = info[0];
  document.getElementById('page-subtitle').textContent = info[1];

  if (name === 'dashboard') loadDashboard();
  if (name === 'routers') loadRouters();
  if (name === 'monitoring') { fillRouterSelect('f-router', true); loadPPP(1); }
  if (name === 'traffic') { fillRouterSelect('traffic-router', false); stopTraffic(); }
  if (name === 'ping') fillRouterSelect('ping-router', false);
  if (name === 'users') loadUsers();
  if (name === 'sync') loadSyncPage();
  if (name === 'logs') loadLogs();
}

// ===== DASHBOARD =====
var chartBar = null, chartDonut = null;

async function loadDashboard() {
  loadStats();
  loadRouterStatus();
  loadRecentLogs();
  loadChartData();
  loadSyncBadge();
}

async function loadStats() {
  var r = await api('/monitoring/stats');
  if (!r || !r.success) return;
  var d = r.data;
  document.getElementById('stat-total').textContent = (d.total_pelanggan || 0).toLocaleString();
  document.getElementById('stat-aktif').textContent = (d.total_aktif || 0).toLocaleString();
  document.getElementById('stat-offline').textContent = (d.total_offline || 0).toLocaleString();
  document.getElementById('stat-isolir').textContent = (d.profile_isolir || 0).toLocaleString();
  document.getElementById('donut-online').textContent = (d.total_aktif || 0).toLocaleString();
  document.getElementById('donut-offline').textContent = (d.total_offline || 0).toLocaleString();
  document.getElementById('donut-isolir').textContent = (d.profile_isolir || 0).toLocaleString();
  updateDonut(d.total_aktif || 0, d.total_offline || 0, d.profile_isolir || 0);
}

async function loadRouterStatus() {
  var r = await api('/monitoring/router-status');
  var el = document.getElementById('router-status-list');
  var badge = document.getElementById('router-count-badge');
  if (!r || !r.success || !r.data || !r.data.length) {
    el.innerHTML = '<div class="empty-state">Belum ada router aktif</div>'; return;
  }
  badge.textContent = r.data.length + ' router';
  el.innerHTML = r.data.map(function(rt) {
    return '<div style="display:flex;align-items:center;justify-content:space-between;background:#1e293b;border-radius:8px;padding:10px 12px;margin-bottom:6px">' +
      '<div style="display:flex;align-items:center;gap:10px">' +
        '<div style="width:8px;height:8px;border-radius:50%;background:' + (rt.online > 0 ? '#22c55e' : '#475569') + ';flex-shrink:0"></div>' +
        '<div><div style="font-size:13px;font-weight:500;color:#f1f5f9">' + rt.router_name + '</div>' +
        '<a href="http://' + rt.router_ip + '" target="_blank" class="link-orange">' + rt.router_ip + '</a></div>' +
      '</div>' +
      '<div style="text-align:right">' +
        '<div style="font-size:12px;color:#34d399;font-weight:500">' + (rt.online||0) + ' online</div>' +
        '<div style="font-size:11px;color:#f87171">' + (rt.offline||0) + ' offline</div>' +
        '<div style="font-size:11px;color:#fbbf24">' + (rt.isolir||0) + ' isolir</div>' +
      '</div>' +
    '</div>';
  }).join('');
}

async function loadChartData() {
  var r = await api('/monitoring/chart-data');
  if (!r || !r.success || !r.data || !r.data.length) return;
  var labels = r.data.map(function(d) { return d.router; });
  var online = r.data.map(function(d) { return d.online || 0; });
  var offline = r.data.map(function(d) { return d.offline || 0; });
  var isolir = r.data.map(function(d) { return d.isolir || 0; });
  var ctx = document.getElementById('chart-bar');
  if (!ctx) return;
  if (chartBar) { chartBar.destroy(); chartBar = null; }
  chartBar = new Chart(ctx, {
    type: 'bar',
    data: { labels: labels, datasets: [
      { label: 'Online', data: online, backgroundColor: 'rgba(16,185,129,0.8)', borderRadius: 4 },
      { label: 'Offline', data: offline, backgroundColor: 'rgba(239,68,68,0.8)', borderRadius: 4 },
      { label: 'Isolir', data: isolir, backgroundColor: 'rgba(245,158,11,0.8)', borderRadius: 4 }
    ]},
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: '#64748b', font:{size:10} }, grid: { color: '#1e293b' } },
        y: { ticks: { color: '#64748b', font:{size:10} }, grid: { color: '#1e293b' }, beginAtZero: true }
      }
    }
  });
}

function updateDonut(online, offline, isolir) {
  var ctx = document.getElementById('chart-donut');
  if (!ctx) return;
  if (chartDonut) { chartDonut.destroy(); chartDonut = null; }
  chartDonut = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: ['Online','Offline','Isolir'], datasets: [{
      data: [online, offline, isolir],
      backgroundColor: ['rgba(16,185,129,0.85)','rgba(239,68,68,0.85)','rgba(245,158,11,0.85)'],
      borderWidth: 0, hoverOffset: 4
    }]},
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '65%',
      plugins: { legend: { display: false } }
    }
  });
}

async function loadRecentLogs() {
  var r = await api('/sync/logs?limit=6');
  var el = document.getElementById('recent-logs-list');
  if (!r || !r.success || !r.data || !r.data.length) {
    el.innerHTML = '<div class="empty-state">Belum ada log</div>'; return;
  }
  el.innerHTML = r.data.map(function(log) {
    return '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid #1e293b">' +
      '<div style="display:flex;align-items:center;gap:10px">' +
        '<div style="width:7px;height:7px;border-radius:50%;flex-shrink:0;background:' + (log.status==='success'?'#22c55e':'#ef4444') + '"></div>' +
        '<div><div style="font-size:13px;font-weight:500;color:#f1f5f9">' + (log.router_name||'All Routers') + '</div>' +
        '<div style="font-size:11px;color:#64748b">' + (log.message||'') + '</div></div>' +
      '</div>' +
      '<div style="text-align:right;flex-shrink:0;margin-left:12px">' +
        '<div style="font-size:11px;color:#94a3b8">' + fmtDate(log.created_at) + '</div>' +
        '<div style="font-size:11px;color:' + (log.status==='success'?'#34d399':'#f87171') + '">' + log.duration_ms + 'ms</div>' +
      '</div>' +
    '</div>';
  }).join('');
}

async function loadSyncBadge() {
  var r = await api('/sync/status');
  if (!r || !r.success) return;
  var d = r.data;
  var badge = document.getElementById('sync-badge');
  if (d.auto_sync_enabled) {
    badge.textContent = 'ON';
    badge.style.background = 'rgba(16,185,129,0.15)'; badge.style.color = '#34d399'; badge.style.border = '1px solid rgba(16,185,129,0.3)';
  } else {
    badge.textContent = 'OFF';
    badge.style.background = 'rgba(100,116,139,0.15)'; badge.style.color = '#94a3b8'; badge.style.border = '1px solid rgba(100,116,139,0.3)';
  }
  document.getElementById('last-sync-sidebar').textContent = d.last_sync_at ? fmtDate(d.last_sync_at) : 'Belum sync';
}

// Dashboard card click
function filterAndGo(type) {
  showPage('monitoring');
  setTimeout(function() {
    document.getElementById('f-router').value = '';
    document.getElementById('f-status').value = type === 'online' ? 'online' : type === 'offline' ? 'offline' : '';
    document.getElementById('f-profile').value = type === 'isolir' ? 'ISOLIR' : '';
    document.getElementById('f-search').value = '';
    var badge = document.getElementById('filter-badge-row');
    var label = document.getElementById('filter-label');
    var live = document.getElementById('live-indicator');
    if (type) {
      var labels = { online:'🟢 Filter: Status Online', offline:'🔴 Filter: Status Offline', isolir:'🔒 Filter: Profile ISOLIR' };
      label.textContent = labels[type] || '';
      badge.style.display = 'flex';
      live.style.display = 'flex';
    } else {
      badge.style.display = 'none';
      live.style.display = 'none';
    }
    loadPPP(1);
  }, 80);
}

// ===== ROUTERS =====
async function loadRouters() {
  var r = await api('/routers');
  var tbody = document.getElementById('routers-tbody');
  if (!r || !r.success || !r.data || !r.data.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Belum ada router. Tambahkan router baru.</td></tr>'; return;
  }
  tbody.innerHTML = r.data.map(function(rt, i) {
    return '<tr>' +
      '<td style="color:#64748b">' + (i+1) + '</td>' +
      '<td style="font-weight:600;color:#f1f5f9">' + rt.name + '</td>' +
      '<td><a href="http://' + rt.ip_address + '" target="_blank" class="link-orange">' + rt.ip_address + '</a></td>' +
      '<td style="color:#cbd5e1">' + rt.username + '</td>' +
      '<td style="color:#94a3b8;font-family:monospace">' + rt.api_port + '</td>' +
      '<td style="color:#94a3b8;font-size:12px">' + (rt.email||'-') + '</td>' +
      '<td><span class="badge ' + (rt.is_active?'badge-active':'badge-inactive') + '">' + (rt.is_active?'Active':'Inactive') + '</span></td>' +
      '<td><div class="gap-row">' +
        '<button class="btn btn-blue btn-sm" onclick="openRouterModal(' + rt.id + ')">✏ Edit</button>' +
        '<button class="btn btn-green btn-sm" onclick="testRouter(' + rt.id + ')">⚡ Test</button>' +
        '<button class="btn btn-purple btn-sm" onclick="syncOneRouter(' + rt.id + ')">↻ Sync</button>' +
        '<button class="btn btn-red btn-sm" onclick="deleteRouter(' + rt.id + ',\'' + rt.name.replace(/'/g,"\\'") + '\')">✕ Hapus</button>' +
      '</div></td>' +
    '</tr>';
  }).join('');
}

function openRouterModal(id) {
  document.getElementById('router-id').value = id || '';
  document.getElementById('router-name').value = '';
  document.getElementById('router-ip').value = '';
  document.getElementById('router-port').value = '8728';
  document.getElementById('router-username').value = '';
  document.getElementById('router-password').value = '';
  document.getElementById('router-email').value = '';
  document.getElementById('router-desc').value = '';
  document.getElementById('modal-title').textContent = id ? 'Edit Router' : 'Tambah Router Baru';
  if (id) {
    api('/routers/' + id).then(function(r) {
      if (!r || !r.success) return;
      var d = r.data;
      document.getElementById('router-name').value = d.name || '';
      document.getElementById('router-ip').value = d.ip_address || '';
      document.getElementById('router-port').value = d.api_port || 8728;
      document.getElementById('router-username').value = d.username || '';
      document.getElementById('router-email').value = d.email || '';
      document.getElementById('router-desc').value = d.description || '';
    });
  }
  document.getElementById('router-modal').classList.add('show');
}

function closeRouterModal() { document.getElementById('router-modal').classList.remove('show'); }
function handleModalClick(e) { if (e.target === document.getElementById('router-modal')) closeRouterModal(); }

async function saveRouter() {
  var id = document.getElementById('router-id').value;
  var data = {
    name: document.getElementById('router-name').value.trim(),
    ip_address: document.getElementById('router-ip').value.trim(),
    api_port: parseInt(document.getElementById('router-port').value) || 8728,
    username: document.getElementById('router-username').value.trim(),
    password: document.getElementById('router-password').value,
    email: document.getElementById('router-email').value.trim(),
    description: document.getElementById('router-desc').value.trim(),
    is_active: true
  };
  if (!data.name || !data.ip_address || !data.username) { showToast('Nama, IP, Username wajib diisi!', 'error'); return; }
  if (!id && !data.password) { showToast('Password wajib untuk router baru!', 'error'); return; }
  var r = id
    ? await api('/routers/' + id, { method: 'PUT', body: JSON.stringify(data) })
    : await api('/routers', { method: 'POST', body: JSON.stringify(data) });
  if (r && r.success) { showToast(id ? 'Router diupdate!' : 'Router ditambahkan!'); closeRouterModal(); loadRouters(); }
  else showToast((r && r.message) || 'Gagal menyimpan', 'error');
}

async function deleteRouter(id, name) {
  if (!confirm('Hapus router "' + name + '"? Semua data terkait dihapus.')) return;
  var r = await api('/routers/' + id, { method: 'DELETE' });
  if (r && r.success) { showToast('Router dihapus'); loadRouters(); }
  else showToast('Gagal hapus', 'error');
}

async function testRouter(id) {
  showToast('Testing koneksi...', 'info');
  var r = await api('/routers/' + id + '/test', { method: 'POST' });
  if (r && r.success) showToast('Koneksi berhasil! ✓');
  else showToast('Koneksi gagal: ' + ((r && r.message) || ''), 'error');
}

async function syncOneRouter(id) {
  showToast('Sync router...', 'info');
  var r = await api('/routers/' + id + '/sync', { method: 'POST' });
  if (r && r.success) { showToast('Sync berhasil!'); loadDashboard(); }
  else showToast('Sync gagal: ' + ((r && r.message) || ''), 'error');
}

// ===== FILL ROUTER SELECT =====
async function fillRouterSelect(elId, addAll) {
  var r = await api('/routers');
  if (!r || !r.success) return;
  var el = document.getElementById(elId);
  if (!el) return;
  var opts = addAll ? '<option value="">Semua Router</option>' : '<option value="">-- Pilih Router --</option>';
  opts += (r.data || []).map(function(rt) {
    return '<option value="' + rt.id + '">' + rt.name + ' (' + rt.ip_address + ')</option>';
  }).join('');
  el.innerHTML = opts;
}

// ===== PPP MONITORING =====
async function loadPPP(page) {
  page = page || 1;
  var params = new URLSearchParams({
    page: page, limit: 25,
    router_id: document.getElementById('f-router').value || '',
    status: document.getElementById('f-status').value || '',
    profile: document.getElementById('f-profile').value || '',
    search: document.getElementById('f-search').value || ''
  });
  var r = await api('/monitoring/secrets?' + params.toString());
  var tbody = document.getElementById('ppp-tbody');
  if (!r || !r.success) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state" style="color:#f87171">Gagal memuat data</td></tr>'; return;
  }
  var d = r.data;
  document.getElementById('ppp-total-info').textContent = 'Total: ' + (d.total || 0).toLocaleString();
  if (!d.data || !d.data.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state">Tidak ada data. Lakukan sync dahulu.</td></tr>';
    document.getElementById('ppp-page-info').textContent = '';
    document.getElementById('ppp-pagination').innerHTML = '';
    return;
  }
  var start = (d.page - 1) * d.limit + 1;
  tbody.innerHTML = d.data.map(function(u, i) {
    var isIsolir = u.profile && u.profile.toUpperCase().indexOf('ISOLIR') >= 0;
    var statusBadge = u.status === 'online'
      ? '<span class="badge badge-online">ONLINE</span>'
      : '<span class="badge badge-offline">OFFLINE</span>';
    if (isIsolir) statusBadge += ' <span class="badge badge-isolir" style="margin-left:3px">ISOLIR</span>';
    var pingBtn = u.ip_address
      ? '<button class="btn btn-secondary btn-sm" onclick="quickPing(\'' + u.ip_address + '\',' + (u.router_id||0) + ')">⚡ Ping</button>'
      : '<button class="btn btn-secondary btn-sm" disabled>⚡ Ping</button>';
    var ontBtn = u.ip_address
      ? '<button class="btn-ont" onclick="remoteONT(\'' + u.ip_address + '\')" title="Buka remote ONT di tab baru"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>Remote ONT</button>'
      : '';
    return '<tr>' +
      '<td style="color:#64748b">' + (start+i) + '</td>' +
      '<td style="font-weight:500;color:#f1f5f9">' + u.username + '</td>' +
      '<td style="font-family:monospace;font-size:12px">' + 
        (u.ip_address ? '<span style="color:#fb923c">' + u.ip_address + '</span>' : '<span style="color:#475569">-</span>') + 
      '</td>' +
      '<td style="font-family:monospace;font-size:12px;color:#94a3b8">' + (u.uptime||'-') + '</td>' +
      '<td style="color:#cbd5e1">' + (u.router_name||'-') + '</td>' +
      '<td><a href="http://' + u.router_ip + '" target="_blank" class="link-orange">' + (u.router_ip||'-') + '</a></td>' +
      '<td style="font-size:12px;color:#94a3b8">' + (u.profile||'-') + '</td>' +
      '<td>' + statusBadge + '</td>' +
      '<td><div class="gap-row">' + pingBtn + ' ' + ontBtn + '</div></td>' +
    '</tr>';
  }).join('');
  var end = Math.min(start + d.limit - 1, d.total);
  document.getElementById('ppp-page-info').textContent = start + '–' + end + ' of ' + d.total.toLocaleString();
  renderPagination('ppp-pagination', d.total_pages, d.page, loadPPP);
}

function clearFilters() {
  document.getElementById('f-router').value = '';
  document.getElementById('f-status').value = '';
  document.getElementById('f-profile').value = '';
  document.getElementById('f-search').value = '';
  document.getElementById('filter-badge-row').style.display = 'none';
  document.getElementById('live-indicator').style.display = 'none';
  loadPPP(1);
}

// ===== PAGINATION =====
function renderPagination(id, total, current, fn) {
  var el = document.getElementById(id);
  if (!el) return;
  if (total <= 1) { el.innerHTML = ''; return; }
  var html = '<button class="page-btn" onclick="' + fn.name + '(' + (current-1) + ')" ' + (current<=1?'disabled':'') + '>‹</button>';
  var s = Math.max(1, current-2), e = Math.min(total, s+4);
  if (e-s < 4) s = Math.max(1, e-4);
  for (var i=s; i<=e; i++) {
    html += '<button class="page-btn ' + (i===current?'active':'') + '" onclick="' + fn.name + '(' + i + ')">' + i + '</button>';
  }
  html += '<button class="page-btn" onclick="' + fn.name + '(' + (current+1) + ')" ' + (current>=total?'disabled':'') + '>›</button>';
  el.innerHTML = html;
}

// ===== TRAFFIC =====
var trafficTimer = null, trafficRunning = false, trafficChart = null;
var trafficHistory = {}, selectedIface = null;

function toggleTraffic() {
  if (trafficRunning) stopTraffic(); else startTraffic();
}

function startTraffic() {
  var routerId = document.getElementById('traffic-router').value;
  if (!routerId) { showToast('Pilih router dahulu!', 'error'); return; }
  stopTraffic();
  trafficRunning = true;
  var btn = document.getElementById('traffic-btn');
  btn.className = 'btn btn-red';
  btn.innerHTML = '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:14px;height:14px"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z"/></svg> Stop Monitor';
  fetchTraffic();
  var interval = parseInt(document.getElementById('traffic-interval').value) || 5000;
  trafficTimer = setInterval(fetchTraffic, interval);
}

function stopTraffic() {
  if (trafficTimer) { clearInterval(trafficTimer); trafficTimer = null; }
  trafficRunning = false;
  var btn = document.getElementById('traffic-btn');
  if (btn) {
    btn.className = 'btn btn-green';
    btn.innerHTML = '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:14px;height:14px"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> Start Monitor';
  }
}

async function fetchTraffic() {
  var routerId = document.getElementById('traffic-router').value;
  if (!routerId) return;
  var r = await api('/traffic/' + routerId + '/live');
  if (!r || !r.success || !r.data) return;
  var data = r.data || [];
  var container = document.getElementById('traffic-cards');
  if (!data.length) {
    container.innerHTML = '<div class="panel" style="grid-column:1/-1"><div class="empty-state">Tidak ada interface aktif</div></div>'; return;
  }
  data.forEach(function(d) {
    if (!trafficHistory[d.interface_name]) trafficHistory[d.interface_name] = { rx:[], tx:[], labels:[] };
    var h = trafficHistory[d.interface_name];
    var now = new Date().toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    h.rx.push(d.rx_bps/1000000);
    h.tx.push(d.tx_bps/1000000);
    h.labels.push(now);
    if (h.rx.length > 60) { h.rx.shift(); h.tx.shift(); h.labels.shift(); }
  });
  container.innerHTML = data.map(function(d) {
    var rxPct = Math.min((d.rx_bps/100000000)*100,100).toFixed(1);
    var txPct = Math.min((d.tx_bps/100000000)*100,100).toFixed(1);
    var isSelected = selectedIface === d.interface_name;
    return '<div class="traffic-card ' + (isSelected?'selected':'') + '" onclick="selectIface(\'' + d.interface_name.replace(/'/g,"\\'") + '\')">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">' +
        '<div style="font-weight:600;font-size:14px;color:#f1f5f9;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + d.interface_name + '</div>' +
        '<span class="live-dot" style="width:7px;height:7px;flex-shrink:0"></span>' +
      '</div>' +
      '<div style="margin-bottom:10px">' +
        '<div style="display:flex;justify-content:space-between;margin-bottom:4px">' +
          '<span style="font-size:12px;color:#64748b">↓ Download (RX)</span>' +
          '<span style="font-size:12px;font-weight:700;color:#34d399;font-family:monospace">' + d.rx_human + '</span>' +
        '</div>' +
        '<div class="progress-bar"><div class="progress-fill" style="width:' + rxPct + '%;background:#10b981"></div></div>' +
      '</div>' +
      '<div>' +
        '<div style="display:flex;justify-content:space-between;margin-bottom:4px">' +
          '<span style="font-size:12px;color:#64748b">↑ Upload (TX)</span>' +
          '<span style="font-size:12px;font-weight:700;color:#fb923c;font-family:monospace">' + d.tx_human + '</span>' +
        '</div>' +
        '<div class="progress-bar"><div class="progress-fill" style="width:' + txPct + '%;background:#f97316"></div></div>' +
      '</div>' +
      '<div style="font-size:11px;color:#475569;text-align:center;margin-top:8px">Klik untuk lihat grafik</div>' +
    '</div>';
  }).join('');
  if (selectedIface && trafficHistory[selectedIface]) updateTrafficChart(selectedIface);
}

function selectIface(name) {
  selectedIface = name;
  document.getElementById('traffic-chart-panel').style.display = '';
  document.getElementById('traffic-iface-name').textContent = name;
  updateTrafficChart(name);
}

function updateTrafficChart(name) {
  var h = trafficHistory[name];
  if (!h) return;
  var ctx = document.getElementById('traffic-chart');
  if (trafficChart) {
    trafficChart.data.labels = h.labels;
    trafficChart.data.datasets[0].data = h.rx;
    trafficChart.data.datasets[1].data = h.tx;
    trafficChart.update('none'); return;
  }
  trafficChart = new Chart(ctx, {
    type: 'line',
    data: { labels: h.labels, datasets: [
      { label:'Download (Mbps)', data:h.rx, borderColor:'#10b981', backgroundColor:'rgba(16,185,129,0.1)', fill:true, tension:0.4, pointRadius:0, borderWidth:2 },
      { label:'Upload (Mbps)', data:h.tx, borderColor:'#f97316', backgroundColor:'rgba(249,115,22,0.1)', fill:true, tension:0.4, pointRadius:0, borderWidth:2 }
    ]},
    options: {
      responsive:true, maintainAspectRatio:false, animation:false,
      plugins:{ legend:{ labels:{ color:'#94a3b8', font:{size:11} } } },
      scales:{
        x:{ ticks:{ color:'#64748b', font:{size:10}, maxTicksLimit:8 }, grid:{ color:'#1e293b' } },
        y:{ ticks:{ color:'#64748b', font:{size:10}, callback:function(v){return v.toFixed(1)+' Mbps'} }, grid:{ color:'#1e293b' }, beginAtZero:true }
      }
    }
  });
}

// ===== PING =====
async function doPing() {
  var routerId = document.getElementById('ping-router').value;
  var target = document.getElementById('ping-target').value.trim();
  var count = parseInt(document.getElementById('ping-count').value) || 4;
  if (!routerId) { showToast('Pilih router dahulu!', 'error'); return; }
  if (!target) { showToast('Masukkan target!', 'error'); return; }
  var btn = document.getElementById('ping-btn');
  var result = document.getElementById('ping-result');
  var output = document.getElementById('ping-output');
  var summary = document.getElementById('ping-summary');
  btn.disabled = true; btn.textContent = 'Pinging...';
  result.style.display = '';
  output.innerHTML = '<span class="ping-info">Mengirim ping ke ' + target + '...</span>';
  var r = await api('/noc/ping/' + routerId, { method:'POST', body: JSON.stringify({target:target, count:count}) });
  btn.disabled = false;
  btn.innerHTML = '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:14px;height:14px"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/></svg> Jalankan Ping';
  if (!r || !r.success) {
    output.innerHTML = '<span class="ping-fail">Ping gagal: ' + ((r&&r.message)||'Unknown error') + '</span>'; return;
  }
  var results = r.data || [];
  var sent=0, recv=0, totalMs=0;
  output.innerHTML = results.map(function(res) {
    sent++;
    if (res['status'] === 'timeout') return '<div class="ping-fail">Request timeout</div>';
    recv++;
    var ms = res['time'] || res['avg-rtt'] || '0';
    totalMs += parseFloat(ms) || 0;
    return '<div class="ping-ok">' + target + ': bytes=' + (res['size']||64) + ' time=' + ms + 'ms TTL=' + (res['ttl']||64) + '</div>';
  }).join('');
  var loss = sent > 0 ? Math.round(((sent-recv)/sent)*100) : 100;
  var avg = recv > 0 ? (totalMs/recv).toFixed(1) : 0;
  summary.innerHTML = '<span style="color:' + (loss===0?'#34d399':'#f87171') + '">' + recv + '/' + sent + ' received, ' + loss + '% loss, avg ' + avg + 'ms</span>';
}

function quickPing(ip, routerId) {
  showPage('ping');
  setTimeout(function() {
    if (routerId) document.getElementById('ping-router').value = routerId;
    document.getElementById('ping-target').value = ip;
  }, 150);
}

document.getElementById('ping-target') && document.getElementById('ping-target').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') doPing();
});

// ===== SYNC =====
async function triggerSync() {
  var badge = document.getElementById('syncing-badge');
  badge.style.display = 'flex';
  var r = await api('/sync/all', { method: 'POST' });
  if (r && r.success) {
    showToast('Sinkronisasi dimulai...');
    setTimeout(function() { badge.style.display = 'none'; loadDashboard(); }, 8000);
  } else {
    badge.style.display = 'none';
    showToast((r&&r.message)||'Sync gagal', 'error');
  }
}

async function loadSyncPage() {
  var r = await api('/sync/settings');
  if (!r || !r.success) return;
  document.getElementById('auto-sync-cb').checked = r.data.auto_sync_enabled;
  document.getElementById('sync-interval').value = r.data.sync_interval_seconds;
  var sr = await api('/sync/status');
  if (sr && sr.success) {
    var sd = sr.data;
    document.getElementById('sync-status-txt').textContent = sd.auto_sync_enabled ? 'Auto (setiap ' + sd.sync_interval_seconds + 'd)' : 'Manual';
    document.getElementById('sync-last-txt').textContent = fmtDate(sd.last_sync_at);
  }
}

async function saveSyncSettings() {
  var data = {
    auto_sync_enabled: document.getElementById('auto-sync-cb').checked,
    sync_interval_seconds: parseInt(document.getElementById('sync-interval').value) || 60
  };
  var r = await api('/sync/settings', { method: 'PUT', body: JSON.stringify(data) });
  if (r && r.success) { showToast('Pengaturan disimpan!'); loadSyncBadge(); }
  else showToast('Gagal menyimpan', 'error');
}

async function loadLogs() {
  var r = await api('/sync/logs?limit=100');
  var el = document.getElementById('logs-list');
  if (!r || !r.success || !r.data || !r.data.length) {
    el.innerHTML = '<div class="empty-state">Belum ada log</div>'; return;
  }
  el.innerHTML = r.data.map(function(log) {
    return '<div style="display:flex;align-items:flex-start;justify-content:space-between;padding:12px 18px;border-bottom:1px solid #1e293b">' +
      '<div style="display:flex;align-items:flex-start;gap:10px">' +
        '<div style="width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-top:4px;background:' + (log.status==='success'?'#22c55e':'#ef4444') + '"></div>' +
        '<div>' +
          '<div style="display:flex;align-items:center;gap:6px">' +
            '<span style="font-size:13px;font-weight:500;color:#f1f5f9">' + (log.router_name||'All Routers') + '</span>' +
            '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:' + (log.status==='success'?'rgba(16,185,129,0.15)':'rgba(239,68,68,0.15)') + ';color:' + (log.status==='success'?'#34d399':'#f87171') + '">' + log.status + '</span>' +
          '</div>' +
          '<div style="font-size:12px;color:#64748b;margin-top:2px">' + (log.message||'') + '</div>' +
        '</div>' +
      '</div>' +
      '<div style="text-align:right;flex-shrink:0;margin-left:12px">' +
        '<div style="font-size:12px;color:#94a3b8">' + fmtDate(log.created_at) + '</div>' +
        '<div style="font-size:11px;color:#64748b;font-family:monospace">' + log.duration_ms + 'ms · ' + log.records_synced + ' rec</div>' +
      '</div>' +
    '</div>';
  }).join('');
}

// ===== INIT =====
document.addEventListener('DOMContentLoaded', function() {
  var username = localStorage.getItem('username') || 'Admin';
  var fullName = localStorage.getItem('full_name') || username;
  var role = localStorage.getItem('role') || 'operator';
  document.getElementById('sidebar-name').textContent = fullName || username;
  document.getElementById('sidebar-role').textContent = role;
  document.getElementById('user-avatar').textContent = (username[0] || 'A').toUpperCase();

  applyRoleAccess();
  showPage('dashboard');

  setInterval(function() {
    var active = document.querySelector('.nav-link.active');
    var page = active ? active.id.replace('nav-','') : '';
    if (page === 'dashboard') { loadStats(); loadSyncBadge(); }
  }, 30000);
});

// ===== ROLE-BASED ACCESS CONTROL =====
const ROLE_ACCESS = {
  'super_admin': ['dashboard','routers','users','monitoring','traffic','ping','sync','logs'],
  'admin':       ['dashboard','routers','monitoring','traffic','ping','sync','logs'],
  'teknisi':     ['dashboard','monitoring','traffic','ping','logs'],
  'viewer':      ['dashboard','monitoring']
};

function applyRoleAccess() {
  var role = localStorage.getItem('role') || 'viewer';
  var allowed = ROLE_ACCESS[role] || ['dashboard','monitoring'];
  
  // Show/hide nav items
  var navMap = {
    'users': 'nav-users',
    'routers': 'nav-routers', 
    'traffic': 'nav-traffic',
    'ping': 'nav-ping',
    'sync': 'nav-sync',
    'logs': 'nav-logs'
  };
  
  Object.keys(navMap).forEach(function(page) {
    var navEl = document.getElementById(navMap[page]);
    if (!navEl) return;
    if (allowed.indexOf(page) >= 0) {
      navEl.style.display = '';
    } else {
      navEl.style.display = 'none';
    }
  });
}

// ===== USER MANAGEMENT =====
var roleColors = {
  'super_admin': '#7c3aed',
  'admin': '#1d4ed8', 
  'teknisi': '#059669',
  'viewer': '#475569'
};

function getRoleBadge(role) {
  return '<span class="badge role-' + role + '">' + role + '</span>';
}

async function loadUsers() {
  var r = await api('/users');
  var tbody = document.getElementById('users-tbody');
  if (!r || !r.success) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state" style="color:#f87171">Akses ditolak atau gagal memuat</td></tr>';
    return;
  }
  if (!r.data || !r.data.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Belum ada user</td></tr>';
    return;
  }
  var myId = parseInt(localStorage.getItem('user_id')) || 0;
  tbody.innerHTML = r.data.map(function(u) {
    var avatarColor = roleColors[u.role] || '#475569';
    var isSelf = u.id === myId;
    var actions = '<div class="gap-row">' +
      '<button class="btn btn-blue btn-sm" onclick="openUserModal(' + u.id + ')">✏ Edit</button>' +
      '<button class="btn btn-purple btn-sm" onclick="openChpassModal(' + u.id + ',' + isSelf + ')">🔑 Password</button>';
    if (!isSelf) {
      actions += '<button class="btn btn-red btn-sm" onclick="deleteUser(' + u.id + ',\'' + u.username + '\')">✕ Hapus</button>';
    }
    actions += '</div>';
    return '<tr>' +
      '<td><div style="display:flex;align-items:center;gap:10px">' +
        '<div class="avatar-circle" style="background:' + avatarColor + '">' + (u.username[0]||'?').toUpperCase() + '</div>' +
        '<span style="font-weight:500;color:#f1f5f9">' + (u.full_name || u.username) + '</span>' +
        (isSelf ? ' <span style="font-size:10px;background:rgba(234,88,12,0.2);color:#fb923c;padding:1px 6px;border-radius:8px">You</span>' : '') +
      '</div></td>' +
      '<td style="font-family:monospace;color:#94a3b8">' + u.username + '</td>' +
      '<td>' + getRoleBadge(u.role) + '</td>' +
      '<td><span class="badge ' + (u.is_active ? 'badge-online' : 'badge-offline') + '">' + (u.is_active ? 'Active' : 'Inactive') + '</span></td>' +
      '<td style="font-size:12px;color:#64748b">' + (u.last_login ? fmtDate(u.last_login) : 'Belum pernah') + '</td>' +
      '<td>' + actions + '</td>' +
    '</tr>';
  }).join('');
}

function openUserModal(id) {
  document.getElementById('user-id').value = id || '';
  document.getElementById('user-fullname').value = '';
  document.getElementById('user-username').value = '';
  document.getElementById('user-role').value = 'teknisi';
  document.getElementById('user-status').value = '1';
  document.getElementById('user-password').value = '';
  document.getElementById('user-modal-title').textContent = id ? 'Edit User' : 'Tambah User Baru';
  // Password required only for new user
  var pwLabel = document.querySelector('#user-password-section .form-label');
  if (pwLabel) pwLabel.textContent = id ? 'Password (kosongkan jika tidak diubah) — gunakan menu Ganti Password' : 'Password *';
  document.getElementById('user-password-section').style.display = id ? 'none' : '';
  
  if (id) {
    api('/users').then(function(r) {
      if (!r || !r.success) return;
      var u = (r.data || []).find(function(x) { return x.id === id; });
      if (!u) return;
      document.getElementById('user-fullname').value = u.full_name || '';
      document.getElementById('user-username').value = u.username || '';
      document.getElementById('user-role').value = u.role || 'teknisi';
      document.getElementById('user-status').value = u.is_active ? '1' : '0';
    });
  }
  document.getElementById('user-modal').classList.add('show');
}

function closeUserModal() { document.getElementById('user-modal').classList.remove('show'); }
function handleUserModalClick(e) { if (e.target === document.getElementById('user-modal')) closeUserModal(); }

async function saveUser() {
  var id = document.getElementById('user-id').value;
  var username = document.getElementById('user-username').value.trim();
  var fullName = document.getElementById('user-fullname').value.trim();
  var role = document.getElementById('user-role').value;
  var isActive = document.getElementById('user-status').value === '1';
  var password = document.getElementById('user-password').value;

  if (!username) { showToast('Username wajib diisi!', 'error'); return; }
  if (!id && !password) { showToast('Password wajib untuk user baru!', 'error'); return; }
  if (!id && password.length < 6) { showToast('Password minimal 6 karakter!', 'error'); return; }

  var r;
  if (id) {
    r = await api('/users/' + id, { method: 'PUT', body: JSON.stringify({ username, full_name: fullName, role, is_active: isActive }) });
  } else {
    r = await api('/users', { method: 'POST', body: JSON.stringify({ username, password, full_name: fullName, role }) });
  }
  
  if (r && r.success) {
    showToast(id ? 'User diupdate!' : 'User ditambahkan!');
    closeUserModal();
    loadUsers();
  } else {
    showToast((r && r.message) || 'Gagal menyimpan', 'error');
  }
}

function openChpassModal(userId, isSelf) {
  document.getElementById('chpass-userid').value = userId;
  document.getElementById('chpass-old').value = '';
  document.getElementById('chpass-new').value = '';
  document.getElementById('chpass-confirm').value = '';
  // Show old password only if changing own password
  document.getElementById('chpass-old-wrap').style.display = isSelf ? '' : 'none';
  document.getElementById('chpass-modal').classList.add('show');
}

async function doChangePassword() {
  var userId = document.getElementById('chpass-userid').value;
  var oldPass = document.getElementById('chpass-old').value;
  var newPass = document.getElementById('chpass-new').value;
  var confirm = document.getElementById('chpass-confirm').value;
  
  if (!newPass || newPass.length < 6) { showToast('Password minimal 6 karakter!', 'error'); return; }
  if (newPass !== confirm) { showToast('Konfirmasi password tidak cocok!', 'error'); return; }
  
  var body = { new_password: newPass };
  if (oldPass) body.old_password = oldPass;
  
  var r = await api('/users/' + userId + '/password', { method: 'PUT', body: JSON.stringify(body) });
  if (r && r.success) {
    showToast('Password berhasil diubah!');
    document.getElementById('chpass-modal').classList.remove('show');
  } else {
    showToast((r && r.message) || 'Gagal mengubah password', 'error');
  }
}

async function deleteUser(id, username) {
  if (!confirm('Hapus user "' + username + '"?')) return;
  var r = await api('/users/' + id, { method: 'DELETE' });
  if (r && r.success) { showToast('User dihapus'); loadUsers(); }
  else showToast((r && r.message) || 'Gagal hapus', 'error');
}

// ===== REMOTE ONT =====
// remoteONT replaced by proxy version below


// ===== ONT REMOTE PROXY =====
var currentONTip = null;
var ontHistory = [];
var ontHistoryIndex = -1;

async function remoteONT(ip) {
  if (!ip || ip === '-' || ip === '') {
    showToast('IP Address tidak tersedia', 'error');
    return;
  }
  currentONTip = ip;
  ontHistory = [];
  ontHistoryIndex = -1;

  // Show modal
  var modal = document.getElementById('ont-modal');
  modal.classList.add('show');
  document.getElementById('ont-modal-title').textContent = 'Remote ONT — ' + ip;
  document.getElementById('ont-modal-subtitle').textContent = ip;
  document.getElementById('ont-url-display').textContent = 'http://' + ip + '/';
  document.getElementById('ont-info-badges').innerHTML = '';

  // Test reachability first
  showONTLoading('Memeriksa koneksi ke ' + ip + '...');

  var testRes = await api('/ont/test?target=' + encodeURIComponent(ip));
  if (!testRes || !testRes.success) {
    showONTError(testRes ? testRes.message : 'Tidak dapat terhubung ke ONT');
    return;
  }

  // Load via proxy
  loadONTPage('/');
}

function loadONTPage(path) {
  if (!currentONTip) return;
  showONTLoading('Memuat halaman...');

  var proxyUrl = '/api/v1/ont/proxy?target=' + encodeURIComponent(currentONTip) + '&path=' + encodeURIComponent(path);
  document.getElementById('ont-url-display').textContent = 'http://' + currentONTip + path;

  // Use iframe with proxy URL
  var iframe = document.getElementById('ont-iframe');
  iframe.style.display = 'none';

  // Fetch content via proxy and inject into iframe
  fetch(proxyUrl, {
    headers: { 'Authorization': 'Bearer ' + token }
  })
  .then(function(r) {
    var contentType = r.headers.get('content-type') || '';
    if (contentType.includes('text/html')) {
      return r.text().then(function(html) {
        return { type: 'html', content: html };
      });
    } else {
      return { type: 'other', url: proxyUrl };
    }
  })
  .then(function(data) {
    hideONTLoading();
    hideONTError();
    iframe.style.display = '';

    if (data.type === 'html') {
      // Inject into iframe
      var iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
      
      // Rewrite links to go through proxy
      var processedHtml = injectONTProxy(data.content, currentONTip);
      
      iframeDoc.open();
      iframeDoc.write(processedHtml);
      iframeDoc.close();

      // Add to history
      if (ontHistoryIndex < 0 || ontHistory[ontHistoryIndex] !== path) {
        ontHistory = ontHistory.slice(0, ontHistoryIndex + 1);
        ontHistory.push(path);
        ontHistoryIndex = ontHistory.length - 1;
      }

      // Update status
      document.getElementById('ont-status-dot').style.background = '#22c55e';
      document.getElementById('ont-modal-subtitle').textContent = 'Terhubung — ' + currentONTip;
      document.getElementById('ont-info-badges').innerHTML =
        '<span style="font-size:11px;background:rgba(14,165,233,0.1);color:#38bdf8;border:1px solid rgba(14,165,233,0.2);padding:2px 8px;border-radius:10px">🔌 ONT Online</span>';

    } else {
      iframe.src = data.url;
    }
  })
  .catch(function(err) {
    showONTError('Gagal memuat halaman: ' + err.message);
  });
}

function injectONTProxy(html, ip) {
  var base = '/api/v1/ont/proxy?target=' + encodeURIComponent(ip) + '&path=';
  var authToken = token;

  // Inject a script to intercept all link clicks and form submissions
  var injectedScript = `
<base href="http://` + ip + `/">
<script>
(function() {
  var PROXY_BASE = '` + base + `';
  var TOKEN = '` + authToken + `';
  
  function proxyPath(url) {
    if (!url) return url;
    try {
      if (url.startsWith('http://` + ip + `')) {
        return PROXY_BASE + encodeURIComponent(url.replace('http://` + ip + `', ''));
      }
      if (url.startsWith('/')) {
        return PROXY_BASE + encodeURIComponent(url);
      }
    } catch(e) {}
    return url;
  }
  
  // Intercept clicks
  document.addEventListener('click', function(e) {
    var a = e.target.closest('a');
    if (a && a.href) {
      e.preventDefault();
      var path = '';
      try {
        var u = new URL(a.href);
        path = u.pathname + u.search;
      } catch(ex) {
        path = a.getAttribute('href');
      }
      if (path && !path.startsWith('javascript')) {
        parent.postMessage({ type: 'ONT_NAV', path: path }, '*');
      }
    }
  }, true);
  
  // Intercept forms
  document.addEventListener('submit', function(e) {
    var form = e.target;
    if (form) {
      e.preventDefault();
      var action = form.getAttribute('action') || '/';
      var method = (form.method || 'GET').toUpperCase();
      var formData = new FormData(form);
      var params = new URLSearchParams(formData).toString();
      
      if (method === 'GET') {
        parent.postMessage({ type: 'ONT_NAV', path: action + (params ? '?' + params : '') }, '*');
      } else {
        parent.postMessage({ type: 'ONT_FORM', action: action, data: params }, '*');
      }
    }
  }, true);
})();
<\/script>`;

  // Insert after <head> or at beginning
  if (html.includes('<head>')) {
    html = html.replace('<head>', '<head>' + injectedScript);
  } else if (html.includes('<html>')) {
    html = html.replace('<html>', '<html>' + injectedScript);
  } else {
    html = injectedScript + html;
  }

  return html;
}

// Listen for messages from iframe
window.addEventListener('message', function(e) {
  if (!e.data) return;
  if (e.data.type === 'ONT_NAV') {
    loadONTPage(e.data.path);
  } else if (e.data.type === 'ONT_FORM') {
    ontSubmitForm(e.data.action, e.data.data);
  }
});

async function ontSubmitForm(action, formData) {
  if (!currentONTip) return;
  showONTLoading('Mengirim data...');
  var proxyUrl = '/api/v1/ont/proxy?target=' + encodeURIComponent(currentONTip) + '&path=' + encodeURIComponent(action);
  
  var r = await fetch(proxyUrl, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: formData
  });
  
  var contentType = r.headers.get('content-type') || '';
  if (contentType.includes('text/html')) {
    var html = await r.text();
    hideONTLoading();
    var iframe = document.getElementById('ont-iframe');
    var iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
    var processedHtml = injectONTProxy(html, currentONTip);
    iframeDoc.open(); iframeDoc.write(processedHtml); iframeDoc.close();
  } else {
    loadONTPage(action);
  }
}

function ontReload() {
  var path = ontHistory[ontHistoryIndex] || '/';
  loadONTPage(path);
}

function ontNavBack() {
  if (ontHistoryIndex > 0) {
    ontHistoryIndex--;
    loadONTPage(ontHistory[ontHistoryIndex]);
  }
}

function ontNavForward() {
  if (ontHistoryIndex < ontHistory.length - 1) {
    ontHistoryIndex++;
    loadONTPage(ontHistory[ontHistoryIndex]);
  }
}

function ontToggleFullscreen() {
  var modal = document.getElementById('ont-modal');
  var btn = document.getElementById('ont-fullscreen-btn');
  if (document.fullscreenElement) {
    document.exitFullscreen();
    btn.classList.remove('active');
  } else {
    modal.requestFullscreen();
    btn.classList.add('active');
  }
}

function closeONTModal() {
  document.getElementById('ont-modal').classList.remove('show');
  var iframe = document.getElementById('ont-iframe');
  iframe.style.display = 'none';
  iframe.src = 'about:blank';
  currentONTip = null;
  if (document.fullscreenElement) document.exitFullscreen();
}

function showONTLoading(msg) {
  document.getElementById('ont-loading').style.display = 'flex';
  document.getElementById('ont-error').style.display = 'none';
  document.getElementById('ont-iframe').style.display = 'none';
  if (msg) document.getElementById('ont-loading-msg').textContent = msg;
}

function hideONTLoading() {
  document.getElementById('ont-loading').style.display = 'none';
}

function showONTError(msg) {
  document.getElementById('ont-loading').style.display = 'none';
  document.getElementById('ont-error').style.display = 'flex';
  document.getElementById('ont-iframe').style.display = 'none';
  document.getElementById('ont-error-msg').textContent = msg || 'Tidak dapat terhubung';
  document.getElementById('ont-status-dot').style.background = '#ef4444';
  document.getElementById('ont-modal-subtitle').textContent = 'Offline — ' + (currentONTip || '');
}

function hideONTError() {
  document.getElementById('ont-error').style.display = 'none';
}
