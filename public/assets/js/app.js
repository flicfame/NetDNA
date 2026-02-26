/**
 * NetDNA Shared JavaScript
 * API client, auth guard, navigation, utilities
 */

// ── AUTH ──────────────────────────────────────────────────────────
const Auth = {
  getToken: ()  => localStorage.getItem('netdna_token'),
  getUser:  ()  => JSON.parse(localStorage.getItem('netdna_user') || '{}'),
  isLoggedIn:() => !!localStorage.getItem('netdna_token'),

  can: (permission) => {
    const user = Auth.getUser();
    return (user.permissions || []).includes(permission);
  },

  logout: () => {
    localStorage.removeItem('netdna_token');
    localStorage.removeItem('netdna_user');
    window.location.href = '/login';
  },

  guard: () => {
    if (!Auth.isLoggedIn()) {
      window.location.href = '/login';
      return false;
    }
    return true;
  }
};

// ── API CLIENT ────────────────────────────────────────────────────
const API = {
  async request(method, path, body = null) {
    const opts = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${Auth.getToken()}`,
      }
    };
    if (body) opts.body = JSON.stringify(body);

    const resp = await fetch('/api/v1' + path, opts);

    if (resp.status === 401) {
      Auth.logout();
      throw new Error('Session expired');
    }

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({detail: 'Request failed'}));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }

    return resp.json();
  },

  get:    (path)        => API.request('GET',    path),
  post:   (path, body)  => API.request('POST',   path, body),
  put:    (path, body)  => API.request('PUT',    path, body),
  delete: (path)        => API.request('DELETE', path),

  // Shorthand endpoints
  dashboard:    ()        => API.get('/dashboard'),
  anomalies:    (s='open')=> API.get(`/anomalies?status_filter=${s}&limit=50`),
  anomaly:      (id)      => API.get(`/anomalies/${id}`),
  entities:     ()        => API.get('/entities?limit=50'),
  entity:       (ip)      => API.get(`/entities/${encodeURIComponent(ip)}`),
  flowStats:    (m=60)    => API.get(`/flows/stats?minutes=${m}`),
  flows:        (m=60)    => API.get(`/flows?minutes=${m}&limit=100`),
  topology:     ()        => API.get('/topology'),
  users:        ()        => API.get('/users'),
  quarantine:   (ip,r)    => API.post('/quarantine', {ip, reason: r}),
  updateAnomaly:(id,s,a)  => API.post(`/anomalies/${id}/status`, {status:s, assigned_to:a}),
  createUser:   (data)    => API.post('/users', data),
  updateUser:   (id,data) => API.put(`/users/${id}`, data),
  deleteUser:   (id)      => API.delete(`/users/${id}`),
};

// ── NAV RENDERING ─────────────────────────────────────────────────
function renderNav(activePage) {
  const user = Auth.getUser();
  const nav = [
    {href:'/dashboard', label:'Overview',     icon:'⊞', perm:'view_dashboard'},
    {href:'/topology',  label:'Topology',    icon:'⬡', perm:'view_dashboard'},
    {href:'/heatmap',   label:'Heatmap',     icon:'⊟', perm:'view_dashboard'},
    {href:'/prediction',label:'Prediction',  icon:'◎', perm:'view_alerts'},
    {href:'/quarantine',label:'ISE Response', icon:'⛔',perm:'quarantine'},
    {href:'/shim-devices',label:'Edge NAC',  icon:'⬡', perm:'view_dashboard'},
    {href:'/users',    label:'Users',        icon:'👤', perm:'manage_users'},
    {href:'/api-docs', label:'API Docs',     icon:'📋', perm:'view_api_docs'},
    {href:'/testlab',  label:'Test Lab',     icon:'🧪', perm:'view_api_docs'},
    {href:'/mynetwork',label:'My Network',   icon:'⚙', role:'admin'},
  ].filter(n => {
    if (n.role) return user.role === n.role;
    return !n.perm || Auth.can(n.perm);
  });

  return `
  <nav class="topnav">
    <div class="cisco-mark">
      <span></span><span></span><span></span><span></span>
      <span></span><span></span><span></span>
    </div>
    <div class="nav-brand">Net<span>DNA</span></div>
    <div class="nav-div"></div>
    <div class="nav-links">
      ${nav.map(n => `
        <a href="${n.href}" class="nav-link ${activePage===n.label?'active':''}">
          ${n.label}
        </a>
      `).join('')}
    </div>
    <div class="nav-right">
      <div class="live-pill"><div class="live-dot"></div>LIVE</div>
      <div class="user-menu" onclick="toggleUserMenu()">
        <div class="user-av">${(user.full_name||user.username||'?')[0].toUpperCase()}</div>
        <div class="user-info">
          <div class="user-name">${user.full_name || user.username}</div>
          <div class="user-role">${user.role_label || user.role}</div>
        </div>
      </div>
      <div class="user-dropdown" id="userDropdown">
        <div class="ud-item" onclick="Auth.logout()">Sign Out</div>
      </div>
    </div>
  </nav>`;
}

function toggleUserMenu() {
  document.getElementById('userDropdown').classList.toggle('open');
}
document.addEventListener('click', e => {
  if (!e.target.closest('.user-menu')) {
    document.getElementById('userDropdown')?.classList.remove('open');
  }
});

// ── SHARED CSS ────────────────────────────────────────────────────
// Injected into pages that use renderNav
const NAV_CSS = `
.topnav{height:52px;background:#004BAF;display:flex;align-items:center;
  padding:0 24px;position:sticky;top:0;z-index:300;
  box-shadow:0 2px 8px rgba(0,0,0,.25);}
.cisco-mark{display:flex;align-items:flex-end;gap:2.5px;height:20px;margin-right:10px;}
.cisco-mark span{display:block;width:4px;background:white;border-radius:2px 2px 0 0;}
.cisco-mark span:nth-child(1){height:8px}.cisco-mark span:nth-child(2){height:13px}
.cisco-mark span:nth-child(3){height:17px}.cisco-mark span:nth-child(4){height:20px}
.cisco-mark span:nth-child(5){height:17px}.cisco-mark span:nth-child(6){height:13px}
.cisco-mark span:nth-child(7){height:8px}
.nav-brand{color:#fff;font-size:15px;font-weight:700;letter-spacing:-.2px;margin-right:24px;}
.nav-brand span{color:#049FD9;font-weight:300;}
.nav-div{width:1px;height:24px;background:rgba(255,255,255,.15);margin:0 12px;}
.nav-links{display:flex;gap:2px;flex:1;}
.nav-link{color:rgba(255,255,255,.65);font-size:12px;font-weight:500;
  padding:6px 13px;border-radius:4px;cursor:pointer;transition:all .15s;
  text-decoration:none;}
.nav-link:hover{background:rgba(255,255,255,.08);color:#fff;}
.nav-link.active{background:rgba(255,255,255,.13);color:#fff;}
.nav-right{display:flex;align-items:center;gap:10px;position:relative;}
.live-pill{display:flex;align-items:center;gap:6px;
  background:rgba(0,133,62,.25);border:1px solid rgba(0,133,62,.4);
  border-radius:20px;padding:3px 10px;font-size:11px;font-weight:600;
  color:#4cd690;letter-spacing:.5px;}
.live-dot{width:6px;height:6px;background:#4cd690;border-radius:50%;
  animation:pulseG 2s ease-in-out infinite;}
@keyframes pulseG{0%,100%{opacity:1}50%{opacity:.3}}
.user-menu{display:flex;align-items:center;gap:8px;cursor:pointer;
  padding:4px 8px;border-radius:6px;transition:background .15s;}
.user-menu:hover{background:rgba(255,255,255,.08);}
.user-av{width:28px;height:28px;background:#049FD9;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  font-size:12px;font-weight:700;color:#fff;}
.user-name{font-size:12px;font-weight:600;color:#fff;}
.user-role{font-size:10px;color:rgba(255,255,255,.5);}
.user-dropdown{position:absolute;top:44px;right:0;background:#fff;
  border:1px solid #DDE1E7;border-radius:6px;
  box-shadow:0 8px 24px rgba(0,0,0,.12);min-width:140px;
  display:none;z-index:400;}
.user-dropdown.open{display:block;}
.ud-item{padding:10px 14px;font-size:13px;cursor:pointer;
  transition:background .1s;}
.ud-item:hover{background:#F5F6F8;}
`;

// ── UTILITIES ─────────────────────────────────────────────────────
function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs/24)}d ago`;
}

function severityBadge(sev) {
  const map = {
    critical: ['sc','Critical'],
    high:     ['sh','High'],
    medium:   ['sm','Medium'],
    low:      ['sl','Low'],
  };
  const [cls, label] = map[sev] || ['sl', sev];
  return `<span class="sev ${cls}">${label}</span>`;
}

function riskChip(score) {
  let cls = 'rc-low';
  if (score >= 80) cls = 'rc-crit';
  else if (score >= 60) cls = 'rc-high';
  else if (score >= 30) cls = 'rc-med';
  return `<span class="risk-chip ${cls}">${score}</span>`;
}

function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1024**2) return (b/1024).toFixed(1) + ' KB';
  if (b < 1024**3) return (b/1024**2).toFixed(1) + ' MB';
  return (b/1024**3).toFixed(2) + ' GB';
}

function toast(msg, type='info') {
  const el = document.createElement('div');
  el.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:9999;
    padding:12px 20px;border-radius:6px;font-size:13px;font-weight:500;
    font-family:Inter,sans-serif;box-shadow:0 4px 16px rgba(0,0,0,.15);
    animation:slideInRight .3s ease;
    ${type==='success'?'background:#E6F4EE;color:#00853E;border:1px solid rgba(0,133,62,.2);':''}
    ${type==='error'  ?'background:#FDECEA;color:#E2231A;border:1px solid rgba(226,35,26,.2);':''}
    ${type==='info'   ?'background:#EBF5FB;color:#004BAF;border:1px solid rgba(4,159,217,.2);':''}
  `;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}
