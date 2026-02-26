if (!Auth.guard()) throw 0;
document.getElementById('navMount').innerHTML = renderNav('Overview');
document.head.insertAdjacentHTML('beforeend', `<style>${NAV_CSS}</style>`);

let currentMinutes = 60;
let selectedAnomalyId = null;

function setTime(btn, m) {
  document.querySelectorAll('.tbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentMinutes = m;
  refreshAll();
}

function switchInner(btn, id) {
  btn.closest('.card').querySelectorAll('.itab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  btn.closest('.card').querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if (id==='tab-proto') drawProto();
  if (id==='tab-vlan')  drawVlan();
}

function exportReport() {
  toast('Export feature — coming soon', 'info');
}

async function refreshAll() {
  await Promise.all([loadDashboard(), loadAnomalies(), loadEntities(), loadFlowChart()]);
}

async function loadDashboard() {
  try {
    const d = await API.dashboard();
    const fps = d.flows_per_sec || 0;
    document.getElementById('kFlows').textContent = fps.toFixed(1);
    document.getElementById('kFlowsBar').style.width = Math.min(fps/120*100, 100)+'%';
    document.getElementById('kAnomalies').textContent = d.open_anomalies || 0;
    document.getElementById('kAnomaliesBreakdown').textContent =
      `${d.critical_anomalies||0} critical · ${d.high_anomalies||0} high`;
    document.getElementById('kAnomBar').style.width = Math.min((d.open_anomalies||0)/20*100,100)+'%';
    document.getElementById('kEntities').textContent = d.entities_monitored || 0;
    document.getElementById('sbEntities').textContent = d.entities_monitored || '—';
  } catch(e) { console.error('Dashboard error:', e); }
}

async function loadAnomalies() {
  try {
    const data = await API.anomalies();
    const anomalies = data.anomalies || [];
    document.getElementById('alertCount').textContent = anomalies.length + ' Active';

    const crit = anomalies.find(a => a.severity === 'critical');
    if (crit) {
      document.getElementById('alertBanner').style.display = 'flex';
      document.getElementById('alertTitle').textContent =
        `Critical Anomaly — ${crit.anomaly_type.replace(/_/g,' ')} · ${crit.mitre_technique||''}`;
      document.getElementById('alertDesc').innerHTML =
        `<strong>${crit.username||crit.entity_ip}</strong> — ${crit.description.slice(0,120)}...
         <a href="#" onclick="openModal(${crit.id});return false;" style="color:var(--cisco-blue);font-weight:600;margin-left:6px">Investigate →</a>`;
    }

    const tbody = document.getElementById('alertsTable');
    if (!anomalies.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--g50)">No active anomalies</td></tr>';
      return;
    }

    tbody.innerHTML = anomalies.map(a => `
      <tr onclick="openModal(${a.id})">
        <td>${severityBadge(a.severity)}</td>
        <td>
          <div class="adesc">${a.description.slice(0,70)}${a.description.length>70?'...':''}</div>
          <div class="asub">${a.anomaly_type.replace(/_/g,' ')} · ${a.entity_ip}</div>
        </td>
        <td><span class="mitre-tag">${a.mitre_technique||'—'}</span></td>
        <td>
          <div style="font-weight:600;font-size:12px">${a.device_name||a.entity_ip}</div>
          <div class="asub">${a.username||'unknown'}</div>
        </td>
        <td style="color:var(--g50);font-size:12px;white-space:nowrap">${timeAgo(a.detected_at)}</td>
        <td>
          <div class="conf-wrap">
            <div class="conf-bar"><div class="conf-fill" style="width:${a.confidence}%;background:${a.severity==='critical'?'var(--red)':a.severity==='high'?'var(--orange)':'var(--cisco-blue)'}"></div></div>
            <span style="font-size:11px;font-weight:600;color:var(--g70)">${a.confidence}%</span>
          </div>
        </td>
        <td><button class="btn btn-sec" style="padding:3px 9px;font-size:10px" onclick="event.stopPropagation();markClosed(${a.id})">✓ Close</button></td>
      </tr>
    `).join('');
  } catch(e) { console.error('Anomalies error:', e); }
}

async function loadEntities() {
  try {
    const data = await API.entities();
    const entities = (data.entities||[]).slice(0,8);
    const colors = [
      ['#FDECEA','#E2231A'],['#FDECEA','#E2231A'],
      ['#FEF3E6','#F7810A'],['#FEF3E6','#F7810A'],
      ['#EBF5FB','#004BAF'],['#E6F4EE','#00853E'],
      ['#E6F4EE','#00853E'],['#E6F4EE','#00853E'],
    ];
    document.getElementById('entityList').innerHTML = entities.map((e,i) => {
      const [bg,col] = colors[Math.min(i, colors.length-1)];
      const initials = (e.username||e.ip_address||'?').slice(0,2).toUpperCase();
      const trend = e.risk_trend==='up'?'↑':e.risk_trend==='down'?'↓':'→';
      const trendCol = e.risk_trend==='up'?'var(--red)':e.risk_trend==='down'?'var(--green)':'var(--g50)';
      return `
        <div class="ent-row" onclick="loadISEContext('${e.ip_address}','${e.username||'Unknown'}')">
          <div class="av" style="background:${bg};color:${col}">${initials}</div>
          <div class="ent-info">
            <div class="ent-name">${e.username||e.ip_address} <span style="color:${trendCol};font-size:11px">${trend}</span></div>
            <div class="ent-meta">${e.department||'Unknown'} · VLAN-${e.vlan_id||'?'} · ${e.posture_status||'unknown'}</div>
          </div>
          <div class="risk-chip ${e.risk_score>=80?'rc-crit':e.risk_score>=60?'rc-high':e.risk_score>=30?'rc-med':'rc-low'}">${e.risk_score}</div>
        </div>`;
    }).join('');
  } catch(e) { console.error('Entities error:', e); }
}

async function loadISEContext(ip, username) {
  try {
    const data = await API.entity(ip);
    document.getElementById('iseTitle').textContent = `Identity Context — ${username}`;
    const e = data.entity;
    document.getElementById('iseContext').innerHTML = `
      <div class="ise-row"><span class="ise-k">Auth Method</span><span class="ise-v">${e.auth_policy||'802.1X / EAP-TLS'}</span></div>
      <div class="ise-row"><span class="ise-k">Posture</span><span class="ise-v ${e.posture_status==='Compliant'?'ok':'warn'}">${e.posture_status||'Unknown'}</span></div>
      <div class="ise-row"><span class="ise-k">VLAN</span><span class="ise-v">VLAN-${e.vlan_id||'?'}</span></div>
      <div class="ise-row"><span class="ise-k">SGT Tag</span><span class="ise-v">${e.sgt_tag||'—'}</span></div>
      <div class="ise-row"><span class="ise-k">Risk Score</span><span class="ise-v ${e.risk_score>=80?'bad':e.risk_score>=60?'warn':'ok'}">${e.risk_score}</span></div>
      <div class="ise-row"><span class="ise-k">Status</span><span class="ise-v ${e.is_quarantined?'bad':'ok'}">${e.is_quarantined?'⛔ Quarantined':'Active'}</span></div>
    `;
  } catch(e) { console.error('ISE context error:', e); }
}

async function loadFlowChart() {
  try {
    const data = await API.flowStats(currentMinutes);
    drawFlowBaseline(data.timeseries||[]);
    window._protoData = data.protocols||[];
    window._vlanData  = data.vlans||[];
  } catch(e) { console.error('Flow stats error:', e); }
}

function drawFlowBaseline(series) {
  const cv = document.getElementById('flowCanvas');
  cv.width = cv.offsetWidth;
  const ctx = cv.getContext('2d'), W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  if (!series.length) return;
  const vals = series.map(s => s.flows||0);
  const maxV = Math.max(...vals, 1);
  const pts  = vals.length;
  const pad  = 40;
  for (let i=0; i<=4; i++) {
    ctx.beginPath(); ctx.moveTo(pad, (i/4)*(H-24));
    ctx.lineTo(W, (i/4)*(H-24));
    ctx.strokeStyle='#E8EBF1'; ctx.lineWidth=1; ctx.stroke();
    ctx.font='10px Inter,sans-serif'; ctx.fillStyle='#9E9EA2'; ctx.textAlign='right';
    ctx.fillText(Math.round(maxV*(1-i/4)), pad-4, (i/4)*(H-24)+4);
  }
  const baseline = vals.map((v,i) => v * (0.85 + Math.sin(i*0.3)*0.05));
  ctx.beginPath();
  vals.forEach((_,i) => {
    const x = pad + (i/(pts-1||1))*(W-pad);
    const y = (H-24)*(1-baseline[i]/maxV);
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  });
  ctx.strokeStyle='rgba(4,159,217,.4)'; ctx.lineWidth=1.5;
  ctx.setLineDash([5,4]); ctx.stroke(); ctx.setLineDash([]);
  const anomalyThreshold = maxV * 0.7;
  let inAnom = false;
  ctx.beginPath();
  vals.forEach((v,i) => {
    const x = pad + (i/(pts-1||1))*(W-pad);
    const y = (H-24)*(1-v/maxV);
    const isAnom = v > anomalyThreshold;
    if (i===0 || isAnom !== inAnom) {
      if (i>0) ctx.stroke();
      ctx.beginPath(); ctx.moveTo(x,y);
      ctx.strokeStyle = isAnom ? '#E2231A' : '#049FD9';
      ctx.lineWidth = 2; inAnom = isAnom;
    } else { ctx.lineTo(x,y); }
  });
  ctx.stroke();
  const step = Math.max(1, Math.floor(pts/6));
  ctx.font='10px Inter,sans-serif'; ctx.fillStyle='#9E9EA2'; ctx.textAlign='center';
  series.forEach((s,i) => {
    if (i%step===0) {
      ctx.fillText(s.t||'', pad+(i/(pts-1||1))*(W-pad), H-6);
    }
  });
}

function drawProto() {
  const cv = document.getElementById('protoCanvas');
  if (!cv || cv.dataset.drawn) return;
  cv.dataset.drawn='1'; cv.width=cv.offsetWidth;
  const ctx = cv.getContext('2d'), W=cv.width, H=cv.height;
  const data = (window._protoData||[]).slice(0,8);
  if (!data.length) return;
  const maxC = Math.max(...data.map(d=>d.flows||0),1);
  const cols = ['#049FD9','#E2231A','#F7810A','#FBAB18','#00853E','#9E9EA2','#C4D6ED','#004BAF'];
  const bH=22,gap=7,sx=140;
  data.forEach((p,i) => {
    const y = 16+i*(bH+gap);
    const bw=(W-sx-50)*(p.flows||0)/maxC;
    ctx.fillStyle=cols[i]+'25'; ctx.fillRect(sx,y,W-sx-50,bH);
    ctx.fillStyle=cols[i]; ctx.fillRect(sx,y,bw,bH);
    ctx.font='600 11px Inter,sans-serif'; ctx.fillStyle='#58585B'; ctx.textAlign='right';
    ctx.fillText(p.protocol_name||p.protocol||'?', sx-8, y+bH/2+4);
    ctx.fillStyle='#1D1D1D'; ctx.textAlign='left';
    ctx.fillText((p.flows||0).toLocaleString(), sx+bw+6, y+bH/2+4);
  });
}

function drawVlan() {
  const cv = document.getElementById('vlanCanvas');
  if (!cv || cv.dataset.drawn) return;
  cv.dataset.drawn='1'; cv.width=cv.offsetWidth;
  const ctx = cv.getContext('2d'), W=cv.width, H=cv.height;
  const data = (window._vlanData||[]).slice(0,6);
  if (!data.length) return;
  const maxB = Math.max(...data.map(d=>d.bytes||0),1);
  const cols = ['#049FD9','#E2231A','#00853E','#F7810A','#9E9EA2','#FBAB18'];
  const bW=Math.min(55,(W-60)/data.length-10);
  data.forEach((v,i) => {
    const x = 60+i*(bW+14);
    const bh=(H-50)*(v.bytes||0)/maxB;
    const y=(H-40)-bh;
    ctx.fillStyle=cols[i]; ctx.fillRect(x,y,bW,bh);
    ctx.font='9px Inter,sans-serif'; ctx.fillStyle='#58585B'; ctx.textAlign='center';
    ctx.fillText(`VLAN-${v.src_vlan}`,x+bW/2,H-24);
    ctx.fillText(v.name||'',x+bW/2,H-12);
  });
  for(let i=0;i<=4;i++){
    ctx.beginPath();ctx.moveTo(56,(i/4)*(H-40));ctx.lineTo(W,(i/4)*(H-40));
    ctx.strokeStyle='#E8EBF1';ctx.lineWidth=1;ctx.stroke();
    ctx.font='10px Inter,sans-serif';ctx.fillStyle='#9E9EA2';ctx.textAlign='right';
    ctx.fillText(formatBytes(maxB*(1-i/4)),54,(i/4)*(H-40)+4);
  }
}

(function(){
  const cv = document.getElementById('lmCanvas');
  if (!cv) return;
  const ctx = cv.getContext('2d');
  const nodes = [
    {id:'j.harris',x:.12,y:.35,col:'#E2231A',bg:'#FDECEA'},
    {id:'SW-CORE',x:.5,y:.5,col:'#049FD9',bg:'#EBF5FB'},
    {id:'DEV VLAN',x:.88,y:.28,col:'#F7810A',bg:'#FEF3E6'},
    {id:'FIN VLAN',x:.12,y:.72,col:'#00853E',bg:'#E6F4EE'},
    {id:'DMZ',x:.88,y:.72,col:'#9E9EA2',bg:'#F5F6F8'},
  ];
  const edges=[{f:0,t:1,s:true},{f:1,t:2,s:true},{f:3,t:1},{f:1,t:4}];
  let t=0;
  function draw(){
    cv.width=cv.offsetWidth;
    const W=cv.width,H=cv.height;
    ctx.clearRect(0,0,W,H);
    edges.forEach(e=>{
      const a=nodes[e.f],b=nodes[e.t];
      const ax=a.x*W,ay=a.y*H,bx=b.x*W,by=b.y*H;
      ctx.beginPath();ctx.moveTo(ax,ay);ctx.lineTo(bx,by);
      ctx.strokeStyle=e.s?'rgba(226,35,26,.4)':'rgba(4,159,217,.2)';
      ctx.lineWidth=e.s?2:1;ctx.setLineDash(e.s?[6,3]:[]);ctx.stroke();ctx.setLineDash([]);
      if(e.s){
        const p=(t%80)/80;
        ctx.beginPath();ctx.arc(ax+(bx-ax)*p,ay+(by-ay)*p,3,0,Math.PI*2);
        ctx.fillStyle='#E2231A';ctx.fill();
      }
    });
    nodes.forEach(n=>{
      const x=n.x*W,y=n.y*H,r=14;
      ctx.beginPath();ctx.arc(x,y,r,0,Math.PI*2);
      ctx.fillStyle=n.bg;ctx.fill();
      ctx.strokeStyle=n.col;ctx.lineWidth=2;ctx.stroke();
      ctx.font='600 8px Inter,sans-serif';ctx.fillStyle=n.col;ctx.textAlign='center';
      ctx.fillText(n.id,x,y+r+10);
    });
    t++;
  }
  draw();
  setInterval(draw,50);
  window.addEventListener('resize',draw);
})();

async function openModal(id) {
  selectedAnomalyId = id;
  document.getElementById('modalOverlay').classList.add('open');
  document.getElementById('modalBody').innerHTML =
    '<div style="padding:30px;text-align:center;color:var(--g50)">Loading investigation data...</div>';
  try {
    const a = await API.anomaly(id);
    document.getElementById('modalTitle').textContent = `⚠ ${a.anomaly_type.replace(/_/g,' ').toUpperCase()} — Alert #${a.id}`;
    document.getElementById('modalSub').textContent =
      `${a.entity_ip} · ${a.username||'unknown'} · ${timeAgo(a.detected_at)}`;
    let evidence = {};
    try { evidence = JSON.parse(a.evidence||'{}'); } catch(e) {}
    document.getElementById('modalBody').innerHTML = `
      <div class="modal-section">
        <div class="ms-title">Incident Summary</div>
        <div class="detail-grid">
          <div class="detail-item"><div class="di-lbl">Severity</div>
            <div class="di-val" style="color:var(--${a.severity==='critical'?'red':a.severity==='high'?'orange':'cisco-dk'})">${a.severity.toUpperCase()}</div></div>
          <div class="detail-item"><div class="di-lbl">Confidence</div>
            <div class="di-val" style="color:var(--red)">${a.confidence}%</div></div>
          <div class="detail-item"><div class="di-lbl">MITRE Technique</div>
            <div class="di-val" style="font-size:11px">${a.mitre_technique||'—'}</div></div>
          <div class="detail-item"><div class="di-lbl">MITRE Tactic</div>
            <div class="di-val" style="font-size:11px">${a.mitre_tactic||'—'}</div></div>
          <div class="detail-item"><div class="di-lbl">Source Entity</div>
            <div class="di-val" style="color:var(--cisco-dk)">${a.username||a.entity_ip}</div></div>
          <div class="detail-item"><div class="di-lbl">Detected</div>
            <div class="di-val">${new Date(a.detected_at).toLocaleString()}</div></div>
        </div>
      </div>
      <div class="modal-section">
        <div class="ms-title">Full Description</div>
        <p style="font-size:13px;color:var(--g70);line-height:1.7">${a.description}</p>
      </div>
      <div class="modal-section">
        <div class="ms-title">Evidence Data</div>
        <div style="background:#1D1D1D;border-radius:5px;padding:14px;font-family:monospace;font-size:11px;color:#e0e0e0;white-space:pre">${JSON.stringify(evidence,null,2)}</div>
      </div>
    `;
  } catch(e) {
    document.getElementById('modalBody').innerHTML =
      `<div style="padding:30px;text-align:center;color:var(--red)">Failed to load: ${e.message}</div>`;
  }
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('open');
}

async function markClosed(id) {
  try {
    await API.updateAnomaly(id, 'closed', null);
    toast('Alert closed', 'success');
    loadAnomalies();
  } catch(e) { toast(e.message, 'error'); }
}

async function assignAnomaly() {
  if (!selectedAnomalyId) return;
  try {
    const user = Auth.getUser();
    await API.updateAnomaly(selectedAnomalyId, 'investigating', user.username);
    toast('Alert assigned to you — status: Investigating', 'success');
    closeModal();
    loadAnomalies();
  } catch(e) { toast(e.message, 'error'); }
}

refreshAll();
setInterval(refreshAll, 8000);
window.addEventListener('resize', () => {
  ['flowCanvas','protoCanvas','vlanCanvas'].forEach(id=>{
    const cv=document.getElementById(id);
    if(cv){cv.dataset.drawn='';delete cv.dataset.drawn;}
  });
  loadFlowChart();
});
