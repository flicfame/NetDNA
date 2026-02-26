if (!Auth.guard()) throw 0;
document.getElementById('navMount').innerHTML = renderNav('Overview');
document.head.insertAdjacentHTML('beforeend', `<style>${NAV_CSS}</style>`);

const RISK_COLORS = {
  'Segmentation failure':    {col:'#E2231A',bg:'rgba(226,35,26,.08)',ico:'🛡'},
  'Integrity breach':        {col:'#E2231A',bg:'rgba(226,35,26,.08)',ico:'🔓'},
  'Zone policy drift':       {col:'#F7810A',bg:'rgba(247,129,10,.08)',ico:'📐'},
  'Trust violation':          {col:'#F7810A',bg:'rgba(247,129,10,.08)',ico:'⚠'},
  'Remote access misuse':    {col:'#F7810A',bg:'rgba(247,129,10,.08)',ico:'🌐'},
  'Safety process override': {col:'#E2231A',bg:'rgba(226,35,26,.08)',ico:'⛔'},
  'Availability risk':       {col:'#E2231A',bg:'rgba(226,35,26,.08)',ico:'💥'},
};

async function loadOT() {
  await Promise.all([loadOTStats(), loadOTEvents(), loadOTPurdue(), loadOTProcessValues()]);
  drawOTProtoChart();
}

async function loadOTStats() {
  try {
    const s = await API.get('/ot/stats');
    document.getElementById('ot-kDevices').textContent = s.total_devices || 0;
    document.getElementById('ot-kDevBar').style.width  = Math.min((s.total_devices||0)/20*100,100)+'%';
    document.getElementById('ot-kFlagged').textContent = s.flagged_devices || 0;
    document.getElementById('ot-kFlagBar').style.width = Math.min((s.flagged_devices||0)/5*100,100)+'%';
    document.getElementById('ot-kEvents').textContent  = s.open_events || 0;
    document.getElementById('ot-kEvBar').style.width   = Math.min((s.open_events||0)/10*100,100)+'%';
    document.getElementById('ot-kAlarms').textContent  = s.process_alarms || 0;
    document.getElementById('ot-kAlBar').style.width   = Math.min((s.process_alarms||0)/5*100,100)+'%';

    renderRiskCategories(s.risk_categories || []);
    updateSegHealth(s);
  } catch(e) { console.error('OT stats error:', e); }
}

function updateSegHealth(s) {
  const badge = document.getElementById('segHealthBadge');
  const total = s.open_events || 0;
  const critical = (s.risk_categories || []).filter(r =>
    r.cisco_risk === 'Segmentation failure' || r.cisco_risk === 'Safety process override'
  ).reduce((sum, r) => sum + r.cnt, 0);

  if (critical > 0) {
    badge.textContent = 'CRITICAL — ' + critical + ' segmentation breach' + (critical>1?'es':'');
    badge.style.background = 'rgba(226,35,26,.9)';
  } else if (total > 3) {
    badge.textContent = 'ELEVATED — ' + total + ' open events';
    badge.style.background = 'rgba(247,129,10,.9)';
  } else {
    badge.textContent = 'HEALTHY — Segmentation validated';
    badge.style.background = 'rgba(0,133,62,.9)';
  }
}

function renderRiskCategories(cats) {
  const el = document.getElementById('riskCategories');
  if (!cats.length) { el.innerHTML = '<div style="font-size:12px;color:var(--g50)">No risk events</div>'; return; }
  const maxCnt = Math.max(...cats.map(c => c.cnt));
  el.innerHTML = cats.map(c => {
    const meta = RISK_COLORS[c.cisco_risk] || {col:'var(--g70)',bg:'var(--g05)',ico:'•'};
    const pct = Math.max(8, (c.cnt / maxCnt) * 100);
    return `
      <div style="padding:8px 0;border-bottom:1px solid var(--g10)">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
          <div style="display:flex;align-items:center;gap:6px">
            <span style="font-size:13px">${meta.ico}</span>
            <span style="font-size:11px;font-weight:600;color:${meta.col}">${c.cisco_risk}</span>
          </div>
          <span style="font-size:13px;font-weight:700;color:${meta.col}">${c.cnt}</span>
        </div>
        <div style="height:4px;background:var(--g10);border-radius:2px">
          <div style="height:100%;width:${pct}%;background:${meta.col};border-radius:2px;transition:width .6s"></div>
        </div>
      </div>`;
  }).join('');
}

const PURDUE_LABELS = {
  0: {label:'Level 0 — Field Devices',         col:'var(--green)',     bg:'var(--green-lt)'},
  1: {label:'Level 1 — Control (PLCs/RTUs)',    col:'var(--cisco-blue)',bg:'var(--cisco-bg)'},
  2: {label:'Level 2 — Supervisory (HMI/SCADA)',col:'var(--orange)',   bg:'var(--orange-lt)'},
  3: {label:'Level 3 — Operations (Historian)', col:'var(--g70)',      bg:'var(--g10)'},
};

async function loadOTPurdue() {
  try {
    const data = await API.get('/ot/purdue-map');
    const devices = data.devices || [];
    const byLevel = {};
    devices.forEach(d => { if (!byLevel[d.purdue_level]) byLevel[d.purdue_level] = []; byLevel[d.purdue_level].push(d); });

    let html = '';
    [0,1,2,3].forEach(level => {
      const devs = byLevel[level] || [];
      const meta = PURDUE_LABELS[level] || {label:`Level ${level}`,col:'var(--g50)',bg:'var(--g10)'};
      html += `<div style="margin-bottom:12px">
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:${meta.col};margin-bottom:6px;padding-bottom:4px;border-bottom:1px solid ${meta.bg}">${meta.label}</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${devs.map(d => `<div style="display:flex;align-items:center;gap:6px;background:${d.anomaly_flag?'var(--red-lt)':'var(--g05)'};border:1px solid ${d.anomaly_flag?'rgba(226,35,26,.25)':'var(--border)'};border-radius:5px;padding:6px 10px" title="${d.function||''}">
            <span style="font-size:11px">${d.anomaly_flag?'🚨':'🟢'}</span>
            <div>
              <div style="font-size:11px;font-weight:600;color:${d.anomaly_flag?'var(--red)':'var(--g90)'}">${d.name}</div>
              <div style="font-size:10px;color:var(--g50)">${d.vendor} · ${d.protocol}</div>
            </div>
          </div>`).join('')}
        </div></div>`;
    });
    document.getElementById('purdueMap').innerHTML = html || '<div style="color:var(--g50)">No devices</div>';
  } catch(e) { console.error('Purdue map error:', e); }
}

async function loadOTEvents() {
  try {
    const data = await API.get('/ot/events?limit=20');
    const events = data.events || [];
    document.getElementById('ot-evCount').textContent = `${events.length} Events`;

    const sevBadge = s => { const m = {critical:'sc',high:'sh',medium:'sm',low:'sl'}; return `<span class="sev ${m[s]||'sl'}">${s}</span>`; };
    const mitreTag = t => `<span class="mitre-tag" style="font-size:9px">${t||'—'}</span>`;
    const riskBadge = r => {
      if (!r) return '<span style="font-size:10px;color:var(--g50)">—</span>';
      const meta = RISK_COLORS[r] || {col:'var(--g70)',bg:'var(--g05)'};
      return `<span style="font-size:10px;font-weight:600;color:${meta.col};background:${meta.bg};padding:2px 7px;border-radius:3px;white-space:nowrap">${r}</span>`;
    };

    document.getElementById('ot-evTable').innerHTML = events.length
      ? events.map(e => `<tr>
          <td>${sevBadge(e.severity)}</td>
          <td><div style="font-weight:600;font-size:12px">${e.device_name}</div><div style="font-size:10px;color:var(--g50)">${e.device_ip}</div></td>
          <td><div style="font-size:12px">${e.description.slice(0,80)}${e.description.length>80?'...':''}</div><div style="font-size:10px;color:var(--g50);margin-top:2px">${e.event_type.replace(/_/g,' ')}</div></td>
          <td>${riskBadge(e.cisco_risk)}</td>
          <td>${mitreTag(e.mitre_technique)}</td>
          <td style="font-size:11px;color:var(--g50);white-space:nowrap">${timeAgo(e.timestamp)}</td>
        </tr>`).join('')
      : '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--g50)">No ICS events yet</td></tr>';
  } catch(e) { console.error('OT events error:', e); }
}

async function loadOTProcessValues() {
  try {
    const data = await API.get('/ot/process-values');
    const values = data.values || [];
    const pct = (v, lo, hi) => Math.min(100, Math.max(0, ((v-lo)/(hi-lo))*100));
    const col  = (v, lo, hi) => v < lo || v > hi ? 'var(--red)' : v > hi*.9 || v < lo*1.1 ? 'var(--orange)' : 'var(--green)';

    document.getElementById('ot-processValues').innerHTML = values.length
      ? values.map(v => {
          const pc = pct(v.value, v.normal_min, v.normal_max);
          const c  = col(v.value, v.normal_min, v.normal_max);
          return `<div style="padding:9px 18px;border-bottom:1px solid var(--g10);${v.is_alarm?'background:rgba(226,35,26,.03)':''}">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
              <div><span style="font-size:11px;font-weight:600">${v.device_name}</span><span style="font-size:10px;color:var(--g50);margin-left:6px">${v.tag_name.replace(/_/g,' ')}</span></div>
              <span style="font-size:13px;font-weight:700;color:${c}">${v.value.toFixed(1)} <span style="font-size:10px;font-weight:400">${v.unit}</span>${v.is_alarm ? ' 🚨' : ''}</span>
            </div>
            <div style="height:4px;background:var(--g10);border-radius:2px;position:relative">
              <div style="height:100%;width:${pc}%;background:${c};border-radius:2px;transition:width .8s"></div>
            </div>
            <div style="display:flex;justify-content:space-between;font-size:9px;color:var(--g50);margin-top:2px"><span>${v.normal_min} ${v.unit}</span><span>${v.normal_max} ${v.unit}</span></div>
          </div>`;
        }).join('')
      : '<div style="padding:14px 18px;color:var(--g50);font-size:12px">No process values yet</div>';
  } catch(e) { console.error('Process values error:', e); }
}

function drawOTProtoChart() {
  const cv = document.getElementById('ot-protoCanvas');
  if (!cv) return;
  cv.width = cv.offsetWidth;
  const ctx = cv.getContext('2d'), W = cv.width, H = cv.height;
  ctx.clearRect(0,0,W,H);
  const protos = [
    {name:'Modbus/TCP',  count:142, col:'#049FD9'},
    {name:'EtherNet/IP', count:87,  col:'#F7810A'},
    {name:'DNP3',        count:64,  col:'#00853E'},
    {name:'OPC-UA',      count:38,  col:'#9E9EA2'},
    {name:'OPC-DA',      count:22,  col:'#FBAB18'},
    {name:'Profinet',    count:18,  col:'#E2231A'},
  ];
  const maxC = Math.max(...protos.map(p => p.count));
  const bH = 16, gap = 8, labelW = 90;
  protos.forEach((p, i) => {
    const y = i*(bH+gap)+10, bw = (W-labelW-50)*p.count/maxC;
    ctx.fillStyle = p.col+'20'; ctx.fillRect(labelW,y,W-labelW-50,bH);
    ctx.fillStyle = p.col; ctx.fillRect(labelW,y,bw,bH);
    ctx.font = '600 10px Inter,sans-serif'; ctx.fillStyle = '#58585B';
    ctx.textAlign = 'right'; ctx.fillText(p.name, labelW-6, y+bH/2+4);
    ctx.fillStyle = '#1D1D1D'; ctx.textAlign = 'left'; ctx.fillText(p.count, labelW+bw+6, y+bH/2+4);
  });
}

loadOT();
setInterval(loadOT, 8000);
