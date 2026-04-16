// PC Plus Endpoint Protection - Dashboard
const API = '/api/dashboard';
const ENDPOINT_API = '/api/endpoint';

let currentPage = 'overview';
let refreshInterval;
let allDevices = [];

// --- Navigation ---
function showPage(page) {
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    document.getElementById('page-' + page).style.display = 'block';
    document.querySelectorAll('.nav-item')[
        ['overview', 'devices', 'alerts', 'incidents', 'policies', 'config']
            .indexOf(page)
    ]?.classList.add('active');

    currentPage = page;
    refreshCurrentPage();
}

function refreshCurrentPage() {
    switch (currentPage) {
        case 'overview': loadOverview(); break;
        case 'devices': loadDevices(); break;
        case 'alerts': loadAlerts(); break;
        case 'incidents': loadIncidents(); break;
        case 'policies': loadPolicies(); break;
        case 'config': loadConfigPage(); break;
    }
}

// --- SVG Donut Chart Helper ---
function createDonutChart(containerId, segments, centerText, size = 140) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const total = segments.reduce((s, seg) => s + seg.value, 0);
    if (total === 0) {
        el.innerHTML = `<div style="color:var(--text-muted);font-size:13px">No data</div>`;
        return;
    }
    const r = size / 2 - 10;
    const cx = size / 2, cy = size / 2;
    const strokeWidth = 18;
    const circumference = 2 * Math.PI * r;
    let offset = 0;

    let arcs = '';
    let legend = '';
    segments.forEach(seg => {
        if (seg.value === 0) return;
        const pct = seg.value / total;
        const dash = pct * circumference;
        const gap = circumference - dash;
        arcs += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${seg.color}" stroke-width="${strokeWidth}" stroke-dasharray="${dash} ${gap}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})"/>`;
        offset += dash;
        legend += `<div style="display:flex;align-items:center;gap:6px;font-size:11px;margin:2px 0"><span style="width:10px;height:10px;border-radius:2px;background:${seg.color};flex-shrink:0"></span><span style="color:var(--text-muted)">${seg.label}</span><span style="margin-left:auto;color:var(--text-primary);font-weight:600">${seg.value}</span></div>`;
    });

    el.innerHTML = `
        <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
            <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="${strokeWidth}"/>
            ${arcs}
            <text x="${cx}" y="${cy - 4}" text-anchor="middle" fill="var(--text-primary)" font-size="24" font-weight="bold">${centerText}</text>
            <text x="${cx}" y="${cy + 14}" text-anchor="middle" fill="var(--text-muted)" font-size="10">total</text>
        </svg>
        <div style="margin-top:8px">${legend}</div>
    `;
}

// --- Canvas Line Chart Helper ---
function drawAlertTimeline(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = (rect.width - 40) * dpr;
    canvas.height = 200 * dpr;
    canvas.style.width = (rect.width - 40) + 'px';
    canvas.style.height = '200px';
    ctx.scale(dpr, dpr);

    const w = rect.width - 40, h = 200;
    const padding = { top: 10, right: 10, bottom: 30, left: 40 };
    const plotW = w - padding.left - padding.right;
    const plotH = h - padding.top - padding.bottom;

    ctx.clearRect(0, 0, w, h);

    if (!data || data.length === 0) {
        ctx.fillStyle = '#6b7280';
        ctx.font = '13px Segoe UI';
        ctx.textAlign = 'center';
        ctx.fillText('No alert data yet', w / 2, h / 2);
        return;
    }

    const maxVal = Math.max(...data.map(d => d.count), 1);

    // Grid lines
    ctx.strokeStyle = 'rgba(255,255,255,0.06)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = padding.top + (plotH / 4) * i;
        ctx.beginPath(); ctx.moveTo(padding.left, y); ctx.lineTo(w - padding.right, y); ctx.stroke();
        ctx.fillStyle = '#6b7280'; ctx.font = '10px Segoe UI'; ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), padding.left - 6, y + 4);
    }

    // Line
    ctx.beginPath();
    ctx.strokeStyle = '#ef4444';
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    data.forEach((d, i) => {
        const x = padding.left + (i / Math.max(data.length - 1, 1)) * plotW;
        const y = padding.top + plotH - (d.count / maxVal) * plotH;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Fill under line
    const lastIdx = data.length - 1;
    ctx.lineTo(padding.left + plotW, padding.top + plotH);
    ctx.lineTo(padding.left, padding.top + plotH);
    ctx.closePath();
    const gradient = ctx.createLinearGradient(0, padding.top, 0, padding.top + plotH);
    gradient.addColorStop(0, 'rgba(239, 68, 68, 0.15)');
    gradient.addColorStop(1, 'rgba(239, 68, 68, 0)');
    ctx.fillStyle = gradient;
    ctx.fill();

    // X labels
    ctx.fillStyle = '#6b7280'; ctx.font = '10px Segoe UI'; ctx.textAlign = 'center';
    const step = Math.max(1, Math.floor(data.length / 5));
    data.forEach((d, i) => {
        if (i % step === 0 || i === lastIdx) {
            const x = padding.left + (i / Math.max(data.length - 1, 1)) * plotW;
            ctx.fillText(d.label, x, h - 8);
        }
    });
}

// --- Overview ---
async function loadOverview() {
    try {
        const [overview, alerts, devices] = await Promise.all([
            fetch(API + '/overview').then(r => r.json()),
            fetch(API + '/alerts?limit=50&acknowledged=false').then(r => r.json()),
            fetch(API + '/devices').then(r => r.json())
        ]);

        // Top stat cards
        const statsEl = document.getElementById('overview-stats');
        statsEl.innerHTML = `
            <div class="stat-card blue">
                <div class="label">Total Devices</div>
                <div class="value">${overview.totalDevices}</div>
                <div class="sub">${overview.onlineDevices} online, ${overview.offlineDevices} offline</div>
            </div>
            <div class="stat-card ${overview.criticalAlerts > 0 ? 'red' : 'green'}">
                <div class="label">Active Alerts</div>
                <div class="value">${overview.activeAlerts}</div>
                <div class="sub">${overview.criticalAlerts} critical</div>
            </div>
            <div class="stat-card ${overview.devicesInLockdown > 0 ? 'red' : 'green'}">
                <div class="label">Lockdowns</div>
                <div class="value">${overview.devicesInLockdown}</div>
                <div class="sub">${overview.devicesInLockdown > 0 ? 'Active lockdowns!' : 'All clear'}</div>
            </div>
            <div class="stat-card ${overview.avgSecurityScore >= 80 ? 'green' : overview.avgSecurityScore >= 60 ? 'yellow' : 'red'}">
                <div class="label">Avg Security Score</div>
                <div class="value">${Math.round(overview.avgSecurityScore)}</div>
                <div class="sub">Across all devices</div>
            </div>
            <div class="stat-card ${overview.openIncidents > 0 ? 'orange' : 'green'}">
                <div class="label">Open Incidents</div>
                <div class="value">${overview.openIncidents}</div>
            </div>
            <div class="stat-card purple">
                <div class="label">Protected Endpoints</div>
                <div class="value">${devices.filter(d => d.isOnline && d.runningModules > 0).length}</div>
                <div class="sub">of ${overview.totalDevices} total</div>
            </div>
        `;

        // Alerts by category donut
        const categories = {};
        alerts.forEach(a => {
            const cat = a.category || a.moduleId || 'Other';
            categories[cat] = (categories[cat] || 0) + 1;
        });
        const catColors = ['#3b82f6', '#ef4444', '#f59e0b', '#22c55e', '#8b5cf6', '#ec4899', '#06b6d4'];
        const catSegments = Object.entries(categories).map(([label, value], i) => ({
            label: label.charAt(0).toUpperCase() + label.slice(1),
            value,
            color: catColors[i % catColors.length]
        }));
        createDonutChart('alerts-donut', catSegments, alerts.length.toString());

        // Alerts over time (group by day for last 7 days)
        const now = new Date();
        const timelineData = [];
        for (let i = 6; i >= 0; i--) {
            const d = new Date(now); d.setDate(d.getDate() - i);
            const dayStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            const dayStart = new Date(d.getFullYear(), d.getMonth(), d.getDate());
            const dayEnd = new Date(dayStart); dayEnd.setDate(dayEnd.getDate() + 1);
            const count = alerts.filter(a => {
                const t = new Date(a.timestamp);
                return t >= dayStart && t < dayEnd;
            }).length;
            timelineData.push({ label: dayStr, count });
        }
        drawAlertTimeline('alerts-timeline', timelineData);

        // Security threats table
        const threatsTable = document.getElementById('security-threats-table');
        if (devices.length === 0) {
            threatsTable.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-muted)">No devices</td></tr>';
        } else {
            threatsTable.innerHTML = devices.map(d => {
                const status = d.lockdownActive ? 'lockdown' : (d.isOnline ? 'online' : 'offline');
                const statusLabel = d.lockdownActive ? 'LOCKDOWN' : (d.isOnline ? 'Online' : 'Offline');
                const gradeClass = (d.securityGrade || '?').toLowerCase();
                const deviceAlerts = alerts.filter(a => (a.hostname || a.deviceId) === (d.hostname || d.deviceId)).length;
                const protectionPct = d.runningModules > 0 ? Math.round((d.runningModules / Math.max(d.totalModules || 5, 1)) * 100) : 0;
                const protColor = protectionPct >= 80 ? '#22c55e' : protectionPct >= 50 ? '#f59e0b' : '#ef4444';
                return `<tr>
                    <td style="font-weight:500">${esc(d.hostname || d.deviceId)}</td>
                    <td><span class="score ${gradeClass}">${esc(d.securityGrade || '?')}</span> <span style="font-size:11px;color:var(--text-muted)">${d.securityScore}/100</span></td>
                    <td>${deviceAlerts > 0 ? `<span style="color:#ef4444;font-weight:600">${deviceAlerts}</span>` : '<span style="color:var(--text-muted)">0</span>'}</td>
                    <td><span class="badge ${status}"><span class="badge-dot"></span>${statusLabel}</span></td>
                    <td><div class="progress" style="width:60px;display:inline-block;vertical-align:middle"><div class="progress-bar ${protColor === '#22c55e' ? 'green' : protColor === '#f59e0b' ? 'orange' : 'red'}" style="width:${protectionPct}%"></div></div> <span style="font-size:11px">${d.runningModules}/${d.totalModules || '?'}</span></td>
                </tr>`;
            }).join('');
        }

        // Protection status donuts
        const onlineCount = devices.filter(d => d.isOnline).length;
        const offlineCount = devices.filter(d => !d.isOnline).length;
        const lockdownCount = devices.filter(d => d.lockdownActive).length;
        const protectedCount = devices.filter(d => d.runningModules > 0 && d.isOnline).length;
        const unprotectedCount = devices.filter(d => d.runningModules === 0 && d.isOnline).length;
        const goodScore = devices.filter(d => d.securityScore >= 80).length;
        const medScore = devices.filter(d => d.securityScore >= 50 && d.securityScore < 80).length;
        const lowScore = devices.filter(d => d.securityScore < 50).length;

        createDonutChart('donut-ransomware', [
            { label: 'Active', value: protectedCount, color: '#22c55e' },
            { label: 'Inactive', value: unprotectedCount, color: '#6b7280' },
            { label: 'Lockdown', value: lockdownCount, color: '#ef4444' }
        ], devices.length.toString(), 120);

        createDonutChart('donut-defender', [
            { label: 'Protected', value: protectedCount, color: '#22c55e' },
            { label: 'Unprotected', value: unprotectedCount + offlineCount, color: '#6b7280' }
        ], protectedCount.toString(), 120);

        createDonutChart('donut-security', [
            { label: 'Good (80+)', value: goodScore, color: '#22c55e' },
            { label: 'Medium (50-79)', value: medScore, color: '#f59e0b' },
            { label: 'Low (<50)', value: lowScore, color: '#ef4444' }
        ], Math.round(overview.avgSecurityScore).toString(), 120);

        createDonutChart('donut-status', [
            { label: 'Online', value: onlineCount, color: '#22c55e' },
            { label: 'Offline', value: offlineCount, color: '#6b7280' },
            { label: 'Lockdown', value: lockdownCount, color: '#ef4444' }
        ], onlineCount.toString(), 120);

        // Recent alerts feed
        const alertsEl = document.getElementById('overview-alerts');
        if (alerts.length === 0) {
            alertsEl.innerHTML = '<div class="empty-state"><p>No active alerts. All systems healthy.</p></div>';
        } else {
            alertsEl.innerHTML = alerts.slice(0, 10).map(a => `
                <div class="alert-item">
                    <div class="alert-severity ${a.severity}"></div>
                    <div class="alert-content">
                        <div class="alert-title">${esc(a.title)}</div>
                        <div class="alert-message">${esc(a.message)}</div>
                        <div class="alert-meta">${esc(a.hostname || a.deviceId)} &middot; ${timeAgo(a.timestamp)} &middot; ${a.severity}</div>
                    </div>
                    <button class="btn btn-sm btn-secondary" onclick="ackAlert(${a.id})">Ack</button>
                </div>
            `).join('');
        }
    } catch (err) {
        console.error('Failed to load overview:', err);
    }
}

// --- Devices ---
async function loadDevices() {
    try {
        allDevices = await fetch(API + '/devices').then(r => r.json());
        renderDevices(allDevices);
    } catch (err) {
        console.error('Failed to load devices:', err);
    }
}

function renderDevices(devices) {
    const tbody = document.getElementById('devices-table');
    if (devices.length === 0) {
        tbody.innerHTML = '<tr><td colspan="13" style="text-align:center;padding:32px;color:var(--text-muted)">No devices registered yet. Endpoints will appear here when they start phoning home.</td></tr>';
        return;
    }

    tbody.innerHTML = devices.map(d => {
        const status = d.lockdownActive ? 'lockdown' : (d.isOnline ? 'online' : 'offline');
        const statusLabel = d.lockdownActive ? 'LOCKDOWN' : (d.isOnline ? 'Online' : 'Offline');
        const gradeClass = (d.securityGrade || '?').toLowerCase();
        const cpuColor = d.cpuPercent > 90 ? 'red' : d.cpuPercent > 70 ? 'orange' : 'green';
        const ramColor = d.ramPercent > 90 ? 'red' : d.ramPercent > 70 ? 'orange' : 'green';
        const diskColor = d.diskPercent > 90 ? 'red' : d.diskPercent > 80 ? 'orange' : 'green';
        const cpuTempColor = d.cpuTempC > 85 ? 'red' : d.cpuTempC > 70 ? 'orange' : 'green';
        const gpuTempColor = d.gpuTempC > 85 ? 'red' : d.gpuTempC > 70 ? 'orange' : 'green';

        return `<tr>
            <td><span class="badge ${status}"><span class="badge-dot"></span>${statusLabel}</span></td>
            <td style="color:var(--text-primary);font-weight:500">${esc(d.hostname || d.deviceId)}</td>
            <td>${esc(d.customerName || d.customerId || '-')}</td>
            <td><span class="score ${gradeClass}">${esc(d.securityGrade || '?')}</span> <span style="font-size:12px;color:var(--text-muted)">${d.securityScore}/100</span></td>
            <td><div class="progress"><div class="progress-bar ${cpuColor}" style="width:${d.cpuPercent}%"></div></div>${Math.round(d.cpuPercent)}%</td>
            <td><div class="progress"><div class="progress-bar ${ramColor}" style="width:${d.ramPercent}%"></div></div>${Math.round(d.ramPercent)}%</td>
            <td><div class="progress"><div class="progress-bar ${diskColor}" style="width:${d.diskPercent}%"></div></div>${Math.round(d.diskPercent)}%</td>
            <td style="color:${cpuTempColor === 'red' ? '#ef4444' : cpuTempColor === 'orange' ? '#f59e0b' : '#22c55e'};font-weight:500">${d.cpuTempC > 0 ? Math.round(d.cpuTempC) + '°C' : '-'}</td>
            <td style="color:${gpuTempColor === 'red' ? '#ef4444' : gpuTempColor === 'orange' ? '#f59e0b' : '#22c55e'};font-weight:500">${d.gpuTempC > 0 ? Math.round(d.gpuTempC) + '°C' : '-'}</td>
            <td><span class="badge info">${esc(d.licenseTier)}</span></td>
            <td>${d.runningModules}</td>
            <td style="font-size:12px;color:var(--text-muted)">${timeAgo(d.lastSeen)}</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="showDeviceDetail('${d.deviceId}')">Detail</button>
            </td>
        </tr>`;
    }).join('');
}

function filterDevices() {
    const q = document.getElementById('device-search').value.toLowerCase();
    if (!q) { renderDevices(allDevices); return; }
    renderDevices(allDevices.filter(d =>
        (d.hostname || '').toLowerCase().includes(q) ||
        (d.customerName || '').toLowerCase().includes(q) ||
        (d.deviceId || '').toLowerCase().includes(q)
    ));
}

function showDeviceDetail(deviceId) {
    const d = allDevices.find(x => x.deviceId === deviceId);
    if (!d) return;

    const modal = document.getElementById('device-modal');
    const content = document.getElementById('device-modal-content');
    content.innerHTML = `
        <h3>${esc(d.hostname)}</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
            <div><span style="color:var(--text-muted);font-size:12px">Device ID</span><br>${esc(d.deviceId)}</div>
            <div><span style="color:var(--text-muted);font-size:12px">Customer</span><br>${esc(d.customerName || d.customerId || '-')}</div>
            <div><span style="color:var(--text-muted);font-size:12px">OS</span><br>${esc(d.osVersion || '-')}</div>
            <div><span style="color:var(--text-muted);font-size:12px">Agent Version</span><br>${esc(d.agentVersion || '-')}</div>
            <div><span style="color:var(--text-muted);font-size:12px">Local IP</span><br>${esc(d.localIp || d.ipAddress || '-')}</div>
            <div><span style="color:var(--text-muted);font-size:12px">Public IP</span><br>${esc(d.publicIp || '-')}</div>
            <div><span style="color:var(--text-muted);font-size:12px">License</span><br>${esc(d.licenseTier)}</div>
            <div><span style="color:var(--text-muted);font-size:12px">Policy</span><br>${esc(d.policyProfile || 'default')}</div>
            <div><span style="color:var(--text-muted);font-size:12px">Registered</span><br>${new Date(d.registeredAt).toLocaleDateString()}</div>
            <div><span style="color:var(--text-muted);font-size:12px">Security Score</span><br><span class="score ${(d.securityGrade||'?').toLowerCase()}">${d.securityGrade}</span> ${d.securityScore}/100</div>
            <div><span style="color:var(--text-muted);font-size:12px">CPU Temp</span><br>${d.cpuTempC > 0 ? Math.round(d.cpuTempC) + '°C' : '-'}</div>
            <div><span style="color:var(--text-muted);font-size:12px">GPU Temp</span><br>${d.gpuTempC > 0 ? Math.round(d.gpuTempC) + '°C' : '-'}</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-sm btn-secondary" onclick="sendCommand('${d.deviceId}','rescan')">Run Security Scan</button>
            <button class="btn btn-sm btn-secondary" onclick="sendCommand('${d.deviceId}','maintenance')">Fix My Computer</button>
            <button class="btn btn-sm btn-danger" onclick="sendCommand('${d.deviceId}','lockdown')">Lockdown</button>
            <button class="btn btn-sm btn-secondary" onclick="closeModal()">Close</button>
        </div>
    `;
    modal.classList.add('active');
}

function closeModal() {
    document.getElementById('device-modal').classList.remove('active');
}

// --- Alerts ---
async function loadAlerts() {
    try {
        const severity = document.getElementById('alert-filter')?.value || '';
        const url = API + '/alerts?limit=100' + (severity ? '&severity=' + severity : '') + '&acknowledged=false';
        const alerts = await fetch(url).then(r => r.json());

        const feed = document.getElementById('alerts-feed');
        if (alerts.length === 0) {
            feed.innerHTML = '<div class="empty-state"><p>No alerts matching filter.</p></div>';
            return;
        }

        feed.innerHTML = alerts.map(a => `
            <div class="alert-item">
                <div class="alert-severity ${a.severity}"></div>
                <div class="alert-content">
                    <div class="alert-title">${esc(a.title)}</div>
                    <div class="alert-message">${esc(a.message)}</div>
                    <div class="alert-meta">${esc(a.hostname || a.deviceId)} &middot; ${a.moduleId} &middot; ${timeAgo(a.timestamp)} &middot; <span class="badge ${a.severity.toLowerCase()}">${a.severity}</span></div>
                </div>
                <button class="btn btn-sm btn-secondary" onclick="ackAlert(${a.id})">Acknowledge</button>
            </div>
        `).join('');
    } catch (err) {
        console.error('Failed to load alerts:', err);
    }
}

async function ackAlert(id) {
    await fetch(API + '/alerts/' + id + '/ack', { method: 'POST' });
    refreshCurrentPage();
}

// --- Incidents ---
async function loadIncidents() {
    try {
        const incidents = await fetch(API + '/incidents?limit=100').then(r => r.json());
        const tbody = document.getElementById('incidents-table');

        if (incidents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted)">No incidents recorded.</td></tr>';
            return;
        }

        tbody.innerHTML = incidents.map(i => `
            <tr>
                <td><span class="badge ${i.resolved ? 'online' : 'critical'}">${i.resolved ? 'Resolved' : 'Open'}</span></td>
                <td>${esc(i.hostname || i.deviceId)}</td>
                <td>${esc(i.type)}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${esc(i.description)}</td>
                <td><span class="badge ${(i.severity||'info').toLowerCase()}">${i.severity}</span></td>
                <td style="font-size:12px">${timeAgo(i.occurredAt)}</td>
                <td>${!i.resolved ? `<button class="btn btn-sm btn-secondary" onclick="resolveIncident(${i.id})">Resolve</button>` : `<span style="font-size:12px;color:var(--text-muted)">${esc(i.resolvedBy)}</span>`}</td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Failed to load incidents:', err);
    }
}

async function resolveIncident(id) {
    await fetch(API + '/incidents/' + id + '/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resolvedBy: 'dashboard', actionsTaken: 'Resolved via dashboard' })
    });
    loadIncidents();
}

// --- Policies ---
async function loadPolicies() {
    try {
        const policies = await fetch(API + '/policies').then(r => r.json());
        const grid = document.getElementById('policies-grid');

        grid.innerHTML = policies.map(p => {
            const config = JSON.parse(p.configJson || '{}');
            const configCount = Object.keys(config).length;
            return `
                <div class="stat-card">
                    <div class="label" style="text-transform:none;font-size:14px;color:var(--text-primary);font-weight:600">${esc(p.name)}</div>
                    <div class="sub" style="margin-top:4px">${esc(p.description)}</div>
                    <div style="margin-top:12px;font-size:12px;color:var(--text-muted)">${configCount} settings configured</div>
                    <div style="margin-top:8px;font-size:11px;color:var(--text-muted)">
                        ${Object.entries(config).slice(0, 4).map(([k,v]) => `${k}: ${v}`).join('<br>')}
                        ${configCount > 4 ? `<br>...and ${configCount - 4} more` : ''}
                    </div>
                </div>
            `;
        }).join('');
    } catch (err) {
        console.error('Failed to load policies:', err);
    }
}

// --- Config Push ---
async function loadConfigPage() {
    try {
        const [devices, policies] = await Promise.all([
            fetch(API + '/devices').then(r => r.json()),
            fetch(API + '/policies').then(r => r.json())
        ]);

        const deviceSelect = document.getElementById('config-device');
        deviceSelect.innerHTML = '<option value="">All Devices</option>' +
            devices.map(d => `<option value="${d.deviceId}">${esc(d.hostname || d.deviceId)}</option>`).join('');

        const profileSelect = document.getElementById('config-profile');
        profileSelect.innerHTML = '<option value="">No profile</option>' +
            policies.map(p => `<option value="${p.name}">${esc(p.name)}</option>`).join('');
    } catch (err) {
        console.error('Failed to load config page:', err);
    }
}

async function pushConfig() {
    const deviceId = document.getElementById('config-device').value;
    const profile = document.getElementById('config-profile').value;

    const config = {};

    // Scoring weights
    document.querySelectorAll('#scoring-weights input[data-key]').forEach(input => {
        config[input.dataset.key] = input.value;
    });

    // Thresholds
    config.scoringWarningThreshold = document.getElementById('cfg-warning').value;
    config.scoringContainmentThreshold = document.getElementById('cfg-containment').value;
    config.scoringLockdownThreshold = document.getElementById('cfg-lockdown').value;
    config.scoringDecayPerMinute = document.getElementById('cfg-decay').value;

    try {
        await fetch(API + '/config/push', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId: deviceId || null, policyProfile: profile || null, config })
        });
        alert('Configuration pushed! Endpoints will pick up changes on next heartbeat.');
    } catch (err) {
        alert('Failed to push config: ' + err.message);
    }
}

function resetConfigDefaults() {
    const defaults = { scoreHoneypotTriggered:50, scoreKnownRansomware:50, scoreShadowCopyDeletion:40,
        scoreRansomNoteCreation:35, scoreMultiFolderTouch:25, scoreMassExtensionChange:20,
        scoreSuspiciousPowerShell:20, scoreHighFileRenameRate:20, scoreHighEntropyWrite:15,
        scoreSuspiciousParentChild:15, scoreRiskyLaunchPath:10, scoreRansomwareExtension:10,
        scoreFileRename:5, scoreUnsignedProcess:5 };

    Object.entries(defaults).forEach(([key, val]) => {
        const input = document.querySelector(`input[data-key="${key}"]`);
        if (input) input.value = val;
    });
    document.getElementById('cfg-warning').value = 30;
    document.getElementById('cfg-containment').value = 60;
    document.getElementById('cfg-lockdown').value = 80;
    document.getElementById('cfg-decay').value = 5;
}

// --- Commands ---
async function sendCommand(deviceId, command) {
    try {
        await fetch(API + '/devices/' + deviceId + '/command', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command })
        });
        alert('Command "' + command + '" sent. Device will execute on next heartbeat.');
        closeModal();
    } catch (err) {
        alert('Failed: ' + err.message);
    }
}

// --- Utilities ---
function esc(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function timeAgo(dateStr) {
    if (!dateStr) return '-';
    const d = new Date(dateStr);
    const now = new Date();
    const diffMs = now - d;
    const diffMin = Math.floor(diffMs / 60000);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);

    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return diffMin + 'm ago';
    if (diffHr < 24) return diffHr + 'h ago';
    if (diffDay < 7) return diffDay + 'd ago';
    return d.toLocaleDateString();
}

// --- Auto-refresh ---
function startAutoRefresh() {
    refreshInterval = setInterval(refreshCurrentPage, 15000); // 15 seconds
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    loadOverview();
    startAutoRefresh();
});

// Close modal on overlay click
document.getElementById('device-modal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('device-modal')) closeModal();
});
