// PC Plus Endpoint Protection - Dashboard
const API = '/api/dashboard';
const ENDPOINT_API = '/api/endpoint';

// --- Mobile sidebar toggle ---
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    sidebar.classList.toggle('open');
    overlay.classList.toggle('active');
}

// Close sidebar when nav item clicked on mobile
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            if (window.innerWidth <= 768) {
                const sidebar = document.getElementById('sidebar');
                const overlay = document.getElementById('sidebar-overlay');
                sidebar.classList.remove('open');
                overlay.classList.remove('active');
            }
        });
    });
});

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

let currentCustomer = '';

function refreshCurrentPage() {
    switch (currentPage) {
        case 'overview': loadOverview(); break;
        case 'customer': loadCustomerDashboard(currentCustomer); break;
        case 'device': loadDeviceDetail(); break;
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

        // Customers table - group devices by customer
        allDevices = devices;
        const threatsTable = document.getElementById('security-threats-table');
        if (devices.length === 0) {
            threatsTable.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-muted)">No devices</td></tr>';
        } else {
            // Group by customer
            const customers = {};
            devices.forEach(d => {
                const cust = d.customerName || d.customerId || 'Unassigned';
                if (!customers[cust]) customers[cust] = [];
                customers[cust].push(d);
            });

            threatsTable.innerHTML = Object.entries(customers).map(([custName, custDevices]) => {
                const onlineCount = custDevices.filter(d => d.isOnline).length;
                const avgScore = Math.round(custDevices.reduce((s, d) => s + (d.securityScore || 0), 0) / custDevices.length);
                const custAlerts = custDevices.reduce((s, d) => {
                    return s + alerts.filter(a => (a.hostname || a.deviceId) === (d.hostname || d.deviceId)).length;
                }, 0);
                const scoreClass = avgScore >= 80 ? 'b' : avgScore >= 60 ? 'c' : 'd';

                return `<tr style="cursor:pointer" onclick="showCustomerDashboard('${esc(custName)}')">
                    <td style="font-weight:600;color:#3b82f6;text-decoration:underline">${esc(custName)}</td>
                    <td>${custDevices.length}</td>
                    <td><span class="score ${scoreClass}">${avgScore >= 80 ? 'B' : avgScore >= 60 ? 'C' : 'D'}</span> <span style="font-size:11px;color:var(--text-muted)">${avgScore}/100</span></td>
                    <td>${custAlerts > 0 ? `<span style="color:#ef4444;font-weight:600">${custAlerts}</span>` : '<span style="color:var(--text-muted)">0</span>'}</td>
                    <td><span style="color:#22c55e;font-weight:500">${onlineCount}</span><span style="color:var(--text-muted)">/${custDevices.length}</span></td>
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

// --- Customer Dashboard ---
function showCustomerDashboard(customerName) {
    currentCustomer = customerName;
    // Show customer page
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('page-customer').style.display = 'block';
    currentPage = 'customer';
    loadCustomerDashboard(customerName);
}

async function loadCustomerDashboard(customerName) {
    if (!customerName) return;
    try {
        const [devices, alerts] = await Promise.all([
            fetch(API + '/devices').then(r => r.json()),
            fetch(API + '/alerts?limit=100&acknowledged=false').then(r => r.json())
        ]);

        allDevices = devices;
        const custDevices = devices.filter(d => (d.customerName || d.customerId || 'Unassigned') === customerName);
        const custAlerts = alerts.filter(a => custDevices.some(d => (d.hostname || d.deviceId) === (a.hostname || a.deviceId)));

        // Title
        document.getElementById('customer-title').textContent = customerName;

        // Stats
        const onlineCount = custDevices.filter(d => d.isOnline).length;
        const offlineCount = custDevices.filter(d => !d.isOnline).length;
        const avgScore = custDevices.length > 0 ? Math.round(custDevices.reduce((s, d) => s + (d.securityScore || 0), 0) / custDevices.length) : 0;
        const critAlerts = custAlerts.filter(a => a.severity === 'Critical' || a.severity === 'Emergency').length;
        const protectedCount = custDevices.filter(d => d.runningModules > 0 && d.isOnline).length;
        const avgCpu = custDevices.length > 0 ? Math.round(custDevices.reduce((s, d) => s + (d.cpuPercent || 0), 0) / custDevices.length) : 0;

        document.getElementById('customer-stats').innerHTML = `
            <div class="stat-card blue">
                <div class="label">Total Endpoints</div>
                <div class="value">${custDevices.length}</div>
                <div class="sub">${onlineCount} online, ${offlineCount} offline</div>
            </div>
            <div class="stat-card ${custAlerts.length > 0 ? 'red' : 'green'}">
                <div class="label">Active Alerts</div>
                <div class="value">${custAlerts.length}</div>
                <div class="sub">${critAlerts} critical</div>
            </div>
            <div class="stat-card ${avgScore >= 80 ? 'green' : avgScore >= 60 ? 'yellow' : 'red'}">
                <div class="label">Avg Security Score</div>
                <div class="value">${avgScore}</div>
                <div class="sub">Across ${custDevices.length} devices</div>
            </div>
            <div class="stat-card ${avgCpu > 80 ? 'red' : avgCpu > 60 ? 'yellow' : 'green'}">
                <div class="label">Avg CPU Usage</div>
                <div class="value">${avgCpu}%</div>
                <div class="sub">${protectedCount} protected endpoints</div>
            </div>
        `;

        // Donuts
        createDonutChart('cust-donut-status', [
            { label: 'Online', value: onlineCount, color: '#22c55e' },
            { label: 'Offline', value: offlineCount, color: '#6b7280' }
        ], custDevices.length.toString(), 120);

        const goodScore = custDevices.filter(d => d.securityScore >= 80).length;
        const medScore = custDevices.filter(d => d.securityScore >= 50 && d.securityScore < 80).length;
        const lowScore = custDevices.filter(d => d.securityScore < 50).length;
        createDonutChart('cust-donut-security', [
            { label: 'Good (80+)', value: goodScore, color: '#22c55e' },
            { label: 'Medium', value: medScore, color: '#f59e0b' },
            { label: 'Low (<50)', value: lowScore, color: '#ef4444' }
        ], avgScore.toString(), 120);

        const unprotected = custDevices.filter(d => d.runningModules === 0).length;
        createDonutChart('cust-donut-protection', [
            { label: 'Protected', value: protectedCount, color: '#22c55e' },
            { label: 'Unprotected', value: unprotected, color: '#ef4444' }
        ], protectedCount.toString(), 120);

        const alertCats = {};
        custAlerts.forEach(a => {
            const cat = a.category || a.moduleId || 'Other';
            alertCats[cat] = (alertCats[cat] || 0) + 1;
        });
        const catColors = ['#3b82f6', '#ef4444', '#f59e0b', '#22c55e', '#8b5cf6'];
        createDonutChart('cust-donut-alerts',
            Object.entries(alertCats).map(([label, value], i) => ({
                label: label.charAt(0).toUpperCase() + label.slice(1), value, color: catColors[i % catColors.length]
            })),
            custAlerts.length.toString(), 120);

        // Devices table
        const tbody = document.getElementById('customer-devices-table');
        tbody.innerHTML = custDevices.map(d => {
            const status = d.lockdownActive ? 'lockdown' : (d.isOnline ? 'online' : 'offline');
            const statusLabel = d.lockdownActive ? 'LOCKDOWN' : (d.isOnline ? 'Online' : 'Offline');
            const gradeClass = (d.securityGrade || '?').toLowerCase();
            const cpuColor = d.cpuPercent > 90 ? 'red' : d.cpuPercent > 70 ? 'orange' : 'green';
            const ramColor = d.ramPercent > 90 ? 'red' : d.ramPercent > 70 ? 'orange' : 'green';
            const diskColor = d.diskPercent > 90 ? 'red' : d.diskPercent > 80 ? 'orange' : 'green';
            const cpuTempColor = d.cpuTempC > 85 ? 'red' : d.cpuTempC > 70 ? 'orange' : 'green';
            const gpuTempColor = d.gpuTempC > 85 ? 'red' : d.gpuTempC > 70 ? 'orange' : 'green';

            return `<tr style="cursor:pointer" onclick="showDeviceDetail('${d.deviceId}')">
                <td><span class="badge ${status}"><span class="badge-dot"></span>${statusLabel}</span></td>
                <td style="font-weight:500;color:#3b82f6">${esc(d.hostname || d.deviceId)}</td>
                <td><span class="score ${gradeClass}">${esc(d.securityGrade || '?')}</span> <span style="font-size:11px;color:var(--text-muted)">${d.securityScore}/100</span></td>
                <td><div class="progress"><div class="progress-bar ${cpuColor}" style="width:${d.cpuPercent}%"></div></div>${Math.round(d.cpuPercent)}%</td>
                <td><div class="progress"><div class="progress-bar ${ramColor}" style="width:${d.ramPercent}%"></div></div>${Math.round(d.ramPercent)}%</td>
                <td><div class="progress"><div class="progress-bar ${diskColor}" style="width:${d.diskPercent}%"></div></div>${Math.round(d.diskPercent)}%</td>
                <td style="color:${cpuTempColor === 'red' ? '#ef4444' : cpuTempColor === 'orange' ? '#f59e0b' : '#22c55e'};font-weight:500">${d.cpuTempC > 0 ? Math.round(d.cpuTempC) + '°C' : '-'}</td>
                <td style="color:${gpuTempColor === 'red' ? '#ef4444' : gpuTempColor === 'orange' ? '#f59e0b' : '#22c55e'};font-weight:500">${d.gpuTempC > 0 ? Math.round(d.gpuTempC) + '°C' : '-'}</td>
                <td>${d.runningModules}</td>
                <td style="font-size:12px;color:var(--text-muted)">${timeAgo(d.lastSeen)}</td>
                <td><button class="btn btn-sm btn-secondary" onclick="event.stopPropagation();showDeviceDetail('${d.deviceId}')">Detail</button></td>
            </tr>`;
        }).join('');

        // Customer alerts
        const custAlertsEl = document.getElementById('customer-alerts');
        if (custAlerts.length === 0) {
            custAlertsEl.innerHTML = '<div class="empty-state"><p>No active alerts for this customer.</p></div>';
        } else {
            custAlertsEl.innerHTML = custAlerts.slice(0, 15).map(a => `
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
        console.error('Failed to load customer dashboard:', err);
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

    // Show device page instead of modal
    currentDevice = deviceId;
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('page-device').style.display = 'block';
    currentPage = 'device';
    loadDeviceDetail(d);
}

let currentDevice = '';

function loadDeviceDetail(d) {
    if (!d && currentDevice) d = allDevices.find(x => x.deviceId === currentDevice);
    if (!d) return;

    const status = d.lockdownActive ? 'lockdown' : (d.isOnline ? 'online' : 'offline');
    const statusLabel = d.lockdownActive ? 'LOCKDOWN' : (d.isOnline ? 'Online' : 'Offline');
    const gradeClass = (d.securityGrade || '?').toLowerCase();
    const cpuColor = d.cpuPercent > 90 ? '#ef4444' : d.cpuPercent > 70 ? '#f59e0b' : '#22c55e';
    const ramColor = d.ramPercent > 90 ? '#ef4444' : d.ramPercent > 70 ? '#f59e0b' : '#22c55e';
    const diskColor = d.diskPercent > 90 ? '#ef4444' : d.diskPercent > 80 ? '#f59e0b' : '#22c55e';
    const cpuTempColor = d.cpuTempC > 85 ? '#ef4444' : d.cpuTempC > 70 ? '#f59e0b' : '#22c55e';
    const gpuTempColor = d.gpuTempC > 85 ? '#ef4444' : d.gpuTempC > 70 ? '#f59e0b' : '#22c55e';
    const scoreColor = d.securityScore >= 80 ? '#22c55e' : d.securityScore >= 60 ? '#f59e0b' : '#ef4444';
    const uptimeStr = d.uptime || '-';

    // Build circular gauge SVG helper
    function gauge(pct, color, size=80) {
        const r = (size/2) - 6;
        const circ = 2 * Math.PI * r;
        const dash = (pct/100) * circ;
        return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
            <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="8"/>
            <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="${color}" stroke-width="8"
                stroke-dasharray="${dash} ${circ - dash}" stroke-dashoffset="${circ/4}" stroke-linecap="round"
                transform="rotate(-90 ${size/2} ${size/2})"/>
            <text x="${size/2}" y="${size/2 + 5}" text-anchor="middle" fill="var(--text-primary)" font-size="18" font-weight="bold">${Math.round(pct)}%</text>
        </svg>`;
    }

    // Navigation breadcrumb
    const custName = d.customerName || d.customerId || 'Unassigned';
    document.getElementById('device-title').textContent = d.hostname || d.deviceId;
    document.getElementById('device-breadcrumb').innerHTML = `
        <a href="#" onclick="showPage('overview');return false" style="color:#3b82f6;text-decoration:none">Dashboard</a>
        <span style="color:var(--text-muted);margin:0 6px">/</span>
        <a href="#" onclick="showCustomerDashboard('${esc(custName)}');return false" style="color:#3b82f6;text-decoration:none">${esc(custName)}</a>
        <span style="color:var(--text-muted);margin:0 6px">/</span>
        <span style="color:var(--text-primary)">${esc(d.hostname || d.deviceId)}</span>
    `;

    const content = document.getElementById('device-detail-content');
    content.innerHTML = `
        <!-- Device Header -->
        <div class="card" style="padding:20px;margin-bottom:16px">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
                <div style="display:flex;align-items:center;gap:16px">
                    <div style="width:56px;height:56px;border-radius:12px;background:linear-gradient(135deg,#1e293b,#334155);display:flex;align-items:center;justify-content:center">
                        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                    </div>
                    <div>
                        <h2 style="margin:0;font-size:22px;font-weight:700">${esc(d.hostname || d.deviceId)}</h2>
                        <div style="color:var(--text-muted);font-size:13px;margin-top:2px">
                            ${esc(custName)} &middot; ${esc(d.osVersion || 'Unknown OS')} &middot; Agent v${esc(d.agentVersion || '-')}
                        </div>
                    </div>
                </div>
                <div style="display:flex;align-items:center;gap:10px">
                    <span class="badge ${status}" style="font-size:13px;padding:8px 16px"><span class="badge-dot"></span>${statusLabel}</span>
                    <button class="btn btn-sm btn-primary" onclick="sendCommand('${d.deviceId}','rescan')">Run Security Scan</button>
                    <button class="btn btn-sm btn-secondary" onclick="sendCommand('${d.deviceId}','maintenance')">Fix My Computer</button>
                    <button class="btn btn-sm btn-danger" onclick="sendCommand('${d.deviceId}','lockdown')">Emergency Lockdown</button>
                </div>
            </div>
        </div>

        <!-- Performance Gauges Row -->
        <div style="display:grid;grid-template-columns:repeat(5, 1fr);gap:12px;margin-bottom:16px">
            <div class="card" style="padding:16px;text-align:center">
                <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">CPU Usage</div>
                ${gauge(d.cpuPercent || 0, cpuColor)}
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">${d.cpuModel || 'CPU'}</div>
            </div>
            <div class="card" style="padding:16px;text-align:center">
                <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Memory</div>
                ${gauge(d.ramPercent || 0, ramColor)}
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">${d.ramUsedGB ? d.ramUsedGB.toFixed(1) + ' / ' + d.ramTotalGB.toFixed(1) + ' GB' : '-'}</div>
            </div>
            <div class="card" style="padding:16px;text-align:center">
                <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Disk Usage</div>
                ${gauge(d.diskPercent || 0, diskColor)}
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">${d.diskFreeGB ? d.diskFreeGB.toFixed(0) + ' GB free' : '-'}</div>
            </div>
            <div class="card" style="padding:16px;text-align:center">
                <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">CPU Temp</div>
                <div style="font-size:42px;font-weight:700;color:${cpuTempColor};line-height:1.2">${d.cpuTempC > 0 ? Math.round(d.cpuTempC) + '°' : '-'}</div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:8px">GPU: ${d.gpuTempC > 0 ? Math.round(d.gpuTempC) + '°C' : '-'}</div>
            </div>
            <div class="card" style="padding:16px;text-align:center">
                <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Security Score</div>
                ${gauge(d.securityScore || 0, scoreColor)}
                <div style="margin-top:4px"><span class="score ${gradeClass}" style="font-size:14px;padding:4px 10px">${esc(d.securityGrade || '?')}</span></div>
            </div>
        </div>

        <!-- Middle Row: Security + Network + System -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">
            <!-- Security Details - from real scan data -->
            <div class="card" style="padding:20px">
                <h4 style="margin:0 0 16px;font-size:14px;display:flex;align-items:center;gap:8px">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    Security Details
                </h4>
                <div style="display:grid;gap:10px;font-size:13px">
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Security Score</span>
                        <span style="font-weight:600;color:${scoreColor}">${d.securityScore}/100</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Grade</span>
                        <span class="score ${gradeClass}" style="font-size:12px;padding:2px 8px">${esc(d.securityGrade || '?')}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Running Modules</span>
                        <span style="font-weight:600">${d.runningModules}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">License Tier</span>
                        <span class="badge info">${esc(d.licenseTier || 'Free')}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Policy Profile</span>
                        <span style="font-weight:500">${esc(d.policyProfile || 'default')}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between">
                        <span style="color:var(--text-muted)">Lockdown</span>
                        <span style="color:${d.lockdownActive ? '#ef4444' : '#22c55e'};font-weight:600">${d.lockdownActive ? 'ACTIVE' : 'Inactive'}</span>
                    </div>
                </div>
            </div>

            <!-- Network Details -->
            <div class="card" style="padding:20px">
                <h4 style="margin:0 0 16px;font-size:14px;display:flex;align-items:center;gap:8px">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                    Network
                </h4>
                <div style="display:grid;gap:10px;font-size:13px">
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Local IP</span>
                        <span style="font-weight:600;font-family:monospace">${esc(d.localIp || d.ipAddress || '-')}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Public IP</span>
                        <span style="font-weight:600;font-family:monospace">${esc(d.publicIp || '-')}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">MAC Address</span>
                        <span style="font-weight:500;font-family:monospace;font-size:11px">${esc(d.macAddress || '-')}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Network Up</span>
                        <span style="font-weight:500">${d.networkSentKBps ? d.networkSentKBps.toFixed(0) + ' KB/s' : '-'}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Network Down</span>
                        <span style="font-weight:500">${d.networkRecvKBps ? d.networkRecvKBps.toFixed(0) + ' KB/s' : '-'}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Firewall</span>
                        <span style="color:${d.firewallEnabled !== false ? '#22c55e' : '#ef4444'};font-weight:600">${d.firewallEnabled !== false ? 'Enabled' : 'Disabled'}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between">
                        <span style="color:var(--text-muted)">Open Ports</span>
                        <span style="font-weight:500">${d.openPorts || '-'}</span>
                    </div>
                </div>
            </div>

            <!-- System Details -->
            <div class="card" style="padding:20px">
                <h4 style="margin:0 0 16px;font-size:14px;display:flex;align-items:center;gap:8px">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                    System Info
                </h4>
                <div style="display:grid;gap:10px;font-size:13px">
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">OS Version</span>
                        <span style="font-weight:500;font-size:11px">${esc(d.osVersion || '-')}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Agent Version</span>
                        <span style="font-weight:600">v${esc(d.agentVersion || '-')}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Customer</span>
                        <span style="display:flex;align-items:center;gap:8px">
                            <span style="font-weight:500" id="dev-customer-label">${esc(custName)}</span>
                            <button onclick="reassignDevice('${esc(d.deviceId)}','${esc(custName)}')" style="background:none;border:1px solid var(--border);color:var(--text-muted);padding:2px 8px;border-radius:4px;cursor:pointer;font-size:11px" title="Move to different customer">Move</button>
                        </span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Device ID</span>
                        <span style="font-weight:500;font-family:monospace;font-size:10px">${esc(d.deviceId.substring(0,16))}...</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Registered</span>
                        <span style="font-weight:500">${d.registeredAt ? new Date(d.registeredAt).toLocaleDateString() : '-'}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid var(--border)">
                        <span style="color:var(--text-muted)">Last Seen</span>
                        <span style="font-weight:600;color:${d.isOnline ? '#22c55e' : '#ef4444'}">${timeAgo(d.lastSeen)}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between">
                        <span style="color:var(--text-muted)">Processes</span>
                        <span style="font-weight:500">${d.processCount || '-'}</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Storage & Donuts Row -->
        <div style="display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px;margin-bottom:16px">
            <!-- Storage Drives -->
            <div class="card" style="padding:20px">
                <h4 style="margin:0 0 16px;font-size:14px;display:flex;align-items:center;gap:8px">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                    Storage Drives
                </h4>
                ${(d.disks && d.disks.length > 0) ? d.disks.map(disk => {
                    const dColor = disk.usedPercent > 90 ? '#ef4444' : disk.usedPercent > 80 ? '#f59e0b' : '#22c55e';
                    return `<div style="margin-bottom:12px">
                        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
                            <span style="font-weight:600">${esc(disk.name)} Drive</span>
                            <span style="color:var(--text-muted)">${disk.freeGB ? disk.freeGB.toFixed(0) : '?'} GB free / ${disk.totalGB ? disk.totalGB.toFixed(0) : '?'} GB</span>
                        </div>
                        <div class="progress" style="height:10px"><div class="progress-bar" style="width:${disk.usedPercent}%;background:${dColor}"></div></div>
                        <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${Math.round(disk.usedPercent)}% used</div>
                    </div>`;
                }).join('') : `
                    <div style="margin-bottom:12px">
                        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
                            <span style="font-weight:600">System Drive</span>
                            <span style="color:var(--text-muted)">${d.diskFreeGB ? d.diskFreeGB.toFixed(0) + ' GB free' : '-'}</span>
                        </div>
                        <div class="progress" style="height:10px"><div class="progress-bar" style="width:${d.diskPercent}%;background:${diskColor}"></div></div>
                        <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${Math.round(d.diskPercent || 0)}% used</div>
                    </div>
                `}
            </div>

            <!-- Device Status Donut -->
            <div class="card" style="padding:20px;text-align:center">
                <h4 style="margin-bottom:12px;font-size:13px;color:var(--text-muted)">Protection Status</h4>
                <div id="dev-donut-protection"></div>
            </div>

            <!-- Resource Health Donut -->
            <div class="card" style="padding:20px;text-align:center">
                <h4 style="margin-bottom:12px;font-size:13px;color:var(--text-muted)">Resource Health</h4>
                <div id="dev-donut-resources"></div>
            </div>
        </div>

        <!-- Top Processes + Recent Alerts -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
            <!-- Top Processes -->
            <div class="card" style="padding:20px">
                <h4 style="margin:0 0 12px;font-size:14px;display:flex;align-items:center;gap:8px">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    Top Processes
                </h4>
                <table style="width:100%;font-size:12px">
                    <thead><tr><th style="text-align:left;padding:4px 8px">Process</th><th>CPU</th><th>Memory</th></tr></thead>
                    <tbody id="dev-processes">
                        <tr><td colspan="3" style="text-align:center;padding:16px;color:var(--text-muted)">Process data from agent</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Recent Device Alerts -->
            <div class="card" style="padding:20px">
                <h4 style="margin:0 0 12px;font-size:14px;display:flex;align-items:center;gap:8px">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                    Recent Alerts
                </h4>
                <div id="dev-alerts"></div>
            </div>
        </div>

        <!-- Modules Running -->
        <div class="card" style="padding:20px;margin-bottom:16px">
            <h4 style="margin:0 0 12px;font-size:14px;display:flex;align-items:center;gap:8px">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                Active Protection Modules
            </h4>
            <div id="dev-modules" style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:8px">
            </div>
        </div>

        <!-- Security Audit - 360 View -->
        <div class="card" style="padding:20px;margin-bottom:16px">
            <h4 style="margin:0 0 4px;font-size:16px;display:flex;align-items:center;gap:8px">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                360° Security Audit
            </h4>
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:16px">Real-time security check results from endpoint agent</div>
            <div id="dev-security-audit"></div>
        </div>
    `;

    // Populate donuts
    const protectedModules = d.runningModules || 0;
    createDonutChart('dev-donut-protection', [
        { label: 'Active', value: Math.max(protectedModules, 0), color: '#22c55e' },
        { label: 'Inactive', value: Math.max((d.totalModules || 6) - protectedModules, 0), color: '#6b7280' }
    ], protectedModules.toString(), 120);

    const cpuHealth = d.cpuPercent <= 70 ? 1 : 0;
    const ramHealth = d.ramPercent <= 80 ? 1 : 0;
    const diskHealth = d.diskPercent <= 85 ? 1 : 0;
    const tempHealth = (d.cpuTempC <= 75 || d.cpuTempC === 0) ? 1 : 0;
    const healthyCount = cpuHealth + ramHealth + diskHealth + tempHealth;
    createDonutChart('dev-donut-resources', [
        { label: 'Healthy', value: healthyCount, color: '#22c55e' },
        { label: 'Warning', value: 4 - healthyCount, color: '#f59e0b' }
    ], healthyCount + '/4', 120);

    // Populate security audit from securityChecksJson
    const auditEl = document.getElementById('dev-security-audit');
    let checks = [];
    try {
        if (d.securityChecksJson && d.securityChecksJson !== '[]')
            checks = JSON.parse(d.securityChecksJson).map(c => ({
                id: c.Id || c.id,
                name: c.Name || c.name,
                category: c.Category || c.category,
                passed: c.Passed != null ? c.Passed : c.passed,
                detail: c.Detail || c.detail,
                recommendation: c.Recommendation || c.recommendation,
                weight: c.Weight || c.weight
            }));
    } catch(e) {}

    if (checks.length > 0) {
        // Group by category
        const categories = {};
        checks.forEach(c => {
            if (!categories[c.category]) categories[c.category] = [];
            categories[c.category].push(c);
        });

        const catIcons = {
            'Protection': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
            'Updates': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>',
            'Data Protection': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
            'Network': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
            'Access': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ec4899" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
            'Identity & Access': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ec4899" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
            'Ransomware Protection': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>',
            'EDR & Advanced': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
            'Device Health': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>'
        };

        auditEl.innerHTML = Object.entries(categories).map(([cat, catChecks]) => {
            const passed = catChecks.filter(c => c.passed).length;
            const total = catChecks.length;
            const allPassed = passed === total;
            const icon = catIcons[cat] || catIcons['Protection'];

            return `
                <div style="margin-bottom:16px">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border)">
                        ${icon}
                        <span style="font-weight:600;font-size:13px">${esc(cat)}</span>
                        <span style="margin-left:auto;font-size:12px;padding:2px 8px;border-radius:10px;background:${allPassed ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)'};color:${allPassed ? '#22c55e' : '#ef4444'};font-weight:600">${passed}/${total} passed</span>
                    </div>
                    ${catChecks.map(c => {
                        const remediable = ['cfa','defender_rt','firewall','rdp','rdp_exposure','smbv1','uac','ps_logging','ps_exec_policy','guest','autologin','shadow_copies','asr_rules','lsass_protect','dns_security'].includes(c.id);
                        const manualOnly = ['tamper_protect','bitlocker','backup','edr','secure_boot'].includes(c.id);
                        return `
                        <div style="display:flex;align-items:flex-start;gap:10px;padding:8px 4px 8px 8px;border-radius:6px;margin-bottom:2px;background:${c.passed ? 'transparent' : 'rgba(239,68,68,0.05)'}">
                            <span style="font-size:14px;margin-top:1px;flex-shrink:0">${c.passed ? '<span style="color:#22c55e">&#10003;</span>' : '<span style="color:#ef4444">&#10007;</span>'}</span>
                            <div style="flex:1;min-width:0">
                                <div style="font-size:13px;font-weight:${c.passed ? '400' : '600'};color:${c.passed ? 'var(--text-primary)' : '#ef4444'}">${esc(c.name)}</div>
                                <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${esc(c.detail)}</div>
                                ${!c.passed && c.recommendation ? `<div style="font-size:11px;color:#f59e0b;margin-top:2px;font-style:italic">&#9888; ${esc(c.recommendation)}</div>` : ''}
                            </div>
                            ${!c.passed && remediable ? `<button onclick="remediateCheck('${c.id}','${esc(c.name)}')" style="flex-shrink:0;background:#16a34a;color:#fff;border:none;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600" title="Auto-fix this issue">Fix</button>` : ''}
                            ${!c.passed && manualOnly ? `<span style="flex-shrink:0;font-size:10px;color:var(--text-muted);padding:3px 8px;border:1px solid var(--border);border-radius:4px" title="Requires manual action">Manual</span>` : ''}
                            <span style="font-size:10px;color:var(--text-muted);flex-shrink:0;padding:2px 6px;background:var(--bg-main);border-radius:4px">${c.weight}pts</span>
                        </div>`;
                    }).join('')}
                </div>
            `;
        }).join('');
    } else {
        auditEl.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted)">Security audit data will appear after the agent runs its first scan (runs every 30 minutes)</div>';
    }

    // Load device-specific alerts
    loadDeviceAlerts(d);

    // Populate modules
    const modulesEl = document.getElementById('dev-modules');
    const moduleNames = ['Health Monitor', 'Security Scanner', 'Ransomware Guard', 'Maintenance', 'Network Monitor', 'Process Monitor'];
    modulesEl.innerHTML = moduleNames.slice(0, Math.max(d.totalModules || 6, d.runningModules || 0)).map((name, i) => {
        const running = i < (d.runningModules || 0);
        return `<div style="display:flex;align-items:center;gap:8px;padding:10px;background:var(--bg-main);border-radius:6px">
            <div style="width:10px;height:10px;border-radius:50%;background:${running ? '#22c55e' : '#6b7280'}"></div>
            <span style="font-size:13px;font-weight:500">${name}</span>
            <span style="margin-left:auto;font-size:11px;color:${running ? '#22c55e' : 'var(--text-muted)'}">${running ? 'Running' : 'Stopped'}</span>
        </div>`;
    }).join('');
}

function generateDeviceReport() {
    if (!currentDevice) return;
    window.open('/report.html?deviceId=' + encodeURIComponent(currentDevice), '_blank');
}

function generateCompanyReport(mode) {
    if (!currentCustomer) return;
    if (mode === 'html') {
        window.open('/api/reports/company/' + encodeURIComponent(currentCustomer), '_blank');
    } else {
        window.open('/company-report.html?customer=' + encodeURIComponent(currentCustomer), '_blank');
    }
}

async function reassignDevice(deviceId, currentCustomer) {
    // Get list of existing customers from loaded devices
    const customers = [...new Set(allDevices.map(d => d.customerName).filter(Boolean))].sort();
    const newCustomer = prompt(
        'Move device to which customer?\n\nExisting customers:\n' +
        customers.map(c => '  - ' + c).join('\n') +
        '\n\nEnter customer name (or type a new one):',
        currentCustomer
    );
    if (!newCustomer || newCustomer === currentCustomer) return;

    try {
        const res = await fetch(API + '/devices/' + encodeURIComponent(deviceId) + '/customer', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ customerName: newCustomer })
        });
        if (res.ok) {
            alert('Device moved to "' + newCustomer + '" successfully!\nThe agent will also update its config on next heartbeat.');
            document.getElementById('dev-customer-label').textContent = newCustomer;
            // Refresh data
            refreshCurrentPage();
        } else {
            alert('Failed to reassign device: ' + res.statusText);
        }
    } catch(e) {
        alert('Error: ' + e.message);
    }
}

async function remediateCheck(checkId, checkName) {
    if (!currentDevice) return;
    if (!confirm('Apply automatic fix for "' + checkName + '"?\n\nThis will be applied on the next agent heartbeat (within 30 seconds).')) return;

    try {
        const res = await fetch(API + '/devices/' + encodeURIComponent(currentDevice) + '/remediate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ checkId: checkId })
        });
        if (res.ok) {
            const data = await res.json();
            alert('Fix queued successfully!\n\n' + (data.message || 'The fix will be applied on next heartbeat.') + '\n\nThe security score will update after the device re-scans.');
            // Refresh device detail after a short delay to show updated status
            setTimeout(() => refreshCurrentPage(), 2000);
        } else {
            alert('Failed to queue fix: ' + res.statusText);
        }
    } catch(e) {
        alert('Error: ' + e.message);
    }
}

async function loadDeviceAlerts(d) {
    try {
        const alerts = await fetch(API + '/alerts?limit=50&acknowledged=false').then(r => r.json());
        const devAlerts = alerts.filter(a => (a.hostname || a.deviceId) === (d.hostname || d.deviceId));
        const alertsEl = document.getElementById('dev-alerts');
        if (!alertsEl) return;

        if (devAlerts.length === 0) {
            alertsEl.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No active alerts for this device</div>';
        } else {
            alertsEl.innerHTML = devAlerts.slice(0, 10).map(a => `
                <div class="alert-item" style="padding:8px 0;border-bottom:1px solid var(--border)">
                    <div class="alert-severity ${a.severity}"></div>
                    <div class="alert-content">
                        <div style="font-size:12px;font-weight:600">${esc(a.title)}</div>
                        <div style="font-size:11px;color:var(--text-muted)">${timeAgo(a.timestamp)} &middot; ${a.severity}</div>
                    </div>
                </div>
            `).join('');
        }
    } catch(err) { console.error('Failed to load device alerts', err); }
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
