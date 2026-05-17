/**
 * PC Plus Dashboard API Layer v4.23.0
 * Fetches real data from the backend and populates dashboard pages.
 * Include this script on any dashboard page to wire up live data.
 */
const DashboardAPI = (() => {
  const BASE = '';  // Same origin when served by the .NET app

  async function fetchJSON(url, options = {}) {
    const res = await fetch(BASE + url, { credentials: 'include', ...options });
    if (res.status === 401) {
      window.location.href = '/login.html';
      return null;
    }
    if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
    return res.json();
  }

  async function post(url, body) {
    return fetchJSON(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  async function put(url, body) {
    return fetchJSON(url, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  // Auth
  const auth = {
    me: () => fetchJSON('/api/auth/me'),
    login: (username, password) => post('/api/auth/login', { username, password }),
    logout: () => post('/api/auth/logout', {})
  };

  // Dashboard overview
  const dashboard = {
    overview: () => fetchJSON('/api/dashboard/overview'),
    devices: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return fetchJSON(`/api/dashboard/devices${q ? '?' + q : ''}`);
    },
    device: (id) => fetchJSON(`/api/dashboard/devices/${id}`),
    alerts: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return fetchJSON(`/api/dashboard/alerts${q ? '?' + q : ''}`);
    },
    incidents: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return fetchJSON(`/api/dashboard/incidents${q ? '?' + q : ''}`);
    },
    ackAlert: (id) => post(`/api/dashboard/alerts/${id}/ack`, {}),
    sendCommand: (deviceId, command) => post(`/api/dashboard/devices/${deviceId}/command`, { command }),
    remediate: (deviceId, checkId) => post(`/api/dashboard/devices/${deviceId}/remediate`, { checkId }),
    pushConfig: (deviceId, config) => post('/api/dashboard/config/push', { deviceId, config }),
    policies: () => fetchJSON('/api/dashboard/policies'),
    history: {
      device: (id, days = 30) => fetchJSON(`/api/dashboard/history/device/${id}?days=${days}`),
      customer: (name, days = 30) => fetchJSON(`/api/dashboard/history/customer/${encodeURIComponent(name)}?days=${days}`),
      overview: (days = 30) => fetchJSON(`/api/dashboard/history/overview?days=${days}`)
    }
  };

  // Security-specific endpoints
  const security = {
    scanResults: (deviceId) => fetchJSON(`/api/dashboard/devices/${deviceId}/scan-results`),
    accessControl: (deviceId) => fetchJSON(`/api/dashboard/devices/${deviceId}/access-control`),
    backup: (deviceId) => fetchJSON(`/api/dashboard/devices/${deviceId}/backup`),
    network: (deviceId) => fetchJSON(`/api/dashboard/devices/${deviceId}/network`),
    ransomware: (deviceId) => fetchJSON(`/api/dashboard/devices/${deviceId}/ransomware`),
    realtimeProtection: (deviceId) => fetchJSON(`/api/dashboard/devices/${deviceId}/realtime-protection`),
    compliance: (deviceId) => fetchJSON(`/api/dashboard/devices/${deviceId}/compliance`),
    logs: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return fetchJSON(`/api/dashboard/security-logs${q ? '?' + q : ''}`);
    }
  };

  // Customer management
  const customers = {
    list: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return fetchJSON(`/api/dashboard/customers${q ? '?' + q : ''}`);
    },
    detail: (name) => fetchJSON(`/api/dashboard/customers/${encodeURIComponent(name)}`),
    setTier: (name, tier) => put(`/api/dashboard/customers/${encodeURIComponent(name)}/tier`, { tier })
  };

  // Reports
  const reports = {
    company: (name) => fetchJSON(`/api/reports/company/${encodeURIComponent(name)}`)
  };

  // Utility: populate overview stats on the main dashboard
  async function populateOverview() {
    try {
      const data = await dashboard.overview();
      if (!data) return;

      setTextContent('[data-stat="total-devices"]', data.totalDevices);
      setTextContent('[data-stat="online-devices"]', data.onlineDevices);
      setTextContent('[data-stat="offline-devices"]', data.offlineDevices);
      setTextContent('[data-stat="active-alerts"]', data.activeAlerts);
      setTextContent('[data-stat="critical-alerts"]', data.criticalAlerts);
      setTextContent('[data-stat="lockdown-devices"]', data.devicesInLockdown);
      setTextContent('[data-stat="open-incidents"]', data.openIncidents);
      setTextContent('[data-stat="avg-score"]', Math.round(data.avgSecurityScore));

      // Tier breakdown
      if (data.devicesByTier) {
        setTextContent('[data-stat="tier-free"]', data.devicesByTier['Free'] || 0);
        setTextContent('[data-stat="tier-home"]', data.devicesByTier['Home'] || 0);
        setTextContent('[data-stat="tier-business"]', data.devicesByTier['Business'] || 0);
        setTextContent('[data-stat="tier-enterprise"]', data.devicesByTier['Enterprise'] || 0);
      }
    } catch (e) {
      console.error('Failed to load overview:', e);
    }
  }

  // Utility: populate customer list
  async function populateCustomers(containerId) {
    try {
      const data = await customers.list();
      if (!data) return;
      const container = document.getElementById(containerId);
      if (!container) return;

      container.innerHTML = data.map(c => `
        <tr>
          <td><strong>${escapeHtml(c.customerName)}</strong></td>
          <td><span class="tier-badge tier-${c.licenseTier.toLowerCase()}">${c.licenseTier}</span></td>
          <td>${c.deviceCount}</td>
          <td>${c.onlineDevices}/${c.deviceCount}</td>
          <td><span class="score-badge grade-${getGradeClass(c.avgGrade)}">${Math.round(c.avgSecurityScore)}% (${c.avgGrade})</span></td>
          <td>${c.totalAlerts}</td>
          <td>${timeAgo(c.lastSeen)}</td>
        </tr>
      `).join('');
    } catch (e) {
      console.error('Failed to load customers:', e);
    }
  }

  // Utility: populate device list
  async function populateDevices(containerId, params = {}) {
    try {
      const data = await dashboard.devices(params);
      if (!data) return;
      const container = document.getElementById(containerId);
      if (!container) return;

      container.innerHTML = data.map(d => `
        <tr data-device-id="${escapeHtml(d.deviceId)}">
          <td>
            <span class="status-dot ${d.isOnline ? 'online' : 'offline'}"></span>
            <strong>${escapeHtml(d.hostname)}</strong>
          </td>
          <td>${escapeHtml(d.customerName)}</td>
          <td><span class="tier-badge tier-${d.licenseTier.toLowerCase()}">${d.licenseTier}</span></td>
          <td>${escapeHtml(d.osVersion)}</td>
          <td>${Math.round(d.securityScore)}% (${d.securityGrade})</td>
          <td>${Math.round(d.cpuPercent)}%</td>
          <td>${Math.round(d.ramPercent)}%</td>
          <td>${timeAgo(d.lastSeen)}</td>
        </tr>
      `).join('');
    } catch (e) {
      console.error('Failed to load devices:', e);
    }
  }

  // Utility: populate scan results for a device
  async function populateScanResults(deviceId, containerId) {
    try {
      const data = await security.scanResults(deviceId);
      if (!data) return;
      const container = document.getElementById(containerId);
      if (!container) return;

      // Update summary
      setTextContent('[data-stat="total-checks"]', data.totalChecks);
      setTextContent('[data-stat="passed-checks"]', data.passedChecks);
      setTextContent('[data-stat="failed-checks"]', data.failedChecks);
      setTextContent('[data-stat="security-score"]', data.securityScore + '%');
      setTextContent('[data-stat="security-grade"]', data.securityGrade);

      // Build category sections
      container.innerHTML = data.categories.map(cat => `
        <div class="category-section">
          <div class="category-header">
            <h3>${escapeHtml(cat.category)}</h3>
            <span class="category-score">${Math.round(cat.compliancePercent)}% (${cat.passedChecks}/${cat.totalChecks})</span>
          </div>
          <table class="checks-table">
            <thead><tr><th>Status</th><th>Check</th><th>Detail</th><th>Frameworks</th></tr></thead>
            <tbody>
              ${cat.checks.map(c => `
                <tr class="${c.passed ? 'passed' : 'failed'}">
                  <td><span class="check-icon ${c.passed ? 'pass' : 'fail'}">${c.passed ? '&#10003;' : '&#10007;'}</span></td>
                  <td><strong>${escapeHtml(c.name)}</strong><br><small>${c.id}</small></td>
                  <td>${escapeHtml(c.detail)}${c.recommendation ? `<br><em>${escapeHtml(c.recommendation)}</em>` : ''}</td>
                  <td>${(c.complianceFrameworks || []).map(f => `<span class="framework-tag">${f}</span>`).join(' ')}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `).join('');
    } catch (e) {
      console.error('Failed to load scan results:', e);
    }
  }

  // Helpers
  function setTextContent(selector, value) {
    const el = document.querySelector(selector);
    if (el) el.textContent = value;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function timeAgo(dateStr) {
    if (!dateStr) return 'Never';
    const d = new Date(dateStr);
    const now = new Date();
    const diff = (now - d) / 1000;
    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    return Math.floor(diff/86400) + 'd ago';
  }

  function getGradeClass(grade) {
    if (!grade) return 'f';
    const g = grade.charAt(0).toUpperCase();
    if (g === 'A') return 'a';
    if (g === 'B') return 'b';
    if (g === 'C') return 'c';
    if (g === 'D') return 'd';
    return 'f';
  }

  // Get device ID from URL params
  function getDeviceId() {
    return new URLSearchParams(window.location.search).get('deviceId') || '';
  }

  // Get customer name from URL params
  function getCustomerName() {
    return new URLSearchParams(window.location.search).get('customer') || '';
  }

  return {
    auth, dashboard, security, customers, reports,
    populateOverview, populateCustomers, populateDevices, populateScanResults,
    getDeviceId, getCustomerName, escapeHtml, timeAgo, getGradeClass,
    fetchJSON, post, put
  };
})();
