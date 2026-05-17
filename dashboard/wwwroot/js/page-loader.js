/**
 * PC Plus Dashboard - Page Loader v4.23.0
 * Auto-detects the current page and loads live data from the backend API.
 * Requires dashboard-api.js and device-persistence.js to be loaded first.
 */
(function() {
  const PAGE = location.pathname.split('/').pop() || 'index.html';

  window.addEventListener('DOMContentLoaded', async function() {
    try {
      const user = await DashboardAPI.auth.me();
      if (!user) return;
    } catch(e) { return; }

    let deviceId = getDeviceId();
    const customerName = getCustomerName();

    // If no device selected but customer is, auto-select first online device for that customer
    if (!deviceId && customerName) {
      try {
        const detail = await DashboardAPI.customers.detail(customerName);
        if (detail && detail.devices && detail.devices.length > 0) {
          const online = detail.devices.find(d => d.isOnline) || detail.devices[0];
          deviceId = online.deviceId;
        }
      } catch(e) {}
    }

    switch(PAGE) {
      case 'ransomware-shield.html': await loadRansomware(deviceId); break;
      case 'realtime-protection.html': await loadRealtimeProtection(deviceId); break;
      case 'security-logs.html': await loadSecurityLogs(); break;
      case 'compliance-overview.html': await loadCompliance(deviceId); break;
      case 'scan-results.html': await loadScanResults(deviceId); break;
      case 'network-security.html': await loadNetwork(deviceId); break;
      case 'backup-detail.html': await loadBackup(deviceId); break;
      case 'access-control.html': await loadAccessControl(deviceId); break;
      case 'reports.html': await loadReports(); break;
      case 'server-management.html': await loadServerManagement(); break;
      case 'settings.html': await loadSettings(deviceId); break;
      case 'ai-advisor.html': await loadAiAdvisor(deviceId); break;
    }
  });

  function getDeviceId() {
    const params = new URLSearchParams(location.search);
    let id = params.get('deviceId');
    if (!id && window.PCPlusPersistence) {
      const stored = PCPlusPersistence.getStoredDevice();
      if (stored) id = stored.deviceId;
    }
    return id || '';
  }

  function getCustomerName() {
    const params = new URLSearchParams(location.search);
    let name = params.get('customerName');
    if (!name && window.PCPlusPersistence) {
      name = PCPlusPersistence.getStoredCustomer();
    }
    return name || '';
  }

  function setText(sel, val) {
    const el = document.querySelector(sel);
    if (el) el.textContent = val != null ? val : '--';
  }

  function setHtml(sel, html) {
    const el = document.querySelector(sel);
    if (el) el.innerHTML = html;
  }

  function esc(s) { return DashboardAPI.escapeHtml(s || ''); }

  function fmtDate(d) {
    if (!d) return 'Never';
    const dt = new Date(d);
    return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + ' ' +
      dt.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
  }

  // ─── RANSOMWARE SHIELD ───
  async function loadRansomware(deviceId) {
    if (!deviceId) { showNoDevice(); return; }
    try {
      const data = await DashboardAPI.security.ransomware(deviceId);
      if (!data) return;

      const banner = document.querySelector('.status-title');
      if (banner) banner.textContent = 'Ransomware Shield: ' + (data.behaviorMonitoringEnabled ? 'ACTIVE' : 'MONITORING');

      const sub = document.querySelector('.status-sub');
      if (sub) sub.textContent = data.honeypotActive ? 'Honeypot decoys deployed - behavioral analysis active' : 'Monitoring file system activity';

      const statVals = document.querySelectorAll('.status-stat-val');
      if (statVals[0]) statVals[0].textContent = fmtDate(data.lastUpdated);
      if (statVals[1]) statVals[1].textContent = (data.threatHistory || []).length + ' Detected';

      // Stat cards
      const cards = document.querySelectorAll('.stat-card-title');
      if (cards.length >= 4) {
        const parent0 = cards[0]?.closest('.card');
        if (parent0) {
          const val = parent0.querySelector('.stat-card-sub');
          if (val) val.textContent = data.behaviorMonitoringEnabled ? 'Active - monitoring processes' : 'Passive mode';
        }
        const parent1 = cards[1]?.closest('.card');
        if (parent1) {
          const val = parent1.querySelector('.stat-card-sub');
          if (val) val.textContent = (data.protectedFolders || []).length + ' folders protected';
        }
        const parent2 = cards[2]?.closest('.card');
        if (parent2) {
          const status = parent2.querySelector('.stat-card-status');
          if (status) {
            status.textContent = data.shadowCopyProtected ? 'Protected' : 'Not Protected';
            status.className = 'stat-card-status ' + (data.shadowCopyProtected ? 'status-ok' : 'status-warn');
          }
        }
        const parent3 = cards[3]?.closest('.card');
        if (parent3) {
          const val = parent3.querySelector('.stat-card-sub');
          if (val) val.textContent = data.honeypotActive ? 'Decoy files deployed' : 'No decoys active';
          const st3 = parent3.querySelector('.stat-card-status');
          if (st3) st3.textContent = data.honeypotActive ? 'Active' : 'Inactive';
        }
      }

      // Update stat card statuses
      const allCards = document.querySelectorAll('.row-4 > .card');
      if (allCards[0]) {
        const st = allCards[0].querySelector('.stat-card-status');
        if (st) st.textContent = data.behaviorMonitoringEnabled ? 'Active' : 'Inactive';
      }
      if (allCards[1]) {
        const st = allCards[1].querySelector('.stat-card-status');
        if (st) st.textContent = (data.protectedFolders || []).length + ' Folders Protected';
      }
      if (allCards[2]) {
        const st = allCards[2].querySelector('.stat-card-status');
        if (st) {
          st.textContent = data.shadowCopyProtected ? 'Protected' : 'Not Protected';
          st.className = 'stat-card-status ' + (data.shadowCopyProtected ? 'status-ok' : 'status-warn');
        }
      }

      // Protected folders list
      const folderList = document.querySelector('.folder-list');
      if (folderList && data.protectedFolders && data.protectedFolders.length > 0) {
        folderList.innerHTML = data.protectedFolders.length > 0 ?
          data.protectedFolders.map(f => `
          <div class="folder-item">
            <div class="folder-item-left">
              <div class="folder-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg></div>
              <div><div class="folder-name">${esc(f.split('\\').pop() || f)}</div><div class="folder-path">${esc(f)}</div></div>
            </div>
            <div class="folder-item-right">
              <span class="protected-badge-sm">Protected</span>
            </div>
          </div>`).join('') :
          '<div style="padding:16px;text-align:center;color:#64748b;font-size:12px;">Folder protection will be configured during setup</div>';
      }

      // Detection rules
      const ruleList = document.querySelector('.rule-list');
      if (ruleList && data.detectionRules) {
        ruleList.innerHTML = data.detectionRules.map(r => `
          <div class="rule-item">
            <span class="rule-label">${esc(r.ruleName)} <small>(${r.severity})</small></span>
            <span class="toggle ${r.enabled ? '' : 'off'}">${r.enabled ? 'ON' : 'OFF'}</span>
          </div>`).join('');
        const ruleNotice = document.querySelector('.rule-status-notice');
        if (ruleNotice) {
          const enabledCount = data.detectionRules.filter(r => r.enabled).length;
          ruleNotice.style.display = 'flex';
          ruleNotice.style.alignItems = 'center';
          ruleNotice.style.gap = '6px';
          ruleNotice.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> ' +
            enabledCount + '/' + data.detectionRules.length + ' detection rules active';
        }
      }

      // Threat history
      const tbody = document.querySelector('.threat-table tbody');
      if (tbody && data.threatHistory) {
        if (data.threatHistory.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:24px;color:#10b981;font-weight:600;">\u2714 No ransomware threats detected - system clean</td></tr>';
        } else {
          tbody.innerHTML = data.threatHistory.map(t => `
            <tr>
              <td>${fmtDate(t.detectedAt)}</td>
              <td><strong>${esc(t.threatName)}</strong></td>
              <td>${esc(t.type)}</td>
              <td>${esc(t.action)}</td>
              <td>${t.filesAffected || 0}</td>
              <td><span class="status-badge ${t.resolved ? 'resolved' : 'active'}">${t.resolved ? 'Resolved' : 'Active'}</span></td>
            </tr>`).join('');
        }
      }

      // Rollback
      const rollbackItems = document.querySelectorAll('.rollback-item');
      if (rollbackItems.length >= 2) {
        const rl0 = rollbackItems[0]?.querySelector('.rollback-value');
        if (rl0) rl0.textContent = data.rollbackCapable ? 'Available' : 'Not Available';
        const rl1 = rollbackItems[1]?.querySelector('.rollback-value');
        if (rl1) rl1.textContent = data.rollbackCapable ? 'Enabled' : 'Disabled';
      }
    } catch(e) { console.error('Ransomware load error:', e); }
  }

  // ─── REAL-TIME PROTECTION ───
  async function loadRealtimeProtection(deviceId) {
    if (!deviceId) { showNoDevice(); return; }
    try {
      const data = await DashboardAPI.security.realtimeProtection(deviceId);
      if (!data) return;

      // Banner
      const bannerH2 = document.querySelector('.status-banner-text h2');
      if (bannerH2) bannerH2.textContent = 'Real-Time Protection: ' + (data.anyRealTimeActive ? 'ACTIVE' : 'DISABLED');

      const bannerVal = document.querySelector('.status-banner-right .value');
      if (bannerVal) bannerVal.textContent = data.totalProducts + ' product(s) installed';

      // Products
      const grid = document.querySelector('.product-grid');
      if (grid) {
        if (data.products && data.products.length > 0) {
          grid.innerHTML = data.products.map(p => `
            <div class="product-card ${(p.realTimeEnabled || p.status === 'Active') ? 'active-product' : 'passive-product'}">
              <div class="product-header">
                <strong>${esc(p.name || p.displayName)}</strong>
                <span class="role-badge ${(p.realTimeEnabled || p.status === 'Active') ? 'active-role' : 'passive-role'}">${(p.realTimeEnabled || p.status === 'Active') ? 'Active' : 'Passive'}</span>
              </div>
              <div class="product-details">
                <div class="detail-row"><span class="detail-label">Version:</span> <span class="detail-value">${esc(p.version || 'N/A')}</span></div>
                <div class="detail-row"><span class="detail-label">Definitions:</span> <span class="detail-value">${fmtDate(p.definitionDate || p.definitionsDate || p.timestamp)}</span></div>
                <div class="detail-row"><span class="detail-label">Status:</span> <span class="detail-value">${(p.realTimeEnabled || p.status === 'Active') ? 'Running' : 'Standby'}</span></div>
              </div>
            </div>`).join('');
        } else {
          grid.innerHTML = '<div style="padding:24px;text-align:center;color:#64748b;">No antivirus products detected. Security data will populate once the full agent reports.</div>';
        }
      }

      // Quarantine - keep static if no data from API
      const qtbody = document.querySelector('.quarantine-table tbody');
      if (qtbody && data.quarantine) {
        if (data.quarantine.length === 0) {
          qtbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:24px;color:#64748b;">No quarantined items</td></tr>';
        } else {
          qtbody.innerHTML = data.quarantine.map(q => `
            <tr>
              <td>${fmtDate(q.date)}</td>
              <td><strong>${esc(q.name)}</strong></td>
              <td><span class="type-badge">${esc(q.type)}</span></td>
              <td>${esc(q.source)}</td>
              <td>${esc(q.action)}</td>
              <td><span class="status-badge">${esc(q.status)}</span></td>
            </tr>`).join('');
        }
      }
    } catch(e) { console.error('RT Protection load error:', e); }
  }

  // ─── SECURITY LOGS ───
  async function loadSecurityLogs() {
    try {
      const resp = await DashboardAPI.security.logs({ limit: 50 });
      if (!resp) return;
      const logs = resp.logs || resp;
      if (!logs || !logs.length) return;

      // Summary stats
      const total = logs.length;
      const critical = logs.filter(l => l.severity === 'Critical').length;
      const warning = logs.filter(l => l.severity === 'Warning').length;
      const info = total - critical - warning;

      const stats = document.querySelectorAll('.summary-stat-value');
      if (stats.length >= 4) {
        stats[0].textContent = total;
        stats[1].textContent = critical;
        stats[2].textContent = warning;
        stats[3].textContent = info;
      }

      setText('.pagination-info', `Showing 1-${Math.min(50, total)} of ${total} events`);

      // Table
      const tbody = document.querySelector('.log-table tbody');
      if (tbody) {
        tbody.innerHTML = logs.map(l => `
          <tr>
            <td class="log-timestamp">${fmtDate(l.timestamp)}</td>
            <td><span class="severity-badge ${l.severity.toLowerCase()}">${esc(l.severity)}</span></td>
            <td class="log-event">${esc(l.message)}</td>
            <td class="log-source">${esc(l.source)}</td>
            <td><span class="category-tag">${esc(l.category)}</span></td>
            <td class="log-details">${esc(l.detailsJson ? (typeof l.detailsJson === 'string' ? l.detailsJson.substring(0,60) : '') : '')}</td>
          </tr>`).join('');
      }

      // Category breakdown
      const cats = {};
      logs.forEach(l => { cats[l.category] = (cats[l.category] || 0) + 1; });
      const catBar = document.querySelector('.category-bar');
      if (catBar) {
        const sorted = Object.entries(cats).sort((a,b) => b[1] - a[1]);
        const max = sorted[0] ? sorted[0][1] : 1;
        catBar.innerHTML = sorted.map(([cat, count]) => `
          <div class="cat-bar-item">
            <span class="cat-bar-label">${esc(cat)}</span>
            <div class="cat-bar-track"><div class="cat-bar-fill" style="width:${Math.round(count/max*100)}%"></div></div>
            <span class="cat-bar-count">${count}</span>
          </div>`).join('');
      }

      // Wire up filters
      wireLogFilters(logs);
    } catch(e) { console.error('Security logs load error:', e); }
  }

  function wireLogFilters(allLogs) {
    const selects = document.querySelectorAll('.filter-select');
    const searchInput = document.querySelector('.filter-bar input[type="text"]');
    const tbody = document.querySelector('.log-table tbody');
    if (!tbody) return;

    function applyFilters() {
      let filtered = allLogs;
      if (selects[0] && selects[0].value) filtered = filtered.filter(l => l.severity === selects[0].value);
      if (selects[1] && selects[1].value) filtered = filtered.filter(l => l.category === selects[1].value);
      if (searchInput && searchInput.value) {
        const q = searchInput.value.toLowerCase();
        filtered = filtered.filter(l => (l.message||'').toLowerCase().includes(q) || (l.source||'').toLowerCase().includes(q));
      }
      tbody.innerHTML = filtered.map(l => `
        <tr>
          <td class="log-timestamp">${fmtDate(l.timestamp)}</td>
          <td><span class="severity-badge ${l.severity.toLowerCase()}">${esc(l.severity)}</span></td>
          <td class="log-event">${esc(l.message)}</td>
          <td class="log-source">${esc(l.source)}</td>
          <td><span class="category-tag">${esc(l.category)}</span></td>
          <td class="log-details"></td>
        </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;padding:24px;">No matching logs</td></tr>';
    }

    selects.forEach(s => s && s.addEventListener('change', applyFilters));
    if (searchInput) searchInput.addEventListener('input', applyFilters);
  }

  // ─── COMPLIANCE ───
  async function loadCompliance(deviceId) {
    if (!deviceId) { showNoDevice(); return; }
    try {
      const data = await DashboardAPI.security.compliance(deviceId);
      if (!data) return;

      // Overall score
      setText('.compliance-ring-num', data.securityScore + '%');
      setText('.compliance-ring-grade', 'Grade ' + data.securityGrade);

      // Ring SVG fill (circumference ~251 for r=40)
      const ring = document.querySelector('.compliance-ring circle:last-child');
      if (ring) {
        const offset = 251 - (251 * data.securityScore / 100);
        ring.style.strokeDashoffset = offset;
      }

      // Summary
      const summaryH3 = document.querySelector('.compliance-summary h3');
      if (summaryH3) summaryH3.textContent = data.passedChecks + '/' + data.totalChecks + ' Controls Passed';
      const summaryP = document.querySelector('.compliance-summary p');
      if (summaryP) summaryP.textContent = data.failedChecks + ' gaps identified across ' + (data.categories || []).length + ' categories';

      // Framework cards - map categories to framework cards
      const fwCards = document.querySelectorAll('.framework-card');
      if (fwCards.length > 0 && data.categories) {
        const fwNames = ['CyberSecure Canada', 'NIST CSF 2.0', 'CIS Controls v8', 'PIPEDA Privacy', 'Insurance Readiness'];
        fwCards.forEach((card, i) => {
          const cat = data.categories[i];
          if (!cat) return;
          const nameEl = card.querySelector('.framework-name');
          if (nameEl) nameEl.textContent = cat.category;
          const valEl = card.querySelector('.mini-ring-value');
          if (valEl) valEl.textContent = Math.round(cat.compliancePercent) + '%';
          const passedEl = card.querySelector('.framework-stats .passed');
          if (passedEl) passedEl.textContent = cat.passedChecks + ' passed';
          const gapsEl = card.querySelector('.framework-stats .gaps');
          if (gapsEl) gapsEl.textContent = (cat.totalChecks - cat.passedChecks) + ' gaps';
          // Mini ring
          const miniRing = card.querySelector('.mini-ring circle:last-child');
          if (miniRing) {
            const c = parseFloat(miniRing.getAttribute('stroke-dasharray') || '100');
            miniRing.style.strokeDashoffset = c - (c * cat.compliancePercent / 100);
          }
        });
      }

      // Gaps
      const gapSections = document.querySelectorAll('.gap-section');
      if (gapSections.length > 0 && data.categories) {
        const allFailed = [];
        data.categories.forEach(cat => {
          cat.checks.filter(c => !c.passed).forEach(c => allFailed.push({...c, catName: cat.category}));
        });
        const critical = allFailed.filter(c => c.weight >= 15);
        const high = allFailed.filter(c => c.weight >= 10 && c.weight < 15);
        const low = allFailed.filter(c => c.weight < 10);

        [critical, high, low].forEach((group, i) => {
          if (!gapSections[i]) return;
          const countEl = gapSections[i].querySelector('.gap-section-count');
          if (countEl) countEl.textContent = group.length;
          const container = gapSections[i].querySelector('.gap-items') || gapSections[i];
          const items = container.querySelectorAll('.gap-item');
          items.forEach((el, j) => {
            if (group[j]) {
              el.querySelector('.gap-name') && (el.querySelector('.gap-name').textContent = group[j].name);
              el.querySelector('.gap-detail') && (el.querySelector('.gap-detail').textContent = group[j].detail);
            } else {
              el.style.display = 'none';
            }
          });
        });
      }
    } catch(e) { console.error('Compliance load error:', e); }
  }

  // ─── SCAN RESULTS (175-point audit) ───
  async function loadScanResults(deviceId) {
    if (!deviceId) { showNoDevice(); return; }
    try {
      const data = await DashboardAPI.security.scanResults(deviceId);
      if (!data) return;

      // Summary bar
      const nums = document.querySelectorAll('.summary-num');
      if (nums.length >= 4) {
        nums[0].textContent = data.totalChecks;
        nums[1].textContent = data.passedChecks;
        const warnings = data.totalChecks - data.passedChecks - data.failedChecks;
        nums[2].textContent = warnings > 0 ? warnings : 0;
        nums[3].textContent = data.failedChecks;
      }
      setText('.summary-last-scan', 'Last scan: ' + fmtDate(data.lastScanned || new Date().toISOString()));

      // Category sections
      const sections = document.querySelectorAll('.category-section');
      if (sections.length > 0 && data.categories) {
        // Clear and rebuild all category sections
        const container = sections[0].parentElement;
        container.innerHTML = '';
        data.categories.forEach(cat => {
          const passed = cat.checks.filter(c => c.passed).length;
          const failed = cat.checks.filter(c => !c.passed).length;
          const section = document.createElement('div');
          section.className = 'category-section';
          section.innerHTML = `
            <div class="category-header" onclick="this.parentElement.classList.toggle('collapsed')">
              <h3>${esc(cat.category)}</h3>
              <span class="category-score">${Math.round(cat.compliancePercent)}% (${passed}/${cat.totalChecks} passed)</span>
            </div>
            <div class="category-body">
              <table class="test-table">
                <thead><tr><th>Status</th><th>Test ID</th><th>Test Name</th><th>Category</th><th>Priority</th><th>Compliance</th><th>Detail</th><th>Action</th></tr></thead>
                <tbody>
                  ${cat.checks.map(c => `
                    <tr class="${c.passed ? 'pass-row' : 'fail-row'}">
                      <td><span class="status-icon ${c.passed ? 'pass' : 'fail'}">${c.passed ? '&#10003;' : '&#10007;'}</span></td>
                      <td>${esc(c.id)}</td>
                      <td><strong>${esc(c.name)}</strong></td>
                      <td>${esc(cat.category)}</td>
                      <td><span class="priority-badge ${c.weight >= 15 ? 'critical' : c.weight >= 10 ? 'high' : c.weight >= 5 ? 'medium' : 'low'}">${c.weight >= 15 ? 'Critical' : c.weight >= 10 ? 'High' : c.weight >= 5 ? 'Medium' : 'Low'}</span></td>
                      <td>${(c.complianceFrameworks || []).map(f => '<span class="comp-tag">' + esc(f) + '</span>').join(' ') || '-'}</td>
                      <td>${esc(c.detail)}${c.recommendation ? '<br><em>' + esc(c.recommendation) + '</em>' : ''}</td>
                      <td>${!c.passed ? '<button class="fix-btn" onclick="fixCheck(\'' + esc(c.id) + '\')">Fix</button>' : ''}</td>
                    </tr>`).join('')}
                </tbody>
              </table>
            </div>`;
          container.appendChild(section);
        });
      }

      // Wire filter
      wireScanFilters(data);
    } catch(e) { console.error('Scan results load error:', e); }
  }

  function wireScanFilters(data) {
    const selects = document.querySelectorAll('.filter-bar select');
    const searchInput = document.querySelector('.filter-bar input[type="text"]');
    if (!selects.length) return;

    // Populate category filter
    if (selects[0] && data.categories) {
      selects[0].innerHTML = '<option value="">All Categories</option>' +
        data.categories.map(c => `<option value="${esc(c.category)}">${esc(c.category)}</option>`).join('');
    }

    function applyFilters() {
      const sections = document.querySelectorAll('.category-section');
      const catFilter = selects[0] ? selects[0].value : '';
      const statusFilter = selects[1] ? selects[1].value : '';
      const search = searchInput ? searchInput.value.toLowerCase() : '';

      sections.forEach(sec => {
        const header = sec.querySelector('.category-header h3');
        const catName = header ? header.textContent : '';
        if (catFilter && catName !== catFilter) { sec.style.display = 'none'; return; }
        sec.style.display = '';

        const rows = sec.querySelectorAll('tbody tr');
        rows.forEach(row => {
          let show = true;
          if (statusFilter === 'passed' && row.classList.contains('fail-row')) show = false;
          if (statusFilter === 'failed' && row.classList.contains('pass-row')) show = false;
          if (search && !row.textContent.toLowerCase().includes(search)) show = false;
          row.style.display = show ? '' : 'none';
        });
      });
    }

    selects.forEach(s => s && s.addEventListener('change', applyFilters));
    if (searchInput) searchInput.addEventListener('input', applyFilters);
  }

  // ─── NETWORK SECURITY ───
  async function loadNetwork(deviceId) {
    if (!deviceId) { showNoDevice(); return; }
    try {
      const data = await DashboardAPI.security.network(deviceId);
      if (!data) return;

      // Firewall status
      const profileList = document.querySelector('.profile-list');
      if (profileList) {
        const profiles = Array.isArray(data.firewallProfiles) ? data.firewallProfiles : [];
        if (profiles.length > 0) {
          profileList.innerHTML = profiles.map(p => `
            <div class="profile-item">
              <span class="profile-name">${esc(p.name || p.Name || p.profile)}</span>
              <span class="profile-status ${(p.enabled || p.Enabled) ? 'on' : 'off'}">${(p.enabled || p.Enabled) ? 'ON' : 'OFF'}</span>
            </div>`).join('');
        } else {
          // Show firewall enabled/disabled overall
          profileList.innerHTML = `<div class="profile-item">
            <span class="profile-name">Windows Firewall</span>
            <span class="profile-status ${data.firewallEnabled ? 'on' : 'off'}">${data.firewallEnabled ? 'ON' : 'OFF'}</span>
          </div>`;
        }
      }

      // Open ports
      const portList = document.querySelector('.port-list-inline');
      const ports = Array.isArray(data.openPorts) ? data.openPorts : [];
      const statVal = document.querySelector('.net-stat-value');
      if (statVal) statVal.textContent = ports.length;
      if (portList) {
        if (ports.length > 0) {
          portList.innerHTML = ports.map(p => `<span class="port-tag">${esc(String(p.port || p.Port || p))}</span>`).join('');
        } else {
          portList.innerHTML = '<span style="color:#64748b;">No open ports detected</span>';
        }
      }

      // RDP
      const rdpItems = document.querySelectorAll('.rdp-item, .status-item');
      if (rdpItems.length > 0) {
        rdpItems.forEach(item => {
          const label = item.querySelector('.status-label, .rdp-label');
          if (label && label.textContent.includes('RDP')) {
            const val = item.querySelector('.status-value, .rdp-value');
            if (val) val.textContent = data.rdpEnabled ? 'Enabled' : 'Disabled';
          }
        });
      }

      // Active connections
      setText('.active-connections-count', String(data.activeConnections || 0));

      // DNS
      const dnsServers = Array.isArray(data.dnsServers) ? data.dnsServers : [];
      const dnsContainer = document.querySelector('.dns-list');
      if (dnsContainer && dnsServers.length > 0) {
        dnsContainer.innerHTML = dnsServers.map(d => `
          <div class="dns-item">
            <span class="dns-label">${esc(typeof d === 'string' ? d : d.address || d.Address || '')}</span>
            <span class="dns-status ok">Active</span>
          </div>`).join('');
      }

      // WiFi
      if (data.wifiSecurityType) {
        const wifiItems = document.querySelectorAll('.wifi-item, .status-item');
        wifiItems.forEach(item => {
          const label = item.textContent || '';
          if (label.includes('Security') || label.includes('SSID')) {
            const val = item.querySelector('.wifi-value, .status-value');
            if (val && label.includes('Security')) val.textContent = data.wifiSecurityType;
          }
        });
      }
    } catch(e) { console.error('Network load error:', e); }
  }

  // ─── BACKUP HEALTH ───
  async function loadBackup(deviceId) {
    if (!deviceId) { showNoDevice(); return; }
    try {
      const data = await DashboardAPI.security.backup(deviceId);
      if (!data) return;

      // Banner
      const bannerText = document.querySelector('.status-banner-text');
      if (bannerText) {
        const h2 = bannerText.querySelector('h2');
        if (h2) {
          const hasProvider = data.providers && data.providers.length > 0;
          h2.textContent = 'Backup Status: ' + (hasProvider ? 'Configured' : 'Not Configured');
        }
      }

      // Providers
      const providerEl = document.querySelector('.backup-provider');
      if (providerEl) {
        providerEl.textContent = data.providers && data.providers.length > 0
          ? data.providers.map(p => p.name || p).join(', ')
          : 'None configured';
      }

      // Shadow copy
      const scItems = document.querySelectorAll('.config-item');
      scItems.forEach(item => {
        const label = item.querySelector('.config-label');
        if (label) {
          const val = item.querySelector('.config-value');
          if (label.textContent.includes('Shadow') && val) {
            val.textContent = data.shadowCopyEnabled ? 'Enabled (' + data.shadowCopyCount + ' copies)' : 'Disabled';
          }
        }
      });

      // Recovery points
      const rpEl = document.querySelector('.recovery-points-count');
      if (rpEl) rpEl.textContent = data.totalRecoveryPoints || 0;

      // Status chips
      const chips = document.querySelectorAll('.status-chip');
      if (chips.length >= 2) {
        const hasBackup = data.providers && data.providers.length > 0;
        chips[0].textContent = hasBackup ? 'Provider OK' : 'No Provider';
        chips[0].className = 'status-chip ' + (hasBackup ? 'success' : 'warning');
        chips[1].textContent = data.shadowCopyEnabled ? 'Shadow Copy OK' : 'No Shadow Copy';
        chips[1].className = 'status-chip ' + (data.shadowCopyEnabled ? 'success' : 'warning');
      }
    } catch(e) { console.error('Backup load error:', e); }
  }

  // ─── ACCESS CONTROL ───
  async function loadAccessControl(deviceId) {
    if (!deviceId) { showNoDevice(); return; }
    try {
      const data = await DashboardAPI.security.accessControl(deviceId);
      if (!data) return;

      const users = data.userAccounts || [];
      const logins = data.recentLogins || [];
      const mfa = data.mfaStatus || {};

      // User accounts count
      const statVals = document.querySelectorAll('.stat-card-value');
      if (statVals[0]) statVals[0].textContent = users.length || '--';

      // User table
      const utbody = document.querySelector('.user-table tbody');
      if (utbody) {
        if (users.length > 0) {
          utbody.innerHTML = users.map(u => `
            <tr>
              <td class="user-cell">
                <div class="user-avatar-sm">${(u.name || u.username || '?')[0].toUpperCase()}</div>
                <div>
                  <div class="user-cell-name">${esc(u.name || u.username)}</div>
                  <div class="user-cell-email">${esc(u.email || '')}</div>
                </div>
              </td>
              <td><span class="type-badge ${(u.type || u.role || '').toLowerCase()}">${esc(u.type || u.role || 'Standard')}</span></td>
              <td>${u.mfaEnabled ? 'Enabled' : 'Not Enabled'}</td>
              <td>${fmtDate(u.lastLogin)}</td>
              <td>${u.passwordAge || '--'} days</td>
              <td><span class="status-dot ${u.isActive !== false ? 'active' : 'disabled'}"></span> ${u.isActive !== false ? 'Active' : 'Disabled'}</td>
            </tr>`).join('');
        }
      }

      // MFA status
      const mfaEl = document.querySelector('.mfa-status');
      if (mfaEl) {
        if (mfa.windowsHelloEnabled || mfa.smartCardRequired || mfa.pinConfigured) {
          const parts = [];
          if (mfa.windowsHelloEnabled) parts.push('Windows Hello');
          if (mfa.smartCardRequired) parts.push('Smart Card');
          if (mfa.pinConfigured) parts.push('PIN');
          mfaEl.textContent = parts.join(', ');
        } else {
          mfaEl.textContent = mfa.detail || 'Not Enabled';
        }
      }

      // Admin count
      if (users.length > 0) {
        const admins = users.filter(u => (u.type || u.role || '').toLowerCase() === 'admin');
        const breakdown = document.querySelector('.stat-card-breakdown');
        if (breakdown) breakdown.textContent = admins.length + ' Admin, ' + (users.length - admins.length) + ' Standard';
      }

      // Login activity table
      const loginTbody = document.querySelector('.login-table tbody, .activity-table tbody');
      if (loginTbody && logins.length > 0) {
        loginTbody.innerHTML = logins.map(l => `
          <tr>
            <td>${esc(l.user || l.username)}</td>
            <td>${fmtDate(l.timestamp || l.date)}</td>
            <td>${esc(l.type || l.logonType || 'Interactive')}</td>
            <td>${esc(l.source || l.sourceIp || 'Local')}</td>
            <td><span class="status-badge ${l.success !== false ? 'success' : 'failed'}">${l.success !== false ? 'Success' : 'Failed'}</span></td>
          </tr>`).join('');
      }
    } catch(e) { console.error('Access control load error:', e); }
  }

  // ─── REPORTS ───
  async function loadReports() {
    try {
      const customers = await DashboardAPI.customers.list();
      if (!customers) return;

      // Populate customer selector if exists
      const sel = document.querySelector('#reportCustomer, select');
      if (sel && customers.length > 0) {
        sel.innerHTML = '<option value="">Select Customer</option>' +
          customers.map(c => `<option value="${esc(c.customerName)}">${esc(c.customerName)} (${c.deviceCount} devices)</option>`).join('');
      }
    } catch(e) { console.error('Reports load error:', e); }
  }

  // ─── SERVER MANAGEMENT ───
  async function loadServerManagement() {
    try {
      const devices = await DashboardAPI.dashboard.devices();
      if (!devices) return;

      // Populate device table if exists
      const tbody = document.querySelector('.device-table tbody, .server-table tbody, table tbody');
      if (tbody) {
        tbody.innerHTML = devices.map(d => `
          <tr data-device-id="${esc(d.deviceId)}">
            <td>
              <span class="status-dot ${d.isOnline ? 'online' : 'offline'}"></span>
              <strong>${esc(d.hostname)}</strong>
            </td>
            <td>${esc(d.customerName)}</td>
            <td>${esc(d.deviceGroup || 'Default')}</td>
            <td>${esc(d.osVersion)}</td>
            <td>${Math.round(d.cpuPercent)}%</td>
            <td>${Math.round(d.ramPercent)}%</td>
            <td>${Math.round(d.diskPercent)}%</td>
            <td>${DashboardAPI.timeAgo(d.lastSeen)}</td>
            <td><span class="tier-badge tier-${(d.licenseTier||'free').toLowerCase()}">${d.licenseTier || 'Free'}</span></td>
          </tr>`).join('');
      }
    } catch(e) { console.error('Server management load error:', e); }
  }

  // ─── SETTINGS ───
  async function loadSettings(deviceId) {
    if (!deviceId) return;
    try {
      const device = await DashboardAPI.dashboard.device(deviceId);
      if (!device) return;

      // Agent version
      const agentVer = document.querySelector('.agent-version, [data-field="agent-version"]');
      if (agentVer) agentVer.textContent = device.agentVersion || 'Unknown';

      // Policy profile
      const policyEl = document.querySelector('.policy-profile');
      if (policyEl) policyEl.textContent = device.policyProfile || 'default';

      // Wire save button
      const saveBtn = document.querySelector('.btn-save');
      if (saveBtn) {
        saveBtn.addEventListener('click', async () => {
          saveBtn.textContent = 'Saving...';
          try {
            const config = {};
            document.querySelectorAll('.toggle-switch input[type="checkbox"]').forEach(cb => {
              config[cb.name || cb.id || cb.closest('.toggle-wrap')?.dataset.key] = cb.checked;
            });
            await DashboardAPI.dashboard.pushConfig(deviceId, config);
            saveBtn.textContent = 'Saved!';
            setTimeout(() => { saveBtn.textContent = 'Save Changes'; }, 2000);
          } catch(e) {
            saveBtn.textContent = 'Error';
            setTimeout(() => { saveBtn.textContent = 'Save Changes'; }, 2000);
          }
        });
      }
    } catch(e) { console.error('Settings load error:', e); }
  }

  // ─── AI ADVISOR ───
  async function loadAiAdvisor(deviceId) {
    try {
      const overview = await DashboardAPI.dashboard.overview();
      if (!overview) return;

      // Populate recommendation summary
      const container = document.querySelector('.advisor-recommendations, .ai-content, .recommendations');
      if (container) {
        const recs = [];
        if (overview.criticalAlerts > 0) recs.push({ priority: 'Critical', text: overview.criticalAlerts + ' critical alerts need immediate attention' });
        if (overview.avgSecurityScore < 50) recs.push({ priority: 'High', text: 'Average security score is ' + Math.round(overview.avgSecurityScore) + '% - run compliance scans' });
        if (overview.devicesInLockdown > 0) recs.push({ priority: 'Critical', text: overview.devicesInLockdown + ' device(s) in lockdown mode' });
        if (overview.offlineDevices > 0) recs.push({ priority: 'Medium', text: overview.offlineDevices + ' device(s) offline - verify connectivity' });
        recs.push({ priority: 'Info', text: overview.onlineDevices + '/' + overview.totalDevices + ' devices reporting normally' });

        container.innerHTML = recs.map(r => `
          <div class="rec-item ${r.priority.toLowerCase()}">
            <span class="rec-priority">${r.priority}</span>
            <span class="rec-text">${r.text}</span>
          </div>`).join('');
      }
    } catch(e) { console.error('AI Advisor load error:', e); }
  }

  // ─── UTILITY ───
  function showNoDevice() {
    const main = document.querySelector('.main-content, main, .content');
    if (main) {
      const notice = document.createElement('div');
      notice.style.cssText = 'background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;padding:16px 24px;margin:16px;color:#92400e;';
      notice.innerHTML = '<strong>No device selected.</strong> Go to the <a href="index.html">Dashboard</a> and select a customer/device to view detailed data for this page.';
      main.insertBefore(notice, main.firstChild);
    }
  }

  // Global fix action
  window.fixCheck = async function(checkId) {
    const deviceId = getDeviceId();
    if (!deviceId) { alert('No device selected'); return; }
    try {
      await DashboardAPI.dashboard.remediate(deviceId, checkId);
      alert('Remediation queued for: ' + checkId);
    } catch(e) {
      alert('Error: ' + e.message);
    }
  };
})();
