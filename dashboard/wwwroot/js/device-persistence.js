(function() {
  const STORAGE_KEY = 'pcplus_selected_device';
  const CUSTOMER_KEY = 'pcplus_selected_customer';

  function getStoredDevice() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch(e) { return null; }
  }

  function storeDevice(device) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(device)); } catch(e) {}
  }

  function storeCustomer(name) {
    try { localStorage.setItem(CUSTOMER_KEY, name || ''); } catch(e) {}
  }

  function getStoredCustomer() {
    try { return localStorage.getItem(CUSTOMER_KEY) || ''; } catch(e) { return ''; }
  }

  function clearDevice() {
    try { localStorage.removeItem(STORAGE_KEY); } catch(e) {}
  }

  function updateNavLinks(deviceId, customerName) {
    document.querySelectorAll('.nav-item[href]').forEach(function(a) {
      var href = a.getAttribute('href');
      if (href && href.includes('.html')) {
        var base = href.split('?')[0];
        var params = [];
        if (deviceId) params.push('deviceId=' + encodeURIComponent(deviceId));
        if (customerName) params.push('customerName=' + encodeURIComponent(customerName));
        a.setAttribute('href', base + (params.length ? '?' + params.join('&') : ''));
      }
    });
  }

  function updateHeader(device) {
    var dn = document.querySelector('.device-name');
    var dos = document.querySelector('.device-os');
    if (dn) dn.textContent = device.hostname || device.deviceName || 'Select Device';
    if (dos) dos.innerHTML = '<span class="online-dot" style="' + (device.isOnline ? '' : 'background:#ef4444') + '"></span> ' +
      (device.osVersion || '') + ' &bull; ' + (device.isOnline ? 'Online' : 'Offline');

    var cn = document.querySelector('.client-name');
    if (cn && device.customerName) cn.textContent = device.customerName;
    var tb = document.querySelector('.tier-badge');
    if (tb && device.licenseTier) {
      tb.className = 'tier-badge ' + device.licenseTier.toLowerCase();
      tb.innerHTML = '<span class="tier-dot"></span>' + device.licenseTier;
    }
  }

  function updateHeaderCustomer(name, deviceCount, onlineCount, tier) {
    var dn = document.querySelector('.device-name');
    var dos = document.querySelector('.device-os');
    if (dn) dn.textContent = name || 'All Customers';
    if (dos && deviceCount != null) dos.innerHTML = '<span class="online-dot"></span> ' + (onlineCount || 0) + '/' + deviceCount + ' devices online';

    var cn = document.querySelector('.client-name');
    if (cn) cn.textContent = name || '';
    var tb = document.querySelector('.tier-badge');
    if (tb && tier) {
      tb.className = 'tier-badge ' + tier.toLowerCase();
      tb.innerHTML = '<span class="tier-dot"></span>' + tier;
    }
  }

  window.addEventListener('DOMContentLoaded', async function() {
    var params = new URLSearchParams(window.location.search);
    var deviceId = params.get('deviceId');
    var customerName = params.get('customerName');

    if (deviceId && typeof DashboardAPI !== 'undefined') {
      try {
        var device = await DashboardAPI.dashboard.device(deviceId);
        if (device) {
          storeDevice({ deviceId: deviceId, hostname: device.hostname, osVersion: device.osVersion,
            isOnline: device.isOnline, customerName: device.customerName, licenseTier: device.licenseTier });
          storeCustomer(device.customerName || '');
          updateHeader(device);
          updateNavLinks(deviceId, device.customerName);
        }
      } catch(e) { console.error('Device load error:', e); }
    } else if (customerName) {
      storeCustomer(customerName);
      clearDevice();
      updateNavLinks('', customerName);
      if (typeof DashboardAPI !== 'undefined') {
        try {
          var detail = await DashboardAPI.customers.detail(customerName);
          if (detail) {
            updateHeaderCustomer(detail.customerName, detail.deviceCount, detail.onlineDevices, detail.licenseTier);
          }
        } catch(e) {}
      }
    } else {
      var stored = getStoredDevice();
      var storedCust = getStoredCustomer();
      if (stored && stored.deviceId) {
        updateHeader(stored);
        updateNavLinks(stored.deviceId, stored.customerName);
        if (typeof DashboardAPI !== 'undefined') {
          try {
            var fresh = await DashboardAPI.dashboard.device(stored.deviceId);
            if (fresh) {
              storeDevice({ deviceId: stored.deviceId, hostname: fresh.hostname, osVersion: fresh.osVersion,
                isOnline: fresh.isOnline, customerName: fresh.customerName, licenseTier: fresh.licenseTier });
              updateHeader(fresh);
            }
          } catch(e) {}
        }
      } else if (storedCust) {
        updateNavLinks('', storedCust);
        if (typeof DashboardAPI !== 'undefined') {
          try {
            var detail = await DashboardAPI.customers.detail(storedCust);
            if (detail) {
              updateHeaderCustomer(detail.customerName, detail.deviceCount, detail.onlineDevices, detail.licenseTier);
            }
          } catch(e) {}
        }
      }
    }
  });

  window.PCPlusPersistence = {
    storeDevice: storeDevice,
    storeCustomer: storeCustomer,
    clearDevice: clearDevice,
    getStoredDevice: getStoredDevice,
    getStoredCustomer: getStoredCustomer,
    updateNavLinks: updateNavLinks,
    updateHeader: updateHeader,
    updateHeaderCustomer: updateHeaderCustomer
  };
})();
