const API_BASE = "http://127.0.0.1:9876";
let serviceActive = false;
let blockedCount = 0;
let scannedCount = 0;

// Check if PC Plus service is running
async function checkService() {
  try {
    const resp = await fetch(`${API_BASE}/api/status`, { signal: AbortSignal.timeout(2000) });
    if (resp.ok) {
      serviceActive = true;
      updateBadge("on");
      return true;
    }
  } catch (e) {}
  serviceActive = false;
  updateBadge("off");
  return false;
}

// Check a single URL against the service
async function checkUrl(url) {
  if (!serviceActive) return null;
  try {
    const resp = await fetch(`${API_BASE}/api/check-url?url=${encodeURIComponent(url)}`, {
      signal: AbortSignal.timeout(3000)
    });
    if (resp.ok) {
      scannedCount++;
      return await resp.json();
    }
  } catch (e) {}
  return null;
}

// Check multiple URLs in batch
async function checkUrls(urls) {
  if (!serviceActive || urls.length === 0) return [];
  try {
    const resp = await fetch(`${API_BASE}/api/check-urls`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(urls),
      signal: AbortSignal.timeout(10000)
    });
    if (resp.ok) {
      const data = await resp.json();
      scannedCount += urls.length;
      return data.results || [];
    }
  } catch (e) {}
  return [];
}

// Report a phishing URL
async function reportPhishing(url) {
  try {
    await fetch(`${API_BASE}/api/report-phishing`, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: url
    });
  } catch (e) {}
}

// Update extension badge
function updateBadge(state) {
  if (state === "on") {
    chrome.action.setBadgeBackgroundColor({ color: "#22c55e" });
    chrome.action.setBadgeText({ text: "ON" });
  } else if (state === "off") {
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    chrome.action.setBadgeText({ text: "OFF" });
  } else if (state === "warn") {
    chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    chrome.action.setBadgeText({ text: "!" });
  }
}

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "checkUrl") {
    checkUrl(msg.url).then(result => sendResponse(result));
    return true;
  }
  if (msg.type === "checkUrls") {
    checkUrls(msg.urls).then(results => sendResponse(results));
    return true;
  }
  if (msg.type === "reportPhishing") {
    reportPhishing(msg.url);
    sendResponse({ ok: true });
    return false;
  }
  if (msg.type === "getStats") {
    sendResponse({ serviceActive, blockedCount, scannedCount });
    return false;
  }
  if (msg.type === "blocked") {
    blockedCount++;
    updateBadge("warn");
    setTimeout(() => { if (serviceActive) updateBadge("on"); }, 5000);
    return false;
  }
});

// Block navigation to dangerous URLs
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!serviceActive) return;

  const url = details.url;
  if (url.startsWith("chrome") || url.startsWith("about") || url.startsWith("edge")) return;

  const result = await checkUrl(url);
  if (result && result.riskScore >= 60) {
    blockedCount++;
    const blockedUrl = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent(url)}&score=${result.riskScore}&reasons=${encodeURIComponent(result.reasons.join(", "))}`
    );
    chrome.tabs.update(details.tabId, { url: blockedUrl });
  }
});

// Check service status every 30 seconds
setInterval(checkService, 30000);
checkService();
