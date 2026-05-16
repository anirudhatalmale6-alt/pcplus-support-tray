// Content script for webmail pages (Gmail, Outlook, Yahoo)
// Scans email content for suspicious links

(function() {
  "use strict";

  const SCAN_INTERVAL = 3000;
  const scannedLinks = new Set();
  let scanning = false;

  function extractLinks() {
    const links = document.querySelectorAll("a[href]");
    const newUrls = [];

    links.forEach(link => {
      const href = link.href;
      if (!href || href.startsWith("javascript:") || href.startsWith("#") || href.startsWith("mailto:")) return;
      if (scannedLinks.has(href)) return;
      if (href.includes("127.0.0.1") || href.includes("localhost")) return;

      // Skip internal webmail navigation links
      if (isInternalLink(href)) return;

      scannedLinks.add(href);
      newUrls.push({ url: href, element: link });
    });

    return newUrls;
  }

  function isInternalLink(href) {
    const host = window.location.hostname;
    try {
      const url = new URL(href);
      // Skip same-domain links (webmail navigation)
      if (url.hostname === host) return true;
      // Skip known safe domains
      const safe = [
        "google.com", "googleapis.com", "gstatic.com",
        "microsoft.com", "office.com", "live.com", "outlook.com",
        "yahoo.com", "yimg.com"
      ];
      return safe.some(d => url.hostname.endsWith(d));
    } catch (e) {
      return false;
    }
  }

  async function scanLinks() {
    if (scanning) return;
    scanning = true;

    try {
      const newLinks = extractLinks();
      if (newLinks.length === 0) { scanning = false; return; }

      const urls = newLinks.map(l => l.url);
      const batchSize = 20;

      for (let i = 0; i < urls.length; i += batchSize) {
        const batch = urls.slice(i, i + batchSize);

        chrome.runtime.sendMessage({ type: "checkUrls", urls: batch }, results => {
          if (!results || !Array.isArray(results)) return;

          results.forEach(result => {
            const linkData = newLinks.find(l => l.url === result.url);
            if (!linkData) return;

            if (result.riskScore >= 60) {
              markDangerous(linkData.element, result);
            } else if (result.riskScore >= 30) {
              markSuspicious(linkData.element, result);
            } else {
              markSafe(linkData.element);
            }
          });
        });
      }
    } catch (e) {}

    scanning = false;
  }

  function markDangerous(element, result) {
    element.classList.add("pcplus-dangerous");
    element.setAttribute("data-pcplus-score", result.riskScore);
    element.setAttribute("data-pcplus-reasons", result.reasons.join(", "));

    // Add warning icon before the link
    if (!element.querySelector(".pcplus-icon")) {
      const icon = document.createElement("span");
      icon.className = "pcplus-icon pcplus-icon-danger";
      icon.textContent = "⚠";
      icon.title = "PC Plus: Dangerous link blocked\n" + result.reasons.join("\n");
      element.insertBefore(icon, element.firstChild);
    }

    // Override click
    element.addEventListener("click", function(e) {
      e.preventDefault();
      e.stopPropagation();
      showWarning(result.url, result.reasons, result.riskScore);
    }, true);

    chrome.runtime.sendMessage({ type: "blocked" });
  }

  function markSuspicious(element, result) {
    element.classList.add("pcplus-suspicious");
    element.setAttribute("data-pcplus-score", result.riskScore);

    if (!element.querySelector(".pcplus-icon")) {
      const icon = document.createElement("span");
      icon.className = "pcplus-icon pcplus-icon-warn";
      icon.textContent = "⚠";
      icon.title = "PC Plus: Suspicious link\n" + result.reasons.join("\n");
      element.insertBefore(icon, element.firstChild);
    }
  }

  function markSafe(element) {
    element.classList.add("pcplus-safe");
  }

  function showWarning(url, reasons, score) {
    // Create overlay warning
    const overlay = document.createElement("div");
    overlay.className = "pcplus-overlay";
    overlay.innerHTML = `
      <div class="pcplus-warning-box">
        <div class="pcplus-warning-header">
          <span class="pcplus-shield">🛡️</span>
          PC Plus Endpoint Protection
        </div>
        <div class="pcplus-warning-title">Dangerous Link Blocked</div>
        <div class="pcplus-warning-url">${escapeHtml(url)}</div>
        <div class="pcplus-warning-score">Risk Score: ${score}/100</div>
        <div class="pcplus-warning-reasons">
          ${reasons.map(r => `<div class="pcplus-reason">${escapeHtml(r)}</div>`).join("")}
        </div>
        <div class="pcplus-warning-actions">
          <button class="pcplus-btn pcplus-btn-safe" id="pcplus-close">Go Back (Safe)</button>
          <button class="pcplus-btn pcplus-btn-report" id="pcplus-report">Report Phishing</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("pcplus-close").addEventListener("click", () => overlay.remove());
    document.getElementById("pcplus-report").addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "reportPhishing", url });
      overlay.querySelector(".pcplus-btn-report").textContent = "Reported!";
    });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // Observe DOM changes (webmail loads content dynamically)
  const observer = new MutationObserver(() => {
    clearTimeout(observer._timeout);
    observer._timeout = setTimeout(scanLinks, 500);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Initial scan and periodic rescan
  setTimeout(scanLinks, 1000);
  setInterval(scanLinks, SCAN_INTERVAL);
})();
