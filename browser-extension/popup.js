const API_BASE = "http://127.0.0.1:9876";

document.addEventListener("DOMContentLoaded", function() {
  // Get extension-level stats
  chrome.runtime.sendMessage({ type: "getStats" }, function(stats) {
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    const scanned = document.getElementById("scannedCount");
    const blocked = document.getElementById("blockedCount");

    if (stats && stats.serviceActive) {
      dot.classList.add("active");
      text.textContent = "Protected";
      text.style.color = "#22c55e";
      fetchProtectionSummary();
    } else {
      dot.classList.add("inactive");
      text.textContent = "Service Offline";
      text.style.color = "#ef4444";
    }

    if (stats) {
      scanned.textContent = formatNum(stats.scannedCount || 0);
      blocked.textContent = formatNum(stats.blockedCount || 0);
    }
  });
});

async function fetchProtectionSummary() {
  try {
    const resp = await fetch(API_BASE + "/api/protection-summary", {
      signal: AbortSignal.timeout(3000)
    });
    if (!resp.ok) return;
    const data = await resp.json();

    // Show protection score ring
    if (data.protectionScore !== undefined) {
      const section = document.getElementById("scoreSection");
      section.style.display = "block";

      const score = data.protectionScore;
      const circle = document.getElementById("scoreCircle");
      const num = document.getElementById("scoreNum");
      const label = document.getElementById("scoreLabel");
      const sub = document.getElementById("scoreSub");

      const circumference = 2 * Math.PI * 44;
      const dash = (score / 100) * circumference;
      circle.setAttribute("stroke-dasharray", dash + " " + circumference);

      const color = score >= 80 ? "#22c55e" : score >= 60 ? "#f59e0b" : "#ef4444";
      circle.setAttribute("stroke", color);
      num.textContent = score;
      num.style.color = color;
      label.textContent = data.scoreLabel || "Protection Score";
      label.style.color = color;

      if (data.uptime && data.uptime.hours) {
        sub.textContent = "Running for " + formatUptime(data.uptime.hours);
      }
    }

    // Update stat boxes with server-side data
    if (data.today) {
      document.getElementById("blockedCount").textContent = formatNum(data.today.threatsBlocked || 0);
      document.getElementById("dnsCount").textContent = formatNum(data.today.dnsBlocked || 0);
    }
    if (data.last30Days) {
      document.getElementById("scannedCount").textContent = formatNum(data.last30Days.linksScanned || 0);
    }
    if (data.uptime && data.uptime.hours) {
      document.getElementById("uptimeText").textContent = formatUptime(data.uptime.hours);
    }

    // Show highlights
    if (data.highlights && data.highlights.length > 0) {
      const hl = document.getElementById("highlightsSection");
      hl.style.display = "block";
      hl.innerHTML = data.highlights.slice(0, 3).map(function(h) {
        return '<div class="highlight"><span class="highlight-dot">&#x25cf;</span>' +
          escapeHtml(h) + '</div>';
      }).join("");
    }

    // Show report link
    document.getElementById("reportLink").style.display = "block";
    document.getElementById("reportLink").addEventListener("click", function() {
      chrome.tabs.create({ url: API_BASE + "/api/protection-summary" });
    });

  } catch (e) {
    // Service might not have reporting module yet - that's ok
  }
}

function formatNum(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "K";
  return n.toString();
}

function formatUptime(hours) {
  if (hours >= 24) return Math.floor(hours / 24) + "d " + Math.floor(hours % 24) + "h";
  if (hours >= 1) return Math.floor(hours) + "h " + Math.floor((hours % 1) * 60) + "m";
  return Math.floor(hours * 60) + "m";
}

function escapeHtml(str) {
  var div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
