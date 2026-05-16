document.addEventListener("DOMContentLoaded", function() {
  chrome.runtime.sendMessage({ type: "getStats" }, function(stats) {
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    const scanned = document.getElementById("scannedCount");
    const blocked = document.getElementById("blockedCount");

    if (stats && stats.serviceActive) {
      dot.classList.add("active");
      text.textContent = "Protected";
      text.style.color = "#22c55e";
    } else {
      dot.classList.add("inactive");
      text.textContent = "Service Offline";
      text.style.color = "#ef4444";
    }

    if (stats) {
      scanned.textContent = stats.scannedCount || 0;
      blocked.textContent = stats.blockedCount || 0;
    }
  });
});
