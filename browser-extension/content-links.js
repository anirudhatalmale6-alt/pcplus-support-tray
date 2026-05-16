// Lightweight content script for all pages
// Adds tooltip warnings on hover for suspicious links

(function() {
  "use strict";

  const checkedLinks = new Set();
  let tooltip = null;

  document.addEventListener("mouseover", async function(e) {
    const link = e.target.closest("a[href]");
    if (!link) return;

    const href = link.href;
    if (!href || href.startsWith("javascript:") || href.startsWith("#") || href.startsWith("mailto:")) return;
    if (href.includes("127.0.0.1") || href.includes("localhost")) return;
    if (checkedLinks.has(href)) return;

    checkedLinks.add(href);

    chrome.runtime.sendMessage({ type: "checkUrl", url: href }, result => {
      if (!result || result.riskScore < 30) return;

      if (result.riskScore >= 60) {
        link.classList.add("pcplus-dangerous");
      } else {
        link.classList.add("pcplus-suspicious");
      }
      link.setAttribute("title",
        `PC Plus: Risk ${result.riskScore}/100 - ${result.reasons.join(", ")}`);
    });
  }, { passive: true });
})();
