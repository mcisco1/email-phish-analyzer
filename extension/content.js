// content.js — runs on gmail + outlook to extract emails and show results

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "extractEmail") {
    const content = extractEmailContent();
    sendResponse({ emailContent: content });
    return;
  }

  if (message.action === "showResult") {
    showResultOverlay(message.data);
    return;
  }
  if (message.action === "showError") {
    showErrorOverlay(message.error);
    return;
  }
});


function extractEmailContent() {
  const host = window.location.hostname;

  if (host === "mail.google.com") return extractGmailContent();
  if (host.includes("outlook")) return extractOutlookContent();
  // TODO: add Yahoo Mail support
  return null;
}

function extractGmailContent() {
  // gmail doesn't expose raw .eml, so we scrape the visible content
  const container = document.querySelector('[role="main"] .gs');
  if (!container) return null;

  const from = document.querySelector('[data-hovercard-id]');
  const subj = document.querySelector('h2[data-thread-perm-id]');
  const bodyEl = document.querySelector('.a3s.aiL');
  if (!bodyEl) return null;

  const parts = [];
  if (from) parts.push(`From: ${from.getAttribute('email') || from.textContent.trim()}`);
  if (subj) parts.push(`Subject: ${subj.textContent.trim()}`);
  parts.push(`Date: ${new Date().toUTCString()}`);
  parts.push("");
  parts.push(bodyEl.innerText || bodyEl.textContent);

  return parts.join("\n");
}

function extractOutlookContent() {
  const bodyEl = document.querySelector('[role="document"]') ||
                 document.querySelector('.ReadMsgBody') ||
                 document.querySelector('[aria-label*="Message body"]');
  if (!bodyEl) return null;

  const subj = document.querySelector('[role="heading"]') ||
               document.querySelector('.SubjectText');
  const fromEl = document.querySelector('.lpc-hoverTarget') ||
                 document.querySelector('[autoid*="PersonaCard"]');

  /* build pseudo-eml from DOM content */
  const parts = [];
  if (fromEl) parts.push(`From: ${fromEl.textContent.trim()}`);
  if (subj) parts.push(`Subject: ${subj.textContent.trim()}`);
  parts.push(`Date: ${new Date().toUTCString()}`);
  parts.push("");
  parts.push(bodyEl.innerText || bodyEl.textContent);
  return parts.join("\n");
}


function showResultOverlay(data) {
  removeOverlay();

  const score = data.score || {};
  const lvl = score.level || "clean";
  const total = score.total || 0;
  const reportId = data.report_id || "";

  const colors = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#22c55e",
    clean: "#10b981"
  };

  const overlay = document.createElement("div");
  overlay.id = "phishguard-overlay";

  // this function is a bit long but it's mostly template strings
  // and it's easier to read all in one place than split across helpers
  let findingsHtml = '';
  if (score.breakdown && score.breakdown.length > 0) {
    findingsHtml = '<div class="pg-findings">';
    findingsHtml += `<div class="pg-findings-title">Key Findings (${score.breakdown.length})</div>`;
    for (const b of score.breakdown.slice(0, 5)) {
      findingsHtml += `<div class="pg-finding-item">
        <span class="pg-finding-pts">+${b.points}</span>
        <span>${b.reason}</span>
      </div>`;
    }
    findingsHtml += '</div>';
  } else {
    findingsHtml = '<div class="pg-findings"><p style="color:#999">No threats detected.</p></div>';
  }

  overlay.innerHTML = `
    <div class="pg-overlay-card">
      <div class="pg-overlay-header" style="background: ${colors[lvl] || '#6b7280'}">
        <span class="pg-overlay-title">PhishGuard Analysis</span>
        <button class="pg-overlay-close" onclick="document.getElementById('phishguard-overlay').remove()">&times;</button>
      </div>
      <div class="pg-overlay-body">
        <div class="pg-score-display">
          <div class="pg-score-ring" style="border-color: ${colors[lvl] || '#6b7280'}">
            <span class="pg-score-num">${total}</span>
            <span class="pg-score-max">/100</span>
          </div>
          <div>
            <div class="pg-threat-level" style="color: ${colors[lvl] || '#6b7280'}">${lvl.toUpperCase()}</div>
            <div class="pg-threat-label">${score.level_label || ''}</div>
          </div>
        </div>
        ${findingsHtml}
        ${reportId ? `
        <a class="pg-view-report" href="${getServerUrl()}/report/${reportId}" target="_blank">
          View Full Report &rarr;
        </a>` : ''}
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
  console.log("[pg] overlay shown, level:", lvl);
}

function showErrorOverlay(errMsg) {
  removeOverlay();

  const el = document.createElement("div");
  el.id = "phishguard-overlay";
  el.innerHTML = `
    <div class="pg-overlay-card">
      <div class="pg-overlay-header" style="background: #ef4444">
        <span class="pg-overlay-title">PhishGuard Error</span>
        <button class="pg-overlay-close" onclick="document.getElementById('phishguard-overlay').remove()">&times;</button>
      </div>
      <div class="pg-overlay-body">
        <p style="color: #ef4444; font-size: 13px;">${errMsg}</p>
        <p style="color: #999; font-size: 12px; margin-top: 8px;">Check extension settings and ensure your PhishGuard server is running.</p>
      </div>
    </div>
  `;
  document.body.appendChild(el);
}

function removeOverlay() {
  const existing = document.getElementById("phishguard-overlay");
  if (existing) existing.remove();
}

function getServerUrl() {
  return "http://127.0.0.1:5000";
}

// ---
// toolbar button injection
// ---

function injectAnalyzeButton() {
  const host = window.location.hostname;
  if (host === "mail.google.com") {
    injectGmailButton();
  } else if (host.includes("outlook")) {
    injectOutlookButton();
  }
}

function createPgButton() {
  const btn = document.createElement("button");
  btn.className = "pg-inject-btn";
  btn.setAttribute("data-pg-injected", "true");
  btn.innerHTML = '&#9673; Analyze';
  btn.title = "Analyze with PhishGuard";

  btn.addEventListener("click", function (e) {
    e.preventDefault();
    e.stopPropagation();
    btn.textContent = "Analyzing...";
    btn.disabled = true;

    const emailContent = extractEmailContent();
    if (!emailContent) {
      btn.textContent = "No email found";
      btn.style.color = "#ef4444";
      setTimeout(function () {
        btn.innerHTML = '&#9673; Analyze';
        btn.disabled = false;
        btn.style.color = "";
      }, 2000);
      return;
    }

    chrome.runtime.sendMessage({
      action: "analyze",
      content: emailContent,
      filename: "inbox-email.eml"
    }, function (resp) {
      if (resp && resp.success) {
        showResultOverlay(resp.data);
        btn.innerHTML = '&#9673; Done!';
        btn.style.color = "#2ea043";
      } else {
        showErrorOverlay(resp ? resp.error : "Analysis failed");
        btn.innerHTML = '&#9673; Failed';
        btn.style.color = "#ef4444";
      }
      setTimeout(function () {
        btn.innerHTML = '&#9673; Analyze';
        btn.disabled = false;
        btn.style.color = "";
      }, 3000);
    });
  });

  return btn;
}

function injectGmailButton() {
  const observer = new MutationObserver(function () {
    const toolbar = document.querySelector('[gh="tm"]') ||
                    document.querySelector('[gh="mtb"]') ||
                    document.querySelector('.iH > div');

    if (toolbar && !toolbar.querySelector('[data-pg-injected]')) {
      const btn = createPgButton();
      btn.style.marginLeft = "8px";
      toolbar.appendChild(btn);
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}

function injectOutlookButton() {
  const observer = new MutationObserver(function () {
    const toolbar = document.querySelector('[role="toolbar"]');
    if (toolbar && !toolbar.querySelector('[data-pg-injected]')) {
      const btn = createPgButton();
      btn.style.marginLeft = "4px";
      toolbar.appendChild(btn);
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", injectAnalyzeButton);
} else {
  injectAnalyzeButton();
}
