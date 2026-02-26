/**
 * PhishGuard Browser Extension — Content Script
 *
 * Runs on Gmail and Outlook web to extract email content
 * and display analysis results inline.
 */

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "extractEmail") {
    const emailContent = extractEmailContent();
    sendResponse({ emailContent });
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
  const hostname = window.location.hostname;

  // Gmail extraction
  if (hostname === "mail.google.com") {
    return extractGmailContent();
  }

  // Outlook extraction
  if (hostname.includes("outlook")) {
    return extractOutlookContent();
  }

  return null;
}

function extractGmailContent() {
  // Try to get the currently open email's raw content
  // Gmail doesn't expose raw .eml directly, so we extract visible content
  const emailContainer = document.querySelector('[role="main"] .gs');
  if (!emailContainer) return null;

  // Get email headers
  const from = document.querySelector('[data-hovercard-id]');
  const subject = document.querySelector('h2[data-thread-perm-id]');
  const bodyEl = document.querySelector('.a3s.aiL');

  if (!bodyEl) return null;

  // Build a pseudo-email format
  const parts = [];
  if (from) parts.push(`From: ${from.getAttribute('email') || from.textContent.trim()}`);
  if (subject) parts.push(`Subject: ${subject.textContent.trim()}`);
  parts.push(`Date: ${new Date().toUTCString()}`);
  parts.push("");
  parts.push(bodyEl.innerText || bodyEl.textContent);

  return parts.join("\n");
}

function extractOutlookContent() {
  // Outlook Web extraction
  const bodyEl = document.querySelector('[role="document"]') ||
                 document.querySelector('.ReadMsgBody') ||
                 document.querySelector('[aria-label*="Message body"]');

  if (!bodyEl) return null;

  // Get subject
  const subjectEl = document.querySelector('[role="heading"]') ||
                    document.querySelector('.SubjectText');
  // Get from
  const fromEl = document.querySelector('.lpc-hoverTarget') ||
                 document.querySelector('[autoid*="PersonaCard"]');

  const parts = [];
  if (fromEl) parts.push(`From: ${fromEl.textContent.trim()}`);
  if (subjectEl) parts.push(`Subject: ${subjectEl.textContent.trim()}`);
  parts.push(`Date: ${new Date().toUTCString()}`);
  parts.push("");
  parts.push(bodyEl.innerText || bodyEl.textContent);

  return parts.join("\n");
}

function showResultOverlay(data) {
  removeOverlay();

  const score = data.score || {};
  const level = score.level || "clean";
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
  overlay.innerHTML = `
    <div class="pg-overlay-card">
      <div class="pg-overlay-header" style="background: ${colors[level] || '#6b7280'}">
        <span class="pg-overlay-title">PhishGuard Analysis</span>
        <button class="pg-overlay-close" onclick="document.getElementById('phishguard-overlay').remove()">&times;</button>
      </div>
      <div class="pg-overlay-body">
        <div class="pg-score-display">
          <div class="pg-score-ring" style="border-color: ${colors[level] || '#6b7280'}">
            <span class="pg-score-num">${total}</span>
            <span class="pg-score-max">/100</span>
          </div>
          <div>
            <div class="pg-threat-level" style="color: ${colors[level] || '#6b7280'}">${level.toUpperCase()}</div>
            <div class="pg-threat-label">${score.level_label || ''}</div>
          </div>
        </div>
        ${score.breakdown && score.breakdown.length > 0 ? `
        <div class="pg-findings">
          <div class="pg-findings-title">Key Findings (${score.breakdown.length})</div>
          ${score.breakdown.slice(0, 5).map(b =>
            `<div class="pg-finding-item">
              <span class="pg-finding-pts">+${b.points}</span>
              <span>${b.reason}</span>
            </div>`
          ).join('')}
        </div>` : '<div class="pg-findings"><p style="color:#999">No threats detected.</p></div>'}
        ${reportId ? `
        <a class="pg-view-report" href="${getServerUrl()}/report/${reportId}" target="_blank">
          View Full Report &rarr;
        </a>` : ''}
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
}

function showErrorOverlay(errorMessage) {
  removeOverlay();

  const overlay = document.createElement("div");
  overlay.id = "phishguard-overlay";
  overlay.innerHTML = `
    <div class="pg-overlay-card">
      <div class="pg-overlay-header" style="background: #ef4444">
        <span class="pg-overlay-title">PhishGuard Error</span>
        <button class="pg-overlay-close" onclick="document.getElementById('phishguard-overlay').remove()">&times;</button>
      </div>
      <div class="pg-overlay-body">
        <p style="color: #ef4444; font-size: 13px;">${errorMessage}</p>
        <p style="color: #999; font-size: 12px; margin-top: 8px;">Check extension settings and ensure your PhishGuard server is running.</p>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
}

function removeOverlay() {
  const existing = document.getElementById("phishguard-overlay");
  if (existing) existing.remove();
}

function getServerUrl() {
  // Default, will be overridden by stored settings
  return "http://127.0.0.1:5000";
}

// =========================================================================
// Inject "Analyze with PhishGuard" button into email toolbar
// =========================================================================

function injectAnalyzeButton() {
  const hostname = window.location.hostname;

  if (hostname === "mail.google.com") {
    injectGmailButton();
  } else if (hostname.includes("outlook")) {
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
    }, function (response) {
      if (response && response.success) {
        showResultOverlay(response.data);
        btn.innerHTML = '&#9673; Done!';
        btn.style.color = "#2ea043";
      } else {
        showErrorOverlay(response ? response.error : "Analysis failed");
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
  // Watch for email open events in Gmail
  const observer = new MutationObserver(function () {
    // Look for the email action toolbar
    const toolbar = document.querySelector('[gh="tm"]') ||
                    document.querySelector('[gh="mtb"]') ||
                    document.querySelector('.iH > div');

    if (toolbar && !toolbar.querySelector('[data-pg-injected]')) {
      const btn = createPgButton();
      btn.style.marginLeft = "8px";
      toolbar.appendChild(btn);
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

function injectOutlookButton() {
  // Watch for email open events in Outlook
  const observer = new MutationObserver(function () {
    const toolbar = document.querySelector('[role="toolbar"]');

    if (toolbar && !toolbar.querySelector('[data-pg-injected]')) {
      const btn = createPgButton();
      btn.style.marginLeft = "4px";
      toolbar.appendChild(btn);
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Initialize button injection
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", injectAnalyzeButton);
} else {
  injectAnalyzeButton();
}
