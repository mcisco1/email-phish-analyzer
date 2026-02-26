/**
 * PhishGuard Extension — Popup Script
 */

document.addEventListener("DOMContentLoaded", () => {
  const serverUrlInput = document.getElementById("serverUrl");
  const apiKeyInput = document.getElementById("apiKey");
  const saveBtn = document.getElementById("saveBtn");
  const fileInput = document.getElementById("fileInput");
  const analyzePageBtn = document.getElementById("analyzePageBtn");
  const statusMsg = document.getElementById("statusMsg");
  const resultCard = document.getElementById("resultCard");

  // Load saved settings
  chrome.runtime.sendMessage({ action: "getSettings" }, (response) => {
    if (response) {
      serverUrlInput.value = response.serverUrl || "http://127.0.0.1:5000";
      apiKeyInput.value = response.apiKey || "";
    }
  });

  // Load recent results
  loadRecentResults();

  // Save settings
  saveBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({
      action: "saveSettings",
      serverUrl: serverUrlInput.value.replace(/\/$/, ""),
      apiKey: apiKeyInput.value.trim()
    }, (response) => {
      showStatus("Settings saved.", "success");
    });
  });

  // File upload
  fileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".eml")) {
      showStatus("Please select a .eml file.", "error");
      return;
    }

    showStatus("Analyzing...", "loading");
    resultCard.style.display = "none";

    const reader = new FileReader();
    reader.onload = (evt) => {
      chrome.runtime.sendMessage({
        action: "analyze",
        content: evt.target.result,
        filename: file.name
      }, (response) => {
        if (response && response.success) {
          showResult(response.data);
          showStatus("Analysis complete.", "success");
        } else {
          showStatus(response ? response.error : "Analysis failed.", "error");
        }
      });
    };
    reader.readAsText(file);
  });

  // Analyze current page email
  analyzePageBtn.addEventListener("click", () => {
    showStatus("Extracting email content...", "loading");
    resultCard.style.display = "none";

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) {
        showStatus("No active tab found.", "error");
        return;
      }

      chrome.tabs.sendMessage(tabs[0].id, { action: "extractEmail" }, (response) => {
        if (chrome.runtime.lastError || !response || !response.emailContent) {
          showStatus("Could not extract email. Make sure you have an email open in Gmail or Outlook.", "error");
          return;
        }

        showStatus("Analyzing...", "loading");
        chrome.runtime.sendMessage({
          action: "analyze",
          content: response.emailContent,
          filename: "inbox-email.eml"
        }, (result) => {
          if (result && result.success) {
            showResult(result.data);
            showStatus("Analysis complete.", "success");
          } else {
            showStatus(result ? result.error : "Analysis failed.", "error");
          }
        });
      });
    });
  });

  function showStatus(message, type) {
    statusMsg.textContent = message;
    statusMsg.className = `status ${type}`;
  }

  function loadRecentResults() {
    chrome.storage.local.get("recentResults", (data) => {
      const results = data.recentResults || [];
      if (results.length === 0) return;

      const section = document.getElementById("recentSection");
      const list = document.getElementById("recentList");
      section.style.display = "block";

      const colors = {
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#22c55e",
        clean: "#10b981"
      };

      const serverUrl = serverUrlInput.value || "http://127.0.0.1:5000";

      list.innerHTML = results.slice(0, 3).map(r => {
        const color = colors[r.level] || "#6b7280";
        const ago = formatTimeAgo(r.timestamp);
        return `
          <a href="${serverUrl}/report/${r.report_id}" target="_blank" class="recent-item">
            <span class="recent-score" style="color: ${color}">${r.score}</span>
            <div class="recent-info">
              <div class="recent-name">${r.filename || 'Analysis'}</div>
              <div class="recent-meta">${r.level.toUpperCase()} &middot; ${ago}</div>
            </div>
          </a>
        `;
      }).join("");
    });
  }

  function formatTimeAgo(timestamp) {
    const diff = Date.now() - timestamp;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return mins + "m ago";
    const hours = Math.floor(mins / 60);
    if (hours < 24) return hours + "h ago";
    const days = Math.floor(hours / 24);
    return days + "d ago";
  }

  function showResult(data) {
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

    const color = colors[level] || "#6b7280";
    const serverUrl = serverUrlInput.value || "http://127.0.0.1:5000";

    let findingsHtml = "";
    if (score.breakdown && score.breakdown.length > 0) {
      findingsHtml = score.breakdown.slice(0, 3).map(b =>
        `<div style="font-size:11px; padding:3px 0; border-bottom:1px solid #1c2333; display:flex; gap:6px;">
          <span style="color:#f97316; font-weight:600; width:24px;">+${b.points}</span>
          <span>${b.reason}</span>
        </div>`
      ).join("");
    }

    resultCard.style.display = "block";
    resultCard.innerHTML = `
      <div class="result-score">
        <div class="result-ring" style="border-color: ${color}">
          <span class="result-num" style="color: ${color}">${total}</span>
          <span class="result-max">/100</span>
        </div>
        <div>
          <div class="result-level" style="color: ${color}">${level}</div>
          <div style="font-size:11px; color:#6e7681;">${score.level_label || ''}</div>
        </div>
      </div>
      ${findingsHtml}
      ${reportId ? `<a href="${serverUrl}/report/${reportId}" target="_blank" class="result-link">View Full Report</a>` : ''}
    `;
  }
});
