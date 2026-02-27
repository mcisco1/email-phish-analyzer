// PhishGuard background service worker
// handles context menu + analysis requests

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-analyze",
    title: "Analyze with PhishGuard",
    contexts: ["selection", "page"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "phishguard-analyze") {
    // Send message to content script to extract email
    chrome.tabs.sendMessage(tab.id, {
      action: "extractEmail"
    }, (response) => {
      if (chrome.runtime.lastError) {
        // Content script not available, try with selection
        if (info.selectionText) {
          analyzeContent(info.selectionText, tab.id);
        }
        return;
      }
      if (response && response.emailContent) {
        analyzeContent(response.emailContent, tab.id);
      } else if (info.selectionText) {
        analyzeContent(info.selectionText, tab.id);
      }
    });
  }
});

/* message handler — popup + content script comms */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyze") {
    performAnalysis(message.content, message.filename)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep channel open for async response
  }

  if (message.action === "getSettings") {
    chrome.storage.sync.get(["serverUrl", "apiKey"], (items) => {
      sendResponse(items);
    });
    return true;
  }

  if (message.action === "saveSettings") {
    chrome.storage.sync.set({
      serverUrl: message.serverUrl,
      apiKey: message.apiKey
    }, () => {
      sendResponse({ success: true });
    });
    return true;
  }
});

async function analyzeContent(content, tabId) {
  try {
    const result = await performAnalysis(content, "browser-email.eml");
    console.log("[pg] analysis result:", result.score?.level, result.score?.total);
    updateBadge(result);

    const level = result.score ? result.score.level : "clean";
    // browser notification for serious threats
    if (level === "critical" || level === "high") {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: `PhishGuard: ${level.toUpperCase()} Threat`,
        message: `Score: ${result.score.total}/100 — ${result.score.level_label || level}`,
        priority: 2
      });
    }

    storeRecentResult(result);
    chrome.tabs.sendMessage(tabId, {
      action: "showResult",
      data: result
    });
  } catch (error) {
    chrome.tabs.sendMessage(tabId, {
      action: "showError",
      error: error.message
    });
  }
}

function updateBadge(result) {
  const lvl = result.score ? result.score.level : "clean";
  const total = result.score ? result.score.total : 0;
  const badgeColors = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#22c55e",
    clean: "#10b981"
  };

  chrome.action.setBadgeBackgroundColor({ color: badgeColors[lvl] || "#6b7280" });
  chrome.action.setBadgeText({ text: String(total) });
  // clear after 30s
  setTimeout(() => {
    chrome.action.setBadgeText({ text: "" });
  }, 30000);
}

async function storeRecentResult(result) {
  const { recentResults = [] } = await chrome.storage.local.get("recentResults");
  recentResults.unshift({
    report_id: result.report_id,
    filename: result.filename,
    score: result.score ? result.score.total : 0,
    level: result.score ? result.score.level : "clean",
    timestamp: Date.now()
  });
  await chrome.storage.local.set({ recentResults: recentResults.slice(0, 10) });
}


async function performAnalysis(content, filename) {
  const cfg = await new Promise((resolve) => {
    chrome.storage.sync.get(["serverUrl", "apiKey"], resolve);
  });

  const serverUrl = cfg.serverUrl || "http://127.0.0.1:5000";
  const apiKey = cfg.apiKey || "";

  if (!apiKey) {
    throw new Error("API key not configured. Open PhishGuard extension settings.");
  }

  const headers = {
    "Content-Type": "application/json"
  };

  // Support both JWT Bearer tokens and legacy API keys
  if (apiKey.startsWith("eyJ")) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  } else {
    headers["X-API-Key"] = apiKey;
  }

  const response = await fetch(`${serverUrl}/api/extension/analyze`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      eml_content: content,
      filename: filename
    })
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || `Server returned ${response.status}`);
  }

  return response.json();
}
