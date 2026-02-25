/**
 * PhishGuard Browser Extension — Background Service Worker
 *
 * Creates context menu items and handles analysis requests.
 */

// Create context menu on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-analyze",
    title: "Analyze with PhishGuard",
    contexts: ["selection", "page"]
  });
});

// Handle context menu clicks
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

// Handle messages from popup
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
    // Send result to content script to display
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

async function performAnalysis(content, filename) {
  const settings = await new Promise((resolve) => {
    chrome.storage.sync.get(["serverUrl", "apiKey"], resolve);
  });

  const serverUrl = settings.serverUrl || "http://127.0.0.1:5000";
  const apiKey = settings.apiKey || "";

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
