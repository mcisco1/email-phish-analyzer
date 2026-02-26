/**
 * PhishGuard Extension — Options Page Script
 */

document.addEventListener("DOMContentLoaded", function () {
  var serverUrlInput = document.getElementById("serverUrl");
  var apiKeyInput = document.getElementById("apiKey");
  var saveBtn = document.getElementById("saveBtn");
  var testBtn = document.getElementById("testBtn");
  var statusMsg = document.getElementById("statusMsg");

  // Load saved settings
  chrome.storage.sync.get(["serverUrl", "apiKey"], function (items) {
    serverUrlInput.value = items.serverUrl || "http://127.0.0.1:5000";
    apiKeyInput.value = items.apiKey || "";
  });

  // Save settings
  saveBtn.addEventListener("click", function () {
    var serverUrl = serverUrlInput.value.replace(/\/$/, "");
    var apiKey = apiKeyInput.value.trim();

    chrome.storage.sync.set({
      serverUrl: serverUrl,
      apiKey: apiKey
    }, function () {
      showStatus("Settings saved successfully.", "success");
    });
  });

  // Test connection
  testBtn.addEventListener("click", function () {
    var serverUrl = serverUrlInput.value.replace(/\/$/, "");
    var apiKey = apiKeyInput.value.trim();

    if (!serverUrl) {
      showStatus("Please enter a server URL.", "error");
      return;
    }

    if (!apiKey) {
      showStatus("Please enter an API key.", "error");
      return;
    }

    showStatus("Testing connection...", "loading");

    var headers = { "Content-Type": "application/json" };
    if (apiKey.startsWith("eyJ")) {
      headers["Authorization"] = "Bearer " + apiKey;
    } else {
      headers["X-API-Key"] = apiKey;
    }

    fetch(serverUrl + "/api/extension/analyze", {
      method: "POST",
      headers: headers,
      body: JSON.stringify({
        eml_content: "From: test@test.com\nSubject: Connection Test\n\nTest",
        filename: "connection-test.eml"
      })
    })
    .then(function (resp) {
      if (resp.ok) {
        showStatus("Connection successful! PhishGuard server is reachable.", "success");
      } else if (resp.status === 401 || resp.status === 403) {
        showStatus("Authentication failed. Check your API key.", "error");
      } else {
        showStatus("Server returned status " + resp.status + ". Check the URL.", "error");
      }
    })
    .catch(function (err) {
      showStatus("Connection failed: " + err.message + ". Ensure the server is running.", "error");
    });
  });

  function showStatus(message, type) {
    statusMsg.textContent = message;
    statusMsg.className = "status show " + type;
  }
});
