// options.js — extension settings page

document.addEventListener("DOMContentLoaded", function () {
  var serverUrlInput = document.getElementById("serverUrl");
  var apiKeyInput = document.getElementById("apiKey");
  var saveBtn = document.getElementById("saveBtn");
  var testBtn = document.getElementById("testBtn");
  var statusMsg = document.getElementById("statusMsg");

  chrome.storage.sync.get(["serverUrl", "apiKey"], function (items) {
    serverUrlInput.value = items.serverUrl || "http://127.0.0.1:5000";
    apiKeyInput.value = items.apiKey || "";
  });

  saveBtn.addEventListener("click", function () {
    var url = serverUrlInput.value.replace(/\/$/, "");
    var key = apiKeyInput.value.trim();

    chrome.storage.sync.set({ serverUrl: url, apiKey: key }, function () {
      showStatus("Settings saved successfully.", "success");
    });
  });

  /* test connection by sending a dummy analysis request */
  testBtn.addEventListener("click", function () {
    var url = serverUrlInput.value.replace(/\/$/, "");
    var key = apiKeyInput.value.trim();

    if (!url) {
      showStatus("Please enter a server URL.", "error");
      return;
    }
    if (!key) {
      showStatus("Please enter an API key.", "error");
      return;
    }

    showStatus("Testing connection...", "loading");
    console.log("[pg] testing connection to", url);

    var hdrs = { "Content-Type": "application/json" };
    if (key.startsWith("eyJ")) {
      hdrs["Authorization"] = "Bearer " + key;
    } else {
      hdrs["X-API-Key"] = key;
    }

    fetch(url + "/api/extension/analyze", {
      method: "POST",
      headers: hdrs,
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
