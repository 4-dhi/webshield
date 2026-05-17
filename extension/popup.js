// popup.js - WebShield.AI Extension Logic
const BACKEND_URL = "http://localhost:8000"; // Replace after deploying

let currentState = "idle";

function setState(state, message = "") {
  currentState = state;
  const container = document.getElementById("circleContainer");
  const button = document.getElementById("actionButton");
  const statusDisplay = document.getElementById("statusDisplay");
  const lockIcon = document.getElementById("lockIcon");
  const warningIcon = document.getElementById("warningIcon");
  const iconContainer = document.getElementById("iconContainer");
  const safeShield = document.getElementById("safeShield");

  const globeImage = document.getElementById("globeImage");
  const shieldImage = document.getElementById("shieldImage");
  const globeBase = document.getElementById("globeBase");

  // Reset all classes and visibility
  container.className = "circle-container active";
  statusDisplay.innerHTML = "";
  iconContainer.classList.remove("scanning");
  lockIcon.style.display = "none";
  warningIcon.classList.remove("show");
  warningIcon.style.display = "none";
  safeShield.classList.remove("show");
  safeShield.style.display = "none";
  globeImage.style.display = "none";
  shieldImage.style.display = "none";
  globeBase.style.display = "block";

  switch (state) {
    case "idle":
      shieldImage.style.display = "block";
      lockIcon.style.display = "none";
      button.textContent = "Check Your Site";
      button.disabled = false;
      break;

    case "analyzing":
      iconContainer.classList.add("scanning");
      lockIcon.style.display = "none";
      globeImage.style.display = "block";
      globeBase.style.display = "none";
      button.disabled = true;
      statusDisplay.innerHTML =
        '<div class="analyzing-text"><span>Analyzing...</span><div class="spinner"></div></div>';
      break;

    case "safe":
      container.classList.add("safe-state");
      // Hide globe and show shield
      setTimeout(() => {
        safeShield.style.display = "block";
        safeShield.classList.add("show");
      }, 300);

      statusDisplay.innerHTML =
        '<div class="result-text safe-result">SAFE</div>';
      button.textContent = "Check Again";
      button.disabled = false;
      break;

    case "phishing":
      container.classList.add("phishing-state");
      lockIcon.style.display = "none";
      warningIcon.style.display = "block";
      warningIcon.classList.add("show");
      statusDisplay.innerHTML =
        '<div class="result-text phishing-result">PHISHING</div>';
      button.textContent = "Check Again";
      button.disabled = false;
      break;

    case "error":
      lockIcon.style.display = "block";
      statusDisplay.innerHTML = `<div class="error-text">${message}</div>`;
      button.textContent = "Try Again";
      button.disabled = false;
      break;
  }
}

function analyzeWebsite() {
  setState("analyzing");

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (!tabs || tabs.length === 0) {
      setState("error", "No active tab found");
      return;
    }

    const tab = tabs[0];
    const url = tab.url;

    if (
      url.startsWith("chrome://") ||
      url.startsWith("chrome-extension://") ||
      url.startsWith("edge://") ||
      url.startsWith("about:")
    ) {
      setState("error", "Cannot analyze system pages");
      return;
    }

    function sendMessageWithRetry(retries = 3) {
      chrome.tabs.sendMessage(
        tab.id,
        { action: "getPageHTML" },
        function (response) {
          if (chrome.runtime.lastError) {
            if (retries > 0) {
              console.log(
                `Retry ${4 - retries} due to ${
                  chrome.runtime.lastError.message
                }`,
              );
              setTimeout(() => sendMessageWithRetry(retries - 1), 500);
            } else {
              console.error("Final error:", chrome.runtime.lastError);
              setState(
                "error",
                "Failed to communicate with content script. Please refresh the page and try again.",
              );
            }
            return;
          }

          if (!response || !response.success) {
            setState(
              "error",
              response ? response.error : "No response from content script",
            );
            return;
          }

          const pageHTML = response.html;
          const MAX_HTML_SIZE = 500000;
          const trimmedHTML =
            pageHTML.length > MAX_HTML_SIZE
              ? pageHTML.slice(0, MAX_HTML_SIZE)
              : pageHTML;

          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 15000);

          fetch(BACKEND_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url, html: trimmedHTML }),
            signal: controller.signal,
          })
            .then((response) => {
              clearTimeout(timeoutId);
              if (!response.ok) {
                throw new Error(
                  "Server responded with status: " + response.status,
                );
              }
              return response.text();
            })
            .then((data) => {
              if (data.includes("SAFE")) {
                setState("safe");
              } else if (data.includes("PHISHING")) {
                setState("phishing");
              } else {
                setState("error", "Unknown server response: " + data);
              }
            })
            .catch((error) => {
              clearTimeout(timeoutId);
              console.error("Fetch error:", error);
              const msg =
                error.name === "AbortError"
                  ? "Server took too long to respond. Try again in a moment."
                  : "Server connection failed. Error: " + error.message;
              setState("error", msg);
            });
        },
      );
    }

    sendMessageWithRetry();
  });
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", function () {
  // Display current URL
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (tabs && tabs.length > 0) {
      let displayURL = tabs[0].url;
      if (displayURL.length > 45) {
        displayURL = displayURL.slice(0, 45) + "...";
      }
      const urlDisplayElement = document.getElementById("urlDisplay");
      if (urlDisplayElement) {
        urlDisplayElement.textContent = displayURL;
      }
    } else {
      const urlDisplayElement = document.getElementById("urlDisplay");
      if (urlDisplayElement) {
        urlDisplayElement.textContent = "URL not available";
      }
    }
  });

  // Add button click handler
  document
    .getElementById("actionButton")
    .addEventListener("click", analyzeWebsite);

  // Set initial state
  setState("idle");
});
