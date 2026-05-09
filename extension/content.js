// Content script to extract page HTML and send to popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getPageHTML") {
    try {
      const html = document.documentElement.outerHTML;
      sendResponse({ success: true, html: html });
    } catch (error) {
      sendResponse({ success: false, error: error.message });
    }
  }
  return true;
});