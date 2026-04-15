// SecretSauce — Background Service Worker
// Author: K. Boykov

// Open full-page app when extension icon is clicked
chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.create({ url: chrome.runtime.getURL(`app.html?tab=${tab.id}`) });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Content script asks for its own tab ID (only available in sender context)
  if (message.type === 'GET_TAB_ID') {
    sendResponse({ tabId: sender.tab?.id ?? null });
    return true;
  }

  if (message.type === 'UPDATE_BADGE') {
    const tabId = sender.tab?.id;
    if (!tabId) return;
    const count = message.secretCount || 0;
    const text  = count > 0 ? (count > 99 ? '99+' : String(count)) : '';
    chrome.action.setBadgeText({ text, tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#e53e3e', tabId });
    chrome.action.setBadgeTextColor({ color: '#ffffff', tabId });
  }
});

// Clear badge + stale scan data when tab navigates
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ text: '', tabId });
    chrome.storage.local.remove(`scan_${tabId}`);
  }
});

// Clean up storage when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`scan_${tabId}`);
});
