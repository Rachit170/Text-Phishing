// background.js - handles API calls and caching
let API_URL = "http://127.0.0.1:5000/predict";
const cache = new Map(); // simple in-memory cache, key -> response

// load saved API url
chrome.storage.sync.get(["api_url"], (res) => {
  if (res && res.api_url) API_URL = res.api_url;
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PREDICT") {
    const payload = message.payload;
    const key = btoa(JSON.stringify({ subject: payload.subject || "", sender: payload.sender || "", hash: (payload.body || "").slice(0,200) }));

    // Return cached response if recent
    if (cache.has(key)) {
      sendResponse(cache.get(key));
      return true;
    }

    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
      .then((resp) => resp.json())
      .then((data) => {
        // Normalize result
        const label = data.label || (data.prediction && data.prediction.label) || "safe";
        const score = data.confidence || data.score || (data.prediction && data.prediction.score) || 0;
        const explanation = data.explanation || "";
        const keywords = data.keywords_detected || data.keywords || data.key_phrases || [];

        const response = { label, confidence: score, explanation, keywords, raw: data };
        // Cache for 10s to avoid spamming backend
        cache.set(key, response);
        setTimeout(() => cache.delete(key), 10 * 1000);
        sendResponse(response);
      })
      .catch((err) => {
        console.error("Prediction error:", err);
        sendResponse({ label: "safe", confidence: 0, explanation: "Prediction failed", keywords: [] });
      });

    return true; // indicates async response
  }
});

// watch for changes to API URL
chrome.storage.onChanged.addListener((changes) => {
  if (changes.api_url) API_URL = changes.api_url.newValue || API_URL;
});
