/***********************************************************
 *  PHISHING EMAIL DETECTOR - CONTENT SCRIPT (GMAIL)
 *  Stable + Robust Version
 ***********************************************************/

console.log("Phishing Detector content script loaded");

// --------------------------
// Utility functions
// --------------------------

function extractLinks(text) {
  if (!text) return [];
  const urlRegex = /(https?:\/\/[^\s"']+)/g;
  return Array.from(new Set((text.match(urlRegex) || [])));
}

function getLinkRisk(url) {
  try {
    const domain = new URL(url).hostname.toLowerCase();

    // Trusted domains
    if (
      domain.includes("google.") ||
      domain.includes("gmail.") ||
      domain.includes("microsoft.") ||
      domain.includes("outlook.") ||
      domain.includes("apple.") ||
      domain.includes("paypal.")
    ) {
      return { risk: "safe", color: "green" };
    }

    // Suspicious patterns
    if (
      domain.length > 25 ||
      domain.includes("-verify") ||
      domain.includes("secure-") ||
      domain.includes("login-") ||
      domain.includes("auth-") ||
      domain.includes(".ru") ||
      domain.includes(".cn")
    ) {
      return { risk: "high", color: "red" };
    }

    return { risk: "unknown", color: "orange" };
  } catch {
    return { risk: "unknown", color: "gray" };
  }
}

// --------------------------
// Email Extraction
// --------------------------

function getEmailFields() {
  let subject = "";
  let sender = "";
  let body = "";

  const gSubject = document.querySelector("h2.hP") || document.querySelector("h2[role='heading']");
  if (gSubject) subject = gSubject.innerText.trim();

  const gSender = document.querySelector(".gD") || document.querySelector(".go") || document.querySelector("[email]");
  if (gSender) sender = gSender.getAttribute("email") || gSender.innerText.trim();

  const gBody = document.querySelector("div.a3s");
  if (gBody) body = gBody.innerText.trim();

  return {
    subject: subject || "",
    sender: sender || "",
    body: body || "",
    links: extractLinks(body || "")
  };
}

// --------------------------
// Banner UI
// --------------------------

function createBanner() {
  let banner = document.getElementById("phish-detector-banner");
  if (banner) return banner;

  banner = document.createElement("div");
  banner.id = "phish-detector-banner";
  banner.style.position = "fixed";
  banner.style.top = "20px";
  banner.style.right = "20px";
  banner.style.zIndex = "99999999";
  banner.style.maxWidth = "360px";
  banner.style.boxShadow = "0 4px 12px rgba(0,0,0,0.15)";
  banner.style.borderRadius = "8px";
  banner.style.padding = "12px";
  banner.style.fontFamily = "Arial, sans-serif";
  banner.style.display = "none";

  const closeBtn = document.createElement("button");
  closeBtn.innerText = "×";
  closeBtn.style.position = "absolute";
  closeBtn.style.top = "4px";
  closeBtn.style.right = "8px";
  closeBtn.style.border = "none";
  closeBtn.style.background = "transparent";
  closeBtn.style.fontSize = "16px";
  closeBtn.style.cursor = "pointer";
  closeBtn.onclick = hideBanner;

  const title = document.createElement("div");
  title.id = "phish-detector-title";
  title.style.fontWeight = "700";
  title.style.marginBottom = "6px";

  const expl = document.createElement("div");
  expl.id = "phish-detector-expl";
  expl.style.fontSize = "13px";
  expl.style.marginBottom = "6px";

  const conf = document.createElement("div");
  conf.id = "phish-detector-confidence";
  conf.style.fontSize = "12px";
  conf.style.opacity = "0.9";

  const more = document.createElement("button");
  more.id = "phish-detector-more";
  more.innerText = "More details ▼";
  more.style.fontSize = "12px";
  more.style.border = "none";
  more.style.background = "transparent";
  more.style.cursor = "pointer";
  more.style.marginTop = "6px";

  const details = document.createElement("div");
  details.id = "phish-detector-details";
  details.style.display = "none";
  details.style.fontSize = "12px";
  details.style.marginTop = "6px";

  more.onclick = () => {
    if (details.style.display === "none") {
      details.style.display = "block";
      more.innerText = "Less details ▲";
    } else {
      details.style.display = "none";
      more.innerText = "More details ▼";
    }
  };

  banner.append(closeBtn, title, expl, conf, more, details);
  document.body.appendChild(banner);

  return banner;
}

function hideBanner() {
  const banner = document.getElementById("phish-detector-banner");
  if (banner) banner.style.display = "none";
}

function showBanner(label, confidence, explanation, payload) {
  const banner = createBanner();
  const title = banner.querySelector("#phish-detector-title");
  const expl = banner.querySelector("#phish-detector-expl");
  const conf = banner.querySelector("#phish-detector-confidence");
  const details = banner.querySelector("#phish-detector-details");

  // --------------------------
  // Confidence Calibration
  // --------------------------
  let displayLabel = label;

  if (confidence < 0.50) {
    displayLabel = "safe";
  } else if (confidence < 0.85) {
    displayLabel = "suspicious";
  }

  // Title
  title.innerText =
    displayLabel === "phishing"
      ? "⚠️ Phishing Email"
      : displayLabel === "suspicious"
      ? "⚠️ Suspicious Email"
      : "✅ Safe Email";

  // Colors
  if (displayLabel === "phishing") {
    banner.style.background = "#ffe6e6";
    banner.style.border = "1px solid #ff4d4d";
  } else if (displayLabel === "suspicious") {
    banner.style.background = "#fff4cc";
    banner.style.border = "1px solid #ffcc00";
  } else {
    banner.style.background = "#e6ffe6";
    banner.style.border = "1px solid #4dff88";
  }

  expl.innerText = explanation || "";
  conf.innerText = `Confidence: ${Math.round(confidence * 100)}%`;

  // Details Section
  const linkList = (payload.links || [])
    .map((l) => {
      const risk = getLinkRisk(l);
      return `<div style="color:${risk.color}">• ${l} (${risk.risk})</div>`;
    })
    .join("");

  details.innerHTML = `
    <div><b>Sender:</b> ${payload.sender || "Unknown"}</div>
    <div><b>Links:</b><br>${linkList || "None"}</div>
    <div><b>Raw score:</b> ${Math.round(confidence * 100)}%</div>
    <div><b>Keywords detected:</b> None</div>
  `;

  banner.style.display = "block";
}

// --------------------------
// Message Request
// --------------------------

function requestPrediction(payload) {
  chrome.runtime.sendMessage({ type: "PREDICT", payload }, (response) => {
    if (!response) return;
    const { label, confidence, explanation } = response;
    showBanner(label, confidence, explanation, payload);
  });
}

// ------------------------------
// ROBUST GMAIL DETECTION ENGINE
// ------------------------------

let lastHash = "";
let emailCheckRunning = false;

function waitForEmailBody(callback) {
  let tries = 0;
  const interval = setInterval(() => {
    tries++;

    const body = document.querySelector("div.a3s");

    if (body && body.innerText.trim().length > 20) {
      clearInterval(interval);
      callback();
    }

    if (tries > 30) clearInterval(interval);
  }, 150);
}

function robustPredict() {
  if (emailCheckRunning) return;
  emailCheckRunning = true;

  waitForEmailBody(() => {
    const email = getEmailFields();

    if (!email.body && !email.subject) {
      hideBanner();
      emailCheckRunning = false;
      return;
    }

    const hash = btoa(
      unescape(
        encodeURIComponent(
          JSON.stringify({
            subject: email.subject,
            sender: email.sender,
            body: email.body.slice(0, 400),
          })
        )
      )
    );

    if (hash !== lastHash) {
      lastHash = hash;
      requestPrediction(email);
    }

    emailCheckRunning = false;
  });
}

// Gmail SPA observer
const observer = new MutationObserver(() => {
  robustPredict();
});

observer.observe(document.body, { childList: true, subtree: true });

window.addEventListener("click", () => {
  setTimeout(robustPredict, 200);
});

setTimeout(robustPredict, 800);
