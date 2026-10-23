(() => {
  let hostEl = null;
  let shadow = null;
  let hideTimer = null;

  function ensureHud() {
    if (hostEl && document.documentElement.contains(hostEl)) {
      return;
    }
    hostEl = document.createElement("div");
    hostEl.id = "yubiesp-hardware-hud-host";
    hostEl.style.cssText = "position:fixed;top:18px;right:18px;z-index:2147483647;pointer-events:none;";
    shadow = hostEl.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = `
      .card {
        display: flex;
        align-items: center;
        gap: 14px;
        min-width: 320px;
        max-width: 400px;
        padding: 14px 16px;
        border-radius: 12px;
        background: rgba(13, 17, 23, 0.96);
        border: 1px solid rgba(56, 189, 248, 0.35);
        box-shadow: 0 16px 40px rgba(0, 0, 0, 0.55), 0 0 0 1px rgba(255, 255, 255, 0.05);
        color: #f0f6fc;
        font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", sans-serif;
        backdrop-filter: blur(12px);
        transition: opacity 0.2s ease, transform 0.2s ease;
      }
      .card.approved {
        border-color: rgba(16, 185, 129, 0.55);
      }
      .card.error {
        border-color: rgba(239, 68, 68, 0.55);
      }
      .led-wrap {
        position: relative;
        width: 36px;
        height: 36px;
        border-radius: 10px;
        background: rgba(56, 189, 248, 0.12);
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }
      .card.approved .led-wrap {
        background: rgba(16, 185, 129, 0.14);
      }
      .card.error .led-wrap {
        background: rgba(239, 68, 68, 0.14);
      }
      .led {
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: #38bdf8;
        box-shadow: 0 0 12px #38bdf8;
        animation: pulse 0.55s infinite alternate;
      }
      .card.approved .led {
        background: #10b981;
        box-shadow: 0 0 12px #10b981;
        animation: none;
      }
      .card.error .led {
        background: #ef4444;
        box-shadow: 0 0 12px #ef4444;
        animation: none;
      }
      @keyframes pulse {
        from { opacity: 0.25; transform: scale(0.88); }
        to   { opacity: 1.0;  transform: scale(1.12); }
      }
      .body {
        display: flex;
        flex-direction: column;
        gap: 3px;
        min-width: 0;
      }
      .badge {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #38bdf8;
      }
      .card.approved .badge { color: #10b981; }
      .card.error .badge { color: #ef4444; }
      .title {
        font-size: 13.5px;
        font-weight: 600;
        color: #f8fafc;
        line-height: 1.25;
      }
      .subtitle {
        font-size: 12px;
        color: #94a3b8;
        line-height: 1.35;
        word-break: break-word;
      }
    `;
    shadow.appendChild(style);
    const container = document.createElement("div");
    container.id = "hud-root";
    shadow.appendChild(container);
    document.documentElement.appendChild(hostEl);
  }

  function renderHud(msg) {
    ensureHud();
    if (hideTimer) {
      clearTimeout(hideTimer);
      hideTimer = null;
    }
    const root = shadow.getElementById("hud-root");
    const stateClass = msg.state === "approved" ? "approved" : msg.state === "error" ? "error" : "waiting";
    const badgeLabel =
      msg.state === "approved"
        ? "YUBIESP CONFIRMED"
        : msg.state === "error"
        ? "YUBIESP ALERT"
        : "YUBIESP HARDWARE KEY";

    root.innerHTML = "";
    const card = document.createElement("div");
    card.className = `card ${stateClass}`;

    const ledWrap = document.createElement("div");
    ledWrap.className = "led-wrap";
    const led = document.createElement("div");
    led.className = "led";
    ledWrap.appendChild(led);

    const body = document.createElement("div");
    body.className = "body";

    const badge = document.createElement("div");
    badge.className = "badge";
    badge.textContent = badgeLabel;

    const title = document.createElement("div");
    title.className = "title";
    title.textContent = msg.title || "Press BOOT on ESP32";

    const subtitle = document.createElement("div");
    subtitle.className = "subtitle";
    subtitle.textContent = msg.subtitle || "";

    body.appendChild(badge);
    body.appendChild(title);
    body.appendChild(subtitle);
    card.appendChild(ledWrap);
    card.appendChild(body);
    root.appendChild(card);

    if (msg.state === "approved" || msg.state === "error") {
      hideTimer = setTimeout(() => {
        if (root) root.innerHTML = "";
      }, 2600);
    }
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === "YUBIESP_FOCUS") {
      try { window.focus(); } catch (_) {}
      sendResponse({ ok: true });
      return false;
    }
    if (msg?.type === "YUBIESP_HUD") {
      try { window.focus(); } catch (_) {}
      renderHud(msg);
    }
  });
})();
