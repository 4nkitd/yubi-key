const BRIDGE_URL = "http://127.0.0.1:17380";
let isAttached = false;
let syncInFlight = null;
const activeCeremonies = new Map();

async function updateBadge(state) {
  if (state === "tap") {
    await chrome.action.setBadgeText({ text: "TAP" });
    await chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
  } else if (state === "on") {
    await chrome.action.setBadgeText({ text: "ON" });
    await chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
  } else if (state === "off") {
    await chrome.action.setBadgeText({ text: "OFF" });
    await chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
  } else if (state === "err") {
    await chrome.action.setBadgeText({ text: "ERR" });
    await chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
  }
}

async function getActiveTabInfo() {
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return { tabId: tabs[0]?.id || null, windowId: tabs[0]?.windowId || null };
  } catch (_) {
    return { tabId: null, windowId: null };
  }
}

async function ensureTabFocused(tabId, windowId) {
  try {
    if (windowId) {
      await chrome.windows.update(windowId, { focused: true });
    }
    if (tabId) {
      await chrome.tabs.update(tabId, { active: true });
      await chrome.tabs.sendMessage(tabId, { type: "YUBIESP_FOCUS" }).catch(() => {});
    }
    await new Promise((r) => setTimeout(r, 60));
  } catch (_) {}
}

async function notifyTab(tabId, payload) {
  try {
    if (tabId) {
      await chrome.tabs.sendMessage(tabId, payload);
      return;
    }
    const { tabId: currentId } = await getActiveTabInfo();
    if (currentId) {
      await chrome.tabs.sendMessage(currentId, payload);
    }
  } catch (_) {}
}

async function syncProxyAttachment() {
  if (syncInFlight) return syncInFlight;
  syncInFlight = (async () => {
    const { proxyEnabled = true } = await chrome.storage.local.get("proxyEnabled");
    if (proxyEnabled) {
      try {
        await chrome.webAuthenticationProxy.attach();
        isAttached = true;
        if (activeCeremonies.size === 0) await updateBadge("on");
      } catch (err) {
        console.error("[YubiESP] attach error:", err);
        isAttached = false;
        await updateBadge("err");
      }
    } else {
      try {
        await chrome.webAuthenticationProxy.detach();
      } catch (_) {}
      isAttached = false;
      await updateBadge("off");
    }
    syncInFlight = null;
    return isAttached;
  })();
  return syncInFlight;
}

chrome.runtime.onInstalled.addListener(() => {
  syncProxyAttachment();
});

chrome.runtime.onStartup.addListener(() => {
  syncProxyAttachment();
});

syncProxyAttachment();

chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener(async (requestInfo) => {
  try {
    await chrome.webAuthenticationProxy.completeIsUvpaaRequest({
      requestId: requestInfo.requestId,
      isUvpaa: true,
    });
  } catch (err) {
    console.error("[YubiESP] completeIsUvpaaRequest error:", err);
  }
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
  const entry = activeCeremonies.get(requestId);
  if (entry) {
    activeCeremonies.delete(requestId);
    entry.abortController.abort();
    clearInterval(entry.keepAlive);
    notifyTab(entry.tabId, {
      type: "YUBIESP_HUD",
      state: "error",
      title: "Request Canceled",
      subtitle: "The website canceled or timed out the WebAuthn request.",
    });
  }
  if (activeCeremonies.size === 0) {
    updateBadge(isAttached ? "on" : "off");
  }
});

chrome.webAuthenticationProxy.onCreateRequest.addListener(async (requestInfo) => {
  const { requestId, requestDetailsJson } = requestInfo;
  let rpId = "website";
  let userName = "";
  try {
    const parsed = JSON.parse(requestDetailsJson);
    rpId = parsed?.rp?.id || parsed?.rp?.name || "website";
    userName = parsed?.user?.name || "";
  } catch (_) {}

  const { tabId, windowId } = await getActiveTabInfo();
  const abortController = new AbortController();
  const keepAlive = setInterval(() => {
    chrome.storage.local.get("proxyEnabled").catch(() => {});
  }, 5000);
  activeCeremonies.set(requestId, { tabId, windowId, abortController, keepAlive });

  await updateBadge("tap");
  await notifyTab(tabId, {
    type: "YUBIESP_HUD",
    state: "waiting_touch",
    op: "create",
    rpId,
    userName,
    title: "Press BOOT or EN Button on ESP32",
    subtitle: `Registering hardware passkey for ${rpId}${userName ? ` (${userName})` : ""}`,
  });

  try {
    const res = await fetch(`${BRIDGE_URL}/webauthn/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ requestId, requestDetailsJson }),
      signal: abortController.signal,
    });
    const data = await res.json();

    if (!activeCeremonies.has(requestId)) return;
    clearInterval(keepAlive);
    activeCeremonies.delete(requestId);

    await ensureTabFocused(tabId, windowId);

    if (data.responseJson) {
      await updateBadge("on");
      await notifyTab(tabId, {
        type: "YUBIESP_HUD",
        state: "approved",
        op: "create",
        rpId,
        title: "Passkey Registered on ESP32",
        subtitle: `Hardware P-256 credential created for ${rpId}`,
      });
      await chrome.webAuthenticationProxy.completeCreateRequest({
        requestId,
        responseJson: data.responseJson,
      });
    } else {
      const error = data.error || { name: "NotAllowedError", message: "ESP32 enrollment failed" };
      await updateBadge("on");
      await notifyTab(tabId, {
        type: "YUBIESP_HUD",
        state: "error",
        op: "create",
        rpId,
        title: "Registration Declined",
        subtitle: error.message,
      });
      await chrome.webAuthenticationProxy.completeCreateRequest({
        requestId,
        error,
      });
    }
  } catch (err) {
    clearInterval(keepAlive);
    if (!activeCeremonies.has(requestId)) return;
    activeCeremonies.delete(requestId);
    await ensureTabFocused(tabId, windowId);
    await updateBadge("err");
    await notifyTab(tabId, {
      type: "YUBIESP_HUD",
      state: "error",
      op: "create",
      rpId,
      title: "YubiESP Bridge Error",
      subtitle: String(err.message || err),
    });
    await chrome.webAuthenticationProxy.completeCreateRequest({
      requestId,
      error: { name: "NotAllowedError", message: "YubiESP bridge unreachable" },
    });
  }
});

chrome.webAuthenticationProxy.onGetRequest.addListener(async (requestInfo) => {
  const { requestId, requestDetailsJson } = requestInfo;
  let rpId = "website";
  try {
    const parsed = JSON.parse(requestDetailsJson);
    rpId = parsed?.rpId || "website";
  } catch (_) {}

  const { tabId, windowId } = await getActiveTabInfo();
  const abortController = new AbortController();
  const keepAlive = setInterval(() => {
    chrome.storage.local.get("proxyEnabled").catch(() => {});
  }, 5000);
  activeCeremonies.set(requestId, { tabId, windowId, abortController, keepAlive });

  await updateBadge("tap");
  await notifyTab(tabId, {
    type: "YUBIESP_HUD",
    state: "waiting_touch",
    op: "get",
    rpId,
    title: "Press BOOT or EN Button on ESP32",
    subtitle: `Confirm sign-in for ${rpId}`,
  });

  try {
    const res = await fetch(`${BRIDGE_URL}/webauthn/get`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ requestId, requestDetailsJson }),
      signal: abortController.signal,
    });
    const data = await res.json();

    if (!activeCeremonies.has(requestId)) return;
    clearInterval(keepAlive);
    activeCeremonies.delete(requestId);

    await ensureTabFocused(tabId, windowId);

    if (data.responseJson) {
      await updateBadge("on");
      await notifyTab(tabId, {
        type: "YUBIESP_HUD",
        state: "approved",
        op: "get",
        rpId,
        title: "Signed by ESP32 Hardware Key",
        subtitle: `Verified P-256 assertion for ${rpId}`,
      });
      await chrome.webAuthenticationProxy.completeGetRequest({
        requestId,
        responseJson: data.responseJson,
      });
    } else {
      const error = data.error || { name: "NotAllowedError", message: "ESP32 signing failed" };
      await updateBadge("on");
      await notifyTab(tabId, {
        type: "YUBIESP_HUD",
        state: "error",
        op: "get",
        rpId,
        title: "Sign-In Declined",
        subtitle: error.message,
      });
      await chrome.webAuthenticationProxy.completeGetRequest({
        requestId,
        error,
      });
    }
  } catch (err) {
    clearInterval(keepAlive);
    if (!activeCeremonies.has(requestId)) return;
    activeCeremonies.delete(requestId);
    await ensureTabFocused(tabId, windowId);
    await updateBadge("err");
    await notifyTab(tabId, {
      type: "YUBIESP_HUD",
      state: "error",
      op: "get",
      rpId,
      title: "YubiESP Bridge Error",
      subtitle: String(err.message || err),
    });
    await chrome.webAuthenticationProxy.completeGetRequest({
      requestId,
      error: { name: "NotAllowedError", message: "YubiESP bridge unreachable" },
    });
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "GET_PROXY_STATE") {
    chrome.storage.local.get("proxyEnabled").then(({ proxyEnabled = true }) => {
      sendResponse({ proxyEnabled, isAttached });
    });
    return true;
  }
  if (msg?.type === "SET_PROXY_STATE") {
    chrome.storage.local.set({ proxyEnabled: !!msg.proxyEnabled }).then(async () => {
      const attached = await syncProxyAttachment();
      sendResponse({ proxyEnabled: !!msg.proxyEnabled, isAttached: attached });
    });
    return true;
  }
  return false;
});
