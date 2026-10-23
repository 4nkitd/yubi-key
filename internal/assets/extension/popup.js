const BRIDGE_URL = "http://127.0.0.1:17380";

const ledIndicator = document.getElementById("ledIndicator");
const devicePort = document.getElementById("devicePort");
const proxyToggle = document.getElementById("proxyToggle");
const ceremonyBanner = document.getElementById("ceremonyBanner");
const ceremonyText = document.getElementById("ceremonyText");
const connStatus = document.getElementById("connStatus");
const signCounter = document.getElementById("signCounter");
const rkCount = document.getElementById("rkCount");
const blinkBtn = document.getElementById("blinkBtn");
const syncBtn = document.getElementById("syncBtn");
const credCount = document.getElementById("credCount");
const credsList = document.getElementById("credsList");

async function loadProxyState() {
  chrome.runtime.sendMessage({ type: "GET_PROXY_STATE" }, (res) => {
    if (res) {
      proxyToggle.checked = !!res.proxyEnabled;
    }
  });
}

proxyToggle.addEventListener("change", () => {
  chrome.runtime.sendMessage({
    type: "SET_PROXY_STATE",
    proxyEnabled: proxyToggle.checked,
  });
});

blinkBtn.addEventListener("click", async () => {
  blinkBtn.disabled = true;
  blinkBtn.textContent = "Blinking...";
  try {
    await fetch(`${BRIDGE_URL}/blink`, { method: "POST" });
  } catch (_) {}
  setTimeout(() => {
    blinkBtn.disabled = false;
    blinkBtn.textContent = "Blink ESP32 LED";
  }, 600);
});

syncBtn.addEventListener("click", async () => {
  syncBtn.disabled = true;
  syncBtn.textContent = "Press BOOT...";
  try {
    await fetch(`${BRIDGE_URL}/credentials/sync`, { method: "POST" });
    await refreshStatus();
  } catch (_) {}
  syncBtn.disabled = false;
  syncBtn.textContent = "Sync from NVS";
});

function renderCredentials(creds) {
  credCount.textContent = String(creds.length);
  credsList.innerHTML = "";
  if (!creds.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No passkeys registered yet.";
    credsList.appendChild(empty);
    return;
  }

  for (const c of creds) {
    const row = document.createElement("div");
    row.className = "cred-item";

    const meta = document.createElement("div");
    meta.className = "cred-meta";

    const rp = document.createElement("div");
    rp.className = "cred-rp";
    rp.textContent = c.rp_id || "unknown";

    const user = document.createElement("div");
    user.className = "cred-user";
    user.textContent = `${c.user_name || "user"} · ${c.cred_id.slice(0, 10)}…`;

    meta.appendChild(rp);
    meta.appendChild(user);

    const del = document.createElement("button");
    del.className = "del-btn";
    del.title = "Remove passkey from local index";
    del.textContent = "✕";
    del.addEventListener("click", async () => {
      await fetch(`${BRIDGE_URL}/credentials/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cred_id: c.cred_id }),
      });
      refreshStatus();
    });

    row.appendChild(meta);
    row.appendChild(del);
    credsList.appendChild(row);
  }
}

async function refreshStatus() {
  try {
    const res = await fetch(`${BRIDGE_URL}/status`);
    const data = await res.json();

    if (data.connected && data.info) {
      connStatus.textContent = "Ready";
      connStatus.style.color = "#10b981";
      devicePort.textContent = `${data.port} · ${data.info.chip}`;
      signCounter.textContent = String(data.info.counter);
      rkCount.textContent = `${data.info.rk_count}/${data.info.rk_max}`;
      ledIndicator.className = "chip-icon online";
    } else {
      connStatus.textContent = "Unplugged";
      connStatus.style.color = "#f87171";
      devicePort.textContent = "Connect ESP32 via USB-C";
      signCounter.textContent = "-";
      rkCount.textContent = "-";
      ledIndicator.className = "chip-icon";
    }

    const cer = data.ceremony;
    if (cer && cer.state === "waiting_touch") {
      ceremonyBanner.hidden = false;
      ceremonyText.textContent = cer.message || "Press BOOT button on ESP32...";
      ledIndicator.className = "chip-icon waiting";
    } else {
      ceremonyBanner.hidden = true;
    }

    renderCredentials(data.credentials || []);
  } catch (_) {
    connStatus.textContent = "Bridge Down";
    connStatus.style.color = "#f87171";
    devicePort.textContent = "127.0.0.1:17380 offline";
    ledIndicator.className = "chip-icon";
  }
}

loadProxyState();
refreshStatus();
setInterval(refreshStatus, 1000);
