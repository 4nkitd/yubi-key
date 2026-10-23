package bridge

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const PlaygroundHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>YubiESP Hardware Security Key - Live WebAuthn Test</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0d1117;
      color: #e6edf3;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", sans-serif;
      min-height: 100vh;
      display: flex;
      justify-content: center;
      padding: 48px 20px;
    }
    .wrap { width: 100%; max-width: 680px; display: flex; flex-direction: column; gap: 20px; }
    .hero {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 14px;
      padding: 22px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .hero h1 { font-size: 20px; font-weight: 700; color: #f0f6fc; }
    .hero p { font-size: 13px; color: #8b949e; margin-top: 4px; }
    .status-pill {
      display: flex; align-items: center; gap: 8px;
      padding: 6px 12px; border-radius: 999px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.35);
      color: #34d399; font-size: 12px; font-weight: 600;
    }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #10b981; box-shadow: 0 0 8px #10b981; }
    .card {
      background: #161b22; border: 1px solid #30363d; border-radius: 14px;
      padding: 22px 24px; display: flex; flex-direction: column; gap: 16px;
    }
    .field { display: flex; flex-direction: column; gap: 6px; }
    .field label { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; color: #8b949e; text-transform: uppercase; }
    .field input {
      background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
      padding: 10px 12px; color: #f0f6fc; font-size: 14px;
    }
    .btns { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    button {
      padding: 12px 16px; border-radius: 9px; font-size: 14px; font-weight: 600;
      cursor: pointer; border: 1px solid transparent; transition: all 0.15s ease;
    }
    .btn-primary { background: #238636; color: #ffffff; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: rgba(56, 189, 248, 0.14); border-color: rgba(56, 189, 248, 0.4); color: #7dd3fc; }
    .btn-secondary:hover { background: rgba(56, 189, 248, 0.24); }
    pre {
      background: #0d1117; border: 1px solid #21262d; border-radius: 10px;
      padding: 14px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px; color: #a5d6ff; overflow-x: auto; white-space: pre-wrap;
      word-break: break-all; min-height: 120px;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div>
        <h1>YubiESP Hardware Passkey Playground</h1>
        <p>Standard W3C <code>navigator.credentials</code> WebAuthn Ceremony backed by ESP32-WROOM-32</p>
      </div>
      <div class="status-pill">
        <span class="dot" id="hwDot"></span>
        <span id="hwText">Checking ESP32...</span>
      </div>
    </div>

    <div class="card">
      <div class="field">
        <label>Username</label>
        <input id="username" value="user@yubiesp.local" />
      </div>
      <div class="btns">
        <button class="btn-primary" id="regBtn">1. Register Passkey (Press BOOT)</button>
        <button class="btn-secondary" id="loginBtn">2. Sign In with Passkey (Press BOOT)</button>
      </div>
      <div class="field">
        <label>Live WebAuthn Output</label>
        <pre id="logOut">Click "Register Passkey" above, then press the physical BOOT button on your ESP32 when its blue LED blinks.</pre>
      </div>
    </div>
  </div>

  <script>
    if (window.location.hostname === "127.0.0.1") {
      window.location.hostname = "localhost";
    }
    const logOut = document.getElementById("logOut");
    const hwText = document.getElementById("hwText");
    const hwDot = document.getElementById("hwDot");

    function b64urlEncode(buf) {
      const bytes = new Uint8Array(buf);
      let bin = "";
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    async function pollHw() {
      try {
        const r = await fetch("/status");
        const d = await r.json();
        if (d.connected && d.info) {
          hwText.textContent = d.info.device + " · Counter #" + d.info.counter;
          hwDot.style.background = "#10b981";
        } else {
          hwText.textContent = "ESP32 Disconnected";
          hwDot.style.background = "#ef4444";
        }
      } catch (_) {}
    }
    pollHw();
    setInterval(pollHw, 1500);

    document.getElementById("regBtn").addEventListener("click", async () => {
      const username = document.getElementById("username").value.trim() || "user";
      logOut.textContent = "Waiting for physical BOOT button press on ESP32 (watch the blue LED blink)...";
      try {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const userId = new TextEncoder().encode(username);
        const cred = await navigator.credentials.create({
          publicKey: {
            challenge,
            rp: { name: "YubiESP Local Demo", id: window.location.hostname },
            user: { id: userId, name: username, displayName: username },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
            timeout: 60000,
            attestation: "direct"
          }
        });
        logOut.textContent = "Passkey Created via navigator.credentials.create()!\n\n" + JSON.stringify({
          id: cred.id,
          type: cred.type,
          authenticatorAttachment: cred.authenticatorAttachment,
          clientDataJSON: JSON.parse(new TextDecoder().decode(cred.response.clientDataJSON)),
          attestationObject_b64url: b64urlEncode(cred.response.attestationObject),
        }, null, 2);
        pollHw();
      } catch (err) {
        logOut.textContent = "Error: " + err.name + ": " + err.message;
      }
    });

    document.getElementById("loginBtn").addEventListener("click", async () => {
      logOut.textContent = "Waiting for physical BOOT button press on ESP32 to sign assertion...";
      try {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge,
            rpId: window.location.hostname,
            userVerification: "preferred",
            timeout: 60000
          }
        });
        logOut.textContent = "Signed In via navigator.credentials.get()!\n\n" + JSON.stringify({
          id: assertion.id,
          type: assertion.type,
          authenticatorAttachment: assertion.authenticatorAttachment,
          clientDataJSON: JSON.parse(new TextDecoder().decode(assertion.response.clientDataJSON)),
          authenticatorData_b64url: b64urlEncode(assertion.response.authenticatorData),
          signature_b64url: b64urlEncode(assertion.response.signature),
          userHandle: assertion.response.userHandle ? new TextDecoder().decode(assertion.response.userHandle) : null
        }, null, 2);
        pollHw();
      } catch (err) {
        logOut.textContent = "Error: " + err.name + ": " + err.message;
      }
    });
  </script>
</body>
</html>`

func isOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return strings.HasPrefix(origin, "chrome-extension://") ||
		strings.HasPrefix(origin, "http://localhost:") ||
		strings.HasPrefix(origin, "http://127.0.0.1:")
}

func setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && isOriginAllowed(r) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}
}

func checkPostAllowed(w http.ResponseWriter, r *http.Request) bool {
	if !isOriginAllowed(r) {
		writeJSON(w, r, http.StatusForbidden, map[string]any{"error": "forbidden_origin"})
		return false
	}
	if r.Method == http.MethodOptions {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": true})
		return false
	}
	if r.Method != http.MethodPost {
		writeJSON(w, r, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	setCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func RunServer(addr string, b *ESP32Bridge) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !isOriginAllowed(r) {
			writeJSON(w, r, http.StatusForbidden, map[string]any{"error": "forbidden_origin"})
			return
		}
		if r.Method == http.MethodOptions {
			writeJSON(w, r, http.StatusOK, map[string]any{"ok": true})
			return
		}
		if r.URL.Path != "/" {
			writeJSON(w, r, http.StatusNotFound, map[string]any{"error": "not_found"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, PlaygroundHTML)
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if !isOriginAllowed(r) {
			writeJSON(w, r, http.StatusForbidden, map[string]any{"error": "forbidden_origin"})
			return
		}
		if r.Method == http.MethodOptions {
			writeJSON(w, r, http.StatusOK, map[string]any{"ok": true})
			return
		}
		writeJSON(w, r, http.StatusOK, b.GetStatus())
	})

	mux.HandleFunc("/ceremony", func(w http.ResponseWriter, r *http.Request) {
		if !isOriginAllowed(r) {
			writeJSON(w, r, http.StatusForbidden, map[string]any{"error": "forbidden_origin"})
			return
		}
		if r.Method == http.MethodOptions {
			writeJSON(w, r, http.StatusOK, map[string]any{"ok": true})
			return
		}
		writeJSON(w, r, http.StatusOK, b.GetCeremony())
	})

	mux.HandleFunc("/blink", func(w http.ResponseWriter, r *http.Request) {
		if !checkPostAllowed(w, r) {
			return
		}
		res, err := b.ExecCmd("BLINK", 5*time.Second, 1, nil)
		if err != nil {
			writeJSON(w, r, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, r, http.StatusOK, res)
	})

	mux.HandleFunc("/raw", func(w http.ResponseWriter, r *http.Request) {
		if !checkPostAllowed(w, r) {
			return
		}
		var body struct {
			Cmd          string  `json:"cmd"`
			Timeout      float64 `json:"timeout"`
			TouchRetries int     `json:"touch_retries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Cmd == "" {
			body.Cmd = "INFO"
		}
		if body.Timeout <= 0 {
			body.Timeout = 18.0
		}
		if body.TouchRetries <= 0 {
			body.TouchRetries = 3
		}
		res, err := b.ExecCmd(body.Cmd, time.Duration(body.Timeout*float64(time.Second)), body.TouchRetries, nil)
		if err != nil {
			writeJSON(w, r, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, r, http.StatusOK, res)
	})

	mux.HandleFunc("/webauthn/create", func(w http.ResponseWriter, r *http.Request) {
		if !checkPostAllowed(w, r) {
			return
		}
		var body struct {
			RequestDetailsJSON string `json:"requestDetailsJson"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}
		writeJSON(w, r, http.StatusOK, b.HandleWebAuthnCreate(body.RequestDetailsJSON))
	})

	mux.HandleFunc("/webauthn/get", func(w http.ResponseWriter, r *http.Request) {
		if !checkPostAllowed(w, r) {
			return
		}
		var body struct {
			RequestDetailsJSON string `json:"requestDetailsJson"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}
		writeJSON(w, r, http.StatusOK, b.HandleWebAuthnGet(body.RequestDetailsJSON))
	})

	mux.HandleFunc("/credentials/delete", func(w http.ResponseWriter, r *http.Request) {
		if !checkPostAllowed(w, r) {
			return
		}
		var body struct {
			CredID string `json:"cred_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		removed := b.Store.Delete(body.CredID)
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "removed": removed})
	})

	mux.HandleFunc("/credentials/sync", func(w http.ResponseWriter, r *http.Request) {
		if !checkPostAllowed(w, r) {
			return
		}
		creds, err := b.SyncResidentKeys()
		if err != nil {
			writeJSON(w, r, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "credentials": creds})
	})

	fmt.Printf("YubiESP Bridge listening on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}
