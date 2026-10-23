# AI Agent Setup Guide (`SETUP.md` / `setup.mc`)

This file gives autonomous coding agents (OpenCode, Claude Code, Cursor, Codex) the exact steps, commands, and constraints needed to build, flash, install, and verify **YubiESP** on a user's machine.

## 1. Architecture & single-binary design

**YubiESP** is packaged as a single self-contained **Go CLI (`yubiesp`)** that embeds:
* Prebuilt ESP32-WROOM-32 firmware binaries (`internal/assets/firmware/{bootloader,partitions,boot_app0,firmware}.bin`)
* The unpacked Chromium MV3 WebAuthn extension (`internal/assets/extension/`)
* The localhost WebAuthn bridge server (`http://127.0.0.1:17380`) and interactive test playground (`http://localhost:17380`)

### Hardware constraint
* **Target board:** Classic **ESP32-WROOM-32 (`ESP32-D0WD-V3`)** connected via USB Type-C or Micro-USB through a **CH340 / CP2102** USB-to-UART serial bridge.
* **Why a host bridge is used:** The classic ESP32 has no hardware USB OTG peripheral and sits behind a UART bridge chip, so it cannot enumerate as a raw USB HID FIDO device (`0xF1D0`) on its own. Instead, private key derivation, NVS storage, NIST P-256 (`secp256r1`) ECDSA signing, and physical button confirmation (`BOOT` on `GPIO 0` or `EN` reset) run on the ESP32 over serial (`115200` baud), while `yubiesp serve` + the Chrome extension connect it to the browser via `chrome.webAuthenticationProxy`.
* **No C++ cross-compiler needed:** Because the compiled ESP32 `.bin` files are embedded inside the Go binary via `//go:embed`, you do not need to install Arduino IDE, PlatformIO, or ESP-IDF unless you modify `firmware/yubiesp/yubiesp.ino`.

## 2. Important compatibility boundary (OpenAI Daybreak / FIDO MDS Root CAs)

Before setting expectations with the user, communicate this cryptographic boundary:

* **Works on standard WebAuthn / Passkey / 2FA sites:** Normal OpenAI / ChatGPT sign-in & MFA, GitHub, Google Account 2FA/Passkeys, Cloudflare, AWS, Bitwarden, Proton, Discord, and `webauthn.io`.
* **Does NOT work in OpenAI "Daybreak" lockdown mode (`is_non_exportable_hardware_key`) or strict FIDO MDS enterprise locks:**
  * OpenAI's optional Daybreak lockdown flow (`/advanced-account-security/daybreak`) requests `attestation: "direct"` and verifies on the backend (`is_non_exportable_hardware_key === true`) that the key's `x5c` attestation certificate chains up to a commercial manufacturer Root CA in the **FIDO Alliance Metadata Service (`mds.fidoalliance.org`)**, such as Yubico's private factory HSM root key (`Yubico U2F Root CA`).
  * Because Yubico's private factory signing key only exists inside Yubico's manufacturing HSMs in Sweden, **no DIY board** (neither this ESP32-WROOM, nor an ESP32-S3 or RP2350 running `Pico-FIDO2` or Google `OpenSK`) can produce a Yubico-CA-signed factory certificate.
  * On OpenAI, the key still registers and appears as **`YubiKey 5 Series with NFC`** for normal account login and MFA, but the Daybreak lockdown wizard's `Continue` button will remain disabled unless a retail factory-signed YubiKey is used.

## 3. Automated execution steps for agents

### Step 1: Verify Go, `esptool`, and serial port
Check that `go`, `esptool` (or `uvx`), and the ESP32 serial port are available:

```bash
which go
which esptool esptool.py uvx 2>/dev/null || true
ls -la /dev/cu.usbserial-* /dev/cu.wchusbserial* /dev/cu.SLAB_USBtoUART* /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true
```

If neither `esptool` nor `uv` is installed (needed only once for flashing), install `esptool` (`brew install esptool` on macOS). If no serial port appears, ask the user to plug in the ESP32 with a data-capable USB-C cable.

### Step 2: Run `./setup.sh` (or `go install`)
From the repository root, run:

```bash
chmod +x ./setup.sh
./setup.sh
```

What `./setup.sh` (and `yubiesp setup`) does automatically:
1. Compiles the `yubiesp` Go binary and installs it to `~/.config/yubiesp/bin/yubiesp` (with a symlink at `~/.local/bin/yubiesp`).
2. Stops any existing `com.yubiesp.bridge` LaunchAgent (macOS) or `yubiesp-bridge.service` (Linux) so the serial port is free.
3. Extracts the embedded ESP32 firmware binaries (`bootloader.bin`, `partitions.bin`, `boot_app0.bin`, `firmware.bin`) and flashes the ESP32 at `460800` baud.
4. Extracts the embedded Chrome extension to `~/.config/yubiesp/extension`.
5. Installs and starts `yubiesp serve` as a persistent background service (`~/Library/LaunchAgents/com.yubiesp.bridge.plist` on macOS, or `yubiesp-bridge.service` under `systemd --user` on Linux).
6. Polls `http://127.0.0.1:17380/status` until the ESP32 completes its handshake and blinks the onboard LED (`GPIO 2`) 5 times.

### Step 3: Verify bridge health & unit tests
Run the Go unit tests and query hardware status:

```bash
go test ./...
~/.config/yubiesp/bin/yubiesp info
curl -s http://127.0.0.1:17380/status
```

Confirm `"connected": true` and `"device": "YubiESP-WROOM-32"` in the JSON output.

### Step 4: Guide the user to load the unpacked browser extension
Chromium extensions using `chrome.webAuthenticationProxy` must be loaded in `chrome://extensions`:

1. Open `chrome://extensions` in Chrome, Brave, Chromium, or Dia.
2. Enable **Developer mode** in the top-right corner.
3. Click **Load unpacked** and select `~/.config/yubiesp/extension` (or `<repo-root>/extension`).
   * Tip on macOS: run `~/.config/yubiesp/bin/yubiesp extension --open` to reveal the folder in Finder.
4. Open `http://localhost:17380` (do **not** use `http://127.0.0.1:17380` because WebAuthn rejects IP literals as RP IDs; the playground redirects `127.0.0.1` to `localhost` automatically).
5. Click **1. Register Passkey**, keep the browser tab focused, and press either physical button (`BOOT` or `EN`) on the ESP32 when the blue LED blinks.

## 4. Troubleshooting for agents

* **`NotAllowedError: The operation is not allowed at this time because the page does not have focus`:**
  Chromium checks `WebContents::IsFocused()` when `completeCreateRequest` resolves. Do not open the extension toolbar popup while a ceremony is waiting for a button press; keep the webpage tab active.
* **Updating the service without re-flashing the ESP32:**
  Run `./setup.sh --skip-flash` (or `yubiesp setup --skip-flash`).
* **Recompiling firmware after editing `firmware/yubiesp/yubiesp.ino`:**
  Compile with PlatformIO (`board = esp32dev`, `platform = espressif32@6.7.0`, `framework = arduino`) and copy `.pio/build/esp32dev/{bootloader,partitions,firmware}.bin` into `internal/assets/firmware/`, then rebuild the Go binary.
