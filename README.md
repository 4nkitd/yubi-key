# YubiESP: ESP32-WROOM Type-C Hardware Security Key

Turn a classic **ESP32-WROOM-32 (`ESP32-D0WD-V3`, CH340/CP2102 Type-C)** into a hardware FIDO2 / WebAuthn Passkey and security key with physical button confirmation, powered by a single self-contained **Go CLI (`yubiesp`)**.

```
[Browser: Chrome / Brave / Dia / Chromium]
       │
       │  chrome.webAuthenticationProxy (MV3 Extension + In-Page HUD)
       ▼
[yubiesp serve (Go Localhost Bridge on http://127.0.0.1:17380)]
       │
       │  115200 baud USB-C UART (/dev/cu.usbserial-* or /dev/ttyUSB*)
       ▼
[ESP32-WROOM-32 Hardware Token]
  ├─ 256-bit Hardware TRNG Master Key in NVS (never leaves the chip)
  ├─ Deterministic HMAC-SHA256 + NIST P-256 (secp256r1) key derivation
  ├─ On-chip mbedTLS ECDSA-SHA256 signing & monotonic NVS counter
  └─ Physical User Presence: LED (GPIO 2) blinks until BOOT/EN button is pressed
```

## Why this architecture exists

A classic **ESP32-WROOM-32** connects its USB-C port through a CH340 or CP2102 USB-to-UART bridge and has no hardware USB OTG peripheral. Because of that, the operating system only sees a serial port (`/dev/cu.usbserial-*`) and cannot enumerate the board as a native USB HID FIDO device (`0xF1D0`) on its own.

**YubiESP** solves this with a single Go binary that embeds the ESP32 firmware, the background bridge server, and the Chromium extension:
* Private keys are generated and derived inside the ESP32 using its hardware True Random Number Generator (`esp_fill_random`) and stored in NVS flash.
* Private keys **never** leave the ESP32.
* Every registration and sign-in request blinks the ESP32's blue status LED (`GPIO 2`) and blocks until you physically press the **`BOOT`** (or **`EN`**) button on the board.
* `yubiesp setup` flashes the ESP32, extracts the Chrome extension to `~/.config/yubiesp/extension`, and registers `yubiesp serve` as a background service (`LaunchAgent` on macOS or `systemd` on Linux).

---

## Quick start (1 minute)

### Prerequisites
* An **ESP32-WROOM-32** development board plugged in via USB-C.
* **Go 1.22+** (`brew install go` on macOS) and **`esptool`** (`brew install esptool` or `uv`).
* A Chromium-based browser (Chrome, Brave, Dia, Edge, or Chromium).

### Option A: One-command setup from source
```bash
git clone https://github.com/4nkitd/yubi-key.git
cd yubi-key
./setup.sh
```

### Option B: Install directly with `go install`
```bash
go install github.com/4nkitd/yubi-key/cmd/yubiesp@latest
yubiesp install
```

`yubiesp install` (or `yubiesp setup`) automatically detects your serial port, flashes the embedded ESP32 firmware, unpacks the Chrome extension to `~/.config/yubiesp/extension`, symlinks `yubiesp` onto your `$PATH`, starts the background bridge service on `http://127.0.0.1:17380`, and blinks the ESP32 LED.

### Load the browser extension
1. Open `chrome://extensions` in your browser.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select `~/.config/yubiesp/extension` (or the `extension` folder in this repo; run `yubiesp extension --open` on macOS to reveal it in Finder).
4. Open **[http://localhost:17380](http://localhost:17380)** (the built-in WebAuthn playground) or **[https://webauthn.io](https://webauthn.io)**.
5. Click **Register Passkey**, watch the blue LED on your ESP32 blink, and press the physical **`BOOT`** button on the board.

*(For AI coding agents setting this up on behalf of a user, see [`SETUP.md`](./SETUP.md) / [`setup.mc`](./setup.mc).)*

---

## Known limitation: OpenAI "Daybreak" & FIDO MDS factory root CA checks

YubiESP works across standard WebAuthn, Passkey, and 2FA sites, including:
* Normal **OpenAI / ChatGPT** passkey login & MFA (registers as `YubiKey 5 Series with NFC`)
* **GitHub**, **Google**, **Cloudflare**, **AWS**, **Bitwarden**, **Proton**, **Discord**, **X**, and **[webauthn.io](https://webauthn.io)**

### Where it will NOT work (OpenAI Daybreak lockdown)
YubiESP **will not pass OpenAI's optional "Daybreak" lockdown enrollment** (`/advanced-account-security/daybreak`) or strict government/enterprise policies that enforce `is_non_exportable_hardware_key` via **FIDO Alliance Metadata Service (MDS) Root CA verification**.

* **Why:** During enrollment with `attestation: "direct"`, OpenAI's Daybreak backend verifies that the `x5c` X.509 attestation certificate inside `attestationObject` was cryptographically signed by a commercial hardware vendor's private factory Root CA (such as `Yubico U2F Root CA`).
* Yubico's private Root CA key only exists inside Yubico's factory HSMs in Sweden where retail YubiKeys are manufactured.
* Because no DIY microcontroller has access to Yubico's private factory signing key, **no DIY board (neither this ESP32-WROOM, nor an ESP32-S3 or RP2350 running `Pico-FIDO2` or Google `OpenSK`)** can pass a strict FIDO MDS factory Root CA check.
* On OpenAI, the key still registers and appears as **`YubiKey 5 Series with NFC`** for normal account login and MFA, but the Daybreak lockdown wizard's `Continue` button will remain disabled unless a retail factory-signed YubiKey is used.

---

## CLI commands

```bash
# One-command install: flash ESP32, unpack Chrome extension, and start background bridge
yubiesp install

# Update binary/extension/service without re-flashing the ESP32
yubiesp install --skip-flash

# Query ESP32 status, AAGUID, signature counter, and resident key slots
yubiesp info

# Blink the onboard blue LED 5 times
yubiesp blink

# Run an interactive end-to-end NIST P-256 enrollment + assertion verification test
yubiesp test

# Print (or reveal in Finder) the unpacked Chrome extension directory
yubiesp extension --open

# Stop service and remove installed binary & extension (keeps credentials.json)
yubiesp uninstall

# Full uninstall including ~/.config/yubiesp credentials & logs
yubiesp uninstall --purge
```

---

## Repository structure

* `main.go` - `yubiesp` CLI entrypoint (`setup`, `serve`, `info`, `blink`, `test`, `extension`, `uninstall`).
* `internal/assets/` - `//go:embed` bundle containing the prebuilt ESP32 firmware binaries (`internal/assets/firmware/`) and the Chromium MV3 extension (`internal/assets/extension/`).
* `internal/bridge/` - Go serial port manager, persistent credential store, WebAuthn/CTAP2 CBOR/COSE/PRF/X.509 engine, and `127.0.0.1:17380` HTTP bridge + Playground UI.
* `internal/installer/` - Automated ESP32 flasher, extension extractor, and macOS `LaunchAgent` / Linux `systemd` service installer.
* `firmware/yubiesp/yubiesp.ino` - ESP32 hardware security key firmware source (NIST P-256 ECDSA, SHA-256, HMAC-SHA256 key wrapping, NVS resident slots, physical `BOOT` button presence check).
* `setup.sh` - One-command builder and installer.
* `SETUP.md` / `setup.mc` - Autonomous setup specification for AI agents.
