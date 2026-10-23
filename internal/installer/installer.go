package installer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/4nkitd/yubi-key/internal/assets"
	"github.com/4nkitd/yubi-key/internal/bridge"
)

func ExtensionDir() string {
	return filepath.Join(bridge.DefaultConfigDir(), "extension")
}

func InstalledBinPath() string {
	return filepath.Join(bridge.DefaultConfigDir(), "bin", "yubiesp")
}

func copySelfBinary() (string, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	dest := InstalledBinPath()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	if filepath.Clean(selfPath) != filepath.Clean(dest) {
		in, err := os.Open(selfPath)
		if err != nil {
			return "", err
		}
		defer in.Close()
		tmp := dest + ".tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return "", err
		}
		_ = out.Close()
		if err := os.Rename(tmp, dest); err != nil {
			return "", err
		}
	}

	home, _ := os.UserHomeDir()
	if home != "" {
		localBin := filepath.Join(home, ".local", "bin")
		if err := os.MkdirAll(localBin, 0o755); err == nil {
			linkPath := filepath.Join(localBin, "yubiesp")
			_ = os.Remove(linkPath)
			_ = os.Symlink(dest, linkPath)
		}
	}
	return dest, nil
}

func stopService() {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		plist := filepath.Join(home, "Library", "LaunchAgents", "com.yubiesp.bridge.plist")
		if _, err := os.Stat(plist); err == nil {
			_ = exec.Command("launchctl", "unload", plist).Run()
		}
	} else if runtime.GOOS == "linux" {
		_ = exec.Command("systemctl", "--user", "stop", "yubiesp-bridge.service").Run()
	}
}

func startService(binPath, customPort string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	if runtime.GOOS == "darwin" {
		launchDir := filepath.Join(home, "Library", "LaunchAgents")
		if err := os.MkdirAll(launchDir, 0o755); err != nil {
			return err
		}
		logDir := bridge.DefaultConfigDir()
		_ = os.MkdirAll(logDir, 0o755)
		outLog := filepath.Join(logDir, "bridge.log")
		errLog := filepath.Join(logDir, "bridge.err.log")
		plistPath := filepath.Join(launchDir, "com.yubiesp.bridge.plist")
		envBlock := ""
		if customPort != "" {
			envBlock = fmt.Sprintf(`  <key>EnvironmentVariables</key>
  <dict>
    <key>YUBIESP_PORT</key>
    <string>%s</string>
  </dict>
`, customPort)
		}
		content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.yubiesp.bridge</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>serve</string>
  </array>
%s  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>%s</string>
  <key>StandardErrorPath</key>
  <string>%s</string>
</dict>
</plist>
`, binPath, envBlock, outLog, errLog)
		if err := os.WriteFile(plistPath, []byte(content), 0o644); err != nil {
			return err
		}
		return exec.Command("launchctl", "load", plistPath).Run()
	}

	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return err
	}
	unitPath := filepath.Join(unitDir, "yubiesp-bridge.service")
	envLine := ""
	if customPort != "" {
		envLine = fmt.Sprintf("Environment=\"YUBIESP_PORT=%s\"\n", customPort)
	}
	unit := fmt.Sprintf(`[Unit]
Description=YubiESP Hardware Security Key Bridge

[Service]
%sExecStart="%s" serve
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
`, envLine, binPath)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	_ = exec.Command("systemctl", "--user", "enable", "yubiesp-bridge.service").Run()
	return exec.Command("systemctl", "--user", "restart", "yubiesp-bridge.service").Run()
}

func findEsptoolCmd() ([]string, error) {
	if p, err := exec.LookPath("esptool"); err == nil {
		return []string{p}, nil
	}
	if p, err := exec.LookPath("esptool.py"); err == nil {
		return []string{p}, nil
	}
	if p, err := exec.LookPath("uvx"); err == nil {
		return []string{p, "--from", "esptool", "esptool"}, nil
	}
	if p, err := exec.LookPath("python3"); err == nil {
		return []string{p, "-m", "esptool"}, nil
	}
	return nil, fmt.Errorf("esptool not found (install with: brew install esptool or brew install uv)")
}

func FlashFirmware(port string) error {
	tmpDir, err := os.MkdirTemp("", "yubiesp-fw-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	files, err := assets.ExtractFirmware(tmpDir)
	if err != nil {
		return err
	}

	esptoolCmd, err := findEsptoolCmd()
	if err != nil {
		return err
	}

	args := append(esptoolCmd[1:],
		"--chip", "esp32",
		"--port", port,
		"--baud", "460800",
		"write-flash", "-z",
		"--flash-mode", "dio",
		"--flash-freq", "40m",
		"--flash-size", "4MB",
		"0x1000", files["bootloader.bin"],
		"0x8000", files["partitions.bin"],
		"0xe000", files["boot_app0.bin"],
		"0x10000", files["firmware.bin"],
	)
	cmd := exec.Command(esptoolCmd[0], args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func RunSetup(explicitPort string, skipFlash bool) error {
	fmt.Println("==> YubiESP Hardware Security Key Setup")

	port := bridge.FindSerialPort(explicitPort)
	if port == "" {
		return fmt.Errorf("no ESP32 serial port detected (/dev/cu.usbserial-* or /dev/ttyUSB*). Plug in your ESP32-WROOM Type-C board and re-run 'yubiesp setup'")
	}
	fmt.Printf("==> Detected ESP32 serial port: %s\n", port)

	stopService()

	if !skipFlash {
		fmt.Printf("==> Flashing embedded YubiESP firmware to %s...\n", port)
		if err := FlashFirmware(port); err != nil {
			return fmt.Errorf("firmware flash failed: %w", err)
		}
	}

	extDir := ExtensionDir()
	fmt.Printf("==> Unpacking Chrome WebAuthn extension to %s...\n", extDir)
	if err := assets.ExtractExtension(extDir); err != nil {
		return fmt.Errorf("failed to extract extension: %w", err)
	}

	binPath, err := copySelfBinary()
	if err != nil {
		return fmt.Errorf("failed to install yubiesp binary: %w", err)
	}
	fmt.Printf("==> Installed yubiesp binary to %s\n", binPath)

	fmt.Println("==> Starting background YubiESP bridge service on http://127.0.0.1:17380...")
	if err := startService(binPath, explicitPort); err != nil {
		return fmt.Errorf("failed to start background service: %w", err)
	}

	fmt.Println("==> Waiting for YubiESP hardware handshake...")
	client := &http.Client{Timeout: 2 * time.Second}
	connected := false
	for i := 0; i < 20; i++ {
		time.Sleep(400 * time.Millisecond)
		resp, err := client.Get("http://127.0.0.1:17380/status")
		if err != nil {
			continue
		}
		var st map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&st)
		_ = resp.Body.Close()
		if st["connected"] == true {
			connected = true
			if info, ok := st["info"].(map[string]any); ok {
				b, _ := json.MarshalIndent(info, "", "  ")
				fmt.Println(string(b))
			}
			break
		}
	}
	if !connected {
		return fmt.Errorf("bridge started, but ESP32 did not respond on %s", port)
	}

	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:17380/blink", nil)
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}

	fmt.Printf(`
====================================================================
YubiESP is flashed and running on http://localhost:17380
====================================================================
Unpacked Chrome Extension Path:
  %s

Next step (load the browser extension once):
  1. Open chrome://extensions in Chrome, Brave, Chromium, or Dia.
  2. Enable "Developer mode" (top right).
  3. Click "Load unpacked" and select:
     %s
  4. Visit http://localhost:17380 or https://webauthn.io to test!
====================================================================
`, extDir, extDir)
	return nil
}

func RunUninstall() error {
	stopService()
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		_ = os.Remove(filepath.Join(home, "Library", "LaunchAgents", "com.yubiesp.bridge.plist"))
	} else if runtime.GOOS == "linux" {
		_ = exec.Command("systemctl", "--user", "disable", "yubiesp-bridge.service").Run()
		_ = os.Remove(filepath.Join(home, ".config", "systemd", "user", "yubiesp-bridge.service"))
	}
	fmt.Println("Stopped and removed YubiESP background service.")
	return nil
}
