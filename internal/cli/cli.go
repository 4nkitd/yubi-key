package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/4nkitd/yubi-key/internal/assets"
	"github.com/4nkitd/yubi-key/internal/bridge"
	"github.com/4nkitd/yubi-key/internal/installer"
)

const defaultBridgeHTTP = "http://127.0.0.1:17380"

func sendCmd(explicitPort, cmdLine string, timeout time.Duration, retries int) (map[string]any, error) {
	if explicitPort == "" {
		c := &http.Client{Timeout: 800 * time.Millisecond}
		if resp, err := c.Get(defaultBridgeHTTP + "/status"); err == nil {
			var st map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&st)
			_ = resp.Body.Close()
			if st["connected"] == true {
				reqBody, _ := json.Marshal(map[string]any{
					"cmd":           cmdLine,
					"timeout":       timeout.Seconds(),
					"touch_retries": retries,
				})
				hc := &http.Client{Timeout: timeout*time.Duration(max(1, retries)) + 5*time.Second}
				r, err := hc.Post(defaultBridgeHTTP+"/raw", "application/json", bytes.NewReader(reqBody))
				if err != nil {
					return nil, err
				}
				defer r.Body.Close()
				var out map[string]any
				if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
					return nil, err
				}
				return out, nil
			}
		}
	}

	store, err := bridge.NewCredentialStore("")
	if err != nil {
		return nil, err
	}
	b := bridge.NewESP32Bridge(store)
	if explicitPort != "" {
		_ = os.Setenv("YUBIESP_PORT", explicitPort)
	}
	return b.ExecCmd(cmdLine, timeout, retries, func(msg map[string]any) {
		fmt.Fprintf(os.Stderr, "\n[YubiESP] Waiting for physical touch (%v) - Press the BOOT button on your ESP32 now...\n", msg["cmd"])
	})
}

func runTest(port string) error {
	info, err := sendCmd(port, "INFO", 3*time.Second, 1)
	if err != nil || info["ok"] != true {
		return fmt.Errorf("INFO failed: %v", err)
	}
	fmt.Printf("Device: %v (%v) | Counter: %v | AAGUID: %v\n", info["device"], info["chip"], info["counter"], info["aaguid"])

	rpID := "yubiesp.test"
	rpHash := sha256.Sum256([]byte(rpID))
	var randBuf [8]byte
	_, _ = rand.Read(randBuf[:])
	chalEnroll := sha256.Sum256(append([]byte("enroll-challenge-"), randBuf[:]...))

	fmt.Println("\n--- Step 1: Hardware Key Enrollment (P-256) ---")
	fmt.Fprintln(os.Stderr, "[YubiESP] Press the BOOT button on your ESP32 now...")
	cmdEnroll := fmt.Sprintf("ENROLL %s %s 45 - 0 %s testuser -",
		hex.EncodeToString(rpHash[:]),
		hex.EncodeToString(chalEnroll[:]),
		rpID)
	enroll, err := sendCmd(port, cmdEnroll, 18*time.Second, 3)
	if err != nil || enroll["ok"] != true {
		return fmt.Errorf("ENROLL failed: %v (%v)", err, enroll)
	}

	khHex, _ := enroll["key_handle"].(string)
	pxHex, _ := enroll["pubkey_x"].(string)
	pyHex, _ := enroll["pubkey_y"].(string)
	u2fSigHex, _ := enroll["u2f_sig_der"].(string)
	sigDERHex, _ := enroll["sig_der"].(string)
	flagsFloat, _ := enroll["flags"].(float64)
	cntFloat, _ := enroll["counter"].(float64)
	aaguidHex, _ := info["aaguid"].(string)

	fmt.Printf("Enrolled! Counter=%d\n", int(cntFloat))
	fmt.Printf("  Key Handle (48B): %s...%s\n", khHex[:32], khHex[len(khHex)-16:])
	fmt.Printf("  Public Key X:     %s\n", pxHex)
	fmt.Printf("  Public Key Y:     %s\n", pyHex)

	khBytes, _ := hex.DecodeString(khHex)
	pxBytes, _ := hex.DecodeString(pxHex)
	pyBytes, _ := hex.DecodeString(pyHex)
	aaguidBytes, _ := hex.DecodeString(aaguidHex)

	var u2fMsg bytes.Buffer
	u2fMsg.WriteByte(0x00)
	u2fMsg.Write(rpHash[:])
	u2fMsg.Write(chalEnroll[:])
	u2fMsg.Write(khBytes)
	u2fMsg.WriteByte(0x04)
	u2fMsg.Write(pxBytes)
	u2fMsg.Write(pyBytes)
	if err := bridge.VerifyP256Signature(pxHex, pyHex, u2fSigHex, u2fMsg.Bytes()); err != nil {
		return fmt.Errorf("U2F attestation verification failed: %w", err)
	}
	fmt.Println("  Verified U2F/OpenSSH enrollment signature on host (NIST P-256 ECDSA-SHA256)!")

	coseKey := bridge.BuildCOSEP256Key(pxBytes, pyBytes)
	var ctapMsg bytes.Buffer
	ctapMsg.Write(rpHash[:])
	ctapMsg.WriteByte(byte(flagsFloat))
	var cntBE [4]byte
	binary.BigEndian.PutUint32(cntBE[:], uint32(cntFloat))
	ctapMsg.Write(cntBE[:])
	ctapMsg.Write(aaguidBytes)
	var khLen [2]byte
	binary.BigEndian.PutUint16(khLen[:], 48)
	ctapMsg.Write(khLen[:])
	ctapMsg.Write(khBytes)
	ctapMsg.Write(coseKey)
	ctapMsg.Write(chalEnroll[:])
	if err := bridge.VerifyP256Signature(pxHex, pyHex, sigDERHex, ctapMsg.Bytes()); err != nil {
		return fmt.Errorf("CTAP2 attestation verification failed: %w", err)
	}
	fmt.Println("  Verified CTAP2/WebAuthn MakeCredential signature on host!")

	fmt.Println("\n--- Step 2: Tampered / Cross-Origin Key Handle Rejection (No Touch Needed) ---")
	wrongRPHash := sha256.Sum256([]byte("phishing-site.evil"))
	badCmd := fmt.Sprintf("SIGN %s %s %s 05", hex.EncodeToString(wrongRPHash[:]), khHex, hex.EncodeToString(chalEnroll[:]))
	badRes, err := sendCmd(port, badCmd, 3*time.Second, 1)
	if err != nil || badRes["ok"] == true || badRes["err"] != "INVALID_KEY_HANDLE" {
		return fmt.Errorf("expected INVALID_KEY_HANDLE, got: %v (err=%v)", badRes, err)
	}
	fmt.Printf("Cross-origin phishing check passed: rejected immediately with %v\n", badRes["err"])

	fmt.Println("\n--- Step 3: Hardware Assertion Signing (P-256) ---")
	fmt.Fprintln(os.Stderr, "[YubiESP] Press the BOOT button on your ESP32 now...")
	_, _ = rand.Read(randBuf[:])
	chalSign := sha256.Sum256(append([]byte("login-challenge-"), randBuf[:]...))
	signCmd := fmt.Sprintf("SIGN %s %s %s 05", hex.EncodeToString(rpHash[:]), khHex, hex.EncodeToString(chalSign[:]))
	signRes, err := sendCmd(port, signCmd, 18*time.Second, 3)
	if err != nil || signRes["ok"] != true {
		return fmt.Errorf("SIGN failed: %v (%v)", err, signRes)
	}

	sFlagsFloat, _ := signRes["flags"].(float64)
	sCntFloat, _ := signRes["counter"].(float64)
	sSigDERHex, _ := signRes["sig_der"].(string)

	var signedBlob bytes.Buffer
	signedBlob.Write(rpHash[:])
	signedBlob.WriteByte(byte(sFlagsFloat))
	binary.BigEndian.PutUint32(cntBE[:], uint32(sCntFloat))
	signedBlob.Write(cntBE[:])
	signedBlob.Write(chalSign[:])

	if err := bridge.VerifyP256Signature(pxHex, pyHex, sSigDERHex, signedBlob.Bytes()); err != nil {
		return fmt.Errorf("assertion signature verification failed: %w", err)
	}
	fmt.Printf("Assertion signed and verified! Counter=%d, Flags=0x%02x\n", int(sCntFloat), int(sFlagsFloat))
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `YubiESP - ESP32-WROOM Type-C Hardware Security Key CLI

Usage:
  yubiesp install [--port PORT] [--skip-flash]  One-command install: flash ESP32, unpack Chrome extension & start bridge
  yubiesp setup   [--port PORT] [--skip-flash]  Alias for 'yubiesp install'
  yubiesp serve   [--addr 127.0.0.1:17380]      Run the localhost WebAuthn bridge daemon in foreground
  yubiesp info    [--port PORT]                 Query ESP32 hardware info, AAGUID, and signature counter
  yubiesp blink   [--port PORT]                 Blink the ESP32 onboard LED 5 times
  yubiesp test    [--port PORT]                 Run interactive end-to-end hardware enroll & sign verification
  yubiesp extension [--open]                    Extract and print the unpacked Chrome extension directory
  yubiesp uninstall [--purge]                   Stop service and remove installed binary & extension (--purge wipes credentials)
`)
}

func Run(args []string) int {
	if len(args) < 2 {
		usage()
		return 1
	}

	subcmd := args[1]
	switch subcmd {
	case "setup", "install":
		fs := flag.NewFlagSet("setup", flag.ExitOnError)
		port := fs.String("port", "", "Serial port (default: auto-detect)")
		skipFlash := fs.Bool("skip-flash", false, "Skip flashing ESP32 firmware")
		_ = fs.Parse(args[2:])
		if err := installer.RunSetup(*port, *skipFlash); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := fs.String("addr", "127.0.0.1:17380", "Bridge listen address")
		_ = fs.Parse(args[2:])
		store, err := bridge.NewCredentialStore("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		b := bridge.NewESP32Bridge(store)
		if err := bridge.RunServer(*addr, b); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

	case "info", "status":
		fs := flag.NewFlagSet("info", flag.ExitOnError)
		port := fs.String("port", "", "Serial port")
		_ = fs.Parse(args[2:])
		res, err := sendCmd(*port, "INFO", 3*time.Second, 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))

	case "blink":
		fs := flag.NewFlagSet("blink", flag.ExitOnError)
		port := fs.String("port", "", "Serial port")
		_ = fs.Parse(args[2:])
		res, err := sendCmd(*port, "BLINK", 5*time.Second, 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))

	case "test":
		fs := flag.NewFlagSet("test", flag.ExitOnError)
		port := fs.String("port", "", "Serial port")
		_ = fs.Parse(args[2:])
		if err := runTest(*port); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

	case "extension":
		fs := flag.NewFlagSet("extension", flag.ExitOnError)
		openFinder := fs.Bool("open", false, "Reveal extension folder in Finder / file manager")
		_ = fs.Parse(args[2:])
		extDir := installer.ExtensionDir()
		if err := assets.ExtractExtension(extDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Println(extDir)
		if *openFinder && runtime.GOOS == "darwin" {
			_ = exec.Command("open", "-R", filepath.Join(extDir, "manifest.json")).Run()
		}

	case "uninstall", "remove":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "Also delete ~/.config/yubiesp credentials and secrets")
		_ = fs.Parse(args[2:])
		if err := installer.RunUninstall(*purge); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

	default:
		usage()
		return 1
	}
	return 0
}
