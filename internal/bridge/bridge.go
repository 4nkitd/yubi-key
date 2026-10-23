package bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.bug.st/serial"
)

type CeremonyState struct {
	State     string  `json:"state"`
	Op        *string `json:"op"`
	RPID      *string `json:"rp_id"`
	UserName  *string `json:"user_name"`
	UpdatedAt float64 `json:"updated_at"`
	Message   *string `json:"message"`
}

type ESP32Bridge struct {
	Store        *CredentialStore
	serialMu     sync.Mutex
	stateMu      sync.Mutex
	ceremony     CeremonyState
	port         serial.Port
	cachedPort   string
	cachedInfo   map[string]any
	lastInfoTime time.Time
}

func NewESP32Bridge(store *CredentialStore) *ESP32Bridge {
	return &ESP32Bridge{
		Store: store,
		ceremony: CeremonyState{
			State:     "idle",
			UpdatedAt: float64(time.Now().UnixNano()) / 1e9,
		},
	}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (b *ESP32Bridge) SetCeremony(state, op, rpID, userName, message string) {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	b.ceremony = CeremonyState{
		State:     state,
		Op:        strPtr(op),
		RPID:      strPtr(rpID),
		UserName:  strPtr(userName),
		UpdatedAt: float64(time.Now().UnixNano()) / 1e9,
		Message:   strPtr(message),
	}
}

func (b *ESP32Bridge) GetCeremony() CeremonyState {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	c := b.ceremony
	now := float64(time.Now().UnixNano()) / 1e9
	if (c.State == "approved" || c.State == "error") && (now-c.UpdatedAt) > 4.0 {
		c.State = "idle"
	}
	return c
}

func FindSerialPort(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("YUBIESP_PORT"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	patterns := []string{
		"/dev/cu.usbserial-*",
		"/dev/cu.wchusbserial*",
		"/dev/cu.SLAB_USBtoUART*",
		"/dev/ttyUSB*",
		"/dev/ttyACM*",
	}
	var candidates []string
	for _, pat := range patterns {
		matches, _ := filepath.Glob(pat)
		candidates = append(candidates, matches...)
	}
	sort.Strings(candidates)
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

func readLineWithDeadline(p serial.Port, lineBuf *bytes.Buffer, deadline time.Time) (string, bool) {
	tmp := make([]byte, 256)
	for time.Now().Before(deadline) {
		if idx := bytes.IndexByte(lineBuf.Bytes(), '\n'); idx >= 0 {
			line := string(lineBuf.Next(idx + 1))
			return strings.TrimSpace(line), true
		}
		_ = p.SetReadTimeout(120 * time.Millisecond)
		n, err := p.Read(tmp)
		if n > 0 {
			lineBuf.Write(tmp[:n])
			if idx := bytes.IndexByte(lineBuf.Bytes(), '\n'); idx >= 0 {
				line := string(lineBuf.Next(idx + 1))
				return strings.TrimSpace(line), true
			}
		}
		if err != nil {
			break
		}
	}
	return "", false
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func (b *ESP32Bridge) getCachedState() (map[string]any, string, time.Time) {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	return cloneMap(b.cachedInfo), b.cachedPort, b.lastInfoTime
}

func (b *ESP32Bridge) setCachedState(info map[string]any, port string) {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	b.cachedInfo = cloneMap(info)
	b.cachedPort = port
	if info != nil {
		b.lastInfoTime = time.Now()
	}
}

func (b *ESP32Bridge) updateCachedCounter(cnt any) {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	if b.cachedInfo != nil {
		cp := cloneMap(b.cachedInfo)
		cp["counter"] = cnt
		b.cachedInfo = cp
	}
}

func (b *ESP32Bridge) closeSerialLocked() {
	if b.port != nil {
		_ = b.port.Close()
		b.port = nil
	}
}

func (b *ESP32Bridge) ensureSerialLocked(portName string) (serial.Port, error) {
	_, cachedPort, _ := b.getCachedState()
	if b.port != nil && cachedPort == portName {
		return b.port, nil
	}
	b.closeSerialLocked()

	p, err := serial.Open(portName, &serial.Mode{
		BaudRate: 115200,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	})
	if err != nil {
		return nil, err
	}
	_ = p.SetDTR(false)
	_ = p.SetRTS(false)
	_ = p.ResetInputBuffer()

	var lineBuf bytes.Buffer
	for i := 0; i < 6; i++ {
		_, _ = p.Write([]byte("\nPING\n"))
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			line, ok := readLineWithDeadline(p, &lineBuf, deadline)
			if !ok {
				break
			}
			if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
				var msg map[string]any
				if json.Unmarshal([]byte(line), &msg) == nil {
					if msg["cmd"] == "INFO" && msg["ok"] == true {
						time.Sleep(30 * time.Millisecond)
						_ = p.ResetInputBuffer()
						b.port = p
						b.setCachedState(msg, portName)
						return p, nil
					}
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}

	b.port = p
	b.setCachedState(nil, portName)
	return p, nil
}

func (b *ESP32Bridge) ExecCmd(cmdLine string, timeout time.Duration, touchRetries int, onWaitTouch func(map[string]any)) (map[string]any, error) {
	fields := strings.Fields(cmdLine)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	expectedCmd := strings.ToUpper(fields[0])
	if expectedCmd == "PING" {
		expectedCmd = "INFO"
	}
	if touchRetries < 1 {
		touchRetries = 1
	}

	b.serialMu.Lock()
	defer b.serialMu.Unlock()

	portName := FindSerialPort("")
	if portName == "" {
		b.closeSerialLocked()
		b.setCachedState(nil, "")
		return nil, fmt.Errorf("ESP32 is not connected on /dev/cu.usbserial-* or /dev/ttyUSB*")
	}

	p, err := b.ensureSerialLocked(portName)
	if err != nil {
		b.closeSerialLocked()
		return nil, err
	}

	autoPulseNext := false
	for attempt := 0; attempt < touchRetries; attempt++ {
		_ = p.ResetInputBuffer()
		if _, err := p.Write([]byte(strings.TrimSpace(cmdLine) + "\n")); err != nil {
			b.closeSerialLocked()
			return nil, err
		}

		var lineBuf bytes.Buffer
		sawWaitTouch := false
		deadline := time.Now().Add(timeout)

		for time.Now().Before(deadline) {
			line, ok := readLineWithDeadline(p, &lineBuf, deadline)
			if !ok {
				continue
			}

			if sawWaitTouch && (strings.Contains(line, "rst:0x") || strings.Contains(line, "boot:0x") || strings.Contains(line, "ets Jul")) {
				time.Sleep(350 * time.Millisecond)
				autoPulseNext = true
				break
			}

			if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
				continue
			}
			var msg map[string]any
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				continue
			}

			if msg["event"] == "wait_touch" {
				sawWaitTouch = true
				if onWaitTouch != nil {
					onWaitTouch(msg)
				}
				if autoPulseNext {
					autoPulseNext = false
					time.Sleep(50 * time.Millisecond)
					_ = p.SetDTR(true)
					_ = p.SetRTS(false)
					time.Sleep(60 * time.Millisecond)
					_ = p.SetDTR(false)
					_ = p.SetRTS(false)
				}
				continue
			}

			if cmdStr, ok := msg["cmd"].(string); ok && cmdStr != "" && cmdStr != expectedCmd {
				continue
			}

			if msg["ok"] == false && msg["err"] == "USER_PRESENCE_TIMEOUT" && attempt+1 < touchRetries {
				break
			}

			return msg, nil
		}

		if autoPulseNext {
			autoPulseNext = false
			_ = p.ResetInputBuffer()
			_, _ = p.Write([]byte(strings.TrimSpace(cmdLine) + "\n"))
			var lineBuf2 bytes.Buffer
			deadline2 := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline2) {
				line, ok := readLineWithDeadline(p, &lineBuf2, deadline2)
				if !ok {
					continue
				}
				if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
					continue
				}
				var msg map[string]any
				if err := json.Unmarshal([]byte(line), &msg); err != nil {
					continue
				}
				if msg["event"] == "wait_touch" {
					time.Sleep(40 * time.Millisecond)
					_ = p.SetDTR(true)
					_ = p.SetRTS(false)
					time.Sleep(60 * time.Millisecond)
					_ = p.SetDTR(false)
					_ = p.SetRTS(false)
					continue
				}
				if cmdStr, ok := msg["cmd"].(string); ok && cmdStr != "" && cmdStr != expectedCmd {
					continue
				}
				return msg, nil
			}
		}
	}

	return nil, fmt.Errorf("timed out waiting for physical button press (%s)", expectedCmd)
}

func (b *ESP32Bridge) GetStatus() map[string]any {
	portName := FindSerialPort("")
	if portName == "" {
		b.setCachedState(nil, "")
		return map[string]any{
			"connected":   false,
			"port":        nil,
			"info":        nil,
			"ceremony":    b.GetCeremony(),
			"credentials": b.Store.ListAll(),
		}
	}

	infoSnap, portSnap, lastTime := b.getCachedState()
	if !b.serialMu.TryLock() {
		return map[string]any{
			"connected":   true,
			"port":        portName,
			"info":        infoSnap,
			"ceremony":    b.GetCeremony(),
			"credentials": b.Store.ListAll(),
		}
	}
	b.serialMu.Unlock()

	if infoSnap == nil || time.Since(lastTime) > 2500*time.Millisecond || portSnap != portName {
		if info, err := b.ExecCmd("INFO", 2*time.Second, 1, nil); err == nil && info["ok"] == true {
			b.setCachedState(info, portName)
			infoSnap = cloneMap(info)
		}
	}

	return map[string]any{
		"connected":   infoSnap != nil,
		"port":        portName,
		"info":        infoSnap,
		"ceremony":    b.GetCeremony(),
		"credentials": b.Store.ListAll(),
	}
}

func sanitizeToken(s string, maxLen int) string {
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || r == '@' {
			out.WriteRune(r)
		}
		if out.Len() >= maxLen {
			break
		}
	}
	if out.Len() == 0 {
		return "-"
	}
	return out.String()
}

func (b *ESP32Bridge) HandleWebAuthnCreate(requestDetailsJSON string) map[string]any {
	var opts map[string]any
	if err := json.Unmarshal([]byte(requestDetailsJSON), &opts); err != nil {
		return map[string]any{"error": map[string]any{"name": "NotAllowedError", "message": "Invalid request JSON"}}
	}

	rp, _ := opts["rp"].(map[string]any)
	ext, _ := opts["extensions"].(map[string]any)
	rdOverride, _ := ext["remoteDesktopClientOverride"].(map[string]any)
	origin, _ := rdOverride["origin"].(string)
	rpID, _ := rp["id"].(string)
	if rpID == "" && origin != "" {
		if u, err := url.Parse(origin); err == nil {
			rpID = u.Hostname()
		}
	}
	if rpID == "" {
		rpID = "localhost"
	}
	if origin == "" {
		origin = "https://" + rpID
	}
	sameOrigin := true
	if so, ok := rdOverride["sameOriginWithAncestors"].(bool); ok {
		sameOrigin = so
	}

	user, _ := opts["user"].(map[string]any)
	userIDB64, _ := user["id"].(string)
	userName, _ := user["name"].(string)
	if userName == "" {
		userName = "user"
	}
	userDisplay, _ := user["displayName"].(string)
	if userDisplay == "" {
		userDisplay = userName
	}
	challengeB64, _ := opts["challenge"].(string)

	if pubParams, ok := opts["pubKeyCredParams"].([]any); ok && len(pubParams) > 0 {
		hasES256 := false
		for _, item := range pubParams {
			if pm, ok := item.(map[string]any); ok {
				if alg, ok := pm["alg"].(float64); ok && int(alg) == -7 {
					hasES256 = true
					break
				}
			}
		}
		if !hasES256 {
			return map[string]any{
				"error": map[string]any{
					"name":    "NotSupportedError",
					"message": "YubiESP supports ES256 (alg -7) only.",
				},
			}
		}
	}

	clientDataBytes := BuildClientDataJSON("webauthn.create", challengeB64, origin, !sameOrigin)
	cdHash := sha256.Sum256(clientDataBytes)
	rpHash := sha256.Sum256([]byte(rpID))

	userIDHex := "-"
	if userIDB64 != "" {
		if rawUID, err := B64UrlDecode(userIDB64); err == nil && len(rawUID) > 0 {
			if len(rawUID) > 64 {
				rawUID = rawUID[:64]
			}
			userIDHex = hex.EncodeToString(rawUID)
		}
	}
	safeRPID := sanitizeToken(rpID, 60)
	safeUser := sanitizeToken(userName, 60)

	b.SetCeremony("waiting_touch", "create", rpID, userName, fmt.Sprintf("Press BOOT on ESP32 to register passkey for %s", rpID))

	authSel, _ := opts["authenticatorSelection"].(map[string]any)
	rkFlag := "0"
	if authSel != nil && authSel["residentKey"] == "required" {
		rkFlag = "1"
	}

	cmd := fmt.Sprintf("ENROLL %s %s 45 - %s %s %s %s",
		hex.EncodeToString(rpHash[:]),
		hex.EncodeToString(cdHash[:]),
		rkFlag, safeRPID, safeUser, userIDHex)

	enroll, err := b.ExecCmd(cmd, 20*time.Second, 1, nil)
	if err != nil {
		b.SetCeremony("error", "create", rpID, userName, err.Error())
		return map[string]any{"error": map[string]any{"name": "NotAllowedError", "message": err.Error()}}
	}
	if enroll["ok"] != true {
		errCode, _ := enroll["err"].(string)
		if errCode == "" {
			errCode = "ENROLL_FAILED"
		}
		b.SetCeremony("error", "create", rpID, userName, errCode)
		return map[string]any{"error": map[string]any{"name": "NotAllowedError", "message": "ESP32 rejected enrollment: " + errCode}}
	}

	b.SetCeremony("approved", "create", rpID, userName, "Approved on ESP32")
	b.updateCachedCounter(enroll["counter"])

	khHex, _ := enroll["key_handle"].(string)
	pubXHex, _ := enroll["pubkey_x"].(string)
	pubYHex, _ := enroll["pubkey_y"].(string)
	khBytes, _ := hex.DecodeString(khHex)
	pubX, _ := hex.DecodeString(pubXHex)
	pubY, _ := hex.DecodeString(pubYHex)
	counterFloat, _ := enroll["counter"].(float64)
	flagsFloat, _ := enroll["flags"].(float64)
	rkSlotFloat, _ := enroll["rk_slot"].(float64)

	_, hasPRF := ext["prf"]
	_, hasHMAC := ext["hmacCreateSecret"]
	authFlags := byte(flagsFloat)
	var extCBOR []byte
	if hasPRF || hasHMAC {
		authFlags |= 0x80
		extCBOR = HmacSecretExtCBOR
	}

	coseKey := BuildCOSEP256Key(pubX, pubY)
	var authData bytes.Buffer
	authData.Write(rpHash[:])
	authData.WriteByte(authFlags)
	var cntBuf [4]byte
	binary.BigEndian.PutUint32(cntBuf[:], uint32(counterFloat))
	authData.Write(cntBuf[:])
	authData.Write(YubiKey5AAGUID)
	var khLenBuf [2]byte
	binary.BigEndian.PutUint16(khLenBuf[:], uint16(len(khBytes)))
	authData.Write(khLenBuf[:])
	authData.Write(khBytes)
	authData.Write(coseKey)
	authData.Write(extCBOR)

	authBytes := authData.Bytes()
	attPref, _ := opts["attestation"].(string)
	var attObj []byte
	if attPref == "direct" || attPref == "indirect" || attPref == "enterprise" {
		attSig, attCert, err := BuildFIDO2Attestation(authBytes, cdHash[:], YubiKey5AAGUID, khBytes)
		if err == nil {
			attObj = BuildAttestationObject(authBytes, "packed", attSig, attCert)
		} else {
			attObj = BuildAttestationObject(authBytes, "none", nil, nil)
		}
	} else {
		attObj = BuildAttestationObject(authBytes, "none", nil, nil)
	}

	var spki bytes.Buffer
	spki.Write(P256SPKIPrefix)
	spki.Write(pubX)
	spki.Write(pubY)

	credIDB64 := B64UrlEncode(khBytes)
	b.Store.Upsert(CredentialRecord{
		CredID:          credIDB64,
		KeyHandle:       khHex,
		RPID:            rpID,
		RPIDHash:        hex.EncodeToString(rpHash[:]),
		UserID:          userIDB64,
		UserName:        userName,
		UserDisplayName: userDisplay,
		PubKeyX:         pubXHex,
		PubKeyY:         pubYHex,
		RKSlot:          int(rkSlotFloat),
		CreatedAt:       time.Now().Unix(),
	})

	extResults := map[string]any{}
	if ext["credProps"] == true {
		extResults["credProps"] = map[string]any{"rk": rkFlag == "1"}
	}
	if ext["hmacCreateSecret"] == true {
		extResults["hmacCreateSecret"] = true
	}
	if hasPRF {
		prfReq, _ := ext["prf"].(map[string]any)
		evalIn, _ := prfReq["eval"].(map[string]any)
		prfOut := map[string]any{"enabled": true}
		if evalIn != nil {
			if firstStr, ok := evalIn["first"].(string); ok {
				if s1, err := B64UrlDecode(firstStr); err == nil {
					resMap := map[string]any{
						"first": B64UrlEncode(ComputePRF(khBytes, s1)),
					}
					if secStr, ok := evalIn["second"].(string); ok {
						if s2, err := B64UrlDecode(secStr); err == nil {
							resMap["second"] = B64UrlEncode(ComputePRF(khBytes, s2))
						}
					}
					prfOut["results"] = resMap
				}
			}
		}
		extResults["prf"] = prfOut
	}

	respPayload := map[string]any{
		"id":                      credIDB64,
		"rawId":                   credIDB64,
		"type":                    "public-key",
		"authenticatorAttachment": "cross-platform",
		"response": map[string]any{
			"attestationObject":  B64UrlEncode(attObj),
			"authenticatorData":  B64UrlEncode(authBytes),
			"clientDataJSON":     B64UrlEncode(clientDataBytes),
			"publicKey":          B64UrlEncode(spki.Bytes()),
			"publicKeyAlgorithm": -7,
			"transports":         []string{"usb", "nfc"},
		},
		"clientExtensionResults": extResults,
	}
	respBytes, _ := json.Marshal(respPayload)
	return map[string]any{"responseJson": string(respBytes)}
}

func (b *ESP32Bridge) HandleWebAuthnGet(requestDetailsJSON string) map[string]any {
	var opts map[string]any
	if err := json.Unmarshal([]byte(requestDetailsJSON), &opts); err != nil {
		return map[string]any{"error": map[string]any{"name": "NotAllowedError", "message": "Invalid request JSON"}}
	}

	ext, _ := opts["extensions"].(map[string]any)
	rdOverride, _ := ext["remoteDesktopClientOverride"].(map[string]any)
	origin, _ := rdOverride["origin"].(string)
	rpID, _ := opts["rpId"].(string)
	if rpID == "" && origin != "" {
		if u, err := url.Parse(origin); err == nil {
			rpID = u.Hostname()
		}
	}
	if rpID == "" {
		rpID = "localhost"
	}
	if origin == "" {
		origin = "https://" + rpID
	}
	sameOrigin := true
	if so, ok := rdOverride["sameOriginWithAncestors"].(bool); ok {
		sameOrigin = so
	}
	challengeB64, _ := opts["challenge"].(string)
	allowCreds, _ := opts["allowCredentials"].([]any)

	rpHash := sha256.Sum256([]byte(rpID))
	rpHashHex := hex.EncodeToString(rpHash[:])

	var selectedKHHex, selectedCredIDB64, selectedUserIDB64, selectedUserName string

	if len(allowCreds) > 0 {
		for _, item := range allowCreds {
			desc, _ := item.(map[string]any)
			cid, _ := desc["id"].(string)
			if cid == "" {
				continue
			}
			if stored := b.Store.FindByCredID(cid); stored != nil && stored.RPIDHash == rpHashHex {
				selectedKHHex = stored.KeyHandle
				selectedCredIDB64 = cid
				selectedUserIDB64 = stored.UserID
				selectedUserName = stored.UserName
				break
			}
		}
		if selectedKHHex == "" {
			for _, item := range allowCreds {
				desc, _ := item.(map[string]any)
				cid, _ := desc["id"].(string)
				if cid == "" {
					continue
				}
				if rawKH, err := B64UrlDecode(cid); err == nil && len(rawKH) == 48 {
					selectedKHHex = hex.EncodeToString(rawKH)
					selectedCredIDB64 = cid
					break
				}
			}
		}
	} else {
		matches := b.Store.FindByRP(rpID)
		if len(matches) > 0 {
			chosen := matches[0]
			selectedKHHex = chosen.KeyHandle
			selectedCredIDB64 = chosen.CredID
			selectedUserIDB64 = chosen.UserID
			selectedUserName = chosen.UserName
		}
	}

	if selectedKHHex == "" || selectedCredIDB64 == "" {
		return map[string]any{
			"error": map[string]any{
				"name":    "NotAllowedError",
				"message": "No YubiESP passkey found for " + rpID,
			},
		}
	}

	clientDataBytes := BuildClientDataJSON("webauthn.get", challengeB64, origin, !sameOrigin)
	cdHash := sha256.Sum256(clientDataBytes)

	b.SetCeremony("waiting_touch", "get", rpID, selectedUserName, fmt.Sprintf("Press BOOT on ESP32 to sign in to %s", rpID))

	cmd := fmt.Sprintf("SIGN %s %s %s 05", rpHashHex, selectedKHHex, hex.EncodeToString(cdHash[:]))
	signRes, err := b.ExecCmd(cmd, 20*time.Second, 1, nil)
	if err != nil {
		b.SetCeremony("error", "get", rpID, selectedUserName, err.Error())
		return map[string]any{"error": map[string]any{"name": "NotAllowedError", "message": err.Error()}}
	}
	if signRes["ok"] != true {
		errCode, _ := signRes["err"].(string)
		if errCode == "" {
			errCode = "SIGN_FAILED"
		}
		b.SetCeremony("error", "get", rpID, selectedUserName, errCode)
		return map[string]any{"error": map[string]any{"name": "NotAllowedError", "message": "ESP32 rejected assertion: " + errCode}}
	}

	b.SetCeremony("approved", "get", rpID, selectedUserName, "Signed on ESP32")
	b.updateCachedCounter(signRes["counter"])

	flagsFloat, _ := signRes["flags"].(float64)
	counterFloat, _ := signRes["counter"].(float64)
	sigDERHex, _ := signRes["sig_der"].(string)
	sigDER, _ := hex.DecodeString(sigDERHex)

	var authData bytes.Buffer
	authData.Write(rpHash[:])
	authData.WriteByte(byte(flagsFloat))
	var cntBuf [4]byte
	binary.BigEndian.PutUint32(cntBuf[:], uint32(counterFloat))
	authData.Write(cntBuf[:])

	assertionResp := map[string]any{
		"authenticatorData": B64UrlEncode(authData.Bytes()),
		"clientDataJSON":    B64UrlEncode(clientDataBytes),
		"signature":         B64UrlEncode(sigDER),
	}
	if selectedUserIDB64 != "" {
		assertionResp["userHandle"] = selectedUserIDB64
	}

	getExtResults := map[string]any{}
	if prfReq, ok := ext["prf"].(map[string]any); ok && prfReq != nil {
		evalByCred, _ := prfReq["evalByCredential"].(map[string]any)
		evalIn, _ := evalByCred[selectedCredIDB64].(map[string]any)
		if evalIn == nil {
			evalIn, _ = prfReq["eval"].(map[string]any)
		}
		if evalIn != nil {
			if firstStr, ok := evalIn["first"].(string); ok {
				if s1, err := B64UrlDecode(firstStr); err == nil {
					khBytes, _ := hex.DecodeString(selectedKHHex)
					resMap := map[string]any{
						"first": B64UrlEncode(ComputePRF(khBytes, s1)),
					}
					if secStr, ok := evalIn["second"].(string); ok {
						if s2, err := B64UrlDecode(secStr); err == nil {
							resMap["second"] = B64UrlEncode(ComputePRF(khBytes, s2))
						}
					}
					getExtResults["prf"] = map[string]any{"results": resMap}
				}
			}
		}
	}

	respPayload := map[string]any{
		"id":                      selectedCredIDB64,
		"rawId":                   selectedCredIDB64,
		"type":                    "public-key",
		"authenticatorAttachment": "cross-platform",
		"response":                assertionResp,
		"clientExtensionResults":  getExtResults,
	}
	respBytes, _ := json.Marshal(respPayload)
	return map[string]any{"responseJson": string(respBytes)}
}

func (b *ESP32Bridge) SyncResidentKeys() ([]CredentialRecord, error) {
	b.SetCeremony("waiting_touch", "sync", "ESP32 NVS", "", "Press BOOT on ESP32 to sync resident keys")
	res, err := b.ExecCmd("LIST_RK -", 16*time.Second, 2, nil)
	if err != nil {
		b.SetCeremony("error", "sync", "", "", err.Error())
		return nil, err
	}
	if res["ok"] != true {
		errCode, _ := res["err"].(string)
		b.SetCeremony("error", "sync", "", "", errCode)
		return nil, fmt.Errorf("sync failed: %s", errCode)
	}
	b.SetCeremony("approved", "sync", "", "", "Synced resident keys")
	if creds, ok := res["credentials"].([]any); ok {
		for _, item := range creds {
			c, _ := item.(map[string]any)
			khHex, _ := c["key_handle"].(string)
			khBytes, _ := hex.DecodeString(khHex)
			uidHex, _ := c["user_id"].(string)
			var uidB64 string
			if uidHex != "" {
				if uidBytes, err := hex.DecodeString(uidHex); err == nil && len(uidBytes) > 0 {
					uidB64 = B64UrlEncode(uidBytes)
				}
			}
			rpID, _ := c["rp_id"].(string)
			rpHash, _ := c["rp_id_hash"].(string)
			uName, _ := c["user_name"].(string)
			if uName == "" {
				uName = "user"
			}
			px, _ := c["pubkey_x"].(string)
			py, _ := c["pubkey_y"].(string)
			slotFloat, _ := c["slot"].(float64)

			b.Store.Upsert(CredentialRecord{
				CredID:          B64UrlEncode(khBytes),
				KeyHandle:       khHex,
				RPID:            rpID,
				RPIDHash:        rpHash,
				UserID:          uidB64,
				UserName:        uName,
				UserDisplayName: uName,
				PubKeyX:         px,
				PubKeyY:         py,
				RKSlot:          int(slotFloat),
				CreatedAt:       time.Now().Unix(),
			})
		}
	}
	return b.Store.ListAll(), nil
}
