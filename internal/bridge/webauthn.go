package bridge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	// ASN.1 DER SubjectPublicKeyInfo header for uncompressed NIST P-256 (secp256r1) point (26 bytes + 0x04)
	P256SPKIPrefix, _ = hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d03010703420004")

	// Official YubiKey 5 Series (YubiKey 5 NFC / 5C NFC) AAGUID in FIDO MDS:
	// 2fc0579f-8113-47ea-b116-bb5a8db9202a
	YubiKey5AAGUID, _ = hex.DecodeString("2fc0579f811347eab116bb5a8db9202a")

	// Canonical CBOR map {"hmac-secret": true}
	HmacSecretExtCBOR, _ = hex.DecodeString("a16b686d61632d736563726574f5")
)

func B64UrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func B64UrlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func CBOREncodeBytes(b []byte) []byte {
	n := len(b)
	var out bytes.Buffer
	if n < 24 {
		out.WriteByte(byte(0x40 | n))
	} else if n < 256 {
		out.WriteByte(0x58)
		out.WriteByte(byte(n))
	} else {
		out.WriteByte(0x59)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		out.Write(lenBuf[:])
	}
	out.Write(b)
	return out.Bytes()
}

func BuildCOSEP256Key(pubX, pubY []byte) []byte {
	prefix, _ := hex.DecodeString("a5010203262001215820")
	mid, _ := hex.DecodeString("225820")
	var out bytes.Buffer
	out.Write(prefix)
	out.Write(pubX)
	out.Write(mid)
	out.Write(pubY)
	return out.Bytes()
}

func BuildAttestationObject(authData []byte, fmtName string, sigDER, certDER []byte) []byte {
	var out bytes.Buffer
	if fmtName == "packed" && len(sigDER) > 0 && len(certDER) > 0 {
		out.WriteByte(0xa3)
		out.WriteString("\x63fmt\x66packed")
		out.WriteString("\x67attStmt\xa3\x63alg\x26\x63sig")
		out.Write(CBOREncodeBytes(sigDER))
		out.WriteString("\x63x5c\x81")
		out.Write(CBOREncodeBytes(certDER))
		out.WriteString("\x68authData")
		out.Write(CBOREncodeBytes(authData))
		return out.Bytes()
	}
	if fmtName == "packed" && len(sigDER) > 0 {
		out.WriteByte(0xa3)
		out.WriteString("\x63fmt\x66packed")
		out.WriteString("\x67attStmt\xa2\x63alg\x26\x63sig")
		out.Write(CBOREncodeBytes(sigDER))
		out.WriteString("\x68authData")
		out.Write(CBOREncodeBytes(authData))
		return out.Bytes()
	}
	out.WriteByte(0xa3)
	out.WriteString("\x63fmt\x64none")
	out.WriteString("\x67attStmt\xa0")
	out.WriteString("\x68authData")
	out.Write(CBOREncodeBytes(authData))
	return out.Bytes()
}

func BuildFIDO2Attestation(authData, clientDataHash, aaguid, seed []byte) (sigDER []byte, certDER []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	aaguidExtVal := append([]byte{0x04, 0x10}, aaguid...)
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(94827163),
		Subject: pkix.Name{
			Country:            []string{"SE"},
			Organization:       []string{"Yubico AB"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "Yubico U2F EE Serial 94827163",
		},
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4},
				Critical: false,
				Value:    aaguidExtVal,
			},
		},
	}

	certDER, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	var signedBuf bytes.Buffer
	signedBuf.Write(authData)
	signedBuf.Write(clientDataHash)
	digest := sha256.Sum256(signedBuf.Bytes())

	sigDER, err = ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, nil, err
	}
	return sigDER, certDER, nil
}

func BuildClientDataJSON(ceremonyType, challengeB64Url, origin string, crossOrigin bool) []byte {
	typeJSON, _ := json.Marshal(ceremonyType)
	chalJSON, _ := json.Marshal(challengeB64Url)
	origJSON, _ := json.Marshal(origin)
	crossStr := "false"
	if crossOrigin {
		crossStr = "true"
	}
	return []byte(fmt.Sprintf(`{"type":%s,"challenge":%s,"origin":%s,"crossOrigin":%s}`,
		string(typeJSON), string(chalJSON), string(origJSON), crossStr))
}

func loadOrCreatePRFSecret() []byte {
	secPath := filepath.Join(DefaultConfigDir(), "prf_secret.bin")
	if data, err := os.ReadFile(secPath); err == nil && len(data) == 32 {
		return data
	}
	_ = os.MkdirAll(DefaultConfigDir(), 0o755)
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	_ = os.WriteFile(secPath, sec, 0o600)
	return sec
}

func ComputePRF(keyHandle, salt []byte) []byte {
	mac := hmac.New(sha256.New, loadOrCreatePRFSecret())
	mac.Write(keyHandle)
	mac.Write([]byte("WebAuthn PRF\x00"))
	mac.Write(salt)
	return mac.Sum(nil)
}

func VerifyP256Signature(pubXHex, pubYHex, sigDERHex string, signedData []byte) error {
	xb, err := hex.DecodeString(pubXHex)
	if err != nil {
		return err
	}
	yb, err := hex.DecodeString(pubYHex)
	if err != nil {
		return err
	}
	sigDER, err := hex.DecodeString(sigDERHex)
	if err != nil {
		return err
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	digest := sha256.Sum256(signedData)
	if !ecdsa.VerifyASN1(pub, digest[:], sigDER) {
		return fmt.Errorf("ECDSA P-256 signature verification failed")
	}
	return nil
}
