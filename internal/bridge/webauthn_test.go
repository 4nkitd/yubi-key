package bridge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestB64UrlRoundtrip(t *testing.T) {
	raw := make([]byte, 48)
	_, _ = rand.Read(raw)
	enc := B64UrlEncode(raw)
	if bytes.ContainsAny([]byte(enc), "=+/") {
		t.Fatalf("unexpected characters in base64url: %s", enc)
	}
	dec, err := B64UrlDecode(enc)
	if err != nil || !bytes.Equal(dec, raw) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestSPKIDERLoads(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubX := priv.PublicKey.X.FillBytes(make([]byte, 32))
	pubY := priv.PublicKey.Y.FillBytes(make([]byte, 32))

	var spki bytes.Buffer
	spki.Write(P256SPKIPrefix)
	spki.Write(pubX)
	spki.Write(pubY)

	if spki.Len() != 91 {
		t.Fatalf("expected 91 bytes SPKI DER, got %d", spki.Len())
	}
	parsed, err := x509.ParsePKIXPublicKey(spki.Bytes())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey failed: %v", err)
	}
	ecPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ecPub.X.Cmp(priv.PublicKey.X) != 0 || ecPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatalf("parsed public key mismatch")
	}
}

func TestCOSEAndAttestationObject(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubX := priv.PublicKey.X.FillBytes(make([]byte, 32))
	pubY := priv.PublicKey.Y.FillBytes(make([]byte, 32))
	cose := BuildCOSEP256Key(pubX, pubY)
	if len(cose) != 77 {
		t.Fatalf("expected 77 bytes COSE key, got %d", len(cose))
	}

	rpHash := sha256.Sum256([]byte("localhost"))
	kh := make([]byte, 48)
	_, _ = rand.Read(kh)

	var authData bytes.Buffer
	authData.Write(rpHash[:])
	authData.WriteByte(0x45)
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], 1)
	authData.Write(cnt[:])
	authData.Write(YubiKey5AAGUID)
	var khLen [2]byte
	binary.BigEndian.PutUint16(khLen[:], 48)
	authData.Write(khLen[:])
	authData.Write(kh)
	authData.Write(cose)

	if authData.Len() != 180 {
		t.Fatalf("expected 180 bytes authData, got %d", authData.Len())
	}

	attNone := BuildAttestationObject(authData.Bytes(), "none", nil, nil)
	expectedPrefix, _ := hex.DecodeString("a363666d74646e6f6e656761747453746d74a068617574684461746158b4")
	if !bytes.HasPrefix(attNone, expectedPrefix) {
		t.Fatalf("unexpected CBOR none attestation prefix: %x", attNone[:32])
	}

	cdHash := sha256.Sum256([]byte("client-data"))
	sigDER, certDER, err := BuildFIDO2Attestation(authData.Bytes(), cdHash[:], YubiKey5AAGUID, kh)
	if err != nil {
		t.Fatalf("BuildFIDO2Attestation failed: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != "Authenticator Attestation" {
		t.Fatalf("missing OU=Authenticator Attestation")
	}
	attPacked := BuildAttestationObject(authData.Bytes(), "packed", sigDER, certDER)
	packedPrefix, _ := hex.DecodeString("a363666d74667061636b65646761747453746d74a363616c672663736967")
	if !bytes.HasPrefix(attPacked, packedPrefix) {
		t.Fatalf("unexpected CBOR packed attestation prefix: %x", attPacked[:32])
	}

	cdJSON := BuildClientDataJSON("webauthn.create", "dGVzdA", "http://localhost:17380", false)
	var parsedCD map[string]any
	if err := json.Unmarshal(cdJSON, &parsedCD); err != nil {
		t.Fatal(err)
	}
	if parsedCD["type"] != "webauthn.create" || parsedCD["origin"] != "http://localhost:17380" {
		t.Fatalf("unexpected clientDataJSON: %s", string(cdJSON))
	}
}
