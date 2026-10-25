package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"

	modernutls "github.com/metacubex/utls"
)

func TestMLKEMRealityClientHelloWireShares(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rc := &RealityConfig{SupportX25519MLKEM768: true}
	copy(rc.PublicKey[:], key.PublicKey().Bytes())
	for n := 0; n < 8; n++ {
		rc.ShortID[n] = byte(n + 1)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c, _, err := newMLKEMRealityConn(a, "chrome", &tls.Config{ServerName: "example.com"}, rc)
	if err != nil {
		t.Fatal(err)
	}
	raw := c.HandshakeState.Hello.Raw
	// Decode the encoded ClientHello, rather than just inspecting extension objects.
	pos := 4 + 2 + 32
	pos += 1 + int(raw[pos])
	pos += 2 + int(binary.BigEndian.Uint16(raw[pos:]))
	pos += 1 + int(raw[pos])
	extLen := int(binary.BigEndian.Uint16(raw[pos:]))
	pos += 2
	end := pos + extLen
	if end != len(raw) {
		t.Fatalf("invalid extensions length: %d != %d", end, len(raw))
	}
	found := false
	for pos < end {
		kind := binary.BigEndian.Uint16(raw[pos:])
		n := int(binary.BigEndian.Uint16(raw[pos+2:]))
		pos += 4
		if kind == 51 {
			data := raw[pos : pos+n]
			length := int(binary.BigEndian.Uint16(data))
			data = data[2:]
			if length != len(data) {
				t.Fatal("invalid key_share list length")
			}
			for len(data) > 0 {
				group := modernutls.CurveID(binary.BigEndian.Uint16(data))
				size := int(binary.BigEndian.Uint16(data[2:]))
				data = data[4:]
				if group == modernutls.X25519 && !found {
					t.Fatal("X25519 offered before hybrid key share")
				}
				if group == modernutls.X25519MLKEM768 {
					found = true
					if size != 1216 {
						t.Fatalf("hybrid share length %d", size)
					}
				}
				data = data[size:]
			}
		}
		pos += n
	}
	if !found {
		t.Fatal("encoded ClientHello has no X25519MLKEM768 share")
	}
}

func TestMLKEMRealityRejectsUnsupportedFingerprint(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	for _, fp := range []string{"none", "unknown", "ios"} {
		if _, _, err := newMLKEMRealityConn(a, fp, &tls.Config{ServerName: "example.com"}, &RealityConfig{}); err == nil {
			t.Fatalf("fingerprint %q unexpectedly accepted", fp)
		}
	}
}

func TestMLKEMVerifierRequiresAuthentication(t *testing.T) {
	v := &mlkemRealityVerifier{serverName: "example.com"}
	if err := v.verify(modernutls.ConnectionState{}); err == nil || v.verified {
		t.Fatal("empty certificate chain accepted")
	}
}
