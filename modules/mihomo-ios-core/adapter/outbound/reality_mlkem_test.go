package outbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestRealityOptionsMLKEMFlag(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		rc, err := (RealityOptions{PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: "0102030405060708", SupportX25519MLKEM768: enabled}).Parse()
		if err != nil {
			t.Fatal(err)
		}
		if rc.SupportX25519MLKEM768 != enabled {
			t.Fatal("ML-KEM option was lost during parse")
		}
	}
}
