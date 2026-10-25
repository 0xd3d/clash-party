package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	modernutls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

// This opt-in path follows the ML-KEM handshake used by Mihomo v1.19.31.
// The legacy TLS path remains available for profiles without the option.
func newMLKEMRealityConn(conn net.Conn, fingerprint string, config *tls.Config, reality *RealityConfig) (*modernutls.UConn, *mlkemRealityVerifier, error) {
	fingerprints := map[string]modernutls.ClientHelloID{
		"chrome":  modernutls.HelloChrome_Auto,
		"firefox": modernutls.HelloFirefox_Auto,
		"safari":  modernutls.HelloSafari_Auto,
		"ios":     modernutls.HelloIOS_Auto,
		"edge":    modernutls.HelloEdge_Auto,
	}
	helloID, ok := fingerprints[fingerprint]
	if !ok {
		return nil, nil, fmt.Errorf("REALITY ML-KEM: unsupported fingerprint %q; use chrome", fingerprint)
	}
	verifier := &mlkemRealityVerifier{serverName: config.ServerName}
	c := modernutls.UClient(conn, &modernutls.Config{
		ServerName: config.ServerName,
		// REALITY authenticates its temporary certificate in VerifyConnection.
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyConnection:       verifier.verify,
	}, helloID)
	if err := c.BuildHandshakeState(); err != nil {
		return nil, nil, err
	}
	hello := c.HandshakeState.Hello
	if len(hello.SessionId) != 32 || len(hello.Raw) < 71 {
		return nil, nil, errors.New("REALITY ML-KEM: invalid ClientHello session ID")
	}
	// The server requires a hybrid share before any plain X25519 share.
	hasHybrid := false
	for _, share := range hello.KeyShares {
		if share.Group == modernutls.X25519MLKEM768 {
			hasHybrid = len(share.Data) == 1216
			break
		}
		if share.Group == modernutls.X25519 {
			break
		}
	}
	if !hasHybrid {
		return nil, nil, fmt.Errorf("REALITY ML-KEM: fingerprint %q does not offer X25519MLKEM768 before X25519", fingerprint)
	}
	keys := c.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return nil, nil, errors.New("REALITY ML-KEM: missing key shares")
	}
	key := keys.Ecdhe
	if key == nil {
		key = keys.MlkemEcdhe
	}
	if key == nil {
		return nil, nil, errors.New("REALITY ML-KEM: missing X25519 private key")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(reality.PublicKey[:])
	if err != nil {
		return nil, nil, err
	}
	authKey, err := key.ECDH(publicKey)
	if err != nil {
		return nil, nil, err
	}
	if _, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, nil, err
	}
	verifier.authKey = authKey
	for i := 39; i < 71; i++ {
		hello.Raw[i] = 0
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(time.Now().Unix()))
	copy(hello.SessionId[8:], reality.ShortID[:])
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 1, 8, 2
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:71], hello.SessionId)
	return c, verifier, nil
}

func getMLKEMRealityConn(ctx context.Context, conn net.Conn, fingerprint string, config *tls.Config, reality *RealityConfig) (net.Conn, error) {
	c, verifier, err := newMLKEMRealityConn(conn, fingerprint, config, reality)
	if err != nil {
		return nil, err
	}
	if err = c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verifier.verified {
		return nil, errors.New("REALITY ML-KEM authentication failed")
	}
	return c, nil
}

type mlkemRealityVerifier struct {
	serverName string
	authKey    []byte
	verified   bool
}

func (v *mlkemRealityVerifier) verify(state modernutls.ConnectionState) error {
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return errors.New("REALITY ML-KEM: server sent no certificate")
	}
	if publicKey, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, v.authKey)
		h.Write(publicKey)
		if hmac.Equal(h.Sum(nil), certs[0].Signature) {
			v.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{DNSName: v.serverName, Intermediates: x509.NewCertPool()}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}
