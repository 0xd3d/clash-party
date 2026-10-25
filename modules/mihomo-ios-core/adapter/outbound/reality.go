package outbound

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	tlsC "github.com/Dreamacro/clash/component/tls"

	"golang.org/x/crypto/curve25519"
)

type RealityOptions struct {
	PublicKey             string `proxy:"public-key"`
	ShortID               string `proxy:"short-id"`
	SupportX25519MLKEM768 bool   `proxy:"support-x25519mlkem768,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.SupportX25519MLKEM768 = o.SupportX25519MLKEM768

		n, err := base64.RawURLEncoding.Decode(config.PublicKey[:], []byte(o.PublicKey))
		if err != nil || n != curve25519.ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}

		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		return config, nil
	}
	return nil, nil
}
