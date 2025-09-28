package internal

import (
	"fmt"

	"github.com/octohelm/jwx/pkg/encryption/internal/cipher"
)

type Cipher = cipher.Cipher

func NewProtected() (*Protected, error) {
	p := &Protected{
		Enc: "AES-256-CFB",
	}

	if err := p.Init(); err != nil {
		return nil, err
	}

	return p, nil
}

type Protected struct {
	Enc   string `json:"enc"`
	Key   string `json:"key"`
	Nonce string `json:"nonce"`
}

func (p *Protected) Init() error {
	if p.Enc == "" {
		p.Enc = "CHACHA20"
	}

	if p.Key == "" || p.Nonce == "" {
		key, nonce, err := cipher.NewKeyNonce(p.Enc)
		if err != nil {
			return err
		}

		p.Key = string(Base64RawURLEncode(key))
		p.Nonce = string(Base64RawURLEncode(nonce))
	}

	return nil
}

func (p *Protected) NewCipher() (Cipher, error) {
	key, err := Base64RawURLDecode([]byte(p.Key))
	if err != nil {
		return nil, fmt.Errorf("invalid key %s", p.Key)
	}

	nonce, err := Base64RawURLDecode([]byte(p.Nonce))
	if err != nil {
		return nil, fmt.Errorf("invalid nonce %s", p.Nonce)
	}

	c, err := cipher.FromKeyNonce(p.Enc, key, nonce)
	if err != nil {
		return nil, err
	}

	return c, nil
}
