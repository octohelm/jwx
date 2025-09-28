package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

func init() {
	Register(&aesCTRCipherFactory{})
}

type aesCTRCipherFactory struct{}

func (aesCTRCipherFactory) Type() string {
	return "AES-256-CTR"
}

func (aesCTRCipherFactory) NewKeyNonce() ([]byte, []byte, error) {
	return GenKeyAndNonce(32, 16)
}

func (aesCTRCipherFactory) FromKeyNonce(key []byte, nonce []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Join(ErrInvalidAESKey, err)
	}
	return &aesCtrCipher{block: block, iv: nonce}, nil
}

type aesCtrCipher struct {
	block cipher.Block
	iv    []byte
}

func (e *aesCtrCipher) EncryptWriter(w io.Writer) (io.Writer, error) {
	stream := cipher.NewCTR(e.block, e.iv)

	return WriteFunc(func(p []byte) (int, error) {
		if n := len(p); n > 0 {
			d := make([]byte, n)
			stream.XORKeyStream(d, p)
			return w.Write(d)
		}
		return 0, io.EOF
	}), nil
}

func (e *aesCtrCipher) DecryptWriter(w io.Writer) (io.Writer, error) {
	stream := cipher.NewCTR(e.block, e.iv)

	return WriteFunc(func(p []byte) (int, error) {
		if n := len(p); n > 0 {
			d := make([]byte, n)
			stream.XORKeyStream(d, p)
			return w.Write(d)
		}
		return 0, io.EOF
	}), nil
}
