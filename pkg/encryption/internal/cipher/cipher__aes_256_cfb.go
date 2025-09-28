package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

func init() {
	Register(&aesCfbCipherFactory{})
}

type aesCfbCipherFactory struct{}

func (aesCfbCipherFactory) Type() string {
	return "AES-256-CFB"
}

func (a aesCfbCipherFactory) NewKeyNonce() ([]byte, []byte, error) {
	return GenKeyAndNonce(32, 16)
}

func (a aesCfbCipherFactory) FromKeyNonce(key []byte, nonce []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Join(ErrInvalidAESKey, err)
	}
	return &aesCfbCipher{block: block, iv: nonce}, nil
}

type aesCfbCipher struct {
	block cipher.Block
	iv    []byte
}

func (e *aesCfbCipher) EncryptWriter(w io.Writer) (io.Writer, error) {
	stream := cipher.NewCFBEncrypter(e.block, e.iv)

	return WriteFunc(func(p []byte) (int, error) {
		if n := len(p); n > 0 {
			d := make([]byte, n)
			stream.XORKeyStream(d, p)
			return w.Write(d)
		}
		return 0, io.EOF
	}), nil
}

func (e *aesCfbCipher) DecryptWriter(w io.Writer) (io.Writer, error) {
	stream := cipher.NewCFBDecrypter(e.block, e.iv)

	return WriteFunc(func(p []byte) (int, error) {
		if n := len(p); n > 0 {
			d := make([]byte, n)
			stream.XORKeyStream(d, p)
			return w.Write(d)
		}
		return 0, io.EOF
	}), nil
}
