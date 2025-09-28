package cipher

import (
	"errors"
	"io"

	"golang.org/x/crypto/chacha20"
)

func init() {
	Register(&chacha20CipherFactory{})
}

type chacha20CipherFactory struct{}

func (chacha20CipherFactory) Type() string {
	return "CHACHA20"
}

func (a chacha20CipherFactory) NewKeyNonce() ([]byte, []byte, error) {
	return GenKeyAndNonce(32, 12)
}

func (a chacha20CipherFactory) FromKeyNonce(key []byte, nonce []byte) (Cipher, error) {
	return &chacha20Cipher{key, nonce}, nil
}

type chacha20Cipher struct {
	key   []byte
	nonce []byte
}

func (e *chacha20Cipher) DecryptWriter(w io.Writer) (io.Writer, error) {
	stream, err := chacha20.NewUnauthenticatedCipher(e.key, e.nonce)
	if err != nil {
		return nil, errors.Join(ErrInvalidChacha20Key, err)
	}

	return WriteFunc(func(p []byte) (int, error) {
		if n := len(p); n > 0 {
			d := make([]byte, n)
			stream.XORKeyStream(d, p)
			return w.Write(d)
		}
		return 0, io.EOF
	}), nil
}

func (e *chacha20Cipher) EncryptWriter(w io.Writer) (io.Writer, error) {
	return e.DecryptWriter(w)
}
