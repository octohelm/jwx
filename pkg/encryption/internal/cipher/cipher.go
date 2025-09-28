package cipher

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
)

type Cipher interface {
	EncryptWriter(w io.Writer) (io.Writer, error)
	DecryptWriter(w io.Writer) (io.Writer, error)
}

type Factory interface {
	Type() string
	NewKeyNonce() ([]byte, []byte, error)
	FromKeyNonce([]byte, []byte) (Cipher, error)
}

var cipherFactories = map[string]Factory{}

func Register(f Factory) {
	cipherFactories[strings.ToUpper(f.Type())] = f
}

func NewKeyNonce(alg string) ([]byte, []byte, error) {
	if x, ok := cipherFactories[strings.ToUpper(alg)]; ok {
		return x.NewKeyNonce()
	}
	return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedEncryptionMethod, alg)
}

func FromKeyNonce(alg string, key []byte, nonce []byte) (Cipher, error) {
	if x, ok := cipherFactories[strings.ToUpper(alg)]; ok {
		return x.FromKeyNonce(key, nonce)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedEncryptionMethod, alg)
}

func GenKeyAndNonce(keyN int, nonceN int) ([]byte, []byte, error) {
	key, err := io.ReadAll(io.LimitReader(rand.Reader, int64(keyN)))
	if err != nil {
		return nil, nil, err
	}

	nonce, err := io.ReadAll(io.LimitReader(rand.Reader, int64(nonceN)))
	if err != nil {
		return nil, nil, err
	}

	return key, nonce, nil
}
