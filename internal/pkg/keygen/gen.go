package keygen

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
)

func NewRSAPrimaryKeyREM() ([]byte, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return jwkbb.EncodePEM(pk)
}
