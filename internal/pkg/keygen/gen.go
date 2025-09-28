package keygen

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func NewRSAPrimaryKeyREM() ([]byte, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return jwk.EncodePEM(pk)
}
