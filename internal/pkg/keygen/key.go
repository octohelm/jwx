package keygen

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"golang.org/x/crypto/pbkdf2"
)

func FromRawREM(pemFormatedPk []byte, headers map[string]any) (jwk.Key, error) {
	v, err := jwk.ParseKey(pemFormatedPk, jwk.WithX509(true))
	if err != nil {
		return nil, err
	}
	headers[jwk.KeyIDKey] = genKeyID(pemFormatedPk)
	return FromRaw(v, headers)
}

func FromRaw(v any, headers map[string]any) (jwk.Key, error) {
	var key jwk.Key
	if k, ok := v.(jwk.Key); ok {
		key = k
	} else {
		var err error
		key, err = jwk.Import[jwk.Key](v)
		if err != nil {
			return nil, err
		}
	}
	for k := range headers {
		if err := key.Set(k, headers[k]); err != nil {
			return nil, err
		}
	}
	return key, nil
}

func genKeyID(raw []byte) string {
	return base64.RawStdEncoding.EncodeToString(
		pbkdf2.Key(raw, []byte("algo"), 7781, 8, sha256.New),
	)
}
