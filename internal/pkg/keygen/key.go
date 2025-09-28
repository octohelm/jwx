package keygen

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/crypto/pbkdf2"
)

func FromRawREM(pemFormatedPk []byte, headers map[string]any) (jwk.Key, error) {
	v, _, err := jwk.DecodePEM(pemFormatedPk)
	if err != nil {
		return nil, err
	}
	headers[jwk.KeyIDKey] = genKeyID(pemFormatedPk)
	return FromRaw(v, headers)
}

func FromRaw(v any, headers map[string]any) (jwk.Key, error) {
	key, err := jwk.FromRaw(v)
	if err != nil {
		return nil, err
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
