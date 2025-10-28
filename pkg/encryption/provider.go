package encryption

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/octohelm/jwx/internal/pkg/keygen"
	"github.com/octohelm/jwx/pkg/encryption/internal"
	encryptionhttp "github.com/octohelm/jwx/pkg/encryption/internal/http"
	pkgjwk "github.com/octohelm/jwx/pkg/jwk"
	"github.com/octohelm/x/datauri"
	"github.com/octohelm/x/sync/singleflight"
)

type (
	EncryptProvider = internal.EncryptProvider
	DecryptProvider = internal.DecryptProvider
)

type (
	MiddlewareProvider = encryptionhttp.MiddlewareProvider
	TransportProvider  = encryptionhttp.TransportProvider
)

// +gengo:injectable
type Encrypter struct {
	// 加密传输用私钥
	PrivateKey datauri.DataURI `flag:",omitzero,secret"`

	privateKey jwk.Key
	publicKey  jwk.Key

	keySetProvider pkgjwk.KeySetProvider `inject:",opt"`
}

func (enc *Encrypter) Encrypt(ctx context.Context, payload []byte) ([]byte, error) {
	pub := &rsa.PublicKey{}
	if err := enc.publicKey.Raw(pub); err != nil {
		return nil, err
	}
	data, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, payload, nil)
	if err != nil {
		return nil, err
	}
	return internal.Base64RawURLEncode(data), nil
}

func (enc *Encrypter) Decrypt(ctx context.Context, base64URLEncoded []byte) ([]byte, error) {
	ciphertext, err := internal.Base64RawURLDecode(base64URLEncoded)
	if err != nil {
		return nil, err
	}
	pk := &rsa.PrivateKey{}
	if err := enc.privateKey.Raw(pk); err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, pk, ciphertext, nil)
}

func (enc *Encrypter) SetDefaults() {
	if enc.PrivateKey.IsZero() {
		enc.PrivateKey.Data, _ = keygen.NewRSAPrimaryKeyREM()
	}
}

func (enc *Encrypter) InjectContext(ctx context.Context) context.Context {
	return internal.ProviderInjectContext(ctx, enc)
}

func (enc *Encrypter) afterInit(ctx context.Context) error {
	if enc.privateKey != nil {
		return nil
	}

	if enc.PrivateKey.IsZero() {
		return errors.New("no rsa private key provided")
	}

	rsaPrivateKey, err := keygen.FromRawREM(enc.PrivateKey.Data, map[string]any{
		jwk.AlgorithmKey: jwa.RSA_OAEP,
		jwk.KeyUsageKey:  jwk.ForEncryption,
	})
	if err != nil {
		return err
	}

	enc.privateKey = rsaPrivateKey

	publicKey, err := enc.privateKey.PublicKey()
	if err != nil {
		return err
	}
	enc.publicKey = publicKey

	if enc.keySetProvider != nil {
		if err = enc.keySetProvider.AddKey(rsaPrivateKey); err != nil {
			return err
		}
	}

	return err
}

func PublicEncryptProviderFunc(get PublicKeyGetter) EncryptProvider {
	return &publicKeyEncryptProvider{get: get}
}

type publicKeyEncryptProvider struct {
	get   PublicKeyGetter
	cache singleflight.GroupValue[string, *publicKeyWithExpirationTimestamp]
}

type PublicKeyGetter = func() (*rsa.PublicKey, error)

type publicKeyWithExpirationTimestamp struct {
	*rsa.PublicKey
	ExpiredAt time.Time
}

func (enc *publicKeyEncryptProvider) Encrypt(ctx context.Context, payload []byte) ([]byte, error) {
	pubKey, err, _ := enc.cache.Do("enc", func() (*publicKeyWithExpirationTimestamp, error) {
		x, err := enc.get()
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}
		return &publicKeyWithExpirationTimestamp{PublicKey: x, ExpiredAt: time.Now().Add(1 * time.Minute)}, nil
	})
	if err != nil {
		// no-cache when request failed
		enc.cache.Forget("enc")
		return nil, err
	}

	if pubKey.ExpiredAt.Before(time.Now()) {
		enc.cache.Forget("enc")
		// retry
		return enc.Encrypt(ctx, payload)
	}

	data, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey.PublicKey, payload, nil)
	if err != nil {
		return nil, err
	}
	return internal.Base64RawURLEncode(data), nil
}
