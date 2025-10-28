package sign

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/octohelm/jwx/internal/pkg/keygen"
	"github.com/octohelm/objectkind/pkg/idgen"
	"github.com/octohelm/x/datauri"

	pkgjwk "github.com/octohelm/jwx/pkg/jwk"
)

type Option = func(b *jwt.Builder)

func WithSubject(sub string) Option {
	return func(b *jwt.Builder) {
		b.Subject(sub)
	}
}

func WithClaim[T comparable](k string, v T) Option {
	return func(b *jwt.Builder) {
		b.Claim(k, v)
	}
}

func WithExpiresIn(d time.Duration) Option {
	return func(b *jwt.Builder) {
		b.Expiration(time.Now().Add(d))
	}
}

func WithAudience(auds ...string) Option {
	return func(b *jwt.Builder) {
		b.Audience(auds)
	}
}

// +gengo:injectable:provider
type Signer interface {
	Validator

	Sign(ctx context.Context, opts ...Option) (string, uint64, error)
}

type Token = jwt.Token

// +gengo:injectable:provider Signer
type JWTSigner struct {
	// jwt token 签发方
	Issuer string `flag:",omitzero"`
	// jwt 签发私钥
	PrivateKey datauri.DataURI `flag:",omitzero,secret"`

	privateKey jwk.Key
	idgen      idgen.Typed[uint64]

	keySetProvider pkgjwk.KeySetProvider `inject:",opt"`
}

func (s *JWTSigner) SetDefaults() {
	if s.Issuer == "" {
		s.Issuer = "octohelm"
	}

	if s.PrivateKey.IsZero() {
		s.PrivateKey.Data, _ = keygen.NewRSAPrimaryKeyREM()
	}
}

func (s *JWTSigner) beforeInit(ctx context.Context) error {
	if s.privateKey != nil {
		return nil
	}

	if s.PrivateKey.IsZero() {
		return errors.New("no rsa private key provided")
	}

	rsaPrivateKey, err := keygen.FromRawREM(s.PrivateKey.Data, map[string]any{
		jwk.AlgorithmKey: jwa.RS256,
		jwk.KeyUsageKey:  jwk.ForSignature,
	})
	if err != nil {
		return err
	}

	s.privateKey = rsaPrivateKey

	if s.keySetProvider != nil {
		if err = s.keySetProvider.AddKey(rsaPrivateKey); err != nil {
			return err
		}
	}

	return err
}

func (s *JWTSigner) Sign(ctx context.Context, opts ...Option) (string, uint64, error) {
	var id uint64

	if err := s.idgen.NewTo(&id); err != nil {
		return "", 0, err
	}

	now := time.Now()

	b := jwt.NewBuilder().
		JwtID(strconv.FormatUint(id, 10)).
		Issuer(s.Issuer).
		IssuedAt(now)

	for _, o := range opts {
		o(b)
	}

	t, err := b.Build()
	if err != nil {
		return "", 0, err
	}

	signed, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, s.privateKey))
	if err != nil {
		return "", 0, err
	}

	return string(signed), id, nil
}

func (s *JWTSigner) Validate(ctx context.Context, tokStr string, validates ...ValidateOption) (Token, error) {
	keySet, err := s.keySetProvider.PublicSet()
	if err != nil {
		return nil, err
	}

	return doValidate(keySet, tokStr, slices.Concat([]ValidateOption{
		func(tok Token) error {
			if tok.Issuer() != s.Issuer {
				return errors.New("非法签发方")
			}
			return nil
		},
	}, validates)...)
}
