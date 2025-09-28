package sign

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/octohelm/courier/pkg/courierhttp"
	"github.com/octohelm/courier/pkg/courierhttp/client"
	"github.com/octohelm/jwx/internal/pkg/clientutil"
	openidv1 "github.com/octohelm/jwx/pkg/apis/openid/v1"
	sqltypetime "github.com/octohelm/storage/pkg/sqltype/time"
	"github.com/octohelm/x/ptr"
	"github.com/octohelm/x/sync/singleflight"
)

type ValidateOption func(t Token) error

func WithClaimExpect[T comparable](key string, expects ...T) ValidateOption {
	return func(t Token) error {
		if v, ok := t.Get(key); ok {
			for _, expect := range expects {
				switch vv := v.(type) {
				case T:
					if vv == expect {
						return nil
					}
				case string:
					if str, ok := any(expect).(encoding.TextMarshaler); ok {
						v, err := str.MarshalText()
						if err == nil {
							if vv == string(v) {
								return nil
							}
						}
					}
				}
			}
			return fmt.Errorf("invalid claim %s: %v", key, v)
		}
		return fmt.Errorf("invalid claim %s", key)
	}
}

// +gengo:injectable:provider
type Validator interface {
	Validate(ctx context.Context, t string, validates ...ValidateOption) (Token, error)
}

// +gengo:injectable:provider
type JWTValidator struct {
	JwksEndpoint string `flag:",omitzero"`
	// 过期时间
	TTL sqltypetime.Duration `flag:",omitzero"`

	Validator `provide:"" flag:"-"`
}

func (x *JWTValidator) SetDefaults() {
	if x.TTL == 0 {
		x.TTL = 10 * sqltypetime.Duration(time.Minute)
	}
}

func (x *JWTValidator) Disabled(ctx context.Context) bool {
	return x.JwksEndpoint == ""
}

func (x *JWTValidator) afterInit(ctx context.Context) error {
	x.Validator = &jwtValidator{
		JwksEndpoint: x.JwksEndpoint,
		TTL:          time.Duration(x.TTL),
	}
	return nil
}

type jwtValidator struct {
	JwksEndpoint string
	TTL          time.Duration

	cache     singleflight.GroupValue[string, jwk.Set]
	expiredAt atomic.Pointer[time.Time]
}

const getKeySet = "get-key-set"

func (s *jwtValidator) getCachedKeySet(ctx context.Context) (jwk.Set, error) {
	if expiredAt := s.expiredAt.Load(); expiredAt != nil {
		if !expiredAt.After(time.Now()) {
			s.cache.Forget(getKeySet)
		}
	}

	keySet, err, hit := s.cache.Do(getKeySet, func() (jwk.Set, error) {
		return s.getKeySet(ctx)
	})
	if err != nil {
		s.cache.Forget(getKeySet)
		return nil, err
	}
	if !hit {
		s.expiredAt.Store(ptr.Ptr(time.Now().Add(s.TTL)))
	}
	return keySet, nil
}

func (s *jwtValidator) getKeySet(ctx context.Context) (jwk.Set, error) {
	c := &client.Client{
		Endpoint: s.JwksEndpoint,
	}

	jwks, err := clientutil.DoWith(ctx, c, func(req *struct {
		courierhttp.MethodGet
		clientutil.Resp[openidv1.Jwks]
	}) {
	})
	if err != nil {
		return nil, err
	}

	jwkSet := jwk.NewSet()

	for _, key := range jwks.Keys {
		if key.Use == "sig" {
			bytes, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}
			key, err := jwk.ParseKey(bytes)
			if err != nil {
				return nil, err
			}

			if err := jwkSet.AddKey(key); err != nil {
				return nil, err
			}
		}
	}

	return jwkSet, nil
}

func (s *jwtValidator) Validate(ctx context.Context, tokStr string, validates ...ValidateOption) (Token, error) {
	keySet, err := s.getCachedKeySet(ctx)
	if err != nil {
		return nil, err
	}
	return doValidate(keySet, tokStr, validates...)
}

func doValidate(keySet jwk.Set, tokStr string, validates ...ValidateOption) (Token, error) {
	tok, err := jwt.ParseString(tokStr, jwt.WithKeySet(keySet))
	if err != nil {
		return nil, &openidv1.ErrInvalidToken{
			Reason: err,
		}
	}

	if time.Until(tok.Expiration()) < 0 {
		return nil, &openidv1.ErrInvalidToken{
			Reason: errors.New("token expired"),
		}
	}

	for _, v := range validates {
		if err := v(tok); err != nil {
			return nil, &openidv1.ErrInvalidToken{
				Reason: err,
			}
		}
	}

	return tok, nil
}
