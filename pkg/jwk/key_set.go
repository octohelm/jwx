//go:generate go tool devtool gen .
package jwk

import (
	"context"
	"sync"

	"github.com/go-json-experiment/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	openidv1 "github.com/octohelm/jwx/pkg/apis/openid/v1"
)

// +gengo:injectable:provider
type KeySetProvider interface {
	AddKey(key jwk.Key) error

	PublicSet() (jwk.Set, error)
	TypedPublicSet() (*openidv1.Jwks, error)
}

// +gengo:injectable:provider KeySetProvider
type KeySet struct {
	jwks jwk.Set

	cache sync.Map
}

func (s *KeySet) PublicSet() (jwk.Set, error) {
	return jwk.PublicSetOf(s.jwks)
}

func (s *KeySet) beforeInit(ctx context.Context) error {
	s.jwks = jwk.NewSet()
	return nil
}

func (s *KeySet) TypedPublicSet() (*openidv1.Jwks, error) {
	get, _ := s.cache.LoadOrStore("typed-public-set", sync.OnceValues(func() (*openidv1.Jwks, error) {
		originKeySets, err := s.PublicSet()
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(originKeySets)
		if err != nil {
			return nil, err
		}
		jwks := &openidv1.Jwks{}
		if err := json.Unmarshal(raw, jwks); err != nil {
			return nil, err
		}
		return jwks, nil
	}))

	return get.(func() (*openidv1.Jwks, error))()
}

func (s *KeySet) AddKey(key jwk.Key) error {
	if s.jwks != nil {
		return s.jwks.AddKey(key)
	}
	return nil
}
