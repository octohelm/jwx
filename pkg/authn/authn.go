package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/octohelm/courier/pkg/courierhttp/client"
	openidv1 "github.com/octohelm/jwx/pkg/apis/openid/v1"
	"github.com/octohelm/x/ptr"
	"github.com/octohelm/x/sync/singleflight"
)

type Authn struct {
	openidv1.ClientAuth

	CheckEndpoint       string
	ExchangeTokenByPost bool

	HttpTransports []client.HttpTransport

	cache     singleflight.GroupValue[string, *openidv1.Token]
	expiredAt atomic.Pointer[time.Time]
}

func (a *Authn) createExchangeTokenRequest(ctx context.Context, realm *url.URL) (*http.Request, error) {
	if a.ExchangeTokenByPost {
		q := realm.Query()
		q.Add("client_id", a.ClientID)
		q.Add("client_secret", a.ClientSecret)

		encoded := q.Encode()
		realm.RawQuery = ""

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, realm.String(), bytes.NewBufferString(encoded))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

		req.URL.RawQuery = ""

		return req, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(a.ClientID, a.ClientSecret)
	return req, nil
}

func (a *Authn) exchangeToken(ctx context.Context, realm *url.URL) (*openidv1.Token, error) {
	c := client.GetShortConnClientContext(ctx, a.HttpTransports...)

	req, err := a.createExchangeTokenRequest(ctx, realm)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		tok := &openidv1.Token{}
		if err := json.Unmarshal(data, tok); err != nil {
			return nil, err
		}
		return tok, nil
	}

	return nil, &openidv1.ErrInvalidToken{
		Reason: errors.New(string(data)),
	}
}

const getToken = "get-token"

func (a *Authn) getToken(ctx context.Context) (*openidv1.Token, error) {
	if expiredAt := a.expiredAt.Load(); expiredAt != nil {
		if !expiredAt.After(time.Now()) {
			a.cache.Forget(getToken)
		}
	}

	tok, err, loaded := a.cache.Do(getToken, func() (*openidv1.Token, error) {
		c := client.GetReasonableClientContext(ctx, a.HttpTransports...)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.CheckEndpoint, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read: %w", err)
		}

		if resp.StatusCode == http.StatusUnauthorized {
			fmt.Println(resp.Header)

			if wwwAuthenticate := resp.Header.Get("WWW-Authenticate"); wwwAuthenticate != "" {
				fmt.Println(wwwAuthenticate)

				parsed, err := openidv1.ParseWwwAuthenticate(wwwAuthenticate)
				if err == nil && parsed.Params != nil {
					realm, ok := parsed.Params["realm"]
					if ok && realm != "" {
						realmUrl, err := url.Parse(realm)
						if err == nil {
							q := &url.Values{}
							for k, v := range parsed.Params {
								if k != "realm" {
									q.Set(k, v)
								}
							}
							realmUrl.RawQuery = q.Encode()

							return a.exchangeToken(ctx, realmUrl)
						}
					}
				}
			}

			return nil, &openidv1.ErrInvalidToken{
				Reason: errors.New(string(data)),
			}
		}

		return nil, &openidv1.ErrInvalidToken{
			Reason: fmt.Errorf("missing WWW-Authenticate: %d: %s", resp.StatusCode, string(data)),
		}
	})

	if err != nil {
		a.cache.Forget(getToken)
		return nil, err
	}

	if !loaded {
		a.expiredAt.Store(ptr.Ptr(time.Now().Add(time.Duration(tok.ExpiresIn-60) * time.Second)))
	}

	return tok, nil
}

func (a *Authn) AsHttpTransport() client.HttpTransport {
	return client.HttpTransportFunc(func(req *http.Request, next client.RoundTrip) (*http.Response, error) {
		tok, err := a.getToken(req.Context())
		if err != nil {
			return nil, err
		}

		if tok != nil {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tok.AccessToken))
		}

		return next(req)
	})
}
