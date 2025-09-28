package http

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/octohelm/courier/pkg/courierhttp/client"
	"github.com/octohelm/jwx/pkg/encryption/internal"
	"github.com/octohelm/jwx/pkg/encryption/internal/cipher"
)

type TransportProvider struct {
	Disabled        bool
	EncryptProvider internal.EncryptProvider
}

func (p *TransportProvider) newProtected(ctx context.Context) (*internal.Protected, []byte, error) {
	protected := &internal.Protected{
		Enc: "AES-256-CFB", // TODO migrate to CHACHA20
	}
	if err := protected.Init(); err != nil {
		return nil, nil, err
	}
	data, err := json.Marshal(protected)
	if err != nil {
		return nil, nil, err
	}
	protectedData, err := p.EncryptProvider.Encrypt(ctx, data)
	if err != nil {
		return nil, nil, err
	}
	return protected, protectedData, nil
}

func (p *TransportProvider) AsHttpTransport() client.HttpTransport {
	if p.Disabled {
		return func(rt http.RoundTripper) http.RoundTripper {
			return rt
		}
	}

	return client.HttpTransportFunc(func(req *http.Request, next client.RoundTrip) (*http.Response, error) {
		protected, prot, err := p.newProtected(req.Context())
		if err != nil {
			return nil, err
		}

		req.Header.Set("Accept", mime.FormatMediaType("*/*+encrypted", map[string]string{
			"protected": string(prot),
		}))

		if req.Body != nil {
			if contentType := req.Header.Get("Content-Type"); contentType != "" {
				mt, params, err := mime.ParseMediaType(contentType)
				if err != nil {
					return nil, err
				}

				params["protected"] = string(prot)

				c, err := protected.NewCipher()
				if err != nil {
					return nil, err
				}

				req.Header.Set("Content-Type", mime.FormatMediaType(fmt.Sprintf("%s+encrypted", mt), params))
				req.Body = cipher.TransformReadCloser(req.Body, c.EncryptWriter)
			}
		}

		resp, err := next(req)
		if err != nil {
			return nil, err
		}

		if contentType := resp.Header.Get("Content-Type"); contentType != "" {
			mt, params, err := mime.ParseMediaType(contentType)
			if err == nil {
				if strings.HasSuffix(mt, "+encrypted") {
					delete(params, "protected")

					resp.Header.Set("Content-Type", mime.FormatMediaType(mt[0:len(mt)-len("+encrypted")], params))

					c, err := protected.NewCipher()
					if err != nil {
						return nil, err
					}

					resp.Body = cipher.TransformReadCloser(resp.Body, c.DecryptWriter)
				}
			}
		}

		return resp, nil
	})
}
