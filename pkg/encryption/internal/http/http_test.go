package http_test

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/innoai-tech/infra/pkg/configuration/testingutil"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/octohelm/courier/pkg/courierhttp/client"
	"github.com/octohelm/jwx/pkg/encryption"
	pkgjwk "github.com/octohelm/jwx/pkg/jwk"
	testingx "github.com/octohelm/x/testing"
)

func TestHttp(t *testing.T) {
	c := &struct {
		pkgjwk.KeySet

		encryption.Encrypter
		encryption.MiddlewareProvider
		encryption.TransportProvider
	}{}

	ctx := testingutil.NewContext(t, c)

	c.EncryptProvider = encryption.PublicEncryptProviderFunc(func() (*rsa.PublicKey, error) {
		ks, err := c.TypedPublicSet()
		if err != nil {
			return nil, err
		}

		for _, k := range ks.Keys {
			if k.Use == "enc" {
				raw, err := json.Marshal(k)
				if err != nil {
					return nil, err
				}
				key, err := jwk.ParseKey(raw)
				if err != nil {
					return nil, err
				}

				pubKey := &rsa.PublicKey{}
				if err := key.Raw(pubKey); err != nil {
					return nil, err
				}
				return pubKey, nil
			}
		}

		return nil, errors.New("not found pub key for enc")
	})

	t.Run("request", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			requestBodyData, _ := io.ReadAll(r.Body)

			if len(requestBodyData) > 0 {
				w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
				w.WriteHeader(200)
				_, _ = w.Write(requestBodyData)
				return
			}

			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("hello"))
		})

		s := httptest.NewServer(c.MiddlewareProvider.Wrap(h))

		t.Cleanup(func() {
			s.Close()
		})

		t.Run("should fetch normal content", func(t *testing.T) {
			resp, err := http.Get(s.URL)
			testingx.Expect(t, err, testingx.BeNil[error]())
			defer resp.Body.Close()

			data, err := io.ReadAll(resp.Body)
			testingx.Expect(t, err, testingx.BeNil[error]())
			testingx.Expect(t, string(data), testingx.Be("hello"))
		})

		t.Run("should fetch encrypted content when content type set", func(t *testing.T) {
			t.Run("without request body", func(t *testing.T) {
				c := client.GetShortConnClientContext(ctx, c.TransportProvider.AsHttpTransport())

				r, _ := http.NewRequest(http.MethodGet, s.URL, nil)

				resp, err := c.Do(r)
				testingx.Expect(t, err, testingx.BeNil[error]())
				defer resp.Body.Close()

				data, err := io.ReadAll(resp.Body)
				testingx.Expect(t, err, testingx.BeNil[error]())

				testingx.Expect(t, resp.Header.Get("Content-Type"), testingx.Be("text/plain"))
				testingx.Expect(t, string(data), testingx.Be("hello"))
			})

			t.Run("with request body", func(t *testing.T) {
				c := client.GetShortConnClientContext(ctx, c.TransportProvider.AsHttpTransport())

				r, _ := http.NewRequest(http.MethodGet, s.URL, bytes.NewBufferString("world"))
				r.Header.Set("Content-Type", "text/plain")

				resp, err := c.Do(r)
				testingx.Expect(t, err, testingx.BeNil[error]())
				defer resp.Body.Close()

				data, err := io.ReadAll(resp.Body)
				testingx.Expect(t, err, testingx.BeNil[error]())

				testingx.Expect(t, resp.Header.Get("Content-Type"), testingx.Be("text/plain"))
				testingx.Expect(t, string(data), testingx.Be("world"))
			})
		})
	})
}
