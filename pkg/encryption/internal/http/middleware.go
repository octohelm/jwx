package http

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/go-courier/logr"
	"github.com/go-json-experiment/json"
	"github.com/octohelm/courier/pkg/content"
	"github.com/octohelm/courier/pkg/statuserror"
	"github.com/octohelm/jwx/pkg/encryption/internal"
	"github.com/octohelm/jwx/pkg/encryption/internal/cipher"
)

// +gengo:injectable:
type MiddlewareProvider struct {
	Provider internal.Provider `inject:""`
}

func (m *MiddlewareProvider) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if contentType := req.Header.Get("Content-Type"); contentType != "" {
			requestBodyCipher, err := m.newCipher(req, contentType)
			if err != nil {
				m.writeError(req.Context(), rw, err)
				return
			}

			if requestBodyCipher != nil {
				req.Header.Set("Content-Type", WithoutEncrypted(contentType))

				req.Body = cipher.TransformReadCloser(req.Body, requestBodyCipher.DecryptWriter)
			}
		}

		acceptByEncrypted := findEncryptedAccept(strings.Split(req.Header.Get("Accept"), ","))

		responseBodyCipher, err := m.newCipher(req, acceptByEncrypted)
		if err != nil {
			m.writeError(req.Context(), rw, err)
			return
		}

		if responseBodyCipher != nil {
			wc, err := responseBodyCipher.EncryptWriter(rw)
			if err != nil {
				return
			}

			next.ServeHTTP(&encryptedResponseWriter{
				ResponseWriter: rw,
				encrypter:      wc,
				accept:         ContentType(acceptByEncrypted),
			}, req)

			return
		}

		next.ServeHTTP(rw, req)
	})
}

func (m *MiddlewareProvider) writeError(ctx context.Context, rw http.ResponseWriter, err error) {
	serr := statuserror.AsErrorResponse(err, "")

	t, err := content.New(reflect.TypeOf(serr), "", "marshal")
	if err != nil {
		logr.FromContext(ctx).Error(err)
		return
	}

	c, err := t.Prepare(ctx, serr)
	if err != nil {
		logr.FromContext(ctx).Error(err)
		return
	}

	defer c.Close()

	if ct := c.GetContentType(); ct != "" {
		rw.Header().Set("Content-Type", ct)
	}

	if i := c.GetContentLength(); i > -1 {
		rw.Header().Set("Content-Length", strconv.FormatInt(i, 10))
	}

	rw.WriteHeader(serr.StatusCode())

	_, err = io.Copy(rw, c)
	if err != nil {
		logr.FromContext(ctx).Error(err)
		return
	}
}

func findEncryptedAccept(list []string) string {
	for _, v := range list {
		if strings.Contains(v, "+encrypted;") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (m *MiddlewareProvider) newCipher(r *http.Request, contentType string) (internal.Cipher, error) {
	if contentType != "" {
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err == nil {
			// `{content-type}+encrypted;protected=xxx`
			if strings.HasSuffix(mediaType, "+encrypted") && len(params) > 0 && params["protected"] != "" {
				protected := params["protected"]
				data, e := m.Provider.Decrypt(r.Context(), []byte(protected))
				if e != nil {
					return nil, &ErrInvalidProtected{
						Value:  protected,
						Reason: e.Error(),
					}
				}

				p := &internal.Protected{}
				if err := json.Unmarshal(data, p); err != nil {
					return nil, &ErrInvalidProtected{
						Value:  protected,
						Reason: fmt.Sprintf("umarshal failed: %s", err),
					}
				}

				return p.NewCipher()
			}
		}
	}

	return nil, nil
}

type encryptedResponseWriter struct {
	http.ResponseWriter
	encrypter io.Writer
	accept    ContentType

	fixedContentType string
	shouldEncrypt    bool
	once             sync.Once
}

func (w *encryptedResponseWriter) WriteHeader(statusCode int) {
	w.once.Do(func() {
		if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
			fixedContentType, params, ok := w.accept.Match(ContentType(w.Header().Get("Content-Type")))

			if ok {
				w.shouldEncrypt = true
				w.fixedContentType = mime.FormatMediaType(fixedContentType, params)
			}
		}

		if w.shouldEncrypt {
			w.ResponseWriter.Header().Set("Content-Type", w.fixedContentType)
		}
	})

	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *encryptedResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *encryptedResponseWriter) Write(b []byte) (int, error) {
	if w.shouldEncrypt {
		return w.encrypter.Write(b)
	}
	return w.ResponseWriter.Write(b)
}
