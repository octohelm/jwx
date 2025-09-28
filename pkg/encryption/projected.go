package encryption

import (
	"github.com/octohelm/jwx/pkg/encryption/internal"
	encryptionhttp "github.com/octohelm/jwx/pkg/encryption/internal/http"
)

type (
	ErrInvalidKey                  = encryptionhttp.ErrInvalidKey
	ErrInvalidProtected            = encryptionhttp.ErrInvalidProtected
	ErrUnsupportedEncryptionMethod = encryptionhttp.ErrUnsupportedEncryptionMethod
)

type Protected = internal.Protected

func NewProtected() (*Protected, error) {
	p := &Protected{
		Enc: "AES-256-CFB",
	}
	if err := p.Init(); err != nil {
		return nil, err
	}
	return p, nil
}
