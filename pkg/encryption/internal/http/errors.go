package http

import (
	"fmt"

	"github.com/octohelm/courier/pkg/statuserror"
)

type ErrInvalidEncryptedData struct {
	statuserror.BadGateway

	Reason string
}

func (e *ErrInvalidEncryptedData) Error() string {
	return fmt.Sprintf("invalid encrypted data: %s", e.Reason)
}

type ErrInvalidProtected struct {
	statuserror.BadRequest

	Reason string
	Value  string
}

func (e *ErrInvalidProtected) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("invalid protected %s: %s", e.Value, e.Reason)
	}

	return fmt.Sprintf("invalid protected: %s", e.Reason)
}

type ErrUnsupportedEncryptionMethod struct {
	statuserror.BadRequest

	Enc string
}

func (e *ErrUnsupportedEncryptionMethod) Error() string {
	return fmt.Sprintf("unsupported encryption method: %s", e.Enc)
}

type ErrInvalidKey struct {
	statuserror.BadRequest

	Reason string
}

func (e *ErrInvalidKey) Error() string {
	return fmt.Sprintf("invalid key: %s", e.Reason)
}
