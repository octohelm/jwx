package cipher

import "errors"

var (
	ErrUnsupportedEncryptionMethod = errors.New("unsupported encryption method")
	ErrInvalidAESKey               = errors.New("invalid aes key")
	ErrInvalidChacha20Key          = errors.New("invalid chacha20 key")
)
