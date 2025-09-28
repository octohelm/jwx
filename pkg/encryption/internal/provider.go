package internal

import "context"

// +gengo:injectable:provider
type Provider interface {
	EncryptProvider
	DecryptProvider
}

type EncryptProvider interface {
	Encrypt(ctx context.Context, payload []byte) (ciphertext []byte, err error)
}

type DecryptProvider interface {
	Decrypt(ctx context.Context, ciphertext []byte) (payload []byte, err error)
}
