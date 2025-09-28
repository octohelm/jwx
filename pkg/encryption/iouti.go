package encryption

import (
	"io"

	"github.com/octohelm/jwx/pkg/encryption/internal/cipher"
)

func TransformReader(r io.Reader, createWriter func(w io.Writer) (io.Writer, error)) io.Reader {
	return cipher.TransformReadCloser(io.NopCloser(r), createWriter)
}
