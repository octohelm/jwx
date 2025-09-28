package cipher

import (
	"io"
)

func TransformReader(r io.Reader, createWriter func(w io.Writer) (io.Writer, error)) io.ReadCloser {
	return TransformReadCloser(io.NopCloser(r), createWriter)
}

func TransformReadCloser(r io.ReadCloser, createWriter func(w io.Writer) (io.Writer, error)) io.ReadCloser {
	pr, pw := io.Pipe()

	go func() {
		_ = (func() (finalErr error) {
			defer func() {
				closeErr := r.Close()
				if finalErr != nil {
					_ = pw.CloseWithError(finalErr)
				} else if closeErr != nil {
					_ = pw.CloseWithError(closeErr)
				} else {
					_ = pw.Close()
				}
			}()

			ww, err := createWriter(pw)
			if err != nil {
				return err
			}

			_, err = io.Copy(ww, r)
			if closer, ok := ww.(io.Closer); ok {
				if closeErr := closer.Close(); closeErr != nil && err == nil {
					return closeErr
				}
			}
			return err
		})()
	}()

	return pr
}

type WriteFunc func(p []byte) (int, error)

func (fn WriteFunc) Write(p []byte) (int, error) {
	return fn(p)
}
