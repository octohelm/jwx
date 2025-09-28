package internal

import (
	"encoding/base64"
)

func Base64RawURLEncode(src []byte) []byte {
	enc := base64.RawURLEncoding
	dst := make([]byte, enc.EncodedLen(len(src)))
	base64.RawURLEncoding.Encode(dst, src)
	return dst
}

func Base64RawURLDecode(b []byte) ([]byte, error) {
	enc := base64.RawURLEncoding
	dbuf := make([]byte, enc.DecodedLen(len(b)))
	n, err := enc.Decode(dbuf, b)
	return dbuf[:n], err
}
