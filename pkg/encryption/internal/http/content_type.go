package http

import (
	"mime"
	"strings"
)

func WithoutEncrypted(contentType string) string {
	mediaType, params, _ := mime.ParseMediaType(contentType)
	delete(params, "protected")
	return mime.FormatMediaType(mediaType[0:len(mediaType)-len("+encrypted")], params)
}

type ContentType string

func (a ContentType) MediaType() string {
	mt := string(a)
	if i := strings.Index(mt, ";"); i > 0 {
		return mt[:i]
	}
	return mt
}

func (a ContentType) Match(ct ContentType) (string, map[string]string, bool) {
	amt := a.MediaType()
	cmt := ct.MediaType()

	if amt == "*/*+encrypted" || amt == cmt+"+encrypted" {
		_, params, _ := mime.ParseMediaType(string(ct))
		if params == nil {
			params = map[string]string{}
		}
		if _, params1, _ := mime.ParseMediaType(string(a)); params1 != nil {
			params["protected"] = params1["protected"]
		}
		return cmt + "+encrypted", params, true
	}
	return "", nil, false
}
