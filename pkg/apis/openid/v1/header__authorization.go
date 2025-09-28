package v1

import (
	"bytes"
	"net/http"

	"cuelang.org/go/cue/errors"
)

func ParseAuthorization(s string) (Authorization, error) {
	auths := Authorization{}
	if len(s) == 0 {
		return nil, errors.New("invalid Authorization")
	}
	tokens := bytes.Split([]byte(s), []byte(";"))
	for _, token := range tokens {
		kv := bytes.Split(bytes.TrimSpace(token), []byte(" "))
		v := ""
		if len(kv) == 2 {
			v = string(bytes.TrimSpace(kv[1]))
		}
		auths[http.CanonicalHeaderKey(string(bytes.TrimSpace(kv[0])))] = v
	}

	if len(auths) == 0 {
		return nil, errors.New("invalid authorization")
	}

	return auths, nil
}

type Authorization map[string]string

func (auths Authorization) Add(k string, v string) {
	auths[http.CanonicalHeaderKey(k)] = v
}

func (auths Authorization) Get(k string) string {
	if v, ok := auths[http.CanonicalHeaderKey(k)]; ok {
		return v
	}
	return ""
}

func (auths Authorization) String() string {
	buf := bytes.Buffer{}

	count := 0
	for tpe, token := range auths {
		if count > 0 {
			buf.WriteString("; ")
		}
		buf.WriteString(http.CanonicalHeaderKey(tpe))
		buf.WriteString(" ")
		buf.WriteString(token)
		count++
	}
	return buf.String()
}

func (a *Authorization) UnmarshalText(text []byte) error {
	aa, err := ParseAuthorization(string(text))
	if err != nil {
		return err
	}
	*a = aa
	return nil
}

func (a Authorization) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}
