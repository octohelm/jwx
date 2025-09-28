package v1

import (
	"testing"

	testingx "github.com/octohelm/x/testing"
)

func TestParseWwwAuthenticate(t *testing.T) {
	a := &WwwAuthenticate{
		AuthType: "Bearer",
		Params: map[string]string{
			"realm":      "http://localhost/token",
			"service":    "test",
			"grant_type": "client_credentials",
		},
	}

	testingx.Expect(t, a.String(), testingx.Be(`Bearer grant_type="client_credentials", realm="http://localhost/token", service="test"`))

	parsed, err := ParseWwwAuthenticate(`Bearer grant_type="client_credentials", realm="http://localhost/token", service="test"`)
	testingx.Expect(t, err, testingx.BeNil[error]())
	testingx.Expect(t, parsed, testingx.Equal(a))
}
