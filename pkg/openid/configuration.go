package openid

import (
	"net/http"

	"github.com/innoai-tech/infra/pkg/http/basehref"
	"github.com/octohelm/courier/pkg/courierhttp"
	openidv1 "github.com/octohelm/jwx/pkg/apis/openid/v1"
)

func Configuration(req *http.Request) *openidv1.Configuration {
	base := basehref.FromHttpRequest(req)

	c := &openidv1.Configuration{
		Issuer:                base.Origin(),
		AuthorizationEndpoint: base.Path("/authorize"),
		IdTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		ClaimsSupported: []string{
			"aud",
			"exp",
			"iat",
			"iss",
			"jti",
			"sub",
		},
		GrantTypesSupported: []string{
			"password",
			"refresh_token",
			"authorization_code",
			"client_credentials",
		},
		ResponseTypesSupported: []string{
			"code",
		},
		ScopesSupported: []string{
			"openid",
			"email",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_post",
			"client_secret_basic",
		},
	}

	if opp, ok := courierhttp.OperationInfoProviderFromContext(req.Context()); ok {
		if r, ok := opp.GetOperation("JWKs"); ok {
			c.JwksUri = base.Path(r.Route)
		}

		if r, ok := opp.GetOperation("CurrentUserInfo"); ok {
			c.UserinfoEndpoint = base.Path(r.Route)
		}

		if r, ok := opp.GetOperation("ExchangeToken"); ok {
			c.TokenEndpoint = base.Path(r.Route)
		}
	}

	return c
}
