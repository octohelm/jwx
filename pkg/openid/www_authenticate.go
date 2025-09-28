package openid

import (
	"github.com/innoai-tech/infra/pkg/http/basehref"
	"github.com/octohelm/courier/pkg/courierhttp"
	openidv1 "github.com/octohelm/jwx/pkg/apis/openid/v1"
)

func WithWwwAuthenticate(req *courierhttp.Request) courierhttp.ResponseSettingFunc {
	ctx := req.Context()

	if opp, ok := courierhttp.OperationInfoProviderFromContext(ctx); ok {
		if r, ok := opp.GetOperation("ExchangeToken"); ok {
			if info, ok := courierhttp.OperationInfoFromContext(ctx); ok {
				base := basehref.FromHttpRequest(req)

				wa := &openidv1.WwwAuthenticate{}
				wa.AuthType = openidv1.TokenTypeBearer
				wa.Params = map[string]string{
					"realm":      base.Path(r.Route),
					"grant_type": "client_credentials",
					"service":    info.Server.Name,
				}

				return courierhttp.WithMetadata("WWW-Authenticate", wa.String())
			}
		}
	}

	return func(s courierhttp.ResponseSetting) {
	}
}
