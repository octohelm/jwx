package v1

import "cmp"

// ClientCredentialsGrant https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/
type ClientCredentialsGrant struct {
	// 授权类型
	GrantType string `json:"grant_type" validate:"@string{client_credentials}"`
	// 授权范围
	Scope string `json:"scope,omitzero"`

	ClientAuth
}

func (t ClientCredentialsGrant) Type() string {
	return cmp.Or(t.GrantType, "client_credentials")
}
