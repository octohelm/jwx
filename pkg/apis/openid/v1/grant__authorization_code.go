package v1

import "cmp"

// AuthorizationCodeGrant
// https://www.oauth.com/oauth2-servers/access-tokens/authorization-code-request/
type AuthorizationCodeGrant struct {
	// 授权类型
	GrantType string `json:"grant_type" validate:"@string{authorization_code}"`
	// Code 临时凭证 code
	Code string `json:"code"`
	// RedirectUri 重定向地址
	RedirectUri string `json:"redirect_uri,omitzero"`

	CodeVerifier string `json:"code_verifier,omitzero"`

	ClientAuth
}

func (t AuthorizationCodeGrant) Type() string {
	return cmp.Or(t.GrantType, "authorization_code")
}
