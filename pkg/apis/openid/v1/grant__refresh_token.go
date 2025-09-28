package v1

import "cmp"

// RefreshTokenGrant https://www.oauth.com/oauth2-servers/access-tokens/refreshing-access-tokens/
type RefreshTokenGrant struct {
	// 授权类型
	GrantType string `json:"grant_type" validate:"@string{refresh_token}"`
	// 刷新 Token
	RefreshToken string `json:"refresh_token"`
	// 授权范围
	Scope string `json:"scope,omitzero"`

	ClientAuth
}

func (t RefreshTokenGrant) Type() string {
	return cmp.Or(t.GrantType, "refresh_token")
}
