package v1

import "cmp"

// PasswordGrant https://www.oauth.com/oauth2-servers/access-tokens/password-grant/
type PasswordGrant struct {
	// 授权类型
	GrantType string `json:"grant_type" validate:"@string{password}"`

	// 用户标识
	// 可以是 用户名/手机/邮箱等
	Username string `json:"username"`
	// 密码
	Password string `json:"password"`
	// 授权范围
	Scope string `json:"scope,omitzero"`

	ClientAuth
}

func (t PasswordGrant) Type() string {
	return cmp.Or(t.GrantType, "password")
}
