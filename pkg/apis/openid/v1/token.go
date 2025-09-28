package v1

// Token
// https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
type Token struct {
	// Token 类型
	TokenType string `json:"token_type"`
	// 过期时间（单位：秒）
	ExpiresIn int `json:"expires_in,omitzero"`
	// 访问凭证
	AccessToken string `json:"access_token"`
	// 刷新凭证
	RefreshToken string `json:"refresh_token,omitzero"`
	// 凭证范围
	// 预留，暂时无实现
	Scope string `json:"scope,omitzero"`
}

const TokenTypeBearer = "Bearer"
