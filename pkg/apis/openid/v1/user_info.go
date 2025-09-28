package v1

// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
type UserInfo struct {
	// 用户标识
	Sub string `json:"sub"`
	// 姓名
	Name string `json:"name,omitzero"`
	// 昵称
	Nickname string `json:"nickname,omitzero"`
	// 自定义用户名
	PreferredUsername string `json:"preferred_username,omitzero"`
	// 邮箱
	Email string `json:"email,omitzero"`
	// 已验证邮箱
	EmailVerified bool `json:"email_verified,omitzero"`
	// 手机号
	PhoneNumber string `json:"phone_number,omitzero"`
	// 已验证手机号
	PhoneNumberVerified bool `json:"phone_number_verified,omitzero"`
	// 其他信息
	Extra map[string]interface{} `json:",inline"`
}
