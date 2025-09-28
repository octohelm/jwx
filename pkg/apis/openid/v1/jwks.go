package v1

type Jwks struct {
	// 密钥列表
	Keys []Jwk `json:"keys"`
}

type Jwk struct {
	// 密钥类型
	Kty string `json:"kty"`
	// 密钥算法类型
	Alg string `json:"alg"`
	// 密钥 ID
	Kid string `json:"kid"`
	// 用途
	// sig （签名和验证）或 enc (加密和解密)
	Use string `json:"use"`
	// RSA 公钥的模数
	E string `json:"e"`
	// RSA 公钥的指数
	N string `json:"n"`
}
