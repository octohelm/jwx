package v1

// https://openid.net/specs/openid-connect-discovery-1_0.html
type Configuration struct {
	Issuer           string `json:"issuer"`
	JwksUri          string `json:"jwks_uri"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`

	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitzero"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

type ConfigurationWithExternalProviders struct {
	Configuration

	ExternalProviders []*ProviderMeta `json:"externalProviders,omitzero"`
}
