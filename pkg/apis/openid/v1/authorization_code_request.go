package v1

// https://www.oauth.com/oauth2-servers/authorization/the-authorization-request/
type AuthorizationCodeRequest struct {
	ResponseType        string `json:"response_type" validate:"@string{code}"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope,omitzero"`
	State               string `json:"state,omitzero"`
	CodeChallenge       string `json:"code_challenge,omitzero"`
	CodeChallengeMethod string `json:"code_challenge_method,omitzero"`
}
