package v1

import (
	"github.com/go-json-experiment/json"
	"github.com/octohelm/courier/pkg/validator"
	"github.com/octohelm/courier/pkg/validator/taggedunion"
)

type Grant interface {
	Type() string

	SetClientAuth(c ClientAuth)
	GetClientAuth() ClientAuth
}

type GrantPayload struct {
	Grant `json:"-"`
}

var _ json.Unmarshaler = &GrantPayload{}

func (p *GrantPayload) UnmarshalJSON(data []byte) error {
	pp := GrantPayload{}
	if err := taggedunion.Unmarshal(data, &pp); err != nil {
		return err
	}
	*p = pp
	return nil
}

var _ json.Marshaler = GrantPayload{}

func (p GrantPayload) MarshalJSON() ([]byte, error) {
	if p.Grant == nil {
		return []byte("null"), nil
	}
	return validator.Marshal(p.Grant)
}

func (d *GrantPayload) SetUnderlying(u any) {
	d.Grant = u.(Grant)
}

func (GrantPayload) Discriminator() string {
	return "grant_type"
}

func (GrantPayload) Mapping() map[string]any {
	return map[string]any{
		"client_credentials": Grant(&ClientCredentialsGrant{}),
		"password":           Grant(&PasswordGrant{}),
		"authorization_code": Grant(&AuthorizationCodeGrant{}),
		"refresh_token":      Grant(&RefreshTokenGrant{}),
	}
}
