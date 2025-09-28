package v1

type ClientAuth struct {
	// ClientID Client ID
	ClientID string `json:"client_id,omitzero" flag:",omitzero"`
	// ClientSecret Client Secret
	ClientSecret string `json:"client_secret,omitzero" flag:",secret,omitzero"`
}

func (c ClientAuth) GetClientAuth() ClientAuth {
	return c
}

func (c *ClientAuth) SetClientAuth(n ClientAuth) {
	c.ClientID = n.ClientID
	c.ClientSecret = n.ClientSecret
}
