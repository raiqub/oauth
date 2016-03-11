package oauth

const (
	AccessToken = "UB736gpbpFp7hS8dNrUFZ7b6Aw2a3N0LI8RRddWO"
	Scope       = "user.read"
)

type FooAdapter struct{}

func (a *FooAdapter) AccessToken(c *TokenContext) *TokenResponse {
	resp := NewTokenResponse(
		AccessToken,
		"Bearer",
		3600,
		"",
		Scope,
		"CudYQpuw",
	)
	return &resp
}

func (a *FooAdapter) Client(c *TokenContext) *ClientEntry {
	if c.ClientAuth.Username != ClientID ||
		c.ClientAuth.Password != ClientSecret {
		return nil
	}

	return &ClientEntry{
		ClientID,
		ClientSecret,
		"public",
		[]string{"http://client.example.com/callback"},
		[]string{"http://client.example.com"},
		[]string{GrantTypeClient},
		[]string{Scope},
	}
}

func (a *FooAdapter) Refresh(*TokenContext) bool {
	return false
}

func (a *FooAdapter) SupportedGrantTypes() []string {
	return []string{GrantTypeClient}
}

func (a *FooAdapter) User(*TokenContext) bool {
	return false
}

var _ TokenAdapter = (*FooAdapter)(nil)
