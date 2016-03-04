package oauth

const (
	AccessToken = "UB736gpbpFp7hS8dNrUFZ7b6Aw2a3N0LI8RRddWO"
	Scope       = "user.read"
)

type FooAdapter struct{}

func (a *FooAdapter) AccessToken(c *TokenContext) *TokenResponse {
	resp := NewTokenResponse(
		AccessToken,
		"bearer",
		3600,
		"",
		Scope,
		"CudYQpuw",
	)
	return &resp
}

func (a *FooAdapter) Client(id, secret string) *ClientEntry {
	if id != ClientID || secret != ClientSecret {
		return nil
	}

	return &ClientEntry{
		id,
		secret,
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

func (a *FooAdapter) User(string, string) bool {
	return false
}

var _ TokenAdapter = (*FooAdapter)(nil)
