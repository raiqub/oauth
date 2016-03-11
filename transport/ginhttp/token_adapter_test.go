package ginhttp

import "github.com/raiqub/oauth"

const (
	AccessToken = "UB736gpbpFp7hS8dNrUFZ7b6Aw2a3N0LI8RRddWO"
	Scope       = "user.read"
)

type FooAdapter struct{}

func (a *FooAdapter) AccessToken(c *oauth.TokenContext) *oauth.TokenResponse {
	resp := oauth.NewTokenResponse(
		AccessToken,
		"bearer",
		3600,
		"",
		Scope,
		"CudYQpuw",
	)
	return &resp
}

func (a *FooAdapter) Client(c *oauth.TokenContext) *oauth.ClientEntry {
	if c.ClientAuth.Username != ClientID ||
		c.ClientAuth.Password != ClientSecret {
		return nil
	}

	return &oauth.ClientEntry{
		ClientID:          ClientID,
		ClientSecret:      ClientSecret,
		ClientType:        "public",
		RedirectUris:      []string{"http://client.example.com/callback"},
		JavascriptOrigins: []string{"http://client.example.com"},
		AllowedGrants:     []string{oauth.GrantTypeClient},
		AllowedScopes:     []string{Scope},
	}
}

func (a *FooAdapter) Refresh(*oauth.TokenContext) bool {
	return false
}

func (a *FooAdapter) SupportedGrantTypes() []string {
	return []string{oauth.GrantTypeClient}
}

func (a *FooAdapter) User(*oauth.TokenContext) bool {
	return false
}

var _ oauth.TokenAdapter = (*FooAdapter)(nil)
