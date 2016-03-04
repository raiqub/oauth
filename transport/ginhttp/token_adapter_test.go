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

func (a *FooAdapter) Client(id, secret string) *oauth.ClientEntry {
	if id != ClientID || secret != ClientSecret {
		return nil
	}

	return &oauth.ClientEntry{
		ClientID:          id,
		ClientSecret:      secret,
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

func (a *FooAdapter) User(string, string) bool {
	return false
}

var _ oauth.TokenAdapter = (*FooAdapter)(nil)
