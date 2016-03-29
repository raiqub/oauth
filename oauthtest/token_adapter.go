package oauthtest

import "github.com/raiqub/oauth"

type TokenAdapter struct {
	AccessToken  string
	ClientID     string
	ClientSecret string
	Scope        string
}

func NewTokenAdapter() *TokenAdapter {
	return &TokenAdapter{
		"UB736gpbpFp7hS8dNrUFZ7b6Aw2a3N0LI8RRddWO",
		"client_id",
		"client_secret",
		"user.read",
	}
}

func (a *TokenAdapter) FindClient(c *oauth.TokenContext) *oauth.ClientEntry {
	if c.ClientAuth.Username != a.ClientID ||
		c.ClientAuth.Password != a.ClientSecret {
		return nil
	}

	return &oauth.ClientEntry{
		ClientID:          a.ClientID,
		ClientSecret:      a.ClientSecret,
		ClientType:        "public",
		RedirectUris:      []string{"http://client.example.com/callback"},
		JavascriptOrigins: []string{"http://client.example.com"},
		AllowedGrants:     []string{oauth.GrantTypeClient},
		AllowedScopes:     []string{a.Scope},
	}
}

func (a *TokenAdapter) NewAccessToken(c *oauth.TokenContext) *oauth.TokenResponse {
	resp := oauth.NewTokenResponse(
		a.AccessToken,
		"bearer",
		3600,
		"",
		a.Scope,
		"CudYQpuw",
	)
	return &resp
}

func (a *TokenAdapter) SupportedGrantTypes() []string {
	return []string{oauth.GrantTypeClient}
}

func (a *TokenAdapter) ValidateRefresh(*oauth.TokenContext) bool {
	return false
}

func (a *TokenAdapter) ValidateUser(*oauth.TokenContext) bool {
	return false
}

var _ oauth.TokenAdapter = (*TokenAdapter)(nil)
