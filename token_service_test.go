package oauth_test

import (
	"testing"

	"github.com/raiqub/oauth"
	"github.com/raiqub/oauth/oauthtest"
)

func TestClientGrant(t *testing.T) {
	adapter := oauthtest.NewTokenAdapter()
	svc := oauth.NewTokenService(adapter)

	context := oauth.TokenContext{
		GrantType: oauth.GrantTypeClient,
		Scope:     adapter.Scope,
		ClientAuth: &oauth.BasicAuth{
			Username: adapter.ClientID,
			Password: adapter.ClientSecret,
		},
	}
	resp, jerr := svc.AccessTokenRequest(&context)
	if jerr != nil {
		t.Fatalf("Error trying to get client grant: %v", jerr.Description)
	}

	if resp.AccessToken != adapter.AccessToken {
		t.Errorf("Unexpected access token: %s", resp.AccessToken)
	}
}
