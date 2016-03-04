package oauth

import "testing"

const (
	ClientID     = "client_id"
	ClientSecret = "client_secret"
)

func TestClientGrant(t *testing.T) {
	adapter := &FooAdapter{}
	svc := NewTokenService(adapter)

	context := TokenContext{
		GrantType: GrantTypeClient,
		Scope:     Scope,
		ClientAuth: &BasicAuth{
			Username: ClientID,
			Password: ClientSecret,
		},
	}
	resp, jerr := svc.AccessTokenRequest(&context)
	if jerr != nil {
		t.Fatalf("Error trying to get client grant: %v", jerr.Description)
	}

	if resp.AccessToken != AccessToken {
		t.Errorf("Unexpected access token: %s", resp.AccessToken)
	}
}
