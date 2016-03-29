/*
 * Copyright 2016 Fabrício Godoy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
