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

package oauthtest

import (
	"github.com/raiqub/oauth"
	"gopkg.in/raiqub/dot.v1"
)

type TokenAdapter struct {
	AccessToken  string
	ClientID     string
	ClientSecret string
	Scope        string
	CustomValues map[string][]string
}

func NewTokenAdapter() *TokenAdapter {
	return &TokenAdapter{
		"UB736gpbpFp7hS8dNrUFZ7b6Aw2a3N0LI8RRddWO",
		"client_id",
		"client_secret",
		"user.read",
		make(map[string][]string, 0),
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
	for k, v := range a.CustomValues {
		var ok bool
		var rawVal interface{}
		if rawVal, ok = c.Values[k]; !ok {
			return nil
		}

		var v2 []string
		if v2, ok = rawVal.([]string); !ok {
			return nil
		}

		if !dot.StringSlice(v2).
			ExistsAll(v, false) {
			return nil
		}
	}

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
