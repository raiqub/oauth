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
	"gopkg.in/raiqub/oauth.v2"
	"gopkg.in/raiqub/slice.v1"
)

// A TokenAdapter is an implementation of TokenAdapter interface for testing
// purposes.
type TokenAdapter struct {
	AccessToken  string
	ClientID     string
	ClientSecret string
	Scope        string
	CustomValues map[string][]string
}

// NewTokenAdapter creates a new instance of TokenAdapter.
func NewTokenAdapter() *TokenAdapter {
	return &TokenAdapter{
		"UB736gpbpFp7hS8dNrUFZ7b6Aw2a3N0LI8RRddWO",
		"client_id",
		"client_secret",
		"user.read",
		make(map[string][]string, 0),
	}
}

// FindClient gets the client information if valid.
func (a *TokenAdapter) FindClient(c *oauth.TokenContext) *oauth.ClientEntry {
	if c.HTTPUser != a.ClientID ||
		c.HTTPSecret != a.ClientSecret {
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

// NewAccessToken creates and returns a new access token.
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

		if !slice.String(v2).
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

// ValidateRefresh validate provided refresh token.
func (a *TokenAdapter) ValidateRefresh(*oauth.TokenContext) bool {
	return false
}

// ValidateUser validate resource owner credentials for password grant type.
func (a *TokenAdapter) ValidateUser(*oauth.TokenContext) bool {
	return false
}

var _ oauth.TokenAdapter = (*TokenAdapter)(nil)
