/*
 * Copyright 2015 Fabrício Godoy
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

package oauth

import "gopkg.in/raiqub/dot.v1"

const (
	// GrantTypeClient defines the code for Client Credentials Grant
	// authentication.
	GrantTypeClient = "client_credentials"

	// GrantTypeCode defines the code for Authorization Code Grant
	// authentication.
	GrantTypeCode = "authorization_code"

	// GrantTypePassword defines the code for Resource Owner Password
	// Credentials Grant authentication.
	GrantTypePassword = "password"

	// GrantTypeRefresh defines the code for Refresh Access Token
	// authentication.
	GrantTypeRefresh = "refresh_token"
)

// A TokenService provides token management for Auth 2.0 server.
type TokenService struct {
	adapter TokenAdapter
}

// NewTokenService creates a new instance of TokenService.
func NewTokenService(ta TokenAdapter) *TokenService {
	if ta.SupportedGrantTypes() == nil {
		return nil
	}

	return &TokenService{ta}
}

func (svc *TokenService) authClient(
	c *TokenContext,
	grant string,
) (*ClientEntry, *Error) {
	// Get client credentials
	if c.ClientAuth == nil {
		jerr := NewError().
			MissingClientCredentials().
			Build()
		return nil, &jerr
	}

	// Validate client credentials
	result := svc.adapter.Client(c)
	if result == nil {
		jerr := NewError().
			InvalidClientCredentials().
			Build()
		return nil, &jerr
	}

	// Validates whether requested scopes is allowed
	if !dot.
		StringSlice(result.AllowedScopes).
		ExistsAll(c.ScopeList(), false) {
		jerr := NewError().
			InvalidScope().
			Build()
		return nil, &jerr
	}

	// Validates whether requested grant type is allowed
	if !dot.
		StringSlice(result.AllowedGrants).
		Exists(grant, false) {
		jerr := NewError().
			UnauthorizedClient().
			Build()
		return nil, &jerr
	}

	return result, nil
}

func (svc *TokenService) clientHandler(c *TokenContext,
) (*TokenResponse, *Error) {
	var jerr *Error
	c.Client, jerr = svc.authClient(c, GrantTypeClient)
	if jerr != nil {
		return nil, jerr
	}

	// Request a new access token
	response := svc.adapter.AccessToken(c)
	response.State = c.State
	return response, nil
}

func (svc *TokenService) passwordHandler(c *TokenContext,
) (*TokenResponse, *Error) {
	var jerr *Error
	c.Client, jerr = svc.authClient(c, GrantTypePassword)
	if jerr != nil {
		return nil, jerr
	}

	// Validates user (resource owner) credentials
	if !svc.adapter.User(c) {
		jerr := NewError().
			InvalidUserCredentials(c.Username).
			Build()
		return nil, &jerr
	}

	// Request a new access token
	response := svc.adapter.AccessToken(c)
	response.State = c.State
	return response, nil
}

func (svc *TokenService) refreshHandler(c *TokenContext,
) (*TokenResponse, *Error) {
	var jerr *Error
	c.Client, jerr = svc.authClient(c, GrantTypeRefresh)
	if jerr != nil {
		return nil, jerr
	}

	// Validates refresh token
	if !svc.adapter.Refresh(c) {
		jerr := NewError().
			InvalidRefreshToken().
			Build()
		return nil, &jerr
	}

	// Request a new access token
	response := svc.adapter.AccessToken(c)
	response.State = c.State
	return response, nil
}

// AccessTokenRequest receives a request to create a new access token.
func (svc *TokenService) AccessTokenRequest(context *TokenContext,
) (*TokenResponse, *Error) {
	if !dot.
		StringSlice(svc.adapter.SupportedGrantTypes()).
		Exists(context.GrantType, false) {
		jerr := NewError().
			UnsupportedGrantType().
			Build()
		return nil, &jerr
	}

	// Route requested grant type to its handler
	switch context.GrantType {
	case GrantTypeClient:
		return svc.clientHandler(context)
	case GrantTypePassword:
		return svc.passwordHandler(context)
	case GrantTypeRefresh:
		return svc.refreshHandler(context)
	default:
		jerr := NewError().
			UnsupportedGrantType().
			Build()
		return nil, &jerr
	}
}
