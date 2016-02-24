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

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gopkg.in/raiqub/dot.v1"
)

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

// A TokenHandler provides handling of token endpoint on Auth 2.0 server.
type TokenHandler struct {
	prov TokenProvider
}

// NewTokenHandler creates a new instance of TokenHandler.
func NewTokenHandler(model TokenProvider) *TokenHandler {
	return &TokenHandler{model}
}

func (h *TokenHandler) authClient(
	c *TokenContext,
	grant string,
) (*ClientEntry, *Error) {
	// Get client credentials
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		jerr := NewError().
			MissingClientCredentials().
			Build()
		return nil, &jerr
	}

	// Validate client credentials
	result := h.prov.Client(clientID, clientSecret)
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
		StringSlice(c.Client.AllowedGrants).
		Exists(grant, false) {
		jerr := NewError().
			UnauthorizedClient().
			Build()
		return nil, &jerr
	}

	return result, nil
}

func (h *TokenHandler) clientHandler(c *TokenContext) {
	var jerr *Error
	c.Client, jerr = h.authClient(c, GrantTypeClient)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	// Request a new access token
	response := h.prov.AccessToken(c)
	response.State = c.State

	// Disables HTTP caching on client and returns access token for client
	disableCaching(c.Writer)
	c.JSON(http.StatusOK, response)
}

func (h *TokenHandler) passwordHandler(c *TokenContext) {
	var jerr *Error
	c.Client, jerr = h.authClient(c, GrantTypePassword)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	// Validates user (resource owner) credentials
	if !h.prov.User(c.Username, c.Password) {
		jerr := NewError().
			InvalidUserCredentials(c.Username).
			Build()
		c.JSON(jerr.Status, jerr)
		return
	}

	// Request a new access token
	response := h.prov.AccessToken(c)
	response.State = c.State

	// Disables HTTP caching on client and returns access token for client
	disableCaching(c.Writer)
	c.JSON(http.StatusOK, response)
}

func (h *TokenHandler) refreshHandler(c *TokenContext) {
	var jerr *Error
	c.Client, jerr = h.authClient(c, GrantTypeRefresh)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	// Validates refresh token
	if !h.prov.Refresh(c) {
		jerr := NewError().
			InvalidRefreshToken().
			Build()
		c.JSON(jerr.Status, jerr)
		return
	}

	// Request a new access token
	response := h.prov.AccessToken(c)
	response.State = c.State

	// Disables HTTP caching on client and returns access token for client
	disableCaching(c.Writer)
	c.JSON(http.StatusOK, response)
}

// AccessTokenRequest receives a request to token endpoint.
func (h *TokenHandler) AccessTokenRequest(c *gin.Context) {
	context := NewTokenContext(c)

	// Determine whether requested grant type is supported
	if !dot.
		StringSlice(h.prov.SupportedGrantTypes()).
		Exists(context.GrantType, false) {
		jerr := NewError().
			UnsupportedGrantType().
			Build()
		c.JSON(jerr.Status, jerr)
		return
	}

	// Route requested grant type to its handler
	switch context.GrantType {
	case GrantTypeClient:
		h.clientHandler(context)
	case GrantTypePassword:
		h.passwordHandler(context)
	case GrantTypeRefresh:
		h.refreshHandler(context)
	default:
		jerr := NewError().
			UnsupportedGrantType().
			Build()
		c.JSON(jerr.Status, jerr)
	}
}
