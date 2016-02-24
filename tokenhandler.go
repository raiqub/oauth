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
	GrantTypeClient   = "client_credentials"
	GrantTypeCode     = "authorization_code"
	GrantTypePassword = "password"
	GrantTypeRefresh  = "refresh_token"
)

type TokenHandler struct {
	prov TokenProvider
}

func NewTokenHandler(model TokenProvider) *TokenHandler {
	return &TokenHandler{model}
}

func (h *TokenHandler) authClient(
	c *TokenContext,
	grant string,
) (*ClientEntry, *OAuthError) {
	// Get client credentials
	client_id, client_secret, ok := c.Request.BasicAuth()
	if !ok {
		jerr := NewOAuthError().
			MissingClientCredentials().
			Build()
		return nil, &jerr
	}

	// Validate client credentials
	result := h.prov.Client(client_id, client_secret)
	if result == nil {
		jerr := NewOAuthError().
			InvalidClientCredentials().
			Build()
		return nil, &jerr
	}

	// Validates whether requested scopes is allowed
	if !dot.
		StringSlice(result.AllowedScopes).
		ExistsAll(c.ScopeList(), false) {
		jerr := NewOAuthError().
			InvalidScope().
			Build()
		return nil, &jerr
	}

	// Validates whether requested grant type is allowed
	if !dot.
		StringSlice(c.Client.AllowedGrants).
		Exists(grant, false) {
		jerr := NewOAuthError().
			UnauthorizedClient().
			Build()
		return nil, &jerr
	}

	return result, nil
}

func (h *TokenHandler) clientHandler(c *TokenContext) {
	var jerr *OAuthError
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

func (s *TokenHandler) passwordHandler(c *TokenContext) {
	var jerr *OAuthError
	c.Client, jerr = s.authClient(c, GrantTypePassword)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	// Validates user (resource owner) credentials
	if !s.prov.User(c.Username, c.Password) {
		jerr := NewOAuthError().
			InvalidUserCredential(c.Username).
			Build()
		c.JSON(jerr.Status, jerr)
		return
	}

	// Request a new access token
	response := s.prov.AccessToken(c)
	response.State = c.State

	// Disables HTTP caching on client and returns access token for client
	disableCaching(c.Writer)
	c.JSON(http.StatusOK, response)
}

func (h *TokenHandler) refreshHandler(c *TokenContext) {
	var jerr *OAuthError
	c.Client, jerr = h.authClient(c, GrantTypeRefresh)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	// Validates refresh token
	if !h.prov.Refresh(c) {
		jerr := NewOAuthError().
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

func (s *TokenHandler) AccessTokenRequest(c *gin.Context) {
	context := NewTokenContext(c)

	// Determine whether requested grant type is supported
	if !dot.
		StringSlice(s.prov.SupportedGrantTypes()).
		Exists(context.GrantType, false) {
		jerr := NewOAuthError().
			UnsupportedGrantType().
			Build()
		c.JSON(jerr.Status, jerr)
		return
	}

	// Route requested grant type to its handler
	switch context.GrantType {
	case GrantTypeClient:
		s.clientHandler(context)
	case GrantTypePassword:
		s.passwordHandler(context)
	case GrantTypeRefresh:
		s.refreshHandler(context)
	default:
		jerr := NewOAuthError().
			UnsupportedGrantType().
			Build()
		c.JSON(jerr.Status, jerr)
	}
}

func (s *TokenHandler) SetRoutes(router gin.RouterGroup) {
	router.POST("/token", s.AccessTokenRequest)
}
