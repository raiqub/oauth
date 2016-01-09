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
	"github.com/raiqub/dot"
)

const (
	GRANTTYPE_CLIENT   = "client_credentials"
	GRANTTYPE_CODE     = "authorization_code"
	GRANTTYPE_PASSWORD = "password"
	GRANTTYPE_REFRESH  = "refresh_token"
)

type TokenServer struct {
	model TokenModel
}

func NewTokenServer(model TokenModel) *TokenServer {
	return &TokenServer{model}
}

func (s *TokenServer) loadClient(c *TokenContext) (*ClientEntry, *OAuthError) {
	client_id, client_secret, ok := c.Request.BasicAuth()
	if !ok {
		jerr := NewOAuthError().
			InvalidClient().
			SetError(MissingClientId(0)).
			Build()
		return nil, &jerr
	}

	result := s.model.Client(client_id, client_secret)
	if result == nil {
		jerr := NewOAuthError().
			InvalidClient().
			Build()
		return nil, &jerr
	}

	if !dot.
		StringSlice(result.AllowedScopes).
		ExistsAll(c.ScopeList(), false) {
		jerr := NewOAuthError().
			InvalidScope().
			Build()
		return nil, &jerr
	}

	return result, nil
}

func (s *TokenServer) passwordHandler(c *TokenContext) {
	var jerr *OAuthError
	c.Client, jerr = s.loadClient(c)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	if !dot.
		StringSlice(c.Client.AllowedGrants).
		Exists(GRANTTYPE_PASSWORD, false) {
		jerr := NewOAuthError().
			UnauthorizedClient().
			Build()
		c.JSON(jerr.Status, jerr)
		return
	}

	if !s.model.User(c.Username, c.Password) {
		jerr := NewOAuthError().
			InvalidGrant().
			SetError(InvalidCredential(c.Username)).
			Build()
		c.JSON(jerr.Status, jerr)
		return
	}

	response := s.model.AccessToken(c)
	response.State = c.State

	disableCaching(c.Writer)
	c.JSON(http.StatusOK, response)
}

func (s *TokenServer) AccessTokenRequest(c *gin.Context) {
	context := NewTokenContext(c)
	if !dot.StringSlice(s.model.SupportedGrantTypes()).
		Exists(context.GrantType, false) {
		jerr := NewOAuthError().
			UnsupportedGrantType().
			Build()
		c.JSON(jerr.Status, jerr)
		return
	}

	switch context.GrantType {
	case GRANTTYPE_PASSWORD:
		s.passwordHandler(context)
	default:
		jerr := NewOAuthError().
			UnsupportedGrantType().
			Build()
		c.JSON(jerr.Status, jerr)
	}
}

func (s *TokenServer) SetRoutes(router gin.IRouter) gin.IRouter {
	g := router.Group("/oauth")
	g.POST("/token", s.AccessTokenRequest)

	return g
}
