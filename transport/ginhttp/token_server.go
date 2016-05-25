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

package ginhttp

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gopkg.in/raiqub/oauth.v2"
	httptransport "gopkg.in/raiqub/oauth.v2/transport/http"
)

// A TokenServer represents a gin-backed HTTP server for TokenService.
type TokenServer struct {
	svcToken *oauth.TokenService
}

// NewTokenServer creates a new instance of TokenServer.
func NewTokenServer(svcToken *oauth.TokenService) *TokenServer {
	return &TokenServer{
		svcToken,
	}
}

// AccessTokenRequest is a endpoint that receives a request to create a new
// access token.
func (s *TokenServer) AccessTokenRequest(c *gin.Context) {
	context := httptransport.NewTokenContext(c.Request)
	resp, jerr := s.svcToken.AccessTokenRequest(context)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	// Disables HTTP caching on client and returns access token for client
	if resp != nil {
		httptransport.DisableCaching(c.Writer)
		c.JSON(http.StatusOK, *resp)
	} else {
		c.Status(http.StatusBadRequest)
	}
}

// SetHandler register a new handler for specified grant type.
func (s *TokenServer) SetHandler(grantType string, handler oauth.TokenHandlerFunc) {
	s.svcToken.SetHandler(grantType, handler)
}
