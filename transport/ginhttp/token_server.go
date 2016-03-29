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
	"github.com/raiqub/oauth"
)

// A TokenServer represents a gin-backed HTTP server for TokenService.
type TokenServer struct {
	svc *oauth.TokenService
}

// NewTokenServer creates a new instance of TokenServer.
func NewTokenServer(adapter oauth.TokenAdapter) *TokenServer {
	return &TokenServer{
		svc: oauth.NewTokenService(adapter),
	}
}

// AccessTokenRequest is a endpoint that receives a request to create a new
// access token.
func (s *TokenServer) AccessTokenRequest(c *gin.Context) {
	context := newTokenContext(c)
	resp, jerr := s.svc.AccessTokenRequest(context)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	// Disables HTTP caching on client and returns access token for client
	if resp != nil {
		disableCaching(c.Writer)
		c.JSON(http.StatusOK, *resp)
	} else {
		c.Status(http.StatusBadRequest)
	}
}

// DisableCaching disables HTTP caching on client.
func disableCaching(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// NewTokenContext creates a new instance of TokenContext based on specified gin
// context.
func newTokenContext(c *gin.Context) *oauth.TokenContext {
	var auth *oauth.BasicAuth
	username, password, ok := c.Request.BasicAuth()
	if ok {
		auth = &oauth.BasicAuth{
			Username: username,
			Password: password,
		}
	}

	tContext := &oauth.TokenContext{
		ClientAuth: auth,
		Client:     nil,
		Values:     make(map[string]interface{}),
	}

	c.Request.ParseForm()
	for k, v := range c.Request.PostForm {
		if len(v) == 0 {
			continue
		}

		switch k {
		case oauth.FormClientID:
			tContext.ClientID = v[0]
		case oauth.FormKeyCode:
			tContext.Code = v[0]
		case oauth.FormKeyGrantType:
			tContext.GrantType = v[0]
		case oauth.FormKeyPassword:
			tContext.Password = v[0]
		case oauth.FormKeyRedirect:
			tContext.RedirectURI = v[0]
		case oauth.FormKeyRefreshToken:
			tContext.RefreshToken = v[0]
		case oauth.FormKeyScope:
			tContext.Scope = v[0]
		case oauth.FormKeyState:
			tContext.State = v[0]
		case oauth.FormKeyUsername:
			tContext.Username = v[0]
		default:
			tContext.Values[k] = v
		}
	}

	return tContext
}
