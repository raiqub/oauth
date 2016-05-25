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

package http

import (
	"net/http"

	"gopkg.in/raiqub/oauth.v2"
	"gopkg.in/raiqub/web.v0"
)

// A TokenServer represents a HTTP server for TokenService.
type TokenServer struct {
	svc *oauth.TokenService
}

// NewTokenServer creates a new instance of TokenServer.
func NewTokenServer(adapter oauth.TokenAdapter, grantTypes ...string) *TokenServer {
	return &TokenServer{
		oauth.NewTokenService(adapter, grantTypes...),
	}
}

// AccessTokenRequest is a endpoint that receives a request to create a new
// access token.
func (srv *TokenServer) AccessTokenRequest(
	w http.ResponseWriter,
	r *http.Request,
) {
	context := NewTokenContext(r)
	resp, jerr := srv.svc.AccessTokenRequest(context)
	if jerr != nil {
		web.JSONWrite(w, jerr.Status, jerr)
		return
	}

	if resp != nil {
		DisableCaching(w)
		web.JSONWrite(w, http.StatusOK, *resp)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

// SetHandler register a new handler for specified grant type.
func (srv *TokenServer) SetHandler(grantType string, handler oauth.TokenHandlerFunc) {
	srv.svc.SetHandler(grantType, handler)
}
