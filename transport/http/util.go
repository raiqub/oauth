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

	"gopkg.in/raiqub/oauth.v1"
)

// DisableCaching disables HTTP caching on client.
func DisableCaching(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// NewTokenContext creates a new instance of TokenContext based on specified gin
// context.
func NewTokenContext(req *http.Request) *oauth.TokenContext {
	var auth *oauth.BasicAuth
	username, password, ok := req.BasicAuth()
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

	req.ParseForm()
	for k, v := range req.PostForm {
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
