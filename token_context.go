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

import "strings"

const (
	// FormClientID defines the form's key name to define client identifier.
	FormClientID = "client_id"

	// FormKeyCode defines the form's key name to define authorization code.
	FormKeyCode = "code"

	// FormKeyGrantType defines the form's key name to define grant type.
	FormKeyGrantType = "grant_type"

	// FormKeyPassword defines the form's key name to define user password.
	FormKeyPassword = "password"

	// FormKeyRedirect defines the form's key name to define redirection
	// endpoint.
	FormKeyRedirect = "redirect_uri"

	// FormKeyRefreshToken defines the form's key name to define refresh token.
	FormKeyRefreshToken = "refresh_token"

	// FormKeyScope defines the form's key name to define client scopes.
	FormKeyScope = "scope"

	// FormKeyState defines the form's key name to define session nonce.
	FormKeyState = "state"

	// FormKeyUsername defines the form's key name to define user name.
	FormKeyUsername = "username"
)

// A TokenContext represents an object to pass variables between TokenHandler
// and TokenProvider methods.
type TokenContext struct {
	// Common form fields

	GrantType string
	Scope     string
	State     string

	// Authorization Code Grant

	Code        string
	RedirectURI string
	ClientID    string

	// Resource Owner Password Credentials Grant

	Username string
	Password string

	// Refresh Access Token

	RefreshToken string

	// Context parsed

	HTTPUser   string
	HTTPSecret string
	Client     *ClientEntry
	Values     map[string]interface{}
}

// ScopeList returns scope split by its spaces.
func (s TokenContext) ScopeList() []string {
	return strings.Split(s.Scope, " ")
}
