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
	// FormKeyGrantType defines the form's key name to define grant type.
	FormKeyGrantType = "grant_type"

	// FormKeyScope defines the form's key name to define client scopes.
	FormKeyScope = "scope"

	// FormKeyState defines the form's key name to define session nonce.
	FormKeyState = "state"

	// FormKeyUsername defines the form's key name to define user name.
	FormKeyUsername = "username"

	// FormKeyPassword defines the form's key name to define user password.
	FormKeyPassword = "password"
)

// A TokenContext represents an object to pass variables between TokenHandler
// and TokenProvider methods.
type TokenContext struct {
	GrantType  string
	Client     *ClientEntry
	Scope      string
	State      string
	Username   string
	Password   string
	Values     map[string]interface{}
	ClientAuth *BasicAuth
}

// A BasicAuth represents an authentication thru HTTP basic authentication.
type BasicAuth struct {
	Username string
	Password string
}

// ScopeList returns scope split by its spaces.
func (s TokenContext) ScopeList() []string {
	return strings.Split(s.Scope, " ")
}
