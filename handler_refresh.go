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

package oauth

// GrantTypeRefresh defines the code for Refresh Access Token
// authentication.
const GrantTypeRefresh = "refresh_token"

// HandlerRefresh handles Refresh Access Token for TokenService.
func HandlerRefresh(adapter TokenAdapter, c *TokenContext) (*TokenResponse, *Error) {
	var jerr *Error
	c.Client, jerr = AuthClient(adapter, c)
	if jerr != nil {
		return nil, jerr
	}

	// Validates refresh token
	if !adapter.ValidateRefresh(c) {
		jerr := NewError().
			InvalidRefreshToken().
			Build()
		return nil, &jerr
	}

	// Request a new access token
	response := adapter.NewAccessToken(c)
	if response != nil {
		response.State = c.State
	}

	return response, nil
}
