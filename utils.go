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

import "gopkg.in/raiqub/slice.v1"

// AuthClient validates client authentication and authorization.
func AuthClient(adapter TokenAdapter, c *TokenContext,
) (*ClientEntry, *Error) {
	// Get client credentials
	if len(c.HTTPUser) == 0 || len(c.HTTPSecret) == 0 {
		jerr := NewError().
			MissingClientCredentials().
			Build()
		return nil, &jerr
	}

	// Validate client credentials
	result := adapter.FindClient(c)
	if result == nil {
		jerr := NewError().
			InvalidClientCredentials().
			Build()
		return nil, &jerr
	}

	// Validates whether requested scopes is allowed
	if !slice.String(result.AllowedScopes).
		ExistsAll(c.ScopeList(), false) {
		jerr := NewError().
			InvalidScope().
			Build()
		return nil, &jerr
	}

	// Validates whether requested grant type is allowed
	if !slice.String(result.AllowedGrants).
		Exists(c.GrantType, false) {
		jerr := NewError().
			UnauthorizedClient().
			Build()
		return nil, &jerr
	}

	return result, nil
}
