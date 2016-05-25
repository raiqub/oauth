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

// A TokenHandlerFunc represents a function that handle a grant type for TokenService.
type TokenHandlerFunc func(TokenAdapter, *TokenContext) (*TokenResponse, *Error)

// A TokenService provides token management for OAuth 2.0 server.
type TokenService struct {
	handlers map[string]TokenHandlerFunc
	adapter  TokenAdapter
}

// NewTokenService creates a new instance of TokenService.
func NewTokenService(ta TokenAdapter, grantTypes ...string) *TokenService {
	tService := TokenService{
		make(map[string]TokenHandlerFunc),
		ta,
	}

	for _, v := range grantTypes {
		switch v {
		case GrantTypeClient:
			tService.handlers[v] = HandlerClient
		case GrantTypePassword:
			tService.handlers[v] = HandlerPassword
		case GrantTypeRefresh:
			tService.handlers[v] = HandlerRefresh
		default:
			panic("Unhandled grant type")
		}
	}
	return &tService
}

// AccessTokenRequest receives a request to create a new access token.
func (svc *TokenService) AccessTokenRequest(context *TokenContext,
) (*TokenResponse, *Error) {
	// Route requested grant type to its handler
	handler, ok := svc.handlers[context.GrantType]
	if !ok || handler == nil {
		jerr := NewError().
			UnsupportedGrantType().
			Build()
		return nil, &jerr
	}

	return handler(svc.adapter, context)
}

// SetHandler register a new handler for specified grant type.
func (svc *TokenService) SetHandler(grantType string, handler TokenHandlerFunc) {
	if handler == nil {
		delete(svc.handlers, grantType)
	} else {
		svc.handlers[grantType] = handler
	}
}
