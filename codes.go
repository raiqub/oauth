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

import "net/http"

const (
	// RFC6749ErrorResponseURI defines URI for documentation of error responses
	// from Auth 2.0 documentation.
	RFC6749ErrorResponseURI = "http://tools.ietf.org/html/rfc6749#section-5.2"

	// CodeInvalidClient defines error code when client authentication failed.
	CodeInvalidClient = "invalid_client"

	// CodeInvalidGrant defines error code when provided authorization grant or
	// refresh token is invalid.
	CodeInvalidGrant = "invalid_grant"

	// CodeInvalidRequest defines error code when the request has any error on
	// parameter or is malformed.
	CodeInvalidRequest = "invalid_request"

	// CodeInvalidScope defines error code when has any error related to scope.
	CodeInvalidScope = "invalid_scope"

	// CodeUnauthorizedClient defines error code when authenticated client lacks
	// authorization.
	CodeUnauthorizedClient = "unauthorized_client"

	// CodeUnsupportedGrantType defines error code when the authorization grant
	// type is not supported.
	CodeUnsupportedGrantType = "unsupported_grant_type"
)

var description = map[string]string{
	CodeInvalidClient: "Client authentication failed (e.g., unknown client, " +
		"no client authentication included, or unsupported authentication " +
		"method).",
	CodeInvalidGrant: "The provided authorization grant (e.g., authorization " +
		"code, resource owner credentials) or refresh token is invalid, " +
		"expired, revoked, does not match the redirection URI used in the " +
		"authorization request, or was issued to another client.",
	CodeInvalidRequest: "The request is missing a required parameter, " +
		"includes an unsupported parameter value (other than grant type), " +
		"repeats a parameter, includes multiple credentials, utilizes more " +
		"than one mechanism for authenticating the client, or is otherwise " +
		"malformed.",
	CodeInvalidScope: "The requested scope is invalid, unknown, malformed, " +
		"or exceeds the scope granted by the resource owner.",
	CodeUnauthorizedClient: "The authenticated client is not authorized to " +
		"use this authorization grant type.",
	CodeUnsupportedGrantType: "The authorization grant type is not supported " +
		"by the authorization server.",
}

var codeStatus = map[string]int{
	CodeInvalidClient:        http.StatusUnauthorized,
	CodeInvalidGrant:         http.StatusBadRequest,
	CodeInvalidRequest:       http.StatusBadRequest,
	CodeInvalidScope:         http.StatusBadRequest,
	CodeUnauthorizedClient:   http.StatusBadRequest,
	CodeUnsupportedGrantType: http.StatusBadRequest,
}

// ErrorDescription returns an error description for error code.
func ErrorDescription(code string) string {
	return description[code]
}

// ErrorStatus returns a HTTP status code for error code.
func ErrorStatus(code string) int {
	return codeStatus[code]
}
