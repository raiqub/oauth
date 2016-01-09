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

type OAuthErrorBuilder interface {
	Build() OAuthError
	InvalidRequest() OAuthErrorBuilder
	InvalidClient() OAuthErrorBuilder
	InvalidGrant() OAuthErrorBuilder
	InvalidScope() OAuthErrorBuilder
	SetError(error) OAuthErrorBuilder
	SetDescription(string) OAuthErrorBuilder
	SetStatus(int) OAuthErrorBuilder
	SetUri(string) OAuthErrorBuilder
	UnauthorizedClient() OAuthErrorBuilder
	UnsupportedGrantType() OAuthErrorBuilder
}

type oAuthErrorBuilder struct {
	OAuthError
}

func NewOAuthError() OAuthErrorBuilder {
	return &oAuthErrorBuilder{OAuthError{}}
}

func (b *oAuthErrorBuilder) Build() OAuthError {
	return b.OAuthError
}

func (b *oAuthErrorBuilder) InvalidRequest() OAuthErrorBuilder {
	result := OAuthError{
		"invalid_request",
		"The request is missing a required parameter, includes an " +
			"unsupported parameter value (other than grant type), " +
			"repeats a parameter, includes multiple credentials, " +
			"utilizes more than one mechanism for authenticating the " +
			"client, or is otherwise malformed.",
		RFC_6749_ERROR_RESPONSE_URI,
		http.StatusBadRequest,
	}
	b.setCode(result)
	return b
}

func (b *oAuthErrorBuilder) InvalidClient() OAuthErrorBuilder {
	result := OAuthError{
		"invalid_client",
		"Client authentication failed (e.g., unknown client, no " +
			"client authentication included, or unsupported " +
			"authentication method).",
		RFC_6749_ERROR_RESPONSE_URI,
		http.StatusUnauthorized,
	}
	b.setCode(result)
	return b
}

func (b *oAuthErrorBuilder) InvalidGrant() OAuthErrorBuilder {
	result := OAuthError{
		"invalid_grant",
		"The provided authorization grant (e.g., authorization " +
			"code, resource owner credentials) or refresh token is " +
			"invalid, expired, revoked, does not match the redirection " +
			"URI used in the authorization request, or was issued to " +
			"another client.",
		RFC_6749_ERROR_RESPONSE_URI,
		http.StatusBadRequest,
	}
	b.setCode(result)
	return b
}

func (b *oAuthErrorBuilder) InvalidScope() OAuthErrorBuilder {
	result := OAuthError{
		"invalid_scope",
		"The requested scope is invalid, unknown, malformed, or " +
			"exceeds the scope granted by the resource owner.",
		RFC_6749_ERROR_RESPONSE_URI,
		http.StatusBadRequest,
	}
	b.setCode(result)
	return b
}

func (b *oAuthErrorBuilder) setCode(err OAuthError) {
	b.Code = err.Code
	if len(b.Description) == 0 {
		b.Description = err.Description
	}
	if len(b.Uri) == 0 {
		b.Uri = err.Uri
	}
	if b.Status == 0 {
		b.Status = err.Status
	}
}

func (b *oAuthErrorBuilder) SetError(err error) OAuthErrorBuilder {
	b.Description = err.Error()
	return b
}

func (b *oAuthErrorBuilder) SetDescription(desc string) OAuthErrorBuilder {
	b.Description = desc
	return b
}

func (b *oAuthErrorBuilder) SetStatus(status int) OAuthErrorBuilder {
	b.Status = status
	return b
}

func (b *oAuthErrorBuilder) SetUri(uri string) OAuthErrorBuilder {
	b.Uri = uri
	return b
}

func (b *oAuthErrorBuilder) UnauthorizedClient() OAuthErrorBuilder {
	result := OAuthError{
		"unauthorized_client",
		"The authenticated client is not authorized to use this " +
			"authorization grant type.",
		RFC_6749_ERROR_RESPONSE_URI,
		http.StatusBadRequest,
	}
	b.setCode(result)
	return b
}

func (b *oAuthErrorBuilder) UnsupportedGrantType() OAuthErrorBuilder {
	result := OAuthError{
		"unsupported_grant_type",
		"The authorization grant type is not supported by the " +
			"authorization server.",
		RFC_6749_ERROR_RESPONSE_URI,
		http.StatusBadRequest,
	}
	b.setCode(result)
	return b
}
