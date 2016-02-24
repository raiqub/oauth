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

import (
	"fmt"
)

type OAuthErrorBuilder interface {
	Build() OAuthError
	InvalidRequest() OAuthErrorBuilder
	InvalidClient() OAuthErrorBuilder
	InvalidClientCredentials() OAuthErrorBuilder
	InvalidGrant() OAuthErrorBuilder
	InvalidRefreshToken() OAuthErrorBuilder
	InvalidScope() OAuthErrorBuilder
	InvalidUserCredential(username string) OAuthErrorBuilder
	MissingClientCredentials() OAuthErrorBuilder
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

func (b *oAuthErrorBuilder) InvalidClient() OAuthErrorBuilder {
	b.setCode(CodeInvalidClient)
	return b
}

func (b *oAuthErrorBuilder) InvalidClientCredentials() OAuthErrorBuilder {
	b.Code = CodeInvalidClient
	b.Description = "Client authentication failed"
	b.Status = codeStatus[CodeInvalidClient]

	return b
}

func (b *oAuthErrorBuilder) InvalidGrant() OAuthErrorBuilder {
	b.setCode(CodeInvalidGrant)
	return b
}

func (b *oAuthErrorBuilder) InvalidRefreshToken() OAuthErrorBuilder {
	b.Code = CodeInvalidGrant
	b.Description = "The refresh token is invalid, expired, revoked, does " +
		"not match the redirection URI used in the authorization request, or " +
		"was issued to another client"
	b.Status = codeStatus[CodeInvalidGrant]

	return b
}

func (b *oAuthErrorBuilder) InvalidRequest() OAuthErrorBuilder {
	b.setCode(CodeInvalidRequest)
	return b
}

func (b *oAuthErrorBuilder) InvalidScope() OAuthErrorBuilder {
	b.setCode(CodeInvalidScope)
	return b
}

func (b *oAuthErrorBuilder) InvalidUserCredential(username string) OAuthErrorBuilder {
	b.Code = CodeInvalidGrant
	b.Description = fmt.Sprintf("Invalid credential for '%s'", username)
	b.Status = codeStatus[CodeInvalidGrant]

	return b
}

func (b *oAuthErrorBuilder) MissingClientCredentials() OAuthErrorBuilder {
	b.Code = CodeInvalidClient
	b.Description =
		"The client must authenticate but no credentials are provided"
	b.Status = codeStatus[CodeInvalidClient]

	return b
}

func (b *oAuthErrorBuilder) setCode(code string) {
	b.Code = code
	if len(b.Description) == 0 {
		b.Description = description[code]
	}
	if b.Status == 0 {
		b.Status = codeStatus[code]
	}
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
	b.setCode(CodeUnauthorizedClient)
	return b
}

func (b *oAuthErrorBuilder) UnsupportedGrantType() OAuthErrorBuilder {
	b.setCode(CodeUnsupportedGrantType)
	return b
}
