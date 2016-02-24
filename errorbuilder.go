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

// An ErrorBuilder provides methods to construct a new Error.
type ErrorBuilder interface {
	// Build creates and returns a new Error.
	Build() Error

	// InvalidRequest sets current error to invalid request error.
	InvalidRequest() ErrorBuilder

	// InvalidClient sets current error to invalid client error.
	InvalidClient() ErrorBuilder

	// InvalidClientCredentials sets current error to invalid client
	// credentials error.
	InvalidClientCredentials() ErrorBuilder

	// InvalidGrant sets current error to invalid grant error.
	InvalidGrant() ErrorBuilder

	// InvalidRefreshToken sets current error to invalid refresh token error.
	InvalidRefreshToken() ErrorBuilder

	// InvalidScope sets current error to invalid scope error.
	InvalidScope() ErrorBuilder

	// InvalidUserCredential sets current error to invalid user credentials
	// error.
	InvalidUserCredentials(username string) ErrorBuilder

	// MissingClientCredentials sets current error to missing client
	// credentials error.
	MissingClientCredentials() ErrorBuilder

	// SetDescription sets the description for current error.
	SetDescription(string) ErrorBuilder

	// SetStatus sets the HTTP status for current error.
	SetStatus(int) ErrorBuilder

	// SetUri sets the URI for current error.
	SetURI(string) ErrorBuilder

	// UnauthorizedClient sets current error to unauthorized client error.
	UnauthorizedClient() ErrorBuilder

	// UnsupportedGrantType sets current error to unsupported grant type error.
	UnsupportedGrantType() ErrorBuilder
}

type errorBuilder struct {
	Error
}

// NewError creates a new instance of ErrorBuilder.
func NewError() ErrorBuilder {
	return &errorBuilder{Error{}}
}

func (b *errorBuilder) Build() Error {
	return b.Error
}

func (b *errorBuilder) InvalidClient() ErrorBuilder {
	b.setCode(CodeInvalidClient)
	return b
}

func (b *errorBuilder) InvalidClientCredentials() ErrorBuilder {
	b.Code = CodeInvalidClient
	b.Description = "Client authentication failed"
	b.Status = codeStatus[CodeInvalidClient]

	return b
}

func (b *errorBuilder) InvalidGrant() ErrorBuilder {
	b.setCode(CodeInvalidGrant)
	return b
}

func (b *errorBuilder) InvalidRefreshToken() ErrorBuilder {
	b.Code = CodeInvalidGrant
	b.Description = "The refresh token is invalid, expired, revoked, does " +
		"not match the redirection URI used in the authorization request, or " +
		"was issued to another client"
	b.Status = codeStatus[CodeInvalidGrant]

	return b
}

func (b *errorBuilder) InvalidRequest() ErrorBuilder {
	b.setCode(CodeInvalidRequest)
	return b
}

func (b *errorBuilder) InvalidScope() ErrorBuilder {
	b.setCode(CodeInvalidScope)
	return b
}

func (b *errorBuilder) InvalidUserCredentials(username string) ErrorBuilder {
	b.Code = CodeInvalidGrant
	b.Description = fmt.Sprintf("Invalid credential for '%s'", username)
	b.Status = codeStatus[CodeInvalidGrant]

	return b
}

func (b *errorBuilder) MissingClientCredentials() ErrorBuilder {
	b.Code = CodeInvalidClient
	b.Description =
		"The client must authenticate but no credentials are provided"
	b.Status = codeStatus[CodeInvalidClient]

	return b
}

func (b *errorBuilder) setCode(code string) {
	b.Code = code
	if len(b.Description) == 0 {
		b.Description = description[code]
	}
	if b.Status == 0 {
		b.Status = codeStatus[code]
	}
}

func (b *errorBuilder) SetDescription(desc string) ErrorBuilder {
	b.Description = desc
	return b
}

func (b *errorBuilder) SetStatus(status int) ErrorBuilder {
	b.Status = status
	return b
}

func (b *errorBuilder) SetURI(uri string) ErrorBuilder {
	b.URI = uri
	return b
}

func (b *errorBuilder) UnauthorizedClient() ErrorBuilder {
	b.setCode(CodeUnauthorizedClient)
	return b
}

func (b *errorBuilder) UnsupportedGrantType() ErrorBuilder {
	b.setCode(CodeUnsupportedGrantType)
	return b
}
