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

import "fmt"

const (
	RFC_6749_ERROR_RESPONSE_URI = "http://tools.ietf.org/html/rfc6749#section-5.2"
)

type InvalidCredential string

func (e InvalidCredential) Error() string {
	return fmt.Sprintf("Invalid credential for '%s'", string(e))
}

type MissingClientId int

func (e MissingClientId) Error() string {
	return fmt.Sprint("The client_id must be specified")
}

type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	Uri         string `json:"error_uri,omitempty"`

	// HTTP status code.
	Status int `json:"-"`
}

func (e OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}
