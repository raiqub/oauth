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

type (
	ClientEntry struct {
		ClientId          string   `bson:"_id" json:"client_id"`
		ClientSecret      string   `bson:"secret" json:"client_secret,omitempty"`
		ClientType        string   `bson:"type" json:"client_type"`
		RedirectUris      []string `bson:"redirs" json:"redirect_uris"`
		JavascriptOrigins []string `bson:"origins" json:"javascript_origins"`
		AllowedGrants     []string `bson:"grants" json:"allowed_grants"`
		AllowedScopes     []string `bson:"scopes" json:"allowed_scopes"`
	}
)
