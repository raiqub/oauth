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

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// A TokenContext represents an object to pass variables between TokenHandler
// and TokenProvider methods.
type TokenContext struct {
	*gin.Context
	GrantType string
	Client    *ClientEntry
	Scope     string
	State     string
	Username  string
	Password  string
}

// NewTokenContext creates a new instance of TokenContext.
func NewTokenContext(c *gin.Context) *TokenContext {
	return &TokenContext{
		c,
		c.PostForm("grant_type"),
		nil,
		c.PostForm("scope"),
		c.PostForm("state"),
		c.PostForm("username"),
		c.PostForm("password"),
	}
}

// ScopeList returns scope split by its spaces.
func (s TokenContext) ScopeList() []string {
	return strings.Split(s.Scope, " ")
}
