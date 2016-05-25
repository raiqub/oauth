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

package http

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gopkg.in/raiqub/oauth.v2"
	"gopkg.in/raiqub/oauth.v2/oauthtest"
)

const (
	FormKeyCustom   = "my_key"
	FormValueCustom = "any_custom_value"
)

func TestClientGrant(t *testing.T) {
	adapter := oauthtest.NewTokenAdapter()
	srv := NewTokenServer(adapter, oauth.GrantTypeClient)
	adapter.CustomValues[FormKeyCustom] = []string{FormValueCustom}

	ts := httptest.NewServer(http.HandlerFunc(srv.AccessTokenRequest))
	defer ts.Close()

	client := &http.Client{}
	form := url.Values{
		oauth.FormKeyGrantType: []string{oauth.GrantTypeClient},
		oauth.FormKeyScope:     []string{adapter.Scope},
		FormKeyCustom:          []string{FormValueCustom},
	}
	req, _ := http.NewRequest(
		"POST", ts.URL, strings.NewReader(form.Encode()))
	req.SetBasicAuth(adapter.ClientID, adapter.ClientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error posting data to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Unexpected HTTP status: %s", resp.Status)
		strBody, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("Response body: %s", string(strBody))
	}

	var response oauth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}

	if response.AccessToken != adapter.AccessToken {
		t.Fatalf("Unexpected response: %#v", response)
	}
}
