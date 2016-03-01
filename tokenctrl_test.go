package oauth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	AccessToken      = "UB736gpbpFp7hS8dNrUFZ7b6Aw2a3N0LI8RRddWO"
	ClientID         = "client_id"
	ClientSecret     = "client_secret"
	ListenerEndpoint = "/token"
	Scope            = "user.read"
	WaitTimeout      = time.Millisecond * 250
)

func TestClientGrant(t *testing.T) {
	config := TokenConfig{
		AccessToken: func(c *TokenContext) *TokenResponse {
			resp := NewTokenResponse(
				AccessToken,
				"bearer",
				3600,
				"",
				Scope,
				"CudYQpuw",
			)
			return &resp
		},
		Client: func(clientID, clientSecret string) *ClientEntry {
			if clientID != ClientID || clientSecret != ClientSecret {
				return nil
			}

			return &ClientEntry{
				clientID,
				clientSecret,
				"public",
				[]string{"http://client.example.com/callback"},
				[]string{"http://client.example.com"},
				[]string{GrantTypeClient},
				[]string{Scope},
			}
		},
		SupportedGrantTypes: []string{GrantTypeClient},
	}

	controller := NewTokenController(config)
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.RedirectTrailingSlash = true

	router.POST(ListenerEndpoint, controller.AccessTokenRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	client := &http.Client{}
	form := url.Values{
		"grant_type": []string{GrantTypeClient},
		"scope":      []string{Scope},
	}
	req, _ := http.NewRequest("POST", ts.URL+ListenerEndpoint,
		strings.NewReader(form.Encode()))
	req.SetBasicAuth(ClientID, ClientSecret)
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

	var response TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}

	if response.AccessToken != AccessToken {
		t.Fatalf("Unexpected response: %#v", response)
	}
}
