package ginhttp

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/raiqub/oauth"
	"github.com/raiqub/oauth/oauthtest"
)

const (
	ListenerEndpoint = "/token"
)

func TestClientGrant(t *testing.T) {
	adapter := oauthtest.NewTokenAdapter()
	srv := NewTokenServer(adapter)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.RedirectTrailingSlash = true

	router.POST(ListenerEndpoint, srv.AccessTokenRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	client := &http.Client{}
	form := url.Values{
		"grant_type": []string{oauth.GrantTypeClient},
		"scope":      []string{adapter.Scope},
	}
	req, _ := http.NewRequest("POST", ts.URL+ListenerEndpoint,
		strings.NewReader(form.Encode()))
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
