package ginhttp

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/raiqub/oauth"
)

// A TokenServer represents a gin-backed HTTP server for TokenService.
type TokenServer struct {
	svc *oauth.TokenService
}

// NewTokenServer creates a new instance of TokenServer.
func NewTokenServer(adapter oauth.TokenAdapter) *TokenServer {
	return &TokenServer{
		svc: oauth.NewTokenService(adapter),
	}
}

// AccessTokenRequest is a endpoint that receives a request to create a new
// access token.
func (s *TokenServer) AccessTokenRequest(c *gin.Context) {
	context := NewTokenContext(c)
	resp, jerr := s.svc.AccessTokenRequest(context)
	if jerr != nil {
		c.JSON(jerr.Status, jerr)
		return
	}

	// Disables HTTP caching on client and returns access token for client
	DisableCaching(c.Writer)
	c.JSON(http.StatusOK, *resp)
}

// DisableCaching disables HTTP caching on client.
func DisableCaching(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// NewTokenContext creates a new instance of TokenContext based on specified gin
// context.
func NewTokenContext(c *gin.Context) *oauth.TokenContext {
	var auth *oauth.BasicAuth
	username, password, ok := c.Request.BasicAuth()
	if ok {
		auth = &oauth.BasicAuth{
			Username: username,
			Password: password,
		}
	}

	return &oauth.TokenContext{
		GrantType:  c.PostForm(oauth.FormKeyGrantType),
		Scope:      c.PostForm(oauth.FormKeyScope),
		State:      c.PostForm(oauth.FormKeyState),
		Username:   c.PostForm(oauth.FormKeyUsername),
		Password:   c.PostForm(oauth.FormKeyPassword),
		ClientAuth: auth,
	}
}
