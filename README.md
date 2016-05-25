# oauth

Raiqub/oauth is a library for the [Go Programming Language][go]. It provides
an implementation of OAuth 2.0 features.

## Status

[![Build Status](https://travis-ci.org/raiqub/oauth.svg?branch=master)](https://travis-ci.org/raiqub/oauth)
[![GoDoc](https://godoc.org/github.com/raiqub/oauth?status.svg)](http://godoc.org/github.com/raiqub/oauth)

## Installation

To install raiqub/oauth library run the following command:

```bash
go get gopkg.in/raiqub/oauth.v2
```

To import this package, add the following line to your code:

```bash
import "gopkg.in/raiqub/oauth.v2"
```

## Usage

To create a server to handle token endpoint, as defined by OAuth 2.0 specification, an
adapter must be created to define the following operations: find a client, create new
access token, validate refresh token and validate user credentials.

To a type be qualified as an adapter must implements the [TokenAdapter][TokenAdapter]
methods. As shown by the example below:

```go
import (
	"gopkg.in/raiqub/oauth.v2"
	"gopkg.in/raiqub/slice.v1"
)

type MyAdapter struct {
	// Should has fields that allow database connection
}

// NewMyAdapter creates a new instance of MyAdapter.
func NewMyAdapter() *MyAdapter {
	return &MyAdapter{}
}

// FindClient gets the client information if valid.
func (a *MyAdapter) FindClient(c *oauth.TokenContext) *oauth.ClientEntry {
	// Should retrieve from database
	clientID, clientSecret := "example_client", "example_secret"
	clientScopes := []string{"profile.write", "calendar.read"}
	if c.HTTPUser != clientID ||
		c.HTTPSecret != clientSecret {
		return nil
	}

	return &oauth.ClientEntry{
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		ClientType:        "public",
		RedirectUris:      []string{"http://client.example.com/callback"},
		JavascriptOrigins: []string{"http://client.example.com"},
		AllowedGrants:     []string{oauth.GrantTypeClient},
		AllowedScopes:     clientScopes,
	}
}

// NewAccessToken creates and returns a new access token.
func (a *MyAdapter) NewAccessToken(c *oauth.TokenContext) *oauth.TokenResponse {
	// Should create an unique token (and state when applicable)
	resp := oauth.NewTokenResponse(
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"bearer",
		3600,
		"",
		"profile.write calendar.read",
		"CudYQpuw",
	)
	return &resp
}

// ValidateRefresh validate provided refresh token.
func (a *MyAdapter) ValidateRefresh(*oauth.TokenContext) bool {
	// Should validate provided refresh token
    // Use: c.RefreshToken
	return false
}

// ValidateUser validate resource owner credentials for password grant type.
func (a *MyAdapter) ValidateUser(c *oauth.TokenContext) bool {
	// Should validate provided user credentials
    // Use: c.Username and c.Password
	return false
}
```

Then you can use a [TokenServer][TokenServer] to handle token endpoint:

```Go
import (
	"net/http"

	"gopkg.in/raiqub/oauth.v2"
	httptransport "gopkg.in/raiqub/oauth.v2/transport/http"
)

svcToken := oauth.NewTokenService(NewMyAdapter(),
	// Accepts client_credentials and refresh_token
	oauth.GrantTypeClient, oauth.GrantTypeRefresh)
srvToken := httptransport.NewTokenServer(svcToken)

http.HandleFunc("/token", srvToken.AccessTokenRequest)
http.ListenAndServe(":8080", nil)
```

Optionally new grant types can be accepted. To do that you will need to create a function
that matchs [TokenHandlerFunc][TokenHandlerFunc] function and [SetHandler][SetHandler]
on server.

```Go
import "gopkg.in/raiqub/oauth.v2"

func MyHandler(adapter oauth.TokenAdapter, c *oauth.TokenContext,
) (*oauth.TokenResponse, *oauth.Error) {
	// Validates client authentication and authorization
	var oerr *oauth.Error
	c.Client, oerr = oauth.AuthClient(adapter, c)
	if oerr != nil {
		return nil, oerr
	}
	
	// You should implement here your logic
}
```

```Go
import (
	"net/http"

	"gopkg.in/raiqub/oauth.v2"
	httptransport "gopkg.in/raiqub/oauth.v2/transport/http"
)

svcToken := oauth.NewTokenService(NewMyAdapter(),
	// Accepts client_credentials and refresh_token
	oauth.GrantTypeClient, oauth.GrantTypeRefresh)

// Adds a custom handler
srvToken.SetHandler("urn:custom:myhandler", MyHandler)

srvToken := httptransport.NewTokenServer(svcToken)
http.HandleFunc("/token", srvToken.AccessTokenRequest)
http.ListenAndServe(":8080", nil)
```

For reference and examples browse [library documentation][doc].

## License

raiqub/oauth is made available under the [Apache Version 2.0 License][license].


[go]: http://golang.org/
[doc]: http://godoc.org/github.com/raiqub/oauth
[license]: http://www.apache.org/licenses/LICENSE-2.0
[TokenAdapter]: https://godoc.org/gopkg.in/raiqub/oauth.v2#TokenAdapter
[TokenServer]: https://godoc.org/gopkg.in/raiqub/oauth.v2/transport/http#TokenServer
[TokenHandlerFunc]: https://godoc.org/gopkg.in/raiqub/oauth.v2#TokenHandlerFunc
[SetHandler]: https://godoc.org/gopkg.in/raiqub/oauth.v2/transport/http#TokenServer.SetHandler
