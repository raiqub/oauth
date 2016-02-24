package oauth

import "net/http"

const (
	RFC6749ErrorResponseURI = "http://tools.ietf.org/html/rfc6749#section-5.2"
)

const (
	CodeInvalidClient        = "invalid_client"
	CodeInvalidGrant         = "invalid_grant"
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidScope         = "invalid_scope"
	CodeUnauthorizedClient   = "unauthorized_client"
	CodeUnsupportedGrantType = "unsupported_grant_type"
)

var description = map[string]string{
	CodeInvalidClient: "Client authentication failed (e.g., unknown client, " +
		"no client authentication included, or unsupported authentication " +
		"method).",
	CodeInvalidGrant: "The provided authorization grant (e.g., authorization " +
		"code, resource owner credentials) or refresh token is invalid, " +
		"expired, revoked, does not match the redirection URI used in the " +
		"authorization request, or was issued to another client.",
	CodeInvalidRequest: "The request is missing a required parameter, " +
		"includes an unsupported parameter value (other than grant type), " +
		"repeats a parameter, includes multiple credentials, utilizes more " +
		"than one mechanism for authenticating the client, or is otherwise " +
		"malformed.",
	CodeInvalidScope: "The requested scope is invalid, unknown, malformed, " +
		"or exceeds the scope granted by the resource owner.",
	CodeUnauthorizedClient: "The authenticated client is not authorized to " +
		"use this authorization grant type.",
	CodeUnsupportedGrantType: "The authorization grant type is not supported " +
		"by the authorization server.",
}

var codeStatus = map[string]int{
	CodeInvalidClient:        http.StatusUnauthorized,
	CodeInvalidGrant:         http.StatusBadRequest,
	CodeInvalidRequest:       http.StatusBadRequest,
	CodeInvalidScope:         http.StatusBadRequest,
	CodeUnauthorizedClient:   http.StatusBadRequest,
	CodeUnsupportedGrantType: http.StatusBadRequest,
}

func ErrorDescription(code string) string {
	return description[code]
}

func ErrorStatus(code string) int {
	return codeStatus[code]
}
