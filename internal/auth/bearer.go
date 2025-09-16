package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoAuthHeader = errors.New("authorization header missing")
var ErrInvalidAuthHeader = errors.New("invalid authorization header")

func GetBearerToken(headers http.Header) (string, error) {
	value := headers.Get("Authorization")
	if strings.TrimSpace(value) == "" {
		return "", ErrNoAuthHeader
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return "", ErrInvalidAuthHeader
	}

	token := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	if token == "" {
		return "", ErrInvalidAuthHeader
	}

	return token, nil
}
