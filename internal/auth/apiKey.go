package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoApiKey = errors.New("api key missing")
var ErrInvalidApiKey = errors.New("invalid api key")

func GetApiKey(headers http.Header) (string, error) {
	value := headers.Get("Authorization")
	if strings.TrimSpace(value) == "" {
		return "", ErrNoAuthHeader
	}

	const prefix = "ApiKey "
	if !strings.HasPrefix(value, prefix) {
		return "", ErrInvalidAuthHeader
	}

	key := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	if key == "" {
		return "", ErrInvalidAuthHeader
	}

	return key, nil
}
