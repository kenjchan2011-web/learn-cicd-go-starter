package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedErr   error
		errorContains string // For dynamic errors created with errors.New
	}{
		{
			name:        "Valid ApiKey header",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "Missing Authorization header",
			headers:     http.Header{},
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed header - no space",
			headers:       http.Header{"Authorization": []string{"ApiKey-secret"}},
			errorContains: "malformed authorization header",
		},
		{
			name:          "Malformed header - wrong prefix",
			headers:       http.Header{"Authorization": []string{"Bearer some-token"}},
			errorContains: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// 1. Check for specific sentinel errors
			if tt.expectedErr != nil {
				if !errors.Is(err, tt.expectedErr) {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
				return
			}

			// 2. Check for dynamic error messages
			if tt.errorContains != "" {
				if err == nil || err.Error() != tt.errorContains {
					t.Errorf("expected error to contain %q, got %v", tt.errorContains, err)
				}
				return
			}

			// 3. Check for success cases
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
