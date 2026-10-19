package main

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetTokenFromHeader(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedToken string
		expectedErr   error
	}{
		{
			name:          "standard Bearer token",
			authHeader:    "Bearer valid.jwt.token",
			expectedToken: "valid.jwt.token",
			expectedErr:   nil,
		},
		{
			name:          "case-insensitive bearer prefix",
			authHeader:    "bearer valid.jwt.token",
			expectedToken: "valid.jwt.token",
			expectedErr:   nil,
		},
		{
			name:          "Bearer with surrounding and multiple spaces",
			authHeader:    "   Bearer    spaced.jwt.token   ",
			expectedToken: "spaced.jwt.token",
			expectedErr:   nil,
		},
		{
			name:          "missing header",
			authHeader:    "",
			expectedToken: "",
			expectedErr:   ErrMissingToken,
		},
		{
			name:          "empty token after Bearer",
			authHeader:    "Bearer    ",
			expectedToken: "",
			expectedErr:   ErrMissingToken,
		},
		{
			name:          "non-bearer scheme (e.g. Basic)",
			authHeader:    "Basic dXNlcjpwYXNz",
			expectedToken: "",
			expectedErr:   ErrInvalidToken,
		},
		{
			name:          "arbitrary header value without Bearer prefix",
			authHeader:    "CustomToken123",
			expectedToken: "",
			expectedErr:   ErrInvalidToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/test", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			if tc.authHeader != "" {
				req.Header.Set(headerAuth, tc.authHeader)
			}

			token, err := getTokenFromHeader(req)
			if tc.expectedErr != nil {
				if !errors.Is(err, tc.expectedErr) {
					t.Fatalf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if token != tc.expectedToken {
					t.Fatalf("expected token %q, got %q", tc.expectedToken, token)
				}
			}
		})
	}
}
