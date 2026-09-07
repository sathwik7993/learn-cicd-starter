package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantKey       string
		wantErr       error
		wantErrString string
	}{
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey valid-api-key-123"},
			},
			wantKey: "valid-api-key-123",
			wantErr: nil,
		},
		{
			name:    "no authorization header included",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed authorization header - wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			wantKey:       "",
			wantErrString: "malformed authorization header",
		},
		{
			name: "malformed authorization header - missing key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:       "",
			wantErrString: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if tt.wantErrString != "" {
				if err == nil || err.Error() != tt.wantErrString {
					t.Fatalf("expected error %q, got %v", tt.wantErrString, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
