package redirect

import (
	"testing"
	"fmt"
)

func TestDetectClientRedirectURL_Complex(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "User Case 403",
			body:     `<html><head><meta http-equiv='refresh' content='1;url=/login?from=%2Fv1.7%2Fswagger-ui.html'/><script>window.location.replace('/login?from=%2Fv1.7%2Fswagger-ui.html');</script></head><body style='background-color:white; color:white;'>`,
			expected: "/login?from=%2Fv1.7%2Fswagger-ui.html",
		},
		{
			name:     "Attribute Order Swapped",
			body:     `<html><head><meta content='1;url=/swapped' http-equiv='refresh'/></head>`,
			expected: "/swapped",
		},
		{
			name:     "Whitespace variations",
			body:     `<html><meta http-equiv = "refresh" content = "0; url=http://example.com/whitespace" /></html>`,
			expected: "http://example.com/whitespace",
		},
		{
			name:     "No Quotes in content url",
			body:     `<meta http-equiv="refresh" content="0;url=http://example.com/noquotes">`,
			expected: "http://example.com/noquotes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectClientRedirectURL(tt.body)
			if result != tt.expected {
				t.Errorf("DetectClientRedirectURL() = '%v', want '%v'", result, tt.expected)
			} else {
				fmt.Printf("[PASS] %s: %s\n", tt.name, result)
			}
		})
	}
}

