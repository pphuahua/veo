package main

import (
	"fmt"
	"net/url"
	"strings"
)

func generateFingerprintCacheKey(rawURL string, fingerprintNames []string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	var builder strings.Builder
	builder.WriteString(parsedURL.Host)
	builder.WriteByte('|')
	builder.WriteString(parsedURL.Path)
	builder.WriteByte('|')

	if len(fingerprintNames) > 0 {
		builder.WriteString(fingerprintNames[0])
	}

	return builder.String()
}

func main() {
	u1 := "http://jenk.kkqd.vip/login?from=%2Ftrace"
	u2 := "http://jenk.kkqd.vip/login?from=%2Factuator%2FconfigurationMetadata"

	key1 := generateFingerprintCacheKey(u1, []string{"jenkins"})
	key2 := generateFingerprintCacheKey(u2, []string{"jenkins"})

	fmt.Printf("URL1: %s\nKey1: %s\n", u1, key1)
	fmt.Printf("URL2: %s\nKey2: %s\n", u2, key2)

	if key1 == key2 {
		fmt.Println("Keys are identical")
	} else {
		fmt.Println("Keys are DIFFERENT")
	}
}
