package redirect

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"veo/internal/core/interfaces"
	"veo/internal/utils/shared"
)

// HTTPFetcher 定义最小化HTTP客户端接口，供重定向跟随使用。
type HTTPFetcher interface {
	MakeRequest(rawURL string) (body string, statusCode int, err error)
}

// HTTPFetcherFull 扩展的HTTP客户端接口，支持返回响应头。
type HTTPFetcherFull interface {
	MakeRequestFull(rawURL string) (body string, statusCode int, headers map[string][]string, err error)
}

// FollowClientRedirect 检测并跟随客户端（HTML/JS）重定向，返回新的HTTP响应。
// 若未检测到重定向或获取失败，返回nil。
func FollowClientRedirect(response *interfaces.HTTPResponse, fetcher HTTPFetcher) (*interfaces.HTTPResponse, error) {
	if response == nil || fetcher == nil {
		return nil, nil
	}

	redirectBody := response.ResponseBody
	if redirectBody == "" {
		redirectBody = response.Body
	}
	if strings.TrimSpace(redirectBody) == "" {
		return nil, nil
	}

	redirectURL := DetectClientRedirectURL(redirectBody)
	if redirectURL == "" {
		return nil, nil
	}

	absoluteURL := ResolveRedirectURL(response.URL, redirectURL)
	if absoluteURL == "" {
		return nil, fmt.Errorf("无法解析客户端重定向URL: %s", redirectURL)
	}

	var body string
	var statusCode int
	var headers map[string][]string
	var err error

	if fullFetcher, ok := fetcher.(HTTPFetcherFull); ok {
		body, statusCode, headers, err = fullFetcher.MakeRequestFull(absoluteURL)
	} else {
		body, statusCode, err = fetcher.MakeRequest(absoluteURL)
	}

	if err != nil {
		return nil, fmt.Errorf("跟随客户端重定向失败: %w", err)
	}
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("客户端重定向响应为空: %s", absoluteURL)
	}

	titleExtractor := shared.NewTitleExtractor()
	title := titleExtractor.ExtractTitle(body)

	redirected := &interfaces.HTTPResponse{
		URL:             absoluteURL,
		Method:          "GET",
		StatusCode:      statusCode,
		Body:            body,
		ResponseBody:    body,
		ContentType:     "",
		ContentLength:   int64(len(body)),
		Length:          int64(len(body)),
		Title:           title,
		ResponseHeaders: headers,
		IsDirectory:     strings.HasSuffix(absoluteURL, "/"),
	}

	return redirected, nil
}

// DetectClientRedirectURL 检测HTML/JS中的客户端重定向URL。
func DetectClientRedirectURL(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}

	// Matches: <meta http-equiv="refresh" content="0;url=http://example.com">
	// Also handles attribute swapping: <meta content="0;url=..." http-equiv="refresh">
	// Strategy: Find <meta ...> tag, then check if it contains http-equiv="refresh" (or 'refresh') and extract url from content.
	// Since regex for unordered attributes is complex, we use a two-step approach or a more generic one.
	// Simplified approach: Look for <meta ... content="..." ...> where content contains "url=".
	// We also need to ensure it's a refresh meta tag.

	// Try standard order first
	metaRe1 := regexp.MustCompile(`(?is)<meta\s+[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)`)
	if m := metaRe1.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}

	// Try swapped order (content first)
	metaRe2 := regexp.MustCompile(`(?is)<meta\s+[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)['"][^>]*http-equiv\s*=\s*['"]?refresh['"]?`)
	if m := metaRe2.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}

	// Fallback: minimal match for content="...url=..." without strict http-equiv check (risky but effective for broken HTML)
	// Only if it looks like a refresh tag context
	metaRe3 := regexp.MustCompile(`(?is)<meta\s+[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)`)
	if m := metaRe3.FindStringSubmatch(body); len(m) >= 2 {
		// Verify it's likely a refresh tag by checking for "refresh" keyword in the tag
		// fullTag := m[0] // Note: this might not capture the full tag if regex is partial, but context is key.
		// Actually, let's just check if "refresh" appears in the vicinity if we want to be strict.
		// For now, let's trust url= inside a meta content is likely a redirect.
		return strings.TrimSpace(m[1])
	}

	// JavaScript redirection extraction
	jsPatterns := []string{
		// location = "..."
		`(?is)(?:window\.|self\.|top\.|parent\.|)location(?:\.href)?\s*=\s*['"]([^'"]+)['"]`,
		// location.replace("...")
		`(?is)(?:window\.|self\.|top\.|parent\.|)location\.replace\(\s*['"]([^'"]+)['"]\s*\)`,
		// location.assign("...")
		`(?is)(?:window\.|self\.|top\.|parent\.|)location\.assign\(\s*['"]([^'"]+)['"]\s*\)`,
	}

	for _, pat := range jsPatterns {
		re := regexp.MustCompile(pat)
		if m := re.FindStringSubmatch(body); len(m) >= 2 {
			return strings.TrimSpace(m[1])
		}
	}

	return ""
}

// ResolveRedirectURL 将相对/协议相对URL解析为绝对地址。
func ResolveRedirectURL(baseRaw, ref string) string {
	ref = strings.TrimSpace(ref)
	if baseRaw == "" || ref == "" {
		return ""
	}

	base, err := url.Parse(baseRaw)
	if err != nil {
		return ""
	}

	if strings.HasPrefix(ref, "//") {
		ref = base.Scheme + ":" + ref
	}

	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}

	return base.ResolveReference(u).String()
}
