package fingerprint

import (
	"net/http"
	"testing"
)

func TestDSLParser_ContainsURL(t *testing.T) {
	parser := NewDSLParser()

	// 创建测试上下文
	ctx := &DSLContext{
		Response: &HTTPResponse{
			URL:        "http://example.com/hiveuserCtr/freshWebCode",
			StatusCode: 200,
			Title:      "索贝融媒体系统",
			Server:     "Apache",
		},
		Headers: make(http.Header),
		Body:    "test body content",
		URL:     "http://example.com/hiveuserCtr/freshWebCode",
		Method:  "GET",
	}

	// 测试用例
	testCases := []struct {
		name     string
		dsl      string
		expected bool
	}{
		{
			name:     "索贝融媒体系统URL匹配",
			dsl:      "contains(url, 'hiveuserCtr/freshWebCode')",
			expected: true,
		},
		{
			name:     "URL部分匹配",
			dsl:      "contains(url, 'example.com')",
			expected: true,
		},
		{
			name:     "URL不匹配",
			dsl:      "contains(url, 'notfound')",
			expected: false,
		},
		{
			name:     "URL大小写不敏感",
			dsl:      "contains(url, 'EXAMPLE.COM')",
			expected: true,
		},
		{
			name:     "验证其他参数仍正常工作 - body",
			dsl:      "contains(body, 'test')",
			expected: true,
		},
		{
			name:     "验证其他参数仍正常工作 - title",
			dsl:      "contains(title, '索贝')",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parser.EvaluateDSL(tc.dsl, ctx)
			if result != tc.expected {
				t.Errorf("DSL: %s, 预期: %v, 实际: %v", tc.dsl, tc.expected, result)
			}
		})
	}
}

func TestDSLParser_ContainsMultipleTexts(t *testing.T) {
	parser := NewDSLParser()

	// 创建测试上下文
	headers := make(http.Header)
	headers.Set("Server", "Apache/2.4.41")
	headers.Set("Content-Type", "text/html")

	ctx := &DSLContext{
		Response: &HTTPResponse{
			URL:        "http://example.com/test",
			StatusCode: 200,
			Title:      "Test Page Title",
			Server:     "Apache/2.4.41",
		},
		Headers: headers,
		Body:    "This is a test body with some content and keywords like admin, login, dashboard",
		URL:     "http://example.com/test",
		Method:  "GET",
	}

	// 测试用例
	testCases := []struct {
		name     string
		dsl      string
		expected bool
	}{
		{
			name:     "多个文本匹配 - 第一个匹配",
			dsl:      "contains(body, 'admin', 'notfound')",
			expected: true,
		},
		{
			name:     "多个文本匹配 - 第二个匹配",
			dsl:      "contains(body, 'notfound', 'login')",
			expected: true,
		},
		{
			name:     "多个文本匹配 - 多个都匹配",
			dsl:      "contains(body, 'admin', 'login', 'dashboard')",
			expected: true,
		},
		{
			name:     "多个文本匹配 - 都不匹配",
			dsl:      "contains(body, 'notfound1', 'notfound2', 'notfound3')",
			expected: false,
		},
		{
			name:     "多个文本匹配 - 单个文本（保持兼容性）",
			dsl:      "contains(body, 'admin')",
			expected: true,
		},
		{
			name:     "多个文本匹配 - header中匹配",
			dsl:      "contains(header, 'Apache', 'notfound')",
			expected: true,
		},
		{
			name:     "多个文本匹配 - title中匹配",
			dsl:      "contains(title, 'Test', 'notfound')",
			expected: true,
		},
		{
			name:     "多个文本匹配 - server中匹配",
			dsl:      "contains(server, 'Apache', 'notfound')",
			expected: true,
		},
		{
			name:     "多个文本匹配 - url中匹配",
			dsl:      "contains(url, 'example.com', 'notfound')",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parser.EvaluateDSL(tc.dsl, ctx)
			if result != tc.expected {
				t.Errorf("DSL: %s, 预期: %v, 实际: %v", tc.dsl, tc.expected, result)
			}
		})
	}
}
