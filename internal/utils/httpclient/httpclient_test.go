package httpclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPClientRedirectFollowing(t *testing.T) {
	// 创建测试服务器链：Server1 -> Server2 -> Server3
	server3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Final destination"))
	}))
	defer server3.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server3.URL, http.StatusFound)
	}))
	defer server2.Close()

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server2.URL, http.StatusFound)
	}))
	defer server1.Close()

	tests := []struct {
		name           string
		followRedirect bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "跟随重定向",
			followRedirect: true,
			expectedStatus: 200,
			expectedBody:   "Final destination",
		},
		{
			name:           "不跟随重定向",
			followRedirect: false,
			expectedStatus: 302,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Timeout:        5 * time.Second,
				FollowRedirect: tt.followRedirect,
				MaxRedirects:   5,
				UserAgent:      "Test-Agent",
				SkipTLSVerify:  true,
				TLSTimeout:     3 * time.Second,
			}
			client := New(config)

			body, statusCode, err := client.MakeRequest(server1.URL)
			if err != nil {
				t.Fatalf("请求失败: %v", err)
			}

			if statusCode != tt.expectedStatus {
				t.Errorf("期望状态码 %d，实际得到 %d", tt.expectedStatus, statusCode)
			}

			if tt.followRedirect && body != tt.expectedBody {
				t.Errorf("期望响应体 %q，实际得到 %q", tt.expectedBody, body)
			}
		})
	}
}

func TestHTTPClientMaxRedirects(t *testing.T) {
	// 创建无限重定向的服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}))
	defer server.Close()

	config := &Config{
		Timeout:        5 * time.Second,
		FollowRedirect: true,
		MaxRedirects:   2, // 限制最大重定向次数
		UserAgent:      "Test-Agent",
		SkipTLSVerify:  true,
		TLSTimeout:     3 * time.Second,
	}
	client := New(config)

	_, _, err := client.MakeRequest(server.URL)
	if err == nil {
		t.Error("期望超过最大重定向次数时返回错误")
	}
}

func TestHTTPClientDefaultConfig(t *testing.T) {
	client := New(nil) // 使用默认配置

	if client.followRedirect != true {
		t.Error("默认配置应该启用重定向跟随")
	}

	if client.maxRedirects != 5 {
		t.Errorf("默认最大重定向次数应该是5，实际得到 %d", client.maxRedirects)
	}
}

func TestHTTPClientTLSConfiguration(t *testing.T) {
	// 创建使用自签名证书的HTTPS测试服务器
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("TLS response"))
	}))
	defer server.Close()

	tests := []struct {
		name          string
		skipTLSVerify bool
		expectError   bool
	}{
		{
			name:          "跳过TLS验证",
			skipTLSVerify: true,
			expectError:   false,
		},
		{
			name:          "启用TLS验证（自签名证书应该失败）",
			skipTLSVerify: false,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Timeout:        5 * time.Second,
				FollowRedirect: true,
				MaxRedirects:   5,
				UserAgent:      "Test-Agent",
				SkipTLSVerify:  tt.skipTLSVerify,
				TLSTimeout:     3 * time.Second,
			}
			client := New(config)

			_, _, err := client.MakeRequest(server.URL)

			if tt.expectError && err == nil {
				t.Error("期望TLS验证失败时返回错误")
			}

			if !tt.expectError && err != nil {
				t.Errorf("期望TLS请求成功，但得到错误: %v", err)
			}
		})
	}
}

func TestHTTPClientTLSTimeout(t *testing.T) {
	config := &Config{
		Timeout:        5 * time.Second,
		FollowRedirect: true,
		MaxRedirects:   5,
		UserAgent:      "Test-Agent",
		SkipTLSVerify:  true,
		TLSTimeout:     1 * time.Nanosecond, // 极短的超时时间
	}
	client := New(config)

	// 验证TLS超时配置是否正确设置
	if transport, ok := client.client.Transport.(*http.Transport); ok {
		if transport.TLSHandshakeTimeout != config.TLSTimeout {
			t.Errorf("TLS握手超时设置错误，期望 %v，实际 %v",
				config.TLSTimeout, transport.TLSHandshakeTimeout)
		}

		if transport.TLSClientConfig.InsecureSkipVerify != config.SkipTLSVerify {
			t.Error("TLS跳过验证设置错误")
		}
	} else {
		t.Error("无法获取HTTP传输层配置")
	}
}
