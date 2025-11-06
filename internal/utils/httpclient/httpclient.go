package httpclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"veo/internal/core/config"
	"veo/internal/core/logger"
	"veo/internal/core/useragent"
)

// ===========================================
// 接口定义
// ===========================================

// HTTPClientInterface HTTP客户端接口（通用HTTP客户端抽象）
type HTTPClientInterface interface {
	// MakeRequest 发起HTTP请求
	// 参数: rawURL - 目标URL
	// 返回: 响应体内容, 状态码, 错误信息
	MakeRequest(rawURL string) (body string, statusCode int, err error)
}

// ===========================================
// 配置结构
// ===========================================

// Config HTTP客户端配置结构
type Config struct {
	Timeout        time.Duration // 请求超时时间
	FollowRedirect bool          // 是否跟随重定向
	MaxRedirects   int           // 最大重定向次数
	UserAgent      string        // User-Agent
	SkipTLSVerify  bool          // 跳过TLS证书验证
	TLSTimeout     time.Duration // TLS握手超时
}

// DefaultConfig 获取默认HTTP客户端配置（安全扫描优化版）
func DefaultConfig() *Config {
	ua := useragent.Pick()
	if ua == "" {
		ua = "veo-HTTPClient/1.0"
	}

	return &Config{
		Timeout:        10 * time.Second,
		FollowRedirect: true, // 默认跟随重定向
		MaxRedirects:   5,    // 最大5次重定向
		UserAgent:      ua,
		SkipTLSVerify:  true,            // 网络安全扫描工具常用设置
		TLSTimeout:     5 * time.Second, // TLS握手超时
	}
}

// DefaultConfigWithUserAgent 获取带自定义UserAgent的默认HTTP客户端配置
func DefaultConfigWithUserAgent(userAgent string) *Config {
	config := DefaultConfig()
	if userAgent != "" {
		config.UserAgent = userAgent
	}
	return config
}

// ===========================================
// 通用HTTP客户端实现（支持TLS配置和重定向）
// ===========================================

// Client 通用HTTP客户端实现
// 支持配置化的重定向跟随和TLS配置功能
type Client struct {
	client         *http.Client
	followRedirect bool   // 是否跟随重定向
	maxRedirects   int    // 最大重定向次数
	userAgent      string // User-Agent
}

// New 创建配置化的HTTP客户端（支持TLS）
func New(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.SkipTLSVerify,
		ServerName:         "", // 允许IP地址连接
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}

	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        20,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
			MaxIdleConnsPerHost: 5,
			TLSClientConfig:     tlsConfig,
			TLSHandshakeTimeout: config.TLSTimeout,
		},
	}

	// 配置重定向策略
	if config.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("超过最大重定向次数: %d", config.MaxRedirects)
			}
			logger.Debugf("跟随重定向: %s -> %s", via[len(via)-1].URL.String(), req.URL.String())
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Client{
		client:         client,
		followRedirect: config.FollowRedirect,
		maxRedirects:   config.MaxRedirects,
		userAgent:      config.UserAgent,
	}
}

// MakeRequest 实现HTTPClientInterface接口，支持TLS和重定向
func (c *Client) MakeRequest(rawURL string) (body string, statusCode int, err error) {
	logger.Debugf("发起请求: %s (跟随重定向: %v)", rawURL, c.followRedirect)

	// 创建请求
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	c.setRequestHeaders(req)

	// 发起请求
	resp, err := c.client.Do(req)
	if err != nil {
		return "", 0, c.handleRequestError(err)
	}
	defer resp.Body.Close()

	// 处理重定向响应
	if c.isRedirectResponse(resp.StatusCode) && !c.followRedirect {
		logger.Debugf("检测到重定向响应 %d，但未启用跟随: %s", resp.StatusCode, rawURL)
	}

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("读取响应体失败: %v", err)
	}

	logger.Debugf("请求完成: %s [%d] 响应体: %d bytes", rawURL, resp.StatusCode, len(respBody))
	return string(respBody), resp.StatusCode, nil
}

// ===========================================
// 辅助方法
// ===========================================

// setRequestHeaders 设置标准请求头（包括全局自定义头部）
func (c *Client) setRequestHeaders(req *http.Request) {
	// 设置标准请求头
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	// [新增] 为指纹识别添加自定义Cookie头
	req.Header.Set("Cookie", "rememberMe=deleteMe;")

	// 应用全局配置中的自定义头部（如学习到的认证头部）
	c.applyCustomHeaders(req)
}

// applyCustomHeaders 应用全局配置中的自定义HTTP头部
func (c *Client) applyCustomHeaders(req *http.Request) {
	// 从全局配置获取自定义头部
	customHeaders := config.GetCustomHeaders()

	if len(customHeaders) > 0 {
		// 应用自定义头部到请求
		for key, value := range customHeaders {
			req.Header.Set(key, value)
		}

		logger.Debugf("应用了 %d 个自定义HTTP头部: %s", len(customHeaders), req.URL.String())

		// 记录应用的头部（调试用）
		for key, value := range customHeaders {
			// 对敏感信息进行遮蔽显示
			maskedValue := c.maskSensitiveValue(value)
			logger.Debugf("自定义头部: %s = %s", key, maskedValue)
		}
	} else {
		logger.Debugf("未发现自定义HTTP头部: %s", req.URL.String())
	}
}

// maskSensitiveValue 遮蔽敏感值用于日志输出
func (c *Client) maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}

	// 显示前4个和后4个字符，中间用*代替
	prefix := value[:4]
	suffix := value[len(value)-4:]
	middle := strings.Repeat("*", len(value)-8)

	return prefix + middle + suffix
}

// handleRequestError 处理请求错误（统一TLS错误处理）
func (c *Client) handleRequestError(err error) error {
	errStr := err.Error()
	if strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:") {
		return fmt.Errorf("TLS连接失败 (可能需要跳过证书验证): %v", err)
	}
	return fmt.Errorf("请求失败: %v", err)
}

// isRedirectResponse 检查是否为重定向响应
func (c *Client) isRedirectResponse(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}
