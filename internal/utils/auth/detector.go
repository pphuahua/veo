package auth

import (
	"veo/internal/core/logger"
	"net/http"
	"strings"
)

// AuthDetector 认证检测器
type AuthDetector struct {
	detectedSchemes map[string]string // 检测到的认证方案
	enabled         bool              // 是否启用自动检测
}

// NewAuthDetector 创建认证检测器
func NewAuthDetector() *AuthDetector {
	return &AuthDetector{
		detectedSchemes: make(map[string]string),
		enabled:         true,
	}
}

// SetEnabled 设置是否启用自动检测
func (ad *AuthDetector) SetEnabled(enabled bool) {
	ad.enabled = enabled
	if !enabled {
		logger.Debug("自动认证检测已禁用")
	} else {
		logger.Debug("自动认证检测已启用")
	}
}

// IsEnabled 检查是否启用自动检测
func (ad *AuthDetector) IsEnabled() bool {
	return ad.enabled
}

// DetectAuthRequirements 从HTTP响应中检测认证要求
func (ad *AuthDetector) DetectAuthRequirements(resp *http.Response, url string) map[string]string {
	if !ad.enabled {
		return nil
	}

	authHeaders := make(map[string]string)

	// 只处理401和403响应
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		return authHeaders
	}

	logger.Debugf("检测到认证响应: %s [%d]", url, resp.StatusCode)

	// 检测响应中提示的自定义认证头部
	// 某些API会在401/403响应中通过特定头部提示需要的认证方式
	customAuthHints := ad.detectCustomAuthHeadersFromResponse(resp)
	for headerName := range customAuthHints {
		// 标记需要该头部，但值为空（需要用户提供）
		authHeaders[headerName] = ""
		logger.Debugf("检测到需要自定义认证头部: %s (需要用户提供)", headerName)
	}

	// 检测Set-Cookie中的认证信息
	for _, cookie := range resp.Cookies() {
		if ad.isAuthCookie(cookie.Name) {
			cookieValue := cookie.Name + "=" + cookie.Value
			if existing := authHeaders["Cookie"]; existing != "" {
				authHeaders["Cookie"] = existing + "; " + cookieValue
			} else {
				authHeaders["Cookie"] = cookieValue
			}
			logger.Debugf("发现认证Cookie: %s", cookieValue)
		}
	}

	// 记录检测到的认证方案
	for key, value := range authHeaders {
		ad.detectedSchemes[key] = value
	}

	if len(authHeaders) > 0 {
		logger.Debugf("检测到 %d 个认证头部", len(authHeaders))
	}

	return authHeaders
}

// LearnFromRequest 从HTTP请求中学习Authorization认证信息（被动代理模式）
func (ad *AuthDetector) LearnFromRequest(req *http.Request, url string) map[string]string {
	if !ad.enabled {
		return nil
	}

	authHeaders := make(map[string]string)
	logger.Debugf("开始从请求中学习认证头部: %s", url)

	// 检测Authorization头部
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		authHeaders["Authorization"] = authHeader
		logger.Debugf("学习到Authorization头部: %s", ad.maskSensitiveValue(authHeader))

		// 解析Authorization类型
		authType := ad.parseAuthorizationType(authHeader)
		if authType != "" {
			logger.Debugf("识别认证类型: %s", authType)
		}

		// 记录学习到的认证方案到全局存储
		ad.detectedSchemes["Authorization"] = authHeader
		logger.Debugf("从请求中学习到Authorization头部")
	}

	// [新增] 检测自定义认证头部（如 X-Access-Token 等）
	customAuthHeaders := ad.detectCustomAuthHeaders(req)
	for headerName, headerValue := range customAuthHeaders {
		authHeaders[headerName] = headerValue
		ad.detectedSchemes[headerName] = headerValue
		logger.Debugf("学习到自定义认证头部: %s = %s", headerName, ad.maskSensitiveValue(headerValue))
	}

	if len(authHeaders) == 0 {
		logger.Debug("请求中未发现认证头部")
	}

	return authHeaders
}

// detectCustomAuthHeaders 检测自定义认证头部（如 X-Access-Token 等）
func (ad *AuthDetector) detectCustomAuthHeaders(req *http.Request) map[string]string {
	customHeaders := make(map[string]string)

	// 遍历所有请求头部，查找自定义认证头部
	for headerName, headerValues := range req.Header {
		if ad.isCustomAuthHeader(headerName) && len(headerValues) > 0 {
			// 使用第一个值（通常只有一个值）
			customHeaders[headerName] = headerValues[0]
		}
	}

	return customHeaders
}

// detectCustomAuthHeadersFromResponse 从HTTP响应中检测自定义认证头部提示
func (ad *AuthDetector) detectCustomAuthHeadersFromResponse(resp *http.Response) map[string]bool {
	customHeaders := make(map[string]bool)

	// 检查响应头中是否有提示需要特定认证头部的信息
	// 例如：X-Required-Auth: X-Access-Token
	if requiredAuth := resp.Header.Get("X-Required-Auth"); requiredAuth != "" {
		if ad.isCustomAuthHeader(requiredAuth) {
			customHeaders[requiredAuth] = true
			logger.Debugf("响应提示需要认证头部: %s", requiredAuth)
		}
	}

	// 检查响应体中的错误信息（某些API会在错误信息中提示需要的头部）
	// 注意：这里只是标记可能需要的头部，实际值需要用户提供
	// 可以根据实际需求扩展此逻辑

	return customHeaders
}

// isCustomAuthHeader 检测是否为自定义认证头部
func (ad *AuthDetector) isCustomAuthHeader(headerName string) bool {
	// 自定义认证头部列表（大小写不敏感）
	customAuthHeaderNames := []string{
		"x-access-token",  // 常见的自定义token头部
		"x-api-key",       // API密钥头部
		"x-auth-token",    // 自定义认证token
		"x-csrf-token",    // CSRF token头部
		"x-xsrf-token",    // XSRF token头部
		"x-session-token", // 会话token头部
		"x-user-token",    // 用户token头部
		"api-key",         // API密钥（无x-前缀）
		"apikey",          // API密钥（无分隔符）
		"access-token",    // 访问token（无x-前缀）
		"auth-token",      // 认证token（无x-前缀）
		"session-token",   // 会话token（无x-前缀）
		"user-token",      // 用户token（无x-前缀）
	}

	headerNameLower := strings.ToLower(headerName)
	for _, authHeaderName := range customAuthHeaderNames {
		if headerNameLower == authHeaderName {
			return true
		}
	}
	return false
}

// isAuthCookie 检测是否为认证相关的Cookie
func (ad *AuthDetector) isAuthCookie(name string) bool {
	authCookieNames := []string{
		"session", "sessionid", "sid", "jsessionid", "phpsessid",
		"auth", "token", "jwt", "access_token", "csrf_token",
		"csrftoken", "xsrf_token", "xsrf-token", "csrf-token",
		"laravel_session", "connect.sid", "express.sid",
		"aspnet_sessionid", "asp.net_sessionid", "viewstate",
		"login", "user", "userid", "username", "remember",
		"ticket", "saml", "oauth", "bearer", "api_key", "apikey",
	}

	name = strings.ToLower(name)
	for _, authName := range authCookieNames {
		if strings.Contains(name, authName) {
			return true
		}
	}
	return false
}

// GetDetectedSchemes 获取已检测到的认证方案
func (ad *AuthDetector) GetDetectedSchemes() map[string]string {
	schemes := make(map[string]string)
	for key, value := range ad.detectedSchemes {
		schemes[key] = value
	}
	return schemes
}

// ClearDetectedSchemes 清空已检测到的认证方案
func (ad *AuthDetector) ClearDetectedSchemes() {
	ad.detectedSchemes = make(map[string]string)
	logger.Debug("已清空检测到的认证方案")
}

// HasDetectedSchemes 检查是否有检测到的认证方案
func (ad *AuthDetector) HasDetectedSchemes() bool {
	return len(ad.detectedSchemes) > 0
}

// LogDetectionSummary 记录检测摘要
func (ad *AuthDetector) LogDetectionSummary() {
	if !ad.enabled {
		logger.Debug("自动认证检测已禁用")
		return
	}

	if len(ad.detectedSchemes) == 0 {
		logger.Debug("未检测到认证要求")
		return
	}

	logger.Debugf("检测摘要: 发现 %d 种认证方案", len(ad.detectedSchemes))
	for scheme, value := range ad.detectedSchemes {
		if value != "" {
			logger.Debugf("  %s: %s", scheme, value)
		} else {
			logger.Debugf("  %s: (需要用户提供)", scheme)
		}
	}
}

// parseAuthorizationType 解析Authorization头部的认证类型
func (ad *AuthDetector) parseAuthorizationType(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	parts := strings.Fields(authHeader)
	if len(parts) > 0 {
		authType := strings.ToLower(parts[0])
		switch authType {
		case "bearer":
			return "Bearer Token"
		case "basic":
			return "Basic Authentication"
		case "digest":
			return "Digest Authentication"
		case "jwt":
			return "JWT Token"
		case "oauth":
			return "OAuth Token"
		default:
			return strings.Title(authType)
		}
	}
	return ""
}

// maskSensitiveValue 遮蔽敏感值用于日志输出
func (ad *AuthDetector) maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}

	// 显示前4个和后4个字符，中间用*代替
	prefix := value[:4]
	suffix := value[len(value)-4:]
	middle := strings.Repeat("*", len(value)-8)

	return prefix + middle + suffix
}
