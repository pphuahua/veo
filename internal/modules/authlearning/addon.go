package authlearning

import (
	"sync"
	"veo/internal/core/config"
	"veo/internal/core/logger"
	"veo/internal/utils/auth"
	"veo/proxy"
)

// AuthLearningAddon 认证学习插件 - 在代理模式下自动学习传入请求中的Authorization头部
type AuthLearningAddon struct {
	proxy.BaseAddon
	detector    *auth.AuthDetector // 认证检测器
	enabled     bool               // 是否启用认证学习
	mu          sync.RWMutex       // 读写锁
	learnedAuth map[string]string  // 本次会话学习到的Authorization头部
}

// NewAuthLearningAddon 创建认证学习插件
func NewAuthLearningAddon() *AuthLearningAddon {
	return &AuthLearningAddon{
		detector:    auth.NewAuthDetector(),
		enabled:     true,
		learnedAuth: make(map[string]string),
	}
}

// SetEnabled 设置是否启用认证学习
func (ala *AuthLearningAddon) SetEnabled(enabled bool) {
	ala.mu.Lock()
	defer ala.mu.Unlock()

	ala.enabled = enabled
	if enabled {
		logger.Info("Authorization头部学习功能已启用")
	} else {
		logger.Info("Authorization头部学习功能已禁用")
	}
}

// IsEnabled 检查是否启用认证学习
func (ala *AuthLearningAddon) IsEnabled() bool {
	ala.mu.RLock()
	defer ala.mu.RUnlock()
	return ala.enabled
}

// Requestheaders 实现proxy.Addon接口，在请求头阶段学习Authorization认证信息
func (ala *AuthLearningAddon) Requestheaders(f *proxy.Flow) {
	if !ala.IsEnabled() {
		return
	}

	// 检查是否已经设置了CLI自定义头部
	if config.HasCustomHeaders() {
		logger.Debug("检测到CLI自定义头部，跳过认证学习")
		return
	}

	// 从请求中学习Authorization头部
	url := f.Request.URL.String()
	authHeaders := ala.detector.LearnFromRequest(f.Request.Raw(), url)

	if len(authHeaders) > 0 {
		ala.mu.Lock()
		// 更新本次会话学习到的Authorization头部
		for key, value := range authHeaders {
			ala.learnedAuth[key] = value
		}
		ala.mu.Unlock()

		// 将学习到的Authorization头部应用到全局配置
		ala.applyLearnedAuthToGlobalConfig(authHeaders)

		logger.Infof("Get Authorization Sucess")
	}
}

// applyLearnedAuthToGlobalConfig 将学习到的Authorization头部应用到全局配置
func (ala *AuthLearningAddon) applyLearnedAuthToGlobalConfig(authHeaders map[string]string) {
	// 获取当前的全局自定义头部
	currentHeaders := config.GetCustomHeaders()

	// 合并学习到的Authorization头部
	mergedHeaders := make(map[string]string)

	// 先复制现有的头部
	for key, value := range currentHeaders {
		mergedHeaders[key] = value
	}

	// 添加新学习到的Authorization头部（如果不存在的话）
	newHeadersCount := 0
	for key, value := range authHeaders {
		if _, exists := mergedHeaders[key]; !exists {
			mergedHeaders[key] = value
			newHeadersCount++
		}
	}

	// 更新全局配置
	if newHeadersCount > 0 {
		config.SetCustomHeaders(mergedHeaders)
		logger.Debugf("应用了 %d 个新的Authorization头部到全局配置", newHeadersCount)
	}
}

// GetLearnedAuth 获取本次会话学习到的Authorization头部
func (ala *AuthLearningAddon) GetLearnedAuth() map[string]string {
	ala.mu.RLock()
	defer ala.mu.RUnlock()

	result := make(map[string]string)
	for key, value := range ala.learnedAuth {
		result[key] = value
	}
	return result
}

// ClearLearnedAuth 清空学习到的Authorization头部
func (ala *AuthLearningAddon) ClearLearnedAuth() {
	ala.mu.Lock()
	defer ala.mu.Unlock()

	ala.learnedAuth = make(map[string]string)
	ala.detector.ClearDetectedSchemes()
	logger.Info("已清空学习到的Authorization头部")
}

// HasLearnedAuth 检查是否学习到了Authorization头部
func (ala *AuthLearningAddon) HasLearnedAuth() bool {
	ala.mu.RLock()
	defer ala.mu.RUnlock()
	return len(ala.learnedAuth) > 0
}

// GetDetector 获取认证检测器（用于测试）
func (ala *AuthLearningAddon) GetDetector() *auth.AuthDetector {
	return ala.detector
}
