package httpclient

import (
	"crypto/tls"
	"time"

	"github.com/valyala/fasthttp"
)

// ClientFactory HTTP客户端工厂
type ClientFactory struct {
	defaultTLSConfig *tls.Config
}

// NewClientFactory 创建HTTP客户端工厂
func NewClientFactory() *ClientFactory {
	return &ClientFactory{
		defaultTLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "",
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
	}
}

// CreateStandardClient 创建标准HTTP客户端（基于net/http）
func (f *ClientFactory) CreateStandardClient(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}
	return New(config)
}

// Deprecated: CreateFasthttpClient 当前未被调用；建议统一通过 requests 内部的 createFastHTTPClient 构造。
// CreateFasthttpClient 创建fasthttp客户端
func (f *ClientFactory) CreateFasthttpClient(config *Config) *fasthttp.Client {
	if config == nil {
		config = DefaultConfig()
	}

	return &fasthttp.Client{
		TLSConfig:           f.defaultTLSConfig,
		ReadTimeout:         config.Timeout,
		WriteTimeout:        config.Timeout,
		MaxConnDuration:     30 * time.Second,
		MaxIdleConnDuration: 5 * time.Second,
		MaxConnsPerHost:     100,
		// MaxIdleConnsPerHost 字段在fasthttp中不存在，已移除
	}
}

// CreateClientWithUserAgent 创建带自定义UserAgent的客户端
func (f *ClientFactory) CreateClientWithUserAgent(userAgent string) *Client {
	config := DefaultConfigWithUserAgent(userAgent)
	return f.CreateStandardClient(config)
}

// GetDefaultTLSConfig 获取默认TLS配置
func (f *ClientFactory) GetDefaultTLSConfig() *tls.Config {
	return f.defaultTLSConfig.Clone()
}

// 全局工厂实例
var globalFactory = NewClientFactory()

// GetGlobalFactory 获取全局HTTP客户端工厂实例
func GetGlobalFactory() *ClientFactory {
	return globalFactory
}

// CreateClient 便捷函数：使用全局工厂创建标准客户端
func CreateClient(config *Config) *Client {
	return globalFactory.CreateStandardClient(config)
}

// CreateClientWithUserAgent 便捷函数：使用全局工厂创建带UserAgent的客户端
func CreateClientWithUserAgent(userAgent string) *Client {
	return globalFactory.CreateClientWithUserAgent(userAgent)
}

// Deprecated: CreateFasthttpClient 便捷函数当前未被调用。
// CreateFasthttpClient 便捷函数：使用全局工厂创建fasthttp客户端
func CreateFasthttpClient(config *Config) *fasthttp.Client {
	return globalFactory.CreateFasthttpClient(config)
}
