package config

import "time"

// ConfigProvider 配置提供者接口，用于依赖注入
type ConfigProvider interface {
	// 获取基础配置
	GetTimeout() time.Duration
	GetMaxConcurrent() int
	GetMaxRetries() int
	GetDelay() time.Duration

	// 获取网络配置
	GetConnectTimeout() time.Duration
	GetFollowRedirect() bool
	GetMaxRedirects() int
	GetSkipTLSVerify() bool

	// 获取用户代理配置
	GetUserAgent() string
	GetRandomUserAgent() bool
	GetUserAgents() []string

	// 获取过滤配置
	IsFilterEnabled() bool
	GetValidStatusCodes() []int
	IsHashFilterEnabled() bool

	// 获取内容配置
	IsContentEnabled() bool
	GetCommonDict() string
	GetAPIDict() string
	GetFilesDict() string

	// 获取代理配置
	GetUpstreamProxy() string
	GetStreamLargeBody() int64
	IsSSLInsecure() bool

	// 获取报告配置
	GetReportOutputDir() string
	GetReportFileName() string

	// 获取日志配置
	GetLogLevel() string
	IsColorOutputEnabled() bool
}

// RequestConfigProvider 请求配置提供者接口
type RequestConfigProvider interface {
	GetTimeout() time.Duration
	GetMaxConcurrent() int
	GetMaxRetries() int
	GetDelay() time.Duration
	GetConnectTimeout() time.Duration
	GetFollowRedirect() bool
	GetMaxRedirects() int
	GetRandomUserAgent() bool
	GetUserAgents() []string
	GetMaxResponseBodySize() int64
}

// FilterConfigProvider 过滤器配置提供者接口
type FilterConfigProvider interface {
	IsEnabled() bool
	GetValidStatusCodes() []int
	IsHashFilterEnabled() bool
	GetHashFilterStatusCodes() []int
}

// CollectorConfigProvider 收集器配置提供者接口
type CollectorConfigProvider interface {
	GetDictGenerationStatusCodes() []int
	GetStaticExtensions() []string
	GetStaticContentTypes() []string
}

// ContentConfigProvider 内容配置提供者接口
type ContentConfigProvider interface {
	IsEnabled() bool
	GetCommonDict() string
	GetAPIDict() string
	GetFilesDict() string
	IsFilesDictFuzzEnabled() bool
	IsCommonDictFuzzEnabled() bool
	IsAPIDictFuzzEnabled() bool
}

// ProxyConfigProvider 代理配置提供者接口
type ProxyConfigProvider interface {
	GetUpstreamProxy() string
	GetStreamLargeBody() int64
	IsSSLInsecure() bool
	GetConnectTimeoutSeconds() int
	GetReadTimeoutSeconds() int
}

// ReportConfigProvider 报告配置提供者接口
type ReportConfigProvider interface {
	GetOutputDir() string
	GetFileName() string
	IsIncludeBody() bool
	GetMaxBodySize() int
}

// LogConfigProvider 日志配置提供者接口
type LogConfigProvider interface {
	GetLevel() string
	IsColorOutputEnabled() bool
}

// ModuleConfigProvider 模块配置提供者接口
type ModuleConfigProvider interface {
	IsDirscanEnabled() bool
	IsFingerprintEnabled() bool
	IsHAEEnabled() bool
}

// HostsConfigProvider 主机配置提供者接口
type HostsConfigProvider interface {
	GetAllowedHosts() []string
	GetRejectedHosts() []string
	IsHostAllowed(host string) bool
}

// ServerConfigProvider 服务器配置提供者接口
type ServerConfigProvider interface {
	GetListenAddr() string
}

// ConfigFactory 配置工厂接口
type ConfigFactory interface {
	// 创建各种配置提供者
	CreateRequestConfigProvider() RequestConfigProvider
	CreateFilterConfigProvider() FilterConfigProvider
	CreateCollectorConfigProvider() CollectorConfigProvider
	CreateContentConfigProvider() ContentConfigProvider
	CreateProxyConfigProvider() ProxyConfigProvider
	CreateReportConfigProvider() ReportConfigProvider
	CreateLogConfigProvider() LogConfigProvider

	CreateModuleConfigProvider() ModuleConfigProvider
	CreateHostsConfigProvider() HostsConfigProvider
	CreateServerConfigProvider() ServerConfigProvider

	// 创建通用配置提供者
	CreateConfigProvider() ConfigProvider
}
