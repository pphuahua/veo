package config

import (
	"veo/internal/core/logger"
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config 全局配置结构体
type Config struct {
	Server ServerConfig `yaml:"server"`
	Module ModuleConfig `yaml:"module"` // 修正拼写错误: modle -> module
	Hosts  HostsConfig  `yaml:"hosts"`
	Addon  AddonConfig  `yaml:"addon"`
	Log    LogConfig    `yaml:"log"` // 新增：日志配置
}

// ModuleConfig 模块配置
type ModuleConfig struct {
	Dirscan     bool `yaml:"dirscan"`
	Fingerprint bool `yaml:"fingerprint"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Listen string `yaml:"listen"`
}

// HostsConfig 主机过滤配置
type HostsConfig struct {
	Allow  []string `yaml:"allow"`
	Reject []string `yaml:"reject"`
}

// LogConfig 日志配置结构体
type LogConfig struct {
	Level       string `yaml:"level"`        // 日志级别
	ColorOutput bool   `yaml:"color_output"` // 彩色输出
}

// AddonConfig 插件配置
type AddonConfig struct {
	Filter    FilterConfig    `yaml:"filter"`
	Collector CollectorConfig `yaml:"collector"`
	Request   RequestConfig   `yaml:"request"`
	Content   ContentConfig   `yaml:"content"`
	Proxy     ProxyConfig     `yaml:"proxy"`
	Report    ReportConfig    `yaml:"report"`
}

// FilterConfig 过滤器配置
type FilterConfig struct {
	Enable                bool  `yaml:"enable"`
	Hash                  bool  `yaml:"hash"`
	ValidStatusCodes      []int `yaml:"ValidStatusCodes"`
	HashFilterStatusCodes []int `yaml:"hash_filter_status_codes"`
	FilterTolerance       int64 `yaml:"filter_tolerance"` // 相似页面过滤容错阈值（字节）
}

// CollectorConfig 收集器配置
type CollectorConfig struct {
	GenerationStatusCodes []int        `yaml:"GenerationStatusCodes"`
	Static                StaticConfig `yaml:"static"`
}

// StaticConfig 静态资源配置
type StaticConfig struct {
	Path       []string `yaml:"path"`
	Extensions []string `yaml:"extensions"`
}

// RequestConfig 请求配置
type RequestConfig struct {
	Timeout             int      `yaml:"timeout"` // 统一超时配置，对所有模块生效
	Retry               int      `yaml:"retry"`   // 重试次数
	UserAgents          []string `yaml:"user_agents"`
	Depth               int      `yaml:"depth"`   // 递归扫描深度
	Threads             int      `yaml:"threads"` // 统一并发控制，对所有模块生效
	KeepAliveSeconds    int      `yaml:"keep_alive_seconds"`
	RandomUA            *bool    `yaml:"randomUA"`               // 保留，processor包中被使用
	MaxResponseBodySize int      `yaml:"max_response_body_size"` // [重要] 内存优化：响应体大小限制
}

// ContentConfig 内容生成配置
type ContentConfig struct {
	Enable     bool   `yaml:"enable"`
	Common     string `yaml:"common"`
	API        string `yaml:"api"`
	Files      string `yaml:"files"`
	FilesDict  bool   `yaml:"files_dict"`  // 保留，dirscan模块中被使用
	CommonDict bool   `yaml:"common_dict"` // 保留，可能被使用
	APIDict    bool   `yaml:"api_dict"`    // 保留，可能被使用
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	UpstreamProxy   string `yaml:"upstream_proxy"`
	StreamLargebody int64  `yaml:"stream_largebody"`
	SSLInsecure     bool   `yaml:"ssl_insecure"`
	ConnectTimeout  int    `yaml:"connect_timeout"`
	ReadTimeout     int    `yaml:"read_timeout"`
}

// ReportConfig 报告配置
type ReportConfig struct {
	FileName    string `yaml:"file_name"`    // 文件名（不含扩展名）
	MaxBodysize int    `yaml:"max_bodysize"` // 最大响应体大小（字符数）
}

// 全局配置实例
var GlobalConfig *Config

// LoadConfig 加载配置文件
func LoadConfig(configPath string) (*Config, error) {
	logger.Debug("[config.go] 开始加载配置文件: ", configPath)

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析YAML配置
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 验证配置
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	// 设置全局配置
	GlobalConfig = &config

	logger.Debug("[config.go] 配置文件加载成功")
	logConfigSummary(&config)

	return &config, nil
}

// validateConfig 验证配置文件
func validateConfig(config *Config) error {
	// 验证服务器配置
	if config.Server.Listen == "" {
		return fmt.Errorf("服务器监听地址不能为空")
	}

	// 验证请求配置
	if config.Addon.Request.Timeout <= 0 {
		return fmt.Errorf("请求超时时间必须大于0")
	}

	// 验证字典文件路径
	if config.Addon.Content.Enable {
		if config.Addon.Content.Common == "" {
			return fmt.Errorf("通用字典文件路径不能为空")
		}

		// 检查字典文件是否存在
		if _, err := os.Stat(config.Addon.Content.Common); os.IsNotExist(err) {
			logger.Warn("[config.go] 通用字典文件不存在: ", config.Addon.Content.Common)
		}
	}

	// 验证代理配置
	if config.Addon.Proxy.ConnectTimeout <= 0 {
		return fmt.Errorf("代理连接超时时间必须大于0")
	}

	if config.Addon.Proxy.ReadTimeout <= 0 {
		return fmt.Errorf("代理读取超时时间必须大于0")
	}

	return nil
}

// logConfigSummary 打印配置摘要
func logConfigSummary(config *Config) {
	logger.Debug("[config.go] 配置摘要:")
	logger.Debug("[config.go]   收集器状态码: ", config.Addon.Collector.GenerationStatusCodes)
}

// InitConfig 初始化配置（自动查找配置文件）
func InitConfig() error {
	// 尝试多个可能的配置文件路径
	configPaths := []string{
		"config.yaml",
		"./configs/config.yaml",
		"./config.yaml",
	}

	for _, configPath := range configPaths {
		if _, err := os.Stat(configPath); err == nil {
			_, err := LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("加载配置文件 %s 失败: %v", configPath, err)
			}
			return nil
		}
	}

	return fmt.Errorf("未找到配置文件，请确保存在以下文件之一: %v", configPaths)
}

// GetConfig 获取全局配置
func GetConfig() *Config {
	if GlobalConfig == nil {
		// 尝试自动初始化配置
		if err := InitConfig(); err != nil {
			logger.Fatal("[config.go] 配置未初始化且自动初始化失败: ", err)
		}
	}
	return GlobalConfig
}

// GetServerConfig 获取服务器配置
func GetServerConfig() *ServerConfig {
	return &GetConfig().Server
}

// GetHostsConfig 获取主机配置
func GetHostsConfig() *HostsConfig {
	return &GetConfig().Hosts
}

// GetFilterConfig 获取过滤器配置
func GetFilterConfig() *FilterConfig {
	return &GetConfig().Addon.Filter
}

// GetCollectorConfig 获取收集器配置（保留，collector包中被使用）
func GetCollectorConfig() *CollectorConfig {
	return &GetConfig().Addon.Collector
}

// GetRequestConfig 获取请求配置（保留，processor包中被使用）
func GetRequestConfig() *RequestConfig {
	return &GetConfig().Addon.Request
}

// GetlogConfig 获取日志配置
func GetlogConfig() *LogConfig {
	config := GetConfig()
	if config == nil {
		// 返回默认日志配置
		return &LogConfig{
			Level:       "info",
			ColorOutput: true,
		}
	}
	return &config.Log
}

// GetContentConfig 获取内容配置（保留，CLI中被使用）
func GetContentConfig() *ContentConfig {
	return &GetConfig().Addon.Content
}

// GetProxyConfig 获取代理配置（保留，CLI中被使用）
func GetProxyConfig() *ProxyConfig {
	return &GetConfig().Addon.Proxy
}

// GetReportConfig 获取报告配置（保留，reporter包中被使用）
func GetReportConfig() *ReportConfig {
	return &GetConfig().Addon.Report
}

// IsHostAllowed 检查主机是否被允许
func IsHostAllowed(host string) bool {
	config := GetHostsConfig()

	// 检查拒绝列表
	for _, reject := range config.Reject {
		if matchPattern(host, reject) {
			return false
		}
	}

	// 检查允许列表
	if len(config.Allow) == 0 {
		return true // 如果没有允许列表，默认允许所有
	}

	for _, allow := range config.Allow {
		if matchPattern(host, allow) {
			return true
		}
	}

	return false
}

// matchPattern 简单的模式匹配（支持通配符*）
func matchPattern(text, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if !strings.Contains(pattern, "*") {
		return text == pattern
	}

	// 简单的通配符匹配
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		// *example*
		middle := pattern[1 : len(pattern)-1]
		return strings.Contains(text, middle)
	} else if strings.HasPrefix(pattern, "*") {
		// *example
		suffix := pattern[1:]
		return strings.HasSuffix(text, suffix)
	} else if strings.HasSuffix(pattern, "*") {
		// example*
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(text, prefix)
	}

	return text == pattern
}

// GetModuleConfig 获取模块配置
func GetModuleConfig() ModuleConfig {
	return GlobalConfig.Module
}

// ============================================================================
// CLI集成功能（原integration.go内容）
// ============================================================================

// CLIOverrides CLI参数覆盖结构体
type CLIOverrides struct {
	Hosts   []string // 主机白名单覆盖
	Modules []string // 模块覆盖
	Port    *int     // 端口覆盖 (使用指针以区分零值和未设置)
}

// ApplyCLIOverrides 应用CLI参数覆盖到全局配置
// 优先级: CLI参数 > config.yaml配置文件
func ApplyCLIOverrides(cliOverrides *CLIOverrides) error {
	if cliOverrides == nil {
		logger.Debug("[config.go] 没有CLI覆盖参数")
		return nil
	}

	logger.Info("[config.go] 正在应用CLI参数覆盖...")

	// 应用主机白名单覆盖
	if err := applyHostOverrides(cliOverrides.Hosts); err != nil {
		return fmt.Errorf("应用主机覆盖失败: %v", err)
	}

	// 应用模块覆盖
	if err := applyModuleOverrides(cliOverrides.Modules); err != nil {
		return fmt.Errorf("应用模块覆盖失败: %v", err)
	}

	// 应用端口覆盖
	if err := applyPortOverride(cliOverrides.Port); err != nil {
		return fmt.Errorf("应用端口覆盖失败: %v", err)
	}

	logger.Info("[config.go] CLI参数覆盖应用完成")
	return nil
}

// applyHostOverrides 应用主机白名单覆盖
func applyHostOverrides(hosts []string) error {
	if len(hosts) == 0 {
		logger.Debug("[config.go] 未指定主机覆盖")
		return nil
	}

	// 备份原始配置
	originalHosts := make([]string, len(GlobalConfig.Hosts.Allow))
	copy(originalHosts, GlobalConfig.Hosts.Allow)

	// 应用CLI指定的主机列表
	GlobalConfig.Hosts.Allow = make([]string, len(hosts))
	copy(GlobalConfig.Hosts.Allow, hosts)

	logger.Info(fmt.Sprintf("[config.go] 主机白名单已覆盖: %s (原配置: %s)",
		strings.Join(hosts, ", "),
		strings.Join(originalHosts, ", ")))

	return nil
}

// applyModuleOverrides 应用模块覆盖
func applyModuleOverrides(modules []string) error {
	if len(modules) == 0 {
		logger.Debug("[config.go] 未指定模块覆盖")
		return nil
	}

	// 首先禁用所有模块
	resetAllModules()

	// 根据CLI参数启用指定模块
	for _, module := range modules {
		if err := enableModule(module); err != nil {
			return fmt.Errorf("启用模块 '%s' 失败: %v", module, err)
		}
	}

	logger.Info(fmt.Sprintf("[config.go] 模块配置已覆盖: %s", strings.Join(modules, ", ")))
	return nil
}

// applyPortOverride 应用端口覆盖
func applyPortOverride(port *int) error {
	if port == nil {
		logger.Debug("[config.go] 未指定端口覆盖")
		return nil
	}

	// 验证端口范围
	if *port <= 0 || *port > 65535 {
		return fmt.Errorf("端口必须在1-65535范围内，当前值: %d", *port)
	}

	// 备份原始配置
	originalAddr := GlobalConfig.Server.Listen

	// 应用新端口
	GlobalConfig.Server.Listen = fmt.Sprintf(":%d", *port)

	logger.Info(fmt.Sprintf("[config.go] 监听端口已覆盖: %d (原配置: %s)",
		*port, originalAddr))

	return nil
}

// resetAllModules 重置所有模块为禁用状态
func resetAllModules() {
	logger.Debug("[config.go] 重置所有模块状态为禁用")

	GlobalConfig.Module.Dirscan = false
	GlobalConfig.Module.Fingerprint = false
}

// enableModule 启用指定模块
func enableModule(module string) error {
	logger.Info(fmt.Sprintf("[config.go] 启用模块: %s", module))

	switch module {
	case "finger", "fingerprint":
		GlobalConfig.Module.Fingerprint = true
		logger.Debug("[config.go] 指纹识别模块已启用")
		return nil

	case "dirscan":
		GlobalConfig.Module.Dirscan = true
		logger.Debug("[config.go] 目录扫描模块已启用")
		return nil

	default:
		return fmt.Errorf("未知的模块: %s", module)
	}
}

// ===========================================
// HTTP认证头部全局管理
// ===========================================

// 全局变量存储自定义HTTP头部
var (
	globalCustomHeaders map[string]string
	customHeadersMutex  sync.RWMutex
)

// SetCustomHeaders 设置全局自定义HTTP头部
func SetCustomHeaders(headers map[string]string) {
	customHeadersMutex.Lock()
	defer customHeadersMutex.Unlock()

	globalCustomHeaders = make(map[string]string)
	for key, value := range headers {
		globalCustomHeaders[key] = value
	}

	logger.Debugf("[config] 设置全局自定义HTTP头部: %d 个", len(globalCustomHeaders))
}

// GetCustomHeaders 获取全局自定义HTTP头部
func GetCustomHeaders() map[string]string {
	customHeadersMutex.RLock()
	defer customHeadersMutex.RUnlock()

	if globalCustomHeaders == nil {
		return make(map[string]string)
	}

	headers := make(map[string]string)
	for key, value := range globalCustomHeaders {
		headers[key] = value
	}

	return headers
}

// HasCustomHeaders 检查是否设置了自定义HTTP头部
func HasCustomHeaders() bool {
	customHeadersMutex.RLock()
	defer customHeadersMutex.RUnlock()
	return len(globalCustomHeaders) > 0
}
