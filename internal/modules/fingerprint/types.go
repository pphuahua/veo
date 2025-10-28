package fingerprint

import (
	"net/http"
	"sync"
	"time"
)

// ===========================================
// 核心类型定义
// ===========================================

// HTTPClientInterface 已移动到 internal/utils/httpclient 包
// 这里保留注释供参考，实际定义在 httpclient_adapter.go 中作为类型别名

// FingerprintRule 指纹识别规则
type FingerprintRule struct {
	ID        string   `yaml:"-"`                   // 规则ID（从YAML key生成）
	Name      string   `yaml:"-"`                   // 规则名称（从YAML key生成）
	DSL       []string `yaml:"dsl"`                 // DSL表达式列表
	Condition string   `yaml:"condition,omitempty"` // 条件逻辑 (and/or，默认or)
	Category  string   `yaml:"category,omitempty"`  // 分类（可选）
	Path      string   `yaml:"path,omitempty"`      // [重要] 新增：主动探测路径
}

// FingerprintMatch 指纹匹配结果
type FingerprintMatch struct {
	URL        string    `json:"url"`               // 匹配的URL
	RuleName   string    `json:"rule_name"`         // 匹配的规则名称
	Technology string    `json:"technology"`        // 识别的技术栈
	DSLMatched string    `json:"dsl_matched"`       // 匹配的DSL表达式
	Timestamp  time.Time `json:"timestamp"`         // 匹配时间
	Snippet    string    `json:"snippet,omitempty"` // 匹配内容片段
}

// HTTPResponse 响应数据结构（简化版，独立于其他模块）
type HTTPResponse struct {
	URL           string              `json:"url"`
	Method        string              `json:"method"`
	StatusCode    int                 `json:"status_code"`
	Headers       map[string][]string `json:"headers"`
	Body          string              `json:"body"`
	ContentType   string              `json:"content_type"`
	ContentLength int64               `json:"content_length"`
	Server        string              `json:"server"`
	Title         string              `json:"title"`
}

// EngineConfig 引擎配置（优化版，移除未使用字段）
type EngineConfig struct {
	RulesPath       string `yaml:"rules_path"`       // 规则文件路径
	MaxConcurrency  int    `yaml:"max_concurrency"`  // 最大并发数
	EnableFiltering bool   `yaml:"enable_filtering"` // 是否启用文件过滤
	MaxBodySize     int    `yaml:"max_body_size"`    // 最大响应体大小
	LogMatches      bool   `yaml:"log_matches"`      // 是否记录匹配日志
}

// Engine 指纹识别引擎
type Engine struct {
	config                   *EngineConfig
	rules                    map[string]*FingerprintRule // 规则映射表
	matches                  []*FingerprintMatch         // 匹配结果
	dslParser                *DSLParser                  // DSL解析器
	mu                       sync.RWMutex                // 读写锁
	stats                    *Statistics                 // 统计信息
	outputCache              map[string]bool             // 已输出指纹的域名缓存
	outputMutex              sync.RWMutex                // 输出缓存的读写锁
	iconCache                map[string]string           // 图标缓存：URL->MD5哈希值
	iconMutex                sync.RWMutex                // 图标缓存的读写锁
	staticExtensions         []string
	staticContentTypes       []string
	staticFileFilterEnabled  bool
	contentTypeFilterEnabled bool
	showSnippet              bool
}

// Statistics 统计信息
type Statistics struct {
	TotalRequests    int64     `json:"total_requests"`    // 总请求数
	MatchedRequests  int64     `json:"matched_requests"`  // 匹配的请求数
	FilteredRequests int64     `json:"filtered_requests"` // 过滤的请求数
	RulesLoaded      int       `json:"rules_loaded"`      // 加载的规则数
	StartTime        time.Time `json:"start_time"`        // 启动时间
	LastMatchTime    time.Time `json:"last_match_time"`   // 最后匹配时间
}

// DSLContext DSL表达式上下文（增强版，支持主动探测）
type DSLContext struct {
	Response   *HTTPResponse
	Headers    http.Header
	Body       string
	URL        string
	Method     string
	HTTPClient interface{} // HTTP客户端（用于icon()函数主动探测）- 临时使用interface{}
	BaseURL    string      // 基础URL（协议+主机，用于构造完整图标路径）
	Engine     *Engine     // 引擎实例（用于访问图标缓存）
}

// DSLParser DSL解析器
type DSLParser struct {
}

// ===========================================
// 静态文件过滤相关
// ===========================================

var (
	// StaticFileExtensions 静态文件扩展名
	StaticFileExtensions = []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
		".css", ".woff", ".woff2", ".ttf", ".eot",
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
	}

	// StaticContentTypes 静态内容类型
	StaticContentTypes = []string{
		"video/",
		"audio/",
		"application/zip",
		"application/x-rar-compressed",
		"application/x-7z-compressed",
		"application/pdf",
		"application/msword",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
	}
)
