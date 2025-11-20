package interfaces

import "veo/pkg/types"

// ===========================================
// 核心业务接口定义
// ===========================================

// URLCollectorInterface URL采集器接口
// 负责URL的收集、存储和管理
type URLCollectorInterface interface {
	// 获取收集的URL映射表
	GetURLMap() map[string]int
	// 获取收集的URL数量
	GetURLCount() int
}

// RequestProcessorInterface 请求处理器接口
// 负责处理HTTP请求和响应
type RequestProcessorInterface interface {
	// 处理URL列表，返回HTTP响应
	ProcessURLs(urls []string) []*HTTPResponse
}

// ResponseFilterInterface 响应过滤器接口
// 负责过滤和处理HTTP响应
type ResponseFilterInterface interface {
	// 过滤响应列表
	FilterResponses(responses []HTTPResponse) *FilterResult
	// 打印过滤结果
	PrintFilterResult(result *FilterResult)
}

// ===========================================
// 数据结构定义
// ===========================================

// HTTPResponse HTTP响应结构体
// 用于在各个模块之间传递HTTP响应数据
type HTTPResponse = types.HTTPResponse

// FilterResult 过滤结果结构体
// 包含过滤操作的完整结果信息
type FilterResult = types.FilterResult

// PageHash 页面哈希信息结构体
// 用于无效页面检测和统计
type PageHash = types.PageHash

// ===========================================
// 指纹识别相关接口
// ===========================================

// FingerprintEngine 指纹识别引擎接口
type FingerprintEngine interface {
	// 加载指纹库规则
	LoadRules(rulesPath string) error
	// 分析响应并识别技术栈
	AnalyzeResponse(response *HTTPResponse) []*FingerprintMatch
	// 获取加载的规则数量
	GetRulesCount() int
}

// FingerprintMatch 指纹匹配结果
type FingerprintMatch = types.FingerprintMatch

// FingerprintRule 指纹识别规则（极简版本，只保留核心字段）
type FingerprintRule struct {
	ID        string   `yaml:"-"`         // 规则ID（从YAML key生成）
	Name      string   `yaml:"-"`         // 规则名称（从YAML key生成）
	Path      string   `yaml:"path"`      // 需要主动访问的路径（可选）
	Condition string   `yaml:"condition"` // 条件逻辑 (and/or，默认or)
	DSL       []string `yaml:"dsl"`       // DSL表达式列表
}

// FingerprintCallback 指纹识别回调函数类型
type FingerprintCallback func(match *FingerprintMatch)
