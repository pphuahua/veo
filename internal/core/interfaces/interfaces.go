package interfaces

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
type HTTPResponse struct {
	URL             string              `json:"url"`              // 请求的URL
	Method          string              `json:"method"`           // 请求方法
	StatusCode      int                 `json:"status_code"`      // HTTP状态码
	Title           string              `json:"title"`            // 页面标题
	ContentLength   int64               `json:"content_length"`   // 内容长度
	ContentType     string              `json:"content_type"`     // 内容类型
	Body            string              `json:"body"`             // 响应体内容
	ResponseHeaders map[string][]string `json:"response_headers"` // 响应头信息
	RequestHeaders  map[string][]string `json:"request_headers"`  // 请求头信息
	Server          string              `json:"server"`           // 服务器信息
	IsDirectory     bool                `json:"is_directory"`     // 是否为目录
	Length          int64               `json:"length"`           // 内容长度（报告用）
	Duration        int64               `json:"duration"`         // 请求耗时（毫秒）
	Depth           int                 `json:"depth"`            // 扫描深度
	ResponseBody    string              `json:"response_body"`    // 响应体内容（报告用）
}

// FilterResult 过滤结果结构体
// 包含过滤操作的完整结果信息
type FilterResult struct {
	StatusFilteredPages  []HTTPResponse `json:"status_filtered_pages"`  // 状态码过滤后的页面
	PrimaryFilteredPages []HTTPResponse `json:"primary_filtered_pages"` // 主要筛选后的页面
	ValidPages           []HTTPResponse `json:"valid_pages"`            // 最终有效页面（二次筛选后）
	InvalidPageHashes    []PageHash     `json:"invalid_page_hashes"`    // 无效页面哈希统计（主要筛选）
	SecondaryHashResults []PageHash     `json:"secondary_hash_results"` // 二次筛选哈希统计
	TotalProcessed       int            `json:"total_processed"`        // 总处理数量
	StatusFiltered       int            `json:"status_filtered"`        // 状态码过滤数量
	PrimaryFiltered      int            `json:"primary_filtered"`       // 主要筛选过滤数量
	SecondaryFiltered    int            `json:"secondary_filtered"`     // 二次筛选过滤数量
}

// PageHash 页面哈希信息结构体
// 用于无效页面检测和统计
type PageHash struct {
	Hash          string `json:"hash"`           // 页面哈希值
	Count         int    `json:"count"`          // 出现次数
	StatusCode    int    `json:"status_code"`    // 状态码
	Title         string `json:"title"`          // 页面标题
	ContentLength int64  `json:"content_length"` // 内容长度（用于新的哈希算法）
	ContentType   string `json:"content_type"`   // 内容类型（保留用于显示）
}

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

// FingerprintMatch 指纹匹配结果（简化版本）
type FingerprintMatch struct {
	URL        string  `json:"url"`        // 匹配的URL
	RuleName   string  `json:"rule_name"`  // 匹配的规则名称
	Matcher    string  `json:"matcher"`    // 匹配的具体表达式
	Confidence float64 `json:"confidence"` // 匹配置信度 (0.0 - 1.0)
	Timestamp  int64   `json:"timestamp"`  // 匹配时间戳
}

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
