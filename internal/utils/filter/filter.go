package filter

import (
	"veo/internal/core/config"
	"veo/internal/core/interfaces"
	"veo/internal/core/logger"
	"veo/internal/utils/filter/strategy"
	"veo/internal/utils/formatter"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
)

// FilterConfig 过滤器配置（独立配置，不依赖外部config包）
type FilterConfig struct {
	ValidStatusCodes        []int // 有效状态码列表
	InvalidPageThreshold    int   // 无效页面阈值（主要筛选）
	SecondaryThreshold      int   // 二次筛选阈值
	EnableStatusFilter      bool  // 是否启用状态码过滤
	EnableInvalidPageFilter bool  // 是否启用无效页面过滤
	EnableSecondaryFilter   bool  // 是否启用二次筛选

	// Content-Type过滤相关配置
	EnableContentTypeFilter bool     // 是否启用Content-Type过滤
	FilteredContentTypes    []string // 需要过滤的Content-Type列表

	// 相似页面过滤容错阈值配置
	FilterTolerance int64 // 相似页面过滤容错阈值（字节），0表示禁用过滤
}

// DefaultFilterConfig 获取默认过滤器配置
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		ValidStatusCodes:        []int{200, 403, 500, 302, 301, 405},
		InvalidPageThreshold:    3,
		SecondaryThreshold:      1,
		EnableStatusFilter:      true,
		EnableInvalidPageFilter: true,
		EnableSecondaryFilter:   true,

		// Content-Type过滤默认配置
		EnableContentTypeFilter: true,
		FilteredContentTypes: []string{
			"image/png",
			"image/jpeg",
			"image/jpg",
			"image/gif",
			"image/webp",
			"image/svg+xml",
			"image/bmp",
			"image/ico",
			"image/tiff",
		},

		// 相似页面过滤容错阈值默认配置
		FilterTolerance: 50, // 默认50字节容错
	}
}

// ResponseFilter 响应过滤器（重构版，使用策略模式）
type ResponseFilter struct {
	config            *FilterConfig                      // 过滤器配置
	statusCodeFilter  strategy.StatusCodeFilterStrategy  // 状态码过滤策略
	hashFilter        strategy.HashFilterStrategy        // 哈希过滤策略
	secondaryFilter   strategy.SecondaryFilterStrategy   // 二次筛选策略
	contentTypeFilter strategy.ContentTypeFilterStrategy // Content-Type过滤策略
	filterChain       *strategy.FilterChain              // 过滤链
	mu                sync.RWMutex                       // 读写锁

	// [新增] 可选的指纹识别引擎（用于目录扫描结果的二次识别）
	fingerprintEngine interface{}
}

// NewResponseFilter 创建新的响应过滤器
func NewResponseFilter(config *FilterConfig) *ResponseFilter {
	if config == nil {
		config = DefaultFilterConfig()
	}

	// 创建过滤策略（传递容错阈值）
	statusCodeFilter := strategy.NewStatusCodeFilter(config.ValidStatusCodes)
	hashFilter := strategy.NewHashFilter(config.InvalidPageThreshold, config.FilterTolerance)
	secondaryFilter := strategy.NewSecondaryFilter(config.SecondaryThreshold, config.FilterTolerance)
	contentTypeFilter := strategy.NewContentTypeFilter(config.FilteredContentTypes)

	// 创建过滤链
	filterChain := strategy.NewFilterChain()

	rf := &ResponseFilter{
		config:            config,
		statusCodeFilter:  statusCodeFilter,
		hashFilter:        hashFilter,
		secondaryFilter:   secondaryFilter,
		contentTypeFilter: contentTypeFilter,
		filterChain:       filterChain,
	}

	// 根据配置添加过滤策略到过滤链
	rf.rebuildFilterChain()

	logger.Debugf("响应过滤器创建完成 - 容错阈值: %d 字节", config.FilterTolerance)
	return rf
}

// SetFingerprintEngine 设置指纹识别引擎（可选，用于目录扫描结果的二次识别）
func (rf *ResponseFilter) SetFingerprintEngine(engine interface{}) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.fingerprintEngine = engine
	logger.Debug("响应过滤器已设置指纹识别引擎，启用二次识别")
}

// FilterResponses 过滤响应列表
func (rf *ResponseFilter) FilterResponses(responses []interfaces.HTTPResponse) *interfaces.FilterResult {
	rf.mu.RLock()
	config := rf.config
	rf.mu.RUnlock()

	result := &interfaces.FilterResult{
		StatusFilteredPages:  make([]interfaces.HTTPResponse, 0),
		PrimaryFilteredPages: make([]interfaces.HTTPResponse, 0),
		ValidPages:           make([]interfaces.HTTPResponse, 0),
		InvalidPageHashes:    make([]interfaces.PageHash, 0),
		SecondaryHashResults: make([]interfaces.PageHash, 0),
		TotalProcessed:       len(responses),
	}

	currentResponses := responses

	// 步骤1: 状态码过滤
	if config.EnableStatusFilter && rf.statusCodeFilter != nil {
		currentResponses = rf.statusCodeFilter.Filter(currentResponses)
		result.StatusFilteredPages = currentResponses
		result.StatusFiltered = len(currentResponses)
	} else {
		result.StatusFilteredPages = currentResponses
		result.StatusFiltered = len(currentResponses)
	}

	// 步骤2: Content-Type过滤
	if config.EnableContentTypeFilter && rf.contentTypeFilter != nil {
		currentResponses = rf.contentTypeFilter.Filter(currentResponses)
		logger.Debugf("Content-Type过滤后剩余响应数量: %d", len(currentResponses))
	}

	// 步骤3: 主要无效页面过滤
	if config.EnableInvalidPageFilter && rf.hashFilter != nil {
		currentResponses = rf.hashFilter.Filter(currentResponses)
		result.PrimaryFilteredPages = currentResponses
		result.PrimaryFiltered = len(currentResponses)
	} else {
		result.PrimaryFilteredPages = currentResponses
		result.PrimaryFiltered = len(currentResponses)
	}

	// 步骤4: 二次筛选
	if config.EnableSecondaryFilter && rf.secondaryFilter != nil {
		currentResponses = rf.secondaryFilter.Filter(currentResponses)
		result.ValidPages = currentResponses
		result.SecondaryFiltered = len(currentResponses)
	} else {
		result.ValidPages = currentResponses
		result.SecondaryFiltered = len(currentResponses)
	}

	// 步骤5: 收集哈希统计
	if rf.hashFilter != nil {
		result.InvalidPageHashes = rf.hashFilter.GetInvalidPageHashes()
	}
	if rf.secondaryFilter != nil {
		result.SecondaryHashResults = rf.secondaryFilter.GetSecondaryHashResults()
	}

	return result
}

// rebuildFilterChain 根据配置重建过滤链
func (rf *ResponseFilter) rebuildFilterChain() {
	rf.filterChain.ClearStrategies()

	// 根据配置添加策略
	if rf.config.EnableStatusFilter && rf.statusCodeFilter != nil {
		rf.filterChain.AddStrategy(rf.statusCodeFilter)
	}
	if rf.config.EnableInvalidPageFilter && rf.hashFilter != nil {
		rf.filterChain.AddStrategy(rf.hashFilter)
	}
	if rf.config.EnableSecondaryFilter && rf.secondaryFilter != nil {
		rf.filterChain.AddStrategy(rf.secondaryFilter)
	}
}

// UpdateConfig 更新过滤器配置
func (rf *ResponseFilter) UpdateConfig(config *FilterConfig) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.config = config

	// 更新各个策略的配置
	if rf.statusCodeFilter != nil {
		rf.statusCodeFilter.UpdateValidStatusCodes(config.ValidStatusCodes)
	}
	if rf.hashFilter != nil {
		rf.hashFilter.UpdateThreshold(config.InvalidPageThreshold)
	}
	if rf.secondaryFilter != nil {
		rf.secondaryFilter.UpdateThreshold(config.SecondaryThreshold)
	}

	// 重建过滤链
	rf.rebuildFilterChain()

	logger.Debug("配置已更新")
}

// GetConfig 获取当前配置
func (rf *ResponseFilter) GetConfig() *FilterConfig {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	// 返回配置副本
	return &FilterConfig{
		ValidStatusCodes:        rf.config.ValidStatusCodes,
		InvalidPageThreshold:    rf.config.InvalidPageThreshold,
		SecondaryThreshold:      rf.config.SecondaryThreshold,
		EnableStatusFilter:      rf.config.EnableStatusFilter,
		EnableInvalidPageFilter: rf.config.EnableInvalidPageFilter,
		EnableSecondaryFilter:   rf.config.EnableSecondaryFilter,
	}
}

// Reset 重置过滤器状态
func (rf *ResponseFilter) Reset() {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.hashFilter != nil {
		rf.hashFilter.Reset()
	}
	if rf.secondaryFilter != nil {
		rf.secondaryFilter.Reset()
	}
	rf.filterChain.Reset()

	logger.Debug("过滤器状态已重置")
}

// GetStatusCodeFilter 获取状态码过滤策略
func (rf *ResponseFilter) GetStatusCodeFilter() strategy.StatusCodeFilterStrategy {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	return rf.statusCodeFilter
}

// GetHashFilter 获取哈希过滤策略
func (rf *ResponseFilter) GetHashFilter() strategy.HashFilterStrategy {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	return rf.hashFilter
}

// GetSecondaryFilter 获取二次筛选策略
func (rf *ResponseFilter) GetSecondaryFilter() strategy.SecondaryFilterStrategy {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	return rf.secondaryFilter
}

// SetStatusCodeFilter 设置状态码过滤策略
func (rf *ResponseFilter) SetStatusCodeFilter(filter strategy.StatusCodeFilterStrategy) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.statusCodeFilter = filter
	rf.rebuildFilterChain()
}

// SetHashFilter 设置哈希过滤策略
func (rf *ResponseFilter) SetHashFilter(filter strategy.HashFilterStrategy) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.hashFilter = filter
	rf.rebuildFilterChain()
}

// SetSecondaryFilter 设置二次筛选策略
func (rf *ResponseFilter) SetSecondaryFilter(filter strategy.SecondaryFilterStrategy) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.secondaryFilter = filter
	rf.rebuildFilterChain()
}

// GetPageHashCount 获取页面哈希统计数量（兼容旧接口）
func (rf *ResponseFilter) GetPageHashCount() int {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	if rf.hashFilter != nil {
		return rf.hashFilter.GetPageHashCount()
	}
	return 0
}

// ============================================================================
// 配置适配器功能 (原config_adapter.go内容)
// ============================================================================

// ConfigAdapter 配置适配器，用于从外部config包转换配置
type ConfigAdapter struct{}

// NewConfigAdapter 创建配置适配器
func NewConfigAdapter() *ConfigAdapter {
	return &ConfigAdapter{}
}

// FromExternalConfig 从外部配置转换为内部配置
func (ca *ConfigAdapter) FromExternalConfig() *FilterConfig {
	externalConfig := config.GetFilterConfig()

	// 转换为内部配置格式
	validStatusCodes := externalConfig.ValidStatusCodes
	if len(validStatusCodes) == 0 {
		validStatusCodes = []int{200, 403, 500, 302, 301, 405} // 默认状态码
	}

	// 获取相似页面过滤容错阈值（从CLI参数或配置文件）
	// 注意：0值表示禁用容错过滤，是有效值
	// 配置文件中的默认值是50（见configs/config.yaml）
	filterTolerance := externalConfig.FilterTolerance

	return &FilterConfig{
		ValidStatusCodes:        validStatusCodes,
		InvalidPageThreshold:    3,    // 从外部配置获取或使用默认值
		SecondaryThreshold:      1,    // 从外部配置获取或使用默认值
		EnableStatusFilter:      true, // 从外部配置获取或使用默认值
		EnableInvalidPageFilter: true, // 从外部配置获取或使用默认值
		EnableSecondaryFilter:   true, // 从外部配置获取或使用默认值

		// Content-Type过滤配置（使用默认值，因为外部配置暂未支持）
		EnableContentTypeFilter: true,
		FilteredContentTypes: []string{
			"image/png",
			"image/jpeg",
			"image/jpg",
			"image/gif",
			"image/webp",
			"image/svg+xml",
			"image/bmp",
			"image/ico",
			"image/tiff",
		},

		// 相似页面过滤容错阈值配置
		FilterTolerance: filterTolerance,
	}
}

// ToExternalConfig 将内部配置转换为外部配置格式（如果需要）
func (ca *ConfigAdapter) ToExternalConfig(internalConfig *FilterConfig) map[string]interface{} {
	return map[string]interface{}{
		"valid_status_codes":         internalConfig.ValidStatusCodes,
		"invalid_page_threshold":     internalConfig.InvalidPageThreshold,
		"secondary_threshold":        internalConfig.SecondaryThreshold,
		"enable_status_filter":       internalConfig.EnableStatusFilter,
		"enable_invalid_page_filter": internalConfig.EnableInvalidPageFilter,
		"enable_secondary_filter":    internalConfig.EnableSecondaryFilter,
	}
}

// CreateFilterConfigFromExternal 便捷方法：从外部配置创建过滤器配置
func CreateFilterConfigFromExternal() *FilterConfig {
	adapter := NewConfigAdapter()
	return adapter.FromExternalConfig()
}

// ============================================================================
// 全局过滤函数 (用于被动模式模块集成)
// ============================================================================

// IsContentTypeFiltered 检查指定Content-Type是否应该被过滤
// 这是一个全局函数，供各模块在被动代理模式下使用
func IsContentTypeFiltered(contentType string) bool {
	// 获取过滤器配置
	config := CreateFilterConfigFromExternal()
	if !config.EnableContentTypeFilter {
		return false // 如果未启用Content-Type过滤，则不过滤
	}

	// 执行Content-Type检查逻辑
	return checkContentTypeAgainstRules(contentType, config.FilteredContentTypes)
}

// checkContentTypeAgainstRules 检查Content-Type是否匹配过滤规则
func checkContentTypeAgainstRules(contentType string, filteredTypes []string) bool {
	if contentType == "" || contentType == "unknown" {
		return false // 不过滤未知类型
	}

	// 清理Content-Type，移除参数部分（如charset等）
	cleanContentType := strings.ToLower(strings.TrimSpace(contentType))
	if idx := strings.Index(cleanContentType, ";"); idx != -1 {
		cleanContentType = cleanContentType[:idx]
	}

	// 检查是否在过滤列表中
	for _, filtered := range filteredTypes {
		if cleanContentType == strings.ToLower(filtered) {
			return true
		}
		// 支持前缀匹配（如image/开头的所有类型）
		if strings.HasSuffix(filtered, "/") && strings.HasPrefix(cleanContentType, strings.ToLower(filtered)) {
			return true
		}
	}

	return false
}

// CreateResponseFilterFromExternal 便捷方法：从外部配置创建响应过滤器
func CreateResponseFilterFromExternal() *ResponseFilter {
	config := CreateFilterConfigFromExternal()
	return NewResponseFilter(config)
}

// ============================================================================
// 打印相关方法 (原printer.go内容)
// ============================================================================

// 使用formatter包中的格式化函数
var (
	formatURL        = formatter.FormatURL
	formatStatusCode = formatter.FormatStatusCode
	formatTitle      = formatter.FormatTitle
	// formatResultNumber 已废弃，不再使用序号显示
	formatContentLength = formatter.FormatContentLength
	formatContentType   = formatter.FormatContentType
)

// PrintFilterResult 打印过滤结果
func (rf *ResponseFilter) PrintFilterResult(result *interfaces.FilterResult) {

	// 打印统计信息
	rf.printFilterStatistics(result)

	// 打印状态码过滤后的页面
	if len(result.StatusFilteredPages) > 0 {
		rf.printStatusFilteredPages(result.StatusFilteredPages)
	}

	// 打印主要筛选后的页面
	if len(result.PrimaryFilteredPages) > 0 {
		rf.printPrimaryFilteredPages(result.PrimaryFilteredPages)
	}

	// 打印最终有效页面
	if len(result.ValidPages) > 0 {
		rf.printValidPages(result.ValidPages)
	}

	// 打印主要筛选无效页面统计
	if len(result.InvalidPageHashes) > 0 {
		rf.printInvalidPageStatistics(result.InvalidPageHashes)
	}

	// 打印二次筛选统计
	if len(result.SecondaryHashResults) > 0 {
		rf.printSecondaryFilterStatistics(result.SecondaryHashResults)
	}
}

// formatNumber 格式化数字显示（加粗）
func formatNumber(num int) string {
	return formatter.FormatNumber(num)
}

// formatPercentage 格式化百分比显示
func formatPercentage(percentage float64) string {
	return formatter.FormatPercentage(percentage)
}

// printFilterStatistics 打印过滤统计信息
func (rf *ResponseFilter) printFilterStatistics(result *interfaces.FilterResult) {
	logger.Debugf("%s", fmt.Sprintf("  总处理数量: %s", formatNumber(result.TotalProcessed)))
	logger.Debugf("%s", fmt.Sprintf("  状态码有效页面: %s", formatNumber(result.StatusFiltered)))
	logger.Debugf("%s", fmt.Sprintf("  主要筛选后页面: %s", formatNumber(result.PrimaryFiltered)))
	logger.Debugf("%s", fmt.Sprintf("  二次筛选后页面: %s", formatNumber(result.SecondaryFiltered)))
	logger.Debugf("%s", fmt.Sprintf("  最终有效页面: %s", formatNumber(len(result.ValidPages))))

	if result.TotalProcessed > 0 {
		validPercentage := float64(len(result.ValidPages)) / float64(result.TotalProcessed) * 100
		logger.Debugf("%s", fmt.Sprintf("  有效页面比例: %s", formatPercentage(validPercentage)))
	}
}

// printStatusFilteredPages 打印通过状态码过滤的页面（移除序号显示）
func (rf *ResponseFilter) printStatusFilteredPages(pages []interfaces.HTTPResponse) {
	logger.Debug("通过状态码过滤的页面（状态码有效）")

	for _, page := range pages {
		logger.Debug(fmt.Sprintf("%s %s %s",
			formatURL(page.URL),
			formatStatusCode(page.StatusCode),
			formatTitle(page.Title)))
	}
}

// printPrimaryFilteredPages 打印主要筛选后的页面（移除序号显示）
func (rf *ResponseFilter) printPrimaryFilteredPages(pages []interfaces.HTTPResponse) {
	logger.Debug("主要筛选后的页面（通过主要hash过滤）")

	for _, page := range pages {
		logger.Debug(fmt.Sprintf("%s %s %s %s %s",
			formatURL(page.URL),
			formatStatusCode(page.StatusCode),
			formatTitle(page.Title),
			formatContentLength(int(page.ContentLength)),
			formatContentType(page.ContentType)))
	}
}

// printValidPages 打印最终有效页面（支持指纹识别）
func (rf *ResponseFilter) printValidPages(pages []interfaces.HTTPResponse) {
	for _, page := range pages {
		// 基础信息
		baseInfo := fmt.Sprintf("%s %s %s %s %s",
			formatURL(page.URL), // 使用绿色格式显示URL，与指纹识别模块保持一致
			formatStatusCode(page.StatusCode),
			formatTitle(page.Title),
			formatContentLength(int(page.ContentLength)),
			formatContentType(page.ContentType),
		)

		// 尝试进行指纹识别
		fingerprintInfo := ""
		rf.mu.RLock()
		hasEngine := rf.fingerprintEngine != nil
		rf.mu.RUnlock()

		if hasEngine {
			fingerprintInfo = rf.performFingerprintRecognition(&page)
		}

		// 输出（如果有指纹信息则追加）
		if fingerprintInfo != "" {
			logger.Infof("%s %s", baseInfo, fingerprintInfo)
		} else {
			logger.Infof("%s", baseInfo)
		}
	}
}

// performFingerprintRecognition 对单个响应执行指纹识别
func (rf *ResponseFilter) performFingerprintRecognition(page *interfaces.HTTPResponse) string {
	if page == nil {
		return ""
	}

	rf.mu.RLock()
	engine := rf.fingerprintEngine
	rf.mu.RUnlock()

	if engine == nil {
		logger.Debugf("[二次指纹] 指纹引擎为nil，跳过识别")
		return ""
	}

	// 使用反射调用指纹引擎的方法（避免循环依赖）
	engineValue := reflect.ValueOf(engine)

	// 检查是否有 AnalyzeResponseWithClientSilent 方法
	method := engineValue.MethodByName("AnalyzeResponseWithClientSilent")
	if !method.IsValid() {
		logger.Debugf("[二次指纹] 指纹引擎没有 AnalyzeResponseWithClientSilent 方法")
		return ""
	}

	// 转换响应格式
	fpResponse := rf.convertToFingerprintResponse(page)
	if fpResponse == nil {
		logger.Debugf("[二次指纹] 响应转换失败: %s", page.URL)
		return ""
	}

	logger.Debugf("[二次指纹] 开始识别: %s", page.URL)

	// 使用反射调用方法
	// 第二个参数是 httpClient，传递 nil
	var nilClient interface{} = nil
	args := []reflect.Value{
		reflect.ValueOf(fpResponse),
		reflect.ValueOf(&nilClient).Elem(), // nil interface{}
	}
	results := method.Call(args)

	// 检查返回值
	if len(results) == 0 {
		logger.Debugf("[二次指纹] 方法调用无返回值")
		return ""
	}

	matchesInterface := results[0].Interface()

	// 使用反射获取切片长度
	matchesValue := reflect.ValueOf(matchesInterface)
	if matchesValue.Kind() != reflect.Slice {
		logger.Debugf("[二次指纹] 返回值不是切片类型: %v", matchesValue.Kind())
		return ""
	}

	logger.Debugf("[二次指纹] 识别完成: %s, 匹配数量: %d", page.URL, matchesValue.Len())

	// 格式化指纹信息
	return rf.formatFingerprintMatches(matchesInterface)
}

// convertToFingerprintResponse 将interfaces.HTTPResponse转换为fingerprint.HTTPResponse
// 使用反射创建正确的类型，避免类型不匹配
func (rf *ResponseFilter) convertToFingerprintResponse(resp *interfaces.HTTPResponse) interface{} {
	if resp == nil {
		return nil
	}

	// 优先使用ResponseBody字段，如果为空则使用Body字段
	body := resp.ResponseBody
	if body == "" {
		body = resp.Body
	}

	// [关键修复] 解压缩响应体（如果被压缩）
	decompressedBody := rf.decompressResponseBody(body, resp.ResponseHeaders)

	// 截取前100个字符用于调试
	bodyPreview := decompressedBody
	if len(bodyPreview) > 100 {
		bodyPreview = bodyPreview[:100]
	}
	logger.Debugf("[二次指纹] 转换响应: %s, 原始长度: %d, 解压后长度: %d, 前100字符: %s",
		resp.URL, len(body), len(decompressedBody), bodyPreview)

	// 使用反射获取指纹引擎的类型
	rf.mu.RLock()
	engine := rf.fingerprintEngine
	rf.mu.RUnlock()

	if engine == nil {
		return nil
	}

	// 通过反射获取 fingerprint.HTTPResponse 类型
	engineValue := reflect.ValueOf(engine)
	engineType := engineValue.Type()

	// 查找 AnalyzeResponseWithClientSilent 方法
	method, found := engineType.MethodByName("AnalyzeResponseWithClientSilent")
	if !found {
		logger.Debugf("[二次指纹] 未找到 AnalyzeResponseWithClientSilent 方法")
		return nil
	}

	// 获取第一个参数的类型（应该是 *fingerprint.HTTPResponse）
	if method.Type.NumIn() < 2 { // 第0个是receiver
		logger.Debugf("[二次指纹] 方法参数数量不足")
		return nil
	}

	// 第1个参数（索引1，因为0是receiver）
	paramType := method.Type.In(1)

	// 如果是指针类型，获取元素类型
	if paramType.Kind() == reflect.Ptr {
		paramType = paramType.Elem()
	}

	// 创建该类型的新实例
	newResp := reflect.New(paramType)
	newRespElem := newResp.Elem()

	// 使用反射设置字段值
	if field := newRespElem.FieldByName("URL"); field.IsValid() && field.CanSet() {
		field.SetString(resp.URL)
	}
	if field := newRespElem.FieldByName("Method"); field.IsValid() && field.CanSet() {
		field.SetString("GET")
	}
	if field := newRespElem.FieldByName("StatusCode"); field.IsValid() && field.CanSet() {
		field.SetInt(int64(resp.StatusCode))
	}
	if field := newRespElem.FieldByName("Headers"); field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(resp.ResponseHeaders))
	}
	if field := newRespElem.FieldByName("Body"); field.IsValid() && field.CanSet() {
		field.SetString(decompressedBody) // 使用解压缩后的内容
	}
	if field := newRespElem.FieldByName("ContentType"); field.IsValid() && field.CanSet() {
		field.SetString(resp.ContentType)
	}
	if field := newRespElem.FieldByName("ContentLength"); field.IsValid() && field.CanSet() {
		field.SetInt(resp.ContentLength)
	}
	if field := newRespElem.FieldByName("Server"); field.IsValid() && field.CanSet() {
		field.SetString(resp.Server)
	}
	if field := newRespElem.FieldByName("Title"); field.IsValid() && field.CanSet() {
		field.SetString(resp.Title)
	}

	logger.Debugf("[二次指纹] 成功创建类型: %v", newResp.Type())
	return newResp.Interface()
}

// formatFingerprintMatches 格式化指纹匹配结果（使用反射避免循环依赖）
func (rf *ResponseFilter) formatFingerprintMatches(matchesInterface interface{}) string {
	if matchesInterface == nil {
		return ""
	}

	// 使用反射处理切片
	matchesValue := reflect.ValueOf(matchesInterface)
	if matchesValue.Kind() != reflect.Slice {
		logger.Debugf("[二次指纹] 匹配结果不是切片类型")
		return ""
	}

	matchCount := matchesValue.Len()
	if matchCount == 0 {
		return ""
	}

	logger.Debugf("[二次指纹] 格式化 %d 个匹配结果", matchCount)

	var parts []string
	for i := 0; i < matchCount; i++ {
		match := matchesValue.Index(i)

		// 如果是指针，解引用
		if match.Kind() == reflect.Ptr {
			match = match.Elem()
		}

		// 使用反射读取字段
		ruleNameField := match.FieldByName("RuleName")
		dslMatchedField := match.FieldByName("DSLMatched")

		if !ruleNameField.IsValid() || !dslMatchedField.IsValid() {
			logger.Debugf("[二次指纹] 无法读取字段: RuleName或DSLMatched")
			continue
		}

		ruleName := ruleNameField.String()
		dslMatched := dslMatchedField.String()

		if ruleName != "" && dslMatched != "" {
			parts = append(parts, fmt.Sprintf("<%s> <%s>",
				formatter.FormatFingerprint(ruleName),
				formatter.FormatDSL(dslMatched)))
			logger.Debugf("[二次指纹] 匹配: %s - %s", ruleName, dslMatched)
		}
	}

	result := strings.Join(parts, " ")
	logger.Debugf("[二次指纹] 格式化结果: %s", result)
	return result
}

// printInvalidPageStatistics 打印无效页面统计（主要筛选，移除序号显示）
func (rf *ResponseFilter) printInvalidPageStatistics(invalidHashes []interfaces.PageHash) {
	logger.Debug("主要筛选无效页面统计")

	for _, hash := range invalidHashes {
		logger.Debug(fmt.Sprintf("哈希: %s", hash.Hash[:16]))
		logger.Debug(fmt.Sprintf("    出现次数: %d", hash.Count))
		logger.Debug(fmt.Sprintf("    状态码: %d", hash.StatusCode))
		logger.Debug(fmt.Sprintf("    标题: %s", hash.Title))
		logger.Debug(fmt.Sprintf("    内容长度: %d字节", hash.ContentLength))
		logger.Debug(fmt.Sprintf("    内容类型: %s", hash.ContentType))
	}
}

// printSecondaryFilterStatistics 打印二次筛选统计
func (rf *ResponseFilter) printSecondaryFilterStatistics(secondaryHashes []interfaces.PageHash) {
	logger.Debug("二次筛选无效页面统计")

	for i, hash := range secondaryHashes {
		logger.Debug(fmt.Sprintf("🔄 [%d] 哈希: %s", i+1, hash.Hash[:16]))
		logger.Debug(fmt.Sprintf("    出现次数: %d", hash.Count))
		logger.Debug(fmt.Sprintf("    状态码: %d", hash.StatusCode))
		logger.Debug(fmt.Sprintf("    标题: %s", hash.Title))
		logger.Debug(fmt.Sprintf("    内容长度: %d字节", hash.ContentLength))
		logger.Debug(fmt.Sprintf("    内容类型: %s", hash.ContentType))
	}
}

// ============================================================================
// 响应体解压缩辅助方法（用于二次指纹识别）
// ============================================================================

// decompressResponseBody 解压缩响应体
func (rf *ResponseFilter) decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}

	// 获取Content-Encoding头部
	var contentEncoding string
	if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
		contentEncoding = strings.ToLower(encodingHeaders[0])
	}

	// 如果没有压缩，直接返回
	if contentEncoding == "" {
		return body
	}

	logger.Debugf("[二次指纹] 检测到压缩编码: %s", contentEncoding)

	bodyBytes := []byte(body)

	// 根据压缩类型进行解压缩
	if strings.Contains(contentEncoding, "gzip") {
		return rf.decompressGzip(bodyBytes)
	} else if strings.Contains(contentEncoding, "deflate") {
		return rf.decompressDeflate(bodyBytes)
	} else if strings.Contains(contentEncoding, "br") {
		return rf.decompressBrotli(bodyBytes)
	}

	// 不支持的压缩格式，返回原始内容
	logger.Debugf("[二次指纹] 不支持的压缩格式: %s", contentEncoding)
	return body
}

// decompressGzip 解压gzip压缩的响应体
func (rf *ResponseFilter) decompressGzip(compressedBody []byte) string {
	reader := bytes.NewReader(compressedBody)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		logger.Debugf("[二次指纹] gzip解压失败: %v, 返回原始内容", err)
		return string(compressedBody)
	}
	defer gzipReader.Close()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		logger.Debugf("[二次指纹] gzip读取失败: %v, 返回原始内容", err)
		return string(compressedBody)
	}

	logger.Debugf("[二次指纹] gzip解压成功: %d bytes -> %d bytes",
		len(compressedBody), len(decompressed))

	return string(decompressed)
}

// decompressDeflate 解压deflate压缩的响应体
func (rf *ResponseFilter) decompressDeflate(compressedBody []byte) string {
	reader := bytes.NewReader(compressedBody)
	deflateReader := flate.NewReader(reader)
	defer deflateReader.Close()

	decompressed, err := io.ReadAll(deflateReader)
	if err != nil {
		logger.Debugf("[二次指纹] deflate读取失败: %v, 返回原始内容", err)
		return string(compressedBody)
	}

	logger.Debugf("[二次指纹] deflate解压成功: %d bytes -> %d bytes",
		len(compressedBody), len(decompressed))

	return string(decompressed)
}

// decompressBrotli 解压brotli压缩的响应体
func (rf *ResponseFilter) decompressBrotli(compressedBody []byte) string {
	reader := bytes.NewReader(compressedBody)
	brotliReader := brotli.NewReader(reader)

	decompressed, err := io.ReadAll(brotliReader)
	if err != nil {
		logger.Debugf("[二次指纹] brotli读取失败: %v, 返回原始内容", err)
		return string(compressedBody)
	}

	logger.Debugf("[二次指纹] brotli解压成功: %d bytes -> %d bytes",
		len(compressedBody), len(decompressed))

	return string(decompressed)
}
