package dirscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"veo/internal/core/config"
	"veo/internal/core/interfaces"
	"veo/internal/core/logger"
	report "veo/internal/modules/reporter"
	"veo/internal/utils/filter"
	"veo/internal/utils/generator"
	requests "veo/internal/utils/processor"
)

// ===========================================
// 引擎实现
// ===========================================

// NewEngine 创建新的目录扫描引擎
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = getDefaultConfig()
	}

	engine := &Engine{
		config: config,
		stats: &Statistics{
			StartTime: time.Now(),
		},
	}

	logger.Debug("目录扫描引擎初始化完成")
	return engine
}

// SetFilterConfig 设置自定义过滤器配置（SDK可用）
func (e *Engine) SetFilterConfig(cfg *filter.FilterConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.filterConfig = filter.CloneFilterConfig(cfg)
}

func (e *Engine) getFilterConfig() *filter.FilterConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.filterConfig == nil {
		return nil
	}
	return filter.CloneFilterConfig(e.filterConfig)
}

// GetStats 获取统计信息
func (e *Engine) GetStats() *Statistics {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 创建统计信息副本
	stats := *e.stats
	return &stats
}

// GetLastScanResult 获取最后一次扫描结果
func (e *Engine) GetLastScanResult() *ScanResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.lastScanResult == nil {
		return nil
	}

	// 返回副本
	result := *e.lastScanResult
	return &result
}

// ClearResults 清空结果
func (e *Engine) ClearResults() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lastScanResult = nil

	logger.Debug("扫描结果已清空")
}

// PerformScan 执行扫描
func (e *Engine) PerformScan(collectorInstance interfaces.URLCollectorInterface) (*ScanResult, error) {
	startTime := time.Now()

	// 1. 生成扫描URL（内部会处理URL收集为空的情况）
	scanURLs, err := e.generateScanURLs(collectorInstance)
	if err != nil {
		return nil, fmt.Errorf("生成扫描URL失败: %v", err)
	}

	if len(scanURLs) == 0 {
		return nil, fmt.Errorf("没有收集到URL，无法开始扫描")
	}

	logger.Debugf("生成扫描URL: %d个", len(scanURLs))
	atomic.StoreInt64(&e.stats.TotalGenerated, int64(len(scanURLs)))

	// 3. 执行HTTP请求
	// [重要] 在开始处理前显示确认信息（显示实际的并发数）
	actualConcurrency := e.getActualConcurrency()
	logger.Infof("%d URL，Threads: %d，Random UA: true", len(scanURLs), actualConcurrency)

	responses, err := e.performHTTPRequests(scanURLs)
	if err != nil {
		return nil, fmt.Errorf("HTTP请求执行失败: %v", err)
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf("没有收到有效的HTTP响应")
	}

	logger.Debugf("HTTP扫描完成，收到 %d 个响应", len(responses))
	atomic.StoreInt64(&e.stats.TotalRequests, int64(len(responses)))

	// 4. 应用过滤器
	filterResult, err := e.applyFilter(responses)
	if err != nil {
		return nil, fmt.Errorf("响应过滤失败: %v", err)
	}

	atomic.StoreInt64(&e.stats.FilteredResults, int64(len(filterResult.ValidPages)))
	logger.Debugf("过滤完成 - 总响应: %d, 有效结果: %d",
		len(responses), len(filterResult.ValidPages))

	// 5. 生成报告
	reportPath := ""
	if e.config.EnableReporting {
		target := e.extractTarget(responses)
		reportPath, err = e.generateReport(filterResult, target)
		if err != nil {
			logger.Warnf("报告生成失败: %v", err)
		}
	}

	// 6. 创建扫描结果
	endTime := time.Now()
	result := &ScanResult{
		Target:        e.extractTarget(responses),
		CollectedURLs: []string{}, // 不再维护收集的URL列表
		ScanURLs:      scanURLs,
		Responses:     responses,
		FilterResult:  filterResult,
		ReportPath:    reportPath,
		StartTime:     startTime,
		EndTime:       endTime,
		Duration:      endTime.Sub(startTime),
	}

	// 7. 更新统计信息
	e.mu.Lock()
	e.lastScanResult = result
	e.stats.LastScanTime = endTime
	atomic.AddInt64(&e.stats.TotalScans, 1)
	atomic.StoreInt64(&e.stats.ValidResults, int64(len(filterResult.ValidPages)))
	e.mu.Unlock()

	logger.Debugf("扫描执行完成，耗时: %v", result.Duration)
	return result, nil
}

// generateScanURLs 生成扫描URL
func (e *Engine) generateScanURLs(collectorInstance interfaces.URLCollectorInterface) ([]string, error) {
	logger.Debug("开始生成扫描URL")

	// 创建内容管理器（使用utils包中的实现）
	contentManager := generator.NewContentManager()
	contentManager.SetCollector(collectorInstance)

	// 生成扫描URL
	scanURLs := contentManager.GenerateScanURLs()

	logger.Debugf("生成扫描URL完成，共%d个", len(scanURLs))
	return scanURLs, nil
}

// performHTTPRequests 执行HTTP请求
func (e *Engine) performHTTPRequests(scanURLs []string) ([]*interfaces.HTTPResponse, error) {
	logger.Debug("开始执行HTTP扫描")

	// 获取或创建请求处理器（简化后的逻辑）
	processor := e.getOrCreateRequestProcessor()

	// 执行请求
	responses := processor.ProcessURLs(scanURLs)

	atomic.StoreInt64(&e.stats.SuccessRequests, int64(len(responses)))

	return responses, nil
}

// getOrCreateRequestProcessor 获取或创建请求处理器
func (e *Engine) getOrCreateRequestProcessor() *requests.RequestProcessor {
	logger.Debug("创建新的请求处理器")

	// 创建新的请求处理器实例
	processor := requests.NewRequestProcessor(nil)

	// 应用CLI指定的自定义HTTP头部
	logger.Debug("准备应用自定义HTTP头部")
	e.applyCustomHeadersToProcessor(processor)

	return processor
}

// applyCustomHeadersToProcessor 应用自定义HTTP头部到请求处理器
func (e *Engine) applyCustomHeadersToProcessor(processor *requests.RequestProcessor) {
	// 从配置系统获取自定义头部
	customHeaders := config.GetCustomHeaders()

	if len(customHeaders) > 0 {
		processor.SetCustomHeaders(customHeaders)
		logger.Debugf("应用了 %d 个自定义HTTP头部到请求处理器", len(customHeaders))

		// 记录应用的头部（调试用）
		for key, value := range customHeaders {
			logger.Debugf("自定义头部: %s = %s", key, value)
		}
	} else {
		logger.Debug("未发现自定义HTTP头部，启用自动认证检测")
	}
}

// getActualConcurrency 获取实际的并发数（用于日志显示）
func (e *Engine) getActualConcurrency() int {
	// 使用默认配置的并发数
	defaultConfig := requests.NewRequestProcessor(nil).GetConfig()
	if defaultConfig != nil {
		return defaultConfig.MaxConcurrent
	}

	// 最后的备用值
	return 50
}

// applyFilter 应用过滤器
func (e *Engine) applyFilter(responses []*interfaces.HTTPResponse) (*interfaces.FilterResult, error) {
	logger.Debug("开始应用响应过滤器")

	var responseFilter *filter.ResponseFilter
	if cfg := e.getFilterConfig(); cfg != nil {
		responseFilter = filter.NewResponseFilter(cfg)
	} else {
		responseFilter = filter.CreateResponseFilterFromExternal()
	}

	// 转换为过滤器可处理的格式
	filterResponses := e.convertToFilterResponses(responses)

	// 应用过滤器
	filterResult := responseFilter.FilterResponses(filterResponses)

	// 显示过滤结果（包含指纹信息）
	responseFilter.PrintFilterResult(filterResult)

	return filterResult, nil
}

// generateReport 生成报告
func (e *Engine) generateReport(filterResult *interfaces.FilterResult, target string) (string, error) {
	logger.Debug("开始生成扫描报告")

	reportDir := "./reports"
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", fmt.Errorf("创建报告目录失败: %v", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	safeTarget := sanitizeForReportFilename(target)
	if safeTarget == "" {
		safeTarget = "scan"
	}
	fileName := fmt.Sprintf("dirscan_%s_%s.xlsx", safeTarget, timestamp)
	outputPath := filepath.Join(reportDir, fileName)

	reportPath, err := report.GenerateExcelReport(filterResult, report.ExcelReportDirscan, outputPath)
	if err != nil {
		return "", err
	}

	logger.Debugf("报告文件已生成: %s", reportPath)
	return reportPath, nil
}

// convertToFilterResponses 转换响应格式（[重要] 内存优化版本）
func (e *Engine) convertToFilterResponses(httpResponses []*interfaces.HTTPResponse) []interfaces.HTTPResponse {
	filterResponses := make([]interfaces.HTTPResponse, len(httpResponses))
	for i, resp := range httpResponses {
		// [重要] 内存优化：只复制过滤器真正需要的4个核心字段
		// 分析过滤器实现发现只需要：URL、StatusCode、ContentLength、ContentType、Title、Body
		filterResponses[i] = interfaces.HTTPResponse{
			URL:           resp.URL,                   // 结果展示需要
			StatusCode:    resp.StatusCode,            // 状态码过滤器使用
			ContentLength: resp.ContentLength,         // 哈希过滤器容错计算使用
			ContentType:   resp.ContentType,           // Content-Type过滤器使用
			Title:         resp.Title,                 // 哈希过滤器生成页面哈希使用
			Body:          e.getFilterBody(resp.Body), // 哈希计算使用（已截断）
			// [重要] 内存优化：其他字段使用零值，大幅减少内存占用
			// Method、Server、IsDirectory、Length、Duration、Depth等字段在过滤器中未使用
		}
	}
	return filterResponses
}

// getFilterBody 获取用于过滤的响应体（[重要] 内存优化）
func (e *Engine) getFilterBody(body string) string {
	// 过滤器只需要响应体的前部分用于哈希计算
	const maxFilterBodySize = 4096 // 4KB足够用于过滤判断
	if len(body) > maxFilterBodySize {
		return body[:maxFilterBodySize]
	}
	return body
}

// extractTarget 提取目标信息
func (e *Engine) extractTarget(responses []*interfaces.HTTPResponse) string {
	if len(responses) == 0 {
		return "unknown"
	}

	// 从第一个响应中提取主机信息
	firstURL := responses[0].URL
	if firstURL == "" {
		return "unknown"
	}

	// 简单提取主机部分
	if len(firstURL) > 50 {
		return firstURL[:50] + "..."
	}
	return firstURL
}

func sanitizeForReportFilename(name string) string {
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"?", "_",
		"*", "_",
		"|", "_",
		"<", "_",
		">", "_",
		"\"", "_",
	)
	return strings.Trim(replacer.Replace(name), "_")
}
