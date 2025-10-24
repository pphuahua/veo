package report

import (
	"veo/internal/core/interfaces"
	"veo/internal/modules/fingerprint"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ===========================================
// JSON输出数据结构
// ===========================================

// JSONScanInfo 扫描信息
type JSONScanInfo struct {
	Target         string                 `json:"target"`          // 扫描目标
	ScanType       string                 `json:"scan_type"`       // 扫描类型 (dirscan/fingerprint)
	StartTime      time.Time              `json:"start_time"`      // 开始时间
	EndTime        time.Time              `json:"end_time"`        // 结束时间
	Duration       string                 `json:"duration"`        // 扫描耗时
	ScanParameters map[string]interface{} `json:"scan_parameters"` // 扫描参数
}

// JSONStatistics JSON统计信息
type JSONStatistics struct {
	// 目录扫描统计
	TotalScanned   int `json:"total_scanned,omitempty"`   // 总扫描数量
	SuccessCount   int `json:"success_count,omitempty"`   // 成功响应数量(2xx)
	RedirectCount  int `json:"redirect_count,omitempty"`  // 重定向数量(3xx)
	AuthCount      int `json:"auth_count,omitempty"`      // 认证相关数量(401)
	ForbiddenCount int `json:"forbidden_count,omitempty"` // 禁止访问数量(403)
	ErrorCount     int `json:"error_count,omitempty"`     // 错误数量(4xx,5xx)

	// 指纹识别统计
	TotalRequests     int64 `json:"total_requests,omitempty"`     // 总请求数
	MatchedRequests   int64 `json:"matched_requests,omitempty"`   // 匹配的请求数
	FilteredRequests  int64 `json:"filtered_requests,omitempty"`  // 过滤的请求数
	FingerprintsFound int   `json:"fingerprints_found,omitempty"` // 发现的指纹数量
	RulesLoaded       int   `json:"rules_loaded,omitempty"`       // 加载的规则数
}

// JSONDirscanResult 目录扫描JSON结果
type JSONDirscanResult struct {
	ScanInfo     JSONScanInfo              `json:"scan_info"`        // 扫描信息
	Statistics   JSONStatistics            `json:"statistics"`       // 统计信息
	TotalResults int                       `json:"total_results"`    // 发现的有效URL总数量
	Results      []interfaces.HTTPResponse `json:"results"`          // 扫描结果
	Filter       *interfaces.FilterResult  `json:"filter,omitempty"` // 过滤结果（可选）
}

// JSONFingerprintResult 指纹识别JSON结果
type JSONFingerprintResult struct {
	ScanInfo          JSONScanInfo           `json:"scan_info"`          // 扫描信息
	Statistics        JSONStatistics         `json:"statistics"`         // 统计信息
	TotalFingerprints int                    `json:"total_fingerprints"` // 发现的指纹总数量
	Fingerprints      []JSONFingerprintMatch `json:"fingerprints"`       // 指纹匹配结果
}

// JSONFingerprintMatch JSON指纹匹配结果
type JSONFingerprintMatch struct {
	URL        string    `json:"url"`         // 匹配的URL
	RuleName   string    `json:"rule_name"`   // 匹配的规则名称
	Technology string    `json:"technology"`  // 识别的技术栈
	DSLMatched string    `json:"dsl_matched"` // 匹配的DSL表达式
	Confidence float64   `json:"confidence"`  // 匹配置信度 (0.0 - 1.0)
	Timestamp  time.Time `json:"timestamp"`   // 匹配时间
	ScanType   string    `json:"scan_type"`   // 扫描类型 (passive/active)
}

// ===========================================
// JSON报告生成器
// ===========================================

// JSONReportGenerator JSON报告生成器
type JSONReportGenerator struct {
	startTime  time.Time
	outputPath string // 自定义输出路径（可选）
}

// NewJSONReportGenerator 创建新的JSON报告生成器
func NewJSONReportGenerator() *JSONReportGenerator {
	return &JSONReportGenerator{
		startTime: time.Now(),
	}
}

// NewCustomJSONReportGenerator 创建自定义输出路径的JSON报告生成器
func NewCustomJSONReportGenerator(outputPath string) *JSONReportGenerator {
	return &JSONReportGenerator{
		startTime:  time.Now(),
		outputPath: outputPath,
	}
}

// GenerateDirscanReport 生成目录扫描JSON报告
func (jrg *JSONReportGenerator) GenerateDirscanReport(filterResult *interfaces.FilterResult, target string, scanParams map[string]interface{}) (string, error) {
	endTime := time.Now()
	duration := endTime.Sub(jrg.startTime)

	// 准备扫描信息
	scanInfo := JSONScanInfo{
		Target:         target,
		ScanType:       "dirscan",
		StartTime:      jrg.startTime,
		EndTime:        endTime,
		Duration:       duration.Round(time.Millisecond).String(),
		ScanParameters: scanParams,
	}

	// 计算统计信息
	statistics := jrg.calculateDirscanStatistics(filterResult)

	// 构建JSON结果
	jsonResult := JSONDirscanResult{
		ScanInfo:     scanInfo,
		Statistics:   statistics,
		TotalResults: len(filterResult.ValidPages), // 设置发现的有效URL总数量
		Results:      filterResult.ValidPages,
		Filter:       filterResult,
	}

	// 生成JSON文件
	return jrg.saveJSONReport(jsonResult, target, "dirscan")
}

// GenerateFingerprintReport 生成指纹识别JSON报告
func (jrg *JSONReportGenerator) GenerateFingerprintReport(matches []*fingerprint.FingerprintMatch, stats *fingerprint.Statistics, target string, scanParams map[string]interface{}) (string, error) {
	endTime := time.Now()
	duration := endTime.Sub(jrg.startTime)

	// 准备扫描信息
	scanInfo := JSONScanInfo{
		Target:         target,
		ScanType:       "fingerprint",
		StartTime:      jrg.startTime,
		EndTime:        endTime,
		Duration:       duration.Round(time.Millisecond).String(),
		ScanParameters: scanParams,
	}

	// 计算统计信息
	statistics := JSONStatistics{
		TotalRequests:     stats.TotalRequests,
		MatchedRequests:   stats.MatchedRequests,
		FilteredRequests:  stats.FilteredRequests,
		FingerprintsFound: len(matches),
		RulesLoaded:       stats.RulesLoaded,
	}

	// 转换指纹匹配结果
	jsonFingerprints := make([]JSONFingerprintMatch, 0, len(matches))
	for _, match := range matches {
		jsonMatch := JSONFingerprintMatch{
			URL:        match.URL,
			RuleName:   match.RuleName,
			Technology: match.Technology,
			DSLMatched: match.DSLMatched,
			Confidence: match.Confidence,
			Timestamp:  match.Timestamp,
			ScanType:   "passive", // 默认为被动扫描，可根据实际情况调整
		}
		jsonFingerprints = append(jsonFingerprints, jsonMatch)
	}

	// 构建JSON结果
	jsonResult := JSONFingerprintResult{
		ScanInfo:          scanInfo,
		Statistics:        statistics,
		TotalFingerprints: len(jsonFingerprints), // 设置发现的指纹总数量
		Fingerprints:      jsonFingerprints,
	}

	// 生成JSON文件
	return jrg.saveJSONReport(jsonResult, target, "fingerprint")
}

// calculateDirscanStatistics 计算目录扫描统计信息
func (jrg *JSONReportGenerator) calculateDirscanStatistics(filterResult *interfaces.FilterResult) JSONStatistics {
	successCount := 0
	redirectCount := 0
	authCount := 0
	forbiddenCount := 0
	errorCount := 0

	for _, page := range filterResult.ValidPages {
		switch {
		case page.StatusCode >= 200 && page.StatusCode < 300:
			successCount++
		case page.StatusCode >= 300 && page.StatusCode < 400:
			redirectCount++
		case page.StatusCode == 401:
			authCount++
		case page.StatusCode == 403:
			forbiddenCount++
		case page.StatusCode >= 400:
			errorCount++
		}
	}

	return JSONStatistics{
		TotalScanned:   len(filterResult.ValidPages),
		SuccessCount:   successCount,
		RedirectCount:  redirectCount,
		AuthCount:      authCount,
		ForbiddenCount: forbiddenCount,
		ErrorCount:     errorCount,
	}
}

// saveJSONReport 保存JSON报告文件
func (jrg *JSONReportGenerator) saveJSONReport(data interface{}, target string, scanType string) (string, error) {
	// 序列化为JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}

	var filePath string

	if jrg.outputPath != "" {
		// 使用自定义输出路径
		filePath = jrg.outputPath

		// 确保输出目录存在
		outputDir := filepath.Dir(filePath)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %v", err)
		}
	} else {
		// 使用默认路径和文件名
		timestamp := time.Now().Format("20060102_150405")
		safeName := sanitizeFilename(target)
		fileName := fmt.Sprintf("%s_%s_%s.json", scanType, safeName, timestamp)

		// 确保输出目录存在
		outputDir := "./reports"
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %v", err)
		}

		filePath = filepath.Join(outputDir, fileName)
	}

	// 写入文件
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return "", fmt.Errorf("写入JSON文件失败: %v", err)
	}

	return filePath, nil
}

// sanitizeFilename 清理文件名中的非法字符
func sanitizeFilename(filename string) string {
	// 替换非法字符
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
	return replacer.Replace(filename)
}

// ===========================================
// 公共接口函数
// ===========================================

// GenerateJSONDirscanReport 生成目录扫描JSON报告的公共接口
func GenerateJSONDirscanReport(filterResult *interfaces.FilterResult, target string, scanParams map[string]interface{}) (string, error) {
	generator := NewJSONReportGenerator()
	return generator.GenerateDirscanReport(filterResult, target, scanParams)
}

// GenerateJSONFingerprintReport 生成指纹识别JSON报告的公共接口
func GenerateJSONFingerprintReport(matches []*fingerprint.FingerprintMatch, stats *fingerprint.Statistics, target string, scanParams map[string]interface{}) (string, error) {
	generator := NewJSONReportGenerator()
	return generator.GenerateFingerprintReport(matches, stats, target, scanParams)
}

// GenerateCustomJSONDirscanReport 生成自定义路径的目录扫描JSON报告
func GenerateCustomJSONDirscanReport(filterResult *interfaces.FilterResult, target string, scanParams map[string]interface{}, outputPath string) (string, error) {
	generator := NewCustomJSONReportGenerator(outputPath)
	return generator.GenerateDirscanReport(filterResult, target, scanParams)
}

// GenerateCustomJSONFingerprintReport 生成自定义路径的指纹识别JSON报告
func GenerateCustomJSONFingerprintReport(matches []*fingerprint.FingerprintMatch, stats *fingerprint.Statistics, target string, scanParams map[string]interface{}, outputPath string) (string, error) {
	generator := NewCustomJSONReportGenerator(outputPath)
	return generator.GenerateFingerprintReport(matches, stats, target, scanParams)
}
