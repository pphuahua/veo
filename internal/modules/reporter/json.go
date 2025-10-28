package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"veo/internal/core/interfaces"
	"veo/internal/core/logger"
	"veo/internal/modules/fingerprint"
)

type SDKResult struct {
	Summary            SDKSummary      `json:"summary"`
	DirscanResults     []SDKPageResult `json:"dirscan_results,omitempty"`
	FingerprintTargets []SDKPageResult `json:"fingerprint_targets,omitempty"`
}

type SDKSummary struct {
	Total                   int   `json:"total"`
	DirscanCount            int   `json:"dirscan_count"`
	FingerprintCount        int   `json:"fingerprint_count"`
	DurationMs              int64 `json:"duration_ms"`
	FingerprintRules        int   `json:"fingerprint_rules"`
	DirTargetsCount         int   `json:"dir_targets_count"`
	FingerprintTargetsCount int   `json:"fingerprint_targets_count"`
}

type SDKPageResult struct {
	URL           string                      `json:"url"`
	StatusCode    int                         `json:"status_code"`
	Title         string                      `json:"title"`
	ContentLength int64                       `json:"content_length"`
	DurationMs    int64                       `json:"duration_ms"`
	ContentType   string                      `json:"content_type,omitempty"`
	Fingerprints  []SDKFingerprintMatchOutput `json:"fingerprints,omitempty"`
}

type SDKFingerprintMatchOutput struct {
	RuleName    string `json:"rule_name"`
	RuleContent string `json:"rule_content,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
}

// JSONReportGenerator JSON报告生成器
type JSONReportGenerator struct {
	startTime  time.Time
	outputPath string
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
	dirPages := extractResponses(filterResult)
	result := jrg.buildSDKResult(dirPages, nil, nil, nil, scanParams)
	return jrg.saveSDKResult(result, target, "dirscan")
}

// GenerateFingerprintReport 生成指纹识别JSON报告
func (jrg *JSONReportGenerator) GenerateFingerprintReport(responses []interfaces.HTTPResponse, matches []*fingerprint.FingerprintMatch, stats *fingerprint.Statistics, target string, scanParams map[string]interface{}) (string, error) {
	result := jrg.buildSDKResult(nil, responses, matches, stats, scanParams)
	return jrg.saveSDKResult(result, target, "fingerprint")
}

// saveSDKResult 保存与SDK一致的JSON报告
func (jrg *JSONReportGenerator) saveSDKResult(result *SDKResult, target string, scanType string) (string, error) {
	if result == nil {
		return "", fmt.Errorf("报告数据为空")
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}

	var filePath string

	if jrg.outputPath != "" {
		filePath = jrg.outputPath
		outputDir := filepath.Dir(filePath)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %v", err)
		}
	} else {
		timestamp := time.Now().Format("20060102_150405")
		safeName := sanitizeFilename(target)
		fileName := fmt.Sprintf("%s_%s_%s.json", scanType, safeName, timestamp)

		outputDir := "./reports"
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %v", err)
		}

		filePath = filepath.Join(outputDir, fileName)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", fmt.Errorf("写入JSON文件失败: %v", err)
	}

	logger.Debugf("JSON报告已生成: %s", filePath)
	return filePath, nil
}

// GenerateJSONDirscanReport 生成目录扫描JSON报告的公共接口
func GenerateJSONDirscanReport(responses []interfaces.HTTPResponse, target string, scanParams map[string]interface{}) (string, error) {
	generator := NewJSONReportGenerator()
	return generator.GenerateDirscanReport(&interfaces.FilterResult{ValidPages: responses}, target, scanParams)
}

// GenerateJSONFingerprintReport 生成指纹识别JSON报告的公共接口
func GenerateJSONFingerprintReport(responses []interfaces.HTTPResponse, matches []*fingerprint.FingerprintMatch, stats *fingerprint.Statistics, target string, scanParams map[string]interface{}) (string, error) {
	generator := NewJSONReportGenerator()
	return generator.GenerateFingerprintReport(responses, matches, stats, target, scanParams)
}

// GenerateCustomJSONDirscanReport 生成自定义路径的目录扫描JSON报告
func GenerateCustomJSONDirscanReport(responses []interfaces.HTTPResponse, target string, scanParams map[string]interface{}, outputPath string) (string, error) {
	generator := NewCustomJSONReportGenerator(outputPath)
	return generator.GenerateDirscanReport(&interfaces.FilterResult{ValidPages: responses}, target, scanParams)
}

// GenerateCustomJSONFingerprintReport 生成自定义路径的指纹识别JSON报告
func GenerateCustomJSONFingerprintReport(responses []interfaces.HTTPResponse, matches []*fingerprint.FingerprintMatch, stats *fingerprint.Statistics, target string, scanParams map[string]interface{}, outputPath string) (string, error) {
	generator := NewCustomJSONReportGenerator(outputPath)
	return generator.GenerateFingerprintReport(responses, matches, stats, target, scanParams)
}

func GenerateCombinedJSON(dirPages []interfaces.HTTPResponse, fingerprintPages []interfaces.HTTPResponse, matches []*fingerprint.FingerprintMatch, stats *fingerprint.Statistics, scanParams map[string]interface{}) (string, error) {
	generator := NewJSONReportGenerator()
	result := generator.buildSDKResult(dirPages, fingerprintPages, matches, stats, scanParams)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}
	return string(data), nil
}

// extractResponses 提取过滤结果中的有效页面
func extractResponses(filterResult *interfaces.FilterResult) []interfaces.HTTPResponse {
	if filterResult == nil {
		return nil
	}

	pages := filterResult.ValidPages
	if len(pages) == 0 {
		return nil
	}

	copied := make([]interfaces.HTTPResponse, len(pages))
	copy(copied, pages)
	return copied
}

// buildSDKResult 根据输入数据构建与SDK一致的结果结构
func (jrg *JSONReportGenerator) buildSDKResult(dirPages []interfaces.HTTPResponse, fpPages []interfaces.HTTPResponse, matches []*fingerprint.FingerprintMatch, stats *fingerprint.Statistics, scanParams map[string]interface{}) *SDKResult {
	dirResults := makeDirscanPageResults(dirPages)
	fpResults := makeFingerprintPageResults(fpPages, matches)

	duration := time.Since(jrg.startTime).Milliseconds()

	summary := SDKSummary{
		Total:                   len(dirResults) + len(fpResults),
		DirscanCount:            len(dirResults),
		FingerprintCount:        len(fpResults),
		DurationMs:              duration,
		FingerprintRules:        rulesLoaded(stats, scanParams),
		DirTargetsCount:         intFromParams(scanParams, "dir_targets_count", len(dirResults)),
		FingerprintTargetsCount: intFromParams(scanParams, "fingerprint_targets_count", len(fpResults)),
	}

	return &SDKResult{
		Summary:            summary,
		DirscanResults:     dirResults,
		FingerprintTargets: fpResults,
	}
}

// makeDirscanPageResults 构造目录扫描结果列表
func makeDirscanPageResults(pages []interfaces.HTTPResponse) []SDKPageResult {
	if len(pages) == 0 {
		return nil
	}

	results := make([]SDKPageResult, 0, len(pages))
	for _, page := range pages {
		length := page.ContentLength
		if length == 0 {
			length = page.Length
		}

		results = append(results, SDKPageResult{
			URL:           page.URL,
			StatusCode:    page.StatusCode,
			Title:         page.Title,
			ContentLength: length,
			DurationMs:    page.Duration,
			ContentType:   page.ContentType,
			Fingerprints:  toSDKMatchesFromInterfaces(page.Fingerprints),
		})
	}

	return results
}

// makeFingerprintPageResults 构造指纹识别结果列表
func makeFingerprintPageResults(pages []interfaces.HTTPResponse, matches []*fingerprint.FingerprintMatch) []SDKPageResult {
	if len(pages) == 0 && len(matches) == 0 {
		return nil
	}

	matchMap := groupMatchesByURL(matches)
	results := make([]SDKPageResult, 0, len(pages)+len(matchMap))
	seen := make(map[string]bool, len(pages))

	for _, page := range pages {
		length := page.ContentLength
		if length == 0 {
			length = page.Length
		}

		existing := toSDKMatchesFromInterfaces(page.Fingerprints)
		fps := matchMap[page.URL]
		if len(fps) > 0 {
			existing = mergeFingerprintOutputs(existing, fps)
		}
		results = append(results, SDKPageResult{
			URL:           page.URL,
			StatusCode:    page.StatusCode,
			Title:         page.Title,
			ContentLength: length,
			DurationMs:    page.Duration,
			ContentType:   page.ContentType,
			Fingerprints:  existing,
		})
		seen[page.URL] = true
	}

	// 对于仅有指纹匹配记录但没有响应的URL，也进行输出
	for url, fps := range matchMap {
		if seen[url] {
			continue
		}
		if len(fps) == 0 {
			continue
		}
		results = append(results, SDKPageResult{
			URL:          url,
			Fingerprints: fps,
		})
	}

	return results
}

// groupMatchesByURL 将指纹匹配结果按URL分组
func groupMatchesByURL(matches []*fingerprint.FingerprintMatch) map[string][]SDKFingerprintMatchOutput {
	if len(matches) == 0 {
		return nil
	}

	grouped := make(map[string][]SDKFingerprintMatchOutput)
	for _, match := range matches {
		if match == nil {
			continue
		}
		url := match.URL
		grouped[url] = append(grouped[url], SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: match.DSLMatched,
			Snippet:     match.Snippet,
		})
	}
	return grouped
}

func toSDKMatchesFromInterfaces(matches []interfaces.FingerprintMatch) []SDKFingerprintMatchOutput {
	if len(matches) == 0 {
		return nil
	}

	outputs := make([]SDKFingerprintMatchOutput, 0, len(matches))
	for _, match := range matches {
		outputs = append(outputs, SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: match.Matcher,
			Snippet:     match.Snippet,
		})
	}

	return outputs
}

func mergeFingerprintOutputs(base []SDKFingerprintMatchOutput, extra []SDKFingerprintMatchOutput) []SDKFingerprintMatchOutput {
	if len(extra) == 0 {
		return base
	}

	if len(base) == 0 {
		merged := make([]SDKFingerprintMatchOutput, len(extra))
		copy(merged, extra)
		return merged
	}

	existing := make(map[string]struct{}, len(base))
	for _, item := range base {
		key := item.RuleName + "|" + item.RuleContent + "|" + item.Snippet
		existing[key] = struct{}{}
	}

	for _, item := range extra {
		key := item.RuleName + "|" + item.RuleContent + "|" + item.Snippet
		if _, ok := existing[key]; ok {
			continue
		}
		base = append(base, item)
	}

	return base
}

// rulesLoaded 计算指纹规则数量
func rulesLoaded(stats *fingerprint.Statistics, params map[string]interface{}) int {
	if stats != nil {
		return stats.RulesLoaded
	}
	return intFromParams(params, "fingerprint_rules_loaded", 0)
}

// intFromParams 从参数映射中提取整数值
func intFromParams(params map[string]interface{}, key string, fallback int) int {
	if params == nil {
		return fallback
	}
	value, ok := params[key]
	if !ok {
		return fallback
	}

	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return fallback
	}
}

// sanitizeFilename 清理文件名中的非法字符
func sanitizeFilename(filename string) string {
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
