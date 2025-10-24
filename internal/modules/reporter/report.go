package report

// report包用于生成扫描报告

import (
	"veo/internal/core/config"
	"veo/internal/core/interfaces"
	"veo/internal/core/logger"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ===========================================
// 报告数据结构
// ===========================================

// ReportData 报告数据结构体
// 包含生成Web报告所需的所有数据
type ReportData struct {
	Target         string                    `json:"target"`          // 扫描目标
	GeneratedAt    time.Time                 `json:"generated_at"`    // 生成时间
	ScanDuration   string                    `json:"scan_duration"`   // 扫描耗时
	TotalScanned   int                       `json:"total_scanned"`   // 总扫描数量
	SuccessCount   int                       `json:"success_count"`   // 成功响应数量(2xx)
	RedirectCount  int                       `json:"redirect_count"`  // 重定向数量(3xx)
	AuthCount      int                       `json:"auth_count"`      // 认证相关数量(401)
	ForbiddenCount int                       `json:"forbidden_count"` // 禁止访问数量(403)
	ErrorCount     int                       `json:"error_count"`     // 错误数量(4xx,5xx)
	Results        []interfaces.HTTPResponse `json:"results"`         // 详细结果列表
	FilterResult   *interfaces.FilterResult  `json:"filter_result"`   // 过滤结果统计
}

// ReportConfig 报告配置
type ReportConfig struct {
	OutputDir   string `json:"output_dir"`    // 输出目录
	FileName    string `json:"file_name"`     // 文件名（不含扩展名）
	IncludeBody bool   `json:"include_body"`  // 是否包含响应体
	MaxBodySize int    `json:"max_body_size"` // 最大响应体大小（字符数）
}

// ===========================================
// 报告生成器
// ===========================================

// WebReportGenerator Web报告生成器
type WebReportGenerator struct {
	config    *ReportConfig
	startTime time.Time
}

// NewWebReportGenerator 创建新的Web报告生成器
func NewWebReportGenerator(config *ReportConfig) *WebReportGenerator {
	if config == nil {
		config = getDefaultReportConfig()
	}

	return &WebReportGenerator{
		config:    config,
		startTime: time.Now(),
	}
}

// NewCustomReportGenerator 创建自定义输出路径的Web报告生成器
func NewCustomReportGenerator(outputPath string) *WebReportGenerator {
	// 解析输出路径
	outputDir := filepath.Dir(outputPath)
	fileName := filepath.Base(outputPath)

	// 移除.html扩展名作为文件名
	if strings.HasSuffix(strings.ToLower(fileName), ".html") {
		fileName = fileName[:len(fileName)-5]
	}

	config := &ReportConfig{
		OutputDir:   outputDir,
		FileName:    fileName,
		IncludeBody: true,
		MaxBodySize: 1000,
	}

	return &WebReportGenerator{
		config:    config,
		startTime: time.Now(),
	}
}

// getDefaultReportConfig 获取默认报告配置
func getDefaultReportConfig() *ReportConfig {
	// 尝试从配置文件读取报告配置
	if reportConfig := getReportConfigFromFile(); reportConfig != nil {
		return reportConfig
	}

	// 如果配置文件中没有，使用硬编码默认值
	return &ReportConfig{
		OutputDir:   "./reports",
		FileName:    "scan_report",
		IncludeBody: true,
		MaxBodySize: 1000, // 限制响应体显示最多1000字符
	}
}

// getReportConfigFromFile 从配置文件获取报告配置
func getReportConfigFromFile() *ReportConfig {
	configReport := config.GetReportConfig()
	if configReport == nil {
		return nil
	}

	// 将config包的ReportConfig转换为report包的ReportConfig
	reportConfig := &ReportConfig{
		OutputDir:   "./reports", // 使用固定默认值
		FileName:    configReport.FileName,
		IncludeBody: true, // 使用固定默认值
		MaxBodySize: configReport.MaxBodysize,
	}

	// 设置默认值（如果配置文件中为空）
	if reportConfig.FileName == "" {
		reportConfig.FileName = "scan_report"
	}
	if reportConfig.MaxBodySize == 0 {
		reportConfig.MaxBodySize = 1000
	}

	return reportConfig
}

// GenerateReport 生成Web报告
// 基于filter.go的FilterResult生成完整的Web扫描报告
func (wrg *WebReportGenerator) GenerateReport(filterResult *interfaces.FilterResult, target string) (string, error) {
	// 准备报告数据
	reportData, err := wrg.prepareReportData(filterResult, target)
	if err != nil {
		return "", fmt.Errorf("准备报告数据失败: %v", err)
	}

	// 生成HTML报告
	htmlContent, err := wrg.generateHTML(reportData)
	if err != nil {
		return "", fmt.Errorf("生成HTML内容失败: %v", err)
	}

	// 保存报告文件
	filePath, err := wrg.saveReport(htmlContent, target)
	if err != nil {
		return "", fmt.Errorf("保存报告文件失败: %v", err)
	}

	return filePath, nil
}

// prepareReportData 准备报告数据
func (wrg *WebReportGenerator) prepareReportData(filterResult *interfaces.FilterResult, target string) (*ReportData, error) {
	logger.Debug("[report.go] 准备报告数据")

	if filterResult == nil {
		return nil, fmt.Errorf("过滤结果为空")
	}

	// 使用最终有效页面作为报告数据
	results := filterResult.ValidPages
	if results == nil {
		results = make([]interfaces.HTTPResponse, 0)
	}

	// 处理响应体数据
	wrg.processResponseBodies(results)

	// 计算各类统计数据
	successCount, redirectCount, authCount, forbiddenCount, errorCount := wrg.calculateStatistics(results)

	// 计算扫描耗时
	scanDuration := time.Since(wrg.startTime).Round(time.Millisecond).String()

	// 按状态码和URL排序
	wrg.sortResults(results)

	reportData := &ReportData{
		Target:         target,
		GeneratedAt:    time.Now(),
		ScanDuration:   scanDuration,
		TotalScanned:   len(results),
		SuccessCount:   successCount,
		RedirectCount:  redirectCount,
		AuthCount:      authCount,
		ForbiddenCount: forbiddenCount,
		ErrorCount:     errorCount,
		Results:        results,
		FilterResult:   filterResult,
	}

	logger.Debug(fmt.Sprintf("[report.go] 报告数据准备完成 - 总数: %d, 成功: %d, 重定向: %d, 认证: %d, 禁止: %d, 错误: %d",
		len(results), successCount, redirectCount, authCount, forbiddenCount, errorCount))

	return reportData, nil
}

// processResponseBodies 处理响应体数据
func (wrg *WebReportGenerator) processResponseBodies(results []interfaces.HTTPResponse) {
	if !wrg.config.IncludeBody {
		return
	}

	for i := range results {
		// 限制响应体大小
		if len(results[i].Body) > wrg.config.MaxBodySize {
			results[i].ResponseBody = results[i].Body[:wrg.config.MaxBodySize] + "... (内容已截断)"
		} else {
			results[i].ResponseBody = results[i].Body
		}

		// 设置Length字段用于报告显示
		results[i].Length = results[i].ContentLength
	}
}

// calculateStatistics 计算各类统计数据
func (wrg *WebReportGenerator) calculateStatistics(results []interfaces.HTTPResponse) (int, int, int, int, int) {
	var successCount, redirectCount, authCount, forbiddenCount, errorCount int

	for _, result := range results {
		switch {
		case result.StatusCode >= 200 && result.StatusCode < 300:
			successCount++
		case result.StatusCode >= 300 && result.StatusCode < 400:
			redirectCount++
		case result.StatusCode == 401:
			authCount++
		case result.StatusCode == 403:
			forbiddenCount++
		case result.StatusCode >= 400:
			errorCount++
		}
	}

	return successCount, redirectCount, authCount, forbiddenCount, errorCount
}

// sortResults 对结果进行排序
func (wrg *WebReportGenerator) sortResults(results []interfaces.HTTPResponse) {
	sort.Slice(results, func(i, j int) bool {
		// 首先按状态码排序（成功的在前）
		if results[i].StatusCode != results[j].StatusCode {
			// 200系列排在最前面
			if results[i].StatusCode >= 200 && results[i].StatusCode < 300 {
				return true
			}
			if results[j].StatusCode >= 200 && results[j].StatusCode < 300 {
				return false
			}
			return results[i].StatusCode < results[j].StatusCode
		}
		// 相同状态码按URL排序
		return results[i].URL < results[j].URL
	})
}

// generateHTML 生成HTML内容
func (wrg *WebReportGenerator) generateHTML(data *ReportData) (string, error) {
	logger.Debug("[report.go] 生成HTML模板内容")

	// 创建模板函数
	funcMap := template.FuncMap{
		"add":            wrg.templateFuncAdd,
		"formatBytes":    wrg.templateFuncFormatBytes,
		"formatDuration": wrg.templateFuncFormatDuration,
		"truncate":       wrg.templateFuncTruncate,
	}

	// 解析模板
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("解析HTML模板失败: %v", err)
	}

	// 渲染模板
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染HTML模板失败: %v", err)
	}

	return buf.String(), nil
}

// saveReport 保存报告文件
func (wrg *WebReportGenerator) saveReport(htmlContent string, target string) (string, error) {
	logger.Debug("[report.go] 保存HTML报告文件")

	// 确保输出目录存在
	if err := os.MkdirAll(wrg.config.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 生成文件名
	var fileName string
	var filePath string

	// 检查是否为自定义路径（文件名不包含默认的scan_report前缀）
	if wrg.config.FileName != "scan_report" && !strings.Contains(wrg.config.FileName, "_") {
		// 自定义路径：直接使用指定的文件名
		fileName = wrg.config.FileName + ".html"
		filePath = filepath.Join(wrg.config.OutputDir, fileName)
	} else {
		// 默认路径：使用时间戳和目标名称
		timestamp := time.Now().Format("20060102_150405")
		safeName := wrg.sanitizeFilename(target)
		fileName = fmt.Sprintf("%s_%s_%s.html", wrg.config.FileName, safeName, timestamp)
		filePath = filepath.Join(wrg.config.OutputDir, fileName)
	}

	// 写入文件
	if err := os.WriteFile(filePath, []byte(htmlContent), 0644); err != nil {
		return "", fmt.Errorf("写入报告文件失败: %v", err)
	}

	// 获取绝对路径
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		logger.Warn("[report.go] 获取绝对路径失败，使用相对路径: ", err)
		return filePath, nil
	}

	return absPath, nil
}

// sanitizeFilename 清理文件名中的非法字符
func (wrg *WebReportGenerator) sanitizeFilename(name string) string {
	// 移除协议前缀
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimPrefix(name, "https://")

	// 替换非法字符
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"?", "_",
		"*", "_",
		"<", "_",
		">", "_",
		"|", "_",
		"\"", "_",
		" ", "_",
	)

	return replacer.Replace(name)
}

// ===========================================
// 模板函数
// ===========================================

// templateFuncAdd 模板函数：加法运算
func (wrg *WebReportGenerator) templateFuncAdd(a, b int) int {
	return a + b
}

// templateFuncFormatBytes 模板函数：格式化字节数
func (wrg *WebReportGenerator) templateFuncFormatBytes(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	} else {
		return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
	}
}

// templateFuncFormatDuration 模板函数：格式化持续时间
func (wrg *WebReportGenerator) templateFuncFormatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	} else {
		return fmt.Sprintf("%.2fs", float64(ms)/1000)
	}
}

// templateFuncTruncate 模板函数：截断文本
func (wrg *WebReportGenerator) templateFuncTruncate(text string, length int) string {
	if len(text) <= length {
		return text
	}
	return text[:length] + "..."
}

// ===========================================
// 公共接口函数
// ===========================================

// GenerateWebReport 生成Web报告的公共接口函数
// 可被其他模块调用以生成扫描报告
func GenerateWebReport(filterResult *interfaces.FilterResult, target string, config *ReportConfig) (string, error) {
	generator := NewWebReportGenerator(config)
	return generator.GenerateReport(filterResult, target)
}

// QuickReport 快速生成报告（使用默认配置）
func QuickReport(filterResult *interfaces.FilterResult, target string) (string, error) {
	return GenerateWebReport(filterResult, target, nil)
}

// ===========================================
// HTML模板定义
// ===========================================

// HTML模板定义 - 基于Tailwind CSS的简洁设计
const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scanner Report - {{.Target}}</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }

        .details-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }

        .details-content.expanded {
            max-height: 2000px;
        }

        .code-block {
            font-size: 11px;
            line-height: 1.4;
        }

        .table-cell {
            font-size: 12px;
        }

        .status-badge {
            font-size: 10px;
        }
    </style>
</head>
<body class="h-full bg-gray-50 text-xs">
    <div class="h-full flex flex-col">
        <!-- 顶部标题栏 -->
        <div class="bg-white border-b border-gray-200 px-4 py-3">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                    <h1 class="text-lg font-semibold text-gray-900">Security Scanner</h1>
                    <div class="flex items-center space-x-2">
                        <button onclick="expandAll()" class="px-2 py-1 text-xs bg-blue-500 text-white rounded hover:bg-blue-600">展开全部</button>
                        <button onclick="collapseAll()" class="px-2 py-1 text-xs bg-gray-500 text-white rounded hover:bg-gray-600">折叠全部</button>
                        <input type="text" id="filterInput" placeholder="过滤..." class="px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:border-blue-500">
                    </div>
                </div>
                <div class="flex items-center space-x-4 text-xs text-gray-500">
                    <span>{{.GeneratedAt.Format "2006-01-02 15:04:05"}}</span>
                    <span>耗时: {{.ScanDuration}}</span>
                </div>
            </div>
        </div>

        <!-- 统计概览 -->
        <div class="bg-white border-b border-gray-200 px-4 py-3">
            <div class="grid grid-cols-6 gap-3">
                <div class="text-center">
                    <div class="text-lg font-bold text-gray-700">{{.TotalScanned}}</div>
                    <div class="text-xs text-gray-500">总数</div>
                </div>
                <div class="text-center">
                    <div class="text-lg font-bold text-green-600">{{.SuccessCount}}</div>
                    <div class="text-xs text-gray-500">成功</div>
                </div>
                <div class="text-center">
                    <div class="text-lg font-bold text-yellow-600">{{.RedirectCount}}</div>
                    <div class="text-xs text-gray-500">重定向</div>
                </div>
                <div class="text-center">
                    <div class="text-lg font-bold text-blue-600">{{.AuthCount}}</div>
                    <div class="text-xs text-gray-500">认证</div>
                </div>
                <div class="text-center">
                    <div class="text-lg font-bold text-red-600">{{.ForbiddenCount}}</div>
                    <div class="text-xs text-gray-500">禁止</div>
                </div>
                <div class="text-center">
                    <div class="text-lg font-bold text-orange-600">{{.ErrorCount}}</div>
                    <div class="text-xs text-gray-500">错误</div>
                </div>
            </div>
            <div class="mt-2 text-xs text-gray-600">
                <span class="font-medium">目标:</span> {{.Target}}
            </div>
        </div>

        <!-- 数据表格 -->
        <div class="flex-1 overflow-auto bg-white">
            <table class="w-full">
                <thead class="bg-gray-50 sticky top-0">
                    <tr class="border-b border-gray-200">
                        <th class="px-2 py-2 text-left text-xs font-medium text-gray-700 w-12">#</th>
                        <th class="px-2 py-2 text-left text-xs font-medium text-gray-700 w-20">状态</th>
                        <th class="px-2 py-2 text-left text-xs font-medium text-gray-700">URL</th>
                        <th class="px-2 py-2 text-left text-xs font-medium text-gray-700 w-32">标题</th>
                        <th class="px-2 py-2 text-left text-xs font-medium text-gray-700 w-16">大小</th>
                        <th class="px-2 py-2 text-left text-xs font-medium text-gray-700 w-16">耗时</th>
                        <th class="px-2 py-2 text-left text-xs font-medium text-gray-700 w-12">深度</th>
                        <th class="px-2 py-2 text-left text-xs font-medium text-gray-700 w-12">详情</th>
                    </tr>
                </thead>
                <tbody id="resultsTable">
                    {{range $index, $result := .Results}}
                    <tr class="border-b border-gray-100 hover:bg-gray-50 filterable-row"
                        data-url="{{$result.URL}}" data-status="{{$result.StatusCode}}" data-title="{{$result.Title}}">
                        <td class="px-2 py-1 table-cell text-gray-600">{{add $index 1}}</td>
                        <td class="px-2 py-1">
                            <span class="status-badge px-1 py-0.5 rounded text-white font-medium
                                {{if eq $result.StatusCode 200}}bg-green-500
                                {{else if and (ge $result.StatusCode 300) (lt $result.StatusCode 400)}}bg-yellow-500
                                {{else if eq $result.StatusCode 401}}bg-blue-500
                                {{else if eq $result.StatusCode 403}}bg-red-500
                                {{else if and (ge $result.StatusCode 400) (lt $result.StatusCode 500)}}bg-red-600
                                {{else}}bg-orange-500{{end}}">
                                {{$result.StatusCode}}
                            </span>
                        </td>
                        <td class="px-2 py-1">
                            <a href="{{$result.URL}}" target="_blank" class="table-cell text-blue-600 hover:text-blue-800 underline">{{$result.URL}}</a>
                            {{if $result.IsDirectory}}<span class="ml-1 text-yellow-500">📁</span>{{end}}
                        </td>
                        <td class="px-2 py-1 table-cell text-gray-700 truncate max-w-32" title="{{$result.Title}}">{{$result.Title}}</td>
                        <td class="px-2 py-1 table-cell text-gray-600">{{formatBytes $result.Length}}</td>
                        <td class="px-2 py-1 table-cell text-gray-600">{{formatDuration $result.Duration}}</td>
                        <td class="px-2 py-1 table-cell text-gray-600">
                            {{if gt $result.Depth 0}}L{{$result.Depth}}{{else}}-{{end}}
                        </td>
                        <td class="px-2 py-1">
                            <button onclick="toggleDetails({{$index}})"
                                    class="w-6 h-6 text-xs bg-gray-200 hover:bg-gray-300 rounded flex items-center justify-center">
                                <span id="toggle-{{$index}}">+</span>
                            </button>
                        </td>
                    </tr>
                    <!-- 详细信息行 -->
                    <tr id="details-{{$index}}" class="details-row hidden">
                        <td colspan="8" class="px-4 py-3 bg-gray-50">
                            <div class="details-content" id="content-{{$index}}">
                                <div class="grid grid-cols-2 gap-4">
                                    <!-- 基本信息 -->
                                    <div>
                                        <h4 class="text-sm font-medium text-gray-900 mb-2">基本信息</h4>
                                        <div class="space-y-1 text-xs">
                                            <div><span class="font-medium">URL:</span> {{$result.URL}}</div>
                                            <div><span class="font-medium">状态:</span> {{$result.StatusCode}}</div>
                                            <div><span class="font-medium">类型:</span> {{$result.ContentType}}</div>
                                            <div><span class="font-medium">大小:</span> {{formatBytes $result.Length}}</div>
                                            <div><span class="font-medium">耗时:</span> {{formatDuration $result.Duration}}</div>
                                            {{if $result.Server}}<div><span class="font-medium">服务器:</span> {{$result.Server}}</div>{{end}}
                                        </div>
                                    </div>

                                    <!-- 请求头 -->
                                    <div>
                                        <h4 class="text-sm font-medium text-gray-900 mb-2">请求头</h4>
                                        <div class="bg-white border border-gray-200 rounded p-2 max-h-32 overflow-y-auto">
                                            <pre class="code-block text-gray-700">{{range $name, $values := $result.RequestHeaders}}{{$name}}: {{range $i, $value := $values}}{{if $i}}, {{end}}{{$value}}{{end}}
{{end}}</pre>
                                        </div>
                                    </div>

                                    <!-- 响应头 -->
                                    <div>
                                        <h4 class="text-sm font-medium text-gray-900 mb-2">响应头</h4>
                                        <div class="bg-white border border-gray-200 rounded p-2 max-h-32 overflow-y-auto">
                                            <pre class="code-block text-gray-700">{{range $name, $values := $result.ResponseHeaders}}{{$name}}: {{range $i, $value := $values}}{{if $i}}, {{end}}{{$value}}{{end}}
{{end}}</pre>
                                        </div>
                                    </div>

                                    <!-- 响应体 -->
                                    {{if $result.ResponseBody}}
                                    <div class="col-span-2">
                                        <h4 class="text-sm font-medium text-gray-900 mb-2">响应体</h4>
                                        <div class="bg-white border border-gray-200 rounded p-2 max-h-48 overflow-y-auto">
                                            <pre class="code-block text-gray-700">{{truncate $result.ResponseBody 1000}}</pre>
                                        </div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // 过滤功能
        document.getElementById('filterInput').addEventListener('input', function(e) {
            const filter = e.target.value.toLowerCase();
            const rows = document.querySelectorAll('.filterable-row');

            rows.forEach(row => {
                const url = row.dataset.url?.toLowerCase() || '';
                const status = row.dataset.status?.toLowerCase() || '';
                const title = row.dataset.title?.toLowerCase() || '';

                if (url.includes(filter) || status.includes(filter) || title.includes(filter)) {
                    row.style.display = '';
                    // 如果详情行存在且可见，也显示它
                    const nextRow = row.nextElementSibling;
                    if (nextRow && nextRow.classList.contains('details-row') && !nextRow.classList.contains('hidden')) {
                        nextRow.style.display = '';
                    }
                } else {
                    row.style.display = 'none';
                    // 隐藏对应的详情行
                    const nextRow = row.nextElementSibling;
                    if (nextRow && nextRow.classList.contains('details-row')) {
                        nextRow.style.display = 'none';
                    }
                }
            });
        });

        // 切换详细信息
        function toggleDetails(index) {
            const detailsRow = document.getElementById('details-' + index);
            const content = document.getElementById('content-' + index);
            const toggle = document.getElementById('toggle-' + index);

            if (detailsRow.classList.contains('hidden')) {
                detailsRow.classList.remove('hidden');
                content.classList.add('expanded');
                toggle.textContent = '−';
            } else {
                detailsRow.classList.add('hidden');
                content.classList.remove('expanded');
                toggle.textContent = '+';
            }
        }

        // 展开所有详细信息
        function expandAll() {
            document.querySelectorAll('.details-row').forEach((row, index) => {
                if (row.classList.contains('hidden')) {
                    const rowIndex = row.id.split('-')[1];
                    toggleDetails(rowIndex);
                }
            });
        }

        // 折叠所有详细信息
        function collapseAll() {
            document.querySelectorAll('.details-row').forEach((row, index) => {
                if (!row.classList.contains('hidden')) {
                    const rowIndex = row.id.split('-')[1];
                    toggleDetails(rowIndex);
                }
            });
        }

        // 快捷键支持
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                document.getElementById('filterInput').focus();
            } else if (e.ctrlKey && e.key === 'e') {
                e.preventDefault();
                expandAll();
            } else if (e.ctrlKey && e.key === 'w') {
                e.preventDefault();
                collapseAll();
            }
        });
    </script>
</body>
</html>`
