package report

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "veo/internal/core/interfaces"
    "veo/internal/core/logger"
    portscanpkg "veo/internal/modules/portscan"

	"github.com/xuri/excelize/v2"
)

type ExcelReportType int

const (
	ExcelReportDirscan ExcelReportType = iota
	ExcelReportFingerprint
	ExcelReportDirscanAndFingerprint
)

// GenerateExcelReport 生成 Excel 报告
func GenerateExcelReport(filterResult *interfaces.FilterResult, reportType ExcelReportType, outputPath string) (string, error) {
	if filterResult == nil {
		return "", fmt.Errorf("过滤结果为空")
	}

	logger.Debugf("开始生成 Excel 报告: %s", outputPath)

	rows := buildExcelRows(filterResult, reportType)

	headers := excelHeaders(reportType)

	file := excelize.NewFile()
	sheetName := "Report"
	file.SetSheetName(file.GetSheetName(0), sheetName)

	for idx, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(idx+1, 1)
		file.SetCellValue(sheetName, cell, header)
	}

	for rowIdx, row := range rows {
		cell, _ := excelize.CoordinatesToCellName(1, rowIdx+2)
		rowCopy := row
		file.SetSheetRow(sheetName, cell, &rowCopy)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", fmt.Errorf("创建输出目录失败: %w", err)
	}

	if err := file.SaveAs(outputPath); err != nil {
		return "", fmt.Errorf("保存 Excel 报告失败: %w", err)
	}

	logger.Infof("Excel Report: %s", outputPath)
	return outputPath, nil
}

// GenerateExcelReportWithPorts 生成包含端口扫描结果的 Excel 报告（合并表格）
// 对于端口结果，将 "IP:Port" 写入 URL 列，其他列留空
func GenerateExcelReportWithPorts(filterResult *interfaces.FilterResult, reportType ExcelReportType, ports []portscanpkg.OpenPortResult, outputPath string) (string, error) {
    if filterResult == nil {
        return "", fmt.Errorf("过滤结果为空")
    }

    logger.Debugf("开始生成包含端口结果的 Excel 报告: %s", outputPath)

    rows := buildExcelRows(filterResult, reportType)

    headers := excelHeaders(reportType)

    // 将端口扫描结果附加到行尾
    if len(ports) > 0 {
        // 端口结果使用 URL 列，其他列置空
        colCount := len(headers)
        for _, r := range ports {
            row := make([]interface{}, colCount)
            if colCount > 0 {
                row[0] = fmt.Sprintf("%s:%d", r.IP, r.Port)
            }
            rows = append(rows, row)
        }
    }

    file := excelize.NewFile()
    sheetName := "Report"
    file.SetSheetName(file.GetSheetName(0), sheetName)

    for idx, header := range headers {
        cell, _ := excelize.CoordinatesToCellName(idx+1, 1)
        file.SetCellValue(sheetName, cell, header)
    }

    for rowIdx, row := range rows {
        cell, _ := excelize.CoordinatesToCellName(1, rowIdx+2)
        rowCopy := row
        file.SetSheetRow(sheetName, cell, &rowCopy)
    }

    if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
        return "", fmt.Errorf("创建输出目录失败: %w", err)
    }
    if err := file.SaveAs(outputPath); err != nil {
        return "", fmt.Errorf("保存 Excel 报告失败: %w", err)
    }
    logger.Infof("Excel Report: %s", outputPath)
    return outputPath, nil
}

func excelHeaders(reportType ExcelReportType) []string {
	switch reportType {
	case ExcelReportDirscanAndFingerprint:
		return []string{"URL", "状态码", "Content-length", "Content-type", "指纹名称", "指纹规则", "匹配内容"}
	case ExcelReportFingerprint:
		return []string{"URL", "标题", "指纹名称", "指纹规则", "匹配内容"}
	case ExcelReportDirscan:
		fallthrough
	default:
		return []string{"URL", "状态码", "标题", "Content-length", "Content-type", "指纹名称", "指纹规则", "匹配内容"}
	}
}

func buildExcelRows(filterResult *interfaces.FilterResult, reportType ExcelReportType) [][]interface{} {
	rows := make([][]interface{}, 0)
	pages := filterResult.ValidPages
	for _, page := range pages {
		fingerprints := page.Fingerprints
		if len(fingerprints) == 0 {
			rows = append(rows, buildExcelRow(page, nil, reportType))
			continue
		}
		for _, match := range fingerprints {
			matchCopy := match
			rows = append(rows, buildExcelRow(page, &matchCopy, reportType))
		}
	}

	if len(rows) == 0 {
		// 没有有效页面时提供空报告主体
		rows = append(rows, buildExcelRow(interfaces.HTTPResponse{}, nil, reportType))
	}

	return rows
}

func buildExcelRow(page interfaces.HTTPResponse, match *interfaces.FingerprintMatch, reportType ExcelReportType) []interface{} {
	var row []interface{}

	switch reportType {
	case ExcelReportDirscanAndFingerprint:
		row = append(row,
			page.URL,
			page.StatusCode,
			page.ContentLength,
			page.ContentType,
		)
	case ExcelReportFingerprint:
		row = append(row,
			page.URL,
			page.Title,
		)
	case ExcelReportDirscan:
		fallthrough
	default:
		row = append(row,
			page.URL,
			page.StatusCode,
			page.Title,
			page.ContentLength,
			page.ContentType,
		)
	}

	if match != nil {
		row = append(row, match.RuleName, match.Matcher, sanitizeSnippet(match.Snippet))
	} else {
		row = append(row, "", "", "")
	}

	return row
}

func sanitizeSnippet(snippet string) string {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" {
		return ""
	}
	if len(snippet) > 65535 {
		// 防止 Excel 单元格过长
		return snippet[:65532] + "..."
	}
	return snippet
}

// Optional helper to include timestamp or metadata if needed.
