package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"veo/internal/core/logger"
	"veo/internal/core/types"
)

// PortscanJSONSummary 简要统计
type PortscanJSONSummary struct {
	Count      int    `json:"count"`
	Generated  string `json:"generated"`
	TargetHint string `json:"target_hint,omitempty"`
}

// PortscanJSONFile 输出结构
type PortscanJSONFile struct {
	Summary PortscanJSONSummary    `json:"summary"`
	Results []types.OpenPortResult `json:"results"`
}

// GeneratePortscanJSON 生成端口扫描JSON报告（默认路径）
// 参数：
//   - results: 端口扫描结果
//   - target: 目标标识（用于文件名提示）
//
// 返回：输出文件路径
func GeneratePortscanJSON(results []types.OpenPortResult, target string) (string, error) {
	ts := time.Now().Format("20060102_150405")
	if target == "" {
		target = "portscan"
	}
	fileName := fmt.Sprintf("portscan_%s_%s.json", sanitizeFilename(target), ts)
	outDir := "./reports"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("创建输出目录失败: %w", err)
	}
	path := filepath.Join(outDir, fileName)
	return GenerateCustomPortscanJSON(results, target, path)
}

// GenerateCustomPortscanJSON 生成端口扫描JSON报告（自定义路径）
func GenerateCustomPortscanJSON(results []types.OpenPortResult, target, outputPath string) (string, error) {
	data := PortscanJSONFile{
		Summary: PortscanJSONSummary{
			Count:      len(results),
			Generated:  time.Now().Format(time.RFC3339),
			TargetHint: target,
		},
		Results: results,
	}

	// 序列化
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", fmt.Errorf("创建输出目录失败: %w", err)
	}
	if err := os.WriteFile(outputPath, b, 0o644); err != nil {
		return "", fmt.Errorf("写入JSON失败: %w", err)
	}
	logger.Debugf("JSON报告已生成: %s", outputPath)
	return outputPath, nil
}
