package ports

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	aliasFiles = map[string]string{
		"web":     "configs/port/web.txt",
		"service": "configs/port/service.txt",
		"top5000": "configs/port/top5000.txt",
		"top1000": "configs/port/top1000.txt",
	}

	// ErrEmptyExpression 表示端口表达式为空
	ErrEmptyExpression = errors.New("端口表达式不能为空")
)

// ResolveExpression 根据用户输入解析最终的端口表达式
// 返回值：解析后的表达式、使用的字典路径（若有）、错误
func ResolveExpression(raw string) (string, string, error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", "", ErrEmptyExpression
	}

	lower := strings.ToLower(clean)
	switch lower {
	case "all":
		return "1-65535", "all", nil
	}

	if path, ok := aliasFiles[lower]; ok {
		expr, err := loadPortFile(path)
		if err != nil {
			return "", path, err
		}
		return expr, path, nil
	}

	if strings.ContainsAny(clean, "/\\") || strings.HasSuffix(lower, ".txt") {
		expr, err := loadPortFile(clean)
		if err != nil {
			return "", clean, err
		}
		return expr, clean, nil
	}

	if isPortExpression(clean) {
		return clean, "", nil
	}

	candidate := clean
	if !strings.HasSuffix(strings.ToLower(candidate), ".txt") {
		candidate = candidate + ".txt"
	}
	candidate = filepath.Join("configs/port", candidate)
	if expr, err := loadPortFile(candidate); err == nil {
		return expr, candidate, nil
	}

	if isPortExpression(clean) {
		return clean, "", nil
	}

	return "", "", fmt.Errorf("无法解析端口参数 '%s'，请使用端口范围或端口字典名称 (web/service/top1000/all)", clean)
}

func loadPortFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	ports := normalizePortList(string(data))
	if ports == "" {
		return "", fmt.Errorf("端口字典 %s 为空", path)
	}
	return ports, nil
}

func normalizePortList(content string) string {
	if content == "" {
		return ""
	}
	replacer := strings.NewReplacer("\r", "\n", "\t", "\n", ";", "\n")
	clean := replacer.Replace(content)
	fields := strings.FieldsFunc(clean, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	return strings.Join(fields, ",")
}

func isPortExpression(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			continue
		case r == ',' || r == '-' || r == ' ' || r == '\t':
			continue
		default:
			return false
		}
	}
	return true
}
