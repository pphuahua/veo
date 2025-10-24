package batch

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"veo/internal/core/logger"
)

// TargetParser 目标文件解析器
type TargetParser struct{}

// NewTargetParser 创建目标文件解析器
func NewTargetParser() *TargetParser {
	return &TargetParser{}
}

// ParseFile 从文件解析目标列表
func (tp *TargetParser) ParseFile(filePath string) ([]string, error) {
	logger.Debugf("开始解析目标文件: %s", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("无法打开目标文件: %v", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		targets = append(targets, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件时发生错误: %v", err)
	}

	logger.Debugf("从文件解析到 %d 个目标", len(targets))
	return targets, nil
}

// NormalizeURL 智能URL标准化
// 根据端口自动判断协议，返回可能的URL列表
func (tp *TargetParser) NormalizeURL(target string) []string {
	logger.Debugf("开始标准化目标: %s", target)

	// 如果已经有协议前缀，直接返回
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}

	// 解析主机和端口
	host, port, err := tp.parseHostPort(target)
	if err != nil {
		logger.Debugf("解析主机端口失败: %v，同时尝试HTTP和HTTPS协议", err)
		// [重要] 连通性修复：解析失败时同时尝试HTTP和HTTPS协议
		return []string{"http://" + target, "https://" + target}
	}

	// 根据端口判断协议
	protocols := tp.determineProtocols(port)

	var urls []string
	for _, protocol := range protocols {
		if port == 0 {
			// [重要] 连通性修复：没有指定端口时，使用协议默认端口
			urls = append(urls, fmt.Sprintf("%s://%s", protocol, host))
		} else if port == 80 && protocol == "http" {
			// 默认HTTP端口，不显示端口号
			urls = append(urls, fmt.Sprintf("%s://%s", protocol, host))
		} else if port == 443 && protocol == "https" {
			// 默认HTTPS端口，不显示端口号
			urls = append(urls, fmt.Sprintf("%s://%s", protocol, host))
		} else {
			// 非默认端口，显示端口号
			urls = append(urls, fmt.Sprintf("%s://%s:%d", protocol, host, port))
		}
	}

	logger.Debugf("目标 %s 标准化为: %v", target, urls)
	return urls
}

// parseHostPort 解析主机和端口
func (tp *TargetParser) parseHostPort(target string) (string, int, error) {
	// 尝试解析为 host:port 格式
	if strings.Contains(target, ":") {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			return "", 0, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("无效的端口号: %s", portStr)
		}

		return host, port, nil
	}

	// 没有端口，返回主机和默认端口列表
	return target, 0, nil
}

// determineProtocols 根据端口确定协议
func (tp *TargetParser) determineProtocols(port int) []string {
	switch port {
	case 80:
		return []string{"http"}
	case 443:
		return []string{"https"}
	case 0:
		// 没有指定端口，尝试常用端口
		return []string{"http", "https"}
	default:
		// 其他端口，同时尝试http和https
		return []string{"http", "https"}
	}
}

// ValidateURL 验证URL格式
func (tp *TargetParser) ValidateURL(target string) error {
	// 确保URL有协议前缀
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	// 解析URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("无效的URL格式: %v", err)
	}

	// 验证主机名
	if parsedURL.Host == "" {
		return fmt.Errorf("URL缺少主机名")
	}

	return nil
}
