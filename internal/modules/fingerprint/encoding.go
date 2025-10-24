package fingerprint

import (
	"veo/internal/core/logger"
	"io"
	"regexp"
	"strings"

	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// ===========================================
// 字符编码处理工具
// ===========================================

// EncodingDetector 字符编码检测器
type EncodingDetector struct{}

// NewEncodingDetector 创建编码检测器
func NewEncodingDetector() *EncodingDetector {
	return &EncodingDetector{}
}

// DetectAndConvert 检测并转换字符编码
func (ed *EncodingDetector) DetectAndConvert(body, contentType string) string {
	// 如果内容为空，直接返回
	if body == "" {
		return body
	}

	// 1. 首先检查Content-Type中的charset
	if charset := ed.extractCharsetFromContentType(contentType); charset != "" {
		if converted := ed.convertCharset(body, charset); converted != "" {
			logger.Debugf("使用Content-Type检测到编码: %s", charset)
			return converted
		}
	}

	// 2. 检查HTML中的meta标签
	if charset := ed.extractCharsetFromMeta(body); charset != "" {
		if converted := ed.convertCharset(body, charset); converted != "" {
			logger.Debugf("使用Meta标签检测到编码: %s", charset)
			return converted
		}
	}

	// 3. 使用库进行字符编码检测
	if detectedCharset, confidence := ed.detectCharsetFromContent(body); confidence > 0.8 {
		if converted := ed.convertCharset(body, detectedCharset); converted != "" {
			logger.Debugf("自动检测到编码: %s (置信度: %.2f)", detectedCharset, confidence)
			return converted
		}
	}

	// 4. 如果检测失败，返回原始内容
	return body
}

// extractCharsetFromContentType 从Content-Type中提取charset
func (ed *EncodingDetector) extractCharsetFromContentType(contentType string) string {
	if contentType == "" {
		return ""
	}

	charsetRegex := regexp.MustCompile(`charset=([^;,\s]+)`)
	matches := charsetRegex.FindStringSubmatch(strings.ToLower(contentType))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// extractCharsetFromMeta 从HTML meta标签中提取charset
func (ed *EncodingDetector) extractCharsetFromMeta(body string) string {
	// 检查HTML5格式的meta charset
	charsetRegex := regexp.MustCompile(`(?i)<meta\s+charset\s*=\s*["']?([^"'>\s]+)`)
	matches := charsetRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.ToLower(strings.TrimSpace(matches[1]))
	}

	// 检查传统格式的meta http-equiv
	httpEquivRegex := regexp.MustCompile(`(?i)<meta\s+http-equiv\s*=\s*["']?content-type["']?\s+content\s*=\s*["']?[^"'>]*charset=([^"'>\s;]+)`)
	matches = httpEquivRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.ToLower(strings.TrimSpace(matches[1]))
	}

	return ""
}

// detectCharsetFromContent 从内容检测字符编码
func (ed *EncodingDetector) detectCharsetFromContent(body string) (string, float64) {
	// 使用golang.org/x/net/html/charset进行检测
	_, name, certain := charset.DetermineEncoding([]byte(body), "")

	confidence := 0.5 // 默认置信度
	if certain {
		confidence = 0.9
	}

	return name, confidence
}

// convertCharset 转换字符编码
func (ed *EncodingDetector) convertCharset(body, charset string) string {
	charset = strings.ToLower(charset)

	// 如果已经是UTF-8，直接返回
	if charset == "utf-8" || charset == "utf8" {
		return body
	}

	// 处理GBK/GB2312编码
	if charset == "gbk" || charset == "gb2312" || charset == "gb18030" {
		return ed.convertFromGBK(body)
	}

	// 处理其他编码
	if charset == "big5" {
		return ed.convertFromBig5(body)
	}

	// 其他编码暂时返回原始内容
	logger.Debugf("不支持的编码格式: %s, 返回原始内容", charset)
	return body
}

// convertFromGBK 从GBK编码转换为UTF-8
func (ed *EncodingDetector) convertFromGBK(gbkStr string) string {
	reader := transform.NewReader(strings.NewReader(gbkStr), simplifiedchinese.GBK.NewDecoder())
	utf8Bytes, err := io.ReadAll(reader)
	if err != nil {
		logger.Debugf("GBK转换失败: %v", err)
		return gbkStr
	}
	return string(utf8Bytes)
}

// convertFromBig5 从Big5编码转换为UTF-8
func (ed *EncodingDetector) convertFromBig5(big5Str string) string {
	// Big5编码处理（简单实现，可以扩展）
	logger.Debugf("Big5编码检测，暂时返回原始内容")
	return big5Str
}

// ===========================================
// HTML实体解码
// ===========================================

// HTMLEntityDecoder HTML实体解码器
type HTMLEntityDecoder struct{}

// NewHTMLEntityDecoder 创建HTML实体解码器
func NewHTMLEntityDecoder() *HTMLEntityDecoder {
	return &HTMLEntityDecoder{}
}

// DecodeHTMLEntities 解码HTML实体
func (hed *HTMLEntityDecoder) DecodeHTMLEntities(text string) string {
	// 常见HTML实体解码
	replacements := map[string]string{
		"&lt;":    "<",
		"&gt;":    ">",
		"&amp;":   "&",
		"&quot;":  "\"",
		"&#39;":   "'",
		"&nbsp;":  " ",
		"&copy;":  "©",
		"&reg;":   "®",
		"&trade;": "™",
	}

	result := text
	for entity, replacement := range replacements {
		result = strings.ReplaceAll(result, entity, replacement)
	}

	// 处理数字实体 &#数字;
	numericEntityRegex := regexp.MustCompile(`&#(\d+);`)
	result = numericEntityRegex.ReplaceAllStringFunc(result, func(match string) string {
		// 简单处理常见的数字实体
		return match // 暂时保持原样，避免复杂解析
	})

	return result
}

// ===========================================
// 全局实例（单例模式）
// ===========================================

var (
	globalEncodingDetector  *EncodingDetector
	globalHTMLEntityDecoder *HTMLEntityDecoder
)

// GetEncodingDetector 获取全局编码检测器实例
func GetEncodingDetector() *EncodingDetector {
	if globalEncodingDetector == nil {
		globalEncodingDetector = NewEncodingDetector()
	}
	return globalEncodingDetector
}

// GetHTMLEntityDecoder 获取全局HTML实体解码器实例
func GetHTMLEntityDecoder() *HTMLEntityDecoder {
	if globalHTMLEntityDecoder == nil {
		globalHTMLEntityDecoder = NewHTMLEntityDecoder()
	}
	return globalHTMLEntityDecoder
}
