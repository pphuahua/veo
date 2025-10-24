package fingerprint

import (
	"veo/internal/core/logger"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// ===========================================
// DSL解析器实现
// ===========================================

// NewDSLParser 创建DSL解析器
func NewDSLParser() *DSLParser {
	return &DSLParser{}
}

// EvaluateDSL 评估DSL表达式
func (p *DSLParser) EvaluateDSL(dsl string, ctx *DSLContext) bool {
	// 预处理DSL表达式
	dsl = strings.TrimSpace(dsl)
	if dsl == "" {
		return false
	}

	// 移除外层引号
	if (strings.HasPrefix(dsl, "\"") && strings.HasSuffix(dsl, "\"")) ||
		(strings.HasPrefix(dsl, "'") && strings.HasSuffix(dsl, "'")) {
		dsl = dsl[1 : len(dsl)-1]
	}

	// 处理逻辑运算符
	if result, ok := p.evaluateLogicalOperators(dsl, ctx); ok {
		return result
	}

	// 处理单个函数调用
	return p.evaluateSingleFunction(dsl, ctx)
}

// evaluateLogicalOperators 处理逻辑运算符 (&&, ||)
func (p *DSLParser) evaluateLogicalOperators(dsl string, ctx *DSLContext) (bool, bool) {
	// 处理 || (OR) 运算符
	if strings.Contains(dsl, "||") {
		parts := strings.Split(dsl, "||")
		for _, part := range parts {
			if p.EvaluateDSL(strings.TrimSpace(part), ctx) {
				return true, true
			}
		}
		return false, true
	}

	// 处理 && (AND) 运算符
	if strings.Contains(dsl, "&&") {
		parts := strings.Split(dsl, "&&")
		for _, part := range parts {
			if !p.EvaluateDSL(strings.TrimSpace(part), ctx) {
				return false, true
			}
		}
		return true, true
	}

	return false, false
}

// evaluateSingleFunction 处理单个函数调用
func (p *DSLParser) evaluateSingleFunction(dsl string, ctx *DSLContext) bool {
	// contains() 函数
	if result, ok := p.evaluateContains(dsl, ctx); ok {
		return result
	}

	// regex() 函数
	if result, ok := p.evaluateRegex(dsl, ctx); ok {
		return result
	}

	// status_code 比较
	if result, ok := p.evaluateStatusCode(dsl, ctx); ok {
		return result
	}

	// icon() 函数
	if result, ok := p.evaluateIcon(dsl, ctx); ok {
		return result
	}

	// title() 函数
	if result, ok := p.evaluateTitle(dsl, ctx); ok {
		return result
	}

	// server() 函数
	if result, ok := p.evaluateServer(dsl, ctx); ok {
		return result
	}

	// header() 函数
	if result, ok := p.evaluateHeader(dsl, ctx); ok {
		return result
	}

	// contains_all() 函数
	if result, ok := p.evaluateContainsAll(dsl, ctx); ok {
		return result
	}

	return false
}

// evaluateContains 处理 contains() 函数
func (p *DSLParser) evaluateContains(dsl string, ctx *DSLContext) (bool, bool) {
	// contains(body, 'text') 或 contains(body, 'text1', 'text2', 'text3') - 支持多个搜索文本的OR逻辑
	if strings.HasPrefix(dsl, "contains(") && strings.HasSuffix(dsl, ")") {
		content := dsl[9 : len(dsl)-1] // 移除 "contains(" 和 ")"
		parts := p.parseParameters(content)
		if len(parts) >= 2 {
			source := strings.TrimSpace(parts[0])

			var target string
			switch source {
			case "body":
				target = ctx.Body
			case "header":
				target = p.headersToString(ctx.Headers)
			case "title":
				target = ctx.Response.Title
			case "server":
				target = ctx.Response.Server
			case "url": // [重要] 新增：支持URL参数
				target = ctx.URL
			default:
				return false, true
			}

			// 转换为小写进行大小写不敏感匹配
			targetLower := strings.ToLower(target)

			// 遍历所有搜索文本，任意一个匹配即返回true（OR逻辑）
			for i := 1; i < len(parts); i++ {
				searchText := p.cleanQuotes(strings.TrimSpace(parts[i]))
				if strings.Contains(targetLower, strings.ToLower(searchText)) {
					return true, true
				}
			}

			// 所有搜索文本都不匹配
			return false, true
		}
	}
	return false, false
}

// evaluateRegex 处理 regex() 函数
func (p *DSLParser) evaluateRegex(dsl string, ctx *DSLContext) (bool, bool) {
	// regex(body, 'pattern') 或 regex('pattern')
	if strings.HasPrefix(dsl, "regex(") && strings.HasSuffix(dsl, ")") {
		content := dsl[6 : len(dsl)-1] // 移除 "regex(" 和 ")"
		parts := p.parseParameters(content)

		var target, pattern string
		if len(parts) >= 2 {
			source := strings.TrimSpace(parts[0])
			pattern = p.cleanQuotes(strings.TrimSpace(parts[1]))

			switch source {
			case "body":
				target = ctx.Body
			case "header":
				target = p.headersToString(ctx.Headers)
			case "title":
				target = ctx.Response.Title
			default:
				return false, true
			}
		} else if len(parts) == 1 {
			// 默认在body中搜索
			target = ctx.Body
			pattern = p.cleanQuotes(strings.TrimSpace(parts[0]))
		} else {
			return false, true
		}

		if compiled, err := regexp.Compile(pattern); err == nil {
			return compiled.MatchString(target), true
		}
	}
	return false, false
}

// evaluateStatusCode 处理状态码比较
func (p *DSLParser) evaluateStatusCode(dsl string, ctx *DSLContext) (bool, bool) {
	// status_code == 200, status_code != 404, etc.
	if strings.Contains(dsl, "status_code") {
		dsl = strings.ReplaceAll(dsl, " ", "")

		operators := []string{"==", "!=", ">=", "<=", ">", "<"}
		for _, op := range operators {
			if strings.Contains(dsl, "status_code"+op) {
				parts := strings.Split(dsl, "status_code"+op)
				if len(parts) == 2 {
					expectedStr := strings.TrimSpace(parts[1])
					if expected, err := strconv.Atoi(expectedStr); err == nil {
						actual := ctx.Response.StatusCode
						return p.compareNumbers(actual, expected, op), true
					}
				}
			}
		}
	}
	return false, false
}

// evaluateIcon 处理 icon() 函数（主动探测实现）
func (p *DSLParser) evaluateIcon(dsl string, ctx *DSLContext) (bool, bool) {
	// icon('/favicon.ico', 'hash')
	if strings.HasPrefix(dsl, "icon(") && strings.HasSuffix(dsl, ")") {
		content := dsl[5 : len(dsl)-1] // 移除 "icon(" 和 ")"
		parts := p.parseParameters(content)

		if len(parts) >= 2 {
			iconPath := p.cleanQuotes(strings.TrimSpace(parts[0]))
			expectedHash := p.cleanQuotes(strings.TrimSpace(parts[1]))

			// 检查是否有HTTP客户端、基础URL和Engine实例（主动探测必需）
			if ctx.HTTPClient == nil || ctx.BaseURL == "" || ctx.Engine == nil {
				logger.Debugf("[dsl.parser] icon()函数缺少必要组件，跳过主动探测")
				return false, false
			}

			// 构造完整的图标URL
			iconURL := ctx.BaseURL + iconPath

			// 使用Engine的缓存机制获取图标哈希值
			actualHash, err := ctx.Engine.getIconHash(iconURL, ctx.HTTPClient)
			if err != nil {
				logger.Debugf("[dsl.parser] 获取图标失败: %s, 错误: %v", iconURL, err)
				return false, false
			}

			// 比较哈希值
			match := actualHash == expectedHash
			logger.Debugf("[dsl.parser] icon()匹配: %s -> %v", iconURL, match)
			return match, true
		}
	}
	return false, false
}

// evaluateTitle 处理 title() 函数
func (p *DSLParser) evaluateTitle(dsl string, ctx *DSLContext) (bool, bool) {
	// title('text')
	if strings.HasPrefix(dsl, "title(") && strings.HasSuffix(dsl, ")") {
		content := dsl[6 : len(dsl)-1] // 移除 "title(" 和 ")"
		searchText := p.cleanQuotes(strings.TrimSpace(content))
		return strings.Contains(strings.ToLower(ctx.Response.Title), strings.ToLower(searchText)), true
	}
	return false, false
}

// evaluateServer 处理 server() 函数
func (p *DSLParser) evaluateServer(dsl string, ctx *DSLContext) (bool, bool) {
	// server('Apache')
	if strings.HasPrefix(dsl, "server(") && strings.HasSuffix(dsl, ")") {
		content := dsl[7 : len(dsl)-1] // 移除 "server(" 和 ")"
		searchText := p.cleanQuotes(strings.TrimSpace(content))
		return strings.Contains(strings.ToLower(ctx.Response.Server), strings.ToLower(searchText)), true
	}
	return false, false
}

// evaluateHeader 处理 header() 函数
func (p *DSLParser) evaluateHeader(dsl string, ctx *DSLContext) (bool, bool) {
	// header('header-name', 'value') 或 header('header-name')
	if strings.HasPrefix(dsl, "header(") && strings.HasSuffix(dsl, ")") {
		content := dsl[7 : len(dsl)-1] // 移除 "header(" 和 ")"
		parts := p.parseParameters(content)

		if len(parts) >= 1 {
			headerName := p.cleanQuotes(strings.TrimSpace(parts[0]))
			headerValue := ""
			if len(parts) >= 2 {
				headerValue = p.cleanQuotes(strings.TrimSpace(parts[1]))
			}

			if values := ctx.Headers.Get(headerName); values != "" {
				if headerValue == "" {
					return true, true // 只检查header是否存在
				}
				return strings.Contains(strings.ToLower(values), strings.ToLower(headerValue)), true
			}
		}
	}
	return false, false
}

// evaluateContainsAll 处理 contains_all() 函数
func (p *DSLParser) evaluateContainsAll(dsl string, ctx *DSLContext) (bool, bool) {
	// contains_all('text1', 'text2', 'text3') - 检查body中是否包含所有指定文本
	if strings.HasPrefix(dsl, "contains_all(") && strings.HasSuffix(dsl, ")") {
		content := dsl[13 : len(dsl)-1] // 移除 "contains_all(" 和 ")"
		parts := p.parseParameters(content)

		if len(parts) < 1 {
			return false, true
		}

		// 默认在body中搜索
		target := strings.ToLower(ctx.Body)

		// 检查所有文本是否都在target中
		for _, part := range parts {
			searchText := p.cleanQuotes(strings.TrimSpace(part))
			if !strings.Contains(target, strings.ToLower(searchText)) {
				return false, true // 有一个不包含就返回false
			}
		}

		return true, true // 所有文本都包含
	}
	return false, false
}

// ===========================================
// 辅助方法
// ===========================================

// parseParameters 解析函数参数
func (p *DSLParser) parseParameters(content string) []string {
	var params []string
	var current strings.Builder
	var inQuotes bool
	var quoteChar byte

	for i := 0; i < len(content); i++ {
		char := content[i]

		if !inQuotes && (char == '"' || char == '\'') {
			inQuotes = true
			quoteChar = char
			current.WriteByte(char)
		} else if inQuotes && char == quoteChar {
			inQuotes = false
			current.WriteByte(char)
		} else if !inQuotes && char == ',' {
			params = append(params, current.String())
			current.Reset()
		} else {
			current.WriteByte(char)
		}
	}

	if current.Len() > 0 {
		params = append(params, current.String())
	}

	return params
}

// cleanQuotes 清理引号
func (p *DSLParser) cleanQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"")) ||
			(strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'")) {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// headersToString 将headers转换为字符串
func (p *DSLParser) headersToString(headers http.Header) string {
	var sb strings.Builder
	for name, values := range headers {
		for _, value := range values {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// compareNumbers 比较数字
func (p *DSLParser) compareNumbers(actual, expected int, operator string) bool {
	switch operator {
	case "==":
		return actual == expected
	case "!=":
		return actual != expected
	case ">":
		return actual > expected
	case "<":
		return actual < expected
	case ">=":
		return actual >= expected
	case "<=":
		return actual <= expected
	default:
		return false
	}
}
