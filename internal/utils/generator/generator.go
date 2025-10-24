package generator

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"veo/internal/core/config"
	"veo/internal/core/interfaces"
	"veo/internal/core/logger"
	"veo/internal/utils/dictionary"
	"veo/internal/utils/shared"
)

// 模板变量定义
var templateVariables = map[string]string{
	"{{domain}}": "", // 将在运行时被实际域名替换
	"{{DOMAIN}}": "", // 支持大写形式
	"{{host}}":   "", // host和domain是同义词
	"{{HOST}}":   "", // 支持大写形式
	"{{path}}":   "", // 将在运行时被实际路径替换
	"{{PATH}}":   "", // 支持大写形式
}

// URLGenerator URL生成器，专门负责生成扫描URL
type URLGenerator struct {
	dictManager   *dictionary.DictionaryManager // 字典管理器
	urlValidator  *shared.URLValidator          // URL验证器
	fileChecker   *shared.FileExtensionChecker  // 文件检查器
	generatedURLs []string                      // 生成的URL列表
	mu            sync.RWMutex                  // 读写锁
}

// URLComponents URL组件
type URLComponents struct {
	Scheme string
	Host   string
	Path   string
	Query  string
}

// NewURLGenerator 创建URL生成器（推荐使用factory.ComponentFactory创建）
func NewURLGenerator() *URLGenerator {
	return &URLGenerator{
		dictManager:   dictionary.NewDictionaryManager(),
		urlValidator:  shared.NewURLValidator(),
		fileChecker:   shared.NewFileExtensionChecker(),
		generatedURLs: make([]string, 0),
	}
}

// NewURLGeneratorWithDependencies 使用依赖注入创建URL生成器（工厂模式）
func NewURLGeneratorWithDependencies(
	dictManager *dictionary.DictionaryManager,
	urlValidator *shared.URLValidator,
	fileChecker *shared.FileExtensionChecker,
) *URLGenerator {
	return &URLGenerator{
		dictManager:   dictManager,
		urlValidator:  urlValidator,
		fileChecker:   fileChecker,
		generatedURLs: make([]string, 0),
	}
}

// GenerateURLsFromCollector 从收集器生成扫描URL
func (ug *URLGenerator) GenerateURLsFromCollector(collector interfaces.URLCollectorInterface) []string {
	// 获取收集的URL
	urlMap := collector.GetURLMap()
	if len(urlMap) == 0 {
		logger.Info("没有收集到URL，无法生成扫描内容")
		return []string{}
	}

	// 转换为URL列表
	baseURLs := ug.convertURLMapToList(urlMap)

	// 生成扫描URL
	scanURLs := ug.GenerateURLs(baseURLs)

	logger.Debug(fmt.Sprintf("URL生成完成: 基础URL %d 个, 生成扫描URL %d 个",
		len(baseURLs), len(scanURLs)))

	return scanURLs
}

// GenerateURLs 从基础URL列表生成扫描URL（[重要] 性能优化版本）
func (ug *URLGenerator) GenerateURLs(baseURLs []string) []string {
	ug.mu.Lock()
	defer ug.mu.Unlock()

	// [重要] 性能优化：预分配切片容量，避免频繁扩容
	// 估算容量：基础URL数量 × 平均字典大小（约1800条目）
	estimatedCapacity := len(baseURLs) * 1800
	ug.generatedURLs = make([]string, 0, estimatedCapacity)

	// [重要] 性能优化：移除每次的字典加载检查，依赖全局缓存
	// 字典将在首次访问时自动加载到全局缓存

	logger.Debug(fmt.Sprintf("开始生成扫描URL，基础URL数量: %d", len(baseURLs)))

	// 处理每个基础URL
	for i, baseURL := range baseURLs {
		logger.Debug(fmt.Sprintf("处理基础URL [%d/%d]: %s", i+1, len(baseURLs), baseURL))

		if !ug.urlValidator.IsValidURL(baseURL) {
			logger.Debugf("无效的基础URL: %s", baseURL)
			continue
		}

		ug.generateURLsForBase(baseURL)
	}

	// 去重
	ug.deduplicateURLs()

	logger.Debug(fmt.Sprintf("URL生成完成，总计: %d 个", len(ug.generatedURLs)))

	// 返回副本
	result := make([]string, len(ug.generatedURLs))
	copy(result, ug.generatedURLs)
	return result
}

// generateURLsForBase 为单个基础URL生成扫描URL
func (ug *URLGenerator) generateURLsForBase(baseURL string) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		logger.Debug("URL解析失败: ", baseURL)
		return
	}

	components := ug.extractURLComponents(parsedURL)

	// 生成根目录扫描URL
	ug.generateRootURLs(components)

	// 生成路径层级扫描URL
	ug.generatePathLevelURLs(components)
}

// extractURLComponents 提取URL组件
func (ug *URLGenerator) extractURLComponents(parsedURL *url.URL) URLComponents {
	return URLComponents{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   parsedURL.Path,
		Query:  parsedURL.RawQuery,
	}
}

// generateRootURLs 生成根目录扫描URL
func (ug *URLGenerator) generateRootURLs(components URLComponents) {
	// 使用通用字典
	commonDict := ug.dictManager.GetCommonDictionary()
	ug.generateURLsFromDictionary(components, "", commonDict, "通用字典")

	// 检查配置是否启用文件字典
	contentConfig := config.GetContentConfig()
	if contentConfig.FilesDict {
		// 使用文件字典（仅限根目录）
		filesDict := ug.dictManager.GetFilesDictionary()
		if len(filesDict) > 0 {
			ug.generateURLsFromDictionary(components, "", filesDict, "文件字典")
			logger.Debug("文件字典已启用，仅在根目录使用")
		}
	} else {
		logger.Debug("文件字典已禁用，跳过文件字典使用")
	}
}

// generatePathLevelURLs 生成路径层级扫描URL
func (ug *URLGenerator) generatePathLevelURLs(components URLComponents) {
	if components.Path == "" || components.Path == "/" {
		return
	}

	pathParts := ug.splitPath(components.Path)
	commonDict := ug.dictManager.GetCommonDictionary()

	// 为每个路径层级生成扫描URL（只使用通用字典）
	for i := 1; i <= len(pathParts); i++ {
		currentPath := "/" + strings.Join(pathParts[:i], "/")
		ug.generateURLsFromDictionary(components, currentPath, commonDict, "通用字典（路径层级）")
	}
}

// generateURLsFromDictionary 从字典生成URL（[重要] 性能优化版本）
func (ug *URLGenerator) generateURLsFromDictionary(components URLComponents, basePath string, dictionary []string, dictType string) {
	// 提取域名用于模板替换
	domain := ug.extractDomainFromHost(components.Host)

	// [重要] 性能优化：使用strings.Builder减少字符串分配
	var urlBuilder strings.Builder

	// [重要] 性能优化：预分配Builder容量
	urlBuilder.Grow(len(components.Scheme) + len(components.Host) + 100) // 预估URL长度

	for _, dictEntry := range dictionary {
		// 处理模板变量替换
		processedEntry := ug.processTemplateVariables(dictEntry, domain, basePath)

		// [重要] 修复：清理字典条目的前导斜杠，避免双斜杠问题
		processedEntry = strings.TrimPrefix(processedEntry, "/")

		// [重要] 性能优化：使用Builder构建URL，避免多次字符串拼接
		urlBuilder.Reset()
		urlBuilder.WriteString(components.Scheme)
		urlBuilder.WriteString("://")
		urlBuilder.WriteString(components.Host)

		// 构建路径部分
		if basePath != "" {
			urlBuilder.WriteString(basePath)
			if !strings.HasSuffix(basePath, "/") {
				urlBuilder.WriteString("/")
			}
		} else {
			urlBuilder.WriteString("/")
		}
		urlBuilder.WriteString(processedEntry)

		// 添加查询参数（如果需要）
		if !ug.fileChecker.IsStaticFile(processedEntry) && components.Query != "" {
			urlBuilder.WriteString("?")
			urlBuilder.WriteString(components.Query)
		}

		scanURL := urlBuilder.String()

		// [重要] 性能优化：简化URL验证，减少不必要的检查
		if len(scanURL) > 0 && len(scanURL) < 2048 { // 基本长度检查
			ug.generatedURLs = append(ug.generatedURLs, scanURL)
		}
	}

	logger.Debug(fmt.Sprintf("使用%s生成URL完成", dictType))
}

// splitPath 分割路径
func (ug *URLGenerator) splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return []string{}
	}
	return strings.Split(path, "/")
}

// deduplicateURLs 去重URL（[重要] 性能优化版本）
func (ug *URLGenerator) deduplicateURLs() {
	beforeCount := len(ug.generatedURLs)

	// [重要] 性能优化：预分配map容量，减少rehash
	seen := make(map[string]bool, beforeCount)
	uniqueURLs := make([]string, 0, beforeCount)

	for _, url := range ug.generatedURLs {
		if !seen[url] {
			seen[url] = true
			uniqueURLs = append(uniqueURLs, url)
		}
	}

	ug.generatedURLs = uniqueURLs
	afterCount := len(ug.generatedURLs)

	if beforeCount != afterCount {
		logger.Debug(fmt.Sprintf("去重完成: 去重前 %d 个, 去重后 %d 个, 去除重复 %d 个",
			beforeCount, afterCount, beforeCount-afterCount))
	}
}

// convertURLMapToList 将URL映射转换为列表
func (ug *URLGenerator) convertURLMapToList(urlMap map[string]int) []string {
	urls := make([]string, 0, len(urlMap))
	for url := range urlMap {
		urls = append(urls, url)
	}
	return urls
}

// GetGeneratedURLs 获取生成的URL列表
func (ug *URLGenerator) GetGeneratedURLs() []string {
	ug.mu.RLock()
	defer ug.mu.RUnlock()

	result := make([]string, len(ug.generatedURLs))
	copy(result, ug.generatedURLs)
	return result
}

// Reset 重置生成器
func (ug *URLGenerator) Reset() {
	ug.mu.Lock()
	defer ug.mu.Unlock()

	ug.generatedURLs = make([]string, 0)
	logger.Debug("URL生成器已重置")
}

// ===========================================
// 模板变量处理方法
// ===========================================

// processTemplateVariables 处理模板变量替换
func (ug *URLGenerator) processTemplateVariables(dictEntry string, domain string, currentPath string) string {
	// 处理变量替换
	processedEntry := dictEntry
	hasReplacement := false

	// 使用全局定义的模板变量进行替换
	for template := range templateVariables {
		if strings.Contains(processedEntry, template) {
			var replacement string
			switch template {
			case "{{domain}}", "{{DOMAIN}}", "{{host}}", "{{HOST}}":
				replacement = domain
			case "{{path}}", "{{PATH}}":
				// 移除路径前后的斜杠，确保路径格式一致
				cleanPath := strings.Trim(currentPath, "/")
				replacement = cleanPath
			default:
				replacement = domain // 默认使用域名（向后兼容）
			}

			processedEntry = strings.ReplaceAll(processedEntry, template, replacement)
			hasReplacement = true
		}
	}

	// 只在有替换时记录日志
	if hasReplacement {
		logger.Debug(fmt.Sprintf("模板变量替换: %s -> %s (域名: %s, 路径: %s)",
			dictEntry, processedEntry, domain, currentPath))
	}

	return processedEntry
}

// extractDomainFromHost 从Host中提取域名（去除端口）
func (ug *URLGenerator) extractDomainFromHost(host string) string {
	// 如果包含端口，移除端口部分
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		// 检查是否是IPv6地址
		if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
			// IPv6地址但没有用[]包围，保持原样
			return host
		} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			// IPv6地址用[]包围，保持原样
			return host
		} else {
			// 普通域名:端口格式，移除端口
			return host[:colonIndex]
		}
	}

	return host
}

// ============================================================================
// 内容管理器功能 (原content/manager.go内容)
// ============================================================================

// ContentManager 内容管理器，负责协调URL生成
type ContentManager struct {
	urlGenerator *URLGenerator                    // URL生成器
	collector    interfaces.URLCollectorInterface // URL收集器
	mu           sync.RWMutex                     // 读写锁
}

// NewContentManager 创建内容管理器
func NewContentManager() *ContentManager {
	return &ContentManager{
		urlGenerator: NewURLGenerator(),
	}
}

// SetCollector 设置URL收集器
func (cm *ContentManager) SetCollector(collector interfaces.URLCollectorInterface) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.collector = collector
	logger.Debug("URL收集器已设置")
}

// GenerateScanURLs 生成扫描URL
func (cm *ContentManager) GenerateScanURLs() []string {
	cm.mu.RLock()
	collector := cm.collector
	cm.mu.RUnlock()

	if collector == nil {
		logger.Warn("URL收集器未设置，无法生成扫描URL")
		return []string{}
	}

	return cm.urlGenerator.GenerateURLsFromCollector(collector)
}

// GetURLGenerator 获取URL生成器（用于测试或高级用法）
func (cm *ContentManager) GetURLGenerator() *URLGenerator {
	return cm.urlGenerator
}

// Reset 重置内容管理器
func (cm *ContentManager) Reset() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.urlGenerator.Reset()
	logger.Debug("内容管理器已重置")
}
