package dictionary

import (
	"veo/internal/core/config"
	"veo/internal/core/logger"
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// DictionaryManager 字典管理器，专门负责字典的加载和管理
type DictionaryManager struct {
	commonDict     []string     // 通用目录字典
	filesDict      []string     // 文件字典
	commonDictPath string       // 通用字典路径
	filesDictPath  string       // 文件字典路径
	loaded         bool         // 是否已加载
	mu             sync.RWMutex // 读写锁
}

// 全局字典缓存
var (
	globalDictCache *DictionaryCache // 全局字典缓存实例
	globalCacheOnce sync.Once        // 确保只初始化一次
	globalLoadMutex sync.Mutex       // 全局加载锁
)

// DictionaryCache 全局字典缓存
type DictionaryCache struct {
	commonDict []string     // 通用字典缓存
	filesDict  []string     // 文件字典缓存
	loaded     bool         // 是否已加载
	mu         sync.RWMutex // 读写锁
}

// getGlobalDictCache 获取全局字典缓存实例（单例模式）
func getGlobalDictCache() *DictionaryCache {
	globalCacheOnce.Do(func() {
		globalDictCache = &DictionaryCache{
			commonDict: make([]string, 0),
			filesDict:  make([]string, 0),
			loaded:     false,
		}
	})
	return globalDictCache
}

// NewDictionaryManager 创建字典管理器
func NewDictionaryManager() *DictionaryManager {
	contentConfig := config.GetContentConfig()

	return &DictionaryManager{
		commonDict:     make([]string, 0),
		filesDict:      make([]string, 0),
		commonDictPath: contentConfig.Common,
		filesDictPath:  contentConfig.Files,
		loaded:         false,
	}
}

// LoadDictionaries 加载所有字典（[重要] 内存优化：统一使用全局缓存）
func (dm *DictionaryManager) LoadDictionaries() error {
	// 直接使用全局缓存，避免重复加载
	cache := getGlobalDictCache()
	if !cache.isLoaded() {
		dm.ensureGlobalCacheLoaded()
	}

	// 标记本地实例已加载（保持兼容性）
	dm.mu.Lock()
	dm.loaded = true
	dm.mu.Unlock()

	return nil
}

// GetCommonDictionary 获取通用字典（[重要] 性能优化：使用全局缓存，避免数据复制）
func (dm *DictionaryManager) GetCommonDictionary() []string {
	cache := getGlobalDictCache()

	// 确保全局缓存已加载
	if !cache.isLoaded() {
		dm.ensureGlobalCacheLoaded()
	}

	// 直接返回缓存数据，避免复制
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return cache.commonDict
}

// GetFilesDictionary 获取文件字典（[重要] 性能优化：使用全局缓存，避免数据复制）
func (dm *DictionaryManager) GetFilesDictionary() []string {
	cache := getGlobalDictCache()

	// 确保全局缓存已加载
	if !cache.isLoaded() {
		dm.ensureGlobalCacheLoaded()
	}

	// 直接返回缓存数据，避免复制
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return cache.filesDict
}

// isLoaded 检查全局缓存是否已加载
func (cache *DictionaryCache) isLoaded() bool {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return cache.loaded
}

// ensureGlobalCacheLoaded 确保全局缓存已加载
func (dm *DictionaryManager) ensureGlobalCacheLoaded() {
	cache := getGlobalDictCache()

	// 双重检查锁定模式
	if cache.isLoaded() {
		return
	}

	globalLoadMutex.Lock()
	defer globalLoadMutex.Unlock()

	// 再次检查，避免重复加载
	if cache.isLoaded() {
		return
	}

	// 加载到全局缓存
	dm.loadToGlobalCache()
}

// loadToGlobalCache 加载字典到全局缓存（[重要] 用户体验优化：增强进度反馈）
func (dm *DictionaryManager) loadToGlobalCache() {
	cache := getGlobalDictCache()
	contentConfig := config.GetContentConfig()

	cache.mu.Lock()
	defer cache.mu.Unlock()

	var errors []string
	totalEntries := 0

	// [重要] 用户体验优化：预估字典条目数并输出开始日志
	estimatedEntries := dm.estimateDictionarySize()
	logger.Debugf("开始加载字典文件，预计条目数: %d", estimatedEntries)

	// 加载通用字典到全局缓存
	if dm.commonDictPath != "" {
		if err := dm.loadCommonDictionaryToCache(cache); err != nil {
			errors = append(errors, fmt.Sprintf("通用字典加载失败: %v", err))
		} else {
			totalEntries += len(cache.commonDict)
			// [重要] 用户体验优化：显示加载进度
			logger.Debugf("字典加载进度: %d/%d (%.1f%%)",
				totalEntries, estimatedEntries, float64(totalEntries)/float64(estimatedEntries)*100)
		}
	}

	// 加载文件字典到全局缓存
	if contentConfig.FilesDict && dm.filesDictPath != "" {
		if err := dm.loadFilesDictionaryToCache(cache); err != nil {
			errors = append(errors, fmt.Sprintf("文件字典加载失败: %v", err))
		} else {
			totalEntries += len(cache.filesDict)
			// [重要] 用户体验优化：显示最终加载进度
			logger.Debugf("字典加载进度: %d/%d (%.1f%%)",
				totalEntries, estimatedEntries, float64(totalEntries)/float64(estimatedEntries)*100)
		}
	}

	cache.loaded = true
	// [重要] 用户体验优化：详细的完成日志
	logger.Debugf("字典加载完成，成功加载 %d 个条目", totalEntries)

	if len(errors) > 0 {
		logger.Warnf("字典加载警告: %s", strings.Join(errors, "; "))
	}
}

// GetCombinedDictionary 获取合并字典
func (dm *DictionaryManager) GetCombinedDictionary() []string {
	dm.ensureLoaded()

	dm.mu.RLock()
	defer dm.mu.RUnlock()

	combined := make([]string, 0, len(dm.commonDict)+len(dm.filesDict))
	combined = append(combined, dm.commonDict...)
	combined = append(combined, dm.filesDict...)
	return combined
}

// IsLoaded 检查字典是否已加载
func (dm *DictionaryManager) IsLoaded() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.loaded
}

// ensureLoaded 确保字典已加载
func (dm *DictionaryManager) ensureLoaded() {
	if !dm.IsLoaded() {
		if err := dm.LoadDictionaries(); err != nil {
			logger.Warnf("[dictionary] 延迟加载字典失败: %v", err)
		}
	}
}

// [重要] 内存优化：移除重复的字典加载方法，统一使用全局缓存机制
// 原有的 loadCommonDictionary、loadFilesDictionary、readDictionaryFile 方法已移除
// 所有字典加载现在通过 loadToGlobalCache 和相关的缓存方法处理

// loadCommonDictionaryToCache 加载通用字典到全局缓存
func (dm *DictionaryManager) loadCommonDictionaryToCache(cache *DictionaryCache) error {
	logger.Debugf("开始加载字典文件: %s", dm.commonDictPath)

	file, err := os.Open(dm.commonDictPath)
	if err != nil {
		return fmt.Errorf("打开通用字典文件失败: %v", err)
	}
	defer file.Close()

	lineCount, commentCount := dm.readDictionaryFileToCache(file, &cache.commonDict)

	logger.Debug(fmt.Sprintf("通用字典加载完成: 总行数 %d, 注释行 %d, 有效条目 %d",
		lineCount, commentCount, len(cache.commonDict)))

	return nil
}

// loadFilesDictionaryToCache 加载文件字典到全局缓存
func (dm *DictionaryManager) loadFilesDictionaryToCache(cache *DictionaryCache) error {
	logger.Debugf("开始加载字典文件: %s", dm.filesDictPath)

	file, err := os.Open(dm.filesDictPath)
	if err != nil {
		return fmt.Errorf("打开文件字典失败: %v", err)
	}
	defer file.Close()

	lineCount, commentCount := dm.readDictionaryFileToCache(file, &cache.filesDict)

	logger.Debug(fmt.Sprintf("文件字典加载完成: 总行数 %d, 注释行 %d, 有效条目 %d",
		lineCount, commentCount, len(cache.filesDict)))

	return nil
}

// readDictionaryFileToCache 读取字典文件到缓存
func (dm *DictionaryManager) readDictionaryFileToCache(file *os.File, targetDict *[]string) (lineCount, commentCount int) {
	// [重要] 性能优化：预分配切片容量，减少扩容开销
	scanner := bufio.NewScanner(file)
	tempDict := make([]string, 0, 1000) // 预估容量

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#") {
				commentCount++
			}
			continue
		}

		tempDict = append(tempDict, line)
	}

	*targetDict = tempDict
	return lineCount, commentCount
}

// estimateDictionarySize 预估字典大小（[重要] 用户体验优化）
func (dm *DictionaryManager) estimateDictionarySize() int {
	contentConfig := config.GetContentConfig()
	estimatedSize := 0

	// 预估通用字典大小（基于经验值）
	if dm.commonDictPath != "" {
		estimatedSize += 500 // 通用字典预估500条
	}

	// 预估文件字典大小（基于经验值）
	if contentConfig.FilesDict && dm.filesDictPath != "" {
		estimatedSize += 900 // 文件字典预估900条
	}

	return estimatedSize
}

// Reset 重置字典管理器
func (dm *DictionaryManager) Reset() {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.commonDict = make([]string, 0)
	dm.filesDict = make([]string, 0)
	dm.loaded = false

	logger.Debug("[dictionary] 字典管理器已重置")
}
