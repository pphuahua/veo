package dirscan

import (
	"bufio"
	"fmt"
	"os"
	"veo/internal/core/console"
	"veo/internal/utils/collector"
	"veo/internal/utils/generator"
	"veo/proxy"

	"veo/internal/core/logger"
)

// ===========================================
// Addon实现
// ===========================================

// DirscanAddon 目录扫描插件
type DirscanAddon struct {
	proxy.BaseAddon
	engine         *Engine
	collector      *collector.Collector
	consoleManager *console.ConsoleManager
	enabled        bool
	status         ScanStatus
}

// NewDirscanAddon 创建目录扫描插件
func NewDirscanAddon(config *EngineConfig) (*DirscanAddon, error) {
	// 创建引擎
	engine := NewEngine(config)

	// 创建collector
	collectorInstance := collector.NewCollector()

	addon := &DirscanAddon{
		engine:         engine,
		collector:      collectorInstance,
		consoleManager: nil, // 需要后续设置
		enabled:        true,
		status:         StatusIdle,
	}

	logger.Debug("目录扫描插件初始化完成")
	return addon, nil
}

// CreateDefaultAddon 创建默认配置的目录扫描插件
func CreateDefaultAddon() (*DirscanAddon, error) {
	config := getDefaultConfig()
	return NewDirscanAddon(config)
}

// ===========================================
// 核心接口方法
// ===========================================

// Enable 启用插件
func (da *DirscanAddon) Enable() {
	da.enabled = true
	if da.collector != nil {
		da.collector.EnableCollection()
	}
	logger.Debugf("目录扫描插件已启用")

	// [重要] 预加载字典文件，提升用户体验
	da.preloadDictionaries()
}

// Disable 禁用插件
func (da *DirscanAddon) Disable() {
	da.enabled = false
	if da.collector != nil {
		da.collector.DisableCollection()
	}
	logger.Debugf("目录扫描插件已禁用")
}

// GetCollectedURLs 获取收集的URL
func (da *DirscanAddon) GetCollectedURLs() []string {
	if da.collector == nil {
		return []string{}
	}

	urlMap := da.collector.GetURLMap()
	urls := make([]string, 0, len(urlMap))
	for url := range urlMap {
		urls = append(urls, url)
	}

	return urls
}

// GetScanResults 获取扫描结果
func (da *DirscanAddon) GetScanResults() *ScanResult {
	return da.engine.GetLastScanResult()
}

// GetStats 获取统计信息
func (da *DirscanAddon) GetStats() *Statistics {
	return da.engine.GetStats()
}

// ClearResults 清空结果
func (da *DirscanAddon) ClearResults() {
	da.engine.ClearResults()
	if da.collector != nil {
		da.collector.ClearURLMap()
	}
	logger.Info("扫描结果已清空")
}

// TriggerScan 触发扫描
func (da *DirscanAddon) TriggerScan() (*ScanResult, error) {
	if !da.enabled {
		return nil, fmt.Errorf("插件未启用")
	}

	if da.collector == nil {
		return nil, fmt.Errorf("collector未初始化")
	}

	// 检查是否有收集到的URL
	if da.collector.GetURLCount() == 0 {
		return nil, fmt.Errorf("没有收集到URL，无法开始扫描")
	}

	da.status = StatusScanning
	defer func() { da.status = StatusIdle }()

	// 暂停采集
	da.collector.DisableCollection()
	defer da.collector.EnableCollection()

	// 执行扫描
	result, err := da.engine.PerformScan(da.collector)
	if err != nil {
		da.status = StatusError
		return nil, err
	}

	return result, nil
}

// GetStatus 获取扫描状态
func (da *DirscanAddon) GetStatus() ScanStatus {
	return da.status
}

// ===========================================
// 配置和依赖注入方法
// ===========================================

// SetConsoleManager 设置控制台管理器
func (da *DirscanAddon) SetConsoleManager(consoleManager *console.ConsoleManager) {
	da.consoleManager = consoleManager
	logger.Debug("控制台管理器已设置")
}

// GetConsoleManager 获取控制台管理器
func (da *DirscanAddon) GetConsoleManager() *console.ConsoleManager {
	return da.consoleManager
}

// GetCollector 获取collector（用于依赖注入）
func (da *DirscanAddon) GetCollector() *collector.Collector {
	return da.collector
}

// SetCollector 注入外部的URL采集器实例，确保与代理侧使用同一实例
//
// 参数:
//   - c: *collector.Collector 外部创建并用于代理拦截的URL采集器
//
// 返回:
//   - 无
//
// 说明:
//   - 在被动代理模式下，代理服务器会将经过的URL写入其注册的Collector实例。
//     若目录扫描插件内部持有不同的Collector实例，将导致“按回车触发扫描”时取不到已采集的URL。
//     通过本方法将外部Collector注入到插件中，可确保两端使用同一个实例，避免“没有收集到URL”的问题。
func (da *DirscanAddon) SetCollector(c *collector.Collector) {
	if c == nil {
		return
	}
	da.collector = c
	logger.Debug("目录扫描插件Collector已注入为外部实例")
}

// ===========================================
// 字典预加载方法
// ===========================================

// preloadDictionaries 预加载字典文件
func (da *DirscanAddon) preloadDictionaries() {
	// 异步预加载字典，避免阻塞插件启用
	go func() {
		// 创建内容管理器来预加载字典
		contentManager := generator.NewContentManager()
		urlGenerator := contentManager.GetURLGenerator()

		// 触发字典加载（通过调用一个空的URL生成来触发字典加载）
		urlGenerator.GenerateURLs([]string{})

		logger.Debug("字典预加载完成")
	}()
}

// ===========================================
// 用户交互方法
// ===========================================

// StartInputListener 启动输入监听器
func (da *DirscanAddon) StartInputListener() {
	if !da.enabled {
		logger.Warn("插件未启用，无法启动输入监听器")
		return
	}

	// 设置控制台模式
	if da.consoleManager != nil {
		da.consoleManager.SetCurrentMode(console.ModeDirectoryScan)
	}

	go da.runInputListener()
	// [重要] 启动URL状态监控器
	logger.Debugf("输入监听器已启动")
}

// runInputListener 运行输入监听器
func (da *DirscanAddon) runInputListener() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		if !da.enabled {
			break
		}

		logger.Debug("按回车开始目录扫描...")
		if !scanner.Scan() {
			break
		}

		// 触发扫描
		da.handleScanTrigger()
	}
}

// handleScanTrigger 处理扫描触发
func (da *DirscanAddon) handleScanTrigger() {
	result, err := da.TriggerScan()
	if err != nil {
		logger.Errorf("扫描失败: %v", err)
		return
	}

	if result != nil {
		logger.Infof("Scan Sucess，Times: %v，Result: %d",
			result.Duration, len(result.FilterResult.ValidPages))
		if result.ReportPath != "" {
			logger.Infof("Scan Report: %s", result.ReportPath)
		}
	}

	// 扫描完成后的用户交互
	da.showScanCompleteMessage(result)
}

// showScanCompleteMessage 显示扫描完成消息
func (da *DirscanAddon) showScanCompleteMessage(result *ScanResult) {
	// 暂停collector，等待用户输入
	if da.collector != nil {
		da.collector.PauseCollection()
	}

	// 等待用户按回车键
	da.waitForUserInput()

	// 用户确认后，恢复完整的收集状态
	if da.collector != nil {
		da.collector.ClearURLMap()      // 清空collector状态
		da.collector.ResumeCollection() // 恢复暂停状态
		da.collector.EnableCollection() // 重新启用收集功能
	}

	// 清空引擎结果
	da.engine.ClearResults()
}

// waitForUserInput 等待用户输入
func (da *DirscanAddon) waitForUserInput() {
	fmt.Println("<Press \"Enter\" to Start URL Collector>")

	var input string
	fmt.Scanln(&input) // 等待用户按回车
}

// ===========================================
// Proxy.Addon接口实现
// ===========================================

// GetName 获取插件名称
func (da *DirscanAddon) GetName() string {
	return "DirscanAddon"
}

// String 字符串表示
func (da *DirscanAddon) String() string {
	return "DirscanAddon - 目录扫描插件"
}
