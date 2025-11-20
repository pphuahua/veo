package dirscan

import (
	"fmt"

	"veo/internal/core/logger"
	"veo/internal/utils/collector"
)

// ===========================================
// Addon实现
// ===========================================

// DirscanAddon 目录扫描插件
type DirscanAddon struct {
	engine    *Engine
	collector *collector.Collector
	enabled   bool
	status    ScanStatus
}

// NewDirscanAddon 创建目录扫描插件
func NewDirscanAddon(config *EngineConfig) (*DirscanAddon, error) {
	// 创建引擎
	engine := NewEngine(config)
	collectorInstance := collector.NewCollector()

	addon := &DirscanAddon{
		engine:    engine,
		collector: collectorInstance,
		enabled:   true,
		status:    StatusIdle,
	}

	logger.Debug("目录扫描插件初始化完成")
	return addon, nil
}

// CreateDefaultAddon 创建默认配置的目录扫描插件
func CreateDefaultAddon() (*DirscanAddon, error) {
	config := getDefaultConfig()
	config.EnableReporting = false
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

// 控制台设置接口已移除，保持简洁依赖

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

// 字典预加载逻辑已经迁移到生成器内部（无须处理）

// ===========================================
// 用户交互方法
// ===========================================

// StartInputListener 启动输入监听器
// 输入监听等交互逻辑已废弃（统一由 CLI 控制）

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
