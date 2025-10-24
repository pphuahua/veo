package stats

import (
	"veo/internal/core/logger"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ScanStats 扫描统计信息
type ScanStats struct {
	StartTime      time.Time // 扫描开始时间
	TotalHosts     int64     // 总主机数
	CompletedHosts int64     // 已完成主机数
	TotalRequests  int64     // 总请求数
	CompletedReqs  int64     // 已完成请求数
	TimeoutCount   int64     // 超时次数
	LastRPS        int64     // 最近的RPS
	mu             sync.RWMutex
}

// StatsDisplay 统计显示器
type StatsDisplay struct {
	stats    *ScanStats
	enabled  bool
	stopChan chan struct{}
	ticker   *time.Ticker
	mu       sync.RWMutex
}

// NewStatsDisplay 创建新的统计显示器
func NewStatsDisplay() *StatsDisplay {
	return &StatsDisplay{
		stats: &ScanStats{
			StartTime: time.Now(),
		},
		enabled:  false,
		stopChan: make(chan struct{}),
	}
}

// Enable 启用统计显示
func (sd *StatsDisplay) Enable() {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	if sd.enabled {
		return
	}

	sd.enabled = true
	sd.stats.StartTime = time.Now()
	sd.ticker = time.NewTicker(5 * time.Second) // 每5秒更新一次

	go sd.displayLoop()
}

// Disable 禁用统计显示
func (sd *StatsDisplay) Disable() {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	if !sd.enabled {
		return
	}

	sd.enabled = false
	if sd.ticker != nil {
		sd.ticker.Stop()
	}

	select {
	case sd.stopChan <- struct{}{}:
	default:
	}
}

// SetTotalHosts 设置总主机数
func (sd *StatsDisplay) SetTotalHosts(count int64) {
	atomic.StoreInt64(&sd.stats.TotalHosts, count)
}

// SetTotalRequests 设置总请求数
func (sd *StatsDisplay) SetTotalRequests(count int64) {
	atomic.StoreInt64(&sd.stats.TotalRequests, count)
}

// AddTotalRequests 累加总请求数（用于批量扫描）
func (sd *StatsDisplay) AddTotalRequests(count int64) {
	atomic.AddInt64(&sd.stats.TotalRequests, count)
}

// IncrementCompletedHosts 增加已完成主机数
func (sd *StatsDisplay) IncrementCompletedHosts() {
	atomic.AddInt64(&sd.stats.CompletedHosts, 1)
}

// IncrementCompletedRequests 增加已完成请求数
func (sd *StatsDisplay) IncrementCompletedRequests() {
	atomic.AddInt64(&sd.stats.CompletedReqs, 1)
}

// IncrementTimeouts 增加超时次数
func (sd *StatsDisplay) IncrementTimeouts() {
	atomic.AddInt64(&sd.stats.TimeoutCount, 1)
}

// UpdateRPS 更新RPS
func (sd *StatsDisplay) UpdateRPS(rps int64) {
	atomic.StoreInt64(&sd.stats.LastRPS, rps)
}

// displayLoop 显示循环
func (sd *StatsDisplay) displayLoop() {
	var lastCompletedReqs int64
	var lastUpdateTime = time.Now()

	for {
		select {
		case <-sd.stopChan:
			return
		case <-sd.ticker.C:
			if !sd.enabled {
				return
			}

			// 计算RPS
			currentTime := time.Now()
			currentCompletedReqs := atomic.LoadInt64(&sd.stats.CompletedReqs)
			timeDiff := currentTime.Sub(lastUpdateTime).Seconds()

			if timeDiff > 0 {
				rps := float64(currentCompletedReqs-lastCompletedReqs) / timeDiff
				atomic.StoreInt64(&sd.stats.LastRPS, int64(rps))
			}

			lastCompletedReqs = currentCompletedReqs
			lastUpdateTime = currentTime

			// 显示统计信息
			sd.displayStats()
		}
	}
}

// displayStats 显示统计信息
func (sd *StatsDisplay) displayStats() {
	elapsed := time.Since(sd.stats.StartTime)
	hours := int(elapsed.Hours())
	minutes := int(elapsed.Minutes()) % 60
	seconds := int(elapsed.Seconds()) % 60

	totalHosts := atomic.LoadInt64(&sd.stats.TotalHosts)
	completedHosts := atomic.LoadInt64(&sd.stats.CompletedHosts)
	totalRequests := atomic.LoadInt64(&sd.stats.TotalRequests)
	completedReqs := atomic.LoadInt64(&sd.stats.CompletedReqs)
	timeoutCount := atomic.LoadInt64(&sd.stats.TimeoutCount)
	rps := atomic.LoadInt64(&sd.stats.LastRPS)

	// 计算完成百分比
	var percentage float64
	if totalRequests > 0 {
		percentage = float64(completedReqs) / float64(totalRequests) * 100
	}

	// 格式化显示
	timeStr := fmt.Sprintf("[%d:%02d:%02d]", hours, minutes, seconds)
	statsStr := fmt.Sprintf("%s Hosts: %d | RPS: %d | Done: %d | Timeout: %d | Requests: %d/%d (%.1f%%) \r",
		timeStr, totalHosts, rps, completedHosts, timeoutCount, completedReqs, totalRequests, percentage)

	// 清除当前行并显示新的统计信息
	fmt.Printf("\r\033[K%s", statsStr)
}

// GetStats 获取当前统计信息
func (sd *StatsDisplay) GetStats() *ScanStats {
	return sd.stats
}

// IsEnabled 检查是否启用
func (sd *StatsDisplay) IsEnabled() bool {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.enabled
}

// Reset 重置统计信息
func (sd *StatsDisplay) Reset() {
	sd.stats = &ScanStats{
		StartTime: time.Now(),
	}
}

// ShowFinalStats 显示最终统计信息
func (sd *StatsDisplay) ShowFinalStats() {
	if !sd.enabled {
		return
	}

	elapsed := time.Since(sd.stats.StartTime)
	totalHosts := atomic.LoadInt64(&sd.stats.TotalHosts)
	completedHosts := atomic.LoadInt64(&sd.stats.CompletedHosts)
	totalRequests := atomic.LoadInt64(&sd.stats.TotalRequests)
	completedReqs := atomic.LoadInt64(&sd.stats.CompletedReqs)
	timeoutCount := atomic.LoadInt64(&sd.stats.TimeoutCount)

	// [重要] 修复已完成主机数统计错误：确保不超过总主机数
	if completedHosts > totalHosts {
		completedHosts = totalHosts
		logger.Warnf("修正已完成主机数统计错误: %d -> %d", atomic.LoadInt64(&sd.stats.CompletedHosts), completedHosts)
	}

	// 格式化耗时显示（秒为单位）
	elapsedSeconds := int(elapsed.Seconds())
	timeStr := fmt.Sprintf("%dS", elapsedSeconds)

	// 清除当前行并显示最终统计（单行紧凑格式）
	fmt.Printf("\r\033[K\n[INF] Times: %s | Host: %d/%d | Request: %d/%d | Timeout: %d\n",
		timeStr, completedHosts, totalHosts, completedReqs, totalRequests, timeoutCount)
}
