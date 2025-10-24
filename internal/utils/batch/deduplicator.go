package batch

import (
	"veo/internal/core/logger"
	"net/url"
	"sort"
	"strings"
)

// Deduplicator 去重器
type Deduplicator struct {
	seen map[string]bool
}

// NewDeduplicator 创建去重器
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]bool),
	}
}

// Deduplicate 对目标列表去重
func (d *Deduplicator) Deduplicate(targets []string) []string {
	logger.Debugf("[batch.deduplicator] 开始去重，原始目标数量: %d", len(targets))

	var result []string

	for _, target := range targets {
		normalized := d.normalizeForDedup(target)
		if !d.seen[normalized] {
			d.seen[normalized] = true
			result = append(result, target)
		} else {
			logger.Debugf("[batch.deduplicator] 发现重复目标: %s (标准化: %s)", target, normalized)
		}
	}

	logger.Debugf("[batch.deduplicator] 去重完成，去重后目标数量: %d", len(result))
	return result
}

// normalizeForDedup 标准化URL用于去重
func (d *Deduplicator) normalizeForDedup(target string) string {
	// 确保URL有协议前缀
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	// 解析URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		// 解析失败，直接使用原始字符串的小写形式
		return strings.ToLower(target)
	}

	// 标准化主机名（转为小写）
	host := strings.ToLower(parsedURL.Host)

	// 标准化路径（移除尾部斜杠，除非是根路径）
	path := parsedURL.Path
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	if path == "" {
		path = "/"
	}

	// 重构标准化的URL
	normalized := parsedURL.Scheme + "://" + host + path

	// 添加查询参数（如果有）
	if parsedURL.RawQuery != "" {
		normalized += "?" + parsedURL.RawQuery
	}

	return normalized
}

// DeduplicateWithStats 去重并返回统计信息
func (d *Deduplicator) DeduplicateWithStats(targets []string) ([]string, *DeduplicationStats) {
	originalCount := len(targets)
	result := d.Deduplicate(targets)
	duplicateCount := originalCount - len(result)

	stats := &DeduplicationStats{
		OriginalCount:  originalCount,
		UniqueCount:    len(result),
		DuplicateCount: duplicateCount,
		DuplicateRate:  float64(duplicateCount) / float64(originalCount) * 100,
	}

	return result, stats
}

// DeduplicationStats 去重统计信息
type DeduplicationStats struct {
	OriginalCount  int     // 原始目标数量
	UniqueCount    int     // 去重后数量
	DuplicateCount int     // 重复目标数量
	DuplicateRate  float64 // 重复率（百分比）
}

// BatchDeduplicator 批量去重器（支持多个列表合并去重）
type BatchDeduplicator struct {
	deduplicator *Deduplicator
}

// NewBatchDeduplicator 创建批量去重器
func NewBatchDeduplicator() *BatchDeduplicator {
	return &BatchDeduplicator{
		deduplicator: NewDeduplicator(),
	}
}

// MergeAndDeduplicate 合并多个目标列表并去重
func (bd *BatchDeduplicator) MergeAndDeduplicate(targetLists ...[]string) []string {
	logger.Debugf("[batch.deduplicator] 开始合并和去重多个目标列表")

	// 合并所有列表
	var allTargets []string
	for i, targets := range targetLists {
		logger.Debugf("[batch.deduplicator] 列表 %d: %d 个目标", i+1, len(targets))
		allTargets = append(allTargets, targets...)
	}

	// 去重
	result := bd.deduplicator.Deduplicate(allTargets)

	// 排序以确保结果的一致性
	sort.Strings(result)

	logger.Debugf("[batch.deduplicator] 合并去重完成: %d -> %d", len(allTargets), len(result))
	return result
}

// Reset 重置去重器状态
func (d *Deduplicator) Reset() {
	d.seen = make(map[string]bool)
	logger.Debugf("[batch.deduplicator] 去重器状态已重置")
}

// GetSeenCount 获取已见过的目标数量
func (d *Deduplicator) GetSeenCount() int {
	return len(d.seen)
}

// HasSeen 检查是否已经见过某个目标
func (d *Deduplicator) HasSeen(target string) bool {
	normalized := d.normalizeForDedup(target)
	return d.seen[normalized]
}
