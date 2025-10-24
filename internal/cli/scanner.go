package cli

import (
	"veo/internal/core/config"
	"veo/internal/core/interfaces"
	"veo/internal/modules/fingerprint"
	report "veo/internal/modules/reporter"
	"veo/internal/utils/batch"
	"veo/internal/utils/filter"
	"veo/internal/utils/formatter"
	"veo/internal/utils/generator"
	"veo/internal/utils/httpclient"
	requests "veo/internal/utils/processor"
	"veo/internal/utils/scheduler"
	"veo/internal/utils/stats"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"veo/internal/core/logger"

	"github.com/andybalholm/brotli"
)

// FingerprintProgressTracker 指纹识别进度跟踪器
type FingerprintProgressTracker struct {
	totalSteps  int    // 总步骤数（1个基础指纹匹配 + N个path探测）
	currentStep int    // 当前步骤
	baseURL     string // 基础URL
	mu          sync.Mutex
}

// NewFingerprintProgressTracker 创建指纹识别进度跟踪器
func NewFingerprintProgressTracker(baseURL string, pathRulesCount int) *FingerprintProgressTracker {
	return &FingerprintProgressTracker{
		totalSteps:  1 + pathRulesCount, // 1个基础指纹匹配 + N个path探测
		currentStep: 0,
		baseURL:     baseURL,
	}
}

// UpdateProgress 更新进度并显示
func (fpt *FingerprintProgressTracker) UpdateProgress(stepName string) {
	fpt.mu.Lock()
	defer fpt.mu.Unlock()

	// [重要] 边界条件检查：防止计数器超过总步骤数
	if fpt.currentStep >= fpt.totalSteps {
		// 已经完成，不再更新进度
		return
	}

	fpt.currentStep++

	// [重要] 确保百分比不超过100%
	percentage := float64(fpt.currentStep) / float64(fpt.totalSteps) * 100
	if percentage > 100.0 {
		percentage = 100.0
	}

	fmt.Printf("\rFingerPrint Working %d/%d (%.1f%%)\r",
		fpt.currentStep, fpt.totalSteps, percentage)
}

// ScanMode 扫描模式
type ScanMode int

const (
	ActiveMode  ScanMode = iota // 主动扫描模式
	PassiveMode                 // 被动代理模式
)

// ScanController 扫描控制器
type ScanController struct {
	mode              ScanMode
	args              *CLIArgs
	config            *config.Config
	requestProcessor  *requests.RequestProcessor
	urlGenerator      *generator.URLGenerator
	contentManager    *generator.ContentManager
	fingerprintEngine *fingerprint.Engine            // 指纹识别引擎
	encodingDetector  *fingerprint.EncodingDetector  // 编码检测器
	entityDecoder     *fingerprint.HTMLEntityDecoder // HTML实体解码器
	probedHosts       map[string]bool                // 已探测的主机缓存（用于path探测去重）
	probedMutex       sync.RWMutex                   // 探测缓存锁
	progressTracker   *FingerprintProgressTracker    // 指纹识别进度跟踪器
	statsDisplay      *stats.StatsDisplay            // 统计显示器
}

// NewScanController 创建扫描控制器
func NewScanController(args *CLIArgs, cfg *config.Config) *ScanController {
	mode := ActiveMode
	if args.Listen {
		mode = PassiveMode
	}

	// 从配置文件获取请求配置（CLI参数已通过applyArgsToConfig应用到配置）
	requestConfigFromFile := config.GetRequestConfig()
	logger.Debugf("配置文件中的线程数: %d", requestConfigFromFile.Threads)
	logger.Debugf("配置文件中的重试次数: %d", requestConfigFromFile.Retry)
	logger.Debugf("配置文件中的超时时间: %d", requestConfigFromFile.Timeout)

	// 创建请求处理器配置
	requestConfig := &requests.RequestConfig{
		Timeout:        time.Duration(requestConfigFromFile.Timeout) * time.Second, // [修复] 使用配置文件中的超时时间（包含CLI参数覆盖）
		MaxRetries:     requestConfigFromFile.Retry,                                // [修复] 使用配置文件中的重试次数（包含CLI参数覆盖）
		MaxConcurrent:  requestConfigFromFile.Threads,                              // [修复] 使用配置文件中的线程数（包含CLI参数覆盖）
		FollowRedirect: true,                                                       // [重要] 修复：启用重定向跟随，确保指纹识别准确性
	}

	// 如果配置文件中的线程数为0，使用默认值200
	if requestConfig.MaxConcurrent <= 0 {
		logger.Debugf("配置文件中线程数为0，使用默认值200")
		requestConfig.MaxConcurrent = 200
	}

	// 如果配置文件中的重试次数为0，使用默认值3
	if requestConfig.MaxRetries <= 0 {
		logger.Debugf("配置文件中重试次数为0，使用默认值3")
		requestConfig.MaxRetries = 3
	}

	// 如果配置文件中的超时时间为0，使用默认值10秒
	if requestConfig.Timeout <= 0 {
		logger.Debugf("配置文件中超时时间为0，使用默认值10秒")
		requestConfig.Timeout = 10 * time.Second
	}

	logger.Debugf("请求处理器并发数设置为: %d", requestConfig.MaxConcurrent)
	logger.Debugf("请求处理器重试次数设置为: %d", requestConfig.MaxRetries)
	logger.Debugf("请求处理器超时时间设置为: %v", requestConfig.Timeout)

	// [重要] 修复重复加载：主动模式复用被动模式的指纹引擎
	var fpEngine *fingerprint.Engine
	if mode == ActiveMode {
		// 获取全局指纹识别插件实例（由被动模式创建）
		globalAddon := fingerprint.GetGlobalAddon()
		if globalAddon != nil {
			// 复用被动模式的指纹引擎，避免重复加载
			fpEngine = globalAddon.GetEngine()
			logger.Debug("复用被动模式的指纹引擎，避免重复加载")
		}
	}

	// 创建请求处理器并自定义防缓存头部
	requestProcessor := requests.NewRequestProcessor(requestConfig)

	// [重要] 为指纹识别模式设置模块上下文，禁用processor进度条
	// 注意：这里只为纯指纹识别模式设置，混合模式需要在运行时动态设置
	if mode == ActiveMode && len(args.Modules) == 1 && args.Modules[0] == "finger" {
		requestProcessor.SetModuleContext("fingerprint")
	}

	// 创建统计显示器
	statsDisplay := stats.NewStatsDisplay()
	if args.Stats {
		statsDisplay.Enable()
	}

	// 设置请求处理器的统计更新器
	if args.Stats {
		requestProcessor.SetStatsUpdater(statsDisplay)
	}

	return &ScanController{
		mode:              mode,
		args:              args,
		config:            cfg,
		requestProcessor:  requestProcessor,
		urlGenerator:      generator.NewURLGenerator(),
		contentManager:    generator.NewContentManager(),
		fingerprintEngine: fpEngine,
		encodingDetector:  fingerprint.GetEncodingDetector(),  // 初始化编码检测器
		entityDecoder:     fingerprint.GetHTMLEntityDecoder(), // 初始化HTML实体解码器
		probedHosts:       make(map[string]bool),              // 初始化探测缓存
		statsDisplay:      statsDisplay,                       // 初始化统计显示器
	}
}

// Run 运行扫描
func (sc *ScanController) Run() error {
	switch sc.mode {
	case ActiveMode:
		return sc.runActiveMode()
	case PassiveMode:
		return sc.runPassiveMode()
	default:
		return fmt.Errorf("未知的扫描模式")
	}
}

// runActiveMode 运行主动扫描模式
func (sc *ScanController) runActiveMode() error {
	logger.Debug("启动主动扫描模式")

	// 解析和验证目标URL
	targets, err := sc.parseTargets(sc.args.Targets)
	if err != nil {
		return fmt.Errorf("目标解析失败: %v", err)
	}

	logger.Debugf("解析到 %d 个目标", len(targets))

	// 初始化统计信息（使用最终有效目标数量）
	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.SetTotalHosts(int64(len(targets)))
		logger.Debugf("统计显示器：设置总主机数 = %d", len(targets))
	}

	// 创建结果收集器
	var allResults []interfaces.HTTPResponse

	// [重要] 顺序执行各个模块，避免模块上下文冲突
	// 优化执行顺序：指纹识别优先，然后目录扫描
	orderedModules := sc.getOptimizedModuleOrder()

	for i, module := range orderedModules {
		logger.Debugf("开始执行模块: %s (%d/%d)", module, i+1, len(orderedModules))

		moduleResults, err := sc.runModuleForTargets(module, targets)
		if err != nil {
			logger.Errorf("模块 %s 执行失败: %v", module, err)
			continue
		}

		// 合并结果
		allResults = append(allResults, moduleResults...)
		logger.Debugf("模块 %s 完成，获得 %d 个结果", module, len(moduleResults))

		// 在模块执行之间添加分隔（混合模式）
		if len(orderedModules) > 1 && i < len(orderedModules)-1 {
			fmt.Println() // 添加空行分隔
		}
	}

	// [修复] 删除重复的已完成主机数更新
	// 已完成主机数由各个模块在目标完成时单独更新，避免重复计数

	logger.Debugf("所有模块执行完成，总结果数: %d", len(allResults))

	// 检查是否只有指纹识别模块
	onlyFingerprint := len(sc.args.Modules) == 1 && sc.args.Modules[0] == "finger"

	var filterResult *interfaces.FilterResult
	if onlyFingerprint {
		// 指纹识别模块不需要Filter处理，直接使用原始结果
		logger.Debugf("指纹识别模块跳过Filter处理")
		filterResult = &interfaces.FilterResult{
			ValidPages: allResults,
		}
	} else {
		// [修改] 目录扫描模块已在各目标扫描时独立应用过滤器
		// 这里的allResults已经是过滤后的结果，直接使用
		logger.Debugf("使用已过滤的结果，数量: %d", len(allResults))
		filterResult = &interfaces.FilterResult{
			ValidPages: allResults,
		}

		// 显示最终合并统计
		if len(allResults) > 0 {
			logger.Debugf("所有目标过滤完成，最终有效结果: %d", len(allResults))
		}
	}

	// 生成报告（支持指纹识别和目录扫描的JSON/HTML输出）
	if sc.args.Output != "" {
		if onlyFingerprint {
			// 指纹识别模式：生成指纹识别报告
			err = sc.generateReport(filterResult)
			if err != nil {
				logger.Errorf("指纹识别报告生成失败: %v", err)
			}
		} else if len(filterResult.ValidPages) > 0 {
			// 目录扫描模式：仅在有有效结果时生成报告
			err = sc.generateReport(filterResult)
			if err != nil {
				logger.Errorf("目录扫描报告生成失败: %v", err)
			}
		}
	}

	// 显示最终统计并禁用统计显示器
	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.ShowFinalStats()
		sc.statsDisplay.Disable()
	}

	return nil
}

// GetRequestProcessor 获取请求处理器（用于测试和调试）
func (sc *ScanController) GetRequestProcessor() *requests.RequestProcessor {
	return sc.requestProcessor
}

// runPassiveMode 运行被动代理模式
func (sc *ScanController) runPassiveMode() error {
	logger.Info("启动被动代理模式")
	// 直接返回，让主函数处理被动模式
	// 这样可以保持与现有代码100%兼容
	return nil
}

// parseTargets 解析目标列表（支持命令行参数和文件输入）
func (sc *ScanController) parseTargets(targetStrs []string) ([]string, error) {
	logger.Debugf("开始解析目标")

	var allTargets []string

	// 处理命令行直接指定的目标
	if len(targetStrs) > 0 {
		logger.Debugf("处理命令行目标，数量: %d", len(targetStrs))
		for _, targetStr := range targetStrs {
			// 分割逗号分隔的目标
			parts := strings.Split(targetStr, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					allTargets = append(allTargets, part)
				}
			}
		}
	}

	// 处理文件中的目标
	if sc.args.TargetFile != "" {
		logger.Debugf("处理目标文件: %s", sc.args.TargetFile)
		parser := batch.NewTargetParser()
		fileTargets, err := parser.ParseFile(sc.args.TargetFile)
		if err != nil {
			return nil, fmt.Errorf("读取目标文件失败: %v", err)
		}
		allTargets = append(allTargets, fileTargets...)
		logger.Debugf("从文件读取到 %d 个目标", len(fileTargets))
	}

	if len(allTargets) == 0 {
		return nil, fmt.Errorf("没有有效的目标")
	}

	// 去重
	deduplicator := batch.NewDeduplicator()
	uniqueTargets, stats := deduplicator.DeduplicateWithStats(allTargets)

	if stats.DuplicateCount > 0 {
		logger.Debugf("去重完成: 原始 %d 个，去重后 %d 个，重复 %d 个 (%.1f%%)",
			stats.OriginalCount, stats.UniqueCount, stats.DuplicateCount, stats.DuplicateRate)
	}

	// 连通性检测和URL标准化
	checker := batch.NewConnectivityChecker(sc.config)
	validTargets := checker.BatchCheck(uniqueTargets)

	if len(validTargets) == 0 {
		return nil, fmt.Errorf("没有可连通的目标")
	}

	logger.Debugf("目标解析完成: 最终有效目标 %d 个", len(validTargets))
	return validTargets, nil
}

// getOptimizedModuleOrder 获取优化的模块执行顺序
// 指纹识别优先执行，然后执行其他模块
func (sc *ScanController) getOptimizedModuleOrder() []string {
	var orderedModules []string

	// 指纹识别优先执行
	for _, module := range sc.args.Modules {
		if module == "finger" {
			orderedModules = append(orderedModules, module)
			break
		}
	}

	// 然后执行其他模块
	for _, module := range sc.args.Modules {
		if module != "finger" {
			orderedModules = append(orderedModules, module)
		}
	}

	return orderedModules
}

// runModuleForTargets 为目标运行指定模块
func (sc *ScanController) runModuleForTargets(moduleName string, targets []string) ([]interfaces.HTTPResponse, error) {

	switch moduleName {
	case "dirscan":
		return sc.runDirscanModule(targets)
	case "finger":

		return sc.runFingerprintModule(targets)
	default:
		return nil, fmt.Errorf("不支持的模块: %s", moduleName)
	}
}

// runDirscanModule 运行目录扫描模块（[重要] 多目标并发优化）
func (sc *ScanController) runDirscanModule(targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("开始目录扫描，目标数量: %d", len(targets))

	// [重要] 多目标优化：判断是否使用并发扫描（重构：简化判断逻辑）
	if len(targets) > 1 {
		return sc.runConcurrentDirscan(targets)
	}

	// 单目标或禁用并发时使用原有逻辑
	return sc.runSequentialDirscan(targets)
}

// runConcurrentDirscan 运行并发目录扫描（修改：单目标独立过滤）
func (sc *ScanController) runConcurrentDirscan(targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("目标数量: %d", len(targets))

	// 创建目标调度器
	scheduler := scheduler.NewTargetScheduler(targets, sc.config)

	// [重要] 设置基础请求处理器，确保统计更新正常工作
	scheduler.SetBaseRequestProcessor(sc.requestProcessor)

	// 执行并发扫描
	targetResults, err := scheduler.ExecuteConcurrentScan()
	if err != nil {
		return nil, fmt.Errorf("多目标并发扫描失败: %v", err)
	}

	// [修改] 对每个目标的结果独立应用过滤器，然后合并
	var allResults []interfaces.HTTPResponse
	for target, responses := range targetResults {
		logger.Debugf("处理目标 %s 的 %d 个响应", target, len(responses))

		// 转换为接口类型
		var targetResponses []interfaces.HTTPResponse
		for _, resp := range responses {
			httpResp := interfaces.HTTPResponse{
				URL:             resp.URL,
				StatusCode:      resp.StatusCode,
				ContentLength:   resp.ContentLength,
				ContentType:     resp.ContentType,
				ResponseHeaders: resp.ResponseHeaders,
				RequestHeaders:  resp.RequestHeaders,
				ResponseBody:    resp.ResponseBody,
				Title:           resp.Title,
				Server:          resp.Server,
				Duration:        resp.Duration,
				IsDirectory:     strings.HasSuffix(resp.URL, "/"),
			}
			targetResponses = append(targetResponses, httpResp)
		}

		// [新增] 对单个目标立即应用过滤器
		if len(targetResponses) > 0 {
			filterResult, err := sc.applyFilterForTarget(targetResponses, target)
			if err != nil {
				logger.Errorf("目标 %s 过滤器应用失败: %v", target, err)
				// 如果过滤失败，使用原始结果
				allResults = append(allResults, targetResponses...)
			} else {
				// 使用过滤后的结果
				allResults = append(allResults, filterResult.ValidPages...)
			}
		}
	}

	return allResults, nil
}

// runSequentialDirscan 运行顺序目录扫描（修改：单目标独立过滤）
func (sc *ScanController) runSequentialDirscan(targets []string) ([]interfaces.HTTPResponse, error) {
	var allResults []interfaces.HTTPResponse

	for _, target := range targets {
		// 生成扫描URL
		scanURLs := sc.generateDirscanURLs(target)
		logger.Debugf("为 %s 生成了 %d 个扫描URL", target, len(scanURLs))

		// 发起HTTP请求
		responses := sc.requestProcessor.ProcessURLs(scanURLs)

		// 转换为接口类型
		var targetResponses []interfaces.HTTPResponse
		for _, resp := range responses {
			httpResp := interfaces.HTTPResponse{
				URL:             resp.URL,
				StatusCode:      resp.StatusCode,
				ContentLength:   resp.ContentLength,
				ContentType:     resp.ContentType,
				ResponseHeaders: resp.ResponseHeaders,
				RequestHeaders:  resp.RequestHeaders,
				ResponseBody:    resp.ResponseBody,
				Title:           resp.Title,
				Server:          resp.Server,
				Duration:        resp.Duration,
				IsDirectory:     strings.HasSuffix(resp.URL, "/"),
			}
			targetResponses = append(targetResponses, httpResp)
		}

		// [新增] 对单个目标立即应用过滤器
		if len(targetResponses) > 0 {
			filterResult, err := sc.applyFilterForTarget(targetResponses, target)
			if err != nil {
				logger.Errorf("目标 %s 过滤器应用失败: %v", target, err)
				// 如果过滤失败，使用原始结果
				allResults = append(allResults, targetResponses...)
			} else {
				// 使用过滤后的结果
				allResults = append(allResults, filterResult.ValidPages...)
			}
		}

		// [重要] 更新已完成主机数统计（单目标扫描）
		if sc.statsDisplay.IsEnabled() {
			sc.statsDisplay.IncrementCompletedHosts()
			logger.Debugf("单目标扫描完成目标 %s，更新已完成主机数", target)
		}
	}
	return allResults, nil
}

// runFingerprintModule 运行指纹识别模块（[重要] 多目标并发优化）
func (sc *ScanController) runFingerprintModule(targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("开始指纹识别，数量: %d", len(targets))

	// [重要] 多目标优化：判断是否使用并发扫描（重构：简化判断逻辑）
	if len(targets) > 1 {
		return sc.runConcurrentFingerprint(targets)
	}

	// 单目标或禁用并发时使用原有逻辑
	return sc.runSequentialFingerprint(targets)
}

// runConcurrentFingerprint 运行并发指纹识别（修复：添加超时和panic恢复）
func (sc *ScanController) runConcurrentFingerprint(targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Infof("并发指纹识别模式，数量: %d", len(targets))

	// [重要] 设置批量扫描模式，确保统计更新正确
	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	defer sc.requestProcessor.SetBatchMode(originalBatchMode) // 恢复原始模式

	// 创建带超时的context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// 指纹识别使用简化的并发逻辑，因为每个目标只需要一个请求
	var allResults []interfaces.HTTPResponse
	var resultsMu sync.Mutex
	var wg sync.WaitGroup

	// 创建目标信号量（重构：使用统一并发控制）
	// 使用请求处理器的并发数作为目标并发数
	maxTargetConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxTargetConcurrent <= 0 {
		maxTargetConcurrent = 20 // 备用默认值
	}
	logger.Debugf("指纹识别目标并发数设置为: %d", maxTargetConcurrent)
	targetSem := make(chan struct{}, maxTargetConcurrent)

	for _, target := range targets {
		wg.Add(1)
		go func(targetURL string) {
			defer func() {
				// 修复：添加panic恢复，确保WaitGroup计数正确
				if r := recover(); r != nil {
					logger.Errorf("指纹识别panic恢复: %v, 目标: %s", r, targetURL)
				}
				wg.Done()
			}()

			// 获取目标信号量（改进：增加重试机制，避免目标丢失）
			acquired := false
			for retryCount := 0; retryCount < 3 && !acquired; retryCount++ {
				select {
				case targetSem <- struct{}{}:
					acquired = true
					defer func() {
						select {
						case <-targetSem:
						default:
							// 信号量已满，不需要释放
						}
					}()
				case <-ctx.Done():
					logger.Debugf("指纹识别被取消: %s", targetURL)
					return
				case <-time.After(time.Duration(30+retryCount*10) * time.Second): // 递增超时时间
					if retryCount < 2 {
						logger.Warnf("获取指纹识别信号量超时，重试 %d/3: %s", retryCount+1, targetURL)
					} else {
						logger.Errorf("获取指纹识别信号量最终失败，跳过目标: %s", targetURL)
						return
					}
				}
			}

			// 处理单个目标的指纹识别（添加超时检查）
			select {
			case <-ctx.Done():
				logger.Debugf("指纹识别处理被取消: %s", targetURL)
				return
			default:
			}

			results := sc.processSingleTargetFingerprintWithTimeout(ctx, targetURL)

			// [重要] 更新已完成主机数统计
			if sc.statsDisplay.IsEnabled() {
				sc.statsDisplay.IncrementCompletedHosts()
				logger.Debugf("指纹识别完成目标 %s，更新已完成主机数", targetURL)
			}

			// 合并结果
			resultsMu.Lock()
			allResults = append(allResults, results...)
			resultsMu.Unlock()

		}(target)
	}

	// 等待所有目标完成（修复：添加超时保护）
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debugf("所有指纹识别任务完成")
	case <-ctx.Done():
		logger.Warnf("指纹识别超时或被取消")
		return allResults, ctx.Err()
	case <-time.After(12 * time.Minute):
		logger.Warnf("指纹识别总体超时")
		cancel() // 取消所有正在进行的任务
		return allResults, fmt.Errorf("指纹识别超时")
	}

	// [重要] 主动探测path字段指纹（复用被动模式逻辑）
	sc.performPathProbingWithTimeout(ctx, targets)

	return allResults, nil
}

// runSequentialFingerprint 运行顺序指纹识别（保持原有逻辑）
func (sc *ScanController) runSequentialFingerprint(targets []string) ([]interfaces.HTTPResponse, error) {
	// [重要] 动态设置模块上下文为指纹识别，禁用processor进度条
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("fingerprint")
	defer sc.requestProcessor.SetModuleContext(originalContext) // 恢复原始上下文

	// 检查指纹引擎是否可用
	if sc.fingerprintEngine == nil {
		return nil, fmt.Errorf("指纹识别引擎未初始化")
	}

	var allResults []interfaces.HTTPResponse

	// [重要] 初始化指纹识别进度跟踪器
	pathRulesCount := 0
	if sc.fingerprintEngine.HasPathRules() {
		pathRulesCount = sc.fingerprintEngine.GetPathRulesCount()
	}

	for _, target := range targets {
		// 为每个目标创建进度跟踪器
		sc.progressTracker = NewFingerprintProgressTracker(target, pathRulesCount)

		responses := sc.requestProcessor.ProcessURLs([]string{target})

		for _, resp := range responses {

			// 转换为fingerprint模块的HTTPResponse格式
			fpResponse := sc.convertToFingerprintResponse(resp)
			if fpResponse == nil {
				logger.Debugf("响应转换失败: %s", resp.URL)
				continue
			}

			// [重要] 关键修复：使用带HTTP客户端的分析方法，支持icon()函数主动探测
			httpClient := sc.createHTTPClientAdapter()

			matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, httpClient)

			// [重要] 更新进度：基础指纹匹配完成
			sc.progressTracker.UpdateProgress("指纹识别进行中")

			// 转换为接口类型（用于报告生成，但指纹识别不需要Filter）
			httpResp := interfaces.HTTPResponse{
				URL:             resp.URL,
				StatusCode:      resp.StatusCode,
				ContentLength:   resp.ContentLength,
				ContentType:     resp.ContentType,
				ResponseHeaders: resp.ResponseHeaders,
				RequestHeaders:  resp.RequestHeaders,
				ResponseBody:    resp.ResponseBody,
				Title:           resp.Title,
				Server:          resp.Server,
				Duration:        resp.Duration,
				IsDirectory:     false,
			}
			allResults = append(allResults, httpResp)

			logger.Debugf("%s 指纹识别完成，匹配数量: %d", target, len(matches))
		}

		// [重要] 更新已完成主机数统计（单目标指纹识别）
		if sc.statsDisplay.IsEnabled() {
			sc.statsDisplay.IncrementCompletedHosts()
			logger.Debugf("单目标指纹识别完成目标 %s，更新已完成主机数", target)
		}
	}

	// [重要] 主动探测path字段指纹（复用被动模式逻辑）
	sc.performPathProbing(targets)

	return allResults, nil
}

// processSingleTargetFingerprint 处理单个目标的指纹识别（[重要] 多目标并发优化）
func (sc *ScanController) processSingleTargetFingerprint(target string) []interfaces.HTTPResponse {
	logger.Debugf("开始处理指纹识别: %s", target)

	// 为目标设置上下文
	targetDomain := extractDomainFromURL(target)
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext(fmt.Sprintf("finger-%s", targetDomain))
	defer sc.requestProcessor.SetModuleContext(originalContext)

	var results []interfaces.HTTPResponse

	// 发起HTTP请求
	responses := sc.requestProcessor.ProcessURLs([]string{target})

	for _, resp := range responses {
		// 转换为fingerprint模块的HTTPResponse格式
		fpResponse := sc.convertToFingerprintResponse(resp)
		if fpResponse == nil {
			logger.Debugf("响应转换失败: %s", resp.URL)
			continue
		}

		// [重要] 关键修复：使用带HTTP客户端的分析方法，支持icon()函数主动探测
		httpClient := sc.createHTTPClientAdapter()
		matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, httpClient)

		// 转换为接口类型
		httpResp := interfaces.HTTPResponse{
			URL:             resp.URL,
			StatusCode:      resp.StatusCode,
			ContentLength:   resp.ContentLength,
			ContentType:     resp.ContentType,
			ResponseHeaders: resp.ResponseHeaders,
			RequestHeaders:  resp.RequestHeaders,
			ResponseBody:    resp.ResponseBody,
			Title:           resp.Title,
			Server:          resp.Server,
			Duration:        resp.Duration,
			IsDirectory:     false,
		}
		results = append(results, httpResp)

		logger.Debugf("%s 识别完成: %d", target, len(matches))
	}

	return results
}

// extractDomainFromURL 从URL中提取域名（用于目标标识）
func extractDomainFromURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	// 简单的域名提取，用于日志标识
	if len(rawURL) > 30 {
		return rawURL[:27] + "..."
	}
	return rawURL
}

// generateDirscanURLs 生成目录扫描URL
func (sc *ScanController) generateDirscanURLs(target string) []string {
	// 解析URL以获取路径信息
	parsedURL, err := url.Parse(target)
	if err != nil {
		logger.Errorf("URL解析失败: %v", err)
		return []string{target}
	}

	// 获取基础URL（协议+主机+端口）
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// 分析路径层级
	path := strings.Trim(parsedURL.Path, "/")
	if path == "" {
		// 根目录扫描
		return sc.urlGenerator.GenerateURLs([]string{baseURL})
	}

	// 多层级目录扫描
	pathParts := strings.Split(path, "/")
	var scanTargets []string

	// 为每个路径层级生成扫描目标
	currentPath := ""
	for _, part := range pathParts {
		currentPath += "/" + part
		scanTarget := baseURL + currentPath
		if !strings.HasSuffix(scanTarget, "/") {
			scanTarget += "/"
		}
		scanTargets = append(scanTargets, scanTarget)
	}

	// 使用URLGenerator生成最终的扫描URL
	return sc.urlGenerator.GenerateURLs(scanTargets)
}

// generateReport 生成扫描报告
func (sc *ScanController) generateReport(filterResult *interfaces.FilterResult) error {
	// 检查输出路径是否指定
	if sc.args.Output == "" {
		logger.Debug("未指定输出路径，跳过报告生成")
		return nil
	}

	// 检查目标文件是否已存在
	if _, err := os.Stat(sc.args.Output); err == nil {
		logger.Infof("目标文件已存在，将被覆盖: %s", sc.args.Output)
	}

	// 使用自定义报告生成器，直接指定输出路径
	reportPath, err := sc.generateCustomReport(filterResult, sc.args.Output)
	if err != nil {
		return fmt.Errorf("报告生成失败: %v", err)
	}

	logger.Infof("Report: %s", reportPath)
	return nil
}

// generateCustomReport 生成自定义路径的报告
func (sc *ScanController) generateCustomReport(filterResult *interfaces.FilterResult, outputPath string) (string, error) {
	logger.Debugf("开始生成自定义报告到: %s", outputPath)

	// 准备报告数据
	target := strings.Join(sc.args.Targets, ",")

	// 根据文件扩展名选择报告格式
	if strings.HasSuffix(strings.ToLower(outputPath), ".json") {
		// 生成JSON报告
		return sc.generateJSONReport(filterResult, target, outputPath)
	} else {
		// 生成HTML报告（默认）
		reportGenerator := report.NewCustomReportGenerator(outputPath)
		reportPath, err := reportGenerator.GenerateReport(filterResult, target)
		if err != nil {
			return "", fmt.Errorf("生成自定义HTML报告失败: %v", err)
		}
		return reportPath, nil
	}
}

// generateJSONReport 生成JSON格式报告
func (sc *ScanController) generateJSONReport(filterResult *interfaces.FilterResult, target string, outputPath string) (string, error) {
	logger.Debugf("开始生成JSON报告到: %s", outputPath)

	// 准备扫描参数
	scanParams := map[string]interface{}{
		"threads": sc.args.Threads,
		"timeout": sc.args.Timeout,
		"retry":   sc.args.Retry,
	}

	// 检查是否为指纹识别模式
	onlyFingerprint := len(sc.args.Modules) == 1 && sc.args.Modules[0] == "finger"

	if onlyFingerprint {
		// 指纹识别JSON报告
		if sc.fingerprintEngine == nil {
			return "", fmt.Errorf("指纹识别引擎未初始化")
		}

		// 获取指纹匹配结果和统计信息
		matches := sc.fingerprintEngine.GetMatches()
		stats := sc.fingerprintEngine.GetStats()

		// 添加指纹识别特定参数
		scanParams["rules_loaded"] = stats.RulesLoaded

		// 生成指纹识别JSON报告
		return report.GenerateCustomJSONFingerprintReport(matches, stats, target, scanParams, outputPath)
	} else {
		// 目录扫描JSON报告
		// 添加目录扫描特定参数
		if sc.args.Wordlist != "" {
			scanParams["wordlist"] = sc.args.Wordlist
		} else {
			scanParams["wordlist"] = "default"
		}

		// 生成目录扫描JSON报告
		return report.GenerateCustomJSONDirscanReport(filterResult, target, scanParams, outputPath)
	}
}

// applyFilter 应用过滤器（复用dirscan模块的实现模式）
func (sc *ScanController) applyFilter(responses []interfaces.HTTPResponse) (*interfaces.FilterResult, error) {
	logger.Debug("开始应用响应过滤器")

	// 创建响应过滤器（从外部配置）
	responseFilter := filter.CreateResponseFilterFromExternal()

	// 应用过滤器
	filterResult := responseFilter.FilterResponses(responses)

	// 显示过滤结果（复用现有的日志打印功能）
	responseFilter.PrintFilterResult(filterResult)

	logger.Debugf("过滤完成 - 总响应: %d, 有效结果: %d",
		len(responses), len(filterResult.ValidPages))

	return filterResult, nil
}

// applyFilterForTarget 对单个目标应用过滤器（新增：单目标独立过滤）
func (sc *ScanController) applyFilterForTarget(responses []interfaces.HTTPResponse, target string) (*interfaces.FilterResult, error) {
	logger.Debugf("开始对目标 %s 应用过滤器，响应数量: %d", target, len(responses))

	// 创建响应过滤器（从外部配置）
	responseFilter := filter.CreateResponseFilterFromExternal()

	// [新增] 如果指纹引擎可用，设置到过滤器中（启用二次识别）
	if sc.fingerprintEngine != nil {
		responseFilter.SetFingerprintEngine(sc.fingerprintEngine)
		logger.Debugf("[二次指纹] 目录扫描模块已启用指纹二次识别功能，引擎类型: %T", sc.fingerprintEngine)
	} else {
		logger.Debugf("[二次指纹] 指纹引擎为nil，未启用二次识别")
	}

	// [关键] 重置过滤器状态，确保目标间状态隔离
	responseFilter.Reset()

	// 应用过滤器
	filterResult := responseFilter.FilterResponses(responses)

	// 显示单个目标的过滤结果（现在会包含指纹信息）
	logger.Debugf("目标 %s 过滤完成:", target)
	responseFilter.PrintFilterResult(filterResult)

	logger.Debugf("目标 %s 过滤完成 - 原始响应: %d, 有效结果: %d",
		target, len(responses), len(filterResult.ValidPages))

	return filterResult, nil
}

// convertToFingerprintResponse 将processor响应转换为fingerprint模块的HTTPResponse格式
// 集成被动模式的高级HTTP处理功能：解压缩、编码检测、HTML实体解码
func (sc *ScanController) convertToFingerprintResponse(resp *interfaces.HTTPResponse) *fingerprint.HTTPResponse {
	if resp == nil {
		return nil
	}

	// 转换响应头格式（interfaces.HTTPResponse.ResponseHeaders已经是map[string][]string）
	headers := resp.ResponseHeaders
	if headers == nil {
		headers = make(map[string][]string)
	}

	// [重要] 关键修复：处理响应体解压缩和编码转换
	processedBody := sc.processResponseBody(resp)

	// 提取处理后的标题（使用解压缩和编码转换后的内容）
	title := sc.extractTitleFromHTML(processedBody)

	logger.Debugf("响应体处理完成: %s (原始: %d bytes, 处理后: %d bytes)",
		resp.URL, len(resp.ResponseBody), len(processedBody))

	return &fingerprint.HTTPResponse{
		URL:           resp.URL,
		Method:        "GET", // 主动扫描默认使用GET方法
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		Body:          processedBody, // 使用处理后的响应体
		ContentType:   resp.ContentType,
		ContentLength: int64(len(processedBody)), // 更新为处理后的长度
		Server:        resp.Server,
		Title:         title, // 使用处理后的标题
	}
}

// processResponseBody 处理响应体：解压缩 + 编码检测转换（复用fingerprint模块逻辑）
func (sc *ScanController) processResponseBody(resp *interfaces.HTTPResponse) string {
	if resp == nil || resp.ResponseBody == "" {
		return ""
	}

	rawBody := resp.ResponseBody

	// [重要] 步骤1: 检查Content-Encoding并解压缩
	decompressedBody := sc.decompressResponseBody(rawBody, resp.ResponseHeaders)

	// [重要] 步骤2: 字符编码检测和转换
	convertedBody := sc.encodingDetector.DetectAndConvert(decompressedBody, resp.ContentType)

	logger.Debugf("响应体处理: %s (原始: %d -> 解压: %d -> 转换: %d bytes)",
		resp.URL, len(rawBody), len(decompressedBody), len(convertedBody))

	return convertedBody
}

// decompressResponseBody 解压缩响应体（复用fingerprint/addon.go的逻辑）
func (sc *ScanController) decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}

	// 获取Content-Encoding头部
	var contentEncoding string
	if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
		contentEncoding = strings.ToLower(encodingHeaders[0])
	}

	// 如果没有压缩，直接返回
	if contentEncoding == "" {
		return body
	}

	bodyBytes := []byte(body)

	// 根据压缩类型进行解压缩
	if strings.Contains(contentEncoding, "gzip") {
		return sc.decompressGzip(bodyBytes)
	} else if strings.Contains(contentEncoding, "deflate") {
		return sc.decompressDeflate(bodyBytes)
	} else if strings.Contains(contentEncoding, "br") {
		return sc.decompressBrotli(bodyBytes)
	}

	// 不支持的压缩格式，返回原始内容
	logger.Debugf("不支持的压缩格式: %s", contentEncoding)
	return body
}

// decompressGzip 解压gzip压缩的响应体（复用fingerprint/addon.go的逻辑）
func (sc *ScanController) decompressGzip(compressedBody []byte) string {
	reader := bytes.NewReader(compressedBody)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		logger.Debugf("gzip解压失败: %v, 返回原始内容", err)
		return string(compressedBody)
	}
	defer gzipReader.Close()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		logger.Debugf("gzip读取失败: %v, 返回原始内容", err)
		return string(compressedBody)
	}

	logger.Debugf("gzip解压成功: %d bytes -> %d bytes",
		len(compressedBody), len(decompressed))

	return string(decompressed)
}

// decompressDeflate 解压deflate压缩的响应体
func (sc *ScanController) decompressDeflate(compressedBody []byte) string {
	reader := bytes.NewReader(compressedBody)
	deflateReader := flate.NewReader(reader)
	defer deflateReader.Close()

	decompressed, err := io.ReadAll(deflateReader)
	if err != nil {
		logger.Debugf("deflate读取失败: %v, 返回原始内容", err)
		return string(compressedBody)
	}

	logger.Debugf("deflate解压成功: %d bytes -> %d bytes",
		len(compressedBody), len(decompressed))

	return string(decompressed)
}

// decompressBrotli 解压brotli压缩的响应体
func (sc *ScanController) decompressBrotli(compressedBody []byte) string {
	reader := bytes.NewReader(compressedBody)
	brotliReader := brotli.NewReader(reader)

	decompressed, err := io.ReadAll(brotliReader)
	if err != nil {
		logger.Debugf("brotli读取失败: %v, 返回原始内容", err)
		return string(compressedBody)
	}

	logger.Debugf("brotli解压成功: %d bytes -> %d bytes",
		len(compressedBody), len(decompressed))

	return string(decompressed)
}

// extractTitleFromHTML 从HTML中提取标题（复用fingerprint/addon.go的逻辑）
func (sc *ScanController) extractTitleFromHTML(body string) string {
	if body == "" {
		return ""
	}

	// 使用正则表达式提取title标签内容，支持多行
	titleRegex := regexp.MustCompile(`(?i)<title[^>]*?>(.*?)</title>`)
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// 解码HTML实体
		title = sc.entityDecoder.DecodeHTMLEntities(title)
		// 清理多余的空白字符
		title = regexp.MustCompile(`\s+`).ReplaceAllString(title, " ")
		return title
	}
	return ""
}

// performPathProbing 执行path字段主动探测（复用被动模式逻辑）
func (sc *ScanController) performPathProbing(targets []string) {
	// 检查指纹引擎是否可用
	if sc.fingerprintEngine == nil {
		logger.Debug("指纹引擎未初始化，跳过path探测")
		return
	}

	// 检查是否有包含path字段的规则
	if !sc.fingerprintEngine.HasPathRules() {
		logger.Debug("没有包含path字段的规则，跳过path探测")
		return
	}

	// 创建HTTP客户端适配器（复用RequestProcessor的HTTP处理能力）
	httpClient := sc.createHTTPClientAdapter()

	// 为每个目标执行path探测
	for _, target := range targets {
		baseURL := sc.extractBaseURL(target)
		hostKey := sc.extractHostKey(baseURL)

		// 检查是否已经探测过此主机（避免重复探测）
		if sc.shouldTriggerPathProbing(hostKey) {
			logger.Debugf("触发path字段主动探测: %s", hostKey)
			sc.markHostAsProbed(hostKey)

			// [重要] 修复：使用同步方式执行path探测，确保所有path规则都被处理
			sc.performSyncPathProbing(baseURL, httpClient)
		} else {
			logger.Debugf("主机已探测过，跳过path探测: %s", hostKey)
		}
	}
}

// createHTTPClientAdapter 创建HTTP客户端（支持TLS和重定向）
func (sc *ScanController) createHTTPClientAdapter() httpclient.HTTPClientInterface {
	// 使用HTTP客户端工厂（代码质量优化）
	userAgent := "veo-Scanner/1.0"
	return httpclient.CreateClientWithUserAgent(userAgent)
}

// extractBaseURL 从完整URL中提取基础URL（协议+主机）
func (sc *ScanController) extractBaseURL(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return rawURL
}

// extractHostKey 提取主机键（用于探测缓存）
func (sc *ScanController) extractHostKey(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return parsedURL.Host // 包含端口的主机名
	}
	return rawURL
}

// shouldTriggerPathProbing 检查是否应该触发path探测
func (sc *ScanController) shouldTriggerPathProbing(hostKey string) bool {
	sc.probedMutex.RLock()
	defer sc.probedMutex.RUnlock()

	// 检查是否已经探测过此主机
	return !sc.probedHosts[hostKey]
}

// markHostAsProbed 标记主机为已探测
func (sc *ScanController) markHostAsProbed(hostKey string) {
	sc.probedMutex.Lock()
	defer sc.probedMutex.Unlock()
	sc.probedHosts[hostKey] = true
}

// performSyncPathProbing 执行同步path字段主动探测（修复异步执行问题）
func (sc *ScanController) performSyncPathProbing(baseURL string, httpClient httpclient.HTTPClientInterface) {
	logger.Debugf("开始同步path字段主动探测: %s", baseURL)

	// 获取所有包含path字段的规则
	pathRules := sc.getPathRulesFromEngine()
	if len(pathRules) == 0 {
		logger.Debug("没有包含path字段的规则，跳过主动探测")
		return
	}

	logger.Debugf("找到 %d 个包含path字段的规则，开始逐一探测", len(pathRules))

	// 解析baseURL获取协议和主机
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		logger.Debugf("URL解析失败: %s, 错误: %v", baseURL, err)
		return
	}

	scheme := parsedURL.Scheme
	host := parsedURL.Host

	// [重要] 性能优化：并发遍历所有path规则进行探测（修复：添加超时和panic恢复）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50) // [重要] 性能优化：提升path探测并发数

	for i, rule := range pathRules {
		wg.Add(1)
		go func(index int, r *fingerprint.FingerprintRule) {
			defer func() {
				// 修复：添加panic恢复，确保WaitGroup计数正确
				if rec := recover(); rec != nil {
					logger.Errorf("Path探测panic恢复: %v, 规则: %s", rec, r.Name)
				}
				wg.Done()
			}()

			// 获取信号量（修复：添加超时避免永久阻塞）
			select {
			case semaphore <- struct{}{}:
				defer func() {
					select {
					case <-semaphore:
					default:
						// 信号量已满，不需要释放
					}
				}()
			case <-ctx.Done():
				logger.Debugf("Path探测被取消: %s", r.Name)
				return
			case <-time.After(30 * time.Second):
				logger.Warnf("获取Path探测信号量超时: %s", r.Name)
				return
			}

			// 处理path规则（添加超时检查）
			select {
			case <-ctx.Done():
				logger.Debugf("Path规则处理被取消: %s", r.Name)
				return
			default:
			}

			sc.processPathRuleWithTimeout(ctx, index, len(pathRules), r, scheme, host, baseURL, httpClient)
		}(i, rule)
	}

	// 等待所有path探测完成（修复：添加超时保护）
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debugf("所有Path探测完成")
	case <-ctx.Done():
		logger.Warnf("Path探测超时或被取消")
	case <-time.After(6 * time.Minute):
		logger.Warnf("Path探测总体超时")
		cancel() // 取消所有正在进行的探测
	}

	logger.Debugf("并发path字段主动探测完成: %s (共探测 %d 个路径)", baseURL, len(pathRules))

	// [新增] 404页面指纹识别
	sc.perform404PageProbing(baseURL, httpClient)
}

// processSingleTargetFingerprintWithTimeout 处理单个目标的指纹识别（新增：支持超时）
func (sc *ScanController) processSingleTargetFingerprintWithTimeout(ctx context.Context, target string) []interfaces.HTTPResponse {
	// 创建带超时的context
	targetCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// 使用channel接收结果，支持超时
	resultChan := make(chan []interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("单目标指纹识别panic: %v, 目标: %s", r, target)
				resultChan <- []interfaces.HTTPResponse{}
			}
		}()

		results := sc.processSingleTargetFingerprint(target)
		resultChan <- results
	}()

	select {
	case results := <-resultChan:
		return results
	case <-targetCtx.Done():
		logger.Warnf("单目标指纹识别超时或被取消: %s", target)
		return []interfaces.HTTPResponse{}
	}
}

// performPathProbingWithTimeout 执行path探测（新增：支持超时）
func (sc *ScanController) performPathProbingWithTimeout(ctx context.Context, targets []string) {
	// 创建带超时的context
	probingCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	// 使用channel通知完成
	done := make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("Path探测panic: %v", r)
			}
			close(done)
		}()

		sc.performPathProbing(targets)
	}()

	select {
	case <-done:
		logger.Debugf("Path探测完成")
	case <-probingCtx.Done():
		logger.Warnf("Path探测超时或被取消")
	}
}

// processPathRuleWithTimeout 处理单个path规则（新增：支持超时）
func (sc *ScanController) processPathRuleWithTimeout(ctx context.Context, index, total int, rule *fingerprint.FingerprintRule, scheme, host, baseURL string, httpClient interface{}) {
	// 创建带超时的context
	ruleCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// 使用channel通知完成
	done := make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("Path规则处理panic: %v, 规则: %s", r, rule.Name)
			}
			close(done)
		}()

		// 类型断言转换为正确的接口类型
		if client, ok := httpClient.(httpclient.HTTPClientInterface); ok {
			sc.processPathRule(index, total, rule, scheme, host, baseURL, client)
		} else {
			logger.Warnf("HTTP客户端类型转换失败，跳过path规则: %s", rule.Name)
		}
	}()

	select {
	case <-done:
		// 处理完成
	case <-ruleCtx.Done():
		logger.Warnf("Path规则处理超时或被取消: %s", rule.Name)
	}
}

// processPathRule 处理单个path规则（提取出来支持并发）
func (sc *ScanController) processPathRule(index, total int, rule *fingerprint.FingerprintRule, scheme, host, baseURL string, httpClient httpclient.HTTPClientInterface) {
	// 构造完整的探测URL
	probeURL := fmt.Sprintf("%s://%s%s", scheme, host, rule.Path)

	logger.Debugf("主动探测URL [%d/%d]: %s (规则: %s)",
		index+1, total, probeURL, rule.Name)

	// 发起HTTP请求
	body, statusCode, err := httpClient.MakeRequest(probeURL)
	if err != nil {
		logger.Debugf("主动探测请求失败: %s, 错误: %v", probeURL, err)
		// [重要] 即使失败也要更新进度
		if sc.progressTracker != nil {
			sc.progressTracker.UpdateProgress("指纹识别进行中")
		}
		return
	}

	logger.Debugf("主动探测请求成功: %s [%d] 响应体长度: %d",
		probeURL, statusCode, len(body))

	// 构造模拟的HTTPResponse用于DSL匹配
	response := &fingerprint.HTTPResponse{
		URL:           probeURL,
		Method:        "GET",
		StatusCode:    statusCode,
		Headers:       make(map[string][]string), // 简化版，暂不解析响应头
		Body:          body,
		ContentType:   "text/html", // 简化假设
		ContentLength: int64(len(body)),
		Server:        "",
		Title:         sc.extractTitleFromHTML(body), // 复用现有的标题提取方法
	}

	// [重要] 性能优化：使用专用的单规则匹配，避免遍历所有525个规则
	match := sc.fingerprintEngine.MatchSpecificRule(rule, response, httpClient, baseURL)
	if match != nil {
		logger.Debugf("path探测发现匹配: %s -> %s", probeURL, rule.Name)

		// 手动输出匹配结果（因为没有使用完整的AnalyzeResponse流程）
		// 使用与指纹引擎一致的高亮格式
		logger.Infof("%s <%s> <%s> [%s]",
			formatter.FormatURL(probeURL),
			formatter.FormatFingerprintName(rule.Name),
			formatter.FormatDSLRule(match.DSLMatched),
			formatter.FormatFingerprintTag("主动探测"))
	}

	// [重要] 更新进度：path探测完成
	if sc.progressTracker != nil {
		sc.progressTracker.UpdateProgress("指纹识别进行中")
	}
}

// getPathRulesFromEngine 从指纹引擎获取包含path字段的规则
func (sc *ScanController) getPathRulesFromEngine() []*fingerprint.FingerprintRule {
	if sc.fingerprintEngine == nil {
		return nil
	}

	// 通过反射或公共方法获取path规则
	// 这里我们需要添加一个公共方法到fingerprint.Engine
	return sc.fingerprintEngine.GetPathRules()
}

// runPassiveModeInternal 运行被动模式的内部实现
// 这个函数将调用现有的被动模式逻辑，保持100%兼容性
func runPassiveModeInternal(args *CLIArgs, cfg *config.Config) error {
	logger.Info("被动代理模式使用现有实现，保持100%兼容性")

	// 初始化应用程序（使用现有逻辑）
	app, err := initializeAppForPassiveMode(args)
	if err != nil {
		return fmt.Errorf("初始化应用程序失败: %v", err)
	}

	// 启动应用程序（使用现有逻辑）
	if err := startApplicationForPassiveMode(args, app); err != nil {
		return fmt.Errorf("启动应用程序失败: %v", err)
	}

	logger.Info("被动代理模式启动成功，等待连接...")

	// 这里不需要等待信号，因为主函数会处理
	return nil
}

// 这些函数将在下一步实现，用于调用现有的被动模式逻辑
func initializeAppForPassiveMode(args *CLIArgs) (*CLIApp, error) {
	// 占位符，将调用现有的initializeApp函数
	return nil, nil
}

func startApplicationForPassiveMode(args *CLIArgs, app *CLIApp) error {
	// 占位符，将调用现有的startApplication函数
	return nil
}

// perform404PageProbing 执行404页面指纹识别
func (sc *ScanController) perform404PageProbing(baseURL string, httpClient httpclient.HTTPClientInterface) {
	logger.Debugf("开始404页面指纹识别: %s", baseURL)

	// 解析baseURL获取协议和主机
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		logger.Debugf("URL解析失败: %s, 错误: %v", baseURL, err)
		return
	}

	scheme := parsedURL.Scheme
	host := parsedURL.Host

	// 构造404测试URL
	notFoundURL := fmt.Sprintf("%s://%s/404test", scheme, host)
	logger.Debugf("404页面探测URL: %s", notFoundURL)

	// 发起HTTP请求
	body, statusCode, err := httpClient.MakeRequest(notFoundURL)
	if err != nil {
		logger.Debugf("404页面探测请求失败: %s, 错误: %v", notFoundURL, err)
		return
	}

	logger.Debugf("404页面响应: 状态码=%d, 内容长度=%d", statusCode, len(body))

	// 构造模拟的HTTPResponse用于DSL匹配
	response := &fingerprint.HTTPResponse{
		URL:           notFoundURL,
		Method:        "GET",
		StatusCode:    statusCode,
		Headers:       make(map[string][]string), // 简化版，暂不解析响应头
		Body:          body,
		ContentType:   "text/html", // 简化假设
		ContentLength: int64(len(body)),
		Server:        "",
		Title:         sc.extractTitleFromHTML(body), // 提取标题
	}

	// 对404页面进行全量指纹规则匹配（使用静默模式避免重复输出）
	httpClientAdapter := sc.createHTTPClientAdapter()
	logger.Debugf("开始对404页面进行全量指纹匹配: %s", notFoundURL)
	matches := sc.fingerprintEngine.AnalyzeResponseWithClientSilent(response, httpClientAdapter)
	logger.Debugf("404页面指纹匹配完成，匹配结果数量: %d", len(matches))

	if len(matches) > 0 {
		logger.Debugf("404页面匹配到 %d 个指纹", len(matches))

		// 输出404页面的匹配结果（使用与主动探测一致的格式）
		for _, match := range matches {
			// [修复] 直接使用原始标题，避免重复格式化导致双重方括号
			title := response.Title
			if title == "" {
				title = "无标题"
			}

			logger.Infof("%s %s <%s> <%s> [%s]",
				formatter.FormatURL(notFoundURL),
				formatter.FormatTitle(title),
				formatter.FormatFingerprintName(match.RuleName),
				formatter.FormatDSLRule(match.DSLMatched),
				formatter.FormatFingerprintTag("404页面"))
		}
	} else {
		logger.Debugf("404页面未匹配到任何指纹")
	}
}
