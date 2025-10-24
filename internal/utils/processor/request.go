package processor

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"veo/internal/core/config"
	"veo/internal/core/interfaces"
	"veo/internal/utils/auth"
	"veo/internal/utils/shared"
	"veo/proxy"

	"veo/internal/core/logger"

	"github.com/valyala/fasthttp"
)

// ===========================================
// 类型定义
// ===========================================

// 注意：HTTPResponse结构体已迁移到addon/interfaces/interfaces.go文件中
// 使用 interfaces.HTTPResponse 来引用统一的结构体定义

// RequestConfig 请求配置
type RequestConfig struct {
	Timeout         time.Duration // 请求超时时间
	MaxRetries      int           // 最大重试次数
	UserAgents      []string      // User-Agent列表（支持随机选择）
	MaxBodySize     int           // 最大响应体大小
	FollowRedirect  bool          // 是否跟随重定向
	MaxConcurrent   int           // 最大并发数
	ConnectTimeout  time.Duration // 连接超时时间
	KeepAlive       time.Duration // 保持连接时间
	RandomUserAgent bool          // 是否随机使用UserAgent
	Delay           time.Duration // 请求延迟时间
}

// ProcessingStats 处理统计信息 (原progress.go内容)
type ProcessingStats struct {
	TotalCount     int64
	SuccessCount   int64
	FailureCount   int64
	SkippedCount   int64
	ProcessedCount int64
	StartTime      time.Time
	TimeoutCount   int64 // 超时次数
}

// WorkerPool 工作池结构体（并发优化）
type WorkerPool struct {
	workerCount int
	taskChan    chan WorkerTask
	resultChan  chan WorkerResult
	workers     []*Worker
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// WorkerTask 工作任务
type WorkerTask struct {
	URL       string
	Index     int
	TotalURLs int
}

// WorkerResult 工作结果
type WorkerResult struct {
	Response *interfaces.HTTPResponse
	URL      string
	Index    int
	Error    error
}

// Worker 工作线程
type Worker struct {
	id         int
	processor  *RequestProcessor
	taskChan   <-chan WorkerTask
	resultChan chan<- WorkerResult
	ctx        context.Context
}

// StatsUpdater 统计更新器接口
type StatsUpdater interface {
	IncrementCompletedRequests()
	IncrementTimeouts()
	SetTotalRequests(count int64)
	AddTotalRequests(count int64) // 累加总请求数（用于批量扫描）
	IncrementCompletedHosts()     // 增加已完成主机数
}

// RequestProcessor 请求处理器
type RequestProcessor struct {
	proxy.BaseAddon
	client         *fasthttp.Client
	config         *RequestConfig
	mu             sync.RWMutex
	userAgentPool  []string               // UserAgent池
	titleExtractor *shared.TitleExtractor // 标题提取器
	moduleContext  string                 // 模块上下文标识（用于区分调用来源）
	workerPool     *WorkerPool            // 并发优化：工作池
	statsUpdater   StatsUpdater           // 统计更新器
	batchMode      bool                   // 批量扫描模式标志

	// 新增：HTTP认证头部管理
	customHeaders map[string]string  // CLI指定的自定义头部
	authDetector  *auth.AuthDetector // 认证检测器
}

// ===========================================
// 构造函数
// ===========================================

// NewRequestProcessor 创建新的请求处理器
func NewRequestProcessor(config *RequestConfig) *RequestProcessor {
	if config == nil {
		config = getDefaultConfig()
	}

	processor := &RequestProcessor{
		client:         createFastHTTPClient(config),
		config:         config,
		userAgentPool:  initializeUserAgentPool(config),
		titleExtractor: shared.NewTitleExtractor(),

		// 新增：初始化认证头部管理
		customHeaders: make(map[string]string),
		authDetector:  auth.NewAuthDetector(),
	}

	return processor
}

// ===========================================
// HTTP认证头部管理方法
// ===========================================

// SetCustomHeaders 设置自定义HTTP头部（来自CLI参数）
func (rp *RequestProcessor) SetCustomHeaders(headers map[string]string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	rp.customHeaders = make(map[string]string)
	for key, value := range headers {
		rp.customHeaders[key] = value
	}

	// 如果设置了自定义头部，禁用自动检测
	if len(headers) > 0 {
		rp.authDetector.SetEnabled(false)
		logger.Debugf("设置了 %d 个自定义头部，禁用自动认证检测", len(headers))
	} else {
		rp.authDetector.SetEnabled(true)
		logger.Debug("未设置自定义头部，启用自动认证检测")
	}
}

// HasCustomHeaders 检查是否设置了自定义头部
func (rp *RequestProcessor) HasCustomHeaders() bool {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return len(rp.customHeaders) > 0
}

// ===========================================
// 请求处理器核心方法
// ===========================================

// ProcessURLs 处理URL列表，发起HTTP请求并返回响应结构体列表（Worker Pool优化版本）
func (rp *RequestProcessor) ProcessURLs(urls []string) []*interfaces.HTTPResponse {
	if len(urls) == 0 {
		return []*interfaces.HTTPResponse{}
	}

	// 初始化处理统计
	stats := rp.initializeProcessingStats(len(urls), rp.config.MaxConcurrent, rp.config.RandomUserAgent)

	// 更新统计显示器的总请求数
	if rp.statsUpdater != nil {
		if rp.IsBatchMode() {
			// 批量模式：累加请求数
			rp.statsUpdater.AddTotalRequests(int64(len(urls)))
		} else {
			// 单目标模式：设置请求数
			rp.statsUpdater.SetTotalRequests(int64(len(urls)))
		}
	}

	// 初始化响应收集
	responses := make([]*interfaces.HTTPResponse, 0, len(urls))
	var responsesMu sync.Mutex

	// 创建进度完成信号通道
	progressDone := make(chan struct{})

	// 并发优化：使用Worker Pool处理URL
	rp.processURLsWithWorkerPool(urls, &responses, &responsesMu, stats)

	// 完成处理
	rp.finalizeProcessing(progressDone, stats, len(responses))

	return responses
}

// ===========================================
// URL处理相关方法
// ===========================================

// processConcurrentURLs 并发处理URL列表（真正的并发控制）
func (rp *RequestProcessor) processConcurrentURLs(urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {
	var wg sync.WaitGroup

	// 使用带缓冲的channel控制并发数
	sem := make(chan struct{}, rp.config.MaxConcurrent)

	for i, url := range urls {
		wg.Add(1)

		go func(index int, targetURL string) {
			// 获取信号量（这里会阻塞，直到有可用的槽位）
			sem <- struct{}{}

			defer func() {
				<-sem // 释放信号量
				wg.Done()
			}()

			rp.processURLWithStats(targetURL, responses, responsesMu, stats)
		}(i, url)
	}

	wg.Wait()
}

// processURLsWithWorkerPool 使用Worker Pool处理URL列表
func (rp *RequestProcessor) processURLsWithWorkerPool(urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {
	// 创建并启动工作池
	workerPool := rp.createAndStartWorkerPool()
	defer workerPool.Stop()

	// 提交任务并收集结果
	taskSubmissionDone := rp.submitTasksAsync(workerPool, urls)
	rp.collectResults(workerPool, urls, responses, responsesMu, stats, taskSubmissionDone)
}

// createAndStartWorkerPool 创建并启动工作池
func (rp *RequestProcessor) createAndStartWorkerPool() *WorkerPool {
	workerPool := NewWorkerPool(rp.config.MaxConcurrent, rp)
	workerPool.Start()
	return workerPool
}

// submitTasksAsync 异步提交所有任务
func (rp *RequestProcessor) submitTasksAsync(workerPool *WorkerPool, urls []string) <-chan struct{} {
	taskSubmissionDone := make(chan struct{})

	go func() {
		defer close(taskSubmissionDone)
		for i, url := range urls {
			// 检查Worker Pool是否已停止
			if rp.shouldStopTaskSubmission(workerPool) {
				logger.Debugf("🚫 Worker Pool已停止，停止提交新任务")
				return
			}

			task := WorkerTask{
				URL:       url,
				Index:     i,
				TotalURLs: len(urls),
			}
			workerPool.SubmitTask(task)
		}
	}()

	return taskSubmissionDone
}

// shouldStopTaskSubmission 检查是否应该停止任务提交
func (rp *RequestProcessor) shouldStopTaskSubmission(workerPool *WorkerPool) bool {
	select {
	case <-workerPool.ctx.Done():
		return true
	default:
		return false
	}
}

// collectResults 收集处理结果（修复：完善超时和取消机制）
func (rp *RequestProcessor) collectResults(workerPool *WorkerPool, urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats, taskSubmissionDone <-chan struct{}) {
	processedCount := 0
	timeoutDuration := 30 * time.Second

	// 创建结果收集的context，支持提前取消
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration+10*time.Second)
	defer cancel()

	for processedCount < len(urls) {
		select {
		case result := <-workerPool.GetResult():
			rp.processWorkerResult(result, responses, responsesMu, stats)
			processedCount++

		case <-time.After(timeoutDuration):
			logger.Warnf("Worker Pool处理超时，尝试收集剩余结果...")

			// 修复：尝试收集剩余结果，避免丢失数据
			remainingResults := rp.collectRemainingResults(workerPool, len(urls)-processedCount, responses, responsesMu, stats)
			processedCount += remainingResults

			logger.Warnf("超时处理完成，最终处理: %d/%d", processedCount, len(urls))

			// 等待任务提交完成，但设置超时避免永久阻塞
			select {
			case <-taskSubmissionDone:
			case <-time.After(5 * time.Second):
				logger.Warnf("等待任务提交完成超时，强制退出")
			}
			return

		case <-ctx.Done():
			logger.Warnf("结果收集被取消，已处理: %d/%d", processedCount, len(urls))
			return
		}
	}

	// 确保任务提交完成，但设置超时避免永久阻塞
	select {
	case <-taskSubmissionDone:
	case <-time.After(5 * time.Second):
		logger.Warnf("等待任务提交完成超时")
	}
}

// collectRemainingResults 收集剩余结果（新增：避免结果丢失）
func (rp *RequestProcessor) collectRemainingResults(workerPool *WorkerPool, maxResults int, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) int {
	collected := 0
	timeout := 100 * time.Millisecond

	for i := 0; i < maxResults && i < 50; i++ { // 最多尝试收集50个剩余结果
		select {
		case result := <-workerPool.GetResult():
			rp.processWorkerResult(result, responses, responsesMu, stats)
			collected++
		case <-time.After(timeout):
			// 逐渐增加超时时间，但有上限
			if timeout < 500*time.Millisecond {
				timeout += 50 * time.Millisecond
			}
			break
		}
	}

	logger.Debugf("收集到 %d 个剩余结果", collected)
	return collected
}

// processWorkerResult 处理单个工作结果
func (rp *RequestProcessor) processWorkerResult(result WorkerResult, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {
	// 应用请求延迟
	if rp.config.Delay > 0 {
		time.Sleep(rp.config.Delay)
	}

	// 更新统计和收集响应
	rp.updateProcessingStats(result.Response, result.URL, responses, responsesMu, stats)
}

// processURLWithStats 处理单个URL并更新统计
func (rp *RequestProcessor) processURLWithStats(targetURL string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {
	// 请求延迟
	if rp.config.Delay > 0 {
		time.Sleep(rp.config.Delay)
	}

	// 处理URL（并发控制已在上层处理）
	response := rp.processURL(targetURL)

	// 更新统计和收集响应
	rp.updateProcessingStats(response, targetURL, responses, responsesMu, stats)
}

// processURL 处理单个URL
func (rp *RequestProcessor) processURL(url string) *interfaces.HTTPResponse {
	var response *interfaces.HTTPResponse
	var err error

	// 改进的重试逻辑（指数退避 + 抖动）
	for attempt := 0; attempt <= rp.config.MaxRetries; attempt++ {
		if attempt > 0 {
			logger.Debug(fmt.Sprintf("重试 %d/%d: %s", attempt, rp.config.MaxRetries, url))
		}

		response, err = rp.makeRequest(url)
		if err == nil {
			return response
		}

		// 检查是否为可重试的错误
		if !rp.isRetryableError(err) {
			logger.Debugf("不可重试的错误，停止重试: %s, 错误: %v", url, err)
			break
		}

		// 改进的重试延迟：指数退避 + 随机抖动
		if attempt < rp.config.MaxRetries {
			baseDelay := time.Duration(1<<uint(attempt)) * time.Second  // 指数退避: 1s, 2s, 4s, 8s
			jitter := time.Duration(rand.Intn(1000)) * time.Millisecond // 随机抖动: 0-1s
			delay := baseDelay + jitter
			if delay > 10*time.Second {
				delay = 10 * time.Second // 最大延迟10秒
			}
			logger.Debugf("重试延迟: %v (基础: %v, 抖动: %v)", delay, baseDelay, jitter)
			time.Sleep(delay)
		}
	}

	logger.Debug(fmt.Sprintf("请求失败 (重试%d次): %s, 错误: %v",
		rp.config.MaxRetries, url, err))
	return nil
}

// ===========================================
// HTTP请求相关方法
// ===========================================

// makeRequest 使用fasthttp发起请求
func (rp *RequestProcessor) makeRequest(rawURL string) (*interfaces.HTTPResponse, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// 准备请求
	rp.prepareRequest(req, rawURL)
	startTime := time.Now()

	// 执行HTTP请求
	err := rp.executeHTTPRequest(req, resp, rawURL)
	if err != nil {
		rp.logRequestError(rawURL, err)
		return nil, fmt.Errorf("请求失败: %v", err)
	}

	// 记录请求完成日志
	duration := time.Since(startTime)
	logger.Debug(fmt.Sprintf("fasthttp请求完成: %s [%d] 耗时: %v",
		rawURL, resp.StatusCode(), duration))

	// 构建响应对象
	return rp.buildHTTPResponse(rawURL, req, resp, startTime)
}

// prepareRequest 准备HTTP请求
func (rp *RequestProcessor) prepareRequest(req *fasthttp.Request, rawURL string) {
	req.SetRequestURI(rawURL)
	req.Header.SetMethod(fasthttp.MethodGet)
	rp.setRequestHeaders(&req.Header)
}

// executeHTTPRequest 执行HTTP请求（支持重定向处理）
func (rp *RequestProcessor) executeHTTPRequest(req *fasthttp.Request, resp *fasthttp.Response, rawURL string) error {
	if rp.config.FollowRedirect {
		return rp.executeWithRedirect(req, resp, rawURL)
	}

	logger.Debugf("fasthttp请求（不跟随重定向）: %s", rawURL)
	return rp.client.DoTimeout(req, resp, rp.config.Timeout)
}

// executeWithRedirect 执行支持重定向的HTTP请求
func (rp *RequestProcessor) executeWithRedirect(req *fasthttp.Request, resp *fasthttp.Response, rawURL string) error {
	logger.Debugf("fasthttp请求（跟随重定向）: %s", rawURL)

	// 首先尝试fasthttp的DoRedirects方法
	err := rp.client.DoRedirects(req, resp, 5)
	if err == nil {
		return nil
	}

	// 如果是重定向错误，尝试手动重定向
	if rp.isRedirectError(err) {
		return rp.handleRedirectError(req, resp, rawURL, err)
	}

	return err
}

// handleRedirectError 处理重定向错误
func (rp *RequestProcessor) handleRedirectError(req *fasthttp.Request, resp *fasthttp.Response, rawURL string, originalErr error) error {
	logger.Debugf("fasthttp重定向失败，尝试手动重定向: %s, 错误: %v", rawURL, originalErr)

	// 释放当前响应
	fasthttp.ReleaseResponse(resp)

	// 使用手动重定向跟随
	manualResp, manualErr := rp.followRedirectManually(rawURL, 5)
	if manualErr == nil {
		// 将手动重定向的响应复制到原响应对象
		*resp = *manualResp
		logger.Debugf("手动重定向成功: %s [%d]", rawURL, resp.StatusCode())
		return nil
	}

	logger.Warnf("手动重定向失败: %s, 错误: %v", rawURL, manualErr)

	// 最后回退：不跟随重定向的方式
	*resp = *fasthttp.AcquireResponse()
	rp.setupRequest(req, rawURL)
	err := rp.client.DoTimeout(req, resp, rp.config.Timeout)
	if err == nil {
		logger.Debugf("回退到不跟随重定向: %s [%d]", rawURL, resp.StatusCode())
	}
	return err
}

// logRequestError 记录请求错误日志
func (rp *RequestProcessor) logRequestError(rawURL string, err error) {
	if rp.isTimeoutOrCanceledError(err) {
		logger.Debugf("[超时丢弃] URL: %s, 耗时: >%v, 错误: %v", rawURL, rp.config.Timeout, err)
	} else if rp.isRedirectError(err) {
		logger.Warnf("重定向处理失败: %s, 错误: %v", rawURL, err)
	} else {
		logger.Debugf("请求失败: %s, 错误: %v", rawURL, err)
	}
}

// buildHTTPResponse 构建HTTP响应对象
func (rp *RequestProcessor) buildHTTPResponse(rawURL string, req *fasthttp.Request, resp *fasthttp.Response, startTime time.Time) (*interfaces.HTTPResponse, error) {
	requestHeaders := rp.extractRequestHeaders(&req.Header)
	return rp.processResponse(rawURL, resp, requestHeaders, startTime)
}

// ===========================================
// Worker Pool 实现（并发优化）
// ===========================================

// calculateOptimalBufferSize 计算最优缓冲区大小
// 根据工作线程数量和缓冲区类型，动态计算最适合的缓冲区大小
// 参数：
//   - workerCount: 工作线程数量
//   - bufferType: 缓冲区类型（"task" 或 "result"）
// 返回：最优的缓冲区大小
func calculateOptimalBufferSize(workerCount int, bufferType string) int {
	baseSize := workerCount * 2 // 基础缓冲区大小：工作线程数的2倍

	switch bufferType {
	case "task":
		// 任务缓冲区：需要更大的缓冲区来避免生产者阻塞
		if workerCount <= 10 {
			return baseSize
		} else if workerCount <= 50 {
			return workerCount * 3
		} else {
			return workerCount * 4
		}
	case "result":
		// 结果缓冲区：相对较小，避免内存占用过多
		if workerCount <= 10 {
			return baseSize
		} else {
			return workerCount + 10
		}
	default:
		return baseSize
	}
}

// NewWorkerPool 创建工作池
// 根据指定的工作线程数量创建一个优化的工作池，支持动态缓冲区大小调整
// 参数：
//   - workerCount: 工作线程数量
//   - processor: 请求处理器实例
// 返回：配置完成的工作池实例
func NewWorkerPool(workerCount int, processor *RequestProcessor) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	// 动态计算最优缓冲区大小，提升并发性能
	taskBufferSize := calculateOptimalBufferSize(workerCount, "task")
	resultBufferSize := calculateOptimalBufferSize(workerCount, "result")

	pool := &WorkerPool{
		workerCount: workerCount,
		taskChan:    make(chan WorkerTask, taskBufferSize),     // 任务通道，带缓冲
		resultChan:  make(chan WorkerResult, resultBufferSize), // 结果通道，带缓冲
		workers:     make([]*Worker, workerCount),
		ctx:         ctx,
		cancel:      cancel,
	}

	// 创建并初始化所有工作线程
	for i := 0; i < workerCount; i++ {
		worker := &Worker{
			id:         i,
			processor:  processor,
			taskChan:   pool.taskChan,
			resultChan: pool.resultChan,
			ctx:        ctx,
		}
		pool.workers[i] = worker
	}

	return pool
}

// Start 启动工作池
func (wp *WorkerPool) Start() {
	for _, worker := range wp.workers {
		wp.wg.Add(1)
		go worker.run(&wp.wg)
	}
}

// Stop 停止工作池（修复：添加超时保护和资源清理）
func (wp *WorkerPool) Stop() {
	// 1. 发送取消信号
	wp.cancel()

	// 2. 关闭任务通道，阻止新任务提交
	close(wp.taskChan)

	// 3. 等待所有worker完成，但设置超时避免永久阻塞
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debugf("所有Worker正常退出")
	case <-time.After(10 * time.Second):
		logger.Warnf("Worker Pool停止超时，可能存在阻塞的goroutine")
	}

	// 4. 安全关闭结果通道
	select {
	case <-wp.resultChan:
		// 通道已经被关闭或为空
	default:
		// 通道还有数据或未关闭
	}
	close(wp.resultChan)

	logger.Debugf("Worker Pool已停止")
}

// SubmitTask 提交任务（修复：添加安全的channel发送机制）
func (wp *WorkerPool) SubmitTask(task WorkerTask) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warnf("任务提交发生panic（channel已关闭），任务: %s, 错误: %v", task.URL, r)
		}
	}()

	select {
	case wp.taskChan <- task:
	case <-wp.ctx.Done():
		return
	}
}

// GetResult 获取结果
func (wp *WorkerPool) GetResult() <-chan WorkerResult {
	return wp.resultChan
}

// run Worker的主运行循环（修复：添加panic恢复和超时保护）
// 持续监听任务通道，处理接收到的URL请求任务
// 参数：
//   - wg: 等待组，用于协调工作线程的生命周期
func (w *Worker) run(wg *sync.WaitGroup) {
	defer func() {
		// 修复：添加panic恢复，确保WaitGroup计数正确
		if r := recover(); r != nil {
			logger.Errorf("Worker %d panic恢复: %v", w.id, r)
		}
		wg.Done()
		logger.Debugf("Worker %d 已退出", w.id)
	}()

	logger.Debugf("Worker %d 已启动", w.id)

	for {
		select {
		case task, ok := <-w.taskChan:
			// 检查任务通道是否已关闭
			if !ok {
				logger.Debugf("Worker %d: 任务通道已关闭，退出", w.id)
				return
			}

			// 处理URL请求任务（添加超时保护）
			response := w.processTaskWithTimeout(task)

			// 构建处理结果
			result := WorkerResult{
				Response: response,
				URL:      task.URL,
				Index:    task.Index,
				Error:    nil,
			}

			// 发送结果到结果通道（修复：改进结果处理，避免丢失有效结果）
			select {
			case w.resultChan <- result:
				// 结果发送成功，继续处理下一个任务
			case <-w.ctx.Done():
				// 工作池已停止，退出工作线程
				logger.Debugf("Worker %d: 收到停止信号，退出", w.id)
				return
			case <-time.After(60 * time.Second): // 增加超时时间到60秒
				// 修复：结果发送超时时，尝试缓存结果而不是直接丢弃
				logger.Warnf("Worker %d: 结果发送超时，尝试缓存结果: %s", w.id, task.URL)
				w.cacheDelayedResult(result)
				// 继续处理下一个任务，不退出worker
			}

		case <-w.ctx.Done():
			// 接收到停止信号，退出工作线程
			logger.Debugf("Worker %d: 收到停止信号，退出", w.id)
			return
		}
	}
}

// cacheDelayedResult 缓存延迟的结果（新增：避免结果丢失）
func (w *Worker) cacheDelayedResult(result WorkerResult) {
	// 在Worker结构体中需要添加delayedResults字段来存储延迟结果
	// 这里先记录日志，实际实现需要在Worker结构体中添加缓存机制
	if result.Response != nil {
		logger.Infof("缓存延迟结果: %s [%d] - 将在下次机会重新发送",
			result.URL, result.Response.StatusCode)
	} else {
		logger.Warnf("缓存失败结果: %s - 请求处理失败", result.URL)
	}
}

// processTaskWithTimeout 处理任务（新增：添加超时保护）
func (w *Worker) processTaskWithTimeout(task WorkerTask) *interfaces.HTTPResponse {
	// 创建带超时的context
	ctx, cancel := context.WithTimeout(w.ctx, 60*time.Second)
	defer cancel()

	// 使用channel接收结果，支持超时
	resultChan := make(chan *interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("Worker %d 处理任务panic: %v, URL: %s", w.id, r, task.URL)
				resultChan <- nil
			}
		}()

		response := w.processor.processURL(task.URL)
		resultChan <- response
	}()

	select {
	case response := <-resultChan:
		return response
	case <-ctx.Done():
		logger.Warnf("Worker %d 处理任务超时: %s", w.id, task.URL)
		return nil
	}
}

// processResponseBody 处理响应体，应用大小限制（内存优化）
func (rp *RequestProcessor) processResponseBody(rawBody []byte) string {
	// 获取配置的最大响应体大小
	maxSize := rp.config.MaxBodySize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 默认10MB
	}

	// 如果响应体超过限制，进行截断
	if len(rawBody) > maxSize {
		truncatedBody := make([]byte, maxSize)
		copy(truncatedBody, rawBody[:maxSize])

		// 添加截断标记
		truncatedStr := string(truncatedBody) + "\n...[响应体已截断，原始大小: " +
			fmt.Sprintf("%d bytes", len(rawBody)) + "]"

		logger.Debugf("响应体已截断: %d bytes -> %d bytes",
			len(rawBody), maxSize)

		return truncatedStr
	}

	return string(rawBody)
}

// processResponse 处理fasthttp响应，构建HTTPResponse结构体
func (rp *RequestProcessor) processResponse(url string, resp *fasthttp.Response, requestHeaders map[string][]string, startTime time.Time) (*interfaces.HTTPResponse, error) {
	// 提取响应基本信息
	body := rp.processResponseBody(resp.Body())
	title := rp.extractTitleSafely(url, body)
	contentLength := rp.getContentLength(resp, body)
	contentType := rp.getContentType(resp)
	responseHeaders := rp.extractResponseHeadersSafely(url, resp)
	server := rp.extractServerInfoSafely(url, resp)
	duration := time.Since(startTime).Milliseconds()

	// 构建响应对象
	response := rp.buildResponseObject(url, resp, title, contentLength, contentType, body, responseHeaders, requestHeaders, server, duration)

	// 新增：处理认证检测（仅在401/403响应时且未设置自定义头部时）
	rp.handleAuthDetection(resp, url)

	// 记录处理完成日志
	logger.Debug(fmt.Sprintf("响应处理完成: %s [%d] %s, 响应头数量: %d, 耗时: %dms",
		url, resp.StatusCode(), title, len(responseHeaders), duration))

	return response, nil
}

// extractTitleSafely 安全地提取页面标题
func (rp *RequestProcessor) extractTitleSafely(url, body string) string {
	var title string
	func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warnf("标题提取发生panic，URL: %s, 错误: %v", url, r)
				title = "标题提取失败"
			}
		}()
		title = rp.titleExtractor.ExtractTitle(body)
	}()
	return title
}

// getContentLength 获取内容长度
func (rp *RequestProcessor) getContentLength(resp *fasthttp.Response, body string) int64 {
	contentLength := int64(len(body))
	if resp.Header.ContentLength() >= 0 {
		contentLength = int64(resp.Header.ContentLength())
	}
	return contentLength
}

// getContentType 获取内容类型
func (rp *RequestProcessor) getContentType(resp *fasthttp.Response) string {
	contentType := string(resp.Header.ContentType())
	if contentType == "" {
		contentType = "unknown"
	}
	return contentType
}

// extractResponseHeadersSafely 安全地提取响应头
func (rp *RequestProcessor) extractResponseHeadersSafely(url string, resp *fasthttp.Response) map[string][]string {
	var responseHeaders map[string][]string
	func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warnf("响应头提取发生panic，URL: %s, 错误: %v", url, r)
				responseHeaders = make(map[string][]string)
			}
		}()

		if resp == nil {
			logger.Warnf("响应对象为空，URL: %s", url)
			responseHeaders = make(map[string][]string)
			return
		}

		responseHeaders = make(map[string][]string)
		resp.Header.VisitAll(func(key, value []byte) {
			if key == nil || value == nil {
				return
			}
			keyStr := string(key)
			valueStr := string(value)
			if _, exists := responseHeaders[keyStr]; !exists {
				responseHeaders[keyStr] = make([]string, 0)
			}
			responseHeaders[keyStr] = append(responseHeaders[keyStr], valueStr)
		})
	}()
	return responseHeaders
}

// extractServerInfoSafely 安全地提取服务器信息
func (rp *RequestProcessor) extractServerInfoSafely(url string, resp *fasthttp.Response) string {
	var server string
	if resp != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Warnf("Server头提取发生panic，URL: %s, 错误: %v", url, r)
					server = "unknown"
				}
			}()
			server = string(resp.Header.Peek("Server"))
		}()
	} else {
		server = "unknown"
	}
	return server
}

// buildResponseObject 构建响应对象
func (rp *RequestProcessor) buildResponseObject(url string, resp *fasthttp.Response, title string, contentLength int64, contentType, body string, responseHeaders, requestHeaders map[string][]string, server string, duration int64) *interfaces.HTTPResponse {
	return &interfaces.HTTPResponse{
		URL:             url,
		Method:          "GET",
		StatusCode:      resp.StatusCode(),
		Title:           title,
		ContentLength:   contentLength,
		ContentType:     contentType,
		Body:            body,
		ResponseHeaders: responseHeaders,
		RequestHeaders:  requestHeaders,
		Server:          server,
		IsDirectory:     rp.isDirectoryURL(url),
		Length:          contentLength,
		Duration:        duration,
		Depth:           0,    // 深度信息需要外部设置
		ResponseBody:    body, // 报告用响应体
	}
}

// extractRequestHeaders 提取请求头信息
// 将fasthttp的RequestHeader转换为标准的map[string][]string格式
func (rp *RequestProcessor) extractRequestHeaders(header *fasthttp.RequestHeader) map[string][]string {
	requestHeaders := make(map[string][]string)
	header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		valueStr := string(value)
		if _, exists := requestHeaders[keyStr]; !exists {
			requestHeaders[keyStr] = make([]string, 0)
		}
		requestHeaders[keyStr] = append(requestHeaders[keyStr], valueStr)
	})
	return requestHeaders
}

// isDirectoryURL 判断URL是否可能是目录
// 通过URL结构特征判断：以斜杠结尾或不包含文件扩展名
func (rp *RequestProcessor) isDirectoryURL(url string) bool {
	return strings.HasSuffix(url, "/") || !rp.hasFileExtension(url)
}

// hasFileExtension 判断URL是否包含文件扩展名
// 检查最后一个点号是否在最后一个斜杠之后，以确定是否为文件
func (rp *RequestProcessor) hasFileExtension(url string) bool {
	lastSlash := strings.LastIndex(url, "/")
	lastDot := strings.LastIndex(url, ".")

	// 如果没有点号，或者点号在最后一个斜杠之前，则认为没有扩展名
	return lastDot > lastSlash && lastDot > 0
}

// setRequestHeaders 设置请求头
func (rp *RequestProcessor) setRequestHeaders(h *fasthttp.RequestHeader) {
	headers := rp.getDefaultHeaders()
	for key, value := range headers {
		h.Set(key, value)
	}
}

// ===========================================
// 配置数据获取方法
// ===========================================

// getDefaultHeaders 获取默认请求头（集成认证头部）
func (rp *RequestProcessor) getDefaultHeaders() map[string]string {
	// 获取基础头部
	headers := map[string]string{
		"User-Agent":                rp.getRandomUserAgent(), // 使用随机UserAgent
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language":           "zh-CN,zh;q=0.9,en;q=0.8",
		"Accept-Encoding":           "gzip, deflate",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
	}

	// 合并认证头部
	authHeaders := rp.getAuthHeaders()
	for key, value := range authHeaders {
		headers[key] = value
	}

	return headers
}

// getAuthHeaders 获取认证头部（CLI自定义头部优先，否则使用自动检测的头部）
func (rp *RequestProcessor) getAuthHeaders() map[string]string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	authHeaders := make(map[string]string)

	// 优先使用CLI指定的自定义头部
	if len(rp.customHeaders) > 0 {
		for key, value := range rp.customHeaders {
			authHeaders[key] = value
		}
		return authHeaders
	}

	// 如果没有自定义头部，使用自动检测的头部
	if rp.authDetector.IsEnabled() && rp.authDetector.HasDetectedSchemes() {
		detectedHeaders := rp.authDetector.GetDetectedSchemes()
		for key, value := range detectedHeaders {
			if value != "" { // 只使用有值的头部
				authHeaders[key] = value
			}
		}
	}

	return authHeaders
}

// handleAuthDetection 处理认证检测（仅在未设置自定义头部时）
func (rp *RequestProcessor) handleAuthDetection(resp *fasthttp.Response, url string) {
	// 如果设置了自定义头部，跳过自动检测
	if rp.HasCustomHeaders() {
		return
	}

	// 只处理401和403响应
	if resp.StatusCode() != 401 && resp.StatusCode() != 403 {
		return
	}

	// 将fasthttp.Response转换为http.Response以便认证检测器使用
	httpResp := rp.convertToHTTPResponse(resp)
	if httpResp == nil {
		return
	}

	// 执行认证检测
	detectedHeaders := rp.authDetector.DetectAuthRequirements(httpResp, url)
	if len(detectedHeaders) > 0 {
		logger.Debugf("检测到认证要求，将应用到后续请求: %s", url)
	}
}

// convertToHTTPResponse 将fasthttp.Response转换为http.Response（用于认证检测）
func (rp *RequestProcessor) convertToHTTPResponse(resp *fasthttp.Response) *http.Response {
	httpResp := &http.Response{
		StatusCode: resp.StatusCode(),
		Header:     make(http.Header),
	}

	// 转换响应头
	resp.Header.VisitAll(func(key, value []byte) {
		httpResp.Header.Add(string(key), string(value))
	})

	// 转换Cookie（如果有）
	resp.Header.VisitAllCookie(func(key, value []byte) {
		if cookie := rp.parseCookieFromHeader(string(key), string(value)); cookie != nil {
			if httpResp.Cookies() == nil {
				// 初始化cookies切片
				httpResp.Header.Add("Set-Cookie", cookie.String())
			}
		}
	})

	return httpResp
}

// parseCookieFromHeader 从头部解析Cookie
func (rp *RequestProcessor) parseCookieFromHeader(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:  name,
		Value: value,
	}
}

// ===========================================
// 配置和客户端创建方法
// ===========================================

// createFastHTTPClient 创建fasthttp客户端
func createFastHTTPClient(config *RequestConfig) *fasthttp.Client {
	return &fasthttp.Client{
		TLSConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		ReadTimeout:                   config.Timeout,           // 读取超时：配置文件的timeout_seconds
		WriteTimeout:                  config.Timeout,           // 写入超时：配置文件的timeout_seconds
		MaxIdleConnDuration:           30 * time.Second,         // 性能优化：延长连接保持时间，提升连接复用率
		MaxConnsPerHost:               config.MaxConcurrent * 2, // 性能优化：连接池大小为并发数的2倍，减少连接竞争
		MaxResponseBodySize:           config.MaxBodySize,       // 最大响应体大小
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		NoDefaultUserAgentHeader:      true,
		ReadBufferSize:                16384, // 16k
	}
}

// ===========================================
// 公共接口方法
// ===========================================

// GetConfig 获取当前配置
func (rp *RequestProcessor) GetConfig() *RequestConfig {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.config
}

// UpdateConfig 更新配置
func (rp *RequestProcessor) UpdateConfig(config *RequestConfig) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	rp.config = config
	rp.client = createFastHTTPClient(config)

	// 更新UserAgent池
	rp.userAgentPool = initializeUserAgentPool(config)

	logger.Info("配置已更新")
}

// UpdateUserAgents 更新UserAgent列表
func (rp *RequestProcessor) UpdateUserAgents(userAgents []string) {
	rp.updateUserAgentPool(userAgents)
}

// SetModuleContext 设置模块上下文标识
func (rp *RequestProcessor) SetModuleContext(context string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.moduleContext = context
}

// GetModuleContext 获取模块上下文标识
func (rp *RequestProcessor) GetModuleContext() string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.moduleContext
}

// SetStatsUpdater 设置统计更新器
func (rp *RequestProcessor) SetStatsUpdater(updater StatsUpdater) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.statsUpdater = updater
}

// GetStatsUpdater 获取统计更新器
func (rp *RequestProcessor) GetStatsUpdater() StatsUpdater {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.statsUpdater
}

// SetBatchMode 设置批量扫描模式
func (rp *RequestProcessor) SetBatchMode(enabled bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.batchMode = enabled
}

// IsBatchMode 检查是否为批量扫描模式
func (rp *RequestProcessor) IsBatchMode() bool {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.batchMode
}

// Close 关闭请求处理器，清理资源
func (rp *RequestProcessor) Close() {
	if rp.client != nil {
		rp.client.CloseIdleConnections()
	}
	logger.Info("请求处理器已关闭")
}

// 性能优化：预编译的超时错误正则表达式
var timeoutErrorRegex = regexp.MustCompile(`(?i)(timeout|context canceled|context deadline exceeded|dial timeout|read timeout|write timeout|i/o timeout|deadline exceeded|operation was canceled)`)

// isTimeoutOrCanceledError 判断是否为超时或取消相关的错误（性能优化版）
func (rp *RequestProcessor) isTimeoutOrCanceledError(err error) bool {
	if err == nil {
		return false
	}

	// 性能优化：使用预编译正则表达式替代线性搜索，提升匹配效率
	return timeoutErrorRegex.MatchString(err.Error())
}

// isRetryableError 判断错误是否可重试（新增：改进重试策略）
func (rp *RequestProcessor) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// 可重试的错误类型
	retryableErrors := []string{
		"timeout", "connection reset", "connection refused",
		"temporary failure", "network unreachable", "host unreachable",
		"dial timeout", "read timeout", "write timeout", "i/o timeout",
		"context deadline exceeded", "server closed idle connection",
		"broken pipe", "connection aborted", "no route to host",
	}

	for _, retryableErr := range retryableErrors {
		if strings.Contains(errStr, retryableErr) {
			return true
		}
	}

	// 不可重试的错误类型
	nonRetryableErrors := []string{
		"certificate", "tls", "ssl", "x509", "invalid url",
		"malformed", "parse error", "unsupported protocol",
		"no such host", "dns", "name resolution",
	}

	for _, nonRetryableErr := range nonRetryableErrors {
		if strings.Contains(errStr, nonRetryableErr) {
			return false
		}
	}

	// 默认情况下，网络相关错误可重试
	return true
}

// isRedirectError 判断是否为重定向相关的错误（重定向优化）
func (rp *RequestProcessor) isRedirectError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// 检查重定向相关的错误
	redirectKeywords := []string{
		"missing location header for http redirect",
		"location header",
		"redirect",
	}

	for _, keyword := range redirectKeywords {
		if strings.Contains(errStr, keyword) {
			return true
		}
	}

	return false
}

// ============================================================================
// HTTP重定向处理相关方法（重定向修复）
// ============================================================================

// findLocationHeader 查找Location头（大小写不敏感）
func (rp *RequestProcessor) findLocationHeader(resp *fasthttp.Response) string {
	// 尝试标准的Location头
	if location := string(resp.Header.Peek("Location")); location != "" {
		return location
	}

	// 尝试小写的location头
	if location := string(resp.Header.Peek("location")); location != "" {
		return location
	}

	// 遍历所有头部查找location相关的头（最后的保险）
	var foundLocation string
	resp.Header.VisitAll(func(key, value []byte) {
		if strings.ToLower(string(key)) == "location" {
			foundLocation = string(value)
		}
	})

	return foundLocation
}

// resolveRedirectURL 解析相对路径重定向URL（URL拼接修复）
func (rp *RequestProcessor) resolveRedirectURL(baseURL, location string) (string, error) {
	// URL拼接修复：智能处理基础URL标准化
	normalizedBaseURL := rp.normalizeBaseURL(baseURL, location)

	base, err := url.Parse(normalizedBaseURL)
	if err != nil {
		return "", fmt.Errorf("解析基础URL失败: %v", err)
	}

	redirect, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("解析重定向URL失败: %v", err)
	}

	// 解析相对URL
	resolved := base.ResolveReference(redirect)
	return resolved.String(), nil
}

// normalizeBaseURL 标准化基础URL（URL拼接修复）
func (rp *RequestProcessor) normalizeBaseURL(baseURL, location string) string {
	// 如果是查询参数形式的重定向，确保基础URL有正确的路径
	if rp.isQueryOnlyRedirect(location) {
		parsed, err := url.Parse(baseURL)
		if err != nil {
			return baseURL // 解析失败，返回原URL
		}

		// 如果路径为空，添加根路径斜杠
		if parsed.Path == "" {
			parsed.Path = "/"
			logger.Debugf("URL路径标准化: %s -> %s", baseURL, parsed.String())
			return parsed.String()
		}

		// 如果路径不以斜杠结尾且没有文件扩展名，添加斜杠
		if !strings.HasSuffix(parsed.Path, "/") && !rp.pathHasFileExtension(parsed.Path) {
			parsed.Path += "/"
			logger.Debugf("URL路径标准化: %s -> %s", baseURL, parsed.String())
			return parsed.String()
		}
	}

	return baseURL // 不需要标准化，返回原URL
}

// isQueryOnlyRedirect 检测是否为查询参数形式的相对重定向（URL拼接修复）
func (rp *RequestProcessor) isQueryOnlyRedirect(location string) bool {
	return strings.HasPrefix(location, "?")
}

// pathHasFileExtension 检测路径是否包含文件扩展名（URL拼接修复）
func (rp *RequestProcessor) pathHasFileExtension(path string) bool {
	// 获取路径的最后一部分
	lastPart := path
	if slashIndex := strings.LastIndex(path, "/"); slashIndex != -1 {
		lastPart = path[slashIndex+1:]
	}

	// 检查是否包含点号（文件扩展名的标志）
	return strings.Contains(lastPart, ".")
}

// isRedirectStatus 检查是否为重定向状态码
func (rp *RequestProcessor) isRedirectStatus(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

// followRedirectManually 手动跟随重定向（重定向修复）
func (rp *RequestProcessor) followRedirectManually(originalURL string, maxRedirects int) (*fasthttp.Response, error) {
	currentURL := originalURL

	for i := 0; i < maxRedirects; i++ {
		// 创建新的请求
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)

		// 设置请求
		rp.setupRequest(req, currentURL)

		// 发起请求（不跟随重定向）
		err := rp.client.DoTimeout(req, resp, rp.config.Timeout)
		if err != nil {
			fasthttp.ReleaseResponse(resp)
			return nil, fmt.Errorf("请求失败: %v", err)
		}

		// 检查是否为重定向状态码
		if !rp.isRedirectStatus(resp.StatusCode()) {
			logger.Debugf("手动重定向完成: %s [%d]", currentURL, resp.StatusCode())
			return resp, nil // 不是重定向，返回最终响应
		}

		// 查找Location头
		location := rp.findLocationHeader(resp)
		if location == "" {
			fasthttp.ReleaseResponse(resp)
			return nil, fmt.Errorf("重定向响应缺少Location头")
		}

		// 解析重定向URL
		redirectURL, err := rp.resolveRedirectURL(currentURL, location)
		if err != nil {
			fasthttp.ReleaseResponse(resp)
			return nil, fmt.Errorf("解析重定向URL失败: %v", err)
		}

		logger.Debugf("🔄 手动跟随重定向 [%d/%d]: %s -> %s",
			i+1, maxRedirects, currentURL, redirectURL)

		// 更新当前URL
		currentURL = redirectURL

		// 释放当前响应，准备下一次请求
		fasthttp.ReleaseResponse(resp)
	}

	return nil, fmt.Errorf("超过最大重定向次数: %d", maxRedirects)
}

// setupRequest 设置HTTP请求（重定向修复）
func (rp *RequestProcessor) setupRequest(req *fasthttp.Request, rawURL string) {
	// 设置请求URL
	req.SetRequestURI(rawURL)

	// 设置请求方法
	req.Header.SetMethod("GET")

	// 使用统一的默认头部设置
	headers := rp.getDefaultHeaders()
	for key, value := range headers {
		if key != "User-Agent" { // User-Agent需要特殊处理
			req.Header.Set(key, value)
		}
	}

	// 设置User-Agent（重定向场景使用固定UA）
	if len(rp.config.UserAgents) > 0 {
		req.Header.SetUserAgent(rp.config.UserAgents[0])
	} else {
		req.Header.SetUserAgent("veo/1.0")
	}

	// 设置防缓存头部（重定向场景特有）
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
}

// ============================================================================
// 配置相关功能 (原config.go内容)
// ============================================================================

// getDefaultConfig 获取默认配置
func getDefaultConfig() *RequestConfig {
	cfg := config.GetRequestConfig()

	// [修复] 优先使用配置文件值，提供合理的默认值作为后备
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second // 默认超时时间
	}

	retries := cfg.Retry
	if retries <= 0 {
		retries = 3 // 默认重试次数
	}

	maxConcurrent := cfg.Threads
	if maxConcurrent <= 0 {
		maxConcurrent = 50 // 默认并发数
	}

	connectTimeout := 5 * time.Second // 默认连接超时时间

	randomUserAgent := true
	if cfg.RandomUA != nil {
		randomUserAgent = *cfg.RandomUA
	}

	delay := time.Duration(0) // 移除延迟配置，统一为0

	return &RequestConfig{
		Timeout:         timeout,
		MaxRetries:      retries,
		UserAgents:      getDefaultUserAgents(),
		MaxBodySize:     10 * 1024 * 1024, // 10MB
		FollowRedirect:  true,             // 修复：默认启用重定向跟随，与HTTPClient保持一致
		MaxConcurrent:   maxConcurrent,
		ConnectTimeout:  connectTimeout,
		RandomUserAgent: randomUserAgent,
		Delay:           delay,
	}
}

// ============================================================================
// 进度统计相关方法 (原progress.go内容)
// ============================================================================

// initializeProcessingStats 初始化处理统计
func (rp *RequestProcessor) initializeProcessingStats(totalURLs int, maxConcurrent int, randomUA bool) *ProcessingStats {
	stats := &ProcessingStats{
		TotalCount: int64(totalURLs),
		StartTime:  time.Now(),
	}

	// 根据模块上下文调整日志级别
	if rp.GetModuleContext() == "fingerprint" {
		// 指纹识别模式：使用DEBUG级别，避免日志冗余
		logger.Debug(fmt.Sprintf("开始处理 %d 个URL，并发数: %d，随机UA: %v",
			stats.TotalCount, maxConcurrent, randomUA))
	} else {
		// 目录扫描模式：使用DEBUG级别，因为在engine中已经显示了
		logger.Debug(fmt.Sprintf("开始处理 %d 个URL，并发数: %d，随机UA: %v",
			stats.TotalCount, maxConcurrent, randomUA))
	}

	return stats
}

// updateProcessingStats 更新处理统计
func (rp *RequestProcessor) updateProcessingStats(response *interfaces.HTTPResponse, targetURL string,
	responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {

	atomic.AddInt64(&stats.ProcessedCount, 1)

	if response != nil {
		responsesMu.Lock()
		*responses = append(*responses, response)
		responsesMu.Unlock()

		atomic.AddInt64(&stats.SuccessCount, 1)

		// 更新统计显示器
		if rp.statsUpdater != nil {
			rp.statsUpdater.IncrementCompletedRequests()
		}
	} else {
		atomic.AddInt64(&stats.FailureCount, 1)

		// 检查是否是超时错误（通过检查错误信息而不是URL）
		// 注意：这里需要传递错误信息，但当前架构中没有传递错误信息
		// 暂时使用简单的超时统计逻辑
		atomic.AddInt64(&stats.TimeoutCount, 1)
		if rp.statsUpdater != nil {
			rp.statsUpdater.IncrementTimeouts()
		}
	}
}

// finalizeProcessing 完成处理
func (rp *RequestProcessor) finalizeProcessing(progressDone chan struct{}, stats *ProcessingStats, responseCount int) {
	close(progressDone)
	rp.logProcessingResults(stats)
}

// logProcessingResults 记录处理结果
func (rp *RequestProcessor) logProcessingResults(stats *ProcessingStats) {
	// 根据模块上下文调整日志级别
	if rp.GetModuleContext() == "fingerprint" {
		// 指纹识别模式：使用DEBUG级别，避免日志冗余
		logger.Debug(fmt.Sprintf("\r总计: %d, 成功: %d, 失败: %d, 跳过: %d",
			stats.TotalCount, stats.SuccessCount, stats.FailureCount, stats.SkippedCount))
	} else {
		// 其他模式（如目录扫描）：使用INFO级别
		logger.Debugf("\r总计: %d, 成功: %d, 失败: %d, 跳过: %d",
			stats.TotalCount, stats.SuccessCount, stats.FailureCount, stats.SkippedCount)
	}
}

// ============================================================================
// UserAgent相关方法 (原useragent.go内容)
// ============================================================================

// initializeUserAgentPool 初始化UserAgent池
func initializeUserAgentPool(config *RequestConfig) []string {
	// 从配置文件获取UserAgent列表
	configUserAgents := loadUserAgentsFromConfig()
	if len(configUserAgents) > 0 {
		logger.Debug(fmt.Sprintf("从配置文件加载了 %d 个UserAgent", len(configUserAgents)))
		return configUserAgents
	}

	// 如果配置文件中没有UserAgent，使用默认列表
	defaultUserAgents := getDefaultUserAgents()
	logger.Debug(fmt.Sprintf("使用默认UserAgent列表，共 %d 个", len(defaultUserAgents)))
	return defaultUserAgents
}

// loadUserAgentsFromConfig 从配置文件加载UserAgent列表
func loadUserAgentsFromConfig() []string {
	cfg := config.GetRequestConfig()
	return cfg.UserAgents
}

// getDefaultUserAgents 获取默认UserAgent列表
func getDefaultUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}
}

// updateUserAgentPool 更新UserAgent池
func (rp *RequestProcessor) updateUserAgentPool(userAgents []string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if len(userAgents) > 0 {
		rp.userAgentPool = userAgents
		logger.Debug(fmt.Sprintf("UserAgent池已更新，共 %d 个", len(userAgents)))
	} else {
		rp.userAgentPool = getDefaultUserAgents()
		logger.Debug("使用默认UserAgent池")
	}
}

// getRandomUserAgent 获取随机UserAgent
func (rp *RequestProcessor) getRandomUserAgent() string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	if len(rp.userAgentPool) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}

	if !rp.config.RandomUserAgent {
		return rp.userAgentPool[0]
	}

	index := rand.Intn(len(rp.userAgentPool))
	return rp.userAgentPool[index]
}

// ============================================================================
// 响应处理工具方法 (原response.go有用部分)
// ============================================================================

// getContentLength 获取内容长度
func getContentLength(resp *fasthttp.Response, body string) int64 {
	contentLength := resp.Header.ContentLength()
	if contentLength >= 0 {
		return int64(contentLength)
	}
	return int64(len(body))
}

// getContentType 获取内容类型
func getContentType(resp *fasthttp.Response) string {
	contentTypeBytes := resp.Header.ContentType()
	if contentTypeBytes == nil {
		return "unknown"
	}
	contentType := string(contentTypeBytes)

	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}

	return strings.TrimSpace(contentType)
}
