package scan

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"veo/internal/core/config"
	"veo/internal/core/interfaces"
	"veo/internal/core/logger"
	portconfig "veo/internal/core/ports"
	internaldirscan "veo/internal/modules/dirscan"
	fingerprintinternal "veo/internal/modules/fingerprint"
	portscanpkg "veo/internal/modules/portscan"
	masscanrunner "veo/internal/modules/portscan/masscan"
	portservice "veo/internal/modules/portscan/service/fingerprint"
	"veo/internal/utils/filter"
	requests "veo/internal/utils/processor"
)

// Config 定义一体化扫描的可配置参数。
type Config struct {
	DirTargets         []string
	FingerprintTargets []string
	PortTargets        []string
	SkipTLSVerify      bool
	AutoSkipTLSForIP   *bool
	HTTPTimeout        time.Duration
	Dirscan            *DirscanConfig
	Fingerprint        *FingerprintConfig
	Portscan           *PortscanConfig
}

// DirscanConfig 描述目录扫描的可调参数。
type DirscanConfig struct {
	MaxConcurrency   int
	RequestTimeout   time.Duration
	EnableCollection bool
	EnableFiltering  bool
	EnableReporting  bool
	LogLevel         string
	Filter           *DirscanFilterOptions
}

// DirscanFilterOptions 控制过滤器行为。
type DirscanFilterOptions struct {
	ValidStatusCodes        []int
	InvalidPageThreshold    *int
	SecondaryThreshold      *int
	EnableStatusFilter      *bool
	EnableInvalidPageFilter *bool
	EnableSecondaryFilter   *bool
	EnableContentTypeFilter *bool
	FilterTolerance         *int64
}

// FingerprintConfig 描述指纹识别的可调参数。
type FingerprintConfig struct {
	RulesPath       string
	MaxConcurrency  int
	EnableFiltering bool
	MaxBodySize     int
	LogMatches      bool
	LogLevel        string
	Filters         *FingerprintFilterOptions
	ShowSnippet     *bool
	ShowRule        *bool
}

// PortscanConfig 描述端口扫描可调参数。
type PortscanConfig struct {
	Ports              string
	Rate               int
	TargetFile         string
	ResolveToIP        bool
	EnableServiceProbe bool
}

// FingerprintFilterOptions 控制指纹识别的过滤行为。
type FingerprintFilterOptions struct {
	ContentTypes               []string
	FileExtensions             []string
	ContentTypeFilterEnabled   *bool
	FileExtensionFilterEnabled *bool
}

// Bool 返回布尔值指针。
func Bool(v bool) *bool { return &v }

// Int 返回整型指针。
func Int(v int) *int { return &v }

// Int64 返回整型指针。
func Int64(v int64) *int64 { return &v }

// DefaultConfig 返回默认扫描配置。
func DefaultConfig() *Config {
	return &Config{
		AutoSkipTLSForIP: boolPtr(true),
		HTTPTimeout:      15 * time.Second,
	}
}

// DefaultDirscanConfig 返回目录扫描的默认配置。
func DefaultDirscanConfig() *DirscanConfig {
	return cloneDirscanConfig(defaultDirscanConfig())
}

// DefaultFingerprintConfig 返回指纹识别的默认配置。
func DefaultFingerprintConfig() *FingerprintConfig {
	return cloneFingerprintConfig(defaultFingerprintConfig())
}

// DefaultPortscanConfig 返回端口扫描默认配置。
func DefaultPortscanConfig() *PortscanConfig {
	return clonePortscanConfig(defaultPortscanConfig())
}

func defaultDirscanConfig() *DirscanConfig {
	return &DirscanConfig{
		MaxConcurrency:   20,
		RequestTimeout:   30 * time.Second,
		EnableCollection: true,
		EnableFiltering:  true,
		EnableReporting:  true,
	}
}

func defaultFingerprintConfig() *FingerprintConfig {
	return &FingerprintConfig{
		RulesPath:       "configs/fingerprint/",
		MaxConcurrency:  20,
		EnableFiltering: true,
		MaxBodySize:     1 * 1024 * 1024,
		LogMatches:      true,
		ShowSnippet:     boolPtr(false),
		ShowRule:        boolPtr(false),
	}
}

func defaultPortscanConfig() *PortscanConfig {
	return &PortscanConfig{
		ResolveToIP:        true,
		EnableServiceProbe: true,
	}
}

// Result 表示整合后的扫描结果。
type Result struct {
	Summary            Summary      `json:"summary"`
	DirscanResults     []PageResult `json:"dirscan_results,omitempty"`
	FingerprintTargets []PageResult `json:"fingerprint_targets,omitempty"`
	PortscanResults    []PortResult `json:"portscan_results,omitempty"`
}

// Summary 扫描统计信息。
type Summary struct {
	Total                   int   `json:"total"`
	DirscanCount            int   `json:"dirscan_count"`
	FingerprintCount        int   `json:"fingerprint_count"`
	PortscanCount           int   `json:"portscan_count"`
	DurationMs              int64 `json:"duration_ms"`
	FingerprintRules        int   `json:"fingerprint_rules"`
	DirTargetsCount         int   `json:"dir_targets_count"`
	FingerprintTargetsCount int   `json:"fingerprint_targets_count"`
	PortTargetsCount        int   `json:"port_targets_count"`
}

// PageResult 描述单个页面的扫描信息。
type PageResult struct {
	URL           string                   `json:"url"`
	StatusCode    int                      `json:"status_code"`
	Title         string                   `json:"title"`
	ContentLength int64                    `json:"content_length"`
	DurationMs    int64                    `json:"duration_ms"`
	ContentType   string                   `json:"content_type,omitempty"`
	Fingerprints  []FingerprintMatchOutput `json:"fingerprints,omitempty"`
}

// PortResult 描述端口扫描结果
type PortResult struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// FingerprintMatchOutput 表示指纹识别的匹配结果。
type FingerprintMatchOutput struct {
	RuleName    string `json:"rule_name"`
	RuleContent string `json:"rule_content,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
}

// Run 执行扫描并返回结构化结果。
func Run(cfg *Config) (*Result, error) {
	start := time.Now()
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	if len(normalized.DirTargets) == 0 && len(normalized.FingerprintTargets) == 0 && len(normalized.PortTargets) == 0 && strings.TrimSpace(safeTargetFile(normalized.Portscan)) == "" {
		return nil, errors.New("至少需要配置一个目录扫描、指纹识别或端口扫描目标")
	}

	fpEngine, err := createFingerprintEngine(normalized.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("初始化指纹识别引擎失败: %w", err)
	}

	var dirOutputs []PageResult
	if len(normalized.DirTargets) > 0 {
		dirResult, err := runDirscan(normalized.Dirscan, normalized.DirTargets)
		if err != nil {
			return nil, fmt.Errorf("目录扫描失败: %w", err)
		}
		dirOutputs = collectDirscanResults(dirResult, fpEngine)
	}

	var fpOutputs []PageResult
	if len(normalized.FingerprintTargets) > 0 {
		processor := buildGlobalRequestProcessor(normalized)
		responses := processor.ProcessURLs(normalized.FingerprintTargets)
		if len(responses) == 0 {
			return nil, errors.New("fingerprint targets processed but no responses returned")
		}
		for idx, resp := range responses {
			if resp == nil {
				return nil, fmt.Errorf("指纹识别失败 (%s): 空响应", normalized.FingerprintTargets[idx])
			}
			fpResp := convertToFingerprintResponse(resp)
			matches := fingerprintMatches(fpEngine, fpResp)
			fpOutputs = append(fpOutputs, PageResult{
				URL:           resp.URL,
				StatusCode:    resp.StatusCode,
				Title:         resp.Title,
				ContentLength: resp.ContentLength,
				DurationMs:    resp.Duration,
				ContentType:   resp.ContentType,
				Fingerprints:  matches,
			})
		}
	}

	var portOutputs []PortResult
	if normalized.Portscan != nil {
		portResults, err := runPortscan(normalized.Portscan, normalized.PortTargets)
		if err != nil {
			return nil, fmt.Errorf("端口扫描失败: %w", err)
		}
		portOutputs = make([]PortResult, 0, len(portResults))
		for _, r := range portResults {
			portOutputs = append(portOutputs, PortResult{IP: r.IP, Port: r.Port, Service: strings.TrimSpace(r.Service)})
		}
	}

	stats := fpEngine.GetStats()
	rulesLoaded := 0
	if stats != nil {
		rulesLoaded = stats.RulesLoaded
	}

	duration := time.Since(start).Milliseconds()

	return &Result{
		Summary: Summary{
			Total:                   len(dirOutputs) + len(fpOutputs) + len(portOutputs),
			DirscanCount:            len(dirOutputs),
			FingerprintCount:        len(fpOutputs),
			PortscanCount:           len(portOutputs),
			DurationMs:              duration,
			FingerprintRules:        rulesLoaded,
			DirTargetsCount:         len(normalized.DirTargets),
			FingerprintTargetsCount: len(normalized.FingerprintTargets),
			PortTargetsCount:        len(normalized.PortTargets),
		},
		DirscanResults:     dirOutputs,
		FingerprintTargets: fpOutputs,
		PortscanResults:    portOutputs,
	}, nil
}

// RunJSON 执行扫描并返回格式化后的 JSON。
func RunJSON(cfg *Config) ([]byte, error) {
	result, err := Run(cfg)
	if err != nil {
		return nil, err
	}
	return result.PrettyJSON()
}

// JSON 返回紧凑 JSON。
func (r *Result) JSON() ([]byte, error) {
	return json.Marshal(r)
}

// PrettyJSON 返回缩进后的 JSON。
func (r *Result) PrettyJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ----------------------------------------------------------------------
// 内部实现
// ----------------------------------------------------------------------

func normalizeConfig(cfg *Config) (*Config, error) {
	base := DefaultConfig()
	if cfg == nil {
		cfg = base
	}

	normalized := &Config{
		DirTargets:         sanitizeTargets(cfg.DirTargets),
		FingerprintTargets: sanitizeTargets(cfg.FingerprintTargets),
		PortTargets:        sanitizeTargets(cfg.PortTargets),
		SkipTLSVerify:      cfg.SkipTLSVerify,
		HTTPTimeout:        cfg.HTTPTimeout,
	}

	autoSkip := true
	if cfg.AutoSkipTLSForIP != nil {
		autoSkip = *cfg.AutoSkipTLSForIP
	}
	normalized.AutoSkipTLSForIP = boolPtr(autoSkip)

	if normalized.HTTPTimeout <= 0 {
		normalized.HTTPTimeout = base.HTTPTimeout
	}

	normalized.Dirscan = cloneDirscanConfig(cfg.Dirscan)
	normalized.Fingerprint = cloneFingerprintConfig(cfg.Fingerprint)
	if cfg.Portscan != nil {
		normalized.Portscan = clonePortscanConfig(cfg.Portscan)
	} else if len(normalized.PortTargets) > 0 {
		normalized.Portscan = clonePortscanConfig(defaultPortscanConfig())
	}
	if normalized.Portscan != nil {
		normalized.Portscan.TargetFile = strings.TrimSpace(normalized.Portscan.TargetFile)
		normalized.Portscan.Ports = strings.TrimSpace(normalized.Portscan.Ports)
	}

	if autoSkip && !normalized.SkipTLSVerify && (anyURLHasIPHost(normalized.DirTargets) || anyURLHasIPHost(normalized.FingerprintTargets)) {
		normalized.SkipTLSVerify = true
	}

	return normalized, nil
}

func sanitizeTargets(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func collectDirscanResults(result *internaldirscan.ScanResult, engine *fingerprintinternal.Engine) []PageResult {
	if result == nil || result.FilterResult == nil {
		return nil
	}

	fullMap := groupResponsesByURL(result.Responses)

	outputs := make([]PageResult, 0, len(result.FilterResult.ValidPages))
	for _, page := range result.FilterResult.ValidPages {
		source := selectFullResponse(page, fullMap)
		fpResp := convertToFingerprintResponse(source)
		matches := fingerprintMatches(engine, fpResp)

		length := source.ContentLength
		if length == 0 {
			length = source.Length
		}
		if length == 0 && fpResp != nil {
			length = fpResp.ContentLength
		}

		outputs = append(outputs, PageResult{
			URL:           source.URL,
			StatusCode:    source.StatusCode,
			Title:         source.Title,
			ContentLength: length,
			DurationMs:    source.Duration,
			ContentType:   source.ContentType,
			Fingerprints:  matches,
		})
	}
	return outputs
}

func convertToFingerprintResponse(page *interfaces.HTTPResponse) *fingerprintinternal.HTTPResponse {
	if page == nil {
		return nil
	}

	body := prepareBody(page)

	headers := make(map[string][]string, len(page.ResponseHeaders))
	for key, values := range page.ResponseHeaders {
		copied := make([]string, len(values))
		copy(copied, values)
		headers[key] = copied
	}

	method := page.Method
	if method == "" {
		method = "GET"
	}

	return &fingerprintinternal.HTTPResponse{
		URL:           page.URL,
		Method:        method,
		StatusCode:    page.StatusCode,
		Headers:       headers,
		Body:          body,
		ContentType:   page.ContentType,
		ContentLength: int64(len(body)),
		Server:        page.Server,
		Title:         page.Title,
	}
}

func fingerprintMatches(engine *fingerprintinternal.Engine, resp *fingerprintinternal.HTTPResponse) []FingerprintMatchOutput {
	if engine == nil || resp == nil {
		return nil
	}

	matches := engine.AnalyzeResponseWithClientSilent(resp, nil)
	if len(matches) == 0 {
		return nil
	}

	includeSnippet := engine.IsSnippetEnabled()
	outputs := make([]FingerprintMatchOutput, 0, len(matches))
	for _, match := range matches {
		snippet := ""
		if includeSnippet {
			snippet = match.Snippet
		}
		outputs = append(outputs, FingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: match.DSLMatched,
			Snippet:     snippet,
		})
	}

	return outputs
}

func hasIPHost(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return net.ParseIP(parsed.Hostname()) != nil
}

func anyURLHasIPHost(urls []string) bool {
	for _, raw := range urls {
		if hasIPHost(raw) {
			return true
		}
	}
	return false
}

func prepareBody(page *interfaces.HTTPResponse) string {
	if page == nil {
		return ""
	}

	body := page.ResponseBody
	if body == "" {
		body = page.Body
	}
	if body == "" {
		return ""
	}

	decompressed := decompressResponseBody(body, page.ResponseHeaders)
	return fingerprintinternal.GetEncodingDetector().DetectAndConvert(decompressed, page.ContentType)
}

func decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}

	encoding := strings.ToLower(getHeaderValue(headers, "Content-Encoding"))
	if encoding == "" {
		return body
	}

	data := []byte(body)
	switch {
	case strings.Contains(encoding, "gzip"):
		if decoded, err := decompressGzip(data); err == nil {
			return decoded
		}
	case strings.Contains(encoding, "deflate"):
		if decoded, err := decompressDeflate(data); err == nil {
			return decoded
		}
	case strings.Contains(encoding, "br"):
		if decoded, err := decompressBrotli(data); err == nil {
			return decoded
		}
	}

	return body
}

func getHeaderValue(headers map[string][]string, key string) string {
	if headers == nil {
		return ""
	}
	if values, ok := headers[key]; ok && len(values) > 0 {
		return values[0]
	}
	if values, ok := headers[strings.ToLower(key)]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func decompressGzip(data []byte) (string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func decompressDeflate(data []byte) (string, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func decompressBrotli(data []byte) (string, error) {
	reader := brotli.NewReader(bytes.NewReader(data))
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func groupResponsesByURL(responses []*interfaces.HTTPResponse) map[string][]*interfaces.HTTPResponse {
	if len(responses) == 0 {
		return nil
	}

	group := make(map[string][]*interfaces.HTTPResponse, len(responses))
	for _, resp := range responses {
		if resp == nil || resp.URL == "" {
			continue
		}
		group[resp.URL] = append(group[resp.URL], resp)
	}
	return group
}

func selectFullResponse(page interfaces.HTTPResponse, fullMap map[string][]*interfaces.HTTPResponse) *interfaces.HTTPResponse {
	if fullMap != nil {
		if candidates, ok := fullMap[page.URL]; ok {
			for _, candidate := range candidates {
				if candidate == nil {
					continue
				}
				if candidate.StatusCode == page.StatusCode {
					return candidate
				}
			}
		}
	}

	copy := page
	return &copy
}

func runDirscan(cfg *DirscanConfig, targets []string) (*internaldirscan.ScanResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	config := cloneDirscanConfig(cfg)
	if config.LogLevel != "" {
		logger.SetLogLevel(config.LogLevel)
	}
	engineCfg := &internaldirscan.EngineConfig{
		MaxConcurrency:   config.MaxConcurrency,
		RequestTimeout:   config.RequestTimeout,
		EnableCollection: config.EnableCollection,
		EnableFiltering:  config.EnableFiltering,
		EnableReporting:  config.EnableReporting,
	}

	engine := internaldirscan.NewEngine(engineCfg)

	if config.Filter != nil {
		if filterCfg := dirscanFilterOptionsToInternal(config.Filter); filterCfg != nil {
			engine.SetFilterConfig(filterCfg)
		}
	}

	collector := newStaticCollector(targets)
	if collector.GetURLCount() == 0 {
		return nil, errors.New("no valid base URLs provided")
	}

	return engine.PerformScan(collector)
}

func buildGlobalRequestProcessor(cfg *Config) *requests.RequestProcessor {
	timeout := 10 * time.Second
	if cfg != nil && cfg.HTTPTimeout > 0 {
		timeout = cfg.HTTPTimeout
	}

	threads := 200
	if cfg != nil && cfg.Fingerprint != nil && cfg.Fingerprint.MaxConcurrency > 0 {
		threads = cfg.Fingerprint.MaxConcurrency
	}

	reqCfg := &requests.RequestConfig{
		Timeout:         timeout,
		MaxRetries:      2,
		MaxConcurrent:   threads,
		FollowRedirect:  true,
		RandomUserAgent: true,
	}
	processor := requests.NewRequestProcessor(reqCfg)
	processor.SetCustomHeaders(config.GetCustomHeaders())
	return processor
}

func runPortscan(cfg *PortscanConfig, targets []string) ([]portscanpkg.OpenPortResult, error) {
	if cfg == nil {
		return nil, errors.New("portscan config is required")
	}

	opts := portscanpkg.Options{
		Rate:       cfg.Rate,
		TargetFile: strings.TrimSpace(cfg.TargetFile),
	}

	if trimmed := strings.TrimSpace(cfg.Ports); trimmed != "" {
		resolved, _, err := portconfig.ResolveExpression(trimmed)
		if err != nil {
			return nil, err
		}
		opts.Ports = resolved
	}

	var resolvedTargets []string
	if len(targets) > 0 {
		if cfg.ResolveToIP {
			dedupTargets := sanitizeTargets(targets)
			ips, err := masscanrunner.ResolveTargetsToIPs(dedupTargets)
			if err != nil {
				return nil, err
			}
			resolvedTargets = ips
		} else {
			resolvedTargets = sanitizeTargets(targets)
		}
	}

	if len(resolvedTargets) == 0 && strings.TrimSpace(opts.TargetFile) == "" {
		return nil, errors.New("未指定端口扫描目标")
	}

	if opts.Ports == "" {
		opts.Ports = masscanrunner.DerivePortsFromTargets(targets)
		if opts.Ports == "" {
			opts.Ports = masscanrunner.DerivePortsFromTargets(resolvedTargets)
		}
	}

	if strings.TrimSpace(opts.Ports) == "" {
		return nil, errors.New("未指定端口表达式")
	}

	opts.Targets = resolvedTargets

	results, err := masscanrunner.Run(opts)
	if err != nil {
		return nil, err
	}

	results = deduplicatePortResults(results)

	if cfg.EnableServiceProbe && len(results) > 0 {
		serviceOpts := portservice.Options{}
		results = portservice.IdentifyServices(context.Background(), results, serviceOpts)
		results = deduplicatePortResults(results)
	}

	return results, nil
}

func createFingerprintEngine(cfg *FingerprintConfig) (*fingerprintinternal.Engine, error) {
	config := cloneFingerprintConfig(cfg)
	if config.LogLevel != "" {
		logger.SetLogLevel(config.LogLevel)
	}

	engineCfg := &fingerprintinternal.EngineConfig{
		RulesPath:       config.RulesPath,
		MaxConcurrency:  config.MaxConcurrency,
		EnableFiltering: config.EnableFiltering,
		MaxBodySize:     config.MaxBodySize,
		LogMatches:      config.LogMatches,
	}

	engine := fingerprintinternal.NewEngine(engineCfg)
	if config.RulesPath != "" {
		if err := engine.LoadRules(config.RulesPath); err != nil {
			return nil, err
		}
	}

	applyFingerprintFilters(engine, config.Filters)

	snippetEnabled := false
	if config.ShowSnippet != nil {
		snippetEnabled = *config.ShowSnippet
	}
	engine.EnableSnippet(snippetEnabled)

	ruleEnabled := false
	if config.ShowRule != nil {
		ruleEnabled = *config.ShowRule
	}
	engine.EnableRuleLogging(ruleEnabled)
	return engine, nil
}

func applyFingerprintFilters(engine *fingerprintinternal.Engine, options *FingerprintFilterOptions) {
	if engine == nil || options == nil {
		return
	}

	if options.ContentTypes != nil {
		engine.SetStaticContentTypes(options.ContentTypes)
	}
	if options.FileExtensions != nil {
		engine.SetStaticFileExtensions(options.FileExtensions)
	}
	if options.ContentTypeFilterEnabled != nil {
		engine.SetContentTypeFilterEnabled(*options.ContentTypeFilterEnabled)
	}
	if options.FileExtensionFilterEnabled != nil {
		engine.SetStaticFileFilterEnabled(*options.FileExtensionFilterEnabled)
	}
}

func dirscanFilterOptionsToInternal(options *DirscanFilterOptions) *filter.FilterConfig {
	if options == nil {
		return nil
	}

	cfg := filter.DefaultFilterConfig()
	changed := false

	if options.ValidStatusCodes != nil {
		cfg.ValidStatusCodes = append([]int(nil), options.ValidStatusCodes...)
		changed = true
	}
	if options.InvalidPageThreshold != nil {
		cfg.InvalidPageThreshold = *options.InvalidPageThreshold
		changed = true
	}
	if options.SecondaryThreshold != nil {
		cfg.SecondaryThreshold = *options.SecondaryThreshold
		changed = true
	}
	if options.EnableStatusFilter != nil {
		cfg.EnableStatusFilter = *options.EnableStatusFilter
		changed = true
	}
	if options.EnableInvalidPageFilter != nil {
		cfg.EnableInvalidPageFilter = *options.EnableInvalidPageFilter
		changed = true
	}
	if options.EnableSecondaryFilter != nil {
		cfg.EnableSecondaryFilter = *options.EnableSecondaryFilter
		changed = true
	}
	if options.EnableContentTypeFilter != nil {
		cfg.EnableContentTypeFilter = *options.EnableContentTypeFilter
		changed = true
	}
	if options.FilterTolerance != nil {
		cfg.FilterTolerance = *options.FilterTolerance
		changed = true
	}

	if !changed {
		return nil
	}
	return cfg
}

type staticCollector struct {
	urls map[string]int
}

func newStaticCollector(base []string) *staticCollector {
	urls := make(map[string]int, len(base))
	for _, raw := range base {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		urls[trimmed] = 1
	}
	return &staticCollector{urls: urls}
}

func (c *staticCollector) GetURLMap() map[string]int {
	result := make(map[string]int, len(c.urls))
	for k, v := range c.urls {
		result[k] = v
	}
	return result
}

func (c *staticCollector) GetURLCount() int {
	return len(c.urls)
}

func cloneDirscanConfig(cfg *DirscanConfig) *DirscanConfig {
	var source *DirscanConfig
	if cfg != nil {
		source = cfg
	} else {
		source = defaultDirscanConfig()
	}

	copyCfg := *source
	if source.Filter != nil {
		filterCopy := *source.Filter
		filterCopy.ValidStatusCodes = cloneIntSlice(source.Filter.ValidStatusCodes)
		filterCopy.InvalidPageThreshold = cloneIntPtr(source.Filter.InvalidPageThreshold)
		filterCopy.SecondaryThreshold = cloneIntPtr(source.Filter.SecondaryThreshold)
		filterCopy.EnableStatusFilter = cloneBoolPtr(source.Filter.EnableStatusFilter)
		filterCopy.EnableInvalidPageFilter = cloneBoolPtr(source.Filter.EnableInvalidPageFilter)
		filterCopy.EnableSecondaryFilter = cloneBoolPtr(source.Filter.EnableSecondaryFilter)
		filterCopy.EnableContentTypeFilter = cloneBoolPtr(source.Filter.EnableContentTypeFilter)
		filterCopy.FilterTolerance = cloneInt64Ptr(source.Filter.FilterTolerance)
		copyCfg.Filter = &filterCopy
	}

	return &copyCfg
}

func cloneFingerprintConfig(cfg *FingerprintConfig) *FingerprintConfig {
	var source *FingerprintConfig
	if cfg != nil {
		source = cfg
	} else {
		source = defaultFingerprintConfig()
	}

	copyCfg := *source
	copyCfg.ShowSnippet = cloneBoolPtr(source.ShowSnippet)
	copyCfg.ShowRule = cloneBoolPtr(source.ShowRule)
	if source.Filters != nil {
		filterCopy := *source.Filters
		filterCopy.ContentTypes = cloneStringSlice(source.Filters.ContentTypes)
		filterCopy.FileExtensions = cloneStringSlice(source.Filters.FileExtensions)
		filterCopy.ContentTypeFilterEnabled = cloneBoolPtr(source.Filters.ContentTypeFilterEnabled)
		filterCopy.FileExtensionFilterEnabled = cloneBoolPtr(source.Filters.FileExtensionFilterEnabled)
		copyCfg.Filters = &filterCopy
	}

	return &copyCfg
}

func clonePortscanConfig(cfg *PortscanConfig) *PortscanConfig {
	var source *PortscanConfig
	if cfg != nil {
		source = cfg
	} else {
		source = defaultPortscanConfig()
	}

	copyCfg := *source
	return &copyCfg
}

func cloneIntSlice(src []int) []int {
	if src == nil {
		return nil
	}
	dst := make([]int, len(src))
	copy(dst, src)
	return dst
}

func cloneStringSlice(src []string) []string {
	if src == nil {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}

func cloneIntPtr(src *int) *int {
	if src == nil {
		return nil
	}
	value := *src
	return &value
}

func cloneInt64Ptr(src *int64) *int64 {
	if src == nil {
		return nil
	}
	value := *src
	return &value
}

func cloneBoolPtr(src *bool) *bool {
	if src == nil {
		return nil
	}
	value := *src
	return &value
}

func boolPtr(v bool) *bool {
	return &v
}

func deduplicatePortResults(results []portscanpkg.OpenPortResult) []portscanpkg.OpenPortResult {
	if len(results) <= 1 {
		return results
	}

	seen := make(map[string]portscanpkg.OpenPortResult, len(results))
	for _, r := range results {
		ip := strings.TrimSpace(r.IP)
		if ip == "" || r.Port <= 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", ip, r.Port)
		if existing, ok := seen[key]; ok {
			if strings.TrimSpace(existing.Service) == "" && strings.TrimSpace(r.Service) != "" {
				seen[key] = r
			}
			continue
		}
		seen[key] = portscanpkg.OpenPortResult{IP: ip, Port: r.Port, Service: strings.TrimSpace(r.Service)}
	}

	deduped := make([]portscanpkg.OpenPortResult, 0, len(seen))
	for _, r := range seen {
		deduped = append(deduped, r)
	}

	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].IP == deduped[j].IP {
			return deduped[i].Port < deduped[j].Port
		}
		return deduped[i].IP < deduped[j].IP
	})

	return deduped
}

func safeTargetFile(cfg *PortscanConfig) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.TargetFile)
}
