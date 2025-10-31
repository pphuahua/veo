package masscan

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"veo/internal/core/logger"
	"veo/internal/modules/portscan"
)

// masscanJSONRecord 对应 -oJ 的单行JSON结构
type masscanJSONRecord struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"` // 解析但不使用
	} `json:"ports"`
}

// DefaultRate 端口扫描默认速率（包/秒）
const DefaultRate = 5012

const targetBatchSize = 64

// ComputeEffectiveRate 计算最终生效的扫描速率（<=0 时采用默认值）
const baseRate = 2048

func ComputeEffectiveRate(rate int) int {
	if rate <= 0 {
		return baseRate
	}
	return rate
}

// Run 执行 masscan 扫描（使用内嵌二进制落地的方式）
// 参数：
//   - opts: 端口扫描选项（端口表达式、速率、目标）
//
// 返回：
//   - []portscan.OpenPortResult: 扫描结果
//   - error: 错误信息
func Run(opts portscan.Options) ([]portscan.OpenPortResult, error) {
	// 基础权限检查（Linux/macOS 通常需要 root）
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("需要root权限或administrator权限，当前非管理员权限。请使用sudo或管理员权限运行")
		}
	}
	if strings.TrimSpace(opts.Ports) == "" {
		return nil, fmt.Errorf("未指定端口表达式")
	}
	// 默认速率：若未指定，则使用默认值
	if opts.Rate <= 0 {
		opts.Rate = DefaultRate
	}
	if len(opts.Targets) == 0 && strings.TrimSpace(opts.TargetFile) == "" {
		return nil, fmt.Errorf("未指定目标 (-u 或 -f)")
	}

	// 解析端口并分片
	// 优化：若 -p 为单一连续范围（例如 1-5000 或 5000-50000），
	// 则将该范围平均切分为 5 份以降低漏扫概率；
	// 对于 1-65535 保持既有按 10000 切片策略。
	var chunks []string
	if a, b, ok := parseSinglePortRange(opts.Ports); ok && !(a == 1 && b == 65535) {
		chunks = splitRangeIntoN(a, b, 5)
	} else {
		var err error
		chunks, err = buildPortChunks(opts.Ports, 10000)
		if err != nil {
			return nil, err
		}
	}
	if len(chunks) == 0 {
		return nil, errors.New("未解析到有效端口")
	}

	// 构建目标分组（支持多目标批量与临时文件处理）
	targetGroups, cleanupTargets, err := buildTargetGroups(opts)
	if err != nil {
		return nil, err
	}
	defer cleanupTargets()
	if len(targetGroups) == 0 {
		return nil, errors.New("未解析到有效目标")
	}

	// 落地内嵌二进制
	binPath, err := ExtractEmbeddedBinary()
	if err != nil {
		return nil, err
	}
	defer os.Remove(binPath)

	chunkWeights := make([]float64, len(chunks))
	for i, expr := range chunks {
		w := float64(countPortsInExpr(expr))
		if w <= 0 {
			w = 1
		}
		chunkWeights[i] = w
	}

	tasks := make([]scanTask, 0, len(chunks)*len(targetGroups))
	for _, group := range targetGroups {
		for ci, chunkExpr := range chunks {
			weight := chunkWeights[ci] * float64(group.count)
			if weight <= 0 {
				weight = 1
			}
			tasks = append(tasks, scanTask{portExpr: chunkExpr, weight: weight, group: group})
		}
	}
	if len(tasks) == 0 {
		return nil, errors.New("未生成扫描任务")
	}

	progress := make([]float64, len(tasks))
	var progressMu sync.Mutex
	var logMu sync.Mutex
	lastLog := time.Now().Add(-2 * time.Second)

	type chunkResult struct {
		data []portscan.OpenPortResult
		err  error
	}

	effectiveRate := opts.Rate
	if effectiveRate <= 0 {
		effectiveRate = baseRate
	}
	if effectiveRate > baseRate {
		effectiveRate = baseRate
	}

	concurrency := 2
	if len(tasks) < concurrency {
		concurrency = len(tasks)
	}

	ratePool := make(chan int, concurrency)
	for i := 0; i < concurrency; i++ {
		ratePool <- effectiveRate
	}

	sumProgress := func() float64 {
		weighted := 0.0
		totalWeight := 0.0
		for i, v := range progress {
			w := tasks[i].weight
			weighted += w * v
			totalWeight += w
		}
		if totalWeight <= 0 {
			return 0
		}
		return weighted / totalWeight
	}

	processTask := func(taskIdx int, task scanTask, rate int) ([]portscan.OpenPortResult, error) {
		outFile, ofErr := os.CreateTemp("", "veo-masscan-out-*.json")
		if ofErr != nil {
			return nil, fmt.Errorf("创建临时输出文件失败: %v", ofErr)
		}
		outPath := outFile.Name()
		outFile.Close()
		defer os.Remove(outPath)

		argsList := []string{"-p", task.portExpr, "--rate", strconv.Itoa(rate)}
		if task.group.filePath != "" {
			argsList = append(argsList, "-iL", task.group.filePath)
		} else if task.group.targetArg != "" {
			argsList = append(argsList, task.group.targetArg)
		} else {
			return nil, fmt.Errorf("未找到有效目标参数")
		}
		argsList = append(argsList, "-oJ", outPath, "--wait=0")

		logger.Debugf("执行: %s %s", binPath, strings.Join(argsList, " "))
		cmd := exec.Command(binPath, argsList...)

		stderr, err := cmd.StderrPipe()
		if err != nil {
			return nil, fmt.Errorf("创建stderr管道失败: %v", err)
		}
		stdout, _ := cmd.StdoutPipe()

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("启动masscan失败: %v", err)
		}

		doneCh := make(chan struct{})
		go func(taskIdx int) {
			defer close(doneCh)
			scanner := bufio.NewScanner(stderr)
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 1024*1024)
			for scanner.Scan() {
				line := scanner.Text()
				if pct, ok := parseMasscanProgress(line); ok {
					progressMu.Lock()
					progress[taskIdx] = pct
					totalPercent := sumProgress()
					progressMu.Unlock()

					logMu.Lock()
					if time.Since(lastLog) >= 900*time.Millisecond {
						fmt.Printf("\rPortScan Working %.1f%%\r", totalPercent)
						lastLog = time.Now()
					}
					logMu.Unlock()
				} else {
					logger.Debugf("masscan: %s", strings.TrimSpace(line))
				}
			}
		}(taskIdx)

		go func() {
			s := bufio.NewScanner(stdout)
			for s.Scan() {
				logger.Debugf("masscan out: %s", strings.TrimSpace(s.Text()))
			}
		}()

		if errRun := cmd.Wait(); errRun != nil {
			<-doneCh
			return nil, fmt.Errorf("执行失败: %v", errRun)
		}
		<-doneCh

		progressMu.Lock()
		progress[taskIdx] = 100.0
		totalPercent := sumProgress()
		progressMu.Unlock()

		logMu.Lock()
		fmt.Printf("\rPortScan Working %.1f%%\r", totalPercent)
		lastLog = time.Now()
		logMu.Unlock()

		file, rfErr := os.Open(outPath)
		if rfErr != nil {
			return nil, fmt.Errorf("读取输出失败: %v", rfErr)
		}
		defer file.Close()

		var chunkResults []portscan.OpenPortResult
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var rec masscanJSONRecord
			if json.Unmarshal([]byte(line), &rec) == nil {
				for _, p := range rec.Ports {
					chunkResults = append(chunkResults, portscan.OpenPortResult{IP: rec.IP, Port: p.Port})
				}
			}
		}

		return chunkResults, nil
	}

	var results []portscan.OpenPortResult
	var firstErr error
	jobCh := make(chan int, len(tasks))
	var wg sync.WaitGroup
	var resMu sync.Mutex
	var errMu sync.Mutex

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobCh {
				rate := <-ratePool
				data, err := processTask(idx, tasks[idx], rate)
				ratePool <- rate

				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					continue
				}

				if len(data) > 0 {
					resMu.Lock()
					results = append(results, data...)
					resMu.Unlock()
				}
			}
		}()
	}

	for idx := range tasks {
		jobCh <- idx
	}
	close(jobCh)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}

	return results, nil
}

// parseMasscanProgress 解析masscan输出中的百分比进度
// 示例：rate:  10.00-kpps,  1.13% done, 0:02:58 to go, found=0
func parseMasscanProgress(line string) (percent float64, ok bool) {
	rePct := regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)%\s*done`)
	if m := rePct.FindStringSubmatch(line); len(m) == 2 {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

// parseSinglePortRange 尝试解析单一连续端口范围表达式，如 "a-b"
// 返回：起始端口a，结束端口b，是否为单一范围
func parseSinglePortRange(expr string) (int, int, bool) {
	e := strings.TrimSpace(expr)
	if e == "" || strings.Contains(e, ",") {
		return 0, 0, false
	}
	if !strings.Contains(e, "-") {
		// 非范围，仅单端口
		v, err := strconv.Atoi(e)
		if err != nil || v < 1 || v > 65535 {
			return 0, 0, false
		}
		return v, v, true
	}
	parts := strings.SplitN(e, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || a < 1 || b < a || b > 65535 {
		return 0, 0, false
	}
	return a, b, true
}

func countPortsInExpr(expr string) int {
	parts := strings.Split(expr, ",")
	total := 0
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			seg := strings.SplitN(p, "-", 2)
			if len(seg) != 2 {
				continue
			}
			a, err1 := strconv.Atoi(strings.TrimSpace(seg[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(seg[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			if b < a {
				a, b = b, a
			}
			total += b - a + 1
		} else {
			if _, err := strconv.Atoi(p); err == nil {
				total++
			}
		}
	}
	if total <= 0 {
		return 0
	}
	return total
}

type scanTask struct {
	portExpr string
	weight   float64
	group    *targetGroup
}

type targetGroup struct {
	count     int
	targetArg string
	filePath  string
}

func buildTargetGroups(opts portscan.Options) ([]*targetGroup, func(), error) {
	const batchSize = 64
	cleanup := func() {}

	if strings.TrimSpace(opts.TargetFile) != "" {
		filePath := strings.TrimSpace(opts.TargetFile)
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, cleanup, fmt.Errorf("读取目标文件失败: %v", err)
		}
		lines := filterLines(strings.Split(string(content), "\n"))
		if len(lines) == 0 {
			return nil, cleanup, fmt.Errorf("目标文件为空")
		}
		if len(lines) <= batchSize {
			return []*targetGroup{{count: len(lines), filePath: filePath}}, cleanup, nil
		}
		var tempFiles []string
		groups := make([]*targetGroup, 0)
		for i := 0; i < len(lines); i += batchSize {
			end := i + batchSize
			if end > len(lines) {
				end = len(lines)
			}
			fp, err := writeTargetsToTemp(lines[i:end])
			if err != nil {
				for _, f := range tempFiles {
					_ = os.Remove(f)
				}
				return nil, cleanup, err
			}
			tempFiles = append(tempFiles, fp)
			groups = append(groups, &targetGroup{count: end - i, filePath: fp})
		}
		cleanup = func() {
			for _, f := range tempFiles {
				_ = os.Remove(f)
			}
		}
		return groups, cleanup, nil
	}

	trimmed := filterLines(opts.Targets)
	if len(trimmed) == 0 {
		return nil, cleanup, fmt.Errorf("未指定有效目标")
	}

	var (
		tempFiles []string
		groups    []*targetGroup
	)

	emitBatch := func(batch []string) error {
		if len(batch) == 0 {
			return nil
		}
		if len(batch) == 1 {
			groups = append(groups, &targetGroup{count: 1, targetArg: batch[0]})
			return nil
		}
		fp, err := writeTargetsToTemp(batch)
		if err != nil {
			return err
		}
		tempFiles = append(tempFiles, fp)
		groups = append(groups, &targetGroup{count: len(batch), filePath: fp})
		return nil
	}

	for _, raw := range trimmed {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		handled, err := expandTargetExpression(raw, emitBatch)
		if err != nil {
			for _, f := range tempFiles {
				_ = os.Remove(f)
			}
			return nil, cleanup, err
		}
		if handled {
			continue
		}

		// 默认按单目标处理
		if err := emitBatch([]string{raw}); err != nil {
			for _, f := range tempFiles {
				_ = os.Remove(f)
			}
			return nil, cleanup, err
		}
	}

	if len(groups) == 0 {
		return nil, cleanup, fmt.Errorf("未生成有效目标分组")
	}

	cleanup = func() {
		for _, f := range tempFiles {
			_ = os.Remove(f)
		}
	}
	return groups, cleanup, nil
}

func expandTargetExpression(raw string, emit func([]string) error) (bool, error) {
	if strings.Contains(raw, "/") {
		if _, _, err := net.ParseCIDR(raw); err == nil {
			return true, expandCIDRTarget(raw, emit)
		}
	}
	if strings.Contains(raw, "-") {
		return expandIPRangeExpression(raw, emit)
	}
	return false, nil
}

func expandCIDRTarget(expr string, emit func([]string) error) error {
	ip, ipNet, err := net.ParseCIDR(expr)
	if err != nil {
		return err
	}
	start := ip.To4()
	if start == nil {
		return fmt.Errorf("暂不支持IPv6 CIDR: %s", expr)
	}
	network := start.Mask(ipNet.Mask)
	current := make(net.IP, len(network))
	copy(current, network)

	var (
		batch []string
		total int
	)

	for ipNet.Contains(current) {
		batch = append(batch, current.String())
		total++
		if len(batch) >= targetBatchSize {
			if err := emit(append([]string(nil), batch...)); err != nil {
				return err
			}
			batch = batch[:0]
		}
		if !incIPv4(current) {
			break
		}
	}

	if len(batch) > 0 {
		if err := emit(append([]string(nil), batch...)); err != nil {
			return err
		}
	}

	return nil
}

func expandIPRangeExpression(raw string, emit func([]string) error) (bool, error) {
	parts := strings.SplitN(raw, "-", 2)
	if len(parts) != 2 {
		return false, nil
	}
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	if left == "" || right == "" {
		return false, nil
	}

	if net.ParseIP(left) != nil && net.ParseIP(right) != nil {
		return true, expandFullIPRange(left, right, emit)
	}

	if idx := strings.LastIndex(left, "."); idx != -1 {
		prefix := left[:idx+1]
		startOct := strings.TrimSpace(left[idx+1:])
		endOct := strings.TrimSpace(right)
		sv, errStart := strconv.Atoi(startOct)
		ev, errEnd := strconv.Atoi(endOct)
		if errStart == nil && errEnd == nil && sv >= 0 && sv <= 255 && ev >= 0 && ev <= 255 {
			if net.ParseIP(prefix+"0") != nil {
				return true, expandLastOctetRange(prefix, sv, ev, emit)
			}
		}
	}

	return false, nil
}

func expandFullIPRange(startStr, endStr string, emit func([]string) error) error {
	startIP := net.ParseIP(startStr).To4()
	endIP := net.ParseIP(endStr).To4()
	if startIP == nil || endIP == nil {
		return fmt.Errorf("暂不支持IPv6地址范围: %s-%s", startStr, endStr)
	}
	start := ipv4ToUint32(startIP)
	end := ipv4ToUint32(endIP)
	if start > end {
		start, end = end, start
	}
	return emitIPUintRange(start, end, emit)
}

func expandLastOctetRange(prefix string, start, end int, emit func([]string) error) error {
	if start > end {
		start, end = end, start
	}
	if start < 0 {
		start = 0
	}
	if end > 255 {
		end = 255
	}
	var (
		batch []string
		total int
	)
	for oct := start; oct <= end; oct++ {
		batch = append(batch, fmt.Sprintf("%s%d", prefix, oct))
		total++
		if len(batch) >= targetBatchSize {
			if err := emit(append([]string(nil), batch...)); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		if err := emit(append([]string(nil), batch...)); err != nil {
			return err
		}
	}
	return nil
}

func emitIPUintRange(start, end uint32, emit func([]string) error) error {
	var (
		batch []string
		total int
	)
	for cur := start; ; cur++ {
		batch = append(batch, uint32ToIPv4String(cur))
		total++
		if len(batch) >= targetBatchSize {
			if err := emit(append([]string(nil), batch...)); err != nil {
				return err
			}
			batch = batch[:0]
		}
		if cur == end {
			break
		}
	}
	if len(batch) > 0 {
		if err := emit(append([]string(nil), batch...)); err != nil {
			return err
		}
	}
	return nil
}

func incIPv4(ip net.IP) bool {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return true
		}
	}
	return false
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIPv4String(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func filterLines(lines []string) []string {
	res := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			res = append(res, line)
		}
	}
	return res
}

func writeTargetsToTemp(targets []string) (string, error) {
	f, err := os.CreateTemp("", "veo-masscan-targets-*.txt")
	if err != nil {
		return "", fmt.Errorf("创建临时目标文件失败: %v", err)
	}
	writer := bufio.NewWriter(f)
	for _, t := range targets {
		_, _ = writer.WriteString(t + "\n")
	}
	_ = writer.Flush()
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("关闭临时文件失败: %v", err)
	}
	logger.Debugf("端口扫描：使用临时目标文件 %s", path)
	return path, nil
}

// splitRangeIntoN 将闭区间 [a,b] 平均切为 n 段，返回范围表达式切片
func splitRangeIntoN(a, b, n int) []string {
	if n <= 1 || a > b {
		return []string{fmt.Sprintf("%d-%d", a, b)}
	}
	total := b - a + 1
	base := total / n
	rem := total % n
	res := make([]string, 0, n)
	cur := a
	for i := 0; i < n; i++ {
		size := base
		if rem > 0 {
			size++
			rem--
		}
		if size <= 0 {
			continue
		}
		start := cur
		end := cur + size - 1
		if start == end {
			res = append(res, strconv.Itoa(start))
		} else {
			res = append(res, fmt.Sprintf("%d-%d", start, end))
		}
		cur = end + 1
		if cur > b {
			break
		}
	}
	return res
}

// ResolveTargetsToIPs 将输入的目标（URL/域名/IP）解析为IP列表
// 参数：
//   - targets: 原始目标列表，可以是 URL（含协议/端口/路径）、域名、IP（可带端口）
//
// 返回：
//   - []string: 解析得到的去重IP列表
//   - error: 解析失败时返回错误
func ResolveTargetsToIPs(targets []string) ([]string, error) {
	uniq := make(map[string]struct{})
	add := func(ip string) {
		if ip == "" {
			return
		}
		uniq[ip] = struct{}{}
	}
	for _, t := range targets {
		raw := strings.TrimSpace(t)
		if raw == "" {
			continue
		}

		// 直接支持 CIDR 表达式（例如 101.35.191.82/24、10.0.0.1/8）
		if _, _, cidrErr := net.ParseCIDR(raw); cidrErr == nil {
			add(raw)
			continue
		}

		// 直接支持 IP 范围表达式：
		// 1) 完整起止IP：10.0.0.1-10.2.0.0
		// 2) 末段范围：10.0.0.1-254
		if strings.Contains(raw, "-") {
			parts := strings.SplitN(raw, "-", 2)
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			// 情况1：两端均为完整IP
			if net.ParseIP(left) != nil && net.ParseIP(right) != nil {
				add(raw)
				continue
			}

			// 情况2：末段范围 A.B.C.X-Y
			// 验证前缀 A.B.C. 合法，且 X、Y 在 0..255
			if idx := strings.LastIndex(left, "."); idx != -1 {
				prefix := left[:idx+1] // 含结尾的点
				startStr := left[idx+1:]
				endStr := right
				if _, errA := strconv.Atoi(startStr); errA == nil {
					if _, errB := strconv.Atoi(endStr); errB == nil {
						// 验证前缀是合法的前三段：prefix+"0" 应为合法IP
						if net.ParseIP(prefix+"0") != nil {
							add(raw)
							continue
						}
					}
				}
			}
		}

		// 优先按URL解析
		if u, err := neturl.Parse(raw); err == nil && u.Host != "" {
			host := u.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if ip := net.ParseIP(host); ip != nil {
				add(ip.String())
				continue
			}
			// 解析域名 -> IP 列表（优先IPv4）
			ips, err := net.LookupIP(host)
			if err == nil {
				for _, ip := range ips {
					if ip.To4() != nil {
						add(ip.String())
					}
				}
			}
			continue
		}

		// 尝试 host:port
		if h, _, err := net.SplitHostPort(raw); err == nil {
			raw = h
		}
		if ip := net.ParseIP(raw); ip != nil {
			add(ip.String())
			continue
		}
		// 当作域名
		if raw != "" {
			ips, err := net.LookupIP(raw)
			if err == nil {
				for _, ip := range ips {
					if ip.To4() != nil {
						add(ip.String())
					}
				}
			}
		}
	}
	res := make([]string, 0, len(uniq))
	for ip := range uniq {
		res = append(res, ip)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("未能从目标中解析到有效IP")
	}
	return res, nil
}

// DerivePortsFromTargets 从 URL 目标中提取端口（若存在），或按协议给出默认端口
// 参数：
//   - targets: 原始目标列表
//
// 返回：
//   - string: 端口表达式（逗号分隔的端口列表，如 "80,443,8080"），若未能推导返回空
func DerivePortsFromTargets(targets []string) string {
	seen := make(map[int]struct{})
	add := func(p int) {
		if p > 0 && p <= 65535 {
			seen[p] = struct{}{}
		}
	}

	for _, t := range targets {
		raw := strings.TrimSpace(t)
		if raw == "" {
			continue
		}
		if u, err := neturl.Parse(raw); err == nil && u.Host != "" {
			// 端口
			if _, portStr, err := net.SplitHostPort(u.Host); err == nil {
				if v, err := strconv.Atoi(portStr); err == nil {
					add(v)
				}
				continue
			}
			// 协议默认端口
			if strings.EqualFold(u.Scheme, "https") {
				add(443)
			} else if strings.EqualFold(u.Scheme, "http") {
				add(80)
			}
			continue
		}
		// 非URL，不推导
	}
	if len(seen) == 0 {
		return ""
	}
	// 收集端口并排序
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	var sb strings.Builder
	for i, p := range ports {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(p))
	}
	return sb.String()
}

// validatePortExpression 粗略校验端口表达式
func validatePortExpression(expr string) error {
	parts := strings.Split(expr, ",")
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			seg := strings.SplitN(p, "-", 2)
			if len(seg) != 2 {
				return fmt.Errorf("范围格式有误: %s", p)
			}
			a, err1 := strconv.Atoi(strings.TrimSpace(seg[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(seg[1]))
			if err1 != nil || err2 != nil || a < 1 || b < a || b > 65535 {
				return fmt.Errorf("范围非法: %s", p)
			}
		} else {
			v, err := strconv.Atoi(p)
			if err != nil || v < 1 || v > 65535 {
				return fmt.Errorf("端口非法: %s", p)
			}
		}
	}
	return nil
}

// buildPortChunks 将表达式切片为不超过 chunkSize 的子范围
func buildPortChunks(expr string, chunkSize int) ([]string, error) {
	if err := validatePortExpression(expr); err != nil {
		return nil, err
	}
	// 展开成有序去重端口列表
	portSet := make(map[int]struct{})
	addRange := func(a, b int) {
		if a < 1 {
			a = 1
		}
		if b > 65535 {
			b = 65535
		}
		for i := a; i <= b; i++ {
			portSet[i] = struct{}{}
		}
	}
	parts := strings.Split(expr, ",")
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			seg := strings.SplitN(p, "-", 2)
			a, _ := strconv.Atoi(strings.TrimSpace(seg[0]))
			b, _ := strconv.Atoi(strings.TrimSpace(seg[1]))
			addRange(a, b)
		} else {
			v, _ := strconv.Atoi(p)
			addRange(v, v)
		}
	}
	if len(portSet) == 0 {
		return nil, nil
	}
	// 转为有序切片（简单排序）
	ports := make([]int, 0, len(portSet))
	for v := range portSet {
		ports = append(ports, v)
	}
	sort.Ints(ports)
	// 分块并压缩为范围字符串
	var chunks []string
	for i := 0; i < len(ports); i += chunkSize {
		end := i + chunkSize
		if end > len(ports) {
			end = len(ports)
		}
		chunk := ports[i:end]
		ranges := compressToRanges(chunk)
		chunks = append(chunks, strings.Join(ranges, ","))
	}
	return chunks, nil
}

func compressToRanges(ports []int) []string {
	if len(ports) == 0 {
		return nil
	}
	var res []string
	start := ports[0]
	prev := ports[0]
	emit := func(a, b int) {
		if a == b {
			res = append(res, strconv.Itoa(a))
		} else {
			res = append(res, fmt.Sprintf("%d-%d", a, b))
		}
	}
	for i := 1; i < len(ports); i++ {
		if ports[i] == prev+1 {
			prev = ports[i]
			continue
		}
		emit(start, prev)
		start = ports[i]
		prev = ports[i]
	}
	emit(start, prev)
	return res
}
