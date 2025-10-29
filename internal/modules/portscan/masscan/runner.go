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
	"runtime"
	"strconv"
	"strings"
	"veo/internal/core/logger"
	"veo/internal/modules/portscan"
)

// masscanJSONRecord 对应 -oJ 的单行JSON结构
type masscanJSONRecord struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	} `json:"ports"`
}

// Run 执行 masscan 扫描（使用内嵌二进制落地的方式）
// 参数：
//   - opts: 端口扫描选项（端口表达式、速率、目标）
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
	// 默认速率：若未指定，则使用10000
	if opts.Rate <= 0 {
		opts.Rate = 10000
	}
	if len(opts.Targets) == 0 && strings.TrimSpace(opts.TargetFile) == "" {
		return nil, fmt.Errorf("未指定目标 (-u 或 -f)")
	}

	// 解析端口并分片
	chunks, err := buildPortChunks(opts.Ports, 10000)
	if err != nil {
		return nil, err
	}
	if len(chunks) == 0 {
		return nil, errors.New("未解析到有效端口")
	}

	// 目标参数构造：
	// 1) 若用户提供 -f 文件，使用 -iL <file>
	// 2) 若通过 -u 指定且仅单个目标，直接追加到命令行（无需 -iL）
	// 3) 若通过 -u 指定多个目标，则创建临时目标文件并使用 -iL
	var targetArgs []string
	targetsFile := strings.TrimSpace(opts.TargetFile)
	if targetsFile != "" {
		targetArgs = []string{"-iL", targetsFile}
	} else if len(opts.Targets) == 1 {
		target := strings.TrimSpace(opts.Targets[0])
		if target == "" {
			return nil, fmt.Errorf("目标无效")
		}
		targetArgs = []string{target}
	} else {
		// 多目标：创建临时目标文件
		f, tfErr := os.CreateTemp("", "veo-masscan-targets-*.txt")
		if tfErr != nil {
			return nil, fmt.Errorf("创建临时目标文件失败: %v", tfErr)
		}
		defer os.Remove(f.Name())
		w := bufio.NewWriter(f)
		for _, t := range opts.Targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			_, _ = w.WriteString(t + "\n")
		}
		_ = w.Flush()
		_ = f.Close()
		targetArgs = []string{"-iL", f.Name()}
		logger.Debugf("端口扫描：使用临时目标文件 %s", f.Name())
	}

	// 落地内嵌二进制
	binPath, err := ExtractEmbeddedBinary()
	if err != nil {
		return nil, err
	}
	defer os.Remove(binPath)

	var results []portscan.OpenPortResult
	for _, c := range chunks {
		// 每片使用独立输出文件
		outFile, ofErr := os.CreateTemp("", "veo-masscan-out-*.json")
		if ofErr != nil {
			return nil, fmt.Errorf("创建临时输出文件失败: %v", ofErr)
		}
		outPath := outFile.Name()
		outFile.Close()

		argsList := []string{"-p", c, "--rate", strconv.Itoa(opts.Rate)}
		argsList = append(argsList, targetArgs...)
		argsList = append(argsList, "-oJ", outPath, "--wait=0")

		logger.Debugf("执行: %s %s", binPath, strings.Join(argsList, " "))
		cmd := exec.Command(binPath, argsList...)
		if out, errRun := cmd.CombinedOutput(); errRun != nil {
			// 将masscan输出附加到错误中，便于用户定位权限/参数问题
			return nil, fmt.Errorf("执行失败: %v\n输出: %s", errRun, strings.TrimSpace(string(out)))
		}

		// 解析 JSON 行
		file, rfErr := os.Open(outPath)
		if rfErr != nil {
			_ = os.Remove(outPath)
			return nil, fmt.Errorf("读取输出失败: %v", rfErr)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var rec masscanJSONRecord
			if json.Unmarshal([]byte(line), &rec) == nil {
				for _, p := range rec.Ports {
					results = append(results, portscan.OpenPortResult{IP: rec.IP, Port: p.Port, Proto: p.Proto})
				}
			}
		}
		_ = file.Close()
		_ = os.Remove(outPath)
	}

	// 简单规范化输出：Windows 下不显示 /tcp 后缀也可
	if runtime.GOOS == "windows" {
		for i := range results {
			if strings.EqualFold(results[i].Proto, "tcp") {
				// no-op，保持
			}
		}
	}

	return results, nil
}

// ResolveTargetsToIPs 将输入的目标（URL/域名/IP）解析为IP列表
// 参数：
//   - targets: 原始目标列表，可以是 URL（含协议/端口/路径）、域名、IP（可带端口）
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
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[j] < ports[i] {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}
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
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[j] < ports[i] {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}
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
