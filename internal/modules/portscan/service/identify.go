package service

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"veo/internal/core/logger"
	"veo/internal/core/useragent"
	portscanpkg "veo/internal/modules/portscan"
	localfingerprint "veo/internal/modules/portscan/service/fingerprint"
)

// Options 控制服务识别的并发与超时
type Options struct {
	Timeout     time.Duration
	Concurrency int
}

// Identify 使用 go-portScan 指纹库识别端口服务
// 传入结果会在原切片上进行更新，并返回同一引用
func Identify(ctx context.Context, results []portscanpkg.OpenPortResult, opts Options) []portscanpkg.OpenPortResult {
	if len(results) == 0 {
		return results
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = runtime.NumCPU()
		if opts.Concurrency <= 0 {
			opts.Concurrency = 1
		}
	}

	type task struct {
		index int
		ip    net.IP
		port  int
	}

	jobs := make(chan task)
	var wg sync.WaitGroup
	var once sync.Once

	cache := sync.Map{}

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case job, ok := <-jobs:
				if !ok {
					return
				}
				cacheKey := job.ip.String() + ":" + strconv.Itoa(job.port)
				if v, ok := cache.Load(cacheKey); ok {
					if svc, ok := v.(string); ok {
						results[job.index].Service = svc
					}
					continue
				}

				serviceName := detectService(job.ip, job.port, opts.Timeout)
				if serviceName == "" {
					if hint, ok := defaultPortHints[job.port]; ok {
						serviceName = hint
					}
				}

				if serviceName != "" {
					results[job.index].Service = serviceName
				}
				cache.Store(cacheKey, serviceName)
			}
		}
	}

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}

enqueueLoop:
	for idx, r := range results {
		select {
		case <-ctx.Done():
			break enqueueLoop
		default:
		}

		ip := net.ParseIP(strings.TrimSpace(r.IP))
		if ip == nil {
			if r.Service == "" {
				if hint, ok := defaultPortHints[r.Port]; ok {
					results[idx].Service = hint
				}
			}
			continue
		}

		// 如果已有服务识别结果，则跳过
		if r.Service != "" {
			cache.Store(ip.String()+":"+strconv.Itoa(r.Port), r.Service)
			continue
		}

		func() {
			defer func() {
				if rec := recover(); rec != nil {
					once.Do(func() {
						logger.Errorf("服务识别出现异常: %v", rec)
					})
				}
			}()
			select {
			case <-ctx.Done():
			case jobs <- task{index: idx, ip: ip, port: r.Port}:
			}
		}()
	}

	close(jobs)
	wg.Wait()

	return results
}

func detectService(ip net.IP, port int, timeout time.Duration) string {
	if ip == nil || port <= 0 || port > 65535 {
		return ""
	}
	serviceName, _, dialErr := localfingerprint.PortIdentify("tcp", ip, uint16(port), timeout)
	if dialErr {
		logger.Debugf("服务识别超时/连接失败: %s:%d", ip.String(), port)
		return ""
	}
	serviceName = strings.TrimSpace(serviceName)
	if serviceName != "" && strings.EqualFold(serviceName, "unknown") {
		serviceName = ""
	}
	if serviceName != "" {
		logger.Debugf("服务识别成功: %s:%d => %s", ip.String(), port, serviceName)
		return serviceName
	}

	if fallbackHTTP(ip.String(), port, timeout) {
		logger.Debugf("HTTP 回退识别成功: %s:%d", ip.String(), port)
		return "http"
	}
	return ""
}

func fallbackHTTP(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}

	requestHost := host
	if port != 80 && port != 0 {
		requestHost = fmt.Sprintf("%s:%d", host, port)
	}
	ua := useragent.Pick()
	if ua == "" {
		ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
	}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", requestHost, ua)
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}

	reader := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	n, err := reader.Read(buf)
	if n <= 0 || err != nil {
		return false
	}
	data := string(buf[:n])
	logger.Debugf("HTTP fallback raw response %s:%d => %q", host, port, data)
	dataUpper := strings.ToUpper(data)
	return strings.Contains(dataUpper, "HTTP/")
}

var defaultPortHints = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	135:   "rpc",
	139:   "netbios",
	143:   "imap",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	587:   "submission",
	993:   "imaps",
	995:   "pop3s",
	1433:  "sqlserver",
	1521:  "oracle",
	1723:  "pptp",
	1883:  "mqtt",
	2049:  "nfs",
	2082:  "cpanel",
	2181:  "zookeeper",
	27017: "mongodb",
	3000:  "grafana",
	3306:  "mysql",
	3389:  "rdp",
	5000:  "upnp",
	5432:  "postgres",
	5900:  "vnc",
	6379:  "redis",
	7001:  "weblogic",
	8080:  "http-alt",
	8081:  "http-alt",
	8443:  "https-alt",
	9000:  "fcgi",
	9200:  "elasticsearch",
	10000: "webmin",
}
