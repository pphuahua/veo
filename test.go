package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"veo/pkg/sdk/scan"
)

func main() {
	dirCfg := scan.DefaultDirscanConfig()
	dirCfg.MaxConcurrency = 150
	dirCfg.RequestTimeout = 8 * time.Second
	dirCfg.EnableReporting = false
	dirCfg.Filter = &scan.DirscanFilterOptions{
		ValidStatusCodes:     []int{200, 301, 302, 401, 403, 405, 500},
		InvalidPageThreshold: scan.Int(3),
		SecondaryThreshold:   scan.Int(1),
		FilterTolerance:      scan.Int64(50),
	}

	fpCfg := scan.DefaultFingerprintConfig()
	fpCfg.MaxConcurrency = 150
	fpCfg.MaxBodySize = 2 * 1024 * 1024
	fpCfg.LogLevel = "debug"

	portCfg := scan.DefaultPortscanConfig()
	portCfg.Ports = "80,443,8080-8082"
	portCfg.Rate = 1500

	autoSkip := true

	cfg := &scan.Config{
		DirTargets:         []string{"http://baidu.com"},
		FingerprintTargets: []string{"http://baidu.com"},
		PortTargets:        []string{"http://baidu.com"},
		SkipTLSVerify:      false,
		AutoSkipTLSForIP:   &autoSkip,
		HTTPTimeout:        20 * time.Second,
		Dirscan:            dirCfg,
		Fingerprint:        fpCfg,
		Portscan:           portCfg,
	}

	resultJSON, err := scan.RunJSON(cfg)
	if err != nil && strings.Contains(err.Error(), "权限") {
		log.Printf("端口扫描需要管理员权限，跳过端口扫描: %v", err)
		cfg.Portscan = nil
		cfg.PortTargets = nil
		resultJSON, err = scan.RunJSON(cfg)
	}
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	fmt.Println(string(resultJSON))
}
