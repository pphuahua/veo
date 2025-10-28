package main

import (
	"fmt"
	"log"
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

	autoSkip := true

	cfg := &scan.Config{
		DirTargets:         []string{"http://223.99.206.205:8201/gmvcs/uap/"},
		FingerprintTargets: []string{"http://223.99.206.205:8201/gmvcs/uap/"},
		SkipTLSVerify:      false,
		AutoSkipTLSForIP:   &autoSkip,
		HTTPTimeout:        20 * time.Second,
		Dirscan:            dirCfg,
		Fingerprint:        fpCfg,
	}

	resultJSON, err := scan.RunJSON(cfg)
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	fmt.Println(string(resultJSON))
}
