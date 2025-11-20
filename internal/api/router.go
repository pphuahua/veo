package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	portscanpkg "veo/pkg/portscan"
)

// SetupRouter 初始化Gin路由
func SetupRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), gin.Logger(), corsMiddleware)

	v1 := r.Group("/api/v1")
	{
		v1.OPTIONS("/*path", func(c *gin.Context) {
			c.AbortWithStatus(http.StatusNoContent)
		})
		v1.POST("/dirscan", dirscanHandler)
		v1.POST("/fingerprint", fingerprintHandler)
		v1.POST("/portscan", portscanHandler)
		v1.POST("/scan", combinedHandler)
	}

	return r
}

func dirscanHandler(c *gin.Context) {
	var req DirscanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, err)
		return
	}
	result, err := RunDirscanService(&req)
	if err != nil {
		sendError(c, http.StatusInternalServerError, err)
		return
	}
	sendSuccess(c, result)
}

func fingerprintHandler(c *gin.Context) {
	var req FingerprintRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, err)
		return
	}
	result, err := RunFingerprintService(&req)
	if err != nil {
		sendError(c, http.StatusInternalServerError, err)
		return
	}
	sendSuccess(c, result)
}

func portscanHandler(c *gin.Context) {
	var req PortscanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, err)
		return
	}
	result, err := RunPortscanService(&req)
	if err != nil {
		sendError(c, http.StatusInternalServerError, err)
		return
	}
	sendSuccess(c, result)
}

func combinedHandler(c *gin.Context) {
	var req CombinedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, err)
		return
	}

	targets := sanitizeTargets(req.Targets)
	if len(targets) == 0 {
		sendError(c, http.StatusBadRequest, errors.New("targets required"))
		return
	}

	response := make(map[string]interface{})

	hasExplicitModules := req.DirscanConfig != nil || req.FingerprintConfig != nil || req.PortscanConfig != nil
	runDirscan := req.DirscanConfig != nil || !hasExplicitModules
	runFingerprint := req.FingerprintConfig != nil || !hasExplicitModules
	runPortscan := req.PortscanConfig != nil

	if runPortscan {
		psReq := PortscanRequest{
			ScanOptionOverrides: req.ScanOptionOverrides,
			Targets:             append([]string(nil), targets...),
			Config:              req.PortscanConfig,
		}
		psRes, err := RunPortscanService(&psReq)
		if err != nil {
			sendError(c, http.StatusInternalServerError, err)
			return
		}
		response["portscan"] = psRes

		httpTargets := deriveHTTPRescanTargets(psRes)
		if !runFingerprint && !runDirscan {
			sendSuccess(c, response)
			return
		}
		if len(httpTargets) == 0 {
			if runFingerprint {
				response["fingerprint"] = []FingerprintPage{}
			}
			if runDirscan {
				response["dirscan"] = []DirscanPage{}
			}
			sendSuccess(c, response)
			return
		}

		if runFingerprint {
			fpReq := FingerprintRequest{
				ScanOptionOverrides: req.ScanOptionOverrides,
				Targets:             append([]string(nil), httpTargets...),
				FingerprintConfig:   req.FingerprintConfig,
			}
			fpRes, err := RunFingerprintService(&fpReq)
			if err != nil {
				sendError(c, http.StatusInternalServerError, err)
				return
			}
			response["fingerprint"] = fpRes
		}

		if runDirscan {
			dirReq := DirscanRequest{
				ScanOptionOverrides: req.ScanOptionOverrides,
				Targets:             append([]string(nil), httpTargets...),
				DirscanConfig:       req.DirscanConfig,
			}
			dirRes, err := RunDirscanService(&dirReq)
			if err != nil {
				sendError(c, http.StatusInternalServerError, err)
				return
			}
			response["dirscan"] = dirRes
		}

		sendSuccess(c, response)
		return
	}

	if runFingerprint {
		fpReq := FingerprintRequest{
			ScanOptionOverrides: req.ScanOptionOverrides,
			Targets:             append([]string(nil), targets...),
			FingerprintConfig:   req.FingerprintConfig,
		}
		fpRes, err := RunFingerprintService(&fpReq)
		if err != nil {
			sendError(c, http.StatusInternalServerError, err)
			return
		}
		response["fingerprint"] = fpRes
	}

	if runDirscan {
		dirReq := DirscanRequest{
			ScanOptionOverrides: req.ScanOptionOverrides,
			Targets:             append([]string(nil), targets...),
			DirscanConfig:       req.DirscanConfig,
		}
		dirRes, err := RunDirscanService(&dirReq)
		if err != nil {
			sendError(c, http.StatusInternalServerError, err)
			return
		}
		response["dirscan"] = dirRes
	}

	sendSuccess(c, response)
}

func sendSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Code:    0,
		Message: "ok",
		Data:    data,
	})
}

func sendError(c *gin.Context, status int, err error) {
	c.JSON(status, APIResponse{
		Code:    status,
		Message: err.Error(),
	})
}

func corsMiddleware(c *gin.Context) {
	origin := c.GetHeader("Origin")
	if origin == "" {
		origin = "*"
	}

	c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
	c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")

	if c.Request.Method == http.MethodOptions {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}
	c.Next()
}

func deriveHTTPRescanTargets(results []portscanpkg.OpenPortResult) []string {
	seen := make(map[string]struct{})
	var targets []string

	for _, r := range results {
		service := strings.ToLower(strings.TrimSpace(r.Service))
		if service == "" {
			continue
		}

		var scheme string
		switch {
		case strings.HasPrefix(service, "https"):
			scheme = "https"
		case strings.HasPrefix(service, "http"):
			scheme = "http"
		default:
			continue
		}

		host := strings.TrimSpace(r.IP)
		if host == "" {
			continue
		}

		targetURL := fmt.Sprintf("%s://%s:%d", scheme, host, r.Port)
		if (scheme == "http" && r.Port == 80) || (scheme == "https" && r.Port == 443) {
			targetURL = fmt.Sprintf("%s://%s", scheme, host)
		}

		if _, exists := seen[targetURL]; exists {
			continue
		}
		seen[targetURL] = struct{}{}
		targets = append(targets, targetURL)
	}

	return targets
}
