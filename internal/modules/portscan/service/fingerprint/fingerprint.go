package fingerprint

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"veo/internal/core/logger"
)

type Action uint8

const (
	ActionRecv = Action(iota)
	ActionSend
)

const (
	refusedStr   = "refused"
	ioTimeoutStr = "i/o timeout"
)

type ruleData struct {
	Action  Action
	Data    []byte
	Regexps []*regexp.Regexp
}

type serviceRule struct {
	Tls       bool
	DataGroup []ruleData
}

var serviceRules = make(map[string]serviceRule)
var readBufPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

// PortIdentify 端口识别
func PortIdentify(network string, ip net.IP, _port uint16, dailTimeout time.Duration) (serviceName string, banner []byte, isDailErr bool) {
	matchedRule := make(map[string]struct{})
	recordMatched := func(s string) {
		matchedRule[s] = struct{}{}
		if gf, ok := groupFlows[s]; ok {
			for _, s2 := range gf {
				matchedRule[s2] = struct{}{}
			}
		}
	}

	unknown := "unknown"
	var sn string

	defer func() {
		if sn == "http" && bytes.HasPrefix(banner, []byte("HTTP/1.1 400")) {
			sn2, banner2, isDailErr2 := matchRule(network, ip, _port, "https", dailTimeout)
			if !isDailErr && sn2 != "" {
				sn = sn2
				banner = banner2
				isDailErr = isDailErr2
			}
		}
	}()

	if serviceNames, ok := portServiceOrder[_port]; ok {
		for _, service := range serviceNames {
			recordMatched(service)
			sn, banner, isDailErr = matchRule(network, ip, _port, service, dailTimeout)
			if sn != "" {
				logger.Debugf("priority port order matched %s:%d => %s banner=%q", ip.String(), _port, sn, previewBanner(banner))
				return sn, banner, false
			} else if isDailErr {
				return unknown, banner, isDailErr
			}
		}
	}

	var lastDailTime time.Duration

	{
		var conn net.Conn
		var n int
		buf := readBufPool.Get().([]byte)
		defer func() {
			readBufPool.Put(buf)
		}()
		address := net.JoinHostPort(ip.String(), strconv.Itoa(int(_port)))
		now := time.Now()
		conn, _ = net.DialTimeout(network, address, dailTimeout)
		if conn == nil {
			return unknown, banner, true
		}
		lastDailTime = time.Since(now) * 2
		if lastDailTime < dailTimeout {
			dailTimeout = lastDailTime
			if dailTimeout < 250*time.Millisecond {
				dailTimeout = 250 * time.Millisecond
			}
		}
		n, _ = read(conn, buf, dailTimeout)
		conn.Close()
		if n != 0 {
			banner = make([]byte, n)
			copy(banner, buf[:n])
			logger.Debugf("only-recv banner %s:%d => %q", ip.String(), _port, previewBanner(buf[:n]))
			for _, service := range onlyRecv {
				_, ok := matchedRule[service]
				if ok {
					continue
				}
				for _, rule := range serviceRules[service].DataGroup {
					if matchRuleWithBuf(buf[:n], ip, _port, rule) {
						return service, banner, false
					}
				}

			}
		}
		for _, service := range onlyRecv {
			recordMatched(service)
		}
	}

	for _, service := range serviceOrder {
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		recordMatched(service)
		sn, banner, isDailErr = matchRule(network, ip, _port, service, dailTimeout)
		if sn != "" {
			logger.Debugf("priority service matched %s:%d => %s banner=%q", ip.String(), _port, sn, previewBanner(banner))
			return sn, banner, false
		} else if isDailErr {
			return unknown, banner, true
		}
	}

	for service := range serviceRules {
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		sn, banner, isDailErr = matchRule(network, ip, _port, service, dailTimeout)
		if sn != "" {
			logger.Debugf("fallback service matched %s:%d => %s banner=%q", ip.String(), _port, sn, previewBanner(banner))
			return sn, banner, false
		} else if isDailErr {
			return unknown, banner, true
		}
	}

	return unknown, banner, false
}

func matchRuleWithBuf(buf, ip net.IP, _port uint16, rule ruleData) bool {
	data := []byte("")
	if rule.Data != nil {
		data = bytes.Replace(rule.Data, []byte("{IP}"), []byte(ip.String()), -1)
		data = bytes.Replace(data, []byte("{PORT}"), []byte(strconv.Itoa(int(_port))), -1)
	}
	if rule.Regexps != nil {
		for _, _regex := range rule.Regexps {
			if _regex.MatchString(convert2utf8(string(buf))) {
				return true
			}
		}
	}
	if len(data) != 0 && bytes.Contains(buf, data) {
		return true
	}
	return false
}

func matchRule(network string, ip net.IP, _port uint16, serviceName string, dailTimeout time.Duration) (serviceNameRet string, banner []byte, isDailErr bool) {
	var err error
	var isTls bool
	var conn net.Conn
	var connTls *tls.Conn

	address := net.JoinHostPort(ip.String(), strconv.Itoa(int(_port)))

	serviceRule2 := serviceRules[serviceName]
	flowsService := groupFlows[serviceName]

	if serviceRule2.Tls {
		connTls, err = tls.DialWithDialer(&net.Dialer{Timeout: dailTimeout}, network, address, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})
		if err != nil {
			if strings.HasSuffix(err.Error(), ioTimeoutStr) || strings.Contains(err.Error(), refusedStr) {
				isDailErr = true
				return
			}
			var oe *net.OpError
			if errors.As(err, &oe) && oe.Op == "remote error" && reflect.TypeOf(oe.Err).Name() == "alert" {
				serviceNameRet = "tls"
			}
			return
		}
		defer connTls.Close()
		isTls = true
	} else {
		conn, err = net.DialTimeout(network, address, dailTimeout)
		if conn == nil {
			isDailErr = true
			return
		}
		defer conn.Close()
	}

	buf := readBufPool.Get().([]byte)
	defer func() {
		readBufPool.Put(buf)
	}()

	data := []byte("")
	for _, rule := range serviceRule2.DataGroup {
		if rule.Data != nil {
			data = bytes.Replace(rule.Data, []byte("{IP}"), []byte(ip.String()), -1)
			data = bytes.Replace(data, []byte("{PORT}"), []byte(strconv.Itoa(int(_port))), -1)
		}

		if rule.Action == ActionSend {
			if isTls {
				connTls.SetWriteDeadline(time.Now().Add(dailTimeout))
				_, err = connTls.Write(data)
			} else {
				conn.SetWriteDeadline(time.Now().Add(dailTimeout))
				_, err = conn.Write(data)
			}
			if err != nil {
				return
			}
		} else {
			var n int
			if isTls {
				n, err = read(connTls, buf, dailTimeout)
			} else {
				n, err = read(conn, buf, dailTimeout)
			}
			if n == 0 {
				return
			}
			banner = make([]byte, n)
			copy(banner, buf[:n])
			logger.Debugf("recv banner %s:%d (%s) => %q", ip.String(), _port, serviceName, previewBanner(buf[:n]))
			if matchRuleWithBuf(buf[:n], ip, _port, rule) {
				serviceNameRet = serviceName
				logger.Debugf("exact match service=%s banner=%q", serviceName, previewBanner(buf[:n]))
				return
			}
			for _, s := range flowsService {
				for _, rule2 := range serviceRules[s].DataGroup {
					if rule2.Action == ActionSend {
						continue
					}
					if matchRuleWithBuf(buf[:n], ip, _port, rule2) {
						logger.Debugf("group match service=%s banner=%q", s, previewBanner(buf[:n]))
						serviceNameRet = s
						return
					}
				}
			}
		}
	}

	if serviceNameRet == "" && len(banner) > 0 {
		for serviceName, _regex := range doneRecvFinger {
			if _regex.MatchString(convert2utf8(string(banner))) {
				logger.Debugf("done-recv regex matched service=%s banner=%q", serviceName, previewBanner(banner))
				serviceNameRet = serviceName
			}
		}
	}

	return
}

func read(conn interface{}, buf []byte, timeout time.Duration) (int, error) {
	switch conn.(type) {
	case net.Conn:
		conn.(net.Conn).SetReadDeadline(time.Now().Add(timeout))
		return conn.(net.Conn).Read(buf[:])
	case *tls.Conn:
		conn.(*tls.Conn).SetReadDeadline(time.Now().Add(timeout))
		return conn.(*tls.Conn).Read(buf[:])
	}
	return 0, errors.New("unknown type")
}

func convert2utf8(src string) string {
	var dst string
	for i, r := range src {
		var v string
		if r == utf8.RuneError {
			v = string(src[i])
		} else {
			v = string(r)
		}
		dst += v
	}
	return dst
}

func previewBanner(b []byte) string {
	const limit = 256
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + "...(truncated)"
}
