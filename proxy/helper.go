package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"veo/internal/core/logger"
)

var normalErrMsgs []string = []string{
	"read: connection reset by peer",
	"write: broken pipe",
	"i/o timeout",
	"net/http: TLS handshake timeout",
	"io: read/write on closed pipe",
	"connect: connection refused",
	"connect: connection reset by peer",
	"use of closed network connection",
	"http2: stream closed",
	"http2: server",
	"http2: stream reset",
	"context canceled",
	"operation was canceled",
}

// 仅打印预料之外的错误信息
func logErr(prefix string, err error) (loged bool) {
	msg := err.Error()

	for _, str := range normalErrMsgs {
		if strings.Contains(msg, str) {
			logger.Debugf("%s %v", prefix, err)
			return
		}
	}

	logger.Errorf("%s %v", prefix, err)
	loged = true
	return
}

// 转发流量
func transfer(prefix string, server, client io.ReadWriteCloser) {
	done := make(chan struct{})
	defer close(done)

	errChan := make(chan error)
	go func() {
		_, err := io.Copy(server, client)
		logger.Debugf("%s client copy end %v", prefix, err)
		client.Close()
		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()
	go func() {
		_, err := io.Copy(client, server)
		logger.Debugf("%s server copy end %v", prefix, err)
		server.Close()

		if clientConn, ok := client.(*wrapClientConn); ok {
			err := clientConn.Conn.(*net.TCPConn).CloseRead()
			logger.Debugf("%s clientConn.Conn.(*net.TCPConn).CloseRead() %v", prefix, err)
		}

		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			logErr(prefix, err)
			return // 如果有错误，直接返回
		}
	}
}

func httpError(w http.ResponseWriter, error string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`) // Indicates that the proxy server requires client credentials
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}
