package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	workersCount = 1
	logsLevel   = slog.LevelInfo
	requestIntervalInMS = 100
)

var client *http.Client

func initClient() {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 64
	transport.MaxIdleConnsPerHost = 8
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12 // maybe this is broken too ?
	// force to use http2...
	transport.TLSClientConfig.NextProtos = []string{"h2"}
	transport.TLSClientConfig.KeyLogWriter = os.Stdout

	client = &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
}

var logger *slog.Logger
var logFile *os.File

func logsToFile() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		// inside pod
		return true
	}

	return false
}

func initLogger() {
	stderrLogHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:     logsLevel,
		AddSource: true,
	})

	if logsToFile() {
		f, err := os.OpenFile("/logs/log.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			panic(err)
		}
		logFile = f

		jsonFileLoggerHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{
			Level:     slog.LevelWarn,
			AddSource: true,
		})

		logger = slog.New(MultiLogHandler(stderrLogHandler, jsonFileLoggerHandler))
	} else {
		logger = slog.New(stderrLogHandler)
	}
}

var requestID int64

func nextRequestID() string {
	nextID := atomic.AddInt64(&requestID, 1)
	return fmt.Sprintf("%d", nextID)
}

func randInt(n int64) int64 {
	rn, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		panic("failed to generate random number")
	}

	return rn.Int64()
}

func doRequest(ctx context.Context, workerId string) {
	requestLogger := logger.With("req.id", nextRequestID(), "worker.id", workerId)
	start := time.Now()
	defer func() {
		requestLogger.Debug("request duration", slog.Duration("duration", time.Since(start)))
	}()

	const tokenURL = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/token?api-version=1.0"

	// NOTE: we don't care about the response
	input := url.Values{}
	input.Add("grant_type", "client_credentials")
	input.Add("client_id", "fake-client-id")
	input.Add("client_secret", "fake-client-secret")
	input.Add("resource", "https://management.azure.com")

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		tokenURL,
		strings.NewReader(input.Encode()),
	)
	if err != nil {
		requestLogger.ErrorContext(ctx, "failed to create request", slog.String("error", err.Error()))
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		respStatusCode := 0
		if resp != nil {
			respStatusCode = resp.StatusCode
		}

		requestLogger.Error("failed to do request", slog.String("error", err.Error()), slog.Int("status", respStatusCode))
		return
	}
	// "error":"unauthorized_client","error_description":"AADSTS700016: Application with identifier 'fake-client-id' was not found in the directory 'Microsoft'
	_, err = io.ReadAll(resp.Body) // drain the body to make a full request
	if err != nil {
		requestLogger.Error("failed to read response body", slog.String("error", err.Error()), slog.Int("status", resp.StatusCode))
		return
	}

	requestLogger.Debug("request done", slog.Int("status", resp.StatusCode))
}

type ConnInfo struct {
	conn     net.Conn
	protocol string
	created  time.Time
	lastUsed time.Time
}

func main() {
	initLogger()
	defer func() {
		if logFile != nil {
			_ = logFile.Close()
		}
	}()

	initClient()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	bookkeepMutex := new(sync.Mutex)
	connMaps := make(map[string]*ConnInfo)

	bookkeepConn := func(connInfo httptrace.GotConnInfo, tlsState *tls.ConnectionState) {
		bookkeepMutex.Lock()
		defer bookkeepMutex.Unlock()

		conn := connInfo.Conn
		key := fmt.Sprintf("%s:%s", conn.RemoteAddr().String(), conn.LocalAddr().String())
		if connInfo.Reused {
			logger.Debug("reused connection", slog.String("key", key))
			_, ok := connMaps[key]
			if !ok {
				// this happen if the connection is using http/1.1
				logger.Debug("reused connection not found", slog.String("key", key))
				return
			}
			connMaps[key].lastUsed = time.Now()
			return
		}

		protocol := "unknown"
		if tlsState != nil {
			protocol = tlsState.NegotiatedProtocol

			if protocol == "" {
				logger.Info("closing non-h2 connection")

				// http 1.1 we don't want that
				if err := conn.Close(); err != nil {
					logger.Error("failed to close connection", slog.String("error", err.Error()))
				}
				return
			}
		}

		logger.Info("new connection", slog.String("key", key), slog.String("protocol", protocol))
		connMaps[key] = &ConnInfo{
			conn:     conn,
			protocol: protocol,
			created:  time.Now(),
			lastUsed: time.Now(),
		}
	}

	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {

		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				logger.Error("tls handshake done with error", slog.String("error", err.Error()))
				return
			}

			logger.Info("tls handshake done", slog.String("protocol", cs.NegotiatedProtocol))
		},
	})

	var requestTimes int64
	wg := new(sync.WaitGroup)

	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func(workerID string) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					func() {
						var gotConnInfo *httptrace.GotConnInfo
						var tlsState *tls.ConnectionState

						reqCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
							GotConn: func(info httptrace.GotConnInfo) {
								gotConnInfo = &info
							},
							TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
								if err != nil {
									logger.Error("tls handshake done with error", slog.String("error", err.Error()))
									return
								}

								tlsState = &cs
							},
						})

						doRequest(reqCtx, workerID)

						if gotConnInfo != nil {
							bookkeepConn(*gotConnInfo, tlsState)
						} else {
							logger.Error("gotConnInfo is nil")
						}

						if atomic.AddInt64(&requestTimes, 1)%100 == 0 {
							logger.Info("request count", slog.Int("count", int(atomic.LoadInt64(&requestID))))
						}
					}()
					time.Sleep(time.Duration(randInt(requestIntervalInMS)) * time.Millisecond)
				}
			}
		}(fmt.Sprintf("%d", i))
	}

	<-ctx.Done()
	wg.Wait()

	for key, connInfo := range connMaps {
		logger.Info(
			"saw connection",
			slog.String("key", key),
			slog.String("protocol", connInfo.protocol),
			slog.Duration("age", time.Since(connInfo.created)),
			slog.Duration("lastUsed", time.Since(connInfo.lastUsed)),
		)
	}
	logger.Info("total connection count", slog.Int("count", len(connMaps)))
}

// multiLogHandler is a slog.Handler that sends log records to multiple handlers.
// simplified version of: https://github.com/samber/slog-multi/blob/main/multi.go
type multiLogHandler struct {
	handlers []slog.Handler
}

func MultiLogHandler(handlers ...slog.Handler) slog.Handler {
	return &multiLogHandler{handlers: handlers}
}

var _ slog.Handler = (*multiLogHandler)(nil)

func (h *multiLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range h.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}

	return false
}

func try(f func() error) (retErr error) {
	defer func() {
		if err := recover(); err != nil {
			retErr = fmt.Errorf("panic: %+v", err)
			return
		}
	}()

	if err := f(); err != nil {
		return err
	}

	return nil
}

func (h *multiLogHandler) Handle(ctx context.Context, r slog.Record) error {
	for i := range h.handlers {
		ch := h.handlers[i]
		if ch.Enabled(ctx, r.Level) {
			if err := try(func() error {
				return ch.Handle(ctx, r)
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (h *multiLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var handlers []slog.Handler
	for _, ch := range h.handlers {
		handlers = append(handlers, ch.WithAttrs(attrs))
	}
	return MultiLogHandler(handlers...)
}

func (*multiLogHandler) WithGroup(name string) slog.Handler {
	var handlers []slog.Handler
	for _, ch := range handlers {
		handlers = append(handlers, ch.WithGroup(name))
	}
	return MultiLogHandler(handlers...)
}
