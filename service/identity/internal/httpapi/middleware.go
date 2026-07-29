package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"
)

type requestIDContextKey struct{}

func applyMiddleware(
	logger *slog.Logger,
	next http.Handler,
) http.Handler {
	handler := securityHeadersMiddleware(next)
	handler = recoveryMiddleware(logger, handler)
	handler = accessLogMiddleware(logger, handler)
	handler = requestIDMiddleware(logger, handler)

	return handler
}

func requestIDMiddleware(
	logger *slog.Logger,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, err := generateRequestID()
		if err != nil {
			logger.Error(
				"failed to generate request ID",
				slog.String("error", err.Error()),
			)

			writeError(
				w,
				http.StatusInternalServerError,
				"ERR_INTERNAL",
				"internal server error",
				"",
				logger,
			)

			return
		}

		ctx := context.WithValue(
			r.Context(),
			requestIDContextKey{},
			requestID,
		)

		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func recoveryMiddleware(
	logger *slog.Logger,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() == nil {
				return
			}

			requestID := requestIDFromContext(r.Context())

			logger.Error(
				"panic recovered",
				slog.String("request_id", requestID),
				slog.String("stack", string(debug.Stack())),
			)

			writeError(
				w,
				http.StatusInternalServerError,
				"ERR_INTERNAL",
				"internal server error",
				requestID,
				logger,
			)
		}()

		next.ServeHTTP(w, r)
	})
}

func accessLogMiddleware(
	logger *slog.Logger,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()

		recorder := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(recorder, r)

		logger.Info(
			"http request completed",
			slog.String(
				"request_id",
				requestIDFromContext(r.Context()),
			),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.statusCode),
			slog.Int("response_bytes", recorder.responseBytes),
			slog.Duration("duration", time.Since(startedAt)),
			slog.String("remote_ip", remoteIP(r.RemoteAddr)),
		)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()

		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cache-Control", "no-store")
		header.Set(
			"Content-Security-Policy",
			"default-src 'none'; frame-ancestors 'none'",
		)

		next.ServeHTTP(w, r)
	})
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode    int
	responseBytes int
	wroteHeader   bool
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	if r.wroteHeader {
		return
	}

	r.statusCode = statusCode
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	written, err := r.ResponseWriter.Write(data)
	r.responseBytes += written

	return written, err
}

func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func generateRequestID() (string, error) {
	randomBytes := make([]byte, 16)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(randomBytes), nil
}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	return requestID
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}

	return host
}
