// cmd/ingestion/main.go
// Ultra-thin Go ingestion handler for Argus
// Validate -> SQS -> 204

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

const (
	maxBodySize  = 64 * 1024 // 64KB max payload size (AR-31)
	maxJSONDepth = 10        // Maximum nesting depth for JSON (AR-31)
)

var (
	sqsClient *sqs.Client
	queueURL  string
	logger    *slog.Logger
)

// FingerprintPayload is the incoming request structure
// Uses json.RawMessage for fingerprint to avoid decode/re-encode overhead
//
//nolint:govet // field order matches JSON schema for readability
type FingerprintPayload struct {
	SessionID   string            `json:"session_id"`
	TenantID    string            `json:"tenant_id"`
	Fingerprint json.RawMessage   `json:"fingerprint,omitempty"`
	TCPBlob     string            `json:"tcp_blob,omitempty"`
	TLSBlob     string            `json:"tls_blob,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timestamp   int64             `json:"timestamp"`
}

func main() {
	// Setup structured logging
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load environment config
	queueURL = os.Getenv("SQS_QUEUE_URL")
	if queueURL == "" {
		logger.Error("SQS_QUEUE_URL environment variable is required")
		os.Exit(1)
	}

	// Initialize AWS SDK
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		logger.Error("Failed to load AWS config", "error", err)
		os.Exit(1)
	}
	sqsClient = sqs.NewFromConfig(cfg)

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/v1/collect", collectHandler)

	// Wrap with CORS middleware (AR-29)
	handler := corsMiddleware(mux)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("Starting server", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server error", "error", err)
			os.Exit(1)
		}
	}()

	<-done
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server shutdown error", "error", err)
	}
	logger.Info("Server stopped")
}

// corsMiddleware adds CORS headers for cross-origin merchant requests (AR-29)
// Reflects the request Origin, allowing any merchant domain to call the API
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Tenant-ID")
			w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		}

		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck,gosec // health check response write errors are non-critical
	w.Write([]byte(`{"status":"healthy"}`))
}

func collectHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Only accept POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit body size to prevent large payload attacks (AR-31)
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	// Parse request body
	var payload FingerprintPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		// Check if it's a body size exceeded error
		if err.Error() == "http: request body too large" {
			logger.Warn("Payload too large", "max_size", maxBodySize)
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		logger.Warn("Invalid JSON payload", "error", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if payload.SessionID == "" {
		logger.Warn("Missing session_id")
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	// Validate fingerprint JSON depth to prevent deeply nested attacks (AR-31)
	if len(payload.Fingerprint) > 0 {
		if depth := getJSONDepth(payload.Fingerprint); depth > maxJSONDepth {
			logger.Warn("Fingerprint JSON too deeply nested", "depth", depth, "max", maxJSONDepth)
			http.Error(w, "Fingerprint JSON too deeply nested", http.StatusBadRequest)
			return
		}
	}

	// Extract tenant from header or payload
	if payload.TenantID == "" {
		payload.TenantID = r.Header.Get("X-Tenant-ID")
	}
	if payload.TenantID == "" {
		payload.TenantID = "default" // Fallback for single-tenant
	}

	// Add timestamp if not provided
	if payload.Timestamp == 0 {
		payload.Timestamp = time.Now().UnixMilli()
	}

	// Extract headers for the payload
	payload.Headers = make(map[string]string)
	for _, h := range []string{"User-Agent", "Accept-Language", "X-Forwarded-For"} {
		if v := r.Header.Get(h); v != "" {
			payload.Headers[h] = v
		}
	}

	// Serialize to JSON for SQS
	msgBody, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal payload", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Send to SQS
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err = sqsClient.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:    &queueURL,
		MessageBody: stringPtr(string(msgBody)),
	})
	if err != nil {
		logger.Error("Failed to send to SQS", "error", err, "session_id", payload.SessionID)
		http.Error(w, "Failed to queue request", http.StatusServiceUnavailable)
		return
	}

	// Success - 204 No Content
	duration := time.Since(start)
	logger.Info("Request queued",
		"session_id", payload.SessionID,
		"tenant_id", payload.TenantID,
		"duration_ms", duration.Milliseconds(),
	)

	w.WriteHeader(http.StatusNoContent)
}

func stringPtr(s string) *string {
	return &s
}

// getJSONDepth calculates the maximum nesting depth of JSON data (AR-31)
// Returns 0 for invalid JSON or empty input
func getJSONDepth(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	maxDepth := 0
	currentDepth := 0
	inString := false
	escape := false

	for _, b := range data {
		if escape {
			escape = false
			continue
		}

		if b == '\\' && inString {
			escape = true
			continue
		}

		if b == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		switch b {
		case '{', '[':
			currentDepth++
			if currentDepth > maxDepth {
				maxDepth = currentDepth
			}
		case '}', ']':
			currentDepth--
		}
	}

	return maxDepth
}
