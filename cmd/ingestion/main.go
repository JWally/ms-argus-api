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

var (
	sqsClient *sqs.Client
	queueURL  string
	logger    *slog.Logger
)

// FingerprintPayload is the incoming request structure
type FingerprintPayload struct {
	SessionID   string                 `json:"session_id"`
	TenantID    string                 `json:"tenant_id"`
	Fingerprint map[string]interface{} `json:"fingerprint"`
	TCPBlob     string                 `json:"tcp_blob,omitempty"`
	TLSBlob     string                 `json:"tls_blob,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Timestamp   int64                  `json:"timestamp"`
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

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
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

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func collectHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Only accept POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var payload FingerprintPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
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
