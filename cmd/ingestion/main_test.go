// cmd/ingestion/main_test.go
// Unit tests for Argus ingestion handler
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// MockSQSClient implements a mock SQS client for testing
type MockSQSClient struct {
	SendMessageFunc func(ctx context.Context, params *sqs.SendMessageInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
	messages        []string
	sendError       error
}

func (m *MockSQSClient) SendMessage(ctx context.Context, params *sqs.SendMessageInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	if m.sendError != nil {
		return nil, m.sendError
	}
	if params.MessageBody != nil {
		m.messages = append(m.messages, *params.MessageBody)
	}
	return &sqs.SendMessageOutput{}, nil
}

// SQSSender interface for dependency injection
type SQSSender interface {
	SendMessage(ctx context.Context, params *sqs.SendMessageInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	healthHandler(w, req)

	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", res.StatusCode)
	}

	var response map[string]string
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got '%s'", response["status"])
	}
}

func TestCollectHandler_MethodNotAllowed(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/v1/collect", nil)
			w := httptest.NewRecorder()

			collectHandler(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected status 405 for %s, got %d", method, w.Code)
			}
		})
	}
}

func TestCollectHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/collect", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	collectHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestCollectHandler_MissingSessionID(t *testing.T) {
	payload := FingerprintPayload{
		TenantID: "test-tenant",
		Fingerprint: map[string]interface{}{
			"screen_width": 1920,
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/v1/collect", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	collectHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestFingerprintPayload_Serialization(t *testing.T) {
	payload := FingerprintPayload{
		SessionID: "test-session-123",
		TenantID:  "tenant-abc",
		Fingerprint: map[string]interface{}{
			"screen_width":  1920,
			"screen_height": 1080,
			"user_agent":    "Mozilla/5.0",
		},
		TCPBlob:   "tcp-data",
		TLSBlob:   "tls-data",
		Timestamp: 1704067200000,
		Headers: map[string]string{
			"User-Agent": "test-agent",
		},
	}

	// Serialize
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	// Deserialize
	var decoded FingerprintPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	// Verify fields
	if decoded.SessionID != payload.SessionID {
		t.Errorf("SessionID mismatch: expected %s, got %s", payload.SessionID, decoded.SessionID)
	}
	if decoded.TenantID != payload.TenantID {
		t.Errorf("TenantID mismatch: expected %s, got %s", payload.TenantID, decoded.TenantID)
	}
	if decoded.Timestamp != payload.Timestamp {
		t.Errorf("Timestamp mismatch: expected %d, got %d", payload.Timestamp, decoded.Timestamp)
	}
}

func TestStringPtr(t *testing.T) {
	s := "test"
	ptr := stringPtr(s)

	if ptr == nil {
		t.Fatal("expected non-nil pointer")
	}
	if *ptr != s {
		t.Errorf("expected %s, got %s", s, *ptr)
	}
}

func TestFingerprintPayload_OptionalFields(t *testing.T) {
	jsonData := `{"session_id":"abc123"}`

	var payload FingerprintPayload
	if err := json.Unmarshal([]byte(jsonData), &payload); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if payload.SessionID != "abc123" {
		t.Errorf("expected session_id 'abc123', got '%s'", payload.SessionID)
	}
	if payload.TenantID != "" {
		t.Errorf("expected empty tenant_id, got '%s'", payload.TenantID)
	}
	if payload.Timestamp != 0 {
		t.Errorf("expected 0 timestamp, got %d", payload.Timestamp)
	}
}

func TestHealthHandler_ContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	healthHandler(w, req)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}
}

func TestFingerprintPayload_NestedFingerprint(t *testing.T) {
	payload := FingerprintPayload{
		SessionID: "nested-test",
		Fingerprint: map[string]interface{}{
			"canvas": map[string]interface{}{
				"hash":   "abc123",
				"width":  300,
				"height": 150,
			},
			"webgl": map[string]interface{}{
				"vendor":   "Intel",
				"renderer": "UHD Graphics",
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal nested payload: %v", err)
	}

	var decoded FingerprintPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal nested payload: %v", err)
	}

	canvas, ok := decoded.Fingerprint["canvas"].(map[string]interface{})
	if !ok {
		t.Fatal("expected canvas to be a map")
	}
	if canvas["hash"] != "abc123" {
		t.Errorf("expected canvas hash 'abc123', got '%v'", canvas["hash"])
	}
}

// Benchmark tests
func BenchmarkHealthHandler(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		healthHandler(w, req)
	}
}

func BenchmarkPayloadSerialization(b *testing.B) {
	payload := FingerprintPayload{
		SessionID: "bench-session",
		TenantID:  "bench-tenant",
		Fingerprint: map[string]interface{}{
			"screen_width":    1920,
			"screen_height":   1080,
			"pixel_ratio":     2.0,
			"color_depth":     24,
			"timezone_offset": -480,
		},
		Timestamp: 1704067200000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(payload)
	}
}
