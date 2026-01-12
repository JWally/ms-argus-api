// cmd/ingestion/validation_test.go
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	baseNestedJSON   = `{"value":1}`
	nestedJSONPrefix = `{"nested":`
)

func TestGetJSONDepth(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty", "", 0},
		{"simple object", `{"a":1}`, 1},
		{"nested object", `{"a":{"b":1}}`, 2},
		{"deeply nested", `{"a":{"b":{"c":{"d":1}}}}`, 4},
		{"array", `[1,2,3]`, 1},
		{"nested array", `[[1,2],[3,4]]`, 2},
		{"mixed nesting", `{"a":[{"b":1}]}`, 3},
		{"string with braces", `{"a":"{not nested}"}`, 1},
		{"escaped quotes", `{"a":"he said \"hi\""}`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getJSONDepth([]byte(tt.input))
			if result != tt.expected {
				t.Errorf("getJSONDepth(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCollectHandler_PayloadTooLarge(t *testing.T) {
	// Create a payload larger than 64KB
	largeData := strings.Repeat("x", 70000)
	body := `{"session_id":"test","fingerprint":{"data":"` + largeData + `"}}`

	req := httptest.NewRequest(http.MethodPost, "/v1/collect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	collectHandler(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status 413, got %d", rr.Code)
	}
}

func TestCollectHandler_DeeplyNestedJSON(t *testing.T) {
	// Create deeply nested JSON (15 levels)
	nested := baseNestedJSON
	for i := 0; i < 15; i++ {
		nested = nestedJSONPrefix + nested + `}`
	}
	body := `{"session_id":"test","fingerprint":` + nested + `}`

	req := httptest.NewRequest(http.MethodPost, "/v1/collect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	collectHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for deeply nested JSON, got %d", rr.Code)
	}

	if !strings.Contains(rr.Body.String(), "too deeply nested") {
		t.Errorf("Expected error message about nesting, got %q", rr.Body.String())
	}
}

func TestGetJSONDepth_AcceptableNesting(t *testing.T) {
	// Create JSON with acceptable nesting (6 levels)
	nested := baseNestedJSON
	for i := 0; i < 5; i++ {
		nested = nestedJSONPrefix + nested + `}`
	}

	depth := getJSONDepth([]byte(nested))
	if depth > maxJSONDepth {
		t.Errorf("6 levels of nesting should be acceptable, got depth %d", depth)
	}
}

func TestGetJSONDepth_EdgeCaseNesting(t *testing.T) {
	// Test exactly at the limit (10 levels)
	nested := baseNestedJSON
	for i := 0; i < 9; i++ {
		nested = nestedJSONPrefix + nested + `}`
	}

	depth := getJSONDepth([]byte(nested))
	if depth != 10 {
		t.Errorf("Expected depth 10, got %d", depth)
	}
	if depth > maxJSONDepth {
		t.Errorf("10 levels should be at the limit, not exceeding")
	}
}

func TestCollectHandler_ExceedsNestingLimit(t *testing.T) {
	// Test one over the limit (11 levels)
	nested := baseNestedJSON
	for i := 0; i < 10; i++ {
		nested = nestedJSONPrefix + nested + `}`
	}
	body := `{"session_id":"test","fingerprint":` + nested + `}`

	req := httptest.NewRequest(http.MethodPost, "/v1/collect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	collectHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for 11 levels of nesting, got %d", rr.Code)
	}
}
