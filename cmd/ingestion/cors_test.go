// cmd/ingestion/cors_test.go
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCorsMiddleware(t *testing.T) {
	// Create a simple handler to wrap
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := corsMiddleware(innerHandler)

	t.Run("OPTIONS preflight returns 204 with CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/v1/collect", nil)
		req.Header.Set("Origin", "https://merchant-site.com")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("Expected status 204, got %d", rr.Code)
		}

		checkCORSHeaders(t, rr, "https://merchant-site.com")
	})

	t.Run("POST response includes CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/collect", nil)
		req.Header.Set("Origin", "https://shop.example.com")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		checkCORSHeaders(t, rr, "https://shop.example.com")
	})

	t.Run("Request without Origin has no CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/collect", nil)
		// No Origin header set

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("Expected no Access-Control-Allow-Origin header when Origin not set")
		}
	})

	t.Run("Access-Control-Max-Age is set to 86400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/v1/collect", nil)
		req.Header.Set("Origin", "https://test.com")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		maxAge := rr.Header().Get("Access-Control-Max-Age")
		if maxAge != "86400" {
			t.Errorf("Expected Access-Control-Max-Age '86400', got '%s'", maxAge)
		}
	})
}

func checkCORSHeaders(t *testing.T, rr *httptest.ResponseRecorder, expectedOrigin string) {
	t.Helper()

	origin := rr.Header().Get("Access-Control-Allow-Origin")
	if origin != expectedOrigin {
		t.Errorf("Expected Access-Control-Allow-Origin '%s', got '%s'", expectedOrigin, origin)
	}

	methods := rr.Header().Get("Access-Control-Allow-Methods")
	if methods != "POST, OPTIONS" {
		t.Errorf("Expected Access-Control-Allow-Methods 'POST, OPTIONS', got '%s'", methods)
	}

	headers := rr.Header().Get("Access-Control-Allow-Headers")
	if headers != "Content-Type, X-Tenant-ID" {
		t.Errorf("Expected Access-Control-Allow-Headers 'Content-Type, X-Tenant-ID', got '%s'", headers)
	}
}
