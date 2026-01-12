// cmd/ingestion/auth_test.go
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractTenant(t *testing.T) {
	// Save original state
	origAPIKeyTenants := apiKeyTenants
	origRequireAPIKey := requireAPIKey
	defer func() {
		apiKeyTenants = origAPIKeyTenants
		requireAPIKey = origRequireAPIKey
	}()

	t.Run("single-tenant mode uses default", func(t *testing.T) {
		requireAPIKey = false
		apiKeyTenants = nil

		req := httptest.NewRequest(http.MethodPost, "/v1/collect", http.NoBody)
		tenant, err := extractTenant(req)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if tenant != "default" {
			t.Errorf("Expected tenant 'default', got '%s'", tenant)
		}
	})

	t.Run("single-tenant mode respects X-Tenant-ID header", func(t *testing.T) {
		requireAPIKey = false
		apiKeyTenants = nil

		req := httptest.NewRequest(http.MethodPost, "/v1/collect", http.NoBody)
		req.Header.Set("X-Tenant-ID", "custom-tenant")
		tenant, err := extractTenant(req)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if tenant != "custom-tenant" {
			t.Errorf("Expected tenant 'custom-tenant', got '%s'", tenant)
		}
	})

	t.Run("multi-tenant mode with valid API key", func(t *testing.T) {
		requireAPIKey = true
		apiKeyTenants = map[string]string{
			"key-abc-123": "tenant-a",
			"key-xyz-789": "tenant-b",
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/collect", http.NoBody)
		req.Header.Set("X-API-Key", "key-abc-123")
		tenant, err := extractTenant(req)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if tenant != "tenant-a" {
			t.Errorf("Expected tenant 'tenant-a', got '%s'", tenant)
		}
	})

	t.Run("multi-tenant mode with invalid API key returns error", func(t *testing.T) {
		requireAPIKey = true
		apiKeyTenants = map[string]string{
			"key-abc-123": "tenant-a",
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/collect", http.NoBody)
		req.Header.Set("X-API-Key", "invalid-key")
		_, err := extractTenant(req)

		if err != errInvalidAPIKey {
			t.Errorf("Expected errInvalidAPIKey, got: %v", err)
		}
	})

	t.Run("multi-tenant mode without API key uses default (backward compatible)", func(t *testing.T) {
		requireAPIKey = true
		apiKeyTenants = map[string]string{
			"key-abc-123": "tenant-a",
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/collect", http.NoBody)
		// No X-API-Key header
		tenant, err := extractTenant(req)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if tenant != "default" {
			t.Errorf("Expected tenant 'default', got '%s'", tenant)
		}
	})

	t.Run("API key lookup is case-sensitive", func(t *testing.T) {
		requireAPIKey = true
		apiKeyTenants = map[string]string{
			"Key-ABC-123": "tenant-a",
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/collect", http.NoBody)
		req.Header.Set("X-API-Key", "key-abc-123") // lowercase
		_, err := extractTenant(req)

		if err != errInvalidAPIKey {
			t.Errorf("Expected errInvalidAPIKey for wrong case, got: %v", err)
		}
	})
}
