# Go Makefile for Argus Ingestion Service
# Professional build, test, and lint commands

.PHONY: all build test test-coverage lint lint-fix format clean deps help

# Go binary
GO := go
GOFLAGS := -v

# Binary output
BINARY := ingestion
BUILD_DIR := ../../dist/go

# Coverage output
COVERAGE_DIR := ../../coverage/go
COVERAGE_FILE := $(COVERAGE_DIR)/coverage.out
COVERAGE_HTML := $(COVERAGE_DIR)/coverage.html
COVERAGE_JSON := $(COVERAGE_DIR)/coverage.json

# Default target
all: lint test build

# Build the binary
build:
	@echo "Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) .

# Build for Docker (linux/arm64)
build-docker:
	@echo "Building $(BINARY) for Docker (linux/arm64)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) .

# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@echo ""
	@echo "Coverage Summary:"
	$(GO) tool cover -func=$(COVERAGE_FILE)
	@echo ""
	@echo "Generating HTML report..."
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "HTML coverage report: $(COVERAGE_HTML)"

# Generate coverage JSON for CI/CD integration
coverage-json: test-coverage
	@echo "Generating JSON coverage report..."
	$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1 | awk '{print "{\"total\":\"" $$3 "\"}"}' > $(COVERAGE_JSON)
	@cat $(COVERAGE_JSON)

# Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

# Lint with golangci-lint
lint:
	@echo "Running linters..."
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

# Lint and fix issues
lint-fix:
	@echo "Running linters with auto-fix..."
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run --fix ./...; \
	else \
		echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

# Format code
format:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@if command -v goimports &> /dev/null; then \
		goimports -w .; \
	else \
		echo "goimports not found. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

# Check formatting (for CI)
format-check:
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "The following files are not properly formatted:"; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "All files are properly formatted."

# Install dependencies
deps:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy

# Verify dependencies
deps-verify:
	@echo "Verifying dependencies..."
	$(GO) mod verify

# Install development tools
tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(COVERAGE_DIR)
	$(GO) clean

# Run the service locally
run:
	@echo "Running service locally..."
	$(GO) run .

# Security scan with gosec
security:
	@echo "Running security scan..."
	@if command -v gosec &> /dev/null; then \
		gosec ./...; \
	else \
		echo "gosec not found. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
		exit 1; \
	fi

# Vulnerability check
vuln:
	@echo "Checking for vulnerabilities..."
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Run lint, test, and build"
	@echo "  build        - Build the binary"
	@echo "  build-docker - Build for Docker (linux/arm64)"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  coverage-json- Generate JSON coverage for CI"
	@echo "  benchmark    - Run benchmarks"
	@echo "  lint         - Run golangci-lint"
	@echo "  lint-fix     - Run golangci-lint with auto-fix"
	@echo "  format       - Format code with gofmt and goimports"
	@echo "  format-check - Check code formatting (CI)"
	@echo "  deps         - Install and tidy dependencies"
	@echo "  tools        - Install development tools"
	@echo "  clean        - Clean build artifacts"
	@echo "  run          - Run the service locally"
	@echo "  security     - Run security scan with gosec"
	@echo "  vuln         - Check for vulnerabilities"
	@echo "  help         - Show this help"
