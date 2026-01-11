# Build stage
FROM public.ecr.aws/docker/library/golang:1.22-alpine AS builder

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy go mod and source files
COPY go.mod ./
COPY *.go ./

# Generate go.sum and download dependencies
RUN go mod tidy && go mod download

# Build with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
    -ldflags="-s -w" \
    -o ingestion \
    .

# Runtime stage
FROM public.ecr.aws/docker/library/alpine:3.19

WORKDIR /app

# Install wget for health check and copy ca-certificates from builder
RUN apk --no-cache add wget
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /app/ingestion .

# Non-root user
RUN adduser -D -u 1000 appuser
USER appuser

# NOTE: Removed Dockerfile HEALTHCHECK to avoid conflict with ECS task definition healthCheck.
# ECS handles health checks via task definition + ALB target group health checks.
# Having both Dockerfile HEALTHCHECK and ECS healthCheck caused tasks to be marked unhealthy
# despite ALB targets being healthy, triggering circuit breaker.

EXPOSE 8080

ENTRYPOINT ["./ingestion"]
