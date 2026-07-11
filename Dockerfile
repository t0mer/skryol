# syntax=docker/dockerfile:1

# Stage 1: frontend — built once on the native build platform (static output).
FROM --platform=$BUILDPLATFORM node:20-alpine AS frontend
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN mkdir -p /app/internal/web/dist
COPY internal/web/dist/.gitkeep /app/internal/web/dist/.gitkeep
RUN npm run build   # Vite outDir -> ../internal/web/dist

# Stage 2: Go binary — runs on the native build platform, cross-compiles to target.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
WORKDIR /app
ENV GOTOOLCHAIN=local
ENV CGO_ENABLED=0
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/internal/web/dist ./internal/web/dist
ARG VERSION=docker
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} go build \
    -trimpath -ldflags="-s -w -X github.com/t0mer/skryol/internal/version.Version=${VERSION}" \
    -o /app/skryol ./cmd/skryol/
# Pre-create the data dir so the non-root scratch image can own it.
RUN mkdir -p /data

# Stage 3: runtime — scratch, non-root, single static binary.
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/skryol /skryol
COPY --from=builder --chown=65532:65532 /data /data
USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/skryol"]
