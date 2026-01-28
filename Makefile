# Server Agent Makefile
#
# Build and package the server agent for multiple platforms.
#
# Usage:
#   make build       - Build for current platform
#   make all         - Build for all platforms
#   make clean       - Remove build artifacts
#   make install     - Install locally
#   make test        - Run tests

# Variables
BINARY_NAME := server-agent
VERSION := 1.0.0
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO := go
GOFLAGS := -ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE) -X main.GitCommit=$(GIT_COMMIT)"

# Output directories
BUILD_DIR := build
DIST_DIR := dist

# Platforms
PLATFORMS := linux/amd64 linux/arm64 linux/arm

# Default target
.DEFAULT_GOAL := build

# Build for current platform
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for all platforms
.PHONY: all
all: clean
	@echo "Building for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		output=$(DIST_DIR)/$(BINARY_NAME)-$$os-$$arch; \
		echo "Building $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch $(GO) build $(GOFLAGS) -o $$output .; \
		chmod +x $$output; \
	done
	@echo "Done! Binaries in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR) $(DIST_DIR)
	$(GO) clean

# Install locally
.PHONY: install
install: build
	@echo "Installing to /usr/local/bin/$(BINARY_NAME)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Installed!"

# Run tests
.PHONY: test
test:
	$(GO) test -v ./...

# Run with race detector
.PHONY: test-race
test-race:
	$(GO) test -race -v ./...

# Lint code
.PHONY: lint
lint:
	golangci-lint run

# Format code
.PHONY: fmt
fmt:
	$(GO) fmt ./...

# Get dependencies
.PHONY: deps
deps:
	$(GO) mod download
	$(GO) mod tidy

# Run locally for development
.PHONY: run
run:
	AGENT_TOKEN=development_token_for_testing_only $(GO) run . --debug --port 3456

# Generate checksums
.PHONY: checksums
checksums:
	@cd $(DIST_DIR) && sha256sum * > checksums.txt
	@cat $(DIST_DIR)/checksums.txt

# Docker build
.PHONY: docker
docker:
	docker build -t $(BINARY_NAME):$(VERSION) .

# Help
.PHONY: help
help:
	@echo "Server Agent Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build      Build for current platform"
	@echo "  make all        Build for all platforms (linux/amd64, linux/arm64, linux/arm)"
	@echo "  make clean      Remove build artifacts"
	@echo "  make install    Install to /usr/local/bin"
	@echo "  make test       Run tests"
	@echo "  make lint       Run linter"
	@echo "  make fmt        Format code"
	@echo "  make deps       Download dependencies"
	@echo "  make run        Run locally for development"
	@echo "  make checksums  Generate SHA256 checksums"
	@echo "  make docker     Build Docker image"
	@echo "  make help       Show this help"
