# confcrypt Makefile
# Supports building with and without CGO (FIDO2 support)

# Binary name
BINARY_NAME := confcrypt

# Version from git tag, with -dev-<branch> suffix if working tree is dirty
# Strips leading "v" from tags like "v1.5.0" -> "1.5.0"
GIT_TAG := $(shell git describe --tags --abbrev=0 2>/dev/null)
GIT_DIRTY := $(shell git status --porcelain 2>/dev/null | head -1)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
BASE_VERSION := $(if $(GIT_TAG),$(patsubst v%,%,$(GIT_TAG)),dev)
VERSION ?= $(if $(GIT_DIRTY),$(BASE_VERSION)-dev-$(GIT_BRANCH),$(BASE_VERSION))

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOVET := $(GOCMD) vet
GOMOD := $(GOCMD) mod
GOFMT := gofmt

# Build flags
LDFLAGS := -ldflags "-s -w -X github.com/maurice2k/confcrypt/cmd.version=$(VERSION)"

# Detect OS and architecture
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# CGO flags for FIDO2 support (macOS with Homebrew)
ifeq ($(GOOS),darwin)
    BREW_PREFIX ?= $(shell brew --prefix 2>/dev/null)
    ifdef BREW_PREFIX
        export CGO_CFLAGS ?= -I$(BREW_PREFIX)/opt/libfido2/include -I$(BREW_PREFIX)/opt/openssl@3/include
        export CGO_LDFLAGS ?= -L$(BREW_PREFIX)/opt/libfido2/lib -lfido2 -L$(BREW_PREFIX)/opt/openssl@3/lib -lcrypto
    endif
endif

# Output directory
BUILD_DIR := build

# Default target
.PHONY: all
all: build

# Help target
.PHONY: help
help:
	@echo "confcrypt Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build with CGO enabled (FIDO2 support)"
	@echo "  make build-nocgo    Build without CGO (no FIDO2 support)"
	@echo "  make install        Install to GOPATH/bin (with CGO)"
	@echo "  make install-nocgo  Install to GOPATH/bin (without CGO)"
	@echo "  make test           Run tests"
	@echo "  make test-verbose   Run tests with verbose output"
	@echo "  make test-coverage  Run tests with coverage report"
	@echo "  make vet            Run go vet"
	@echo "  make fmt            Format code"
	@echo "  make fmt-check      Check code formatting"
	@echo "  make lint           Run golangci-lint (if installed)"
	@echo "  make clean          Remove build artifacts"
	@echo "  make deps           Download dependencies"
	@echo "  make tidy           Tidy go.mod"
	@echo ""
	@echo "Cross-compilation:"
	@echo "  make build-all      Build for all platforms (with CGO where possible)"
	@echo "  make build-all-nocgo Build for all platforms (without CGO)"
	@echo ""
	@echo "Variables:"
	@echo "  CGO_ENABLED=0|1     Override CGO setting"
	@echo "  GOOS=linux|darwin   Target OS"
	@echo "  GOARCH=amd64|arm64  Target architecture"
	@echo "  VERSION=x.y.z       Override version string"

# Build with CGO enabled (FIDO2 support)
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) with CGO (FIDO2 support)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

# Build without CGO (no FIDO2 support)
.PHONY: build-nocgo
build-nocgo:
	@echo "Building $(BINARY_NAME) without CGO (no FIDO2 support)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

# Install with CGO
.PHONY: install
install:
	@echo "Installing $(BINARY_NAME) with CGO (FIDO2 support)..."
	CGO_ENABLED=1 $(GOBUILD) $(LDFLAGS) -o $(GOPATH)/bin/$(BINARY_NAME) .
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

# Install without CGO
.PHONY: install-nocgo
install-nocgo:
	@echo "Installing $(BINARY_NAME) without CGO (no FIDO2 support)..."
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(GOPATH)/bin/$(BINARY_NAME) .
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) ./...

# Run tests with verbose output
.PHONY: test-verbose
test-verbose:
	@echo "Running tests (verbose)..."
	$(GOTEST) -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"

# Run go vet
.PHONY: vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

# Check code formatting
.PHONY: fmt-check
fmt-check:
	@echo "Checking code formatting..."
	@test -z "$$($(GOFMT) -s -l . | tee /dev/stderr)" || (echo "Code is not formatted. Run 'make fmt'" && exit 1)

# Run golangci-lint (if installed)
.PHONY: lint
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running golangci-lint..."; \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install with:"; \
		echo "  brew install golangci-lint  # macOS"; \
		echo "  # or see https://golangci-lint.run/usage/install/"; \
	fi

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

# Tidy go.mod
.PHONY: tidy
tidy:
	@echo "Tidying go.mod..."
	$(GOMOD) tidy

# Build for current platform with specific CGO setting
.PHONY: build-cgo
build-cgo: build

.PHONY: build-static
build-static: build-nocgo

# Cross-compilation targets (without CGO for portability)
.PHONY: build-all-nocgo
build-all-nocgo:
	@echo "Building for all platforms (without CGO)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Built binaries in $(BUILD_DIR)/"
	@ls -la $(BUILD_DIR)/

# Build for all platforms (CGO only for current platform)
.PHONY: build-all
build-all: build-all-nocgo
	@echo ""
	@echo "Note: Cross-compiled binaries are built without CGO (no FIDO2 support)."
	@echo "For FIDO2 support, build natively on each platform with 'make build'."

# Development: build and run
.PHONY: run
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

# Check if libfido2 is available
.PHONY: check-fido2
check-fido2:
	@echo "Checking for libfido2..."
	@if pkg-config --exists libfido2 2>/dev/null; then \
		echo "libfido2 found via pkg-config"; \
		pkg-config --modversion libfido2; \
	elif [ -f /usr/include/fido.h ] || [ -f /usr/local/include/fido.h ] || [ -f "$$(brew --prefix 2>/dev/null)/include/fido.h" ]; then \
		echo "libfido2 headers found"; \
	else \
		echo "libfido2 not found. Install with:"; \
		echo "  brew install libfido2        # macOS"; \
		echo "  apt install libfido2-dev     # Debian/Ubuntu"; \
		echo "  dnf install libfido2-devel   # Fedora"; \
	fi

# Verify build
.PHONY: verify
verify: fmt-check vet test
	@echo "All checks passed!"
