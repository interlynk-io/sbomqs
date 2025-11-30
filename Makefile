# Copyright 2023 Interlynk.io
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Inspired by https://github.com/pinterb/go-semver/blob/master/Makefile

.DEFAULT_GOAL := help

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Version information
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
  BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
  BUILD_DATE ?= $(shell date -u "$(DATE_FMT)")
endif
GIT_TREESTATE = clean
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = dirty
endif

# Build variables
PKG ?= sigs.k8s.io/release-utils/version
LDFLAGS = -buildid= -X $(PKG).gitVersion=$(GIT_VERSION) \
          -X $(PKG).gitCommit=$(GIT_HASH) \
          -X $(PKG).gitTreeState=$(GIT_TREESTATE) \
          -X $(PKG).buildDate=$(BUILD_DATE)

BUILD_DIR = ./build
BINARY_NAME = sbomqs
TARGETOS ?= $(shell go env GOOS)
TARGETARCH ?= $(shell go env GOARCH)

##@ General

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

.PHONY: generate
generate: ## Run go generate
	@echo "Running go generate..."
	@go generate ./...

.PHONY: fmt
fmt: ## Run go fmt
	@echo "Formatting code..."
	@go fmt ./...

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

.PHONY: lint
lint: ## Run golangci-lint (requires golangci-lint installed)
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --config .golangci.yml; \
	else \
		echo "golangci-lint not found. Install it from https://golangci-lint.run/"; \
	fi

##@ Testing

.PHONY: test
test: generate ## Run all tests
	@echo "Running tests..."
	@go test -cover -race ./...

##@ Building

.PHONY: build
build: ## Build binary for current platform
	@echo "Building $(BINARY_NAME) for $(TARGETOS)/$(TARGETARCH)..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) .

.PHONY: build-all
build-all: ## Build binaries for all platforms
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	@GOOS=linux GOARCH=arm64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	@GOOS=darwin GOARCH=amd64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	@GOOS=darwin GOARCH=arm64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	@GOOS=windows GOARCH=amd64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Build complete. Binaries in $(BUILD_DIR)/"

.PHONY: install
install: build ## Install binary to GOBIN
	@echo "Installing $(BINARY_NAME) to $(GOBIN)..."
	@install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(GOBIN)/$(BINARY_NAME)
	@echo "Installed to $(GOBIN)/$(BINARY_NAME)"

##@ Release

.PHONY: snapshot
snapshot: ## Create a snapshot release (without publishing)
	@echo "Creating snapshot release..."
	@goreleaser release --clean --snapshot --skip=publish

.PHONY: release
release: ## Create a release (requires proper git tag)
	@echo "Creating release..."
	@goreleaser release --clean

##@ Maintenance

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) dist/ coverage.out coverage.html

.PHONY: clean-all
clean-all: clean ## Clean all artifacts including caches
	@echo "Cleaning all artifacts..."
	@go clean -cache -testcache -modcache

.PHONY: update-deps
update-deps: ## Update all dependencies
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

.PHONY: update-licenses
update-licenses: ## Update license database files
	@echo "Updating license database files..."
	@curl -fsSL "https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/json/licenses.json" \
		-o pkg/licenses/files/licenses_spdx.json
	@curl -fsSL "https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/json/exceptions.json" \
		-o pkg/licenses/files/licenses_spdx_exception.json
	@curl -fsSL "https://scancode-licensedb.aboutcode.org/index.json" \
		-o pkg/licenses/files/licenses_aboutcode.json
	@echo "License database files updated successfully"

.PHONY: tidy
tidy: ## Run go mod tidy
	@echo "Tidying go.mod..."
	@go mod tidy

##@ CI/CD

.PHONY: ci
ci: deps generate vet ## Run CI pipeline locally with test summary
	@echo "Running CI pipeline..."
	@set +e; \
	echo "Unit tests:"; \
	go test -cover -race -failfast -p 1 $$(go list ./... | grep -v integration_test) 2>&1 | grep -E "^(ok|FAIL|coverage:)" | sed 's/github.com\/interlynk-io\/sbomqs\/v2\///' ; \
	UNIT_EXIT_CODE=$$?; \
	echo ""; \
	echo "Integration tests:"; \
	go test -run "Test_ScoreForStaticSBOMFiles_Summary|Test_NTIAProfile|Test_NTIA2025Profile|Test_InterlynkProfile" ./pkg/scorer/v2/... 2>&1 | grep -E "(PASS|FAIL|ok|NTIA.*Profile:|Interlynk.*Profile:)" ; \
	INTEGRATION_EXIT_CODE=$$?; \
	echo ""; \
	echo "=========================================="; \
	echo "CI Pipeline Summary"; \
	echo "=========================================="; \
	if [ $$UNIT_EXIT_CODE -ne 0 ]; then \
		echo "✗ Unit tests: FAILED"; \
	else \
		echo "✓ Unit tests: PASSED"; \
	fi; \
	if [ $$INTEGRATION_EXIT_CODE -ne 0 ]; then \
		echo "✗ Integration tests: FAILED"; \
	else \
		echo "✓ Integration tests: PASSED"; \
	fi; \
	echo "=========================================="; \
	if [ $$UNIT_EXIT_CODE -eq 0 ] && [ $$INTEGRATION_EXIT_CODE -eq 0 ]; then \
		echo "✓ CI Pipeline: SUCCESS"; \
	else \
		echo "✗ CI Pipeline: FAILED"; \
	fi; \
	echo "=========================================="; \
	exit $$((UNIT_EXIT_CODE + INTEGRATION_EXIT_CODE))

.PHONY: pre-commit
pre-commit: fmt vet lint test ## Run pre-commit checks
	@echo "Pre-commit checks passed"
