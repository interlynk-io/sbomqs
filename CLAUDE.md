# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build
```bash
# Build the main binary (CGO disabled by default)
make build
# Output: ./build/sbomqs

# Clean build artifacts
make clean
```

### Test
```bash
# Run all tests with coverage and race detection
make test

# Run specific package tests
go test -cover -race ./pkg/sbom/...
go test -cover -race ./pkg/compliance/...
```

### Lint
```bash
# Run golangci-lint (uses configuration from golangci.yml)
golangci-lint run --timeout=5m

# Specific linters enabled: asciicheck, unused, errcheck, errorlint, gofmt, goimports, gosec, revive, misspell, stylecheck, staticcheck, unconvert
```

### Dependencies
```bash
# Update and tidy dependencies
make dep

# Update all dependencies to latest versions
make updatedeps
```

### Release
```bash
# Create a snapshot release for testing
make snapshot

# Create a full release
make release
```

## High-Level Architecture

### Core Structure
sbomqs is a Go application that evaluates SBOM (Software Bill of Materials) quality and compliance. The architecture follows a command-based pattern with clear separation of concerns:

1. **Entry Point**: `main.go` → `cmd/Execute()` using Cobra framework with Fang styling
2. **Commands Layer** (`cmd/`): User-facing commands (score, compliance, list, share, etc.)
3. **Engine Layer** (`pkg/engine/`): Orchestrates operations across different components
4. **Core Business Logic** (`pkg/`):
   - `sbom/`: SBOM parsing and representation (supports SPDX and CycloneDX)
   - `compliance/`: Compliance validation engines (BSI, NTIA, FSCT, OpenChain Telco)
   - `scorer/`: Quality scoring algorithms
   - `reporter/`: Output formatting (basic, detailed, JSON)
   - `policy/`: Custom policy evaluation framework

### Key Architectural Decisions

**Multi-Format SBOM Support**: The `pkg/sbom` package provides a unified interface for both SPDX and CycloneDX formats. Format detection happens automatically in `sbom.go:detectSbomFormat()`.

**Scoring System**: Quality scores are calculated on a 0-10 scale using weighted criteria across multiple categories (NTIA compliance, structural quality, semantic quality). The scoring engine is configurable via YAML profiles.

**Compliance Framework**: Each compliance standard (BSI, NTIA, FSCT, OCT) has its own module in `pkg/compliance/` with dedicated scoring and reporting logic. Common functionality is shared via `pkg/compliance/common/`.

**Extensible Reporter Pattern**: Output formatting uses a strategy pattern where different reporters (basic, detailed, JSON, PDF) implement the same interface, allowing flexible output generation.

### Data Flow
1. User invokes command → Command parses arguments
2. Engine loads SBOM file(s) → Auto-detects format (SPDX/CycloneDX)
3. Creates internal SBOM representation → Unified model across formats
4. Applies scoring/compliance/analysis → Based on command and flags
5. Generates report via reporter → Formatted output to stdout

### External Integrations
- **Dependency-Track**: Integration via `cmd/dtrackScore.go` and `pkg/engine/dtrack.go`
- **Share Service**: External API for sharing SBOM quality reports (`pkg/share/`)
- **Docker**: Containerized execution support with official image

### Configuration
- Scoring profiles can be customized via YAML configuration files
- Environment variable `INTERLYNK_DISABLE_VERSION_CHECK` disables version checking for air-gapped environments
- The tool respects standard Go build flags and environment variables