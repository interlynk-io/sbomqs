# Golangci-lint Fix Plan for sbomqs

## Summary
Total issues found: 4,158
Configuration file: `.golangci.yml`

## Issue Distribution by Linter
- **revive**: 549 issues (mostly missing comments and naming)
- **goconst**: 67 issues (repeated strings)
- **gocritic**: 56 issues (code style improvements)
- **whitespace**: 35 issues (formatting)
- **prealloc**: 35 issues (performance)
- **dupl**: 30 issues (duplicate code)
- **gosec**: 24 issues (security)
- **errcheck**: 24 issues (unchecked errors)
- **gocognit**: 14 issues (complexity)
- **staticcheck**: 12 issues (bugs/issues)
- **nolintlint**: 10 issues (incorrect nolint directives)
- **unused**: 7 issues (unused code)
- **unparam**: 6 issues (unused parameters)
- **misspell**: 4 issues (typos)
- **unconvert**: 2 issues (unnecessary conversions)
- **nilerr**: 1 issue (nil error handling)
- **govet**: 1 issue (suspicious constructs)

## Fix Priority (Easiest to Hardest)

### Phase 1: Quick Automated Fixes (1-2 hours)
These can be fixed with simple find/replace or automated tools:

#### 1.1 Whitespace Issues (35 issues)
**Command to fix automatically:**
```bash
# Remove trailing/leading newlines
find . -name "*.go" -not -path "./vendor/*" -exec sed -i '' 's/[ \t]*$//' {} \;
gofmt -w .
```

#### 1.2 Misspellings (4 issues)
**Command to fix:**
```bash
misspell -w .
```

#### 1.3 Nolint Directives (10 issues)
**Pattern to fix:**
- Change `// nolint` to `//nolint` (remove space)
- Remove unused `//nolint:gosec` directives
**Example fix:**
```go
// Before: // nolint:gosec
// After:  //nolint:gosec
```

### Phase 2: Simple Manual Fixes (2-4 hours)
These require simple, repetitive changes:

#### 2.1 Package Comments (34 issues)
**Fix pattern for each package:**
```go
// Package cpe provides CPE (Common Platform Enumeration) validation and handling.
package cpe

// Package logger provides structured logging capabilities for the sbomqs application.
package logger
```

#### 2.2 Exported Type/Function Comments (500+ issues)
**Fix pattern:**
```go
// CPE represents a Common Platform Enumeration identifier.
type CPE string

// Valid checks if the CPE string is valid.
func (cpe CPE) Valid() bool {

// NewCPE creates a new CPE instance from a string.
func NewCPE(cpe string) CPE {
```

#### 2.3 Simple Code Style Issues (56 gocritic issues)
**Common patterns:**
```go
// sloppyLen: len(x) <= 0 → len(x) == 0
if len(args) <= 0 { → if len(args) == 0 {

// assignOp: x = x + y → x += y  
sectionID = sectionID + "*" → sectionID += "*"

// unlambda: func(x Type) bool { return simple } → simpleExpression
filter := func(c sbom.GetComponent) bool { return c.GetID() == id }
// Replace with direct comparison where possible
```

### Phase 3: Constants Extraction (67 issues)
Create constants for repeated strings:

#### 3.1 Create a constants file
**File: `pkg/common/constants.go`**
```go
package common

const (
    // SBOM format types
    FormatSPDX     = "spdx"
    FormatCycloneDX = "cyclonedx"
    FormatJSON     = "json"
    
    // Report types
    ReportBasic    = "basic"
    ReportDetailed = "detailed"
    
    // Version strings
    Version16      = "1.6"
)
```

### Phase 4: Error Handling (24 issues)
Add proper error checking:

#### 4.1 File Close Errors
```go
// Before:
defer f.Close()

// After:
defer func() {
    if err := f.Close(); err != nil {
        log.Warnf("failed to close file: %v", err)
    }
}()
```

#### 4.2 HTTP Response Body Close
```go
// Before:
defer resp.Body.Close()

// After:
defer func() {
    if err := resp.Body.Close(); err != nil {
        log.Debugf("failed to close response body: %v", err)
    }
}()
```

### Phase 5: Performance Optimizations (35 issues)
Pre-allocate slices where size is known:

```go
// Before:
var results []string
for _, item := range items {
    results = append(results, process(item))
}

// After:
results := make([]string, 0, len(items))
for _, item := range items {
    results = append(results, process(item))
}
```

### Phase 6: Security Issues (24 issues)
Address gosec warnings:

#### 6.1 File Permissions (G306)
```go
// Before:
os.WriteFile(path, data, 0644)

// After:
os.WriteFile(path, data, 0600) // or 0644 with //nolint:gosec if intended
```

#### 6.2 File Inclusion (G304)
```go
// Add validation or use //nolint:gosec with justification
// #nosec G304 - User-provided paths are expected for CLI tool
content, err := os.ReadFile(userPath)
```

### Phase 7: Complex Refactoring (30+ hours)

#### 7.1 Duplicate Code (30 issues)
- Extract common functions for BSI and NTIA compliance checks
- Create shared utility functions for repeated patterns
- Consider creating interfaces for common behaviors

#### 7.2 Cognitive Complexity (14 issues)
- Break down complex functions into smaller, focused functions
- Extract conditional logic into separate methods
- Consider using strategy pattern for complex switch statements

#### 7.3 Unused Parameters (6 issues)
- Review function signatures and remove unused parameters
- Or rename to `_` if required by interface

## Recommended Approach

### Step 1: Quick Wins (Day 1)
```bash
# Fix whitespace
gofmt -w .

# Fix misspellings
misspell -w .

# Run tests to ensure nothing broke
go test ./...
```

### Step 2: Documentation Sprint (Day 2-3)
- Add package comments to all packages
- Add comments to exported types and functions
- Focus on public API documentation first

### Step 3: Code Quality (Day 4-5)
- Fix gocritic issues (simple refactoring)
- Extract constants for repeated strings
- Fix error handling issues

### Step 4: Performance & Security (Day 6)
- Add slice pre-allocation
- Address security issues with proper validation or nolint directives

### Step 5: Major Refactoring (Week 2+)
- Address duplicate code issues
- Refactor complex functions
- Review and optimize interfaces

## Validation Commands

After each phase, validate fixes:
```bash
# Check specific linter
golangci-lint run --disable-all --enable=revive ./...

# Run full lint
golangci-lint run --config .golangci.yml ./...

# Run tests
go test -race ./...

# Check build
go build ./...
```

## CI Integration

Once issues are reduced to manageable level, add to CI:
```yaml
# .github/workflows/lint.yml
- name: golangci-lint
  uses: golangci/golangci-lint-action@v3
  with:
    version: v2.6.2
    args: --config .golangci.yml --timeout 5m
```

## Tracking Progress

Create issues for each phase:
- [ ] Phase 1: Automated fixes (whitespace, spelling, nolint)
- [ ] Phase 2: Add missing documentation
- [ ] Phase 3: Extract constants
- [ ] Phase 4: Fix error handling
- [ ] Phase 5: Performance optimizations
- [ ] Phase 6: Security fixes
- [ ] Phase 7: Refactor duplicate code
- [ ] Phase 8: Reduce complexity

## Notes

1. Some issues may be false positives or intentional design choices
2. Use `//nolint:lintername` with explanation for legitimate exceptions
3. Consider adjusting linter settings if too strict for project needs
4. Focus on new code quality while gradually improving existing code
5. The G304 (file inclusion) warnings are expected for a CLI tool that processes user-provided files

## Success Metrics

- Reduce total issues from 4,158 to under 500 in first pass
- Zero critical security issues without valid justification
- All exported APIs documented
- No unchecked errors in critical paths
- Complexity scores under thresholds (cognitive: 40, cyclomatic: 20)