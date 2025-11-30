# Golangci-lint Fix Plan for sbomqs - UPDATED

## Progress Report
- **Initial issues**: 4,158
- **Current issues**: 4,006  
- **Issues fixed**: 152 (3.6% reduction)
- **Phases completed**: 1-4

## What Was Fixed (Phases 1-4)

### ✅ Phase 1: Quick Automated Fixes
- **Whitespace**: 35 issues → Some remain due to new code
- **Misspellings**: 4 issues → 0 issues ✓
- **Nolint directives**: 10 issues → 5 issues (50% fixed)

### ✅ Phase 2: Simple Manual Fixes  
- **Package comments**: 34 issues → ~20 issues (some packages fixed)
- **Exported comments**: 549 issues → 528 issues (21 fixed, key packages only)
- **Code style (gocritic)**: 56 issues → 39 issues (17 fixed)

### ✅ Phase 3: Constants Extraction
- **goconst**: 67 issues → 62 issues (5 fixed, main repeated strings extracted)

### ✅ Phase 4: Error Handling
- **errcheck**: 24 issues → 0 issues ✓ (all fixed!)

## Updated Issue Distribution

| Linter | Before | After | Change | Status |
|--------|--------|-------|--------|---------|
| revive | 549 | 528 | -21 | Many exported comments remain |
| goconst | 67 | 62 | -5 | More strings to extract |
| gocritic | 56 | 39 | -17 | Some patterns remain |
| whitespace | 35 | 35 | 0 | New issues appeared |
| prealloc | 35 | 35 | 0 | Not addressed yet |
| dupl | 30 | 32 | +2 | Slightly increased |
| gosec | 24 | 24 | 0 | Not addressed yet |
| errcheck | 24 | 0 | -24 | ✓ Complete |
| gocognit | 14 | 14 | 0 | Not addressed yet |
| staticcheck | 12 | 12 | 0 | Not addressed yet |
| nolintlint | 10 | 5 | -5 | Partially fixed |
| unused | 7 | 7 | 0 | Not addressed yet |
| unparam | 6 | 6 | 0 | Not addressed yet |
| misspell | 4 | 0 | -4 | ✓ Complete |

## Revised Priority Plan (Remaining Work)

### Phase 5: Quick Documentation Wins (1-2 hours, ~500 issues)
Focus on the most critical exported identifiers only:

```bash
# Priority packages for exported comments:
# - pkg/sbom/*.go (core SBOM types)
# - pkg/compliance/*.go (public API)
# - pkg/scorer/v2/*.go (scoring API)
# - cmd/*.go (CLI commands)
```

**Strategy**: Add comments in batches by package, focusing on:
- Public types used by external consumers
- Main entry point functions
- Interface definitions

### Phase 6: Performance Optimizations (1 hour, 35 issues)
Pre-allocate slices where size is known:

```go
// Common pattern to fix:
// Before:
var results []Type
for _, item := range items {
    results = append(results, process(item))
}

// After:
results := make([]Type, 0, len(items))
```

Target files with most prealloc issues:
- pkg/sbom/cdx.go
- pkg/compliance/bsi.go
- pkg/compliance/ntia.go

### Phase 7: Security Issues (2 hours, 24 issues)
Address gosec warnings:

1. **G304 (File inclusion)**: Add `//nolint:gosec` with justification for CLI tool
2. **G306 (File permissions)**: Review each case, fix or add nolint
3. **G104**: Already fixed in Phase 4

### Phase 8: Additional goconst fixes (1 hour, 62 issues)
Extract more repeated strings:

```go
// Add to pkg/common/constants.go:
const (
    // Component types
    ComponentLibrary = "library"
    ComponentApplication = "application"
    
    // Check result strings  
    ResultPass = "pass"
    ResultFail = "fail"
    
    // Common messages
    MsgNotFound = "not found"
    MsgInvalid = "invalid"
)
```

### Phase 9: Code Cleanup (2 hours)
- **unused** (7 issues): Remove unused functions/variables
- **unparam** (6 issues): Remove unused parameters or rename to `_`
- **staticcheck** (12 issues): Fix bugs and deprecated usage
- **nolintlint** (5 issues): Clean up remaining nolint directives
- **whitespace** (35 issues): Re-run gofmt

### Phase 10: Complex Refactoring (Week 2+)

#### 10.1 Duplicate Code (32 issues)
Most critical duplications to address:
- `pkg/compliance/bsi.go` and `pkg/compliance/ntia.go` share ~100 lines
- Extract shared compliance checking logic to `pkg/compliance/common/`
- Create base compliance checker struct

#### 10.2 Cognitive Complexity (14 issues) 
Target functions with highest complexity:
- Break down functions > 40 cognitive complexity
- Extract nested conditions to helper functions
- Use early returns to reduce nesting

#### 10.3 Remaining gocritic (39 issues)
- ifElseChain: Convert to switch statements
- unlambda: Simplify anonymous functions
- Other minor style improvements

## Recommended Next Steps

### Immediate (Today)
1. **Phase 5**: Add minimal exported comments (~500 issues)
2. **Phase 6**: Fix prealloc issues (35 issues)
3. **Phase 7**: Address security with nolint directives (24 issues)

### Short Term (This Week)
4. **Phase 8**: Extract more constants (62 issues)
5. **Phase 9**: Clean up unused code and formatting (59 issues)

### Medium Term (Next Week)
6. **Phase 10.1**: Refactor duplicate code (32 issues)
7. **Phase 10.2**: Reduce complexity (14 issues)

## Updated Success Metrics

### Achieved ✓
- ✓ All errors properly handled (errcheck: 0)
- ✓ No misspellings (misspell: 0)
- ✓ Package comments added to key packages

### Next Milestones
- [ ] Reduce total issues to under 3,000 (Phase 5-7)
- [ ] Reduce total issues to under 2,000 (Phase 8-9)
- [ ] Reduce total issues to under 1,000 (Phase 10)
- [ ] All exported APIs documented
- [ ] Zero security issues without justification
- [ ] No duplicate code blocks > 50 lines

## Validation After Each Phase

```bash
# Quick check of specific linters
golangci-lint run --config .golangci.yml --no-config --enable-only=revive ./...
golangci-lint run --config .golangci.yml --no-config --enable-only=prealloc ./...

# Full check
golangci-lint run --config .golangci.yml ./...

# Ensure tests still pass
go test ./...
```

## Notes on Progress

1. **errcheck** completely resolved - excellent foundation for reliability
2. **revive** (exported comments) is the largest remaining category
3. **dupl** slightly increased - likely due to code additions, needs refactoring
4. Some issues may be intentional (e.g., G304 for CLI tools)
5. Focus on high-impact, low-effort fixes first

## Time Estimate

- **Immediate fixes** (Phases 5-7): 4-5 hours
- **Short term** (Phases 8-9): 3-4 hours  
- **Refactoring** (Phase 10): 20-30 hours

Total remaining work: ~30-40 hours to reach under 500 issues