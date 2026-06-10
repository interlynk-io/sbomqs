# Weightage Scoring Guide

This comprehensive guide explains how to customize SBOMQS scoring using weightage configuration files. With weightage scoring, you can tailor the importance of different categories and features to match your organization's specific SBOM quality requirements.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Configuration File Format](#configuration-file-format)
- [Weightage Rules](#weightage-rules)
- [Examples](#examples)
- [Edge Cases](#edge-cases)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)

## Overview

SBOMQS comprehensive scoring evaluates SBOMs across multiple categories (Identification, Provenance, Integrity, etc.). By default, each category has a predefined weight that contributes to the final quality score.

**Weightage scoring allows you to:**
- Disable categories you don't care about (set weight to 0)
- Increase importance of critical categories
- Focus only on specific aspects of SBOM quality
- Create organization-specific scoring profiles

## Quick Start

### 1. Generate Default Configuration

```bash
sbomqs generate comprehensive > my-weights.yaml
```

This creates a YAML file with all default weights that you can customize.

### 2. Edit Weights

Open `my-weights.yaml` and modify weights:

```yaml
categories:
  - name: "Identification"
    key: "identification"
    weight: 15      # Increased from default 10
    features:
      - name: "Component With Name"
        key: "comp_with_name"
        weight: 0.50  # Increased from default 0.40
```

### 3. Run Scoring

```bash
sbomqs score --configpath my-weights.yaml my-sbom.json
```

## Configuration File Format

### Structure

```yaml
metadata:
  version: "2.0.0"
  description: "Custom scoring weights"
  last_updated: "2026-06-10"

categories:
  - name: "Category Name"
    key: "category_key"
    weight: <number>        # Category weight
    features:
      - name: "Feature Name"
        key: "feature_key"
        weight: <number>    # Feature weight (0.0-1.0)
        ignore: <boolean>   # Skip this feature
```

### Available Categories and Keys

| Category | Key | Default Weight |
|----------|-----|----------------|
| Identification | `identification` | 10 |
| Provenance | `provenance` | 12 |
| Integrity | `integrity` | 15 |
| Completeness | `completeness` | 12 |
| Licensing | `licensing_and_compliance` | 15 |
| Vulnerability | `vulnerability_and_traceability` | 10 |
| Structural | `structural` | 8 |
| Component Quality | `compinfo` | 10 |

### Category Feature Keys

#### Identification
- `comp_with_name` - Component has a name
- `comp_with_version` - Component has a version
- `comp_with_local_id` - Component has local identifiers

#### Provenance
- `sbom_creation_timestamp` - Document creation time
- `sbom_authors` - Document authors
- `sbom_tool_version` - Creator tool & version
- `sbom_supplier` - Document supplier
- `sbom_namespace` - Document URI/Namespace
- `sbom_lifecycle` - Document lifecycle

#### Integrity
- `comp_with_strong_checksums` - Component with SHA256+ checksums
- `comp_with_weak_checksums` - Component with weak checksums
- `sbom_signature` - Document signature

#### Completeness
- `comp_with_dependencies` - Component dependencies defined
- `sbom_completeness_declared` - Declared completeness
- `sbom_primary_component` - Primary component identified
- `comp_with_source_code` - Source code location
- `comp_with_supplier` - Component supplier
- `comp_with_purpose` - Component purpose/type

#### Licensing
- `comp_with_licenses` - Components have licenses
- `comp_with_valid_licenses` - Valid license identifiers
- `comp_no_deprecated_licenses` - No deprecated licenses
- `comp_no_restrictive_licenses` - No restrictive licenses
- `comp_with_declared_licenses` - Declared/original licenses
- `sbom_data_license` - Document data license

#### Vulnerability
- `comp_with_purl` - Components have PURL
- `comp_with_cpe` - Components have CPE
- `comp_with_purl_or_cpe` - Either PURL or CPE

#### Structural
- `sbom_spec_declared` - SBOM spec declared
- `sbom_spec_version` - Spec version identified
- `sbom_file_format` - File format (JSON/XML)
- `sbom_schema_valid` - Schema validation passed

## Weightage Rules

### How Weights Work

**Category Weights:**
- Categories with `weight: 0` are completely excluded
- Higher category weights increase their contribution to the final score
- The final score is calculated as a weighted average: `Σ(category_score × category_weight) / Σ(category_weight)`

**Feature Weights:**
- Feature weights are relative within a category (should sum to 1.0)
- Features marked `ignore: true` are skipped entirely
- Features are weighted within their category to produce the category score

### Score Calculation Example

With this configuration:
```yaml
categories:
  - name: "Licensing"
    weight: 15
    features:
      - weight: 0.4  # 40% of licensing score
      - weight: 0.6  # 60% of licensing score
  - name: "Structural"
    weight: 8
    features:
      - weight: 1.0  # 100% of structural score
```

Calculation:
- Total category weight: 15 + 8 = 23
- Licensing contributes: 15/23 = 65.2%
- Structural contributes: 8/23 = 34.8%
- Final score: `(licensing_score × 0.652) + (structural_score × 0.348)`

## Examples

### Example 1: Focus on Licensing Only

Only evaluate licensing compliance:

```yaml
metadata:
  version: "2.0.0"
  description: "Licensing-only scoring"

categories:
  - name: "Licensing"
    key: "licensing_and_compliance"
    weight: 15
    features:
      - name: "Components With Licenses"
        key: "comp_with_licenses"
        weight: 0.20
      - name: "Component With Valid Licenses"
        key: "comp_with_valid_licenses"
        weight: 0.30
      - name: "Component Without Deprecated Licenses"
        key: "comp_no_deprecated_licenses"
        weight: 0.25
      - name: "Component Without Restrictive Licenses"
        key: "comp_no_restrictive_licenses"
        weight: 0.25
```

**Result:** Only Licensing category appears in output.

### Example 2: Exclude Specific Categories

Evaluate everything except Component Quality:

```yaml
categories:
  - name: "Identification"
    key: "identification"
    weight: 10
    features:
      - key: comp_with_name
        weight: 0.40
      - key: comp_with_version
        weight: 0.35
      - key: comp_with_local_id
        weight: 0.25
  - name: "Provenance"
    key: "provenance"
    weight: 12
    features: ...
  # ... other categories ...
  # Component Quality omitted entirely
```

**Result:** Component Quality is not evaluated or displayed.

### Example 3: Custom Weights

Prioritize structural integrity and licensing:

```yaml
categories:
  - name: "Structural"
    key: "structural"
    weight: 20      # Increased importance
    features:
      - key: sbom_spec_declared
        weight: 0.30
      - key: sbom_spec_version
        weight: 0.30
      - key: sbom_file_format
        weight: 0.20
      - key: sbom_schema_valid
        weight: 0.20
  
  - name: "Licensing"
    key: "licensing_and_compliance"
    weight: 20      # Increased importance
    features: ...
  
  - name: "Identification"
    key: "identification"
    weight: 5       # Reduced importance
    features: ...
  
  - name: "Vulnerability"
    key: "vulnerability_and_traceability"
    weight: 0       # Disabled
    features: ...
```

### Example 4: Skip Specific Features

Evaluate Identification but skip version checking:

```yaml
categories:
  - name: "Identification"
    key: "identification"
    weight: 10
    features:
      - name: "Component With Name"
        key: "comp_with_name"
        weight: 0.60  # Increased since version is ignored
      - name: "Component With Version"
        key: "comp_with_version"
        weight: 0.35
        ignore: true  # Skip this feature
      - name: "Component With Local IDs"
        key: "comp_with_local_id"
        weight: 0.40
```

**Result:** Version checking is skipped; name and ID contribute to category score.

## Edge Cases

### Case 1: All Categories Weight = 0

```yaml
categories:
  - name: "Identification"
    weight: 0
  - name: "Structural"
    weight: 0
```

**Result:** Score 0.0/10.0, no categories displayed. Total weight is 0.

### Case 2: Category Weight > 0 but All Features Ignored

```yaml
categories:
  - name: "Identification"
    weight: 10
    features:
      - key: comp_with_name
        ignore: true
      - key: comp_with_version
        ignore: true
```

**Result:** Category is excluded (no features to evaluate).

### Case 3: Mix of Ignored and Non-Ignored Features

```yaml
categories:
  - name: "Identification"
    weight: 10
    features:
      - key: comp_with_name
        weight: 0.40
        ignore: false
      - key: comp_with_version
        weight: 0.35
        ignore: true
      - key: comp_with_local_id
        weight: 0.25
        ignore: true
```

**Result:** Only `comp_with_name` is evaluated and displayed.

### Case 4: Features with Zero Weight

```yaml
categories:
  - name: "Identification"
    weight: 10
    features:
      - key: comp_with_name
        weight: 0
      - key: comp_with_version
        weight: 1.0
```

**Result:** Features with weight 0 are evaluated but contribute 0% to category score.

### Case 5: Empty Features List

```yaml
categories:
  - name: "Empty Category"
    weight: 10
    features: []
```

**Result:** Category is excluded (no features to evaluate).

### Case 6: Single Category

```yaml
categories:
  - name: "Structural"
    weight: 8
    features:
      - key: sbom_spec_declared
        weight: 0.30
```

**Result:** Category shown with 100% weight contribution.

## Validation

SBOMQS validates your configuration and provides clear error messages:

### Negative Weights

```yaml
categories:
  - name: "Identification"
    weight: -5
```

**Error:** `invalid weight -5.00 for category "Identification": weights must be non-negative`

### Negative Feature Weights

```yaml
categories:
  - name: "Identification"
    weight: 10
    features:
      - name: "Component With Name"
        weight: -0.5
```

**Error:** `invalid weight -0.50 for feature "Component With Name" in category "Identification": weights must be non-negative`

## Troubleshooting

### Issue: Category Not Appearing in Output

**Possible Causes:**
1. Category weight is 0
2. All features in category are marked `ignore: true`
3. Features list is empty

**Solution:** Check weight and ignore settings in your configuration.

### Issue: Feature Percentage Shows 0%

**Cause:** Feature weight is 0 within the category.

**Solution:** Increase feature weight or check your configuration.

### Issue: Total Category Weight Shows Negative or Weird Percentages

**Cause:** Negative weights in configuration.

**Solution:** Ensure all weights are non-negative (≥ 0).

### Issue: Config File Not Loading

**Causes:**
1. File path is incorrect
2. YAML syntax error
3. Missing required fields

**Solution:** Validate YAML syntax and check file path.

## Best Practices

1. **Start with defaults:** Generate default config and modify incrementally
2. **Document your changes:** Add comments explaining why weights were changed
3. **Version your configs:** Include version in metadata for tracking
4. **Test thoroughly:** Validate configs with sample SBOMs before deployment
5. **Keep feature weights balanced:** Feature weights within a category should ideally sum to 1.0
6. **Use meaningful descriptions:** Help your team understand the scoring rationale

## See Also

- [Customization Guide](./customization.md) - General customization options
- [Command Reference](../commands/score.md) - Score command documentation
- [Getting Started](../getting-started.md) - Basic usage guide
