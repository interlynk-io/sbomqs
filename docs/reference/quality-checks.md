# SBOM Quality Checks Reference

This reference document describes all quality checks performed by sbomqs, organized by category.

## Check Categories

- **NTIA-minimum-elements**: Compliance with NTIA's minimum element guidelines
- **Structural**: SBOM format and specification compliance
- **Semantic**: Correctness and validity of SBOM field meanings
- **Quality**: Data completeness and accuracy metrics
- **Sharing**: Distribution and consumption readiness
- **BSI**: German BSI TR-03183-2 compliance checks

## Scoring Methodology

- Each quality check has equal weight with a score range of 0.0 - 10.0
- Checks applied to lists average scores across all elements
- Category scores are averaged across all checks in that category
- Overall score is the weighted average of all enabled categories

## Quality Checks by Category

### NTIA Minimum Elements

| Check ID | Description | Required |
|----------|-------------|----------|
| `comp_with_name` | Components have names | Yes |
| `comp_with_supplier` | Components have supplier names | Yes |
| `comp_with_uniq_ids` | Components have unique identifiers | Yes |
| `comp_with_version` | Components have versions | Yes |
| `sbom_authors` | SBOM has author information | Yes |
| `sbom_creation_timestamp` | SBOM has creation timestamp | Yes |
| `sbom_dependencies` | Dependencies are documented | Yes |

### Structural Checks

| Check ID | Description | Impact |
|----------|-------------|---------|
| `spec_compliant` | Valid SPDX/CycloneDX specification | Critical |
| `spec_parsable` | SBOM can be parsed without errors | Critical |
| `spec_file_format` | Supported file format (JSON, XML, etc.) | High |
| `sbom_required_fields` | All required spec fields present | High |

### Semantic Checks

| Check ID | Description | Impact |
|----------|-------------|---------|
| `comp_valid_licenses` | Valid SPDX license identifiers | High |
| `comp_with_checksums` | Components have integrity checksums | Medium |
| `comp_with_primary_purpose` | Component type/purpose specified | Low |
| `sbom_with_primary_component` | Primary component identified | Medium |

### Quality Checks

| Check ID | Description | Impact |
|----------|-------------|---------|
| `comp_with_cpes` | CPE identifiers for vulnerability lookup | High |
| `comp_with_purls` | Package URLs for ecosystem identification | High |
| `comp_with_multi_vuln_lookup_id` | Multiple vulnerability identifiers | Medium |
| `comp_with_source_code_uri` | Source code repository links | Medium |
| `comp_with_executable_uri` | Binary/executable download locations | Low |
| `comp_no_deprecated_licenses` | No deprecated license usage | Medium |
| `comp_no_restrictive_licenses` | No highly restrictive licenses | Medium |

### Sharing Checks

| Check ID | Description | Impact |
|----------|-------------|---------|
| `sbom_sharable` | SBOM has unencumbered license | High |
| `sbom_with_uri` | SBOM has unique identifier/namespace | Medium |

## Component-Based Features

Features that evaluate individual components:

- `comp_with_name`: Component has a name
- `comp_with_version`: Component has a version
- `comp_with_supplier`: Component has supplier information
- `comp_with_uniq_ids`: Component has unique identifiers
- `comp_valid_licenses`: Valid SPDX licenses
- `comp_with_any_vuln_lookup_id`: CPE or PURL present
- `comp_with_deprecated_licenses`: Uses deprecated licenses
- `comp_with_multi_vuln_lookup_id`: Both CPE and PURL present
- `comp_with_primary_purpose`: Component purpose specified
- `comp_with_restrictive_licenses`: Uses restrictive licenses
- `comp_with_checksums`: Has integrity checksums
- `comp_with_licenses`: Has license information
- `comp_with_checksums_sha256`: SHA-256 checksum present
- `comp_with_source_code_uri`: Source repository link
- `comp_with_source_code_hash`: Source code integrity hash
- `comp_with_executable_uri`: Binary download location
- `comp_with_associated_license`: Associated license present
- `comp_with_concluded_license`: Concluded license specified
- `comp_with_declared_license`: Declared license specified

## SBOM-Based Features

Features that evaluate document-level properties:

- `sbom_creation_timestamp`: Creation timestamp present
- `sbom_authors`: Author information included
- `sbom_with_creator_and_version`: Creator tool and version
- `sbom_with_primary_component`: Primary component identified
- `sbom_dependencies`: Dependency relationships documented
- `sbom_sharable`: Has shareable license
- `sbom_parsable`: Can be parsed successfully
- `sbom_spec`: Valid specification format
- `sbom_spec_file_format`: Supported file format
- `sbom_spec_version`: Specification version
- `spec_with_version_compliant`: Version compliance
- `sbom_with_uri`: Has unique URI/namespace
- `sbom_with_vuln`: Contains vulnerability data
- `sbom_build_process`: Build process documented
- `sbom_with_bomlinks`: External SBOM references

## Remediation Guidelines

### Critical Issues (Fix Immediately)
1. Missing component versions - Required for vulnerability scanning
2. No unique identifiers - Prevents component tracking
3. Invalid specification format - Blocks SBOM usage

### High Priority Issues
1. Missing supplier information - Supply chain transparency
2. No license information - Legal compliance risk
3. Missing checksums - Integrity verification

### Medium Priority Issues
1. No CPE/PURL identifiers - Limited vulnerability matching
2. Missing dependency relationships - Incomplete understanding
3. No source code links - Reduced transparency

### Low Priority Issues
1. Missing build information - Process documentation
2. No external references - Limited context
3. Component purpose not specified - Usage clarity

## Custom Configuration

To customize which checks are performed, generate a configuration file:

```bash
sbomqs generate features > custom-checks.yaml
```

Edit the file to enable/disable specific checks and adjust weights, then use:

```bash
sbomqs score sbom.json --configpath custom-checks.yaml
```

## See Also

- [Compliance Standards Reference](./compliance-standards.md) - Detailed compliance mappings
- [Score Command](../commands/score.md) - How to run quality checks
- [Customization Guide](../guides/customization.md) - Creating custom profiles