# SBOM Policy Examples

This directory contains comprehensive policy examples for the `sbomqs policy` command. These policies demonstrate various use cases from license compliance to security enforcement.

## Quick Start

```bash
# Run a policy against an SBOM
sbomqs policy -f testdata/policy/license-allowlist.yaml my-sbom.cdx.json

# Use table output for detailed results
sbomqs policy -f testdata/policy/security-ban-vulnerables.yaml my-sbom.cdx.json -o table

# Multiple policies at once
sbomqs policy -f testdata/policy/license-allowlist.yaml -f testdata/policy/security-required-fields.yaml my-sbom.cdx.json
```

## Policy Categories

### 1. License Compliance

Policies for enforcing license compliance in your organization.

| Policy | Description | Use Case |
|--------|-------------|----------|
| `license-allowlist.yaml` | Only permits OSI-approved permissive licenses | Commercial products, distribution |
| `license-block-copyleft.yaml` | Blocks all GPL variants | Proprietary software development |
| `license-block-proprietary.yaml` | Blocks custom/proprietary licenses | Open source projects |
| `license-dual-check.yaml` | Requires both declared and concluded licenses | High-compliance environments |

### 2. Security

Policies for preventing security risks and vulnerabilities.

| Policy | Description | Use Case |
|--------|-------------|----------|
| `security-ban-vulnerables.yaml` | Blocks known vulnerable package versions | Production deployments |
| `security-required-fields.yaml` | Requires checksums, PURLs, versions | Supply chain security |
| `security-no-snapshots.yaml` | Blocks SNAPSHOT/pre-release versions | Stable releases |
| `security-verified-sources.yaml` | Requires source code URLs and hashes | Reproducible builds |

### 3. Metadata Quality

Policies for ensuring SBOM completeness and quality.

| Policy | Description | Use Case |
|--------|-------------|----------|
| `metadata-required.yaml` | Requires all basic metadata fields | SBOM completeness checks |
| `metadata-provenance.yaml` | Requires author, supplier, timestamp | Audit trails |
| `metadata-identifiers.yaml` | Requires PURL or CPE for all components | Vulnerability scanning |

### 4. Enterprise/Organizational

Policies for organizational governance.

| Policy | Description | Use Case |
|--------|-------------|----------|
| `enterprise-approved-suppliers.yaml` | Whitelist approved vendors | Vendor management |
| `enterprise-complete-sbom.yaml` | Comprehensive production-ready SBOM | Release gates |

### 5. Industry-Specific

Policies tailored to specific industry requirements.

| Policy | Description | Use Case |
|--------|-------------|----------|
| `industry-finance-compliance.yaml` | Finance sector requirements | Banking, fintech |

### 6. Community/Open Source

Policies for open source project health and distribution.

| Policy | Description | Use Case |
|--------|-------------|----------|
| `open-source-distribution.yaml` | Ensures OSS compliance before publishing | Open source releases |
| `community-health.yaml` | Checks OSI-approved licenses and provenance | Community projects |

### 7. Advanced/Multi-Policy

Complex policies combining multiple rules.

| Policy | Description | Use Case |
|--------|-------------|----------|
| `advanced-comprehensive.yaml` | All compliance checks combined | Ultimate compliance gate |

## Testing Policies

### Using Provided Test SBOMs

A dedicated test SBOMs directory is provided for validating policies:

```bash
# Test license policies
sbomqs policy -f testdata/policy/license-allowlist.yaml testdata/sboms/license-allowlist-violations.cdx.json
sbomqs policy -f testdata/policy/license-block-copyleft.yaml testdata/sboms/license-block-copyleft-violations.cdx.json

# Test security policies
sbomqs policy -f testdata/policy/security-ban-vulnerables.yaml testdata/sboms/security-ban-vulnerables-violations.cdx.json
sbomqs policy -f testdata/policy/security-required-fields.yaml testdata/sboms/security-required-fields-violations.cdx.json

# Test metadata policies
sbomqs policy -f testdata/policy/metadata-required.yaml testdata/sboms/metadata-required-violations.cdx.json
sbomqs policy -f testdata/policy/metadata-provenance.yaml testdata/sboms/metadata-provenance-violations.cdx.json

# Test comprehensive policy
sbomqs policy -f testdata/policy/advanced-comprehensive.yaml testdata/sboms/advanced-comprehensive-violations.cdx.json
```