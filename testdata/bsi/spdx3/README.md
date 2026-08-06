# BSI TR-03183-2 v2.1.0 — SPDX 3.0 Test Data

This directory contains **clean, deterministic SPDX 3.0 JSON-LD test files** for the BSI v2.1.0 profile.

## Design Philosophy

Every test file follows a strict **"minimal base + one isolated field"** pattern:

- **Two components** in every file: a **primary component** and its **dependency**.
- **Component A (Primary)** is always **fully populated** with all required, additional, and optional fields.
- **Component B (Dependency)** is also fully populated **except** for the one specific field being tested.
- This means each file simultaneously shows:
  - ✅ What the field looks like when **present** (on Component A)
  - ❌ What the field looks like when **missing** (on Component B)

For **document-level fields**, both components remain fully populated; only the document-level field is removed.

## File Inventory

### Core Reference Files

| File | Description |
|------|-------------|
| `v2.1.0-minimal-valid.json` | Absolute minimum valid SBOM (1 component, required fields only) |
| `v2.1.0-complete-all-fields.json` | Golden reference: 2 fully populated components with **all** required, additional, and optional fields (uses primary/standard representations) |
| `v2.1.0-complete-alt-patterns.json` | Alternative-patterns reference: same coverage as above, but uses **only** the alternative representations for fields that support multiple SPDX 3.0 patterns |

### Component Field Tests (`two-comps-one-with-*`)

Each file tests **one** component-level field. Component A has it; Component B is missing it.

| File | Field Tested | Component A | Component B |
|------|-------------|-------------|-------------|
| `v2.1.0-two-comps-one-with-filename.json` | `comp_filename` | `File.name` present | `File.name` key removed |
| `v2.1.0-two-comps-one-with-deployable-hash.json` | `comp_deployable_hash` | `File.verifiedUsing` present | `File.verifiedUsing` key removed |
| `v2.1.0-two-comps-one-with-executable-prop.json` | `comp_executable_prop` | `additionalPurpose: ["executable", "archive", "container"]` | `"executable"` removed from array |
| `v2.1.0-two-comps-one-with-archive-prop.json` | `comp_archive_prop` | `additionalPurpose: ["executable", "archive", "container"]` | `"archive"` removed from array |
| `v2.1.0-two-comps-one-with-structured-prop.json` | `comp_structured_prop` | `additionalPurpose: ["executable", "archive", "container"]` | `"container"` removed from array |
| `v2.1.0-two-comps-one-with-concluded-license.json` | `comp_distribution_license` | `hasConcludedLicense` relationship present | Relationship removed |
| `v2.1.0-two-comps-one-with-declared-license.json` | `comp_original_licenses` | `hasDeclaredLicense` relationship present | Relationship removed |
| `v2.1.0-two-comps-one-with-effective-license.json` | `comp_effective_license` | `other` + `comment: "hasEffectiveLicense"` present | Relationship removed |
| `v2.1.0-two-comps-one-with-purl-cpe.json` | `comp_other_identifiers` | `externalIdentifiers` (PURL + CPE) present | Key removed |
| `v2.1.0-two-comps-one-with-download-url.json` | `comp_download_url` | `software_downloadLocation` present | Key removed |
| `v2.1.0-two-comps-one-with-source-code-url.json` | `comp_source_code_url` | `software_SoftwareArtifact.externalRef` present | Key removed |
| `v2.1.0-two-comps-one-with-source-code-hash.json` | `comp_source_code_hash` | `software_SoftwareArtifact.verifiedUsing` present | Key removed |
| `v2.1.0-two-comps-one-with-security-txt-url.json` | `comp_security_txt_url` | `externalRef` (type `securityOther`) present | Key removed |
| `v2.1.0-two-comps-one-with-dependencies.json` | `comp_dependencies` | `dependsOn` relationship present | Relationship removed |
| `v2.1.0-two-comps-one-with-creator.json` | `comp_creator` | `originatedBy` present | Key removed |

### Document Field Tests (`doc-missing-*`)

Each file tests **one** document-level field. Both components are fully populated; the document field is missing.

| File | Field Tested | Modification |
|------|-------------|--------------|
| `v2.1.0-doc-missing-creator.json` | `sbom_creator` | `Person.externalIdentifiers` removed from `_:author` |
| `v2.1.0-doc-missing-timestamp.json` | `sbom_timestamp` | `CreationInfo.created` key removed |
| `v2.1.0-doc-missing-spec-version.json` | `sbom_spec_version` | `CreationInfo.specVersion` key removed |
| `v2.1.0-doc-missing-sbom-uri.json` | `sbom_uri` | `SpdxDocument.spdxId` changed from URL to `SPDXRef-DOCUMENT` |

## Alternative Patterns Reference (`v2.1.0-complete-alt-patterns.json`)

Some BSI fields can be represented in SPDX 3.0 via **multiple equivalent patterns**. `sbomqs` supports both, but typically prioritizes the primary one. The alternative-patterns file ensures the secondary code paths are also covered.

| BSI Field | Primary Pattern (in `complete-all-fields.json`) | Alternative Pattern (in `complete-alt-patterns.json`) |
|-----------|--------------------------------------------------|------------------------------------------------------|
| **SBOM URI** | `SpdxDocument.spdxId` as a URL | `SpdxDocument.namespaceMap[].namespace` |
| **SBOM Creator** | `Person.externalIdentifiers` with `email` | `Person.externalIdentifiers` with `urlScheme` |
| **Component Creator** | `Organization.externalIdentifiers` with `email` | `Organization.externalIdentifiers` with `urlScheme` |
| **Source Code URI** | `software_Package.software_sourceInfo` | `software_SoftwareArtifact` + `generates` + `externalRef` (`SourceArtifact`) |
| **Download URI** | `software_Package.software_downloadLocation` | `software_File` + `hasDistributionArtifact` + `externalRef` (`binaryArtifact`) |

Both `complete-all-fields.json` and `complete-alt-patterns.json` score **10.0/10.0**, confirming that `sbomqs` correctly handles both representations.

## SPDX 3.0 JSON-LD Structure

### Shared Elements

Every `two-comps-*` and `doc-missing-*` file contains:

1. **SpdxDocument** — `spdxId` as URL (for SBOM URI in primary files) or `namespaceMap` (in alt-patterns file), references all elements
2. **CreationInfo** — `specVersion`, `created`, `createdBy`
3. **Person** — Author with `externalIdentifiers` (`email` in primary files, `urlScheme` in alt-patterns file)
4. **Organization** — Supplier with `externalIdentifiers` (`email` in primary files, `urlScheme` in alt-patterns file)

### Component A (Primary)

- `software_Package` — `SPDXRef-Package-A`
- `software_File` — `SPDXRef-File-A` (distribution artifact)
- `software_SoftwareArtifact` — `SPDXRef-Source-A` (source artifact)
- 3× `simpleLicensing_LicenseExpression` — declared, concluded, effective
- Relationships: `describes`, `hasDistributionArtifact`, `hasDeclaredLicense`, `hasConcludedLicense`, `hasEffectiveLicense`, `dependsOn`, `generates`

### Component B (Dependency)

- `software_Package` — `SPDXRef-Package-B`
- `software_File` — `SPDXRef-File-B` (distribution artifact)
- `software_SoftwareArtifact` — `SPDXRef-Source-B` (source artifact)
- 3× `simpleLicensing_LicenseExpression` — declared, concluded, effective
- Relationships: `hasDistributionArtifact`, `hasDeclaredLicense`, `hasConcludedLicense`, `hasEffectiveLicense`, `dependsOn` (empty), `generates`

## Mapping Notes (BSI TR-03183-2 v2.1.0 §8.2)

### Required Fields

| BSI Field | SPDX 3.0 Representation |
|-----------|----------------------|
| Creator | `CreationInfo.createdBy` → `Person`/`Organization` with `externalIdentifiers` (`email` or `urlScheme`) |
| Timestamp | `CreationInfo.created` |
| SBOM URI | `SpdxDocument.spdxId` as URL, or `SpdxDocument.namespaceMap[].namespace` |
| Component creator | `software_Package.originatedBy` → `Person`/`Organization` with `externalIdentifiers` |
| Component name | `software_Package.name` |
| Component version | `software_Package.software_packageVersion` |
| Filename | `hasDistributionArtifact` → `software_File.name` |
| Dependencies | `dependsOn` relationship |
| Distribution license | `hasConcludedLicense` relationship → `simpleLicensing_LicenseExpression` |
| Deployable hash | `software_File.verifiedUsing` (`Hash` with `sha512`) |
| Executable/Archive/Structured | `software_File.software_additionalPurpose` array |

### Additional Fields

| BSI Field | Primary SPDX 3.0 Representation | Alternative SPDX 3.0 Representation |
|-----------|--------------------------------|-----------------------------------|
| Source code URI | `software_Package.software_sourceInfo` | `software_SoftwareArtifact` + `generates` + `externalRef` (type `SourceArtifact`) |
| Download URI | `software_Package.software_downloadLocation` | `software_File` + `hasDistributionArtifact` + `externalRef` (type `binaryArtifact`) |
| Other identifiers | `software_Package.externalIdentifiers` (PURL, CPE22, CPE23, SWID) | — |
| Original license | `hasDeclaredLicense` relationship | — |

### Optional Fields

| BSI Field | SPDX 3.0 Representation |
|-----------|----------------------|
| Effective license | `Relationship` with `relationshipType: "other"` + `comment: "hasEffectiveLicense"` |
| Source code hash | `software_SoftwareArtifact.verifiedUsing` (`Hash` with `sha512`) |
| Security.txt URL | `software_Package.externalRef` with `externalRefType: "securityOther"` |
| SBOM URI | `SpdxDocument.spdxId` as a valid URL |
| BOM links | `SpdxDocument.import` / `ExternalMap` with `locationHint` |

## Test Commands

```bash
# Score the golden reference
sbomqs score --profile bsi-v2.1 testdata/bsi/spdx3/v2.1.0-complete-all-fields.json

# Score a specific component field test
sbomqs score --profile bsi-v2.1 testdata/bsi/spdx3/v2.1.0-two-comps-one-with-filename.json

# Score a document field test
sbomqs score --profile bsi-v2.1 testdata/bsi/spdx3/v2.1.0-doc-missing-creator.json
```

## Validation Results

All files were validated against `sbomqs` built from the current source tree (`bsi-v2.1` profile). Both `score` and `compliance` commands were run.

### Core Reference

| File | Overall Score | Note |
|------|--------------|------|
| `v2.1.0-complete-all-fields.json` | **10.0/10.0** | All required, additional, and optional fields present on both components (primary patterns) |
| `v2.1.0-complete-alt-patterns.json` | **10.0/10.0** | Same coverage using alternative SPDX 3.0 representations only |
| `v2.1.0-minimal-valid.json` | **3.3/10.0** | Only required fields present (1 component) |

### Component Field Tests (`two-comps-one-with-*`)

Files with a required or additional field missing on Component B score **~9.7/10.0** (field shows `5.0/10.0` for 1/2 components). Optional fields show the same partial component score but do not penalize the overall grade because they are bonus points.

| File | Overall Score | Target Field Score |
|------|--------------|-------------------|
| `v2.1.0-two-comps-one-with-filename.json` | 9.7/10.0 | `comp_filename`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-deployable-hash.json` | 9.7/10.0 | `comp_deployable_hash`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-executable-prop.json` | 9.7/10.0 | `comp_executable_prop`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-archive-prop.json` | 9.7/10.0 | `comp_archive_prop`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-structured-prop.json` | 9.7/10.0 | `comp_structured_prop`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-concluded-license.json` | 9.7/10.0 | `comp_distribution_license`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-declared-license.json` | 9.7/10.0 | `comp_original_licenses`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-purl-cpe.json` | 9.7/10.0 | `comp_other_identifiers`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-download-url.json` | 9.7/10.0 | `comp_download_url`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-source-code-url.json` | 9.7/10.0 | `comp_source_code_url`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-creator.json` | 9.7/10.0 | `comp_creator`: 5.0/10.0 (1/2) |
| `v2.1.0-two-comps-one-with-dependencies.json` | **10.0/10.0** | `comp_depth`: 10.0/10.0 (tree is structurally complete) |
| `v2.1.0-two-comps-one-with-effective-license.json` | **10.0/10.0** | `comp_effective_license`: 5.0/10.0 (1/2) — optional, no overall penalty |
| `v2.1.0-two-comps-one-with-source-code-hash.json` | **10.0/10.0** | `comp_source_hash`: 5.0/10.0 (1/2) — optional, no overall penalty |
| `v2.1.0-two-comps-one-with-security-txt-url.json` | **10.0/10.0** | `comp_security_txt_url`: 5.0/10.0 (1/2) — optional, no overall penalty |

### Document Field Tests (`doc-missing-*`)

| File | Overall Score | Target Field Score | Note |
|------|--------------|-------------------|------|
| `v2.1.0-doc-missing-creator.json` | 9.4/10.0 | `sbom_creator`: 0.0/10.0 | Document-level required field missing |
| `v2.1.0-doc-missing-timestamp.json` | 9.4/10.0 | `sbom_timestamp`: 0.0/10.0 | Document-level required field missing |
| `v2.1.0-doc-missing-spec-version.json` | **10.0/10.0** | `sbom_spec_version`: 10.0/10.0 | sbomqs infers version from `@context` URL |
| `v2.1.0-doc-missing-sbom-uri.json` | **9.4/10.0** | `sbom_uri`: 0.0/10.0 | Both `spdxId` (URL) and `namespaceMap` removed |

## Notes

- All files use SPDX 3.0.1 (`specVersion: "3.0.1"`).
- All `Hash` elements use `sha512` as required by BSI v2.1.0.
- The `completeness` field is set to `"complete"` on all relationships.
- Missing fields are represented by **physically removing the key or relationship** from the JSON, not by empty strings or `null` values.
- Optional fields (effective license, source code hash, security.txt URL, BOM links) are scored as bonus points: present → component gets credit; missing → no penalty to the overall grade.
- `comp_depth` evaluates the structural completeness of the dependency tree. For SPDX 3.0, relationship-level `completeness` fields serve as the explicit indication per BSI v2.1 §5.2.2.
