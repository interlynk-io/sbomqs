# BSI TR-03183-2 v2.1.0 - Changes Required for sbomqs

## Overview

BSI TR-03183-2 v2.1.0 (dated 2025-08-20) introduces changes from v2.0.0. This document captures
all changes needed in sbomqs to support the new version.

**SPDX v2 is NOT allowed by v2.1.0.** All SPDX v2 fields are N/A. Only SPDX v3.0.1+ and
CycloneDX v1.6+ are valid. Since sbomqs does not currently support SPDX3, SPDX v2 SBOMs
scored against this profile should receive a **hard fail** on the format version check, and all
individual field checks should return N/A.

Key changes in v2.1.0 from v2.0.0:
- CycloneDX minimum version bumped from **1.5 to 1.6**
- SPDX minimum version bumped from **2.2.1 to 3.0.1** (SPDX v2 no longer allowed)
- Introduces **logical components** and **identified components**
- Restructured data fields (sections 5.2.1-5.2.5) — previously "additional" fields are now **SHALL**
- New data fields: Filename, Executable property, Archive property, Structured property, Original licences, Effective licence, URL of security.txt
- Digital signature removed from required/additional (now only a recommendation)
- Vulnerability info: SBOM MUST NOT contain it
- Added field mapping tables (Appendix 8.2)

---

## 1. New Profile: `bsi-v2.1`

Register a new profile `bsi-v2.1` alongside `bsi-v1.1` and `bsi-v2.0`. Update aliases so `bsi`/`BSI` point to `bsi-v2.1`.

---

## 2. SBOM Format Version Checks

### 2a. CycloneDX Minimum Version: 1.6
- **Current (v2.0):** CycloneDX >= 1.5
- **Required (v2.1):** CycloneDX >= 1.6
- **Action:** New evaluator or parameterized version check for CDX >= 1.6

### 2b. SPDX: v2 Not Allowed, v3.0.1+ Required
- **Current (v2.0):** SPDX >= 2.2.1
- **Required (v2.1):** SPDX >= 3.0.1
- **Action:** Since SPDX3 is not supported:
  - SPDX v2 SBOMs: **hard fail** on format version check (score 0)
  - All individual SPDX v2 field checks: return **N/A**
  - SPDX3 parsing support is a prerequisite for full v2.1 SPDX compliance

---

## 3. Complete Field Mapping (SHALL / MAY)

All fields below follow the authoritative mapping. SPDX v2 is N/A for every field.

### 3.1 Required (SHALL) SBOM-Level Fields

| # | Data Field | Required | SPDX v2 | SPDX v3.0.1 | CycloneDX v1.6+ |
|---|---|---|---|---|---|
| 1 | Creator of the SBOM | SHALL | N/A | `CreationInfo.createdBy` | `metadata.manufacturer[].url` XOR `metadata.manufacturer[].contact[].email` |
| 2 | Timestamp | SHALL | N/A | `CreationInfo.created` | `metadata.timestamp` |
| 3 | SBOM-URI | SHALL | N/A | `Sbom.spdxId` | `serialNumber` (BOM-Link: `urn:cdx:{serialNumber}/{version}`) |

### 3.2 Required (SHALL) Component-Level Fields

| # | Data Field | Required | SPDX v2 | SPDX v3.0.1 | CycloneDX v1.6+ |
|---|---|---|---|---|---|
| 4 | Component creator | SHALL | N/A | `Package.originatedBy` | `components[].manufacturer[].url` XOR `components[].manufacturer[].contact[].email` |
| 5 | Component name | SHALL | N/A | `Package.name` | `components[].name` (optionally `.group`) |
| 6 | Component version | SHALL | N/A | `Package.packageVersion` | `components[].version` |
| 7 | Filename of the component | SHALL | N/A | `File.name` | `components[].properties[].name="bsi:component:filename"` + `.value` |
| 8 | Dependencies on other components | SHALL | N/A | `Relationship.relationshipType=["contains" OR "dependsOn"]` | `dependencies[]` + `components[].components` + `compositions.assemblies[]` OR `compositions.dependencies[]` |
| 9 | Distribution licences | SHALL | N/A | `Relationship.relationshipType="hasConcludedLicense"` | `components[].licenses[].expression` + `acknowledgement="concluded"` |
| 10 | Hash value of deployable component | SHALL | N/A | `File.verifiedUsing` | `components[].externalReferences[].hashes[]` with `type="distribution"` |
| 11 | Executable property | SHALL | N/A | `File.additionalPurpose=["executable"]` | `components[].properties[].name="bsi:component:executable"` + `.value` |
| 12 | Archive property | SHALL | N/A | `File.additionalPurpose=["archive"]` | `components[].properties[].name="bsi:component:archive"` + `.value` |
| 13 | Structured property | SHALL | N/A | `File.additionalPurpose=["container" OR "firmware"]` | `components[].properties[].name="bsi:component:structured"` + `.value` |
| 14 | Source code URI | SHALL | N/A | `SoftwareArtifact.externalRef.externalRefType="SourceArtifact"` + `.locator` | `components[].externalReferences[].type="source-distribution"` + `.url` |
| 15 | URI of the deployable form | SHALL | N/A | `File.externalRef.externalRefType="binaryArtifact"` + `.locator` | `components[].externalReferences[].type="distribution"` + `.url` |
| 16 | Other unique identifiers | SHALL | N/A | `Package.externalIdentifiers.externalIdentifierType=` `"cpe22" OR "cpe23" OR "swid" OR "packageURL"` | `components[].cpe` OR `components[].swid` OR `components[].purl` |
| 17 | Original licences | SHALL | N/A | `Relationship.relationshipType="hasDeclaredLicense"` | `components[].licenses[].expression` + `acknowledgement="declared"` |

### 3.3 Optional (MAY) Component-Level Fields

| # | Data Field | Required | SPDX v2 | SPDX v3.0.1 | CycloneDX v1.6+ |
|---|---|---|---|---|---|
| 18 | Effective licence | MAY | N/A | `Relationship.relationshipType="other"` + `.comment="hasEffectiveLicense"` | `components[].properties[].name="bsi:component:effectiveLicense"` + `.value` |
| 19 | Hash value of source code | MAY | N/A | `SoftwareArtifact.verifiedUsing` + `Relationship.relationshipType="generates"` | `components[].externalReferences[].hashes[]` with `type="source-distribution"` |
| 20 | URL of the security.txt | MAY | N/A | `Package.externalRef.externalRefType="securityOther"` + `.locator` | `components[].externalReferences[].type="rfc-9116"` + `.url` |

---

## 4. Removed/Changed Fields from v2.0

| v2.0 Field | v2.1 Status | Notes |
|---|---|---|
| `sbom_signature` (Digital Signature) | Removed from required/additional. Recommendation only (Appendix 8.1.15) | Remove from required features |
| `sbom_vulnerabilities` | **SBOM MUST NOT contain vulnerability info** (Section 3.1) | Remove from profile (was optional in v2.0). Could add inverse check. |
| `comp_hash_sha256` (SHA-256+) | Hash of deployable now via `externalReferences` with `type="distribution"` | Replace with new evaluator using externalReferences path |

### Key mapping changes from v2.0:
- **Hash of deployable component:** Was checked on component-level hash. Now mapped to `externalReferences[].hashes[]` with `type="distribution"` (CDX). Different evaluator logic needed.
- **SBOM-URI:** Was "Additional" in v2.0, now **SHALL** (required).
- **Source code URI:** Was "Additional" in v2.0, now **SHALL** (required).
- **URI of deployable form:** Was "Additional" in v2.0, now **SHALL** (required).
- **Distribution licences:** CDX mapping now explicitly requires `acknowledgement="concluded"`.

---

## 5. Profile Spec Registration

New profile spec to add in `registry.go`:

```go
ProfileBSI21 catalog.ProfileKey = "bsi-v2.1"
```

### Profile aliases to update:
```go
"BSI":       ProfileBSI21,  // default to latest
"bsi":       ProfileBSI21,
"BSI-V2.1":  ProfileBSI21,
"bsi-v2.1":  ProfileBSI21,
"bsi-v2_1":  ProfileBSI21,
```

### Feature spec structure:

```
Required (SHALL) SBOM fields:
  - sbom_spec            (SBOM Format - CDX >= 1.6 or SPDX >= 3.0.1)
  - sbom_creator         (Creator email/URL)
  - sbom_timestamp       (Creation timestamp)
  - sbom_uri             (SBOM-URI/Namespace) [promoted from additional to SHALL]

Required (SHALL) Component fields:
  - comp_creator              (Component creator email/URL)
  - comp_name                 (Component name)
  - comp_version              (Component version)
  - comp_filename             (Filename of the component) [NEW]
  - comp_depth                (Dependencies on other components)
  - comp_distribution_license (Distribution licences - concluded)
  - comp_hash                 (Hash of deployable via externalReferences type=distribution)
  - comp_executable_prop      (Executable property) [NEW]
  - comp_archive_prop         (Archive property) [NEW]
  - comp_structured_prop      (Structured property) [NEW]
  - comp_source_code_url      (Source code URI) [promoted from additional to SHALL]
  - comp_download_url         (URI of deployable form) [promoted from additional to SHALL]
  - comp_other_identifiers    (CPE/SWID/purl) [NEW, SHALL]
  - comp_original_licenses    (Original licences - declared) [NEW, SHALL]

Optional (MAY) Component fields:
  - comp_effective_license     (Effective licence) [NEW]
  - comp_source_hash           (Hash of source code) [NEW]
  - comp_security_txt_url      (URL of security.txt) [NEW]
```

---

## 6. New Evaluator Functions Needed

| Function | File | Description |
|---|---|---|
| `BSIV21SpecVersion` | `bsiv21.go` | CDX >= 1.6; SPDX v2 = hard fail; SPDX >= 3.0.1 = pass |
| `BSIV21CompFilename` | `bsiv21.go` | CDX: check `bsi:component:filename` property |
| `BSIV21CompExecutableProperty` | `bsiv21.go` | CDX: check `bsi:component:executable` property |
| `BSIV21CompArchiveProperty` | `bsiv21.go` | CDX: check `bsi:component:archive` property |
| `BSIV21CompStructuredProperty` | `bsiv21.go` | CDX: check `bsi:component:structured` property |
| `BSIV21CompDeployableHash` | `bsiv21.go` | CDX: check `externalReferences[].hashes[]` with `type="distribution"` |
| `BSIV21CompDistributionLicence` | `bsiv21.go` | CDX: check `licenses[].acknowledgement="concluded"` |
| `BSIV21CompOtherIdentifiers` | `bsiv21.go` | CDX: check `cpe` OR `swid` OR `purl` |
| `BSIV21CompOriginalLicences` | `bsiv21.go` | CDX: check `licenses[].acknowledgement="declared"` |
| `BSIV21CompEffectiveLicence` | `bsiv21.go` | CDX: check `bsi:component:effectiveLicense` property |
| `BSIV21CompSourceHash` | `bsiv21.go` | CDX: check `externalReferences[].hashes[]` with `type="source-distribution"` |
| `BSIV21CompSecurityTxtURL` | `bsiv21.go` | CDX: check `externalReferences[].type="rfc-9116"` |
| `BSIV21CompDownloadURI` | `bsiv21.go` | CDX: check `externalReferences[].type="distribution"` + `.url` |
| `BSIV21CompSourceCodeURI` | `bsiv21.go` | CDX: check `externalReferences[].type="source-distribution"` + `.url` |

---

## 7. SPDX3 Gaps (Out of Scope)

The following cannot be evaluated without SPDX3 parsing support:

- SPDX 3.0.1 minimum version validation
- `software_File` type differentiation (for filename, executable/archive/structured properties)
- `software_additionalPurpose` field
- `hasDistributionArtifact` relationship type
- `hasDeclaredLicense` / `hasConcludedLicense` relationship types
- `simpleLicensing_LicenseExpression` type
- New SPDX3 element types (`CreationInfo`, `software_Sbom`, `software_Package`, `software_SoftwareArtifact`)

**For SPDX v2 SBOMs scored against `bsi-v2.1`:** hard fail on spec version, all fields N/A.

---

## 8. Summary of Work Items

1. **New file:** `pkg/scorer/v2/profiles/bsiv21.go` - ~14 new evaluator functions
2. **Registry update:** `pkg/scorer/v2/registry/registry.go` - new profile key, aliases, feature spec, key-to-function maps
3. **CLI update:** `cmd/score.go` and `cmd/dtrackScore.go` - add `bsi-v2.1` to help text
4. **Tests:** `pkg/scorer/v2/profiles/bsiv21_test.go` and integration tests
5. **BSI property parsing:** Ensure `sbom.GetComponent` interface can access CycloneDX `properties` by name (for `bsi:component:*` keys)
6. **External reference parsing:** Ensure `type="distribution"`, `type="source-distribution"`, and `type="rfc-9116"` are recognized, and that `hashes[]` on external references are accessible
7. **Licence acknowledgement parsing:** Ensure CDX `licenses[].acknowledgement` field ("declared"/"concluded") is accessible
8. **Documentation:** Update profile docs
