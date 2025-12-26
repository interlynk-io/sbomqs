# Actionable & Resilient Scoring SBOMQS 2.0

## Table of Contents

- [Actionable \& Resilient Scoring SBOMQS 2.0](#actionable--resilient-scoring-sbomqs-20)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
    - [Cmd Usage](#cmd-usage)
  - [SBOM Spec Support](#sbom-spec-support)
  - [Scoring Formula and Rules](#scoring-formula-and-rules)
    - [Base Scoring Formulas](#base-scoring-formulas)
  - [Scoring and Grades](#scoring-and-grades)
  - [Scoring Profiles](#scoring-profiles)
    - [Available Profiles](#available-profiles)
    - [Planned Profiles (Not Yet Available)](#planned-profiles-not-yet-available)
    - [Profile Usage](#profile-usage)
    - [Profile vs Comprehensive Scoring](#profile-vs-comprehensive-scoring)
  - [Score Categories with Weights](#score-categories-with-weights)
    - [1. Identification (Weight: 10)](#1-identification-weight-10)
    - [2. Provenance (Weight: 12)](#2-provenance-weight-12)
    - [3. Integrity (Weight: 15)](#3-integrity-weight-15)
    - [4. Completeness (Weight: 12)](#4-completeness-weight-12)
    - [5. Licensing \& Compliance (Weight: 15)](#5-licensing--compliance-weight-15)
    - [6. Vulnerability \& Traceability (Weight: 10)](#6-vulnerability--traceability-weight-10)
    - [7. Structural (Weight: 8)](#7-structural-weight-8)
    - [8. Component Quality (Informational Only - API Key Required)](#8-component-quality-informational-only---api-key-required)
  - [Profile Definitions](#profile-definitions)
    - [NTIA Minimum Elements](#ntia-minimum-elements)
    - [BSI TR-03183-2 v1.1](#bsi-tr-03183-2-v11)
    - [BSI TR-03183-2 v2.0](#bsi-tr-03183-2-v20)
    - [OpenChain Telco (OCT)](#openchain-telco-oct)
    - [AUTO-ISAC Automotive (Planned)](#auto-isac-automotive-planned)
    - [Profile Implementation Notes](#profile-implementation-notes)
      - [Mapping to v2.0 Categories](#mapping-to-v20-categories)
      - [Features Not in v2.0 Scoring](#features-not-in-v20-scoring)
      - [Important Differences](#important-differences)
  - [Example Calculations](#example-calculations)
    - [Example 1: High-Quality SBOM](#example-1-high-quality-sbom)
    - [Example 2: Feature Score Calculation](#example-2-feature-score-calculation)
    - [Example 3: N/A Handling](#example-3-na-handling)
    - [Example 4: Component Quality Display (Informational)](#example-4-component-quality-display-informational)
    - [Example 5: Profile-Based Scoring](#example-5-profile-based-scoring)
  - [Appendix: License Lists](#appendix-license-lists)
    - [Deprecated Licenses (Examples)](#deprecated-licenses-examples)
    - [Restrictive Licenses (Examples)](#restrictive-licenses-examples)
    - [Permissive Licenses (Examples)](#permissive-licenses-examples)
  - [Appendix: Profile Requirements](#appendix-profile-requirements)
    - [NTIA Minimum Elements](#ntia-minimum-elements-1)
    - [BSI TR-03183-2 Evolution](#bsi-tr-03183-2-evolution)
    - [AUTO-ISAC Automotive Requirements](#auto-isac-automotive-requirements)
    - [OpenChain Telco SBOM Guide](#openchain-telco-sbom-guide)
    - [Profile Compliance Thresholds](#profile-compliance-thresholds)
  - [Implementation Notes](#implementation-notes)
    - [Component Quality API Integration](#component-quality-api-integration)
    - [Profile Configuration](#profile-configuration)
  - [Version History](#version-history)

---

## Overview

We are evolving the sbomqs SBOM scoring to be more meaningful, explainable, resilient to spec differences, and actionable. Based on our learnings from the last 3 years, we are introducing a new scoring mechanism to help better consumption of SBOMs. These new changes will help users easily classify and consume SBOMs. The scoring will be the default mechanism starting with sbomqs 2.0.

---

### Cmd Usage

With the new scoring logic, the new formats will look like the following. 

**Basic**

```bash
# Default comprehensive scoring
$ sbomqs score --basic samples/example.cdx.json
8.9	B cyclonedx	1.6	json	samples/example.cdx.json

# Profile-based scoring
$ sbomqs score --basic --profile ntia samples/example.cdx.json
8.5	ntia	cyclonedx	1.6	json	samples/example.cdx.json

$ sbomqs score --basic --profile bsi-v2.0 samples/example.cdx.json
7.8	bsi-v2.0	cyclonedx	1.6	json	samples/example.cdx.json
```

**Detailed**

```
# Default comprehensive scoring
$ sbomqs score --detailed samples/example.cdx.json

SBOM Quality Score: 8.9/10.0  Grade: B  Components: 247  samples/example.cdx.json

+-----------------------+--------------------------------+-----------+--------------------------------+
|       CATEGORY        |            FEATURE             |   SCORE   |              DESC              |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Identification        | comp_with_name                 | 10.0/10.0 | 247/247 have names             |
|                       | comp_with_version              | 9.5/10.0  | 235/247 have versions          |
|                       | comp_with_identifiers          | 8.2/10.0  | 203/247 have unique IDs        |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Provenance            | sbom_creation_timestamp        | 10.0/10.0 | 2025-01-20T10:30:45Z           |
|                       | sbom_authors                   | 10.0/10.0 | 2 authors                      |
|                       | sbom_tool_version              | 10.0/10.0 | syft v0.95.0                   |
|                       | sbom_supplier                  | 5.0/10.0  | no supplier                    |
|                       | sbom_namespace                 | 10.0/10.0 | valid namespace                |
|                       | sbom_lifecycle                 | 5.0/10.0  | no lifecycle                   |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Integrity             | comp_with_checksums            | 9.3/10.0  | 230/247 have checksums         |
|                       | comp_with_sha256               | 8.0/10.0  | 198/247 have SHA-256+          |
|                       | sbom_signature                 | 10.0/10.0 | signed                         |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Completeness          | comp_with_dependencies         | 7.5/10.0  | 185/247 have dependencies      |
|                       | sbom_completeness_declared     | 10.0/10.0 | declared                       |
|                       | primary_component              | 10.0/10.0 | identified                     |
|                       | comp_with_source_code          | 6.5/10.0  | 160/247 have source URIs       |
|                       | comp_with_supplier             | 8.5/10.0  | 210/247 have suppliers         |
|                       | comp_with_purpose              | 9.0/10.0  | 222/247 have type              |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Licensing             | comp_with_licenses             | 9.5/10.0  | 235/247 have licenses          |
|                       | comp_with_valid_licenses       | 9.0/10.0  | 211/235 valid SPDX             |
|                       | comp_with_declared_licenses    | 8.0/10.0  | 188/235 have declared          |
|                       | sbom_data_license              | 10.0/10.0 | CC0-1.0                        |
|                       | comp_no_deprecated_licenses    | 10.0/10.0 | 0 deprecated                   |
|                       | comp_no_restrictive_licenses   | 7.0/10.0  | 15 restrictive                 |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Vulnerability         | comp_with_purl                 | 8.0/10.0  | 198/247 have PURL              |
|                       | comp_with_cpe                  | 7.0/10.0  | 173/247 have CPE               |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Structural            | sbom_spec_declared             | 10.0/10.0 | CycloneDX                      |
|                       | sbom_spec_version              | 10.0/10.0 | v1.6                           |
|                       | sbom_file_format               | 10.0/10.0 | JSON                           |
|                       | sbom_schema_valid              | 10.0/10.0 | valid                          |
+-----------------------+--------------------------------+-----------+--------------------------------+

Component Quality (Informational - API Key Required):
- EOL/EOS: 12/247 (4.9%) - webpack@3.12.0, node-sass@4.x
- Malicious: 0/247 (0%)
- KEV: 3/247 (1.2%) - log4j@2.14.1, spring@5.2.1
- High EPSS: 5/247 (2.0%)

Recommendations:
- CRITICAL: Replace 3 components with Known Exploited Vulnerabilities
- Add PURL/CPE identifiers (49 missing PURL, 74 missing CPE)
- Complete dependency mapping for 62 components
- Update 12 EOL/EOS components
- Upgrade 32 SHA-1 checksums to SHA-256+
```

**Profile-based scoring (NTIA)**

```bash
$ sbomqs score --detailed --profile ntia samples/example.cdx.json

NTIA Minimum Elements: PASS  Components: 247  samples/example.cdx.json

+-----------------------+--------------------------------+-----------+--------------------------------+
|      REQUIREMENT      |            FEATURE             |   STATUS  |              RESULT            |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Component Name        | comp_with_name                 |    PASS   | 247/247 (100%)                 |
| Component Version     | comp_with_version              |    PASS   | 235/247 (95%)                  |
| Component Supplier    | comp_with_supplier             |    PASS   | 210/247 (85%)                  |
| Unique Identifiers    | comp_with_uniq_ids             |    PASS   | 247/247 (100%)                 |
| Dependency Mapping    | sbom_dependencies              |    PASS   | Present                        |
| Creation Timestamp    | sbom_creation_timestamp        |    PASS   | 2025-01-20T10:30:45Z           |
| Author Information    | sbom_authors                   |    PASS   | 2 authors                      |
+-----------------------+--------------------------------+-----------+--------------------------------+

Status: PASS - All minimum elements satisfied
Score: 8.9/10.0 (Grade B)
```

**Json**

```json
{
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-01-20T10:30:45Z",
  "creation_info": {
    "name": "sbomqs",
    "version": "v2.0.0",
    "scoring_engine_version": "2.0",
    "vendor": "Interlynk (support@interlynk.io)"
  },
  "files": [
    {
      "file_name": "samples/example.cdx.json",
      "spec": "cyclonedx",
      "spec_version": "1.6",
      "file_format": "json",
      "overall_score": 8.91,
      "grade": "B",
      "grade_label": "Good",
      "num_components": 247,
      "creation_time": "2025-01-20T09:00:00Z",
      "gen_tool_name": "syft",
      "gen_tool_version": "0.95.0",
      "categories": [
        {
          "name": "Identification",
          "weight": 10,
          "score": 9.5,
          "weighted_score": 1.16,
          "features": [
            {
              "name": "comp_with_name",
              "score": 10.0,
              "max_score": 10.0,
              "weight": 0.4,
              "description": "247/247 have names"
            },
            {
              "name": "comp_with_version",
              "score": 9.5,
              "max_score": 10.0,
              "weight": 0.35,
              "description": "235/247 have versions"
            },
            {
              "name": "comp_with_identifiers",
              "score": 8.2,
              "max_score": 10.0,
              "weight": 0.25,
              "description": "203/247 have unique IDs"
            }
          ]
        },
        {
          "name": "Provenance",
          "weight": 12,
          "score": 8.8,
          "weighted_score": 1.29,
          "features": [
            {
              "name": "sbom_creation_timestamp",
              "score": 10.0,
              "max_score": 10.0,
              "weight": 0.20,
              "description": "doc has creation timestamp"
            },
            {
              "name": "sbom_authors",
              "score": 10.0,
              "max_score": 10.0,
              "weight": 0.20,
              "description": "doc has 2 authors"
            },
            {
              "name": "sbom_tool_version",
              "score": 10.0,
              "max_score": 10.0,
              "weight": 0.20,
              "description": "syft v0.95.0"
            },
            {
              "name": "sbom_supplier",
              "score": 5.0,
              "max_score": 10.0,
              "weight": 0.15,
              "description": "no supplier specified"
            },
            {
              "name": "sbom_namespace",
              "score": 10.0,
              "max_score": 10.0,
              "weight": 0.15,
              "description": "valid namespace/serialNumber"
            },
            {
              "name": "sbom_lifecycle",
              "score": 5.0,
              "max_score": 10.0,
              "weight": 0.10,
              "description": "no lifecycle specified"
            }
          ]
        }
      ],
      "component_quality": {
        "informational": true,
        "requires_api_key": true,
        "api_key_present": true,
        "metrics": [
          {
            "name": "eol_eos_components",
            "count": 12,
            "percentage": 4.9,
            "severity": "warning",
            "affected_components": ["webpack@3.12.0", "node-sass@4.14.1", "babel-core@6.26.3"]
          },
          {
            "name": "malicious_components",
            "count": 0,
            "percentage": 0.0,
            "severity": "ok",
            "affected_components": []
          },
          {
            "name": "kev_vulnerabilities",
            "count": 3,
            "percentage": 1.2,
            "severity": "critical",
            "affected_components": ["log4j@2.14.1", "spring-core@5.2.1", "struts@2.5.20"]
          },
          {
            "name": "high_epss",
            "count": 5,
            "percentage": 2.0,
            "severity": "warning",
            "epss_threshold": 0.8,
            "affected_components": ["jackson-databind@2.9.10", "commons-text@1.9", "lodash@4.17.15"]
          }
        ]
      },
      "profile": {
        "name": "ntia",
        "full_name": "NTIA Minimum Elements",
        "version": "1.0",
        "type": "pass_fail",
        "compliance_status": "PASS",
        "features_evaluated": [
          {
            "name": "comp_with_name",
            "status": "pass",
            "result": "247/247 (100%)"
          },
          {
            "name": "comp_with_version",
            "status": "pass",
            "result": "235/247 (95%)"
          },
          {
            "name": "comp_with_supplier",
            "status": "pass",
            "result": "210/247 (85%)"
          },
          {
            "name": "comp_with_uniq_ids",
            "status": "pass",
            "result": "247/247 (100%)"
          },
          {
            "name": "sbom_dependencies",
            "status": "pass",
            "result": "present"
          },
          {
            "name": "sbom_creation_timestamp",
            "status": "pass",
            "result": "2025-01-20T10:30:45Z"
          },
          {
            "name": "sbom_authors",
            "status": "pass",
            "result": "2 authors"
          }
        ],
        "missing_requirements": [],
        "profile_score": null,
        "comprehensive_score": 8.91
      },
      "recommendations": [
        {
          "priority": "critical",
          "category": "Component Quality",
          "action": "Replace 3 components with Known Exploited Vulnerabilities",
          "score_impact": null,
          "informational": true
        },
        {
          "priority": "high",
          "category": "Vulnerability",
          "action": "Add PURL identifiers to 49 components",
          "score_impact": 0.2
        },
        {
          "priority": "high",
          "category": "Vulnerability",
          "action": "Add CPE identifiers to 74 components",
          "score_impact": 0.3
        },
        {
          "priority": "medium",
          "category": "Completeness",
          "action": "Map dependencies for 62 components",
          "score_impact": 0.25
        },
        {
          "priority": "medium",
          "category": "Component Quality",
          "action": "Update 12 EOL/EOS components to maintained versions",
          "score_impact": null,
          "informational": true
        }
      ]
    }
  ]
}
```

---

## SBOM Spec Support

- **CycloneDX**: 1.4, 1.5, 1.6+
- **SPDX**: 2.2, 2.3+, 3.0 (WIP)

---

## Scoring Formula and Rules

### Base Scoring Formulas

1. **Per-component coverage features** (e.g., component has checksum):
   ```
   feature_score = 10 × (components_with_feature / total_components)
   ```
   Example: If 80 out of 100 components have checksums:
   `score = 10 × (80/100) = 8.0`

2. **Doc-level boolean features** (e.g., sbom_signature_present):
   ```
   score = 10 if present, else 0
   ```

3. **Qualitative features** (e.g., license validity):
   ```
   feature_score = 10 × (valid_items / total_items)
   ```
   Example: If 45 out of 50 licenses are valid:
   `score = 10 × (45/50) = 9.0`

4. **N/A handling**: 
   
   - If a feature is truly not-applicable, exclude that feature from the category's denominator
   - Renormalize category weights proportionally
   - Example: If 1 of 5 features is N/A in a category:
     ```
     adjusted_weight = original_weight × (5/4)
     ```
   
5. **Category score calculation**:
   
   ```
   category_score = Σ(feature_score × feature_weight) / Σ(feature_weights)
   ```
   Where feature_weights are normalized within each category
   
6. **Interlynk Score (0–10)**:
   ```
   interlynk_score = Σ(category_score × category_weight) / Σ(category_weights)
   ```
   **Note**: Only categories 1-7 contribute to the score (total weight: 82). Component Quality (category 8) is informational only and requires an API key.

7. **Component Quality (Informational)**:
   - These metrics do NOT affect the overall quality score
   - Requires API key for external threat intelligence lookups
   - Provides real-time risk assessment for supply chain security
   - Displayed separately as informational metrics

---

## Scoring and Grades

sbomqs produces scores in the range of 0.0 to 10.0. Grades allow for quick classification and consumption.

| **Grade** | **Color**               | **Score Range** | **Meaning**      | **Recommended Action**                      |
| --------- | ----------------------- | --------------- | ---------------- | -------------------------------------------- |
| **A**     | Green (#2ECC71)         | **9.0 – 10.0**  | **Excellent**    | Ready for production use                    |
| **B**     | Light Green (#58D68D)   | **8.0 – 8.9**   | **Good**         | Minor improvements recommended              |
| **C**     | Yellow (#F4D03F)        | **7.0 – 7.9**   | **Acceptable**   | Review and enhance key missing elements     |
| **D**     | Orange (#E67E22)        | **5.0 – 6.9**   | **Poor**         | Significant improvements required           |
| **F**     | Red (#E74C3C)           | **< 5.0**       | **Bad**          | Not suitable for use, major rework needed   |

---

## Scoring Profiles

sbomqs supports both comprehensive quality scoring and profile-based compliance checking. Profiles allow you to evaluate SBOMs against specific industry standards and regulatory requirements.

### Available Profiles

| Profile | Full Name | Description | Type | Status |
| :------ | :-------- | :---------- | :--- | :----- |
| **ntia** | NTIA Minimum Elements | US NTIA minimum required elements for SBOMs | Scored | Implemented |
| **bsi-v1.1** | BSI TR-03183-2 v1.1 | German BSI technical guideline v1.1 | Scored | Implemented |
| **bsi-v2.0** | BSI TR-03183-2 v2.0 | German BSI technical guideline v2.0.x (adds cryptographic signatures) | Scored | Implemented |
| **oct** | OpenChain Telco | SPDX-specific telecommunications requirements | Scored | Implemented |

### Planned Profiles (Not Yet Available)

- **bsi-v2.1**: Latest BSI guideline with enhanced requirements
- **auto-isac**: Automotive industry SBOM requirements  
- **fsct**: Financial Services requirements

### Profile Usage

Profiles can be used individually or in combination:

```bash
# Single profile
$ sbomqs score --profile ntia samples/example.cdx.json

# BSI v1.1 profile
$ sbomqs score --profile bsi-v1.1 samples/example.cdx.json

# BSI v2.0 profile
$ sbomqs score --profile bsi-v2.0 samples/example.cdx.json

# OpenChain Telco (SPDX only)
$ sbomqs score --profile oct samples/example.spdx.json

# Multiple profiles
$ sbomqs score --profile ntia,bsi-v2.0 samples/example.cdx.json
```

### Profile vs Comprehensive Scoring

- **Comprehensive Score** (default): Evaluates all 7 categories with weighted scoring (0-10)
- **Profile Score**: Evaluates only relevant features for specific compliance requirements
- Both can be run together to get compliance status AND quality score

---

## Score Categories with Weights

### 1. Identification (Weight: 10)

*Identification of components is critical for understanding/locating and mapping supply chain metadata.*

| Feature                              | SPDX 2.2/3              | CDX 1.4+          | Validation Rules                             | Weight |
| :----------------------------------- | ----------------------- | :---------------- | :------------------------------------------- | :----- |
| % components with name               | PackageName             | component.name    | Trim spaces, check non-empty                | 0.4    |
| % components with version            | PackageVersion          | component.version | Trim spaces, check non-empty                | 0.35   |
| % components with local identifiers  | SPDXID                  | bom-ref           | Trim spaces, check uniqueness               | 0.25   |

### 2. Provenance (Weight: 12)

*Enables trust and audit trails.*

| Feature                         | SPDX 2.2/3                        | CDX 1.4+                                | Validation Rules                                      | Weight |
| :------------------------------ | --------------------------------- | --------------------------------------- | ---------------------------------------------------- | :----- |
| Document creation time          | Created                           | metadata.timestamp                      | ISO 8601 format validation                          | 0.20   |
| Document authors                | Creator.(Person/Organization)      | metadata.(authors/author)               | Non-empty, valid email/name format                  | 0.20   |
| Document creator tool & version | Creator.Tool                      | metadata.(tools/tool)                   | Tool name and version present                       | 0.20   |
| Document supplier               | PackageSupplier                   | metadata.(supplier/manufacturer)        | Non-empty supplier identification                   | 0.15   |
| Document URI/namespace          | namespace                         | serialNumber + version                  | Valid URI format or UUID                            | 0.15   |
| Document Lifecycle              | N/A                               | lifecycles                              | Valid lifecycle present                             | 0.10   |

### 3. Integrity (Weight: 15)

*Allows for verification if artifacts were altered.*

| Feature                     | SPDX 2.2/3           | CDX 1.4+              | Validation Rules                                | Weight |
| :-------------------------- | -------------------- | --------------------- | ----------------------------------------------- | :----- |
| % components with checksums | PackageChecksum      | component.hashes      | Any valid hash algorithm (SHA-1 minimum)       | 0.60   |
| % components with SHA-256+  | PackageChecksum      | component.hashes      | SHA-256 or stronger algorithm                  | 0.30   |
| Document signature          | (External signature) | signature             | Valid digital signature                        | 0.10   |

### 4. Completeness (Weight: 12)

*Allows for vulnerability and impact analysis.*

| Feature                           | SPDX 2.2/3                          | CDX 1.4+                          | Validation Rules                                    | Weight |
| :-------------------------------- | ----------------------------------- | --------------------------------- | -------------------------------------------------- | :----- |
| % components with dependencies    | Relationships                       | dependencies                      | Valid dependency graph                            | 0.25   |
| % components with declared completeness | N/A                          | Compositions/Aggregate            | Completeness declaration present                  | 0.15   |
| Primary component identified      | Relationships.DESCRIBES             | metadata.component                | Single primary component defined                  | 0.20   |
| % components with source code     | PackageSourceInfo                   | externalReferences.type=vcs      | Valid VCS URL                                     | 0.15   |
| % components with supplier        | PackageSupplier/PackageOriginator  | component.supplier                | Non-empty supplier field                          | 0.15   |
| % components with primary purpose | PrimaryPackagePurpose               | component.type                    | Valid purpose/type enum                           | 0.10   |

### 5. Licensing & Compliance (Weight: 15)

*Determines redistribution rights and legal compliance.*

| Feature                                   | SPDX 2.2/3       | CDX 1.4+                 | Validation Rules                                  | Weight |
| :---------------------------------------- | ---------------- | ------------------------ | ------------------------------------------------- | :----- |
| % components with licenses                | ConcludedLicense | component.licenses       | Non-NOASSERTION value                             | 0.20   |
| % components with valid licenses          | ConcludedLicense | component.licenses       | SPDX/ScanCode DB validation                       | 0.20   |
| % components with original licenses       | DeclaredLicense  | Declared acknowledgement | License declaration present                      | 0.15   |
| Document data license                     | DataLicense      | metadata.licenses        | Valid SPDX data license                           | 0.10   |
| % components without deprecated licenses  | ConcludedLicense | component.licenses       | Check against deprecated license list             | 0.15   |
| % components without restrictive licenses | ConcludedLicense | component.licenses       | Check against restrictive license list (GPL, etc) | 0.20   |

### 6. Vulnerability & Traceability (Weight: 10)

*Ability to map components to vulnerability databases.*

| Feature                      | SPDX 2.2/3                          | CDX 1.4+            | Validation Rules                              | Weight |
| :--------------------------- | ----------------------------------- | ------------------- | --------------------------------------------- | :----- |
| % components with PURL       | ExternalRef.PACKAGE_MANAGER        | component.purl      | Valid PURL syntax per spec                   | 0.50   |
| % components with CPE        | ExternalRef.SECURITY/cpe22/3 Type  | component.cpe       | Valid CPE 2.3 format                         | 0.50   |

### 7. Structural (Weight: 8)

*If a BOM can't be reliably parsed, all downstream automation fails.*

| Feature                 | SPDX 2.2/3          | CDX 1.4+         | Validation Rules                          | Weight |
| :---------------------- | ------------------- | ---------------- | ----------------------------------------- | :----- |
| SBOM spec declared      | spdxVersion         | bomFormat        | Valid spec identifier                     | 0.30   |
| SBOM spec version       | spdxVersion         | specVersion      | Supported version                         | 0.30   |
| SBOM file format        | JSON/Tag-Value/YAML | JSON/XML         | Valid, parseable format                   | 0.20   |
| Schema validation       | SPDX JSON Schema    | CDX JSON Schema  | Passes schema validation                  | 0.20   |

### 8. Component Quality (Informational Only - API Key Required)

*Real-time component risk assessment based on external threat intelligence. These metrics are informational only and do NOT affect the overall quality score.*

| Feature                           | Validation Rules                                                  | Weight |
| :-------------------------------- | --------------------------------------------------------------- | :----- |
| % components which are EOL or EOS | Components no longer maintained or declared end-of-life         | 0.10   |
| % components that are malicious   | Components tagged as malicious in threat databases              | 0.30   |
| % components that have KEV        | Components with vulnerabilities in CISA's Known Exploited Vulns | 0.30   |
| % components that have EPSS > 0.8 | Components with Exploit Prediction Scoring System > 0.8         | 0.30   |

**Note**: Weights shown are for relative importance within Component Quality metrics only. These do not contribute to the overall SBOM quality score.

---

## Profile Definitions

Each profile evaluates specific features based on industry standards and regulatory requirements. Features marked as "Not in v2.0" require implementation beyond the current scoring categories.

### NTIA Minimum Elements

| Feature | Implementation | Required | Description |
| :------ | :------------- | :------- | :---------- |
| Automation Support | sbom_machine_format | Yes | Valid spec (SPDX/CycloneDX) and format (JSON/XML) |
| Component Name | comp_with_name | Yes | All components must have names |
| Component Supplier | comp_creator/supplier | Yes | Supplier/manufacturer info for components |
| Component Version | comp_with_version | Yes | Version strings for all components |
| Component Other Identifiers | comp_other_uniq_ids | Yes | PURL, CPE, or other unique IDs |
| Dependency Relationships | sbom_dependencies | Yes | Component dependency mapping |
| SBOM Author | sbom_creator | Yes | Tool or person who created SBOM |
| SBOM Timestamp | sbom_timestamp | Yes | ISO 8601 creation timestamp |

### BSI TR-03183-2 v1.1

| Feature | Implementation | Required | Description |
| :------ | :------------- | :------- | :---------- |
| SBOM Formats | sbom_spec | Yes | SPDX or CycloneDX |
| SBOM Spec Version | sbom_spec_version | Yes | Valid supported version |
| Build Information | sbom_build | No | Build phase indication |
| SBOM Depth | sbom_depth | Yes | Complete dependency tree |
| Creator Info | sbom_creator | Yes | Contact email/URL |
| Creation Time | sbom_timestamp | Yes | Valid timestamp |
| URI/Namespace | sbom_uri | Yes | Unique SBOM identifier |
| Component Name | comp_name | Yes | All components named |
| Component Version | comp_version | Yes | Version for each component |
| Component License | comp_license | Yes | License information |
| Component Hash | comp_hash | Yes | Checksums for components |
| Component Source URL | comp_source_code_url | No | Source code repository |
| Component Download URL | comp_download_url | Yes | Where to obtain component |
| Component Source Hash | comp_source_hash | No | Hash of source code |
| Component Dependencies | comp_depth | Yes | Dependency relationships |

### BSI TR-03183-2 v2.0

| Feature | Implementation | Required | Description |
| :------ | :------------- | :------- | :---------- |
| All BSI v1.1 features | - | Yes | Inherits all v1.1 requirements |
| Digital Signature | sbom_signature | Yes | Cryptographic signature verification |
| External References | sbom_bom_links | No | Links to other SBOMs |
| Vulnerability Info | sbom_vulnerabilities | No | Known vulnerabilities (absence preferred) |
| SHA-256 Checksums | comp_hash_sha256 | Yes | SHA-256 or stronger required |
| License Validation | comp_associated_license | Yes | Valid SPDX license identifiers |

### OpenChain Telco (OCT)

| Feature | Implementation | Required | SPDX Elements |
| :------ | :------------- | :------- | :------------ |
| SBOM Format | sbom_spec | Yes | Must be SPDX |
| Spec Version | sbom_spec_version | Yes | SPDX version |
| SPDX ID | sbom_spdxid | Yes | Document SPDXID |
| Document Name | sbom_name | Yes | SBOM name |
| Document Comment | sbom_comment | No | Additional info |
| Creator Organization | sbom_organization | No | Organization info |
| Creator Tool | sbom_tool | Yes | Tool name & version |
| Document Namespace | sbom_namespace | Yes | Unique namespace |
| Data License | sbom_license | Yes | CC0-1.0 or similar |
| Package Name | pack_name | Yes | All packages named |
| Package Version | pack_version | Yes | Package versions |
| Package SPDXID | pack_spdxid | Yes | Unique SPDX IDs |
| Package Download URL | pack_download_url | Yes | Where to get package |
| Files Analyzed | pack_file_analyzed | No | File analysis status |
| Package License Concluded | pack_license_con | Yes | Concluded license |
| Package License Declared | pack_license_dec | Yes | Declared license |
| Package Copyright | pack_copyright | Yes | Copyright text |

### AUTO-ISAC Automotive (Planned)

| Feature | Implementation | Required | Threshold | Automotive Focus |
| :------ | :------------- | :------- | :-------- | :--------------- |
| **Document Level** | | | | |
| SBOM Format | sbom_spec | Yes | SPDX/CDX | Machine readable |
| Spec Version | sbom_spec_version | Yes | SPDX 2.3+/CDX 1.4+ | Modern versions |
| Creation Timestamp | sbom_timestamp | Yes | ISO 8601 | Traceability |
| Creator Info | sbom_creator | Yes | Tool & person | Accountability |
| Document Version | sbom_doc_version | Yes | Present | Change tracking |
| Namespace/SerialNumber | sbom_namespace | Yes | Unique | Identity |
| Lifecycle Phase | sbom_lifecycle | Yes | Build/runtime | Context |
| Data License | sbom_data_license | Yes | CC0-1.0 | Sharing |
| Primary Component | primary_component | Yes | Defined | Clear scope |
| **Component Level** | | | | |
| Component Name | comp_name | Yes | 100% | All components |
| Component Version | comp_version | Yes | 100% | Version control |
| Component Supplier | comp_supplier | Yes | >95% | Supply chain |
| Unique Identifiers | comp_uniq_ids | Yes | 100% | Traceability |
| Component Type | comp_type | Yes | >90% | Classification |
| Package URL (PURL) | comp_purl | Yes | >90% | Identification |
| CPE | comp_cpe | Yes | >80% | CVE mapping |
| Checksums SHA-256+ | comp_hash_sha256 | Yes | >95% | Integrity critical |
| License Info | comp_license | Yes | >95% | Compliance |
| Copyright Text | comp_copyright | Recommended | >80% | Attribution |
| **Dependencies** | | | | |
| Complete Graph | dependency_complete | Yes | 100% | Safety analysis |
| All Relationships | dependency_relationships | Yes | Present | Full mapping |
| Direct vs Transitive | dependency_type | Yes | Distinguished | Clarity |
| No Orphans | dependency_no_orphans | Yes | 0 orphans | Completeness |
| Depth Tracked | dependency_depth | Yes | All levels | Impact analysis |
| **Security & Integrity** | | | | |
| Vulnerability Status | vuln_status | Yes | Documented | Risk awareness |
| CVE IDs | vuln_cve | Yes | Listed | Tracking |
| CVSS Scores | vuln_severity | Recommended | Present | Prioritization |
| Digital Signature | sbom_signature | Recommended | If safety-critical | Authentication |
| **Automotive Specific** | | | | |
| Safety Critical Flag | safety_critical | Yes | ASIL rated | ISO 26262 |
| ECU/Domain Mapping | ecu_mapping | Recommended | Present | Deployment |
| Tier Supplier Level | tier_supplier | Yes | Identified | Supply chain |
| Recall Readiness | recall_ready | Yes | Sufficient data | Regulatory |
| UN R155 Compliance | un_r155 | Required | Aligned | Cybersecurity |

### Profile Implementation Notes

#### Mapping to v2.0 Categories

Profile features may map to v2.0 scoring categories as follows:

- **NTIA features** → Primarily Identification, Completeness, and Provenance categories
- **BSI features** → All categories, with emphasis on Integrity (signatures, checksums)
- **OCT features** → Heavy focus on Licensing & Compliance, SPDX-specific metadata

#### Features Not in v2.0 Scoring

Some profile requirements exist outside the v2.0 scoring framework:

- **BSI Build Information**: Build phase/environment details (profile-specific)
- **BSI Source Code URL/Hash**: Source repository and verification (profile-specific)
- **OCT SPDX-specific fields**: SPDXID, FilesAnalyzed (format-specific)
- **Machine/Human readable formats**: Separate evaluation outside scoring
- **Delivery metadata**: Time, method, scope (enterprise-specific)
- **External references by type**: Security, package manager categories (detailed tracking)

#### Important Differences

1. **Profiles use --profile flag** for profile-based evaluation
2. **All profiles return scores** (0-10), not just pass/fail status
3. **BSI v2.0 includes signature scoring** for CycloneDX files with embedded signatures
4. **OCT is SPDX-only** and will fail on CycloneDX files
5. **Feature names differ** between profiles and v2.0 scoring (see tables above)

---

## Example Calculations

### Example 1: High-Quality SBOM

```text
Category Scores:
- Identification: 9.5 (weight: 10)
- Provenance: 8.8 (weight: 12)
- Integrity: 9.2 (weight: 15)
- Completeness: 8.5 (weight: 12)
- Licensing: 9.0 (weight: 15)
- Vulnerability: 7.5 (weight: 10)
- Structural: 10.0 (weight: 8)

Total Score = (9.5×10 + 8.8×12 + 9.2×15 + 8.5×12 + 9.0×15 + 7.5×10 + 10.0×8) / 82
Total Score = (95 + 105.6 + 138 + 102 + 135 + 75 + 80) / 82
Total Score = 730.6 / 82 = 8.91 (Grade B)
```

### Example 2: Feature Score Calculation

```text
Component Checksum Coverage:
- Total components: 150
- Components with SHA-256: 120
- Components with SHA-1 only: 20
- Components without checksums: 10

Checksum presence score = 10 × (140/150) = 9.33
SHA-256+ score = 10 × (120/150) = 8.00
Combined integrity feature score = (9.33×0.6 + 8.00×0.3) / 0.9 = 8.87
```

### Example 3: N/A Handling

```text
Licensing Category with N/A feature:
- Feature 1: Concluded licenses (score: 8.5, weight: 0.20) 
- Feature 2: Valid licenses (score: 9.0, weight: 0.20)
- Feature 3: Original licenses (score: 8.0, weight: 0.15)
- Feature 4: Data license (N/A for this SBOM type, weight: 0.10)
- Feature 5: No deprecated licenses (score: 10.0, weight: 0.15)
- Feature 6: No restrictive licenses (score: 7.0, weight: 0.20)

Adjusted weights (excluding feature 4 which is N/A):
- Total weight without N/A: 0.20 + 0.20 + 0.15 + 0.15 + 0.20 = 0.90
- Renormalization factor: 1.0 / 0.90 = 1.111

Adjusted category score = (8.5×0.20 + 9.0×0.20 + 8.0×0.15 + 10.0×0.15 + 7.0×0.20) × 1.111
                        = (1.7 + 1.8 + 1.2 + 1.5 + 1.4) × 1.111
                        = 7.6 × 1.111 = 8.44
```

### Example 4: Component Quality Display (Informational)

```text
Component Quality (API Key Required):
Total components: 150
- EOL/EOS: 8 (5.3%) - jquery@2.2.4, angular@1.8.3, moment@2.24.0
- Malicious: 0 (0%)
- KEV: 2 (1.3%) - log4j-core@2.14.1 (CVE-2021-44228), spring-beans@5.2.2 (CVE-2022-22965)
- EPSS >0.8: 4 (2.7%) - commons-text@1.9 (0.97)

Status: ATTENTION NEEDED
Note: Informational only, does not affect score (8.91/10.0, Grade B)
```

### Example 5: Profile-Based Scoring

```text
BSI TR-03183-2 v2.0 Profile:
Components: 150  Score: 8.58/10.0  Grade: B

Features:
- Component names: 10.0 (150/150, w:0.15)
- Component versions: 9.5 (143/150, w:0.15)
- SHA-256+ checksums: 8.0 (120/150, w:0.20)
- Valid licenses: 7.0 (105/150, w:0.15)
- PURL identifiers: 6.5 (98/150, w:0.10)
- Supplier info: 8.5 (128/150, w:0.10)
- Digital signature: 10.0 (present, w:0.15)

Status: COMPLIANT
Improvements needed:
- SHA-256 coverage: 80% -> 95%
- License validation: 70% -> 90%
- PURL identifiers: 65% -> 90%
```

---

## Appendix: License Lists

### Deprecated Licenses (Examples)

- AGPL-1.0
- AGPL-3.0
- BSD-2-Clause-FreeBSD
- BSD-2-Clause-NetBSD
- bzip2-1.0.5
- eCos-2.0
- GFDL-1.1
- GFDL-1.2
- GFDL-1.3
- GPL-1.0
- GPL-1.0+
- GPL-2.0
- GPL-2.0+
- GPL-2.0-with-autoconf-exception
- GPL-2.0-with-bison-exception
- GPL-2.0-with-classpath-exception
- GPL-2.0-with-font-exception
- GPL-2.0-with-GCC-exception
- GPL-3.0+
- GPL-3.0-with-autoconf-exception
- GPL-3.0-with-GCC-exception
- LGPL-2.0
- LGPL-2.0+
- LGPL-2.1
- LGPL-2.1+
- LGPL-3.0
- LGPL-3.0+
- Net-SNMP
- Nunit
- StandardML-NJ
- wxWindows

### Restrictive Licenses (Examples)

SPDX itself does not define any “restrictive” flag or field for licenses. We use AboutCode license categories to determine the resctriveness of a license. So, if a category `Copyleft" or "Copyleft Limited" category, then it is considered to be a "“restrictive” license.

- GPL family (copyleft)
- AGPL family (network copyleft)
- CC-BY-NC (non-commercial)
- CC-BY-ND (no derivatives)
- Proprietary licenses

### Permissive Licenses (Examples)

- MIT
- Apache-2.0
- BSD-2-Clause
- BSD-3-Clause
- ISC
- CC0-1.0

---

## Appendix: Profile Requirements

### NTIA Minimum Elements

The US National Telecommunications and Information Administration defines minimum elements for SBOMs:

- **Supplier Name**: Entity that creates, defines, and identifies components
- **Component Name**: Designation assigned by the supplier
- **Version String**: Identifier to specify a change from a previously identified version
- **Other Unique Identifiers**: Other identifiers to identify a component or serve as a look-up key
- **Dependency Relationship**: Characterization of relationship between components
- **Author of SBOM Data**: Name of entity that creates the SBOM
- **Timestamp**: Record of when the SBOM was created

### BSI TR-03183-2 Evolution

- **v1.0** (in German) and **v1.1** (English translation of v1.0 with minor corrections; both 2023): Initial requirements focusing on basic component identification
- **v2.0.0** (2024): This version added several new sections and required data fields, updated license fields, refined component definitions, and altered the minimum required versions for CycloneDX to 1.5 and SPDX to 2.2.1
- **v2.1.0** (2025): The data fields were restructured, minimum CycloneDX (1.6) and SPDX (3.0.1) versions were raised, the concepts of logical, external, identified and referenced components were introduced, and a new section for mapping of this Technical Guideline's requirements to an SPDX format's data fields was added

### AUTO-ISAC Automotive Requirements
Specific to automotive industry safety and compliance:

- **Safety-Critical Components**: Enhanced integrity verification (SHA-256 minimum)
- **Supply Chain Tracking**: Mandatory supplier identification for all components
- **Dependency Mapping**: Complete dependency graphs for safety analysis
- **Vulnerability Management**: CPE/CVE tracking for recall management
- **License Compliance**: Clear licensing for regulatory approval
- **Digital Signatures**: Authentication for safety-critical systems

### OpenChain Telco SBOM Guide

Telecommunications industry focus on open source compliance:

- **License Clarity**: All components must have identified licenses
- **License Validation**: Licenses must be valid SPDX identifiers
- **Original Licenses**: Declared/upstream licenses must be captured
- **Source Availability**: Source code links for GPL compliance
- **Attribution**: Complete author and supplier information
- **Vendor Management**: Clear identification of all suppliers

### Profile Compliance Thresholds

- **Pass/Fail Profiles** (NTIA, OpenChain Telco): All required elements must be present
- **Scored Profiles** (BSI, AUTO-ISAC): Weighted scoring with minimum thresholds
  - Grade A (9.0-10.0): Fully compliant, production-ready
  - Grade B (8.0-8.9): Compliant with minor gaps
  - Grade C (7.0-7.9): Minimally compliant, improvements needed
  - Grade D-F (<7.0): Non-compliant

---

## Implementation Notes

### Component Quality API Integration

1. **API Key Management**:
   - Component Quality metrics require an active API key for threat intelligence lookups
   - API keys should be stored securely (environment variables or secure configuration)
   - Without an API key, Component Quality section displays "Not Available"

2. **External Data Sources**:
   - **EOL/EOS Data**: Package registry APIs, EndOfLife.date API
   - **Malicious Components**: OpenSSF malicious packages
   - **KEV (Known Exploited Vulnerabilities)**: CISA KEV catalog (updated daily)
   - **EPSS Scores**: FIRST EPSS API (Exploit Prediction Scoring System)

3. **Caching Strategy**:
   - Cache Component Quality data for 24 hours to reduce API calls
   - KEV and EPSS data should be refreshed more frequently (every 6 hours)
   - Malicious component checks should be real-time or near real-time

4. **Performance Considerations**:
   - Component Quality checks are performed asynchronously
   - Batch API calls when possible (e.g., check multiple components in one request)
   - Implement rate limiting to respect API quotas
   - Timeout after 30 seconds if external APIs are unresponsive

5. **Fallback Behavior**:
   - If API is unavailable, display cached data with timestamp
   - Show clear messaging when data is unavailable or outdated
   - Never let Component Quality checks block the main scoring calculation

6. **Display Guidelines**:
   - Always clearly mark Component Quality as "Informational Only"
   - Show API key status (present/absent)
   - Use severity indicators: Critical, Warning, OK
   - Prioritize actionable items (KEV > Malicious > High EPSS > EOL)

### Profile Configuration

1. **Profile Selection**:
   - Profiles can be specified via `--profile` flag
   - Multiple profiles can be run simultaneously (comma-separated)
   - Default behavior runs comprehensive scoring without profiles

2. **Profile Customization**:
   - Profiles are defined in YAML configuration files
   - Custom profiles can be added to `~/.sbomqs/profiles/`
   - Enterprise-specific profiles supported

3. **Profile Output Modes**:
   - **Pass/Fail**: Binary compliance check (NTIA, OpenChain Telco)
   - **Scored**: Weighted scoring with grades (BSI, AUTO-ISAC)
   - **Hybrid**: Both compliance status and quality score

4. **Backwards Compatibility**:
   - Legacy category names (e.g., "NTIA-minimum-elements") mapped to new profile names
   - Old scoring behavior available via `--legacy` flag
   - Migration path provided for custom configurations

---

## Version History

| Version | Date       | Changes                                                |
| ------- | ---------- | ------------------------------------------------------ |
| 2.0.0   | 2025-01-20 | Initial release of new scoring mechanism              |
| 1.x     | 2022-2024  | Legacy scoring system (deprecated)                    |

---

This specification provides a robust, actionable framework for SBOM quality scoring that addresses real-world needs while remaining flexible and extensible.
