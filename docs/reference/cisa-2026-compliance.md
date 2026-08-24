
# CISA 2026 SBOM Minimum Elements: Field Reference

**Standard:** SBOM Minimum Elements Report, 2026 Edition
**Issuer:** Cybersecurity and Infrastructure Security Agency (CISA), United States Department of Commerce, and allied agencies
**Publication Date:** July 29, 2026
**Effective:** Replaces and supersedes the NTIA Minimum Elements (2021) and all prior drafts

This document explains how **sbomqs** evaluates SBOMs against the finalized CISA 2026 Minimum Elements. It covers the official definitions, terminology shifts from the prior NTIA baseline, exact mappings to SPDX and CycloneDX, and the scoring logic sbomqs applies.

## What Changed from NTIA 2021/2025

The July 2026 guidance makes the following changes explicit:

- **Terminology realignment:**
  - `Supplier Name` → **Component Producer**
  - `Author of SBOM Data` → **SBOM Author**
  - `Version of the Component` → **Component Version**
- **New SBOM metadata elements:** Author Signature, Data Format Name, Data Format Version, Generation Context, Tool Name, Tool Version, SBOM Version
- **New component elements:** Component Hash Value, Component Hash Algorithm, Component License
- **Expanded scope:** Explicitly covers open-source software, AI-generated components, and SaaS
- **RFC 9557 timestamps:** All timestamps must now adhere to RFC 9557 (supersedes prior RFC 3339 guidance)
- **Machine-processable emphasis:** Stronger requirement for machine-actionable identifiers (PURL, CPE, SWID)

## Field Categories

CISA 2026 organizes elements into two groups:

1. **SBOM Metadata** (9 elements) — Information about the SBOM document itself
2. **Component Data** (8 elements) — Information about each enumerated component

## Summary Table

| CISA 2026 Field | Category | Required | CycloneDX | SPDX v2.x | SPDX v3.x | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| SBOM Author | SBOM Metadata | Yes | `metadata.authors[]` (preferred), then `metadata.manufacturer` | `creationInfo.creators[]` (`Person` / `Organization`) | `creationInfo.createdBy` → `Person` / `Organization` | Tool entries are **not** accepted as authors |
| SBOM Author Signature | SBOM Metadata | Yes | `signature` (JSF) | `--signature` / `--public-key` CLI flags (detached envelope) | `SpdxDocument.verifiedUsing` with `type: "Signature"` (embedded), or `--signature` / `--public-key` CLI flags (detached) | sbomqs detects embedded CycloneDX JSF signatures; SPDX 2.x and 3.x detached signatures via `--signature` + `--public-key`; SPDX 3.x embedded signatures via `verifiedUsing` |
| SBOM Data Format Name | SBOM Metadata | Yes | `bomFormat` | `spdxVersion` | `creationInfo.specVersion` | |
| SBOM Data Format Version | SBOM Metadata | Yes | `specVersion` | `spdxVersion` | `creationInfo.specVersion` | |
| SBOM Generation Context | SBOM Metadata | Yes | `metadata.lifecycles[].phase` | `creationInfo.comment` | `Software/Sbom.sbomType` | |
| SBOM Timestamp | SBOM Metadata | Yes | `metadata.timestamp` | `creationInfo.created` | `creationInfo.created` | Must be RFC 9557 compliant |
| SBOM Tool Name | SBOM Metadata | Yes | `metadata.tools.components[].name` (1.5+), `metadata.tools[].name` (1.4) | `creationInfo.creators[].Tool` | `createdUsing` → `Tool.name` | |
| SBOM Tool Version | SBOM Metadata | Yes | `metadata.tools.components[].version` (1.5+), `metadata.tools[].version` (1.4) | Extracted from `creationInfo.creators[].Tool` | Extracted from `createdUsing` → `Tool.name` | `UNKNOWN`, `NOASSERTION`, `NONE` accepted as valid non-empty values |
| SBOM Version | SBOM Metadata | Yes | `version` + `serialNumber` | N/A | N/A | SPDX does not support author-assigned document versions |
| Component Producer | Component Data | Yes | `components[].manufacturer` (1.6+), then `components[].authors[]` (1.5) | `packages[].originator` | `Package.originatedBy` | Per-component; replaces "Supplier Name" from NTIA 2021 |
| Component Dependency Relationship | Component Data | Yes | `dependencies[]` graph | `relationships[]` (`DEPENDS_ON`) | `relationships[]` (`dependsOn`) | Evaluated for primary component; top-level direct dependencies minimum |
| Component Hash Value | Component Data | Yes | `components[].hashes[].content` | `packages[].checksums[].checksumValue` | `software.verifiedUsing.hashValue` | Per-component percentage score |
| Component Hash Algorithm | Component Data | Yes | `components[].hashes[].alg` | `packages[].checksums[].algorithm` | `software.verifiedUsing.algorithm` | Per-component percentage score |
| Component Identifiers | Component Data | Yes | `components[].purl`, `components[].cpe`, `components[].swid`, `components[].omniborId`, `components[].swhid` | `packages[].externalRefs[]` (PURL, CPE), `REFERENCE_CATEGORY_OTHER` (SWID, OmniBOR, commit) | `externalIdentifiers` (`packageUrl`, `cpe23`, `swid`, `gitoid`, `swhid`) | Per-component percentage score; at least one identifier sufficient |
| Component License | Component Data | Yes | `components[].licenses[]` (1.4/1.5); `components[].licenses[]` with `acknowledgement=declared` (1.6+) | `packages[].licenseDeclared` | Linked via `hasDeclaredLicense` relationship type | Per-component percentage score; declared licenses only |
| Component Name | Component Data | Yes | `components[].name` | `packages[].name` | `package.name` | Per-component percentage score |
| Component Version | Component Data | Yes | `components[].version` | `packages[].versionInfo` | `package.packageVersion` | Per-component percentage score; `UNKNOWN` / `NOASSERTION` / `NONE` accepted |

## SBOM Metadata

### 1. SBOM Author

**Official Definition (2026):**
> "The name of the entity that creates the SBOM data for the target component."

**Old Definition (2021):**
> "The name of the entity that creates the SBOM data for this component."

**Change:** Clarified that the entity is creating the SBOM data *for the target component*, not for the component generically. Inputs should use full names and should not use acronyms (unless the official name of the entity includes an acronym).

**Motive:**
The SBOM author is the accountable party for the data. If the SBOM is incorrect, incomplete, or stale, automated tools and auditors must know who to contact. A name, email, or URL provides a traceable contact point.

**Mapping:**

- **SPDX v2.x:**
  - `creationInfo.creators[]`
    - `Person: <name> (<email>)`
    - `Organization: <name> (<email>)`

- **SPDX v3.x:**
  - `creationInfo.createdBy` → `Person` or `Organization`
    - `name` or `email` or `url`

- **CycloneDX:**
  - `metadata.authors[]` (preferred)
    - `name`
    - `email` (optional)
  - `metadata.manufacturer`
    - `name`
    - `url`

**Final Conclusion — SBOM Author:**
> **The SBOM Author is the identifiable person or organization that created the SBOM metadata. Automated tools are not accepted as authors under CISA 2026. At least one contact identifier (name, email, or URL) must be present.**

### 2. SBOM Author Signature

**Official Definition (2026):**
> "A digital signature attributable to the SBOM author."

**Motive:**
A digital signature proves the SBOM data has not been tampered with since the author produced it. It enables downstream consumers to verify authenticity before making risk decisions based on the SBOM contents.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - External signed envelope (detached from the SBOM document)

- **CycloneDX:**
  - `signature` (JSON Signature Format — JSF)
    - `algorithm`, `value`, optional `publicKey`

**Final Conclusion — SBOM Author Signature:**
> **A digital signature attributable to the SBOM author must be present.**
>
> sbomqs detects signatures as follows:
> 
> - **CycloneDX:** inline JSF signature inside the `signature` element (JSF — `algorithm`, `value`, optional `publicKey`).
> - **SPDX v2.x:** detached signature via `--signature <path>` and `--public-key <path>` CLI flags.
> - **SPDX v3.x:** embedded signature inside `SpdxDocument.verifiedUsing` with `type: "Signature"` (`algorithm`, `signatureValue`, optional `publicKey`), or detached signature via `--signature` and `--public-key` CLI flags.
>
> sbomqs checks that the signature object is present, complete (algorithm + value), and that verification material (public key or certificate) is provided where applicable.

### 3. SBOM Data Format Name

**Official Definition (2026):**
> "The name of the data format used to represent the SBOM data."

**Motive:**
Consumers must know which specification to use when parsing the SBOM. The format name identifies the ecosystem (SPDX vs CycloneDX) and determines which validation tools and schemas apply.

**Mapping:**

- **SPDX v2.x:**
  - `spdxVersion` — e.g., `SPDX-2.2`, `SPDX-2.3`

- **SPDX v3.x:**
  - `creationInfo.specVersion` — e.g., `3.0.1`

- **CycloneDX:**
  - `bomFormat` + media type — e.g., `CycloneDX`

**Final Conclusion — SBOM Data Format Name:**
> **The SBOM must declare its data format name. sbomqs accepts SPDX or CycloneDX as valid machine-readable formats.**

### 4. SBOM Data Format Version

**Official Definition (2026):**
> "Identifier designated by the SBOM data format to specify the version of the data format."

**Motive:**
Different versions of the same format support different fields. Knowing the exact version lets consumers determine whether required fields are expected to exist and which schema to validate against.

**Mapping:**

- **SPDX v2.x:**
  - `spdxVersion` — e.g., `SPDX-2.2`, `SPDX-2.3`

- **SPDX v3.x:**
  - `creationInfo.specVersion` — e.g., `3.0.1`

- **CycloneDX:**
  - `specVersion` — e.g., `1.5`, `1.6`, `1.7`

**Final Conclusion — SBOM Data Format Version:**
> **The SBOM must declare the version of its data format. sbomqs extracts the version from the format-specific field and validates it against supported versions.**

### 5. SBOM Generation Context

**Official Definition (2026):**
> "The relative software lifecycle phase and data available at the time the SBOM author generated the SBOM."

**Motive:**
An SBOM generated from source code (design phase) contains different information than one generated from a built artifact (build phase). The generation context tells consumers what kind of data they can expect and whether the SBOM is likely to be complete.

**Mapping:**

- **SPDX v2.x:**
  - `creationInfo.comment`

- **SPDX v3.x:**
  - `Software/Sbom.sbomType`

- **CycloneDX:**
  - `metadata.lifecycles[].phase`
    - e.g., `design`, `pre-build`, `build`, `post-build`, `operations`, `decommission`

**Final Conclusion — SBOM Generation Context:**
> **The generation context indicates the software lifecycle phase during which the SBOM was produced. sbomqs checks the format-specific lifecycle or comment field for a non-empty value.**

### 6. SBOM Timestamp

**Official Definition (2026):**
> "Record of the date and time of the most recent update to the SBOM data."

**Old Definition (2021):**
> "Record of the date and time of the SBOM data assembly."

**Change:** Clarified that the timestamp reflects the *most recent update*, not just initial assembly. Each version of an SBOM must have a new timestamp. Content must adhere to RFC 9557.

**Motive:**
The timestamp is essential for determining whether an SBOM is stale. Vulnerability databases, component versions, and risk postures change over time; the timestamp anchors the SBOM to a specific point in time for correlation.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - `creationInfo.created`

- **CycloneDX:**
  - `metadata.timestamp`

**Final Conclusion — SBOM Timestamp:**
> **The SBOM must include a timestamp of its most recent update. sbomqs validates that a valid RFC 9557 timestamp is present.**

### 7. SBOM Tool Name

**Official Definition (2026):**
> "The name of the tool used by the SBOM author to generate or amend the SBOM."

**Motive:**
Knowing which tool produced the SBOM helps consumers understand the quality and completeness of the data. Different tools have different capabilities (e.g., some capture hashes, some don't). Tool names also help with debugging and reproducibility.

**Mapping:**

- **SPDX v2.2:**
  - `creationInfo.creators[].Tool`
    - e.g., `syft-0.78.0`, `Microsoft.SBOMTool-1.0.2`

- **SPDX v3.x:**
  - `createdUsing` → `Tool.name`
    - e.g., `spdx-tools-1.0.0`

- **CycloneDX 1.5, 1.6, 1.7:**
  - `metadata.tools.components[].name`

- **CycloneDX 1.4:**
  - `metadata.tools[].name`

**Final Conclusion — SBOM Tool Name:**
> **The name of the tool used to generate the SBOM must be present. sbomqs extracts the tool name from the format-specific tool metadata field.**

### 8. SBOM Tool Version

**Official Definition (2026):**
> "Identifier for the version of the tool identified in the SBOM Tool Name element."

**Motive:**
The tool version allows consumers to identify a specific code delivery of the generator. Different versions of the same tool may produce different field coverage or quality levels. If no version is available, the SBOM author should indicate that the information is unknown.

**Mapping:**

- **SPDX v2.2:**
  - `creationInfo.creators[].Tool` — version extracted from the string
    - e.g., `syft-0.78.0` → version `0.78.0`

- **SPDX v3.x:**
  - `createdUsing` → `Tool.name` — version extracted from the string

- **CycloneDX 1.5, 1.6, 1.7:**
  - `metadata.tools.components[].version`

- **CycloneDX 1.4:**
  - `metadata.tools[].version`

**Final Conclusion — SBOM Tool Version:**
> **The version of the SBOM generation tool must be present. sbomqs extracts the version from tool metadata. Values indicating unavailability (UNKNOWN, NOASSERTION, NONE) are accepted as valid non-empty values.**

### 9. SBOM Version

**Official Definition (2026):**
> "Identifier designated by the SBOM author to specify a change in the SBOM document from a previously identified version or to indicate that it is the first version."

**Motive:**
The SBOM version indicates a relationship with earlier iterations of an SBOM. It signals that the SBOM author made changes to the previous iteration. This is the version of the SBOM document itself, not the version of any component or the data format.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - **Not supported by the SPDX specification.** No author-assigned document version field exists.

- **CycloneDX:**
  - `version` (integer)
  - `serialNumber` (UUID)
  - Together these identify the BOM document revision.

**Final Conclusion — SBOM Version:**
> **The SBOM document version is required for CycloneDX (`version` + `serialNumber`). SPDX does not support author-assigned document versions, so this field is scored as N/A for SPDX SBOMs.**

## Component Data

### 10. Component Producer

**Official Definition (2026):**
> "The name of an entity that creates, defines, and identifies components."

**Old Terminology (2021):**
> "Supplier Name"

**Change:** "Component Producer" replaces "Supplier Name." The definition is substantively the same, but the terminology is now aligned with CISA 2026 vocabulary.

**Motive:**
The component producer is the authority responsible for the component's identity. This entity may be an organization, a project, or an upstream source. Distinguishing between components of the same name produced by different entities is essential for vulnerability correlation and license compliance.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].originator`
    - `name` or `email` or `url`

- **SPDX v3.x:**
  - `Package.originatedBy`
    - `name` or `email` or `url`

- **CycloneDX 1.5:**
  - `components[].author`
    - `name` or `email` or `url`

- **CycloneDX 1.6, 1.7:**
  - `components[].manufacturer`
    - `name` or `email` or `url`
  - `components[].authors[]`
    - `name` or `email` or `url`

**Final Conclusion — Component Producer:**
> **Component Producer is a per-component field identifying the entity that created or defined the component. sbomqs checks each component for a name, email, or URL identifying the producer.**

### 11. Component Dependency Relationship

**Official Definition (2026):**
> "The relationship between two components, where one component is necessary for the operation of the other."

**Old Definition (2021):**
> "Characterizing the relationship that an upstream component X is included in software Y."

**Change:** Restated as a bidirectional necessity relationship rather than a unidirectional inclusion. Emphasizes that the relationship supports dependency graph construction.

**Motive:**
Dependency relationships enable consumers to build a dependency graph, which is essential for vulnerability reachability analysis, license propagation, and impact assessment.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - `relationships[]` with `dependsOn` or `DEPENDS_ON`

- **CycloneDX:**
  - `dependencies[]` graph
  - `dependsOn` references

**Final Conclusion — Component Dependency Relationship:**
> **The SBOM must declare dependency relationships for the primary component. At minimum, direct (top-level) dependencies must be present.**

### 12. Component Hash Value

**Official Definition (2026):**
> "The output generated from applying a cryptographic hash algorithm to an executable component artifact."

**Motive:**
Hashes provide integrity verification. Consumers can re-compute the hash of a downloaded artifact and compare it against the SBOM to detect tampering, corruption, or substitution attacks.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].checksums[].checksumValue`

- **SPDX v3.x:**
  - `software.verifiedUsing.hashValue`

- **CycloneDX:**
  - `components[].hashes[].content`

**Final Conclusion — Component Hash Value:**
> **Each component should have a cryptographic hash value for integrity verification. sbomqs scores this as a per-component percentage.**

### 13. Component Hash Algorithm

**Official Definition (2026):**
> "The cryptographic algorithm used to compute the Component Hash Value of the software component."

**Motive:**
The hash algorithm must be documented so consumers can validate the integrity of the component using the correct algorithm. Weak or obsolete algorithms undermine the security purpose of the hash.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].checksums[].algorithm`

- **SPDX v3.x:**
  - `software.verifiedUsing.algorithm`

- **CycloneDX:**
  - `components[].hashes[].alg`

**Final Conclusion — Component Hash Algorithm:**
> **The hash algorithm must be declared alongside the hash value. sbomqs scores this as a per-component percentage, matching the hash value coverage.**

### 14. Component Identifiers

**Official Definition (2026):**
> "Identifiers used to identify a component or serve as a look-up key for relevant databases."

**Old Definition (2021):**
> "Other identifiers that are used to identify a component, or serve as a look-up key for relevant databases."

**Change:** "At least one" is now explicit. Expanded list of accepted identifiers to include UUID, OmniBOR, SWHID, and commit hashes.

**Motive:**
Machine-processable, unique identifiers support automated analysis. PURL enables package manager lookups; CPE enables NVD correlation; SWID enables software asset management; OmniBOR and SWHID enable reproducible builds.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].externalRefs[]`
  - `REFERENCE_CATEGORY_OTHER` for SWID, OmniBOR, commit hashes
  - `purl`, `cpe22Type`, `cpe23Type`

- **SPDX v3.x:**
  - `externalIdentifiers.identifier`
  - `externalIdentifierType`: `cpe22`, `cpe23`, `gitoid`, `packageUrl`, `swhid`, `swid`

- **CycloneDX:**
  - `components[].cpe`
  - `components[].purl`
  - `components[].swid`
  - `components[].omniborId`
  - `components[].swhid`

**Final Conclusion — Component Identifiers:**
> **Each component must have at least one machine-processable identifier. sbomqs accepts PURL, CPE, SWID, OmniBOR, SWHID, commit hashes, and other unique identifiers. Presence of any one is sufficient.**

### 15. Component License

**Official Definition (2026):**
> "The identifier(s) for the license(s) under which the software component is available."

**Motive:**
License information is critical for legal compliance, redistribution decisions, and supply chain risk management. The license identifier should allow consumers to find the full license text. If no SPDX identifier is available, a URL or other machine-processable reference is acceptable.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].licenseDeclared`

- **SPDX v3.x:**
  - Linked via `hasDeclaredLicense` relationship type

- **CycloneDX 1.4, 1.5:**
  - `components[].licenses[]`

- **CycloneDX 1.6, 1.7:**
  - `components[].licenses[]` with `acknowledgement=declared`

**Final Conclusion — Component License:**
> **Each component must declare its license information. sbomqs accepts SPDX identifiers, declared expressions, and generic license references. Unknown licenses should be explicitly marked as such.**

### 16. Component Name

**Official Definition (2026):**
> "The name assigned by the component producer to a software component."

**Old Definition (2021):**
> "Designation assigned to a unit of software defined by the original supplier."

**Change:** Now explicitly assigned by the **component producer** (not the supplier). Emphasizes that the producer determines the name.

**Motive:**
The component name is the most fundamental human-readable identifier. Without it, an SBOM entry cannot be matched against vulnerability databases, license registries, or other SBOMs.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - `packages[].name`

- **CycloneDX:**
  - `components[].name`

**Final Conclusion — Component Name:**
> **Every component must have a non-empty name assigned by its producer. sbomqs checks all components for name presence.**

### 17. Component Version

**Official Definition (2026):**
> "Identifier used by the component producer to specify a change in a software component from a previously identified version or to indicate that it is the first version."

**Old Definition (2021):**
> "Identifier used by the supplier to specify a change in software from a previously identified version."

**Change:** Now explicitly the **component producer's** version identifier. If the producer does not provide a version, the SBOM author should indicate that the information is unknown.

**Motive:**
Vulnerability tracking is version-specific. A CVE may affect version `1.2.3` but not `1.2.4`. Without a version, it is impossible to determine whether a given component instance is affected.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].versionInfo`

- **SPDX v3.x:**
  - `package.packageVersion`

- **CycloneDX:**
  - `components[].version`

**Final Conclusion — Component Version:**
> **Every component must have a version identifier. If the producer does not provide one, the SBOM author must explicitly indicate that the information is unknown.**

## CISA 2026 Compliance Structure (sbomqs)

```text
CISA 2026 Minimum Elements Compliance Report

1. SBOM Metadata (Document-level)
   - SBOM Author
   - SBOM Author Signature
   - SBOM Data Format Name
   - SBOM Data Format Version
   - SBOM Generation Context
   - SBOM Timestamp
   - SBOM Tool Name
   - SBOM Tool Version
   - SBOM Version (CycloneDX only; N/A for SPDX)

2. Component Data (Per-component)
   - Component Producer (N / Total)
   - Component Name (N / Total)
   - Component Version (N / Total)
   - Component Identifiers (N / Total)
   - Component Hash Value (N / Total)
   - Component Hash Algorithm (N / Total)
   - Component License (N / Total)
   - Component Dependency Relationship (primary component)

3. Practices & Processes
   - Depth (top-level dependencies)
   - Known Unknowns (explicitly marked unknown information)
   - Non-machine-testable practices explicitly noted
```

## Final Takeaway

> **Profiling measures quality, completeness, and correctness.
> Compliance measures minimum CISA 2026 acceptability.
> sbomqs deliberately keeps these concerns separate, explicit, and explainable.**

The CISA 2026 guidance replaces both the NTIA 2021 Minimum Elements and all prior drafts. The `cisa-2026` profile in sbomqs reflects the finalized vocabulary, new elements, and updated mappings. The legacy `ntia` (2021) profile remains available for regulations that still cite the 2019/2021 baseline.
