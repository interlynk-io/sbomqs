
# ENISA SBOM Minimum Elements: Field Reference

**Standard:** SBOM Analysis — Towards an Implementation Guide  
**Issuer:** European Union Agency for Cybersecurity (ENISA)  
**Version:** v1.20 (Published December 2025)  
**Key Section:** Table 2 — Comparative Analysis of Minimum Elements

This document explains how **sbomqs** evaluates SBOMs against the ENISA minimum elements identified in Table 2 of the ENISA Implementation Guide. ENISA itself does not invent new fields; it is a **comparative synthesis** of existing requirements (NTIA 2021 and CISA Draft 2025), mapping them to what SBOM standards should support.

**Important context:** ENISA's Table 2 shows two columns — one aligned with **NTIA 2021** requirements and one aligned with **CISA Draft 2025** requirements. Where the two sources differ, sbomqs treats both as valid sources and evaluates accordingly.

---

## Field Categories

ENISA Table 2 identifies **11 minimum elements** (NTIA and CISA use different names for the same timestamp field), organized as follows:

| Category | Count | Fields |
| :--- | :--- | :--- |
| **SBOM Metadata** (Document-level) | 4 | SBOM Author, Timestamp (Creation Timestamp), Tool Name, Generation Context |
| **Component Data** (Component-level) | 7 | Software Producer, Component Name, Component Version, Software Identifiers, Dependency Relationship, License, Component Hash |

## Summary Table

| ENISA Field | Table 2 Source | Category | Required | CycloneDX | SPDX v2.x | SPDX v3.x | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SBOM Metadata** |
| SBOM Author | NTIA + CISA | Document | Yes | `metadata.authors[]` (Person only) | `creationInfo.creators[]` (`Person` only) | `creationInfo.createdBy` → `Person` only | **Person only** — Organization represents supplier, not author; Tool entries **not** accepted |
| Timestamp | NTIA + CISA | Document | Yes | `metadata.timestamp` | `creationInfo.created` | `creationInfo.created` | NTIA calls it "Creation Timestamp", CISA calls it "Timestamp" — same single field in both formats |
| Tool Name | CISA | Document | Yes | `metadata.tools.components[].name` (1.5+), `metadata.tools[].name` (1.4) | `creationInfo.creators[].Tool` | `createdUsing` → `Tool.name` | Tool used to generate the SBOM |
| Generation Context | CISA | Document | Yes | `metadata.lifecycles[].phase` | `creationInfo.comment` | `Software/Sbom.sbomType` | Lifecycle stage: design, pre-build, build, post-build, operations, runtime |
| **Component Data** |
| Software Producer | NTIA + CISA | Component | Yes | `components[].authors[]` (Person only) | `packages[].originator` (`Person` only) | `Package.originatedBy` → `Person` only | **Person only** — Organization represents supplier, not producer; creator/originator of the component |
| Component Name | NTIA + CISA | Component | Yes | `components[].name` | `packages[].name` | `package.name` | |
| Component Version | NTIA + CISA | Component | Yes | `components[].version` | `packages[].versionInfo` | `package.packageVersion` | `UNKNOWN` / `NOASSERTION` / `NONE` accepted as valid non-empty values |
| Software Identifiers | NTIA + CISA | Component | Yes | `components[].purl`, `components[].cpe`, `components[].swid`, `components[].omniborId`, `components[].swhid` | `packages[].externalRefs[]` (PURL, CPE), `REFERENCE_CATEGORY_OTHER` (SWID, OmniBOR, commit); `packages[].contentIdentifier` (SPDX 3.x: gitoid, swhid) | `externalIdentifiers` (`packageUrl`, `cpe23`, `swid`); `contentIdentifier` (`gitoid`, `swhid`) | At least one identifier sufficient; per-component percentage score |
| Dependency Relationship | NTIA + CISA | Component | Yes | `dependencies[]` graph | `relationships[]` (`DEPENDS_ON`) | `relationships[]` (`dependsOn`) | Primary component + direct dependencies minimum; evaluated per component |
| License | CISA | Component | Yes | `components[].licenses[]` (1.4/1.5); `components[].licenses[]` with `acknowledgement=declared` (1.6+) | `packages[].licenseDeclared` | Linked via `hasDeclaredLicense` relationship type | Per-component percentage score; declared licenses |
| Component Hash | NTIA + CISA | Component | Yes | `components[].hashes[].content` + `components[].hashes[].alg` | `packages[].checksums[].checksumValue` + `packages[].checksums[].algorithm` | `software.verifiedUsing.hashValue` + `software.verifiedUsing.algorithm` | Per-component percentage score; value + algorithm both required |

---

## ENISA Context: NTIA 2021 vs CISA 2025

ENISA Table 2 is explicitly **comparative**. The two source columns differ in these ways:

| Element | NTIA 2021 Column | CISA Draft 2025 Column | sbomqs Approach |
| :--- | :--- | :--- | :--- |
| Timestamp | **Creation Timestamp** — generation time | **Timestamp** — last updated time | Both refer to the same single field in SPDX/CDX; evaluated as one feature |
| Tool | Not in NTIA 2021 | **Tool Name** — required | CISA-only; included in ENISA as mandatory |
| Generation Context | Not in NTIA 2021 | **Generation Context** — lifecycle phase | CISA-only; included in ENISA as mandatory |
| License | "Other Unique Identifiers" only | **License** — explicit requirement | CISA extends; sbomqs evaluates license separately from identifiers |
| Component Hash | Implied via identifiers | **Component Hash** — explicit requirement | CISA extends; sbomqs evaluates hash separately |

---

## SBOM Metadata (Document-Level)

### 1. SBOM Author

**ENISA Table 2 Definition (NTIA 2021):**
> "The name of the entity that creates the SBOM data for the target component."

**ENISA Table 2 Definition (CISA 2025):**
> "The name of the entity that creates the SBOM data."

**sbomqs Accepted Logic:**

The SBOM Author is the **Person** responsible for generating the SBOM data. **Organization entries are NOT accepted as authors** — an Organization represents a supplier or producer, not an author. Tool entries are also **not** accepted as authors; they are captured separately under Tool Name.

**Accepted Identifiers:**

* `name`
* `email`
* `url`

**Evaluation Order (Precedence):**

1. Explicit SBOM author (`Person` only)
2. Organization entries are **rejected** — use Supplier/Producer fields instead

**Mapping:**

- **SPDX v2.x:**
  - `creationInfo.creators[]` — **only `Person:` entries** are accepted as authors
  - `Organization:` entries are treated as supplier/producer, not author
  - Tool entries (`Tool: <name>-<version>`) are captured for Tool Name, not Author

- **SPDX v3.x:**
  - `creationInfo.createdBy` → **only `Person`** is accepted as author
  - `Organization` entries are treated as supplier/producer

- **CycloneDX:**
  - `metadata.authors[]` (preferred) — individual authors
  - `metadata.manufacturer` is **not** used as an author fallback — it represents the producing organization

---

### 2. Timestamp / Creation Timestamp

**ENISA Table 2 Definition (NTIA 2021):**
> "Date/time when SBOM was generated."

**ENISA Table 2 Definition (CISA 2025):**
> "Date/time when SBOM was last updated."

**sbomqs Accepted Logic:**

NTIA 2021 and CISA 2025 use **different names** for the same concept. In practice, SPDX and CycloneDX only provide a **single timestamp field** — there is no separate "created" vs "last updated" distinction in either format.

sbomqs therefore evaluates this as **one feature**: the presence and validity of the SBOM's single timestamp field satisfies both NTIA's "Creation Timestamp" and CISA's "Timestamp" requirements.

**Mapping:**

- **SPDX v2.x:** `creationInfo.created`
- **SPDX v3.x:** `creationInfo.created`
- **CycloneDX:** `metadata.timestamp`

---

### 3. Tool Name

**ENISA Table 2 Definition (CISA column):**
> "Tool used to generate the SBOM."

**sbomqs Accepted Logic:**

The tool that generated the SBOM. This is distinct from the SBOM Author. The tool may be identified in the same metadata structure (e.g., SPDX `creators[]` with `Tool:` prefix), but it is evaluated as a separate field.

**Mapping:**

- **SPDX v2.x:**
  - `creationInfo.creators[]` with `Tool:` prefix
  - Tool name and version may be combined (e.g., `Tool: sbomqs-2.1.0`)

- **SPDX v3.x:**
  - `createdUsing` → `Tool.name`

- **CycloneDX:**
  - `metadata.tools.components[].name` (1.5+)
  - `metadata.tools[].name` (1.4)

---

### 5. Generation Context

**ENISA Table 2 Definition (CISA column):**
> "Lifecycle stage when SBOM was created."

**sbomqs Accepted Logic:**

The lifecycle phase indicates when the SBOM was generated: design, pre-build, build, post-build, operations, or runtime. This informs consumers about the SBOM's accuracy and completeness expectations.

**Mapping:**

- **SPDX v2.x:**
  - `creationInfo.comment` (free-text; may contain phase information)
  - No standardized enum in SPDX 2.x

- **SPDX v3.x:**
  - `Software/Sbom.sbomType` (provides lifecycle context)

- **CycloneDX:**
  - `metadata.lifecycles[].phase` (standardized: `design`, `pre-build`, `build`, `post-build`, `operations`, `decommission`)

---

## Component Data (Component-Level)

### 6. Software Producer

**ENISA Table 2 Definition (NTIA + CISA):**
> "Entity that created, specified, and identified the component." (NTIA: "Supplier")

**sbomqs Accepted Logic:**

The Software Producer is the **Person** responsible for creating or originating the software component. **Organization entries are NOT accepted as producers/authors** — an Organization represents a supplier or distributor, not a creator. In ENISA's synthesis, "Producer" means the individual or role that authored/created the component, not the company that distributes it.

**Accepted Identifiers:**

* `name`
* `email`
* `url`

**Evaluation Order (Precedence):**

1. `authors` (CDX) / `originator` (SPDX 2.x) — the individual creator (Person only)
2. `manufacturer` (CDX 1.6+) — only if it represents an individual, not an organization
3. `supplier` — **never used**; supplier is distributor, not producer

**Rejected:**

* `Organization:` entries in SPDX `creators[]` or `originator`
* `Organization` types in SPDX 3.x `originatedBy`
* Company names in CDX `manufacturer` or `supplier`

**Mapping:**

- **SPDX v2.x:**
  - `packages[].originator` — **only `Person:` entries** accepted as producer
  - `packages[].supplier` — **never used** (represents distributor, not creator)

- **SPDX v3.x:**
  - `Package.originatedBy` → **only `Person`** accepted as producer
  - `Organization` entries are treated as supplier, not producer

- **CycloneDX:**
  - `components[].authors[]` (preferred) — individual authors/creators
  - `components[].manufacturer` — **not used** (represents producing organization)
  - `components[].supplier` — **not used** (represents distributing organization)

---

### 7. Component Name

**ENISA Table 2 Definition:**
> "Name of the software component."

**Mapping:**

- **SPDX v2.x:** `packages[].name`
- **SPDX v3.x:** `package.name`
- **CycloneDX:** `components[].name`

**sbomqs Logic:**

* Must be non-empty
* Required for **all components**

---

### 8. Component Version

**ENISA Table 2 Definition:**
> "Specific version identifier."

**Mapping:**

- **SPDX v2.x:** `packages[].versionInfo`
- **SPDX v3.x:** `package.packageVersion`
- **CycloneDX:** `components[].version`

**sbomqs Logic:**

* Must be present
* Evaluated per component
* `UNKNOWN` / `NOASSERTION` / `NONE` accepted as valid non-empty values

---

### 9. Software Identifiers

**ENISA Table 2 Definition:**
> "Consistent unique ID (PURL, SPDX ID, SWHID, etc.)."

**sbomqs Accepted Logic:**

At least one unique identifier per component is required. Multiple identifiers strengthen the SBOM but one is sufficient for compliance.

**Accepted Identifiers:**

* PURL (Package URL)
* CPE (Common Platform Enumeration)
* SWID (Software Identification Tag)
* OmniBOR ID (gitoid)
* SWHID (Software Heritage ID)
* SPDX ID (document-scoped identifier)

**Mapping:**

- **SPDX v2.x:**
  - `packages[].externalRefs[]`:
    - `purl` → `referenceCategory: PACKAGE_MANAGER`
    - `cpe23Type` → `referenceCategory: SECURITY`
    - `swid` → `referenceCategory: OTHER`

- **SPDX v3.x:**
  - `externalIdentifiers`:
    - `packageUrl` (PURL)
    - `cpe23` (CPE)
    - `swid` (SWID)
  - `contentIdentifier`:
    - `gitoid` (OmniBOR)
    - `swhid` (Software Heritage)

- **CycloneDX:**
  - `components[].purl`
  - `components[].cpe`
  - `components[].swid`
  - `components[].omniborId`
  - `components[].swhid`

---

### 10. Dependency Relationship

**ENISA Table 2 Definition:**
> "How component relates to others."

**sbomqs Accepted Logic:**

Dependency relationships describe how components are connected within the software product. At minimum, the primary (top-level) component and its direct dependencies should have defined relationships.

**Mapping:**

- **SPDX v2.x:**
  - `relationships[]` with `relationshipType: DEPENDS_ON`
  - Also accepts: `CONTAINS`, `DESCRIBES`, `DESCRIBED_BY`

- **SPDX v3.x:**
  - `relationships[]` with `relationshipType: dependsOn`

- **CycloneDX:**
  - `dependencies[]` graph
  - `compositions[]` for completeness assertions

---

### 11. License

**ENISA Table 2 Definition (CISA column):**
> "License(s) under which component is distributed."

**sbomqs Accepted Logic:**

License information is evaluated per component. For CycloneDX 1.6+, the `acknowledgement` field distinguishes between concluded and declared licenses. sbomqs evaluates **declared licenses** (what the component claims) for compliance.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].licenseDeclared` — the declared license
  - `packages[].licenseConcluded` — the concluded license (if evaluated separately)

- **SPDX v3.x:**
  - Linked via `hasDeclaredLicense` relationship type

- **CycloneDX:**
  - `components[].licenses[]` (1.4/1.5)
  - `components[].licenses[]` with `acknowledgement=declared` (1.6+)

---

### 12. Component Hash

**ENISA Table 2 Definition:**
> "Cryptographic hashes to verify integrity."

**sbomqs Accepted Logic:**

Cryptographic hashes verify component integrity. Both the hash value and the algorithm are required for a complete assessment.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].checksums[].checksumValue`
  - `packages[].checksums[].algorithm`

- **SPDX v3.x:**
  - `software.verifiedUsing.hashValue`
  - `software.verifiedUsing.algorithm`

- **CycloneDX:**
  - `components[].hashes[].content`
  - `components[].hashes[].alg`

**Accepted Algorithms:**

* SHA-256 (preferred)
* SHA-512 (preferred)
* SHA-1 (acceptable but not preferred)
* MD5 (acceptable but not preferred)

---

## ENISA Compliance Structure (sbomqs)

```text
ENISA Compliance Report

1. SBOM Metadata (Document-level)
   - SBOM Author
   - Timestamp / Creation Timestamp
   - Tool Name
   - Generation Context

2. Component Data (Component-level, per component)
   - Software Producer (N / Total)
   - Component Name (N / Total)
   - Component Version (N / Total)
   - Software Identifiers (N / Total)
   - Dependency Relationship (N / Total)
   - License (N / Total)
   - Component Hash (N / Total)
```

---

## Final Takeaway

> **ENISA does not define new SBOM fields.** It synthesizes existing requirements from NTIA 2021 and CISA Draft 2025 into a single comparative table.
>
> sbomqs evaluates ENISA compliance by checking all 12 identified elements, with mappings to both SPDX and CycloneDX. Where NTIA and CISA requirements differ (e.g., Timestamp vs Creation Timestamp, Tool Name, Generation Context), sbomqs evaluates both interpretations against the available SBOM fields.
>
> **Profiling measures quality and completeness. Compliance measures minimum ENISA acceptability. sbomqs keeps these concerns separate, explicit, and explainable.**
