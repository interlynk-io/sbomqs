# OpenChain SBOM Document Quality Guide: sbomqs Implementation Reference

> **Document Version:** OpenChain SBOM Document Quality Guide v2026.04.03  
> **Purpose:** Explain the Guide's quality framework and how sbomqs implements it.

## 1. What Is the OpenChain SBOM Document Quality Guide?

The OpenChain SBOM Document Quality Guide is a **format-independent framework** focused on the **quality of the information contained within an SBOM document** specifically via **accuracy** and **integrity**.

In short it answer the below question:
> *"Even if an SBOM is syntactically valid SPDX or CycloneDX, is the information inside actually good enough to use for security and compliance?"*

## 2. The Quality Framework: Accuracy and Integrity

The guide builds quality in two dimensions:

### 2.1 Accuracy

Accuracy is not a single checkbox. The guide divides it into **three layers**:

| Layer | What It Means | Guide Sections |
|-------|--------------|----------------|
| **1. Standardization First** | Use SPDX or CycloneDX so everyone speaks the same language; use JSON/XML for automation | 3.1, 3.3 |
| **2. Minimum Fields Required** | Define what information must be present at Document, Package, License, and Relationship levels | 3.2 |
| **3. Accuracy of That Information** | The values must be correct: package names match vulnerability databases, identifiers (PURL, CPE) are valid, licenses use standardized expressions | 3.2 details, Section 5 |

> **Bottom line:** Accuracy = **correct, complete, and standardized** information.

### 2.2 Integrity

Integrity ensures the document has not been tampered with and can be shared freely:

| Aspect | Requirement | Section |
|--------|-------------|---------|
| **Verification** | Digital signatures SHOULD be provided to guarantee the document has not changed | 3.6 |
| **Confidentiality** | Access controls are allowed, but redistribution SHALL NOT be blocked; TLP labeling recommended | 3.7 |

## 3. The Seven Quality Criteria

An SBOM Document is recognized as high-quality when it meets these seven criteria from Chapter 3:

### 3.1 Data Format

- SHALL be in a machine-readable format (JSON, XML, YAML).
- MUST use internationally recognized formats such as **SPDX** or **CycloneDX**.

### 3.2 Elements to Be Included

#### Document Information

| Element | Description | Format Mapping |
|---------|-------------|----------------|
| Format Version | The spec version used | SPDX: `spdxVersion`; CycloneDX: `specVersion` |
| SBOM Document License | License under which the SBOM itself is distributed | SPDX: `dataLicense`; CycloneDX: `metadata.licenses` |
| Unique ID | Document-level identifier | SPDX: `SPDXID` + `DocumentNamespace`; CycloneDX: `serialNumber` + `version` |
| Creation Info | Who created it, when, and in what lifecycle phase | SPDX: `creators`, `created`; CycloneDX: `metadata.authors`, `metadata.timestamp`, `metadata.lifecycle` |

#### Software Package Information

| Element | Why It Matters |
|---------|----------------|
| Package Name | Must match vulnerability database conventions |
| Package Version | Specific version identifier |
| Package Identifiers | PURL, CPE, SWHID, gitoid, or distribution URL |
| Package Supplier | Contact info (valid email or URL) for vulnerability reporting |
| Package Hash | Cryptographic hash to verify component integrity |
| Proprietary Software Indicator | Distinguishes open source from proprietary components |

#### License Information

| Element | Description |
|---------|-------------|
| License Declared | The license as declared by the component author (SPDX License Expressions) |
| License Concluded | The license as concluded by the SBOM creator/distributor |

#### Relationship Information

| Element | Requirement |
|---------|-------------|
| Primary Component | Must specify which component the SBOM describes (`DESCRIBES`) |
| Containment Relationships | Must express how components relate (`CONTAINS`, `DEPENDS_ON`) |

### 3.3 File Format

- SHALL be machine-readable (enabling automated processing by SCA tools).
- SHOULD be human-readable or easily convertible to human-readable form.

### 3.4 Timing of Delivery

- The SBOM SHALL be available **no later than at the time of software delivery**.
- High-quality SBOMs are delivered with the software, not tracked down afterwards. If the SBOM arrives after delivery, the recipient has already accepted software they have not properly vetted.

### 3.5 SBOM Document Scope

**Core Requirements:**

- **Open Source Software:** Every OSS component delivered with the product **MUST** be listed.
- **Commercial Components:** Commercial/proprietary components **SHOULD** be included.

**Known Unknowns Mechanism:**
When components are missing or unclear, the SBOM cannot silently omit them. They **SHALL** be reported as "Known Unknowns" — explicitly labeled gaps.

| Category | Definition | Example |
|----------|------------|---------|
| **Genuinely Unknown** | Information truly unavailable at creation time | A transitive dependency the tools could not resolve |
| **Intentionally Withheld** | Information exists but is deliberately excluded | Proprietary component details under NDA |

### 3.6 SBOM Document Verification

- Digital signatures **SHOULD** be provided to guarantee document integrity.
- Sigstore is referenced as a recommended verification resource.

### 3.7 SBOM Document Confidentiality

- Access controls **SHOULD** be implemented for confidential content.
- Confidentiality agreements **SHALL NOT** prevent recipients from redistributing the SBOM Document alongside the software.
- TLP (Traffic Light Protocol) labeling is recommended for managing confidentiality.

## 4. How the Guide Enforces Quality

The guide achieves its quality goals through **prescriptive requirements**, **standardization mandates**, and **verifiability mechanisms**:

| Quality Aspect | How the Guide Enforces It |
|----------------|---------------------------|
| **Accuracy** | Standardized identifiers (PURL, CPE), naming conventions, required element definitions |
| **Completeness** | Mandatory element lists, "Known Unknowns" reporting, transitive dependency inclusion |
| **Integrity** | Digital signatures, hash values, author accountability |
| **Timeliness** | Delivery timing requirements |
| **Consistency** | Machine-readable format mandates (SPDX/CycloneDX), granularity standardization |

## 5. Common Quality Issues and Improvement Measures (Section 5)

Section 5 bridges theory with practice, showing why accuracy matters and what goes wrong when requirements are not met.

| Issue | Core Problem | Key Solution |
|-------|--------------|--------------|
| **5.1 Value Consistency** | Inconsistent package names/versions across tools | Standardized identifiers (PURL) |
| **5.2 Granularity** | File-level vs. package-level mismatch | Explicitly declare granularity level |
| **5.3 Source Code Info** | Binary-only distributions lack traceability | Include source URLs, commit hashes, pedigree |
| **5.4 Component ID** | Poor identification misses vulnerabilities | Align with OSV/NVD naming; include supplier contact |
| **5.5 Tamper Detection** | No mechanism to detect modifications | Digital signatures, version control |
| **5.6 Scope & Accountability** | Unclear who owns what data | Define responsibilities per entity |
| **5.7 Relationships** | Different tools express dependencies differently | Standardized relationship types |
| **5.8 Interoperability** | Tools have varying capabilities | Balanced conformance levels (MUST vs. SHOULD vs. MAY) |

## 6. sbomqs Implementation & Support

sbomqs is Interlynk's SBOM quality scoring tool. Below is the current support matrix for OpenChain Quality Guide requirements.

### 6.1 Fully Supported

| Quality Guide Field | sbomqs Check |
|---------------------|--------------|
| Data Format (SPDX/CycloneDX) | Validates format and JSON/XML schema |
| Format Version | Checks spec version compliance |
| Unique ID | Validates `SPDXID`, `serialNumber` |
| Author / Timestamp | Presence and format validation |
| Package Name / Version | Required field check |
| PURL Identifiers | Validates Package URL format |
| Package Hash | Algorithm and presence validation |
| Primary Component Relationship | Checks `DESCRIBES` relationship |
| License Presence | Validates declared license and SPDX expression |
| SBOM Document License | Checks presence |
| Generation Context / Lifecycle | detect field |
| CPE Identifiers | check presence |
| Supplier Contact | Presence check and validate email/URL |
| License Concluded | Checks presence and validate from SPDX List |
| File Format Nuances | Validates JSON |
| Digital signed SBOM | support signatue validation |


### 6.2 Not Yet Supported (Implementation Opportunities)

| Quality Guide Field | Why It Matters | Opportunity |
|---------------------|----------------|-------------|
| **Proprietary software** indicator | Distinguishes OSS from commercial components | Add scope classification checks |
| **TLP labeling** | Traffic Light Protocol for confidentiality management | Add metadata property checks |
| **Scope validation** | Verifies all OSS components are listed | Add completeness heuristics |
| **Timing validation** | Ensures SBOM is delivered with software | Process-level check (out of band) |

## 7. Conclusion

The OpenChain SBOM Document Quality Guide treats SBOM quality as a **compliance exercise with operational consequences**. It moves beyond "is this valid JSON?" to ask:

- Is the information **correct** (accuracy)?
- Is the information **complete** (scope, known unknowns)?
- Is the information **verifiable** (integrity, signatures)?
- Is the information **actionable** (standardized identifiers, correct granularity)?

For sbomqs, this means our scoring engine must evolve from **structural validation** to **semantic quality assessment**, checking not just that a field exists, but that its value is meaningful for vulnerability correlation, license compliance, and supply chain transparency.

**NOTE**: *This document is a living reference. As the OpenChain Guide evolves and sbomqs capabilities expand, this mapping should be updated to reflect the latest compliance and tooling landscape.*