# Compliance & Profiling Quality Summary Report

*(FSCT – Framing Software Component Transparency, 3rd Edition, sbomqs Interpretation)*

This document explains how **sbomqs** evaluates **FSCT (Framing Software Component Transparency)** across **profiling** (quality scoring) and **compliance-style baseline checks**.

FSCT is **not a minimum-field checklist** like NTIA.
Instead, it focuses on **transparency**, **declaration**, and **coverage** of SBOM data. It's more of a community-driven compliance whose motive is to make SBOMs better.

This document defines:

- the **official FSCT intent** for each transparency signal,
- mapping each field to **SPDX** and **CycloneDX**, and
- the **exact logic sbomqs applies**, including baseline rules, coverage handling, and scoring behavior.

The goal is to make FSCT evaluation **fully explainable**, so users understand **what is missing**, **what is already present**, and **why a score was produced**.

## 1. FSCT Transparency Elements

### Summary Table

| Check ID                 | FSCT Signal                 | Type                      | SPDX Mapping                                | CycloneDX Mapping                      |
| ------------------------ | --------------------------- | ------------------------- | ------------------------------------------- | -------------------------------------- |
| `sbom_provenance`        | SBOM Provenance             | Baseline (binary)         | CreationInfo.Creators, CreationInfo.Created | metadata.authors, metadata.timestamp   |
| `sbom_primary_component` | Primary Component Defined   | Baseline (binary)         | DocumentDescribes                           | metadata.component                     |
| `comp_identity`          | Component Identity          | Baseline (binary)         | PackageName + PackageVersion                | component.name + component.version     |
| `supplier_attribution`   | Supplier Attribution        | Baseline (binary)         | PackageSupplier                             | component.supplier                     |
| `comp_unique_id`         | Unique Identification       | Baseline (binary)         | ExternalRef (PURL, CPE, etc.)               | component.purl, component.cpe          |
| `artifact_integrity`     | Artifact Integrity (Hashes) | Baseline (binary)         | PackageChecksum                             | component.hashes                       |
| `relationships_coverage` | Dependency Relationships    | Baseline (primary + deps) | Relationship (DEPENDS_ON) + composition     | dependencies + dependency completeness |
| `license_coverage`       | License Coverage            | Coverage-based            | PackageLicenseDeclared                      | component.licenses                     |
| `copyright_coverage`     | Copyright Coverage          | Coverage-based            | PackageCopyrightText                        | component.copyright                    |

## 1.1 SBOM Provenance

### FSCT Definition

> Provenance describes **who produced the SBOM** and **when it was produced**.

**SBOM Author official definition:**
> Minimum Expected: An SBOM must list the entity that prompted the creation of the SBOM. The Author Name Attribute should include the name of the legal entity and some form of unique identification (e.g., an email address or website) if possible. If no legal entity name is available, attempt to uniquely identify the SBOM creator along with contact information.

**SBOM Timestamp official definition:**
> As a minimum expectation: The Timestamp is the date and time that the SBOM was produced.

Both are required at minimum level.

#### Evaluation Rules

- Both **author** and **timestamp** must be present
- Either missing → provenance is incomplete

### Mapping of SBOM Provenance

**SPDX:**

- `CreationInfo.Created`
- `CreationInfo.Creators`

**CycloneDX:**

- `metadata.timestamp`
- `metadata.authors`

---

## 1.2 Primary Component (SBOM Subject)

### SBOM Primary Component official definition

> The Primary Component, or root of Dependencies, is the subject of the SBOM or the foundational Component being described in the SBOM.

### Mapping of Primary Component

**SPDX:**

- `DocumentDescribes`

**CycloneDX:**

- `metadata.component`

---

## 1.3 Component Identity

### Component Name official definition

> As a minimum expectation, the Component name should declare the commonly used public name for the Component. The Component Name is defined as the public name for a Component defined by the Originating Supplier of the Component.

### Component Version official definition

> As a minimum expectation, declare the version string as provided by the Supplier. The Version is a supplier-defined identifier that specifies an update change in the software from
a previously identified version.

#### Evaluation Rules

- Both **name** and **version** must be present
- Either missing → component identity is incomplete

### Mapping of Component Identity

**SPDX:**

- `PackageName`
- `PackageVersion`

**CycloneDX:**

- `component.name`
- `component.version`

---

## 1.4 Supplier Attribution

### Supplier official definition

> As a minimum expectation, the Supplier Name should be declared for all Components. Supplier Name is the entity that creates, defines, and identifies a Component.

### Mapping

**SPDX:**

* `PackageSupplier`

**CycloneDX:**

* `component.supplier`

---

## 1.5 Unique Identification

### Unique ID official definition

> Minimum Expected: at least one unique identifier should be declared for each Component listed in the SBOM. A globally unique identifier is preferred.

- Accepted unique identifiers include:
  - PURL
  - CPE
  - SWHID
  - SWID
  - Omnibor

### Mapping

**SPDX:**

- `ExternalRef`:
  - `purl`
  - `cpe23Type`

**CycloneDX:**

- `component.purl`
- `component.cpe`

---

## 1.6 Artifact Integrity (Cryptographic Hashes)

### Cryptographic Hashes official definition

> Minimum Expected: Provide a hash for any Component listed in the SBOM for which the hash was provided or sufficient information is available to generate the hash. If sufficient information is not available, indicate as unknown.

### Mapping

**SPDX:**

- `PackageChecksum`

**CycloneDX:**

- `component.hashes`

---

## 1.7 Dependency Relationships & Completeness

### Dependency Relationship official definition

> Minimum Expected - Relationships and relationship completeness declared for the Primary Component and direct Dependencies.

### Requirements

- Primary component must declare:
  - its direct dependencies, and
  - dependency completeness
- All **direct dependencies** must also declare completeness

---

## 1.8 License Coverage

### License official definition

> Minimum Expected: Provide license information for the Primary Component.
> Recommended Practice: Provide license information for as many Components as possible
> Aspirational Goal: Provide license information for all listed SBOM Components. Attestation of Concluded License information, i.e., license text and concluded terms and conditions, is included in the SBOM.

### Coverage Model

| Level        | Meaning                                         |
| ------------ | ----------------------------------------------- |
| Minimum      | License declared for primary component          |
| Recommended  | License declared for some additional components |
| Aspirational | License declared for all components             |

---

## 1.9 Copyright Coverage

### Copyright official definition

> Minimum Expected: Provide copyright notice for the Primary Component.
> Recommended Practice: Provide copyright notice for as many Components as possible.
> Aspirational Goal: Provide copyright notice for all listed SBOM Components.

### Coverage Model

Same as license.

---

## FSCT Compliance Structure

```text
FSCT Transparency Report

1. SBOM-Level Transparency
   - Provenance (author + timestamp)
   - Primary component definition

2. Component-Level Transparency (Baseline)
   - Identity (name + version)
   - Supplier attribution
   - Unique identification
   - Artifact integrity (hashes)

3. Dependency Transparency
   - Direct dependencies
   - Dependency completeness

4. Coverage-Based Transparency
   - License coverage
   - Copyright coverage
```