
# Compliance & Profiling Quality Summary Report

*(NTIA Minimum Elements – sbomqs Interpretation)*

This document explains how **sbomqs** evaluates NTIA Minimum Elements across both **profiling** (quality scoring) and **compliance** (minimum acceptability).
It defines:

* the **official NTIA meaning** of each field,
* the **mapping to SPDX and CycloneDX**, and
* the **exact logic sbomqs applies**, including accepted values and fallbacks.

The intent is to provide full transparency so users can understand **why an SBOM passed or failed** and **what data is expected**.

---

## 1. NTIA Minimum Element Fields

### Summary Table

| Check ID                  | NTIA Field               | Required     | SPDX Mapping                                              | CycloneDX Mapping                                                 |
| ------------------------- | ------------------------ | ------------ | --------------------------------------------------------- | ----------------------------------------------------------------- |
| `comp_with_supplier`      | Supplier                 | Yes          | PackageSupplier (preferred), PackageOriginator (fallback) | component.supplier (preferred), component.manufacturer (fallback) |
| `comp_with_name`          | Component Name           | Yes          | PackageName                                               | component.name                                                    |
| `comp_with_version`       | Component Version        | Yes          | PackageVersion                                            | component.version                                                 |
| `comp_with_uniq_ids`      | Other Unique Identifiers | Conditional* | ExternalRef (PURL, CPE, SWID, etc.)                       | component.purl, component.cpe                                     |
| `sbom_dependencies`       | Dependency Relationship  | Yes          | Relationship (DEPENDS_ON )                      | dependencies graph                                                |
| `sbom_authors`            | Author of SBOM Data      | Yes          | CreationInfo.Creators                                     | metadata.authors / metadata.tools (fallbacks allowed)             |
| `sbom_creation_timestamp` | Creation Timestamp       | Yes          | CreationInfo.Created                                      | metadata.timestamp                                                |

* *Conditionally required: only evaluated if such identifiers are available.*

---

## 2. Field-by-Field Definitions and sbomqs Logic

## Author of SBOM Data

### NTIA Definition

> **“Author reflects the source of the metadata, which could come from the creator of the software being described in the SBOM, the upstream component supplier, or some third-party analysis tool.”**
> **“Note:** this is not the author of the software itself, just the source of the descriptive data.”

The NTIA definition uses **“entity”** to mean an **identifiable source of SBOM metadata**, not a legal entity.

An author may therefore be:

* a person,
* an organization, or
* an automated tool.

Legal personhood is **not required**.

### sbomqs Accepted Logic

#### Evaluation Order (Precedence)

1. Explicit SBOM author
2. SBOM generation tool
3. Supplier (fallback)
4. Manufacturer (fallback)

#### Accepted Identifiers

Any of the following are sufficient:

* `name`
* `email`
* `url`

### Mapping

**SPDX**

* `CreationInfo.Creators`

  * `Person: <name> (<email>)`
  * `Organization: <name> (<email>)`
  * `Tool: <name>-<version>` or `Tool: <name>`

**CycloneDX**

* `metadata.authors` (preferred)
* `metadata.tools`
* `metadata.supplier` (fallback)
* `metadata.manufacturer` (fallback)

### Final Conclusion — Author of SBOM Data

> **NTIA defines the “Author of SBOM Data” as the identifiable source of the SBOM metadata.
> This source may be a person, organization, or automated tool.
> Legal identity is not required.**

---

## Supplier Name (Component-level)

### NTIA Definition

> **“Supplier — The name of an entity that creates, defines, and identifies components.”**

This refers to the **authority responsible for the component’s identity**, not manufacturing or legal ownership.

### sbomqs Accepted Logic

#### Precedence

1. Supplier
2. Manufacturer (fallback only)

#### Accepted Identifiers

* `name`
* `email`
* `url`

If both supplier and manufacturer exist, **supplier always wins**.

### Mapping

**SPDX**

* `PackageSupplier` (primary)
* `PackageOriginator` (not equivalent, informational only)

**CycloneDX**

* `component.supplier` (primary)
* `component.manufacturer` (fallback)

### Final Conclusion — Supplier Name

> **NTIA defines the Supplier as the identifiable authority that creates, defines, and identifies a software component.
> This may be an organization, project, or upstream source.
> Manufacturing responsibility or legal ownership is not required.**

---

## Component Name

### NTIA Definition

> Name assigned to the component by the supplier.

### Mapping

* **SPDX**: `PackageName`
* **CycloneDX**: `component.name`

### sbomqs Logic

* Must be non-empty
* Required for **all components**

---

## Component Version

### NTIA Definition

> Version identifier used to distinguish a specific release.

### Mapping

* **SPDX**: `PackageVersion`
* **CycloneDX**: `component.version`

### sbomqs Logic

* Must be present
* Evaluated per component

---

## Other Unique Identifiers

### NTIA Definition

> *“At least one additional identifier if available (e.g., CPE, PURL, SWID).”*

This field is **conditional**.

### sbomqs Accepted Logic

* Accepted identifiers:

  * PURL
  * CPE
* Presence is sufficient for **compliance**
* Syntax validity is evaluated only in **profiling**

### Mapping

**SPDX**

* `ExternalRef`:

  * `purl`
  * `cpe23Type`

**CycloneDX**

* `component.purl`
* `component.cpe`

---

## Dependency Relationship

### NTIA Definition

> **“Characterizing the relationship that an upstream component X is included in software Y.”**

NTIA minimum depth requirement:

> *“At minimum, all top-level dependencies must be listed.”*

### sbomqs Accepted Logic

* Dependency evaluation applies **only to the primary component**
* Compliance is satisfied if:

  1. at least one direct dependency exists, **or**
  2. dependency completeness is explicitly declared

### Mapping

**SPDX**

* `Relationship`:

  * `DEPENDS_ON`

**CycloneDX**

* `dependencies` graph
* Completeness via dependency composition

### Final Conclusion — Dependency Relationship

> **NTIA defines Dependency Relationship as the directional inclusion of upstream components in a primary software component.
> At minimum, top-level dependencies or explicit completeness declarations must be present.
> Full transitive depth is encouraged but not required.**

---

## 3. NTIA Compliance Structure (sbomqs)

```text
NTIA Compliance Report

1. Automation Support
   - Machine-readable format
   - SBOM generation tool declared

2. SBOM Data Fields

   Document-level:
   - Author of SBOM Data
   - Timestamp
   - Dependency Relationship (primary component)

   Component-level (applies to all components):
   - Component Name (N / Total)
   - Supplier (N / Total)
   - Version (N / Total)
   - Other Unique Identifiers (N / Total, conditional)

3. Practices & Processes (Partially Evaluated)
   - Depth (top-level dependencies)
   - Known Unknowns (dependency completeness)
   - Non-machine-testable practices explicitly noted
```

## Final Takeaway

> **Profiling measures quality and correctness.
> Compliance measures minimum NTIA acceptability.
> sbomqs deliberately keeps these concerns separate, explicit, and explainable.**
