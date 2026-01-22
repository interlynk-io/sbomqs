# Compliance quality summary Reports

## NTIA Minimum Element Fields

| Check ID | Description | Required | SPDX | CycloneDX |
|----------|-------------|----------|------|-----------|
| `comp_with_supplier` | Entity that creates, defines, and identifies the software component | Yes | PackageSupplier (preferred), PackageOriginator (fallback) | component.supplier |
| `comp_with_name` | Name assigned to the component by the supplier | Yes | PackageName | component.name |
| `comp_with_version` | Version identifier used by the supplier to distinguish this release | Yes | PackageVersion | component.version |
| `comp_with_uniq_ids` | At least one additional identifier if available (CPE, PURL, SWID, etc.) | Conditional* | ExternalRef (CPE, PURL, SWID, etc.) | component.cpe, component.purl, component.swid |
| `sbom_dependencies` | Relationship showing component X is included in software Y | Yes | Relationship: DEPENDS_ON / CONTAINS | dependencies (dependency graph) |
| `sbom_authors` | Entity(person/org/tools) that created the SBOM data | Yes | CreationInfo.Creators (Person / Organization / Tool) | metadata.authors(preferred) or metada.tools(preferred), metadata.supplier(fallback) |
| `sbom_creation_timestamp` | Date and time when the SBOM was created | Yes | CreationInfo.Created | metadata.timestamp |

### Official Definition of Fields (for clarity)

#### Author of SBOM Data

> **“Author reflects the source of the metadata, which could come from the creator of the software being described in the SBOM, the upstream component supplier, or some third-party analysis tool.”**
> **“Note:** this is not the author of the software itself, just the source of the descriptive data.”

From this definition, **“author” refers to the source of the SBOM metadata**, not to legal ownership or responsibility for the software.

Accordingly, the SBOM author may be any of the following:

- the creator of the software,
- the upstream component supplier, or
- a third-party analysis or generation tool.

The NTIA minimum element definition —

> *“The name of the entity that creates the SBOM data for this component”* —
> uses the term **“entity”** to mean an **identifiable source of SBOM metadata**, not a legal entity.

In this context, **“entity” includes**:

- a person,
- an organization, or
- an automated tool.

Here, *entity* does **not** imply *legal entity*. A legal entity typically refers to a person or organization with legal standing, which is **out of scope** for NTIA’s SBOM minimum elements.

Corresponding fields:

General:

- author(with name or email)
- tool(name required, version recommended)
- supplier(fallback)
- manufacturer(fallback)

SPDX:

- CreationInfo.Creators:
  - Person: <name> (<email>)
  - Organization: <name> (<email>)
  - Tool: <name>-<version>

CDX:

- metadata.authors
- metadata.tools
- metadata.supplier(fallback)
- metadata.manufacturer(fallback)

---

#### Final Conclusion for "Author of SBOM Data"

> **NTIA defines the “Author of SBOM Data” as the source of the SBOM metadata.
> This source may be a person, an organization, or an automated tool.
> Legal personhood is not required.**

#### Supplier Name

> “Supplier — The name of an entity that creates, defines, and identifies components.”

SPDX

- `PackageSupplier` is the primary field representing NTIA Supplier.
- `PackageOriginator` may describe original authorship, but does not replace supplier.

CycloneDX

- `component.supplier` is the primary representation of NTIA Supplier.
- `component.manufacturer` may be used only as a fallback when supplier is not present.

When both are present, `component.supplier` always takes precedence.

`manufacturer` is not a semantic equivalent of supplier; it may represent physical production or build provenance rather than software identity authority.

---

#### Final Conclusion of "Supplier Name"

> NTIA defines the “Supplier Name” as the identifiable authority that creates, defines, and identifies a software component.
The supplier may be an organization, project, vendor, or other upstream source responsible for the component’s identity.
Legal ownership or manufacturing responsibility is not required.

#### Dependency Relationship

> “Dependency Relationship — Characterizing the relationship that an upstream component X is included in software Y.” 

NTIA further clarifies dependency expectations under Depth:

> “At minimum, all top-level dependencies must be listed with enough detail to seek out the transitive dependencies recursively.”

From this, NTIA requires that dependency relationships be declared** at least for primary (top-level) components**. Enumeration of deeper transitive dependencies is encouraged, but not required to meet the minimum elements.

SPDX

- Expressed via Relationship entries such as:
  - `DEPENDS_ON`
  - `CONTAINS`

CycloneDX

- Expressed via the dependencies graph.
- Completeness is inferred by:
  - dependsOn: [] → no dependencies
  - missing dependency node → unknown/incomplete

#### Final Conclusion of "Final Conclusion"

> NTIA defines “Dependency Relationship” as the directional inclusion relationship indicating that an upstream component is included in a downstream software component.
At minimum, top-level dependencies must be declared, and the SBOM must distinguish between complete and incomplete dependency information.
Full transitive dependency depth is encouraged but not required for minimum compliance.

## Compliance

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
   - Non-machine-testable practices noted
```