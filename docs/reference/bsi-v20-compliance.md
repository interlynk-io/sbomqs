
# BSI TR-03183-2 v1.1: Field Reference

**Standard:** BSI Technical Guideline TR-03183-2, Part 2: Software Bill of Materials (SBOM), Version 1.1 (2023-11-28)
**Issuer:** Federal Office for Information Security (BSI), Germany

This document covers the data fields defined in BSI TR-03183-2 v1.1: their official definitions, the reasoning behind each requirement, what values are accepted, and how they map to SPDX and CycloneDX SBOM formats.

## Required Fields

BSI §5.2 defines two sets of mandatory fields: one for the SBOM document itself and one for each component listed in the SBOM.

### SBOM-Level Required Fields

*(BSI §5.2.1, Table 2)*

#### 1. Creator of the SBOM

**Official Definition:**
> "Email address of the entity that created the SBOM. If no email address is available this MUST be a 'Uniform Resource Locator (URL)'."

**Motive:**
BSI is built around the assumption that SBOMs must be processable by machines across the entire software supply chain. A plain name or phone number cannot be used programmatically to contact or look up the responsible party. An email or URL provides a machine-actionable contact point that can be integrated into automated vulnerability response and notification workflows.

**Accepted Values:**

- Valid email address (preferred)
- Valid URL (accepted only when no email address is available)

> Name, phone number, or any other contact form alone is **not** accepted.

**Sources of Creator:**

- Authors
- Manufacturer
- Supplier

> **NOTE:** Any of these sources satisfying the email/URL requirement is sufficient. Only one valid contact across all sources is needed.

**SBOM Mappings:**

- SPDX:
  - [`creationInfo.creator`](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field): `Person` or `Organization` entry, email extracted from the value

- CycloneDX:
  - [`metadata.authors[].email`](https://cyclonedx.org/docs/1.7/json/#metadata_authors_items_email)
  - [`metadata.manufacturer.email`](https://cyclonedx.org/docs/1.7/json/#metadata_manufacturer_contact_items_email) OR [`metadata.manufacturer.url`](https://cyclonedx.org/docs/1.7/json/#metadata_manufacturer_url) OR [`metadata.manufacturer.contact[].email`](https://cyclonedx.org/docs/1.7/json/#metadata_manufacturer_contact_items_email)
  - [`metadata.supplier.email`](https://cyclonedx.org/docs/1.7/json/#metadata_supplier_contact_items_email) OR [`metadata.supplier.url`](https://cyclonedx.org/docs/1.7/json/#metadata_supplier_url) OR [`metadata.supplier.contact[].email`](https://cyclonedx.org/docs/1.7/json/#metadata_supplier_contact_items_email)

#### 2. Timestamp

**Official Definition:**
> "Date and time of the SBOM data compilation according to the specification of the formats (see chapter 4)"

**Motive:**
The timestamp ties the SBOM snapshot to a specific point in time. Since software components and their known vulnerabilities change continuously, the timestamp lets automated tools detect stale SBOMs and correctly correlate the listed components against vulnerability databases (e.g., NVD, OSV) as of the SBOM's creation date. It is also required for traceability, knowing *when* an SBOM was produced is essential for audit trails.

**Accepted Values:**

- RFC 3339 / ISO 8601 compliant timestamp (e.g., `2025-04-25T00:42:27Z`)

**SBOM Mappings:**

- SPDX:
  - [`creationInfo.created`](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field)

- CycloneDX:
  - [`metadata.timestamp`](https://cyclonedx.org/docs/1.7/json/#metadata_timestamp)

### Component-Level Required Fields

*(BSI §5.2.2, Table 3)*

#### 3. Component creator

**Official Definition:**
> "Email address of the entity that created and, if applicable, maintains the respective software component. If no email address is available this MUST be a 'Uniform Resource Locator (URL)'."

**Motive:**
Same rationale as the SBOM creator: BSI requires a machine-actionable contact for each component's responsible entity. If a CVE is discovered in a specific component, automated tooling must be able to identify and contact its maintainer or originator without manual intervention. A name alone provides no actionable contact channel.

**Accepted Values:**

- Valid email address (preferred)
- Valid URL (accepted only when no email address is available)

> Name, phone, or any other contact form alone is **not** accepted.

**Sources of Component Creator:**

- Authors (email)
- Manufacturer (email or URL, including contacts list)
- Supplier (email or URL, including contacts list)

> **NOTE:** Any source providing a valid email or URL satisfies the requirement. Only one valid contact per component is required.

**SBOM Mappings:**

- SPDX:
  - [`PackageOriginator`](https://spdx.github.io/spdx-spec/v2.3/package-information/#76-package-originator-field) (`Person` or `Organization`): email (preferred)
  - [`PackageSupplier`](https://spdx.github.io/spdx-spec/v2.3/package-information/#75-package-supplier-field) (`Person` or `Organization`): email (fallback)

- CycloneDX:
  - [`components[].authors[].email`](https://cyclonedx.org/docs/1.7/json/#components_items_authors_items_email)
  - [`components[].manufacturer.email`](https://cyclonedx.org/docs/1.7/json/#components_items_manufacturer_contact_items_email) OR [`components[].manufacturer.url`](https://cyclonedx.org/docs/1.7/json/#components_items_manufacturer_url) OR [`components[].manufacturer.contact[].email`](https://cyclonedx.org/docs/1.7/json/#components_items_manufacturer_contact_items_email)
  - [`components[].supplier.email`](https://cyclonedx.org/docs/1.7/json/#components_items_supplier_contact_items_email) OR [`components[].supplier.url`](https://cyclonedx.org/docs/1.7/json/#components_items_supplier_url) OR [`components[].supplier.contact[].email`](https://cyclonedx.org/docs/1.7/json/#components_items_supplier_contact_items_email)

#### 4. Component name

**Official Definition:**
> "Name assigned to the software component by its creator"

**Motive:**
The component name is the most fundamental identifier. Without it, an SBOM entry cannot be matched against vulnerability databases, licence registries, or other SBOMs. It is the entry point for all downstream analysis.

**Accepted Values:**

- Any non-empty string assigned by the component's creator

**SBOM Mappings:**

- SPDX:
  - [`PackageName`](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field)

- CycloneDX:
  - [`components[].name`](https://cyclonedx.org/docs/1.7/json/#components_items_name)

#### 5. Component version

**Official Definition:**
> "Identifier used by the creator to specify changes in the software component to a previously created version. Identifiers according to Semantic Versioning or alternatively Calendar Versioning SHOULD be used if one determines the versioning scheme. Existing identifiers MUST NOT be changed for this purpose."

**Motive:**
Vulnerability tracking is version-specific, a CVE may affect version `1.2.3` of a library but not `1.2.4`. Without a version, it is impossible to determine whether a given component instance is affected by a known vulnerability. The version is what makes a component entry security-actionable.

**Accepted Values:**

- Any version string assigned by the creator
- Semantic Versioning (e.g., `1.2.3`), recommended
- Calendar Versioning (e.g., `2024.01`), recommended alternative
- Existing identifiers must not be altered

**SBOM Mappings:**

- SPDX:
  - [`PackageVersion`](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field)

- CycloneDX:
  - [`components[].version`](https://cyclonedx.org/docs/1.7/json/#components_items_version)

#### 6. Dependencies on other components

**Official Definition:**
> "Enumeration of all components on which this component is directly dependent, according to the requirements in section 5.1"

**Motive (Simplified):**
Think of dependencies as a chain: if your software uses library A, then A must be listed in the SBOM. If library A itself uses library B (and B is within the scope of what is delivered), then B must also be listed. This continues recursively until you reach the boundary of what is actually shipped (the "scope of delivery"). The goal is a complete, verifiable inventory with no hidden or undeclared dependencies.

BSI §5.1 specifically requires a **"Delivery item SBOM"** minimum (see §6.2.4): recursive dependency resolution must be performed for every component in the scope of delivery, at minimum through the first component that falls outside that scope. The SBOM must be produced as part of the build process (Build SBOM, §6.3.3).

**What constitutes a valid dependency declaration:**

- Each component must enumerate its direct dependencies by reference to other components in the SBOM
- All referenced dependencies must be present in the SBOM (no dangling references to undefined components)
- The dependency graph must be structurally consistent — no relation can point to a component not declared in the SBOM

> **NOTE:** Leaf components (those with no dependencies) are inherently compliant, they simply declare an empty dependency list.

**SBOM Mappings:**

- SPDX:
  - [`Relationships`](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) of type `DEPENDS_ON` or `CONTAINS`

- CycloneDX:
  - [`dependencies[]`](https://cyclonedx.org/docs/1.7/json/#dependencies) — `ref` (the component) and `dependsOn` (its direct dependencies)

#### 7. Licence

**Official Definition:**
> "Associated licence(s) of the component from the perspective of the SBOM creator."
>
> Licence identification principles:
>
> - Licences MUST be identified with their SPDX identifier.
> - If the licence cannot be found in the SPDX list, the Scancode LicenseDB AboutCode database MUST be consulted next; identifiers from this database use the prefix `LicenseRef-scancode-[...]`.
> - Completely unknown licences MUST use prefix `LicenseRef-<inventorising_entity>-[...]`.
> - Licence expressions for multiple licensing, licence choices, and licence exceptions MUST use SPDX operators (`AND`, `OR`, `WITH`).

**Motive:**
Licence information serves two critical purposes: legal compliance (ensuring the software supply chain respects all licence obligations, such as attribution or copyleft requirements) and security (certain licences restrict code modification, which may prevent patching a vulnerable component). BSI mandates standardized SPDX identifiers to ensure that licence information is machine-processable and interoperable across toolchains.

**Accepted Values:**

- Valid SPDX licence identifier (e.g., `MIT`, `Apache-2.0`, `GPL-2.0-only`)
- Valid SPDX licence expression (e.g., `MIT OR Apache-2.0`, `GPL-2.0-only WITH Classpath-exception-2.0`)
- Valid `LicenseRef-*` identifier (e.g., `LicenseRef-scancode-abc`, `LicenseRef-myorg-proprietary`)

> **Not accepted:** `NONE`, `NOASSERTION`, free-text names without SPDX/LicenseRef format (e.g., `"Apache License"` instead of `Apache-2.0`), empty values.

**SBOM Mappings:**

- SPDX:
  - [`PackageLicenseConcluded`](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field) (preferred — the SBOM creator's concluded licence)
  - [`PackageLicenseDeclared`](https://spdx.github.io/spdx-spec/v2.3/package-information/#715-declared-license-field) (fallback — the licence as declared by the originator)

- CycloneDX:
  - [`components[].licenses[].license.id`](https://cyclonedx.org/docs/1.7/json/#components_items_licenses_items_oneOf_i0_license) (SPDX ID)
  - [`components[].licenses[].license.name`](https://cyclonedx.org/docs/1.7/json/#tab-pane_components_items_licenses_items_oneOf_i0_license_oneOf_i1) (name, if no SPDX ID available)
  - [`components[].licenses[].expression`](https://cyclonedx.org/docs/1.7/json/#components_items_licenses_items_oneOf_i1_expression) (SPDX expression)

#### 8. Hash value of the executable component

**Official Definition:**
> "Cryptographically secure checksum (hash value) of the component in its executable form (i.e. as the single executable file on a mass storage device) as SHA-256"

**Motive:**
A hash of the executable artifact provides a tamper-evident fingerprint of the exact binary that is delivered. It allows any consumer to verify that what they received matches what the SBOM declares, guarding against supply chain attacks where a malicious binary is substituted for the genuine artifact. SHA-256 is mandated specifically because it provides sufficient collision resistance for security-critical verification.

**Accepted Values:**

- SHA-256 hash of the deliverable executable artifact
- Algorithm: **SHA-256 only** — MD5, SHA-1, SHA-512, and all other algorithms do **not** satisfy this requirement

**SBOM Mappings:**

- SPDX:
  - [`PackageChecksum`](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field) with algorithm `SHA256`

- CycloneDX:
  - [`components[].hashes[]`](https://cyclonedx.org/docs/1.7/json/#components_items_hashes) with `alg` = `SHA-256` and non-empty `content`

> **NOTE:** This hash is of the **executable** (compiled/delivered binary) form, not the source code. The source code hash is a separate additional field (see field 12 below).

## Additional Fields

Additional fields MUST be provided *if they exist and their prerequisites are fulfilled* (BSI §5.3). They are not optional in the sense of being discouraged — if the data exists, it must be included.

### SBOM-Level Additional Fields

*(BSI §5.3.1, Table 4)*

#### 9. SBOM-URI

**Official Definition:**
> "Uniform Resource Identifier (URI)" of this SBOM

**Motive:**
A URI uniquely identifies the SBOM document itself, independent of how or where it is stored. This enables automated systems to reference, retrieve, and cross-link SBOMs across the supply chain. It is also essential for associating security advisories, VEX documents, or updated SBOMs with a specific SBOM version.

**Accepted Values:**

- A valid URL (e.g., `https://example.com/sboms/myapp-1.0.json`)
- A valid URN (e.g., `urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6`)

**SBOM Mappings:**

- SPDX:
  - [`documentNamespace`](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field)

- CycloneDX:
  - [`serialNumber`](https://cyclonedx.org/docs/1.7/json/#serialNumber) combined with [`version`](https://cyclonedx.org/docs/1.7/json/#version) (together they form a unique SBOM document identifier)

### Component-Level Additional Fields

*(BSI §5.3.2, Table 5)*

#### 10. Source code URI

**Official Definition:**
> "Uniform Resource Identifier (URI)" of the source code of the component, e.g. the URL of the source code repository"

**Motive:**
Knowing where a component's source code lives enables downstream consumers to audit the code for security issues, verify licence compliance by inspecting the actual source, and locate patches or forks when a vulnerability is discovered. It bridges the gap between the binary artifact and its origin.

**Accepted Values:**

- A valid URL pointing to the source code repository or source archive
- Examples: GitHub/GitLab/Bitbucket repository URL, internal Git server URL, source tarball download URL

**SBOM Mappings:**

- SPDX:
  - No dedicated native field in SPDX for source repository URI. There is no deterministic standard mapping; it may be expressed informally via [`ExternalRef`](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field) with category `OTHER`.

- CycloneDX:
  - [`components[].externalReferences[]`](https://cyclonedx.org/docs/1.7/json/#components_items_externalReferences_items_type) with type:
    - `vcs` — version control system URL (preferred)
    - `source-distribution` — source distribution download URL

> **NOTE:** SPDX lacks a standardized field for source code URI. CycloneDX's `externalReferences` with type `vcs` is the clearest and most widely adopted mapping for this BSI requirement.

#### 11. URI of the executable form of the component

**Official Definition:**
> "Uniform Resource Identifier (URI)", which points directly to the executable form of the component."

**Motive:**
This URI allows automated tools to retrieve the exact distributable artifact — the compiled binary, container image, or installable package, for integrity verification, deployment automation, or security scanning. It connects the SBOM entry to the actual artifact stored in a registry or distribution platform.

**Accepted Values:**

- A valid URL pointing to the executable or distributable artifact
- Examples: container image registry URL (e.g., Docker Hub, GHCR), binary download link, npm/PyPI/Maven artifact URL, artifact repository link (e.g., Nexus, Artifactory)

**SBOM Mappings:**

- SPDX:
  - [`PackageDownloadLocation`](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field)

- CycloneDX:
  - [`components[].externalReferences[]`](https://cyclonedx.org/docs/1.7/json/#components_items_externalReferences_items_type) with type:
    - `distribution` — direct download of the distributable artifact
    - `distribution-intake` — distribution intake endpoint

#### 12. Hash value of the source code of the component

**Official Definition:**
> "Cryptographically secure checksum (hash value) of the component source code as SHA-256"

**Motive:**
A hash of the source code allows independent verification that the source archive or repository snapshot has not been tampered with. Together with the executable hash (field 8), it establishes a verifiable chain from source to binary — enabling detection of cases where the distributed binary does not match what was actually built from the declared source.

**Accepted Values:**

- SHA-256 hash of the source code archive or source tree

> **NOTE:** BSI footnote 16 acknowledges that "The method to calculate the hash value of the source code is currently not specified." SHA-256 is the required algorithm, but the exact calculation method (e.g., hash of a tarball, a tree hash, a `PackageVerificationCode`) is left to the implementer.

**SBOM Mappings:**

- SPDX:
  - [`PackageVerificationCode`](https://spdx.github.io/spdx-spec/v2.3/package-information/#79-package-verification-code-field) (SHA-1-based hash of all package files; closest available SPDX field)

- CycloneDX:
  - [`components[].externalReferences[]`](https://cyclonedx.org/docs/1.7/json/#components_items_externalReferences_items_type) with type `vcs` or `source-distribution`, including associated `hashes[]` entries with `alg` = `SHA-256`

#### 13. Other unique identifiers

**Official Definition:**
> "Other identifiers that can be used to identify the component or to look it up in relevant databases, such as Common Platform Enumeration (CPE) or Package URL (purl)."

**Motive:**
Standard identifiers like PURL and CPE enable automated cross-referencing against vulnerability databases (NVD, OSV, GitHub Advisory Database), package registries, and licence databases. Without them, matching a component to external databases requires fuzzy name/version matching, which is error-prone and not machine-reliable. These identifiers make the SBOM directly queryable for security analysis without ambiguity.

**Accepted Values:**

- **Package URL (PURL)**: ecosystem-specific canonical identifier (e.g., `pkg:npm/lodash@4.17.21`, `pkg:maven/org.apache.commons/commons-lang3@3.12.0`)
- **Common Platform Enumeration (CPE)** — NIST standard identifier (e.g., `cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*`)

**SBOM Mappings:**

- SPDX:
  - [`ExternalRef`](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field) with:
    - Category `PACKAGE-MANAGER`, type `purl` — for PURL
    - Category `SECURITY`, type `cpe22Type` or `cpe23Type` — for CPE

- CycloneDX:
  - [`components[].purl`](https://cyclonedx.org/docs/1.7/json/#components_items_purl)
  - [`components[].cpe`](https://cyclonedx.org/docs/1.7/json/#components_items_cpe)

## Summary Table

| # | Field | Level | Category | BSI Section |
|---|-------|-------|----------|-------------|
| 1 | Creator of the SBOM | SBOM | Required | §5.2.1 |
| 2 | Timestamp | SBOM | Required | §5.2.1 |
| 3 | Component creator | Component | Required | §5.2.2 |
| 4 | Component name | Component | Required | §5.2.2 |
| 5 | Component version | Component | Required | §5.2.2 |
| 6 | Dependencies on other components | Component | Required | §5.2.2 |
| 7 | Licence | Component | Required | §5.2.2 |
| 8 | Hash value of the executable component | Component | Required | §5.2.2 |
| 9 | SBOM-URI | SBOM | Additional | §5.3.1 |
| 10 | Source code URI | Component | Additional | §5.3.2 |
| 11 | URI of the executable form | Component | Additional | §5.3.2 |
| 12 | Hash value of the source code | Component | Additional | §5.3.2 |
| 13 | Other unique identifiers | Component | Additional | §5.3.2 |
