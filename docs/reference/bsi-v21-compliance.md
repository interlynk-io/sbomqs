
# BSI TR-03183-2 v2.1.0: Field Reference

**Standard:** BSI Technical Guideline TR-03183-2, Part 2: Software Bill of Materials (SBOM), Version 2.1.0 (2025-08-20)
**Issuer:** Federal Office for Information Security (BSI), Germany

This document covers the data fields defined in BSI TR-03183-2 v2.1.0: their official definitions, the reasoning behind each requirement, what values are accepted, and how they map to SPDX and CycloneDX SBOM formats.

## What Changed in v2.1.0

Version 2.1.0 (2025-08-20) introduced the following significant changes compared to v2.0.0:

- **Restructured data fields** (§5.2): split into required, additional, and optional sub-sections with new numbering (§5.2.1–§5.2.5)
- **New component concepts**: Logical component (§3.2.2), Identified component (§3.2.4), Referenced component (§3.2.5), with distinct required-field sets for each
- **Licence model reworked**: "Associated licences" renamed to "Distribution licences" (required); "Concluded licences" (additional in v2.0) renamed to "Original licences"; "Effective licence" introduced as a new optional field; "Declared licences" (optional in v2.0) removed as a separate concept and absorbed into "Original licences"
- **Format versions updated**: CycloneDX minimum raised from 1.5 to **1.6**; SPDX minimum raised from 2.2.1 to **3.0.1**
- **New appendix §8.2**: Official mapping tables for every data field to SPDX v3.0.1 and CycloneDX v1.6 JSON
- **URL of security.txt** added as a new optional field
- **Completeness of dependencies** must now be explicitly indicated in the SBOM

## SBOM Formats

A newly generated or updated SBOM MUST be in JSON- or XML-format and conform to one of the following specifications (BSI §4):

- **CycloneDX**, version **1.6 or higher**
- **SPDX** (System Package Data Exchange), version **3.0.1 or higher**

Only officially released versions of these specifications MUST be used.

## Component Types and Their Required Fields

v2.1.0 introduces three levels of component description (BSI §3.2, §5.1). Depending on its role in the SBOM, a component may be:

### Fully Described Component (§5.2)

A component that is within scope and for which all applicable data fields from §5.2.2 must be provided.

### Logical Component (§3.2.2)

An abstraction level that groups multiple physical components under one identity (e.g. to represent a product by name). Logical components MUST only address these data fields:

- Component creator, Component name, Component version
- Dependencies on other components
- Distribution licences, Other unique identifiers, Original licences
- Effective licence, URL of the **security.txt**

### Identified Component (§3.2.4)

A component that must be present in the SBOM but does not need to be fully described. MUST address:

- Component creator, Component name, Component version, Other unique identifiers

### Referenced Component (§3.2.5)

A component whose full description lives in another BOM that this SBOM references. The referencing SBOM MUST copy:

- Component creator, Component name, Component version

## Required Fields

BSI §5.2 defines two sets of mandatory fields: one for the SBOM document itself and one for each component listed in the SBOM.

### SBOM-Level Required Fields

*(BSI §5.2.1, Table 2)*

### 1. Creator of the SBOM

**Official Definition:**
> "Email address of the entity that created the SBOM. If no email address is available this MUST be a 'Uniform Resource Locator (URL)', e.g. the creator's home page or the project's web page."

**Motive:**
BSI is built around the assumption that SBOMs must be processable by machines across the entire software supply chain. A plain name or phone number cannot be used programmatically to contact or look up the responsible party. An email or URL provides a machine-actionable contact point that can be integrated into automated vulnerability response and notification workflows.

**Accepted Values:**

- Valid email address (preferred)
- Valid URL (accepted only when no email address is available), e.g. the creator's home page or the project's web page

> Name, phone number, or any other contact form alone is **not** accepted.

**SBOM Mappings:**

- SPDX v3.0.1:
  - `CreationInfo.createdBy` references a `Person` or `Organization` element
  - The `Person`/`Organization` element carries an `externalIdentifiers` entry of type `email` (`"...@..."`) XOR type `urlScheme` (`"https://..."`)

- CycloneDX v1.6:
  - [`metadata.manufacturer[].url`](https://cyclonedx.org/docs/1.6/json/#metadata_manufacture_url): URL of the manufacturer
  - XOR [`metadata.manufacturer[].contact[].email`](https://cyclonedx.org/docs/1.6/json/#metadata_manufacturer_contact_items_email): email in the manufacturer's contact list

### 2. Timestamp

**Official Definition:**
> "Date and time of the SBOM data compilation according to the specification of the formats (see section 4). Note: It is recommended to only use timestamps in UTC ('Zulu' time)."

**Motive:**
The timestamp ties the SBOM snapshot to a specific point in time. Since software components and their known vulnerabilities change continuously, the timestamp lets automated tools detect stale SBOMs and correctly correlate the listed components against vulnerability databases (e.g., NVD, OSV) as of the SBOM's creation date. It is also required for traceability — knowing *when* an SBOM was produced is essential for audit trails.

**Accepted Values:**

- RFC 3339 / ISO 8601 compliant timestamp, UTC preferred (e.g., `2025-08-20T00:00:00Z`)

**SBOM Mappings:**

- SPDX v3.0.1:
  - `CreationInfo.created`: the creation datetime string

- CycloneDX v1.6:
  - [`metadata.timestamp`](https://cyclonedx.org/docs/1.6/json/#metadata_timestamp)

### Component-Level Required Fields

*(BSI §5.2.2, Table 3)*

> **Note:** For logical components only a subset of these fields applies (see §3.2.2 above). For components that comprise multiple sub-components in a manner that prevents the original sub-components from being determined, fields that are unavailable due to the assembly method (e.g. hash or filename) must be omitted.

### 3. Component creator

**Official Definition:**
> "Email address of the entity that created and, if applicable, maintains the respective component. If no email address is available this MUST be a 'Uniform Resource Locator (URL)', e.g. the creator's home page or the project's web page."
>
> "Note: If the creator of a component still maintains the component but operates under a different name than the one at the time of integrating the component, the current name may be used."

**Motive:**
Same rationale as the SBOM creator: BSI requires a machine-actionable contact for each component's responsible entity. If a CVE is discovered in a specific component, automated tooling must be able to identify and contact its maintainer or originator without manual intervention. A name alone provides no actionable contact channel.

**Accepted Values:**

- Valid email address (preferred)
- Valid URL (accepted only when no email address is available)

> Name, phone, or any other contact form alone is **not** accepted.

**SBOM Mappings:**

- SPDX v3.0.1:
  - `software_Package.originatedBy` references a `Person` or `Organization`
  - The element carries `externalIdentifiers` of type `email` (`"...@..."`) XOR type `other` (`"https://..."`)

- CycloneDX v1.6 (primary component):
  - [`metadata.component.manufacturer[].url`](https://cyclonedx.org/docs/1.6/json/#metadata_component_manufacturer_url) XOR [`metadata.component.manufacturer[].contact[].email`](https://cyclonedx.org/docs/1.6/json/#metadata_component_manufacturer_contact_items_email)

- CycloneDX v1.6 (other components):
  - [`components[].manufacturer[].url`](https://cyclonedx.org/docs/1.6/json/#components_items_manufacturer_url) XOR [`components[].manufacturer[].contact[].email`](https://cyclonedx.org/docs/1.6/json/#components_items_manufacturer_contact_items_email)

### 4. Component name

**Official Definition:**
> "Name assigned to the component by the component creator. If no name is assigned this MUST be the actual filename."
>
> "Note: If the component name was changed between versions, the component name that was valid during the integration of the component must be used."

**Motive:**
The component name is the most fundamental identifier. Without it, an SBOM entry cannot be matched against vulnerability databases, licence registries, or other SBOMs. It is the entry point for all downstream analysis.

**Accepted Values:**

- Any non-empty string assigned by the component's creator
- If no name is assigned, the actual filename MUST be used

**SBOM Mappings:**

- SPDX v3.0.1:
  - `software_Package.name`

- CycloneDX v1.6:
  - [`metadata.component.name`](https://cyclonedx.org/docs/1.6/json/#metadata_component_name) (primary component)
  - [`components[].name`](https://cyclonedx.org/docs/1.6/json/#components_items_name) (other components)

> **Note:** CycloneDX's `group` field is not required by BSI or the CycloneDX spec, but may be useful to distinguish equally-named components built by different projects (see BSI §8.2, Table 9 note).

### 5. Component version

**Official Definition:**
> "Identifier used by the creator to specify changes in the component to a previously created version. The following points apply to determine a version in this order:
> 
> 1. Existing identifiers MUST NOT be changed for this purpose.
> 2. Identifiers according to Semantic Versioning or alternatively Calendar Versioning SHOULD be used if one determines the versioning scheme; this is often the component creator.
> 3. If no version is assigned this MUST be the modification date of the file expressed as date-time according to RFC 3339 section 5.6. To determine the creation time the file metadata MUST be consulted."

**Motive:**
Vulnerability tracking is version-specific — a CVE may affect version `1.2.3` of a library but not `1.2.4`. Without a version, it is impossible to determine whether a given component instance is affected by a known vulnerability. The version is what makes a component entry security-actionable.

**Accepted Values:**

- Any version string assigned by the creator
- Semantic Versioning (e.g., `1.2.3`), recommended
- Calendar Versioning (e.g., `2024.01`), recommended alternative
- If no version exists: RFC 3339 date-time of the file modification date
- Existing identifiers must not be altered

**SBOM Mappings:**

- SPDX v3.0.1:
  - `software_Package.software_packageVersion`

- CycloneDX v1.6:
  - [`metadata.component.version`](https://cyclonedx.org/docs/1.6/json/#metadata_component_version) (primary component)
  - [`components[].version`](https://cyclonedx.org/docs/1.6/json/#components_items_version) (other components)

### 6. Filename of the component

**Official Definition:**
> "The actual filename of the component (i.e. not its file system path); see also section 3.2.1"

**Motive:**
The filename is the physical identity of the component as it appears on disk. It is required alongside the name and hash to unambiguously identify which file was inventoried. Tools use this to correlate SBOM entries with files found on a system, and to verify delivery integrity without relying solely on names that may differ across ecosystems.

**Accepted Values:**

- The filename of the component file (not the full path, not the directory)
- For logical components, this field does not apply

**SBOM Mappings:**

- SPDX v3.0.1:
  - A `software_File` element linked from the `software_Package` via a `Relationship` of type `hasDistributionArtifact` (completeness: `complete`); the file's `name` field holds the filename

- CycloneDX v1.6:
  - [`metadata.component.properties`](https://cyclonedx.org/docs/1.6/json/#metadata_component_properties) with `name: "bsi:component:filename"` and `value: "..."` (primary component)
  - [`components[].properties`](https://cyclonedx.org/docs/1.6/json/#components_items_properties) with `name: "bsi:component:filename"` and `value: "..."` (other components)
  - Uses the [BSI CycloneDX property taxonomy](https://github.com/BSI-Bund/tr-03183-cyclonedx-property-taxonomy)

### 7. Dependencies on other components

**Official Definition:**
> "Enumeration of all components on which this component is directly dependent, according to requirements in section 5.1, or which this component contains according to requirements in section 3.2.1. Furthermore, the completeness of this enumeration MUST be clearly indicated."

**Motive:**
Think of dependencies as a chain: if your software uses library A, then A must be listed in the SBOM. If library A itself uses library B (and B is within the scope of what is delivered), then B must also be listed. This continues recursively until you reach the boundary of what is actually shipped (the "scope of delivery"). The goal is a complete, verifiable inventory with no hidden or undeclared dependencies.

**What constitutes a valid dependency declaration:**

- Each component must enumerate its direct dependencies by reference to other components in the SBOM
- The completeness of the enumeration MUST be explicitly declared (complete, incomplete, or unknown)
- All referenced dependencies must be present in the SBOM (no dangling references)

> **NOTE:** Leaf components (those with no dependencies) are inherently compliant — they simply declare an empty dependency list.

**SBOM Mappings:**

- SPDX v3.0.1:
  - `Relationship` with `from: example_URI_01`, `relationshipType: "contains"` XOR `"dependsOn"`, `to: [...]`, `completeness: "complete"` XOR `"incomplete"` XOR `"noAssertion"`

- CycloneDX v1.6:
  - [`dependencies[]`](https://cyclonedx.org/docs/1.6/json/#dependencies) — `ref` (the component) and `dependsOn` (its direct dependencies)
  - Components without any own `dependencies` MUST be declared as empty elements within the dependency graph (per CycloneDX v1.6 spec)
  - [`compositions[]`](https://cyclonedx.org/docs/1.6/json/#compositions) — `ref`, `aggregate: "complete"` XOR `"incomplete"` XOR `"unknown"`, `assemblies: [...]` OR `dependencies: [...]` — used to indicate completeness

### 8. Distribution licences

**Official Definition:**
> "Distribution licence(s) of the component under which it can be used by a licensee. For specifics see sections 6.1 and 8.1.13."

**Motive:**
Distribution licences represent the licence under which a downstream party is permitted to use the component. BSI mandates standardized SPDX identifiers to ensure that licence information is machine-processable and interoperable across toolchains. Licence data is also security-relevant: certain licences restrict code modification, which may prevent patching a vulnerable component.

> **Note on licence terminology (v2.1.0):** v2.1.0 distinguishes three licence categories:
> 
> - **Distribution licences** (required): the licence(s) under which a licensee of the SBOM can use the component — this replaces "Associated licences" from earlier versions
> - **Original licences** (additional): the licence(s) assigned by the component's creator — this replaces what was called "Declared licences" in v2.0
> - **Effective licence** (optional): the licence under which the SBOM creator uses the component — new in v2.1.0

**Accepted Values (§6.1):**

- Valid SPDX licence identifier (e.g., `MIT`, `Apache-2.0`, `GPL-2.0-only`)
- Valid SPDX licence expression (e.g., `MIT OR Apache-2.0`, `GPL-2.0-only WITH Classpath-exception-2.0`)
- Valid `LicenseRef-scancode-[...]` identifier (from Scancode LicenseDB AboutCode)
- Valid `LicenseRef-<licence_inventorising_entity>-[...]` for completely unknown licences

> **Not accepted:** `NONE`, `NOASSERTION`, free-text names without SPDX/LicenseRef format, empty values, raw licence text as a substitute for an identifier.

**SBOM Mappings:**

- SPDX v3.0.1:
  - `software_Package` linked via `Relationship` of type `hasConcludedLicense` (completeness: `complete`) to a `simpleLicensing_LicenseExpression` element whose `licenseExpression` holds the SPDX expression

- CycloneDX v1.6:
  - [`metadata.component.licenses[].expression`](https://cyclonedx.org/docs/1.6/json/#metadata_component_licenses_items_oneOf_i1_expression) with `"acknowledgement": "concluded"` (primary component)
  - [`components[].licenses[].expression`](https://cyclonedx.org/docs/1.6/json/#components_items_licenses_items_oneOf_i1_expression) with `"acknowledgement": "concluded"` (other components)

### 9. Hash value of the deployable component

**Official Definition:**
> "Cryptographically secure checksum (hash value) of the deployed/deployable component (i.e. as a file on a mass storage device) as SHA-512; see also section 3.2.1"

**Motive:**
A hash of the deployable artifact provides a tamper-evident fingerprint of the exact binary that is delivered. It allows any consumer to verify that what they received matches what the SBOM declares, guarding against supply chain attacks where a malicious binary is substituted for the genuine artifact. SHA-512 is mandated for its stronger collision resistance compared to SHA-256 used in v1.1.

**Accepted Values:**

- SHA-512 hash of the deployed/deployable component file
- Algorithm: **SHA-512 only** — SHA-256, MD5, SHA-1, and all other algorithms do **not** satisfy this requirement

> **Note (v2.1.0 vs v1.1):** v1.1 required SHA-256; v2.0 and v2.1.0 require **SHA-512**. The field was also renamed from "Hash value of the executable component" to "Hash value of the deployable component".

**SBOM Mappings:**

- SPDX v3.0.1:
  - A `software_File` element linked via `hasDistributionArtifact` relationship from the `software_Package`; the file carries `verifiedUsing[].algorithm: "sha512"` and `verifiedUsing[].hashValue: "..."`

- CycloneDX v1.6:
  - [`metadata.component.externalReferences[]`](https://cyclonedx.org/docs/1.6/json/#metadata_component_externalReferences_items_type) with `type: "distribution"`, `hashes[].alg: "SHA-512"`, `hashes[].content: "..."` (primary component)
  - [`components[].externalReferences[]`](https://cyclonedx.org/docs/1.6/json/#components_items_externalReferences_items_type) with `type: "distribution"`, `hashes[].alg: "SHA-512"`, `hashes[].content: "..."` (other components)

### 10. Executable property

**Official Definition:**
> "Describes whether the component is executable; possible values are 'executable' and 'non-executable'; see also Appendix, section 8.1.4"

**Motive:**
Executables (compiled binaries, interpreted scripts, shared libraries) are the primary attack surface for malicious code. Non-executable files (configuration files, documentation, graphics) carry no such risk. Declaring this property explicitly allows automated tooling to prioritize security analysis on executable components and skip irrelevant ones, reducing noise in vulnerability scanning pipelines.

**Accepted Values:**

- `executable` — the component is an executable file (compiled binary, interpreted script, shared library, etc.)
- `non-executable` — the component is not executable (configuration file, documentation, etc.)

**SBOM Mappings:**

- SPDX v3.0.1:
  - A `software_File` element (linked via `hasDistributionArtifact`) with `software_additionalPurpose: ["executable"]` if executable; if non-executable, omit `"executable"` from the list
  - Comment on the file: `"software_additionalPurpose field is used to indicate the properties of BSI TR-03183-2"`

- CycloneDX v1.6:
  - [`metadata.component.properties[]`](https://cyclonedx.org/docs/1.6/json/#metadata_component_properties) with `name: "bsi:component:executable"`, `value: "executable"` or `"non-executable"` (primary component)
  - [`components[].properties[]`](https://cyclonedx.org/docs/1.6/json/#components_items_properties) with `name: "bsi:component:executable"`, `value: "executable"` or `"non-executable"` (other components)

### 11. Archive property

**Official Definition:**
> "Describes whether the component is an archive; possible values are 'archive' and 'no archive'; see also Appendix, section 8.1.5"

**Motive:**
An archive (a combination of multiple components, such as a `.zip`, `.tar`, or container image) may need to be dissected to inventory its contents. Flagging archives allows downstream tools to know which entries require further unpacking and analysis. This property is important to identify files which may need to be dissected (BSI §8.1.5).

**Accepted Values:**

- `archive` — the component is an archive (a combination of multiple components); note that compression alone does not change this property
- `no archive` — the component is not an archive

**SBOM Mappings:**

- SPDX v3.0.1:
  - A `software_File` (linked via `hasDistributionArtifact`) with `software_additionalPurpose: ["archive"]` if it is an archive; otherwise omit `"archive"` from the list

- CycloneDX v1.6:
  - `properties[]` with `name: "bsi:component:archive"`, `value: "archive"` or `"no archive"`

### 12. Structured property

**Official Definition:**
> "Describes whether the component is a structured file, i.e. metadata of the contents is still present (see section 3.2.1); possible values are 'structured' and 'unstructured'; see also Appendix, section 8.1.6. If a component contains both structured and unstructured parts the value 'structured' MUST be used."

**Motive:**
Structured archives (e.g., `.zip`, `.tar`, containers, packages, ISO images) retain metadata about their original components and can be decomposed. Unstructured archives (e.g., firmware images, binaries with statically linked libraries) do not — their internal structure cannot be recovered. This property tells consumers whether they can drill further into the component for deeper SBOM analysis.

**Accepted Values:**

- `structured` — the component is a structured file; metadata of contents is still present (use this if any part is structured)
- `unstructured` — the component is an unstructured archive or binary with no recoverable structure

**SBOM Mappings:**

- SPDX v3.0.1:
  - If structured: `software_additionalPurpose: ["container"]` on the linked `software_File`
  - If unstructured: `software_additionalPurpose: ["firmware"]` on the linked `software_File`

- CycloneDX v1.6:
  - `properties[]` with `name: "bsi:component:structured"`, `value: "structured"` or `"unstructured"`

## Additional Fields

Additional fields MUST be provided *if they exist and their prerequisites are fulfilled* (BSI §5.2.3, §5.2.4). They are not optional in the sense of being discouraged — if the data exists and the format supports it, it must be included.

### SBOM-Level Additional Fields

*(BSI §5.2.3, Table 4)*

### 13. SBOM-URI

**Official Definition:**
> "Uniform Resource Identifier (URI)" of this SBOM

**Motive:**
A URI uniquely identifies the SBOM document itself, independent of how or where it is stored. This enables automated systems to reference, retrieve, and cross-link SBOMs across the supply chain. It is also essential for associating security advisories, VEX documents, or updated SBOMs with a specific SBOM version.

**Accepted Values:**

- A valid URL (e.g., `https://example.com/sboms/myapp-1.0.json`)
- A valid URN (e.g., `urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6`)

**SBOM Mappings:**

- SPDX v3.0.1:
  - `SpdxDocument.rootElement` points to a `software_Sbom` element whose `spdxId` serves as the SBOM URI/identifier; the main `software_Package` representing the described software has its own distinct `spdxId` and is linked from the `software_Sbom` (for example, as a subject or via an SPDX relationship)

- CycloneDX v1.6:
  - [`serialNumber`](https://cyclonedx.org/docs/1.6/json/#serialNumber): the unique serial number of the SBOM document

### Component-Level Additional Fields

*(BSI §5.2.4, Table 5)*

### 14. Source code URI

**Official Definition:**
> "Uniform Resource Identifier (URI)" of the source code of the component, e.g. the URL of the utilised source code version in its repository, or if a version cannot be specified the utilised source code repository itself."

**Motive:**
Knowing where a component's source code lives enables downstream consumers to audit the code for security issues, verify licence compliance by inspecting the actual source, and locate patches or forks when a vulnerability is discovered. It bridges the gap between the binary artifact and its origin.

**Accepted Values:**

- A valid URL pointing to the specific source code version in its repository (preferred)
- A valid URL pointing to the source code repository (if a specific version URL is not available)

**SBOM Mappings:**

- SPDX v3.0.1:
  - A `software_SoftwareArtifact` element with `software_primaryPurpose: "source"` and `externalRef[].externalRefType: "SourceArtifact"`, `locator: "..."`, linked from the package via a `Relationship` of type `generates` (completeness: `complete`)

- CycloneDX v1.6:
  - [`metadata.component.externalReferences[]`](https://cyclonedx.org/docs/1.6/json/#metadata_component_externalReferences_items_type) with `type: "source-distribution"`, `url: "..."` (primary component)
  - [`components[].externalReferences[]`](https://cyclonedx.org/docs/1.6/json/#components_items_externalReferences_items_type) with `type: "source-distribution"`, `url: "..."` (other components)

### 15. URI of the deployable form of the component

**Official Definition:**
> "Uniform Resource Identifier (URI)", which points directly to the deployable (e.g. downloadable) form of the component."

**Motive:**
This URI allows automated tools to retrieve the exact distributable artifact — the compiled binary, container image, or installable package — for integrity verification, deployment automation, or security scanning. It connects the SBOM entry to the actual artifact stored in a registry or distribution platform.

**Accepted Values:**

- A valid URL pointing to the deployable (downloadable) artifact
- Examples: container image registry URL, binary download link, npm/PyPI/Maven artifact URL

**SBOM Mappings:**

- SPDX v3.0.1:
  - A `software_File` element with `binaryArtifact: "..."`, linked from the `software_Package` via a `hasDistributionArtifact` relationship (completeness: `complete`)

- CycloneDX v1.6:
  - `externalReferences[]` with `type: "distribution"`, `url: "..."`

> **Note (v2.1.0 vs v1.1):** The field was renamed from "URI of the executable form of the component" to "URI of the deployable form of the component".

### 16. Other unique identifiers

**Official Definition:**
> "Other identifiers that can be used to identify the component or to look it up in relevant databases, such as Common Platform Enumeration (CPE) or Package URL (purl)."

**Motive:**
Standard identifiers like PURL and CPE enable automated cross-referencing against vulnerability databases (NVD, OSV, GitHub Advisory Database), package registries, and licence databases. Without them, matching a component to external databases requires fuzzy name/version matching, which is error-prone and not machine-reliable. These identifiers make the SBOM directly queryable for security analysis without ambiguity.

**Accepted Values:**

- **Package URL (PURL)**: ecosystem-specific canonical identifier (e.g., `pkg:npm/lodash@4.17.21`)
- **Common Platform Enumeration (CPE)** v2.2 or v2.3 — NIST standard identifier
- **SWID tag ID** — ISO/IEC 19770-2 software identification tag

**SBOM Mappings:**

- SPDX v3.0.1:
  - `software_Package.externalIdentifiers[]` with `externalIdentifierType: "cpe22"` OR `"cpe23"` OR `"swid"` OR `"packageURL"` and `identifier: "..."`

- CycloneDX v1.6:
  - [`metadata.component.cpe`](https://cyclonedx.org/docs/1.6/json/#metadata_component_cpe): `"cpe:/..."` (primary component)
  - OR [`metadata.component.swid.tagId`](https://cyclonedx.org/docs/1.6/json/#metadata_component_swid_tagId)
  - OR [`metadata.component.purl`](https://cyclonedx.org/docs/1.6/json/#metadata_component_purl)
  - Same pattern for [`components[]`](https://cyclonedx.org/docs/1.6/json/#components_items_cpe)

### 17. Original licences

**Official Definition:**
> "The licence(s) that have been assigned by the creator of the component. For specifics see sections 6.1 and 8.1.13."

**Motive:**
Original licences represent what the component's creator declared as the licence at the source. This is distinct from the distribution licence (what a downstream licensee can use) and the effective licence (what the SBOM creator is actually using). Recording original licences enables full licence chain traceability and is essential when distribution licences differ from what the upstream author declared (e.g., the Qt dual-licensing scenario).

> **Note (v2.1.0 vs v2.0):** This field was called "Concluded licences" in v2.0 and referred to the licensee's concluded licence. In v2.1.0 the terminology was realigned: "Original licences" now means the licences assigned by the component's creator (previously "Declared licences"), and the additional category replaces the v2.0 "Concluded licences" field.

**Accepted Values:** Same as Distribution licences — valid SPDX identifiers, expressions, and LicenseRef variants.

**SBOM Mappings:**

- SPDX v3.0.1:
  - `software_Package` linked via `Relationship` of type `hasDeclaredLicense` (completeness: `complete`) to a `simpleLicensing_LicenseExpression` element

- CycloneDX v1.6:
  - `licenses[].expression` with `"acknowledgement": "declared"`

## Optional Fields

Optional fields MAY be included if the data exists and the format supports it (BSI §5.2.5, Table 6). This list is not exhaustive.

*(BSI §5.2.5, Table 6)*

### 18. Effective licence

**Official Definition:**
> "The licence under which the component is used by the licensee that is the creator of the current SBOM. For specifics see sections 6.1 and 8.1.13."

**Motive:**
When a component is available under multiple mutually exclusive licence choices (e.g., GPL vs. proprietary), the SBOM creator must select one — this selection is the effective licence. Recording it informs downstream parties which licence governs the SBOM creator's use of the component, enabling correct licence obligation tracking as the component moves further down the supply chain. Note that because the effective licence is set by the SBOM creator, it must be re-evaluated when SBOMs are merged.

**Accepted Values:** Valid SPDX identifiers, expressions, and LicenseRef variants (same as Distribution licences).

**SBOM Mappings:**

- SPDX v3.0.1:
  - `software_Package` linked via `Relationship` of type `other` with `comment: "hasEffectiveLicense"` (completeness: `complete`) to a `simpleLicensing_LicenseExpression` element

- CycloneDX v1.6:
  - `properties[]` with `name: "bsi:component:effectiveLicense"`, `value: "..."`

### 19. Hash value of the source code of the component

**Official Definition:**
> "Cryptographically secure checksum (hash value) of the component source code. A specific algorithm how to create a hash value of multiple source files or a source code tree, and which hash algorithm is utilised for that has not yet been determined."

**Motive:**
A hash of the source code allows independent verification that the source archive or repository snapshot has not been tampered with. Together with the deployable hash (field 9), it establishes a verifiable chain from source to binary — enabling detection of cases where the distributed binary does not match what was actually built from the declared source.

> **Note (v2.1.0 vs v1.1):** This field moved from "additional" in v1.1 to "optional" in v2.0 and remains optional in v2.1.0. The hash algorithm method is still unspecified (SHA-512 by analogy), but the calculation method for source trees is not yet standardized.

**SBOM Mappings:**

- SPDX v3.0.1:
  - A `software_SoftwareArtifact` with `software_primaryPurpose: "source"`, `verifiedUsing[].algorithm: "sha512"`, `verifiedUsing[].hashValue: "..."`, linked via a `generates` relationship (completeness: `complete`)

- CycloneDX v1.6:
  - `externalReferences[]` with `type: "source-distribution"`, `hashes[].alg: "SHA-512"`, `hashes[].content: "..."`

### 20. URL of the security.txt

**Official Definition:**
> "Contains the 'Uniform Resource Locator (URL)' of the component creator's **security.txt**."

**Motive:**
The `security.txt` file (RFC 9116) provides a standardized machine-readable contact for security vulnerability disclosure. Including its URL in the SBOM enables automated tooling to find the correct reporting channel for a given component's security issues — closing the loop between vulnerability discovery (via SBOM) and responsible disclosure (via security.txt).

**Accepted Values:**

- A valid URL pointing to the component creator's `security.txt` file (e.g., `https://example.com/.well-known/security.txt`)

**SBOM Mappings:**

- SPDX v3.0.1:
  - `software_Package.externalRef[]` with `externalRefType: "securityOther"`, `locator: "..."`

- CycloneDX v1.6:
  - [`externalReferences[]`](https://cyclonedx.org/docs/1.6/json/#components_items_externalReferences_items_type) with `type: "rfc-9116"`, `url: "..."`

## Summary Table

| # | Field | Level | Category | BSI Section |
|---|-------|-------|----------|-------------|
| 1 | Creator of the SBOM | SBOM | Required | §5.2.1 |
| 2 | Timestamp | SBOM | Required | §5.2.1 |
| 3 | Component creator | Component | Required | §5.2.2 |
| 4 | Component name | Component | Required | §5.2.2 |
| 5 | Component version | Component | Required | §5.2.2 |
| 6 | Filename of the component | Component | Required | §5.2.2 |
| 7 | Dependencies on other components | Component | Required | §5.2.2 |
| 8 | Distribution licences | Component | Required | §5.2.2 |
| 9 | Hash value of the deployable component (SHA-512) | Component | Required | §5.2.2 |
| 10 | Executable property | Component | Required | §5.2.2 |
| 11 | Archive property | Component | Required | §5.2.2 |
| 12 | Structured property | Component | Required | §5.2.2 |
| 13 | SBOM-URI | SBOM | Additional | §5.2.3 |
| 14 | Source code URI | Component | Additional | §5.2.4 |
| 15 | URI of the deployable form of the component | Component | Additional | §5.2.4 |
| 16 | Other unique identifiers | Component | Additional | §5.2.4 |
| 17 | Original licences | Component | Additional | §5.2.4 |
| 18 | Effective licence | Component | Optional | §5.2.5 |
| 19 | Hash value of the source code of the component | Component | Optional | §5.2.5 |
| 20 | URL of the **security.txt** | Component | Optional | §5.2.5 |

## Key Differences vs v1.1

| Aspect | v1.1 | v2.1.0 |
|--------|------|--------|
| CycloneDX minimum | 1.4 | **1.6** |
| SPDX minimum | 2.3 | **3.0.1** |
| Deployable hash algorithm | SHA-256 | **SHA-512** |
| Required component fields | 6 | **10** (adds filename, executable, archive, structured properties) |
| Licence model | Single "Licence" field | **Three-tier**: Distribution (required) / Original (additional) / Effective (optional) |
| Component types | One (fully described) | **Four**: Fully described, Logical, Identified, Referenced |
| Dependency completeness | Implicit | **Must be explicitly indicated** |
| Official format mappings | None in spec | **§8.2 mapping tables** for SPDX 3.0.1 and CycloneDX 1.6 JSON |
| security.txt URL | Not present | **New optional field** |
