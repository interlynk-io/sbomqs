# G7 SBOM for AI — Minimum Elements: Field Reference

**Standard:** Software Bill of Materials (SBOM) for AI — Minimum Elements  
**Issuer:** G7 Cybersecurity Working Group (BSI, CISA, ACN, ANSSI, CSE, NCSC, NCO) + EU Commission  
**Publication Date:** May 12, 2026  
**Status:** Consensus-based guidance (not mandatory legislation)

This document explains how **sbomqs** evaluates SBOMs against the G7 AI SBOM Minimum Elements. It covers the official definitions, our interpretation, exact mappings to SPDX and CycloneDX, and the scoring logic sbomqs applies.

## What the G7 AI SBOM Minimum Elements Cover

The G7 guidance defines **7 clusters** with **50 elements** that extend traditional software SBOM minimum elements (like NTIA 2021) to address the unique transparency needs of AI systems:

1. **Metadata** (10 elements) — Information about the SBOM for AI document itself
2. **System Level Properties** (9 elements) — Information about the AI system as a whole
3. **Models** (13 elements) — Model identity, hashes, architecture, training, licenses, external refs
4. **Datasets Properties** (10 elements) — Dataset identity, content, provenance, sensitivity, licenses
5. **Infrastructure** (2 elements) — Software dependencies + link to HBOM
6. **Security Properties** (4 elements) — Security controls, compliance, policy info, vulnerability refs
7. **Key Performance Indicators** (2 elements) — Security metrics + operational KPIs

The G7 explicitly states these elements are **recommendations to a reasonable extent** and should be decided according to the specific context of use. They do not create mandatory requirements or legislation.

---

## Summary Table

| # | G7 Field | Cluster | CycloneDX | SPDX v2.x | SPDX v3.x | Notes |
|---|----------|---------|-----------|-----------|-----------|-------|
| 1 | `sbom_author` | Metadata | `metadata.authors[].name` or `metadata.authors[].email` | `creationInfo.creators[]` (`Person:`) | `creationInfo.createdBy` → `Person` | Distinct from Producer; **Person only** |
| 2 | `sbom_version` | Metadata | `version` (top-level) | `documentNamespace` (version in URI) | `SBOM.spdxId` (URI); optional `Relationship` (`amendedBy`) | SPDX uses URI-based versioning |
| 3 | `sbom_data_format_name` | Metadata | `bomFormat` | `spdxVersion` (prefix) | Implicit | Always "CycloneDX" or "SPDX" |
| 4 | `sbom_data_format_version` | Metadata | `specVersion` | `spdxVersion` | `spdxVersion` | e.g., "1.7" or "SPDX-3.0.1" |
| 5 | `sbom_author_signature` | Metadata | `signature` (top-level JSF) | Detached via `--signature` / `--public-key` CLI flags | `SpdxDocument.verifiedUsing` with `type: "Signature"` | BOM-level signature, not component-level |
| 6 | `sbom_tool_name` | Metadata | `metadata.tools.components[].name` (1.5+) | `creationInfo.creators[].Tool` | `createdUsing` → `Tool.name` | Full names, not acronyms |
| 7 | `sbom_tool_version` | Metadata | `metadata.tools.components[].version` (1.5+) | Extracted from `creationInfo.creators[].Tool` | Extracted from `createdUsing` → `Tool` | |
| 8 | `sbom_generation_context` | Metadata | Custom `properties` or `metadata.lifecycles[].phase` | `creationInfo.comment` | `Software/Sbom.sbomType` | See Discussion #26 |
| 9 | `sbom_timestamp` | Metadata | `metadata.timestamp` | `creationInfo.created` | `creationInfo.created` | RFC 9557 format |
| 10 | `sbom_dependency_relationship` | Metadata | `dependencies[].ref / dependsOn[]` | `relationships[]: spdxElementId / DEPENDS_ON / relatedSpdxElement` | `Relationship: dependsOn` | "includes"/"derived from" |
| 11 | `system_name` | SLP | `metadata.component.name` | `packages[].name` where `SPDXRef-DOCUMENT` → `DESCRIBES` → package | `Package.name` where `SpdxDocument` → `describes` → package | Human-readable; **primary component** |
| 12 | `system_components` | SLP | `components[]` (all types) | `packages[]` | `Package` / `AIPackage` / `DatasetPackage` in `@graph` | Constituent parts of the system; its dependencies |
| 13 | `system_producer` | SLP | `metadata.component.manufacturer.name` | `packages[].originator` of DESCRIBES package | `Package.originatedBy` of described package | Distinct from author; **system is primary component** |
| 14 | `system_version` | SLP | `metadata.component.version` | `packages[].versionInfo` of DESCRIBES package | `Package.packageVersion` of described package | **System is primary component** |
| 15 | `system_timestamp` | SLP | Custom `properties` | N/A | N/A | Date/time of most recent system update |
| 16 | `system_data_flow` | SLP | `externalReferences[]` (type: `documentation`) | `packages[].externalRefs[]` (type: `other`/`documentation`) | `Package.externalRef` (type: `documentation`/`other`) | Link/reference/description |
| 17 | `system_data_usage` | SLP | Custom `properties` or `externalReferences` | Custom annotations | Custom annotations | I/O endpoints, APIs, multi-agent protocols |
| 18 | `system_input_output_properties` | SLP | `modelCard.modelParameters.inputs[]`, `outputs[]` | N/A | `AIPackage.informationAboutApplication` | Data types, modality, tokenizer |
| 19 | `intended_application_area` | SLP | `modelCard.considerations.useCases[]` | N/A | `AIPackage.domain` | Medical, finance, cybersecurity, etc. |
| 20 | `model_name` | Models | `component.name` (type: `machine-learning-model`) | `packages[].name` — **no model type in SPDX 2.x** | `AIPackage.name` (`@type: "AIPackage"`) | Human-readable; see Discussion #7 |
| 21 | `model_identifier` | Models | `component.bom-ref`, `component.purl`, `component.hashes[]` | `packages[].externalRefs[]` (PURL, CPE) | `Package.externalIdentifier` (PURL, CPE, SWHID) | Include ALL available identifiers |
| 22 | `model_version` | Models | `component.version` | `packages[].versionInfo` | `Package.packageVersion` | |
| 23 | `model_timestamp` | Models | `component.releaseNotes.timestamp` or custom property | N/A | `Package.releaseTime` | Required for AIPackage; see Discussion #8 |
| 24 | `model_producer` | Models | `component.manufacturer.name` or `component.manufacturer.email` | `packages[].originator` | `Package.originatedBy` | Name or email; required for AIPackage |
| 25 | `model_description` | Models | `component.description` | `packages[].description` | `AIPackage.limitation`, `Package.summaryDescription` | Capabilities, limitations, lineage |
| 26 | `model_hash_value` | Models | `component.hashes[].content` | `packages[].checksums[].checksumValue` | `Package.verifiedUsing[].hash.hashValue` | Hash of weights or model file |
| 27 | `model_hash_algorithm` | Models | `component.hashes[].alg` | `packages[].checksums[].algorithm` | `Package.verifiedUsing[].hash.algorithm` | IANA textual names; NIST-approved |
| 28 | `model_properties` | Models | `modelCard.modelParameters.architectureFamily`, `modelArchitecture`, custom `properties` (cdx:ai-ml:*) | N/A | `AIPackage.typeOfModel`, `AIPackage.informationAboutTraining`, `AIPackage.hyperparameter` | See Discussion #9 |
| 29 | `model_input_output_properties` | Models | `modelCard.modelParameters.inputs[]`, `outputs[]` | N/A | `AIPackage.informationAboutApplication` | See Discussion #10 |
| 30 | `model_training_properties` | Models | `modelCard.modelParameters.approach.type`, custom properties for RLHF/DPO/etc. | N/A | `AIPackage.informationAboutTraining`, `AIPackage.hyperparameter` | See Discussion #11 |
| 31 | `model_license` | Models | `component.licenses[]` | `packages[].licenseDeclared` | `Package.declaredLicense` | SPDX/CDX file references; open weight/architecture/data/training |
| 32 | `model_external_references` | Models | `component.externalReferences[]` | `packages[].externalRefs[]` | `Package.externalReference` | Model card, system card, research paper |
| 33 | `dataset_name` | Datasets | `component.name` (type: `data`) | N/A | `DatasetPackage.name` | See Discussion #12 |
| 34 | `dataset_description` | Datasets | `component.description` | N/A | `DatasetPackage.datasetAvailability`, `DatasetPackage.datasetType` | See Discussion #13 |
| 35 | `dataset_content` | Datasets | `data[].contents.url`, `data[].type` (="dataset") | N/A | `DatasetPackage.contentIdentifier` | See Discussion #14 |
| 36 | `dataset_identifier` | Datasets | `component.purl`, `component.bom-ref` | N/A | `Package.spdxId`, `Package.externalIdentifier` | URL, URI |
| 37 | `dataset_hash` | Datasets | `component.hashes[]` | N/A | `Package.verifiedUsing[].hash` | |
| 38 | `dataset_provenance` | Datasets | `component.pedigree`, custom properties | N/A | `DatasetPackage.dataCollectionProcess`, `DatasetPackage.datasetUpdateMechanism` | See Discussion #15 |
| 39 | `dataset_statistical_properties` | Datasets | Custom properties | N/A | Custom annotations | See Discussion #16 |
| 40 | `dataset_sensitivity` | Datasets | Custom properties | N/A | `DatasetPackage.hasSensitivePersonalInformation`, `DatasetPackage.confidentialityLevel` | See Discussion #17 |
| 41 | `dataset_dependency_relationship` | Datasets | `dependencies[]` | N/A | `relationships[]` | See Discussion #18 |
| 42 | `dataset_license` | Datasets | `component.licenses[]` | N/A | `Package.declaredLicense` | |
| 43 | `infrastructure_software` | Infrastructure | `components[]` (type: `library`, `framework`, `application`) | `packages[]` | `Package.hasContainedElement` (software packages) | Firmware, libraries, frameworks, runtime environments |
| 44 | `infrastructure_hardware` | Infrastructure | `externalReferences[]` (type: `bom`) linking to HBOM | N/A | `Package.hasContainedElement` (hardware) or HBOM reference | See Discussion #19 |
| 45 | `security_controls` | Security | `modelCard.considerations` (technical limitations, ethical), custom properties | N/A | `AIPackage.safetyRiskAssessment`, custom annotations | See Discussion #20 |
| 46 | `security_compliance` | Security | `modelCard.considerations.ethicalConsiderations`, custom properties | N/A | `AIPackage.standardCompliance` | See Discussion #21 |
| 47 | `cybersecurity_policy_information` | Security | `externalReferences[]` (type: `support` or custom) | N/A | `Package.primaryPurpose` or external references | See Discussion #22 |
| 48 | `vulnerability_referencing` | Security | `vulnerabilities[]` or external vulnerability databases | `vulnerabilities[]` | `Vulnerability` class or external references | See Discussion #23 |
| 49 | `security_metrics` | KPI | `modelCard.quantitativeAnalysis.performanceMetrics[]` | N/A | `AIPackage.metric`, `AIPackage.metricDecisionThreshold` | See Discussion #24 |
| 50 | `operational_performance_kpis` | KPI | Custom properties or `modelCard.quantitativeAnalysis` | N/A | `AIPackage.metric` | See Discussion #25 |

---

## Cluster 1: Metadata (10 Elements)

> **Official Cluster Definition:**
> "This cluster is used to represent information related to the SBOM for AI itself, and not the individual components or sub-elements. Information related to individual SBOM for AI components or sub-elements will be detailed separately in the dedicated clusters."

---

### 1. SBOM Author

**Official Definition:**
> "The name of the entity that creates the SBOM data for the target component. The SBOM author element contains a string that identifies the entity that generated the SBOM for the target component. This element captures the entity operating the tool to generate the SBOM, not the tool itself. Inputs for this element should use full names and should not use acronyms (unless the tool's official name includes an acronym). The SBOM author element is distinct from the Producer element."

**Motive:**
The SBOM author is the accountable party for the document. If the AIBOM is incorrect, incomplete, or stale, automated tools and auditors must know who to contact. The author is distinct from the producer — the author generates the SBOM, while the producer created the AI system or model.

**Mapping:**

- **SPDX v2.x:**
  - `creationInfo.creators[]`
    - `Person: <name> (<email>)`
    - **Note:** `Organization` entries in `creators[]` are **not** accepted as SBOM authors; they represent the producing entity, not the document author.

- **SPDX v3.x:**
  - `creationInfo.createdBy` → `Person`
    - `name`, `email`, or `url`
    - **Note:** `Organization` is not accepted as SBOM author; use `originatedBy` (system/model producer) instead.

- **CycloneDX:**
  - `metadata.authors[].name` (preferred)
  - `metadata.authors[].email` (acceptable fallback)
  - **Note:** `metadata.manufacturer.name` represents the system/model producer, **not** the SBOM author.

**Final Conclusion — SBOM Author:**
> **The SBOM Author is the identifiable person (individual or named contact) that created the AIBOM document. Organization entries and tool entries are not accepted as authors. At least one contact identifier (name, email, or URL) must be present. The author is distinct from the System Producer and the Model Producer.**

---

### 2. SBOM Version

**Official Definition:**
> "Identifier designated by the SBOM author to specify a change in the SBOM document from a previously identified version or to indicate that it is the first version. The SBOM version tracks the SBOM component data for a component-name/component-version pair. The SBOM version element may use Semantic Versioning; if it uses Semantic Versioning, the major version of a published SBOM following these minimum elements should be 1."

**Motive:**
The SBOM version tracks changes to the AIBOM document itself. If a vendor updates the AIBOM after retraining a model or adding new components, the version signals that the document has changed. This helps consumers detect stale AIBOMs and understand the evolution of the document over time.

**Mapping:**

- **SPDX v2.x:**
  - No native author-assigned SBOM version field.
  - `documentNamespace` — unique URI identifying the document; can encode version in the URI path.

- **SPDX v3.x:**
  - No native author-assigned SBOM version field.
  - `SBOM.spdxId` — document identifier (URI).
  - Optionally, a `Relationship` with `amendedBy` to the previous `SBOM.spdxId` can track document evolution.

- **CycloneDX:**
  - `version` (top-level integer)
  - `serialNumber` (UUID) for uniqueness

**Final Conclusion — SBOM Version:**
> **The SBOM version identifies iterations of the AIBOM document. CycloneDX provides a native `version` field. SPDX has no author-assigned version field; document identity is conveyed via `documentNamespace` (v2.x) or `spdxId` (v3.x), with optional `amendedBy` relationships to track document evolution.**

---

### 3. SBOM Data Format Name

**Official Definition:**
> "The name of the data format used to represent the SBOM data. The SBOM data format name element identifies the data format that the SBOM is in (in machine processable data format)."

**Motive:**
Consumers must know which specification to use when parsing the AIBOM. The format name identifies the ecosystem (SPDX vs CycloneDX) and determines which validation tools and schemas apply.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - Implicit — always "SPDX"
  - `spdxVersion` field confirms the format

- **CycloneDX:**
  - `bomFormat` — always "CycloneDX"

**Final Conclusion — SBOM Data Format Name:**
> **The AIBOM must declare its data format name. CycloneDX uses `bomFormat`. SPDX is implicit from the document structure.**

---

### 4. SBOM Data Format Version

**Official Definition:**
> "Identifier designated by the SBOM data format to specify the version of the data format. The SBOM data format version element identifies the version of the data format indicated in SBOM data format name. Versions declared to be deprecated by the organization(s) maintaining the data format should not be used."

**Motive:**
Different versions of the same format support different fields. Knowing the exact version lets consumers determine whether required fields are expected to exist and which schema to validate against. Deprecated versions should not be used.

**Mapping:**

- **SPDX v2.x:**
  - `spdxVersion` — e.g., `SPDX-2.2`, `SPDX-2.3`

- **SPDX v3.x:**
  - `spdxVersion` — e.g., `SPDX-3.0.1`

- **CycloneDX:**
  - `specVersion` — e.g., `1.5`, `1.6`, `1.7`

**Final Conclusion — SBOM Data Format Version:**
> **The AIBOM must declare the version of its data format. sbomqs extracts the version from the format-specific field and validates it against supported versions. Deprecated format versions should not be used.**

---

### 5. SBOM Author Signature

**Official Definition:**
> "A digital signature attributable to the SBOM author. The SBOM author signature element provides assurance that the claimed signatory signed the information and that the information was not modified after signature generation. Digital signatures should use a signature algorithm approved for secure use, according to regulations or recommendations from relevant authorities, such as NIST DSS, ISO/IEC 14888-4:2024, or ENISA Agreed Cryptographic Mechanisms."

**Motive:**
A digital signature proves the AIBOM data has not been tampered with since the author produced it. It enables downstream consumers to verify authenticity before making risk decisions based on the AIBOM contents.

**Mapping:**

- **CycloneDX (BOM-level signature):**
  - `signature` (top-level element, JSON Signature Format — JSF)
    - Signs the entire BOM document
    - `algorithm`, `value`, optional `publicKey`
  - **Note:** `metadata.component.signature` is a *component-level* signature (e.g., signing the model artifact itself), not the SBOM author's signature on the document.

- **SPDX v2.x:**
  - Detached signed envelope (external to the SBOM document)
  - `--signature` / `--public-key` CLI flags

- **SPDX v3.x:**
  - Embedded: `SpdxDocument.verifiedUsing` with `type: "Signature"`
  - Detached: `--signature` / `--public-key` CLI flags

**Final Conclusion — SBOM Author Signature:**
> **A digital signature attributable to the SBOM author should be present at the BOM/document level (not the component level). sbomqs detects signatures as follows:**
>
> - **CycloneDX:** top-level JSF `signature` element signing the entire BOM document. Component-level signatures (`metadata.component.signature`) do not satisfy this requirement.
> - **SPDX v2.x:** detached signature via `--signature` and `--public-key` CLI flags.
> - **SPDX v3.x:** embedded signature inside `SpdxDocument.verifiedUsing` or detached via CLI flags.

---

### 6. SBOM Tool Name

**Official Definition:**
> "The name of the tool used by the SBOM author to generate or amend the SBOM. The SBOM tool name element contains a string that identifies the software tool that the SBOM author used to generate the SBOM. Inputs for this element should use full names and should not use acronyms (unless the tool's official name includes an acronym)."

**Motive:**
Knowing which tool produced the AIBOM helps consumers understand the quality and completeness of the data. Different tools have different capabilities (e.g., some capture modelCard data, some don't). Tool names also help with debugging and reproducibility.

**Mapping:**

- **SPDX v2.x:**
  - `creationInfo.creators[].Tool`
    - e.g., `syft-0.78.0`, `sbomqs-generator-1.0.0`

- **SPDX v3.x:**
  - `createdUsing` → `Tool.name`

- **CycloneDX:**
  - `metadata.tools.components[].name` (1.5+)
  - `metadata.tools[].name` (1.4)

**Final Conclusion — SBOM Tool Name:**
> **The name of the tool used to generate the AIBOM should be present. Full names preferred; acronyms only if the tool's official name includes them.**

---

### 7. SBOM Tool Version

**Official Definition:**
> "Identifier for the version of the tool identified in the SBOM tool name element. The SBOM tool version element captures the tool version and allows an organization to identify a specific code delivery. If no version identifier is available, the SBOM author should indicate that the information is unknown."

**Motive:**
The tool version identifies a specific code delivery. Older tool versions may not support newer AIBOM fields (e.g., modelCard parsing was added in later versions). Knowing the tool version helps consumers assess data completeness.

**Mapping:**

- **SPDX v2.x:**
  - Extracted from `creationInfo.creators[].Tool`

- **SPDX v3.x:**
  - Extracted from `createdUsing` → `Tool`

- **CycloneDX:**
  - `metadata.tools.components[].version` (1.5+)
  - `metadata.tools[].version` (1.4)

**Final Conclusion — SBOM Tool Version:**
> **The version of the tool used to generate the AIBOM should be present. If unavailable, the author should indicate "unknown".**

---

### 8. SBOM Generation Context

**Official Definition:**
> "The relative software lifecycle phase and data available at the time the SBOM author generated the SBOM. The SBOM generation context element conveys information about the component data documented in the SBOM. Component data may differ based on the phase of the software lifecycle during which the SBOM was generated. General software lifecycle references such as 'before build,' 'build,' and 'after build,' as well as more specific identifiers, can satisfy this element."

**Motive:**
An AIBOM generated from source code (design phase) contains different information than one generated from a deployed artifact (operations phase). The generation context tells consumers what kind of data they can expect and whether the AIBOM is likely to be complete.

**Mapping:**

- **SPDX v2.x:**
  - `creationInfo.comment`

- **SPDX v3.x:**
  - `Software/Sbom.sbomType`

- **CycloneDX:**
  - `metadata.lifecycles[].phase` (e.g., `design`, `pre-build`, `build`, `post-build`, `operations`)
  - Custom `properties` if no native lifecycle field

> **Note — To confirm with SPDX/CDX community:** SPDX 3.x `sbomType` uses a fixed enum (`build`, `source`, `analyzed`, `runtime`, etc.) which may not perfectly align with the G7's broader lifecycle phase examples (`before build`, `build`, `after build`, `operations`). Whether `sbomType` fully satisfies the G7 "generation context" requirement should be confirmed with the SPDX community.

**Final Conclusion — SBOM Generation Context:**
> **The generation context indicates the software lifecycle phase during which the AIBOM was produced. sbomqs checks the format-specific lifecycle or comment field for a non-empty value.**

---

### 9. SBOM Timestamp

**Official Definition:**
> "Record of the date and time of the most recent update to the SBOM data. The SBOM timestamp element identifies when the SBOM author last changed the SBOM data, either manually or using a software tool. Each version of an SBOM will reflect a new timestamp. The content of this element should adhere to RFC 9557."

**Motive:**
The timestamp is essential for determining whether an AIBOM is stale. Model versions, vulnerability databases, and risk postures change over time; the timestamp anchors the AIBOM to a specific point in time for correlation.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - `creationInfo.created`

- **CycloneDX:**
  - `metadata.timestamp`

**Final Conclusion — SBOM Timestamp:**
> **The AIBOM must include a timestamp of its most recent update. The content should adhere to RFC 9557.**

---

### 10. SBOM Dependency Relationship

**Official Definition:**
> "The relationship between two software components, specifically noting that Software X includes Component Y or that Component A is largely derived from Component B. The SBOM dependency relationship element reflects how a given software component was included in the target software. The inclusion relationship ('includes' or 'included in') supports the capability to build a dependency graph. In addition to inclusion, the dependency relationship should reflect how a given component may be largely derived from another piece of software, or that it is a descendant of another piece of software. This allows an SBOM to explicitly document backported or forked software."

**Motive:**
Dependency relationships enable consumers to build a complete dependency graph of the AI system. This is critical for vulnerability management ("If model A depends on dataset B, and B has a poisoned data issue, is A affected?") and for understanding system composition.

**Mapping:**

- **SPDX v2.x:**
  - `relationships[]` with types like `DEPENDS_ON`, `DESCRIBED_BY`, `CONTAINS`

- **SPDX v3.x:**
  - Top-level `Relationship` objects with `relationshipType`

- **CycloneDX:**
  - `dependencies[]` graph
  - `compositions[]` for completeness assertions

**Final Conclusion — SBOM Dependency Relationship:**
> **Dependency relationships must reflect how components are included or derived from one another. sbomqs evaluates relationship completeness for the primary component and checks that all referenced dependencies exist in the BOM.**


---

## Cluster 2: System Level Properties — SLP (9 Elements)

> **Official Cluster Definition:**
> "The SLP cluster contains elements that refer to information on the AI system as a whole (e.g., capturing system level information and AI system inner workings that are relevant to AI systems composed of multiple AI elements, such as classifiers, large language models (LLMs) or AI agents). This cluster also includes all software dependencies and frameworks used in the AI system as well as information about how AI system components interact and process user data. Elements that are in support or that have been used to deploy the system are included in the cluster Infrastructure below."

**Note on Primary Component:**
In the G7 framework, the AI system itself is the **primary component** that the AIBOM describes. All models, datasets, infrastructure components, and software dependencies are sub-components of this system. In CycloneDX, this maps to `metadata.component`. In SPDX, the system is the top-level package described by the document via a `DESCRIBES` (v2.x) or `describes` (v3.x) relationship.

---

### 11. System Name

**Official Definition:**
> "The name assigned by the System producer to an AI system. The System name element identifies the AI system in a human-readable way. The System producer determines the AI system name. Data formats implementing the System name element should allow for multiple entries to capture alternate names (full names and not acronyms – unless the System's official name includes an acronym)."

**Motive:**
The system name is the human-readable identity of the AI system — the primary component that the AIBOM describes. It tells consumers what they are looking at: "Chest X-Ray Analysis Pipeline" not "model_7b_2024_q3_final_real.pt". Multiple entries allow for alternate names and internationalization.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].name` (for the top-level package representing the system)
  - The system package is the one referenced by `DESCRIBES` in `relationships[]`

- **SPDX v3.x:**
  - `Package.name` (for the top-level package)
  - The system is the primary subject of the `SpdxDocument` via a `describes` relationship

- **CycloneDX:**
  - `metadata.component.name` — the system is the BOM subject (primary component)
  - Component `name` for sub-systems

**Final Conclusion — System Name:**
> **The human-readable name of the AI system. The AI system is the primary component that the AIBOM describes; all models, datasets, and infrastructure are sub-components. Must be assigned by the system producer. Data formats should allow multiple entries for alternate names.**

---

### 12. System Components

**Official Definition:**
> "This element captures the components that are included in the AI system."
> — Examples: AI models included in the system; databases; other software tools and components.

**Motive:**
An AI system is more than a model — it's a collection of components: the model, vector databases, API gateways, monitoring agents, data pipelines. This element documents what pieces make up the whole.

**Mapping:**

- **SPDX v2.x:**
  - `packages[]` array — each component is a separate package
  - Relationship: the top-level system package `DESCRIBES` / `CONTAINS` these packages

- **SPDX v3.x:**
  - Elements in the `@graph` representing the system's constituent parts:
    - `Package` (software dependencies: libraries, frameworks, tools)
    - `AIPackage` (AI models)
    - `DatasetPackage` (datasets)
  - Relationship: `Relationship` with `contains` or `dependsOn` from the system to these elements

- **CycloneDX:**
  - `components[]` array — all types (machine-learning-model, data, library, framework, application)
  - Relationship: `dependencies[]` graph links the primary system to its components

**Final Conclusion — System Components:**
> **All components included in the AI system must be enumerated: models, datasets, databases, software tools, frameworks, and other dependencies. These are the constituent parts (sub-components) of the primary system, documented via the `components[]` (CycloneDX), `packages[]` (SPDX 2.x), or typed elements in the `@graph` (SPDX 3.x).**

---

### 13. System Producer

**Official Definition:**
> "Identifier used for the name of the entity that creates, defines, and identifies an AI system."

**Motive:**
The system producer is the entity that created/defined the AI system. This is distinct from the SBOM author (who generated the document) and the model producer (who trained the model). A single entity may be all three, but they are semantically different roles.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].originator` (for the top-level system package)

- **SPDX v3.x:**
  - `Package.originatedBy` (for the primary system package)
  - **Note:** `Package.suppliedBy` identifies the **distributor/supplier**, not the creator. For the G7 "producer" semantic, use `originatedBy`.

- **CycloneDX:**
  - `metadata.component.manufacturer.name` — the system is the BOM subject

**Final Conclusion — System Producer:**
> **The entity that creates, defines, and identifies the AI system (the primary component). Distinct from the SBOM author and the model producer.**

---

### 14. System Version

**Official Definition:**
> "Identifier used by the System producer to specify a change in a software component from a previously identified version or to indicate that it is the first version. The System version element captures the target component's version and allows an organization to identify a specific code delivery. If the System producer does not provide a version, then the SBOM author should indicate that the information is unknown."

**Motive:**
The system version is distinct from the model version. A system may be updated (e.g., API changes, monitoring added) while the underlying model remains the same. Version tracking enables consumers to identify specific deployments.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].versionInfo` (for the top-level system package)

- **SPDX v3.x:**
  - `Package.packageVersion` (for the primary system package)

- **CycloneDX:**
  - `metadata.component.version` — the system is the BOM subject

**Final Conclusion — System Version:**
> **The version identifier for the AI system as a whole (primary component), distinct from model version. If not provided by the system producer, the SBOM author should indicate "unknown".**

---

### 15. System Timestamp

**Official Definition:**
> "Record of the date and time of the most recent update to the AI system. Updates can include model updates or software updates of other components that make up the system."

**Motive:**
The system timestamp records when the AI system itself was last updated — not when the AIBOM was generated. This could reflect a model retraining, a software patch, or a configuration change.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - No native system-level timestamp for the primary component. May use custom annotations.

- **CycloneDX:**
  - Custom `properties` on `metadata.component` or `releaseNotes.timestamp`

**Final Conclusion — System Timestamp:**
> **The date/time of the most recent update to the AI system (primary component). No native field in most formats; use custom properties or annotations.**

---

### 16. System Data Flow

**Official Definition:**
> "This element describes the Data flow (link, reference, or description) between the different components of an AI system."
> — Examples: input/output endpoints; description of the data information flow (source → destination); APIs of external services the AI system uses; multi-agent communication protocols; bidirectional data flow towards external services (web grounding).

**Motive:**
Data flow describes how information moves between components. Does user input flow through a filter before reaching the model? Does the model output go through a confidence threshold before being displayed? Understanding data flow is critical for security analysis and incident response.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].externalRefs[]` with type `other` or `documentation`
  - Custom annotations or relationships

- **SPDX v3.x:**
  - `Package.externalRef` with type `documentation` or `other`
  - Relationships describing data flow between components

- **CycloneDX:**
  - `externalReferences[]` with type `documentation`
  - Custom `properties`

> **Note — To confirm with SPDX/CDX community:** The G7 element describes dynamic data flow between AI system components (source → destination, APIs, multi-agent protocols). Existing SBOM `externalReferences`/`externalRef` fields are designed for static links to external resources, not for describing runtime data flow topology. Whether external references with type `documentation` sufficiently capture data flow semantics, or whether a new relationship type or extension is needed, should be discussed with the SPDX and CycloneDX communities.

**Final Conclusion — System Data Flow:**
> **Describes how data moves between AI system components. Use `externalReferences` (CycloneDX) or `externalRef`/`externalRefs` (SPDX) with type `documentation` or `other` to link to data flow documentation.**

---

### 17. System Data Usage

**Official Definition:**
> "This element describes how data in the AI system is processed and consumed."
> — Examples: link/URL to technical documentation (such documentation may contain information on whether data is used for improving the model performance, information on data logging from the APIs used to invoke the system and information on whether metadata is derived from the user input data).

**Motive:**
Data usage describes what the AI system actually *does* with data. Is user data logged? Is it used for model improvement? Are API responses cached? This is critical for privacy compliance (GDPR, CCPA) and for understanding system behavior.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - Custom annotations

- **CycloneDX:**
  - Custom `properties` or `externalReferences`

> **Note — To confirm with SPDX/CDX community:** The G7 element captures runtime data usage semantics (logging, model improvement, metadata derivation from user input). Neither SPDX nor CycloneDX has a native field for "how data is consumed or processed" by a component. Custom annotations/properties are the only current mechanism, but they lack standardization. Whether a new property namespace, relationship type, or profile extension is needed to represent data usage should be discussed with the SPDX and CycloneDX communities.

**Final Conclusion — System Data Usage:**
> **Describes how data is processed and consumed within the AI system. No native field in most formats; use custom properties or external references.**

---

### 18. System Input/Output Properties

**Official Definition:**
> "Element used to describe the properties of the input and the output of the AI system."
> — Examples: type of input and output data handled, clearly specifying the differences between input and output data types and characteristics; the modality (text, audio, image, video, etc.); the input preprocessing (such as the type of tokenizer used in the case of LLMs); link to URL/documentation describing impacts on system decision making.

**Motive:**
Input/output properties tell consumers what data types the system accepts and produces. A medical imaging system that accepts DICOM but outputs text reports has very different I/O properties than a chatbot that accepts and produces text. This is essential for integration planning and safety assessment.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.informationAboutApplication`

- **CycloneDX:**
  - `modelCard.modelParameters.inputs[]`, `outputs[]`
    - `format` field describes data type (string, image, audio, etc.)

> **Note — To confirm with SPDX/CDX community:** The fields `modelCard` (CycloneDX) and `AIPackage` (SPDX 3.x) are explicitly defined in their respective AI extensions. However, there is currently no established convention for the primary component type of an AI *system* (as opposed to a single model). If the system is typed as `application` (CycloneDX) or a regular `Package` (SPDX 3.x), these AI-specific fields may not apply to the primary component. Real-world AIBOM examples are needed to confirm community conventions for representing system-level I/O versus model-level I/O.

**Final Conclusion — System Input/Output Properties:**
> **Describes the data types, modality, and preprocessing of system inputs and outputs. CycloneDX captures this via modelCard inputs/outputs. SPDX 3.0 uses AIPackage.informationAboutApplication.**

---

### 19. Intended Application Area

**Official Definition:**
> "This element describes the type of application the AI system is deployed in."
> — Examples: real time or near real time application; cybersecurity, medical/healthcare, finance, etc.

**Motive:**
The intended application area places guardrails on system use. A model designed for "medical question answering" should not be deployed for "automated trading" without additional validation. This element helps prevent misuse and supports compliance with domain-specific regulations.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.domain`

- **CycloneDX:**
  - `modelCard.considerations.useCases[]`
  - Custom `properties`

**Final Conclusion — Intended Application Area:**
> **The domain or type of application the AI system is designed for. CycloneDX captures this via modelCard useCases. SPDX 3.0 uses AIPackage.domain.**

---

## Cluster 3: Models (13 Elements)

> **Official Cluster Definition:**
> "The Models cluster includes basic information for identifying the models used by the AI system, describes for each model how its weights were produced, and outlines their properties and limitations."

A model is a **sub-component** of the AI system — one of the system's dependencies. Each model's detailed information is captured inside the BOM's component list: `components[]` in CycloneDX (with `type="machine-learning-model"`), `packages[]` in SPDX v2.x, or as an `AIPackage` element in the SPDX 3.x `@graph`. The AI system itself (primary component) is described in Cluster 2 (System Level Properties).

---

### 20. Model Name

**Official Definition:**
> "The name assigned by the Model producer to a software component. The Model name element identifies the software component in a human-readable way. The Model producer determines the component name. This element is distinct from the Model identifier element. Data formats implementing the Model name element should allow for multiple entries to capture alternate names. Inputs for this element should use full names and should not use acronyms (unless the component's official name includes an acronym)."

**Motive:**
The model name is the human-readable identity of the model. "Meta-Llama-3.1-8B-Instruct" tells you the producer, the base model family, the size, and the variant. Alternate names allow for discoverability across different naming conventions.

**Mapping:**

- **SPDX v2.x / v3.x:**
  - `Package.name`

- **CycloneDX:**
  - `component.name` (for type="machine-learning-model")

**Final Conclusion — Model Name:**
> **The human-readable name of the model, assigned by the model producer. Must be distinct from the model identifier. Allow multiple entries for alternate names.**

---

### 21. Model Identifier

**Official Definition:**
> "Identifier(s) used to identify a component or serve as a look-up key for relevant databases. The Model identifier element contains at least one software identifier associated with the target component. Machine-processable, unique software identifiers support automated analysis. This element should use common software identifiers, such as Common Platform Enumeration (CPE) and Package-URL (PURL). This element may also include universally unique identifiers (UUID), organization-specific identifiers, commit hashes, and intrinsic identifiers such as OmniBOR and SWHID. If there are multiple software identifiers, either in the same identifier format or different one(s), the SBOM author should include all of them."

**Motive:**
Machine-processable identifiers enable automated vulnerability tracking, license analysis, and dependency resolution. A model without a PURL or CPE cannot be looked up in vulnerability databases. Multiple identifiers increase discoverability across different ecosystems.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].externalRefs[]` (PURL, CPE)
  - `REFERENCE_CATEGORY_OTHER` (SWHID, OmniBOR, commit)

- **SPDX v3.x:**
  - `Package.externalIdentifier` (PURL, CPE, SWHID)
  - `contentIdentifier` (gitoid, SWHID)

- **CycloneDX:**
  - `component.bom-ref` (unique within BOM)
  - `component.purl` (global Package URL)
  - `component.hashes[]` (content-based identifiers)
  - Custom properties for CPE, SWHID

**Final Conclusion — Model Identifier:**
> **Machine-processable identifiers for the model. At least one identifier must be present. Include ALL available identifiers (PURL, CPE, SWHID, UUID, commit hash, OmniBOR).**

---

### 22. Model Version

**Official Definition:**
> "Identifier used by the AI model producer to specify a change in a software component from a previously identified version or to indicate that it is the first version. The AI model version element captures the target component's version and allows an organization to identify a specific code delivery. If the AI model producer does not provide a version, then the SBOM author should indicate that the information is unknown."

**Motive:**
Model version is critical for vulnerability tracking. A CVE may affect version `v1.0.0` but not `v1.0.1`. Without version information, it is impossible to determine whether a deployed model is affected by known vulnerabilities or quality issues.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].versionInfo`

- **SPDX v3.x:**
  - `Package.packageVersion`

- **CycloneDX:**
  - `component.version`

**Final Conclusion — Model Version:**
> **The version identifier for the model, assigned by the model producer. If not provided, the SBOM author should indicate "unknown".**

---

### 23. Model Timestamp

**Official Definition:**
> "Record of the date and time of the most recent update to the AI model. This element can also be used for official production release date of the AI model."

**Motive:**
The model timestamp records when the model was last updated or officially released. This is distinct from the system timestamp and the SBOM timestamp. It helps consumers determine if they are running the latest version and if the model is still supported.

**Mapping:**

- **SPDX v3.x:**
  - `Package.releaseTime` (required for AIPackage)

- **CycloneDX:**
  - `component.releaseNotes.timestamp`
  - Custom property

> **Note — To confirm with SPDX/CDX community:** In SPDX 3.x, `Package.releaseTime` is explicitly required for `AIPackage` elements and maps cleanly to the model timestamp. In CycloneDX, `component.releaseNotes.timestamp` exists but `releaseNotes` is typically a document-level or metadata-level construct, not a per-component field in common usage. Whether model-level timestamps are best captured via `releaseNotes.timestamp`, custom properties, or another mechanism should be confirmed with the CycloneDX community.

**Final Conclusion — Model Timestamp:**
> **The date/time of the most recent model update or official production release. Required for AIPackage in SPDX 3.0.**

---

### 24. Model Producer

**Official Definition:**
> "Identifier used for the name of the entity that creates, defines, and identifies an AI model. The Model producer element contains a human-readable string that identifies the entity that produced the model. Model producer refers to the originator or manufacturer of the model. Organizations can use the Model producer element to learn more about a model's producer. It can also enable the identification of a point of contact for software security concerns. The Model producer element should allow for multiple entries."
> — Examples: companies involved in pre-training, post-training, or fine tuning of the model.

**Motive:**
The model producer is the originator or manufacturer of the model. This entity may be different from the system producer (who assembled the AI system) and the SBOM author (who generated the document). Multiple entries accommodate collaborative models (e.g., one company pre-trained, another fine-tuned).

**Mapping:**

- **SPDX v2.x:**
  - `packages[].originator`

- **SPDX v3.x:**
  - `Package.originatedBy` (for the AIPackage element)
  - **Note:** `Package.suppliedBy` identifies the **distributor/supplier**, not the creator. For the G7 "producer" semantic, use `originatedBy`.

- **CycloneDX:**
  - `component.manufacturer.name` (preferred)
  - `component.manufacturer.email` (acceptable fallback)

**Final Conclusion — Model Producer:**
> **The entity that created/defined/identified the model. Distinct from system producer and SBOM author. Name or email acceptable. Should allow multiple entries for collaborative models.**

---

### 25. Model Description

**Official Definition:**
> "Element used to describe the model's capabilities, known limitations, and lineage."
> — Examples: intended application area the model was designed or developed for as well as known weaknesses and limitations; lineage contains creation information of the model, such as information about the predecessor model on which fine tuning was done (distillation or finetuning) or known derivative models; model dependencies such as internal or third-party packages, libraries, modules, or development frameworks.

**Motive:**
The model description tells consumers what the model can do, what it can't do, and where it came from. Known limitations ("Not for diagnostic use") prevent misuse. Lineage information ("Fine-tuned from Llama-2-7B") enables traceability across the model supply chain.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].description`

- **SPDX v3.x:**
  - `AIPackage.limitation`
  - `Package.summaryDescription`

- **CycloneDX:**
  - `component.description`

**Final Conclusion — Model Description:**
> **Describes model capabilities, known limitations, and lineage. Essential for risk assessment and preventing misuse.**

---

### 26. Model Hash Value

**Official Definition:**
> "The output generated from applying a cryptographic hash algorithm to an executable component artifact. The Model hash value element contains an ASCII formatted value that is the result of providing the executable component artifact as input to a cryptographic hash algorithm. If the SBOM author does not have access to the executable component artifact, then the SBOM author should indicate the value is unknown."
> — Example: the hash of the weights or model file or other model related artifacts.

**Motive:**
The model hash value proves that the model weights have not been tampered with since the hash was computed. It enables consumers to verify that the model file they received matches the model file the producer intended to distribute. This is critical for supply chain integrity.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].checksums[].checksumValue`

- **SPDX v3.x:**
  - `Package.verifiedUsing[].hash.hashValue`

- **CycloneDX:**
  - `component.hashes[].content`

**Final Conclusion — Model Hash Value:**
> **The cryptographic hash of the model artifact (weights, model file, or related artifacts). Enables integrity verification.**

---

### 27. Model Hash Algorithm

**Official Definition:**
> "The cryptographic algorithm used to compute the Model hash value of the software component. The Model hash algorithm element documents the algorithm that produced the Model hash value to allow validation of the integrity of the target component. The SBOM author should identify the algorithm using Internet Assigned Numbers Authority (IANA) Hash Function Textual Names. The algorithm should be approved by a relevant authority, such as the U.S. National Institute of Standards and Technology (NIST)."

**Motive:**
The hash algorithm must be documented to enable validation. Using a deprecated or weak algorithm (e.g., MD5) undermines the security purpose of the hash. NIST-approved algorithms (SHA-256, SHA-512) are recommended.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].checksums[].algorithm`

- **SPDX v3.x:**
  - `Package.verifiedUsing[].hash.algorithm`

- **CycloneDX:**
  - `component.hashes[].alg` (IANA names, e.g., "SHA-256")

**Final Conclusion — Model Hash Algorithm:**
> **The algorithm used to compute the model hash. Must use IANA textual names (e.g., "SHA-256"). Should be NIST-approved.**

---

### 28. Model Properties

**Official Definition:**
> "Element used to describe the characteristics of the specific model considered, such as the architecture of the model in case of parametric models. This element can contain several different sub-elements with more specific and detailed model information."
> — Examples: parametric as Neural Networks, non-parametric such as Clustering or KNN; the number of parameters/model size; the architecture of the model (encoder-decoder, encoder only, decoder only, and the underlying network type, e.g., transformer, CNN, RNN, LSTM); popular architectures such as ResNet, VGG, or GPT; information on hyperparameters of the model.

**Motive:**
Model properties describe the "shape" of the model: how many parameters it has, what architecture it uses, whether it's parametric or non-parametric. This information is critical for deployment planning ("Can this model fit on our GPU?"), performance estimation, and compatibility assessment.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.typeOfModel` — model type (supervised, RL, etc.)
  - `AIPackage.informationAboutTraining` — training details
  - `AIPackage.hyperparameter` — hyperparameters as DictionaryEntry

- **CycloneDX:**
  - `modelCard.modelParameters.architectureFamily` — transformer, CNN, RNN, LSTM, GRU, GAN
  - `modelCard.modelParameters.modelArchitecture` — specific implementation (LlamaForCausalLM)
  - Custom `properties` with `cdx:ai-ml:model:parameter:*` namespace
    - `cdx:ai-ml:model:parameter:count` — parameter count (e.g., "7B")
    - `cdx:ai-ml:model:hyperparameter:num_hidden_layers` — architecture details

> **Note — To confirm with SPDX/CDX community:** SPDX 3.x `AIPackage.typeOfModel` and `informationAboutTraining` are explicitly defined in the AI Profile, but their granularity for representing detailed architecture families and parameter counts may vary. CycloneDX `modelCard` fields and the reserved `cdx:ai-ml:model:*` property namespace provide rich coverage, but the namespace is still evolving. Whether these mappings fully capture all G7 model property examples (parametric vs non-parametric, parameter count, architecture family) should be confirmed with both communities.

**Final Conclusion — Model Properties:**
> **Describes model characteristics: parametric vs non-parametric, parameter count, architecture family, specific architecture, hyperparameters.**

---

### 29. Model Input/Output Properties

**Official Definition:**
> "Element used to describe the properties of the input and the output of the AI model."
> — Examples: type of input and output data handled, clearly specifying the differences between input and output data types and characteristics; the context length; the modality (text, audio, image, video, etc.); input preprocessing (such as the type of tokenizer used in the case of LLMs, Vision Language Models or multimodal models).

**Motive:**
Model I/O properties describe what data types the model accepts and produces. A vision model that accepts 224x224 RGB images produces very different outputs than an LLM that accepts text tokens. Context length, tokenizer type, and modality are all critical for integration.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.informationAboutApplication`

- **CycloneDX:**
  - `modelCard.modelParameters.inputs[]` — `format` field
  - `modelCard.modelParameters.outputs[]` — `format` field

> **Note — To confirm with SPDX/CDX community:** Both SPDX 3.x `AIPackage.informationAboutApplication` and CycloneDX `modelCard.modelParameters.inputs/outputs` are explicitly defined in their respective AI extensions. However, the exact granularity of what each field captures (e.g., context length, tokenizer type, multimodal inputs) may vary between formats and implementations. Whether these fields fully satisfy the G7 requirement for detailed input/output properties should be confirmed with both communities.

**Final Conclusion — Model Input/Output Properties:**
> **Describes input/output data types, context length, modality, and preprocessing. CycloneDX captures via modelCard inputs/outputs.**

---

### 30. Model Training Properties

**Official Definition:**
> "This element describes the different training techniques that have been used for the AI system models (this includes all types of training, including what is generally referred to as pre-training and post-training/fine tuning/continual learning)."
> — Example: link/URL to documentation (e.g., models cards) describing the type of learning (unsupervised, supervised, self-supervised) as well as the post-training characteristics (continual learning, fine tuning stages, reinforcement learning from human feedback, instruction tuning, and Reinforcement Learning Optimization type such as DPO, PPO, and GRPO).

**Motive:**
Training properties reveal how the model was created. A model trained with RLHF (Reinforcement Learning from Human Feedback) has different safety characteristics than one trained with pure supervised learning. Fine-tuning on medical data produces different biases than pre-training on web text.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.informationAboutTraining`
  - `AIPackage.hyperparameter` — for training hyperparameters

- **CycloneDX:**
  - `modelCard.modelParameters.approach.type` — supervised, unsupervised, RL, etc.
  - Custom properties for post-training techniques:
    - `cdx:ai-ml:model:parameter:tune_method` — sft, rlhf, dpo, ppo, grpo

> **Note — To confirm with SPDX/CDX community:** SPDX 3.x `AIPackage.informationAboutTraining` is explicitly defined in the AI Profile, and CycloneDX `modelCard.modelParameters.approach.type` covers learning type. However, the G7 examples include granular post-training stages (RLHF, DPO, PPO, GRPO, continual learning, instruction tuning). Whether these fine-grained training properties are best captured via the existing fields, custom properties, or a new structured extension should be confirmed with both communities.

**Final Conclusion — Model Training Properties:**
> **Describes training techniques: learning type (supervised/unsupervised/RL), post-training (fine-tuning, RLHF, DPO, PPO, GRPO).**

---

### 31. Model License

**Official Definition:**
> "This element describes the license type of the AI model."
> — Examples: link/URL to the model licensing document (can contain references of open source licensing such as EUPL, GPL, Apache) or to the corresponding fields in SPDX/CDX files; specifies whether the AI model is open weight, open architecture, open data or open training.

**Motive:**
Model licenses govern legal use. Some models are open-weight (weights freely available) but closed-data (training data proprietary). Others restrict commercial use. Understanding the license type is essential for procurement and compliance.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].licenseDeclared`

- **SPDX v3.x:**
  - `Package.declaredLicense`

- **CycloneDX:**
  - `component.licenses[]`
    - `license.id` (SPDX license ID)
    - `license.name` (custom license name)
    - `expression` (SPDX license expression)

**Final Conclusion — Model License:**
> **The license governing the model. Should specify open weight, open architecture, open data, and/or open training status.**

---

### 32. Model External References

**Official Definition:**
> "Link/URL to external references related to the model."
> — Examples: link/URL to any existing framework related to the model or system card from editors; JSON schema of the model card itself, such as is provided by existing tools; public documentation; research paper.

**Motive:**
External references link to authoritative sources: the model card on Hugging Face, the research paper on arXiv, the system card from the vendor. These documents contain detailed information that cannot fit into the AIBOM itself.

**Mapping:**

- **SPDX v2.x:**
  - `packages[].externalRefs[]`

- **SPDX v3.x:**
  - `Package.externalReference`

- **CycloneDX:**
  - `component.externalReferences[]`
    - Types: `documentation`, `model-card`, `vcs`, `issue-tracker`, `website`

**Final Conclusion — Model External References:**
> **Links to model cards, system cards, research papers, public documentation, and JSON schemas.**


---

## Cluster 4: Datasets Properties — DP (10 Elements)

> **Official Cluster Definition:**
> "The DP cluster provides information on datasets used during the whole life cycle of the model, including basic information that documents the identity and provenance of data."

Datasets are **sub-components** of the AI system — dependencies used for training, fine-tuning, benchmarking, or evaluation. Each dataset's detailed information is captured inside the BOM's component list: `components[]` in CycloneDX (with `type="data"`), `packages[]` in SPDX v2.x, or as a `DatasetPackage` element in the SPDX 3.x `@graph`.

---

### 33. Dataset Name

**Official Definition:**
> "The name assigned to the dataset by the dataset creator."
> — Examples: string to publicly identify the dataset; equivalent to component name.

**Motive:**
The dataset name is the human-readable identity of the dataset. "Common Crawl 2023-06" or "Medical QA v2" tells consumers what data the model was trained on.

**Mapping:**

- **SPDX v3.x:**
  - `DatasetPackage.name`

- **CycloneDX:**
  - `component.name` (for type="data")

**Final Conclusion — Dataset Name:**
> **The human-readable name of the dataset, assigned by the dataset creator.**

---

### 34. Dataset Description

**Official Definition:**
> "Element used to describe the dataset, such as its primary intended use with regards to AI model training (for example, fine-tuning, benchmark, context extension)."
> — Examples: dataset used for pre-training, fine tuning, or model/system evaluation; can include whether the dataset is private or public.

**Motive:**
The dataset description tells consumers what the dataset was used for. A dataset used for pre-training has different quality requirements than one used for benchmarking. Knowing whether the dataset is private or public affects reproducibility and compliance.

**Mapping:**

- **SPDX v3.x:**
  - `DatasetPackage.datasetAvailability`
  - `DatasetPackage.datasetType`

- **CycloneDX:**
  - `component.description` (for type="data")

> **Note — To confirm with SPDX/CDX community:** The G7 definition emphasizes the dataset's *primary intended use* (pre-training, fine-tuning, benchmark, evaluation) rather than a generic description. CycloneDX `component.description` is a general-purpose field, and SPDX 3.x `DatasetPackage.datasetType` / `datasetAvailability` are more focused on availability/type. Whether these fields fully capture "intended use with regards to AI model training" should be confirmed with both communities.

**Final Conclusion — Dataset Description:**
> **Describes the dataset's primary intended use: pre-training, fine-tuning, benchmark, or evaluation. May indicate whether public or private.**

---

### 35. Dataset Content

**Official Definition:**
> "Element used to describe the content of the dataset."
> — Examples: description of the content of the dataset, such as financial data, medical records data, etc.; the format of the dataset (data structure, encoding like JSON or XML); the data format (image, audio, video, 3D).

**Motive:**
Dataset content describes what is in the data. Financial data has different sensitivity and regulatory implications than synthetic images. The format (JSON, Parquet, TFRecord) affects tooling and interoperability.

**Mapping:**

- **SPDX v3.x:**
  - `DatasetPackage.contentIdentifier`

- **CycloneDX:**
  - `data[].type` (="dataset")
  - `data[].contents.url`

> **Note — To confirm with SPDX/CDX community:** The G7 element covers content description, data format (JSON, XML), and modality (image, audio, video, 3D). CycloneDX `data[].contents.url` links to content but does not describe it inline. SPDX 3.x `DatasetPackage.contentIdentifier` is typically a URI/URL reference. Whether inline content descriptions (e.g., "financial data, JSON format") are best captured via these fields, custom properties, or a new extension should be confirmed with both communities.

**Final Conclusion — Dataset Content:**
> **Describes the content type (financial, medical, etc.), format (JSON, XML), and modality (image, audio, video, 3D).**

---

### 36. Dataset Identifier

**Official Definition:**
> "Information that allows univocal identification of the dataset."
> — Example: dataset URL, URI, etc.

**Motive:**
Univocal identification ensures that consumers can locate the exact dataset used for training. A URL or URI pointing to Hugging Face, Kaggle, or an institutional repository provides traceability.

**Mapping:**

- **SPDX v3.x:**
  - `Package.spdxId`
  - `Package.externalIdentifier`

- **CycloneDX:**
  - `component.purl`
  - `component.bom-ref`

**Final Conclusion — Dataset Identifier:**
> **URL, URI, PURL, or other identifier that uniquely locates the dataset.**

---

### 37. Dataset Hash

**Official Definition:**
> "The cryptographic value generated from taking the hash of the dataset."
> — Example: the hash over the dataset file.

**Motive:**
The dataset hash proves that the training data has not been altered since the hash was computed. This is critical for reproducibility and for detecting data poisoning attacks.

**Mapping:**

- **SPDX v3.x:**
  - `Package.verifiedUsing[].hash`

- **CycloneDX:**
  - `component.hashes[]`

**Final Conclusion — Dataset Hash:**
> **Cryptographic hash of the dataset file. Enables integrity verification and reproducibility.**

---

### 38. Dataset Provenance

**Official Definition:**
> "Element used to track dataset provenance."
> — Element used to capture information regarding: the origin (sources or organizations contributing to the dataset elements), the data collection methods (e.g., web crawling or commercial agreements), the data post processing steps, the data preprocessing/curation steps, and the data labelling steps; the creator; in case of synthetic data, the methods used to create it.

**Motive:**
Dataset provenance is critical for bias assessment, privacy compliance, and quality evaluation. A dataset scraped from the web without consent has very different legal implications than one purchased under a commercial agreement. Synthetic data creation methods affect model reliability.

**Mapping:**

- **SPDX v3.x:**
  - `DatasetPackage.dataCollectionProcess`
  - `DatasetPackage.datasetUpdateMechanism`

- **CycloneDX:**
  - `component.pedigree` — ancestors, descendants, variants
  - Custom `properties`

> **Note — To confirm with SPDX/CDX community:** The G7 element covers a rich set of provenance details: origin, collection methods, preprocessing/curation steps, labeling, and synthetic data creation. SPDX 3.x `DatasetPackage.dataCollectionProcess` and `datasetUpdateMechanism` are defined in the Dataset Profile but may not cover all G7 examples (e.g., labeling steps, synthetic data methods). CycloneDX `component.pedigree` is designed for software lineage (ancestors, descendants), not dataset provenance. Whether these fields are sufficient or require custom properties/extensions should be confirmed with both communities.

**Final Conclusion — Dataset Provenance:**
> **Tracks dataset origin, collection methods, preprocessing, curation, labeling, and synthetic data creation methods.**

---

### 39. Dataset Statistical Properties

**Official Definition:**
> "Element used to capture statistical characteristics associated with the dataset throughout its lifecycle."
> — Example: statistical metrics, when relevant, of the dataset (e.g., mean, variance, median, mode, range, skewness).

**Motive:**
Statistical properties enable bias assessment and quality evaluation. A dataset with 89% cars and 11% motorcycles will produce a biased traffic detection model. Demographic breakdowns are essential for fairness assessment.

**Mapping:**

- **SPDX v3.x:**
  - Custom annotations (no native field)

- **CycloneDX:**
  - Custom `properties`

> **Note — To confirm with SPDX/CDX community:** The G7 element captures statistical metrics (mean, variance, median, mode, range, skewness) for bias assessment and quality evaluation. Neither SPDX 3.x nor CycloneDX has a native structured field for dataset statistics. Custom properties or annotations are the only current mechanism, but they lack standardization for statistical representation. Whether a structured extension or property namespace is needed should be confirmed with both communities.

**Final Conclusion — Dataset Statistical Properties:**
> **Statistical metrics of the dataset: size, distribution, demographic breakdown. No native field in most formats; use custom properties.**

---

### 40. Dataset Sensitivity

**Official Definition:**
> "Element used to express the type of data present inside the dataset, where type is related to the sensitivity level of the data."
> — This element covers whether the dataset includes PII data, freely accessible data, copyright protected data, sensitive data (like financial or medical records) or national security related data.

**Motive:**
Dataset sensitivity drives privacy and security requirements. A dataset containing PII or medical records requires GDPR/HIPAA compliance. Copyright-protected data affects licensing. National security data has access control requirements.

**Mapping:**

- **SPDX v3.x:**
  - `DatasetPackage.hasSensitivePersonalInformation` (PresenceType: yes/no)
  - `DatasetPackage.confidentialityLevel` (TLP-style: clear/green/amber/red)

- **CycloneDX:**
  - Custom `properties`

> **Note — To confirm with SPDX/CDX community:** The G7 element covers a broad range of sensitivity types: PII, freely accessible data, copyright-protected data, sensitive data (financial/medical), and national security data. SPDX 3.x `DatasetPackage.hasSensitivePersonalInformation` is a binary yes/no, and `confidentialityLevel` uses a TLP-style scale (clear/green/amber/red) — neither fully captures copyright-protected or national security classifications. CycloneDX has no native dataset sensitivity field. Whether these fields are sufficient or require custom properties/extensions should be confirmed with both communities.

**Final Conclusion — Dataset Sensitivity:**
> **Indicates sensitivity level: PII, freely accessible, copyright-protected, sensitive (financial/medical), or national security. SPDX 3.0 uses confidentialityLevel and hasSensitivePersonalInformation.**

---

### 41. Dataset Dependency Relationship

**Official Definition:**
> "List of software used to create, modify and maintain the dataset during its lifecycle. The dependency relationship should reflect how a given dataset may be largely derived from another dataset."
> — Examples: management of datasets, labeling tools, filtering tools.

**Motive:**
Dataset dependencies include the tools used to create, label, filter, and maintain the dataset. If a labeling tool has a known bias, the dataset may inherit that bias. Derivation relationships ("derived from WebText") enable lineage tracking.

**Mapping:**

- **SPDX v3.x:**
  - `relationships[]` with appropriate relationship types

- **CycloneDX:**
  - `dependencies[]`

> **Note — To confirm with SPDX/CDX community:** The G7 element covers two distinct concepts: (1) software tools used to create/maintain the dataset (labeling tools, filtering tools), and (2) derivation relationships from other datasets ("derived from WebText"). Standard SBOM dependency relationships (`relationships[]`, `dependencies[]`) are designed for software inclusion/derivation, but dataset-to-dataset derivation semantics and tool-to-dataset relationship types are not well-defined. Whether existing relationship types suffice or new types are needed should be confirmed with both communities.

**Final Conclusion — Dataset Dependency Relationship:**
> **Software tools used to create/maintain the dataset and derivation relationships from other datasets.**

---

### 42. Dataset License

**Official Definition:**
> "This element describes the license type of the datasets."
> — Example: link/URL to the dataset licensing document.

**Motive:**
Dataset licenses govern whether the data can be used for commercial model training. A dataset with a non-commercial license cannot be used to train a product model. Understanding dataset licensing is essential for legal compliance.

**Mapping:**

- **SPDX v3.x:**
  - `Package.declaredLicense`

- **CycloneDX:**
  - `component.licenses[]` (for type="data")

**Final Conclusion — Dataset License:**
> **The license governing the dataset. May be distinct from the model license.**

---

## Cluster 5: Infrastructure (2 Elements)

> **Official Cluster Definition:**
> "The Infrastructure cluster contains physical and virtual infrastructure that is critical to proper operation and support of the AI system. If existing, it also includes a link to a Hardware Bill of Materials (HBOM), to also cover specialized AI hardware."

---

### 43. Infrastructure Software

**Official Definition:**
> "This element lists dependencies to software components specifically required to deliver and run an AI system."
> — Examples: firmware; package managers; third party libraries; frameworks; runtime environments; tools used by the AI system.

**Motive:**
AI systems depend on a software stack: CUDA drivers, PyTorch, Python libraries, container runtimes. Each of these has its own vulnerabilities, licenses, and lifecycle. Documenting software dependencies enables vulnerability management and deployment planning.

**Mapping:**

- **SPDX v2.x:**
  - `packages[]` with types library/framework/application

- **SPDX v3.x:**
  - `Package.hasContainedElement` (software packages)

- **CycloneDX:**
  - `components[]` with type `library`, `framework`, `application`

> **Note — To confirm with SPDX/CDX community:** The G7 element lists software dependencies specifically required to deliver and run an AI system. While standard SBOM dependency mechanisms (`packages[]`, `components[]`, `hasContainedElement`) can capture software components, the distinction between "general dependencies" and "AI-system-specific infrastructure" is not natively represented. Whether a dedicated relationship type, component purpose field, or existing mechanisms best capture this AI-system-specific dependency scope should be confirmed with both communities.

**Final Conclusion — Infrastructure Software:**
> **All software dependencies required to deliver and run the AI system: firmware, libraries, frameworks, runtime environments, tools.**

---

### 44. Infrastructure Hardware

**Official Definition:**
> "This element links to an existing HBOM as dependencies, which contains the hardware components on which the AI system is deployed."
> — Example: link to an existing HBOM.

**Motive:**
AI systems run on specialized hardware: GPUs, TPUs, and accelerators. Hardware has its own vulnerabilities (e.g., microcode updates, side-channel attacks). Linking to an HBOM provides complete infrastructure transparency.

**Mapping:**

- **SPDX v3.x:**
  - `Package.hasContainedElement` (hardware)
  - HBOM reference via relationships

- **CycloneDX:**
  - `externalReferences[]` with type `bom` linking to HBOM

> **Note — To confirm with SPDX/CDX community:** The G7 element requires a link to a Hardware Bill of Materials (HBOM) for specialized AI hardware (GPUs, TPUs, accelerators). Neither SPDX 3.x nor CycloneDX has a native "link to HBOM" field. CycloneDX `externalReferences[type=bom]` and SPDX 3.x relationships/external references can be repurposed, but HBOM as a concept is not yet standardized in SBOM ecosystems. Whether a dedicated HBOM reference type or extension is needed should be confirmed with both communities.

**Final Conclusion — Infrastructure Hardware:**
> **Link to a Hardware Bill of Materials (HBOM) containing the hardware components on which the AI system is deployed.**

---

## Cluster 6: Security Properties — SP (4 Elements)

> **Official Cluster Definition:**
> "The SP cluster focuses on the cybersecurity measures that apply to AI models and systems."

---

### 45. Security Controls

**Official Definition:**
> "This element describes the implemented AI specific and general cybersecurity controls. The element may also include a link to a specific framework or guideline used as reference for the implementation."
> — Technical controls implemented, such as: **General cybersecurity controls**: encryption; data minimization; differential privacy techniques; access controls; API authentication; input/output anomaly detection systems and filters; physical controls; technical controls; system-level controls (role-based access); administrative measures; link/references to specific applied security guidelines. **AI specific controls**: adversarial robustness training; prompt injection controls and tools for LLMs or LLM-based agents; input/output filters; data-level controls (to curate training data).

**Motive:**
Security controls describe what defenses are in place. An LLM without input filtering is vulnerable to prompt injection. A model without adversarial training is vulnerable to evasion attacks. Documenting controls enables consumers to assess risk and compare systems.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.safetyRiskAssessment`
  - Custom annotations

- **CycloneDX:**
  - `modelCard.considerations.technicalLimitations[]`
  - `modelCard.considerations.ethicalConsiderations[]`
  - Custom `properties`

> **Note — To confirm with SPDX/CDX community:** The G7 element covers a comprehensive set of security controls: general controls (encryption, data minimization, differential privacy, access controls, API authentication, anomaly detection) and AI-specific controls (adversarial robustness training, prompt injection controls, input/output filters, data-level controls). SPDX 3.x `AIPackage.safetyRiskAssessment` focuses on safety risk, not security controls. CycloneDX `modelCard.considerations` is designed for model limitations and ethics, not security controls. Whether these fields can adequately represent the full G7 security controls taxonomy should be confirmed with both communities.

**Final Conclusion — Security Controls:**
> **Describes implemented cybersecurity controls: encryption, differential privacy, access controls, adversarial robustness training, prompt injection controls, input/output filters.**

---

### 46. Security Compliance

**Official Definition:**
> "This element describes the cybersecurity standards and certifications related to the AI model/system, if obtained by the producer."
> — The element can include cybersecurity certification schemes, standards or frameworks to which the AI model/system is compliant.

**Motive:**
Security compliance demonstrates that the system has been evaluated against recognized standards. SOC 2, ISO 27001, and NIST AI RMF provide third-party validation of security posture. This is valuable for procurement and regulatory compliance.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.standardCompliance`

- **CycloneDX:**
  - `modelCard.considerations.ethicalConsiderations[]`
  - Custom `properties`

> **Note — To confirm with SPDX/CDX community:** The G7 element covers cybersecurity standards and certifications (SOC 2, ISO 27001, NIST AI RMF, etc.). SPDX 3.x `AIPackage.standardCompliance` is explicitly defined in the AI Profile and maps well. CycloneDX `modelCard.considerations.ethicalConsiderations` is focused on ethical considerations, not security certifications. Whether CycloneDX needs a dedicated security compliance field or custom properties suffice should be confirmed with the CycloneDX community.

**Final Conclusion — Security Compliance:**
> **Cybersecurity standards and certifications obtained: SOC 2, ISO 27001, NIST AI RMF, etc.**

---

### 47. Cybersecurity Policy Information

**Official Definition:**> "This element provides a link/URL to documentation regarding the AI model/system producer's published security.txt file."
> — This element can contain a static link/URL to the security repository of the system provider of the AI model.

**Motive:**
The security.txt file (per RFC 9116) tells security researchers where to report vulnerabilities. Without it, researchers may disclose vulnerabilities publicly instead of following responsible disclosure. This is critical for maintaining system security over time.

**Mapping:**

- **SPDX v3.x:**
  - `Package.primaryPurpose` or external references

- **CycloneDX:**
  - `externalReferences[]` with type `support` or custom

> **Note — To confirm with SPDX/CDX community:** The G7 element provides a link to the producer's `security.txt` file (per RFC 9116) or security repository. While `externalReferences` (CycloneDX) and `externalRef` (SPDX 3.x) can link to such resources, there is no standardized reference type for `security.txt` in either format. Whether a dedicated reference type (e.g., `security`) should be introduced or existing types (`support`, `other`) suffice should be confirmed with both communities.

**Final Conclusion — Cybersecurity Policy Information:**
> **Link to the producer's security.txt file or security repository for vulnerability reporting.**

---

### 48. Vulnerability Referencing

**Official Definition:**> "This element links to databases/repositories that provide exploitability of known vulnerabilities in the AI model/system. This is to help users decide whether to deploy a model in specific contexts where there is known risk."

**Motive:**
Vulnerability referencing links to CVE databases and AI-specific vulnerability repositories. A model with a known weights-poisoning vulnerability should not be deployed in high-security contexts without mitigation.

**Mapping:**

- **SPDX v2.x:**
  - `vulnerabilities[]`

- **SPDX v3.x:**
  - `Vulnerability` class or external references

- **CycloneDX:**
  - `vulnerabilities[]` or external vulnerability databases

> **Note — To confirm with SPDX/CDX community:** The G7 element links to databases providing exploitability information for AI-specific vulnerabilities. Standard SBOM vulnerability mechanisms (`vulnerabilities[]`, `Vulnerability` class) are designed for software CVEs. AI-specific vulnerabilities (e.g., weights poisoning, adversarial examples, prompt injection) may not fit traditional CVE models. Whether existing vulnerability fields are sufficient for AI-specific exploitability data or whether AI vulnerability databases require new representation should be confirmed with both communities.

**Final Conclusion — Vulnerability Referencing:**
> **Links to vulnerability databases/repositories providing exploitability information for known vulnerabilities.**

---

## Cluster 7: Key Performance Indicators — KPI (2 Elements)

> **Official Cluster Definition:**
> "The KPI cluster contains elements that refer to information on the AI system's KPIs and its components (including AI models that are integrated in the system), focusing on their lifecycle phases."

---

### 49. Security Metrics

**Official Definition:**> "Metrics to evaluate the security characteristics of the AI models integrated in the AI system or the system itself."
> — Example: security related benchmarks and metrics, e.g., robustness (resilience against third-party manipulation).

**Motive:**
Security metrics measure how well the model resists attacks. Adversarial robustness (performance under perturbation), fairness metrics (demographic parity), and bias scores all indicate whether the model is safe to deploy.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.metric` (DictionaryEntry)
  - `AIPackage.metricDecisionThreshold`

- **CycloneDX:**
  - `modelCard.quantitativeAnalysis.performanceMetrics[]`
    - `type`: "adversarial_robustness", "fairness"
    - `value`: numeric score

> **Note — To confirm with SPDX/CDX community:** The G7 element captures security metrics (adversarial robustness, resilience against manipulation). SPDX 3.x `AIPackage.metric` as a `DictionaryEntry` provides flexibility but lacks standardization for security metric keys. CycloneDX `performanceMetrics[]` is designed for model performance, not specifically security benchmarks. Whether standardized metric keys or a dedicated security metrics structure are needed should be confirmed with both communities.

**Final Conclusion — Security Metrics:**
> **Security-related benchmarks: adversarial robustness, fairness metrics, bias scores. CycloneDX via performanceMetrics. SPDX 3.0 via metric dictionary.**

---

### 50. Operational Performance KPIs

**Official Definition:**> "KPIs related to the operational condition or other threat indicators of the AI system."
> — Examples: system uptime, incident resolution time, system latency, request throughput, and load balancing.

**Motive:**
Operational KPIs measure system health. A model with 99.9% uptime and 45ms latency performs very differently than one with 95% uptime and 500ms latency. These metrics help consumers evaluate whether the system meets their operational requirements.

**Mapping:**

- **SPDX v3.x:**
  - `AIPackage.metric` (DictionaryEntry)

- **CycloneDX:**
  - Custom `properties`
  - `modelCard.quantitativeAnalysis.performanceMetrics[]`

> **Note — To confirm with SPDX/CDX community:** The G7 element captures operational KPIs (uptime, latency, throughput, load balancing, incident resolution time). These are runtime/operational metrics, distinct from model performance metrics. Neither SPDX 3.x nor CycloneDX has a native field for operational system metrics. SPDX 3.x `AIPackage.metric` (DictionaryEntry) and CycloneDX `performanceMetrics` are designed for model performance, not system operations. Whether a dedicated operational metrics extension or standardized custom properties are needed should be confirmed with both communities.

**Final Conclusion — Operational Performance KPIs:**
> **Operational metrics: uptime, latency, throughput, incident resolution time. No native field in most formats; use performanceMetrics or custom properties.**

---

## Complete Summary Table

| # | G7 Field | Cluster | CycloneDX | SPDX v2.x | SPDX v3.x | Notes |
|---|----------|---------|-----------|-----------|-----------|-------|
| 1 | `sbom_author` | Metadata | `metadata.authors[].name` | `creationInfo.creators[]` | `creationInfo.createdBy` | Distinct from Producer |
| 2 | `sbom_version` | Metadata | `version` | N/A | N/A | No native SPDX SBOM version |
| 3 | `sbom_data_format_name` | Metadata | `bomFormat` | `spdxVersion` prefix | Implicit | "CycloneDX" or "SPDX" |
| 4 | `sbom_data_format_version` | Metadata | `specVersion` | `spdxVersion` | `spdxVersion` | e.g., "1.7", "SPDX-3.0.1" |
| 5 | `sbom_author_signature` | Metadata | `signature` (JSF) | Detached CLI flags | `verifiedUsing` (Signature) | sbomqs detects all |
| 6 | `sbom_tool_name` | Metadata | `metadata.tools.components[].name` | `creationInfo.creators[].Tool` | `createdUsing` → `Tool.name` | Full names, not acronyms |
| 7 | `sbom_tool_version` | Metadata | `metadata.tools.components[].version` | Extracted from Tool | Extracted from Tool | |
| 8 | `sbom_generation_context` | Metadata | `metadata.lifecycles[].phase` | `creationInfo.comment` | `Software/Sbom.sbomType` | See Discussion #26 |
| 9 | `sbom_timestamp` | Metadata | `metadata.timestamp` | `creationInfo.created` | `creationInfo.created` | RFC 9557 |
| 10 | `sbom_dependency_relationship` | Metadata | `dependencies[]` | `relationships[]` | `relationships[]` | "includes"/"derived from" |
| 11 | `system_name` | SLP | `metadata.component.name` | `packages[].name` where `SPDXRef-DOCUMENT` → `DESCRIBES` → package | `Package.name` where `SpdxDocument` → `describes` → package | Human-readable; **primary component** |
| 12 | `system_components` | SLP | `components[]` (all types) | `packages[]` | `Package` / `AIPackage` / `DatasetPackage` in `@graph` | Constituent parts of the system; its dependencies |
| 13 | `system_producer` | SLP | `metadata.component.manufacturer.name` | `packages[].originator` of DESCRIBES package | `Package.originatedBy` of described package | Distinct from author; **system is primary component** |
| 14 | `system_version` | SLP | `metadata.component.version` | `packages[].versionInfo` of DESCRIBES package | `Package.packageVersion` of described package | **System is primary component** |
| 15 | `system_timestamp` | SLP | Custom `properties` | N/A | N/A | System update time |
| 16 | `system_data_flow` | SLP | `externalReferences[]` (documentation) | `packages[].externalRefs[]` (other/documentation) | `Package.externalRef` (documentation/other) | Link to data flow docs |
| 17 | `system_data_usage` | SLP | Custom `properties` | Custom annotations | Custom annotations | No native field |
| 18 | `system_input_output_properties` | SLP | `modelCard.modelParameters.inputs/outputs` | N/A | `AIPackage.informationAboutApplication` | Data types, modality |
| 19 | `intended_application_area` | SLP | `modelCard.considerations.useCases` | N/A | `AIPackage.domain` | Medical, finance, etc. |
| 20 | `model_name` | Models | `component.name` (type: `machine-learning-model`) | `packages[].name` — **no model type in SPDX 2.x** | `AIPackage.name` (`@type: "AIPackage"`) | Human-readable; see Discussion #7 |
| 21 | `model_identifier` | Models | `component.purl`, `bom-ref` | `externalRefs[]` | `externalIdentifier` | PURL, CPE, SWHID |
| 22 | `model_version` | Models | `component.version` | `packages[].versionInfo` | `Package.packageVersion` | |
| 23 | `model_timestamp` | Models | `releaseNotes.timestamp` | N/A | `Package.releaseTime` | Required for AIPackage; see Discussion #8 |
| 24 | `model_producer` | Models | `component.manufacturer.name` or `component.manufacturer.email` | `packages[].originator` | `Package.originatedBy` | Name or email; required for AIPackage |
| 25 | `model_description` | Models | `component.description` | `packages[].description` | `AIPackage.limitation` | Capabilities, lineage |
| 26 | `model_hash_value` | Models | `component.hashes[].content` | `checksums[].checksumValue` | `verifiedUsing[].hash.hashValue` | |
| 27 | `model_hash_algorithm` | Models | `component.hashes[].alg` | `checksums[].algorithm` | `verifiedUsing[].hash.algorithm` | IANA names |
| 28 | `model_properties` | Models | `modelCard.modelParameters` | N/A | `AIPackage.typeOfModel`, `hyperparameter` | See Discussion #9 |
| 29 | `model_input_output_properties` | Models | `modelCard.modelParameters.inputs/outputs` | N/A | `AIPackage.informationAboutApplication` | See Discussion #10 |
| 30 | `model_training_properties` | Models | `modelCard.modelParameters.approach.type` | N/A | `AIPackage.informationAboutTraining` | See Discussion #11 |
| 31 | `model_license` | Models | `component.licenses[]` | `packages[].licenseDeclared` | `Package.declaredLicense` | |
| 32 | `model_external_references` | Models | `component.externalReferences[]` | `packages[].externalRefs[]` | `Package.externalReference` | Model card, paper |
| 33 | `dataset_name` | Datasets | `component.name` (data) | N/A | `DatasetPackage.name` | See Discussion #12 |
| 34 | `dataset_description` | Datasets | `component.description` | N/A | `DatasetPackage.datasetAvailability` | See Discussion #13 |
| 35 | `dataset_content` | Datasets | `data[].contents.url` | N/A | `DatasetPackage.contentIdentifier` | See Discussion #14 |
| 36 | `dataset_identifier` | Datasets | `component.purl`, `bom-ref` | N/A | `Package.spdxId`, `externalIdentifier` | URL, URI |
| 37 | `dataset_hash` | Datasets | `component.hashes[]` | N/A | `Package.verifiedUsing[].hash` | |
| 38 | `dataset_provenance` | Datasets | `component.pedigree` | N/A | `DatasetPackage.dataCollectionProcess` | See Discussion #15 |
| 39 | `dataset_statistical_properties` | Datasets | Custom `properties` | N/A | Custom annotations | See Discussion #16 |
| 40 | `dataset_sensitivity` | Datasets | Custom `properties` | N/A | `DatasetPackage.hasSensitivePersonalInformation` | See Discussion #17 |
| 41 | `dataset_dependency_relationship` | Datasets | `dependencies[]` | N/A | `relationships[]` | See Discussion #18 |
| 42 | `dataset_license` | Datasets | `component.licenses[]` | N/A | `Package.declaredLicense` | |
| 43 | `infrastructure_software` | Infrastructure | `components[]` (library/framework) | `packages[]` | `Package.hasContainedElement` | Dependencies |
| 44 | `infrastructure_hardware` | Infrastructure | `externalReferences[]` (type: bom) | N/A | HBOM reference | See Discussion #19 |
| 45 | `security_controls` | Security | `modelCard.considerations` | N/A | `AIPackage.safetyRiskAssessment` | See Discussion #20 |
| 46 | `security_compliance` | Security | Custom `properties` | N/A | `AIPackage.standardCompliance` | See Discussion #21 |
| 47 | `cybersecurity_policy_information` | Security | `externalReferences[]` (support) | N/A | External references | See Discussion #22 |
| 48 | `vulnerability_referencing` | Security | `vulnerabilities[]` | `vulnerabilities[]` | `Vulnerability` class | See Discussion #23 |
| 49 | `security_metrics` | KPI | `modelCard.quantitativeAnalysis.performanceMetrics` | N/A | `AIPackage.metric` | See Discussion #24 |
| 50 | `operational_performance_kpis` | KPI | Custom `properties` | N/A | `AIPackage.metric` | See Discussion #25 |

---

## Key Differences: CycloneDX vs SPDX 3.0

| Aspect | CycloneDX ML-BOM | SPDX 3.0 AI/Dataset Profiles |
|--------|------------------|------------------------------|
| **Format maturity** | Stable (v1.5+), rich ecosystem | Stable (v3.0.1), newer ecosystem |
| **Model representation** | `type: "machine-learning-model"` component | `AIPackage` class |
| **Dataset representation** | `type: "data"` component | `DatasetPackage` class |
| **Model metadata** | Nested `modelCard` object | Direct properties on `AIPackage` |
| **Training approach** | `modelCard.modelParameters.approach.type` | `typeOfModel` |
| **Architecture** | `modelCard.modelParameters.architectureFamily` | `hyperparameter` dictionary |
| **Benchmarks/KPIs** | `modelCard.quantitativeAnalysis.performanceMetrics[]` | `metric` + `metricDecisionThreshold` dictionaries |
| **Security/safety** | `modelCard.considerations` | `safetyRiskAssessment`, `standardCompliance`, `limitation` |
| **Lineage** | `pedigree.ancestors[]` / `pedigree.descendants[]` | `Relationship` with `derivedFrom` |
| **Custom properties** | `component.properties[]` with reserved namespaces | `Annotation` elements or `extension` |
| **Serialization** | Traditional nested JSON | JSON-LD (`@id`, `@type`, `@graph`) |
| **Parser complexity** | Lower | Higher — requires graph traversal |
| **Required model fields** | `type`, `bom-ref`, `name` | `name`, `packageVersion`, `suppliedBy`, `downloadLocation`, `releaseTime`, `primaryPurpose` |

---

## Sources

All official definitions are quoted from:

> **G7 Cybersecurity Working Group.** *Software Bill of Materials (SBOM) for AI — Minimum Elements.* May 12, 2026.
>
> Available from:
> - [BSI (Germany)](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.pdf)
> - [CISA (United States)](https://www.cisa.gov/resources-tools/resources/software-bill-materials-ai-minimum-elements)
> - [ACN (Italy)](https://www.acn.gov.it/portale/documents/d/guest/g7-sbom-for-ai-miminum-elements_12-may-2026)

Additional references:
- [OWASP CycloneDX Authoritative Guide to AI/ML-BOM](https://www.cyclonedx.org/guide/OWASP_CycloneDX-Authoritative-Guide-to-AI-ML-BOM-en.pdf)
- [SPDX 3.0.1 Specification](https://spdx.github.io/spdx-spec/v3.0.1/)
- [SPDX AI Working Group Profiles](https://spdxai.github.io/profiles/)
