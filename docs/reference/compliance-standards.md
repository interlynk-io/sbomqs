# Compliance Reports

`sbomqs` helps generating compliance reports for your SBOMs.  We support industry standard regulations/guidelines like NTIA minimum elements, BSI TR-03183-2 v1.1 & v2.0 and OpenChain Telco.  The goal of these compliance reports is to assess to which extent an SBOM file adheres to these standards, before it is distributed.

Our mapping of the various requirements to CycloneDX's and SPDX's SBOM format tags is documented below.

## TR-03183-2: Technical Guideline for SBOMs by BSI

TR-03183-2 by the German Federal Office for Information Security (BSI) follows a transitional system: To comply with BSI TR-03183-2, SBOMs must be generated using its most recent version, though the previous version is still allowed for six months after a new version was published, and SBOMs remain compliant indefinitely when based on a version of TR-03183-2 valid at their delivery date.

### [BSI TR-03183-2 v2.1.0](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.pdf)

- Released: August 20th 2025
- Contact: <TR03183@bsi.bund.de>

Key changes from v2.0.0:
- CycloneDX minimum version bumped from 1.5 to **1.6**
- SPDX minimum version bumped from 2.2.1 to **3.0.1** (SPDX v2 no longer allowed)
- Previously "Additional" fields are now **SHALL** (required): SBOM-URI, Source code URI, URI of deployable form, Other unique identifiers, Original licences
- New data fields: Filename, Executable property, Archive property, Structured property, Effective licence, URL of security.txt
- Digital signature removed from required (recommendation only)
- Vulnerability info: SBOM **MUST NOT** contain it

| TR-03183-2 Section | Data Field | Required | CycloneDX v1.6+ | SPDX v3.0.1 | SPDX v2 | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 5.2.1 SBOM Fields | Creator of the SBOM | SHALL | `metadata.manufacturer[].url` XOR `metadata.manufacturer[].contact[].email` | `CreationInfo.createdBy` | N/A | |
| | Timestamp | SHALL | `metadata.timestamp` | `CreationInfo.created` | N/A | |
| | SBOM-URI | SHALL | `serialNumber` (BOM-Link: `urn:cdx:{serialNumber}/{version}`) | `Sbom.spdxId` | N/A | Promoted from additional in v2.0 |
| 5.2.2 Component Fields | Component creator | SHALL | `components[].manufacturer[].url` XOR `components[].manufacturer[].contact[].email` | `Package.originatedBy` | N/A | |
| | Component name | SHALL | `components[].name` | `Package.name` | N/A | |
| | Component version | SHALL | `components[].version` | `Package.packageVersion` | N/A | |
| | Filename | SHALL | `components[].properties[].name="bsi:component:filename"` | `File.name` | N/A | New in v2.1 |
| | Dependencies | SHALL | `dependencies[]` + `compositions` | `Relationship.relationshipType=["contains" OR "dependsOn"]` | N/A | |
| | Distribution licences | SHALL | `components[].licenses[].expression` + `acknowledgement="concluded"` | `Relationship.relationshipType="hasConcludedLicense"` | N/A | Requires CDX 1.6+ acknowledgement field |
| | Hash of deployable component | SHALL | `components[].externalReferences[].hashes[]` with `type="distribution"` | `File.verifiedUsing` | N/A | Changed from component hash in v2.0 |
| | Executable property | SHALL | `components[].properties[].name="bsi:component:executable"` | `File.additionalPurpose=["executable"]` | N/A | New in v2.1 |
| | Archive property | SHALL | `components[].properties[].name="bsi:component:archive"` | `File.additionalPurpose=["archive"]` | N/A | New in v2.1 |
| | Structured property | SHALL | `components[].properties[].name="bsi:component:structured"` | `File.additionalPurpose=["container" OR "firmware"]` | N/A | New in v2.1 |
| | Source code URI | SHALL | `components[].externalReferences[].type="source-distribution"` | `SoftwareArtifact.externalRef.externalRefType="SourceArtifact"` | N/A | Promoted from additional in v2.0 |
| | URI of the deployable form | SHALL | `components[].externalReferences[].type="distribution"` + `.url` | `File.externalRef.externalRefType="binaryArtifact"` | N/A | Promoted from additional in v2.0 |
| | Other unique identifiers | SHALL | `components[].cpe` OR `components[].swid` OR `components[].purl` | `Package.externalIdentifiers` | N/A | Promoted from additional in v2.0 |
| | Original licences | SHALL | `components[].licenses[].expression` + `acknowledgement="declared"` | `Relationship.relationshipType="hasDeclaredLicense"` | N/A | New in v2.1 (SHALL) |
| 5.2.3 Optional Fields | Effective licence | MAY | `components[].properties[].name="bsi:component:effectiveLicense"` | `Relationship.relationshipType="other"` + `.comment="hasEffectiveLicense"` | N/A | New in v2.1 |
| | Hash of source code | MAY | `components[].externalReferences[].hashes[]` with `type="source-distribution"` | `SoftwareArtifact.verifiedUsing` | N/A | |
| | URL of the security.txt | MAY | `components[].externalReferences[].type="rfc-9116"` + `.url` | `Package.externalRef.externalRefType="securityOther"` | N/A | New in v2.1 |

> **Note:** SPDX v2 SBOMs scored against BSI v2.1.0 receive a hard fail on the format version check. All individual field checks return N/A. Full SPDX v3 support is required for complete v2.1.0 compliance.

---

### [BSI TR-03183-2 v2.0.0](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2-2_0_0.pdf)

- Released: September 20th 2024
- Contact: <TR03183@bsi.bund.de>

| TR-03183-2                                    | TR-03183-2 field             | CycloneDX                                                              | SPDX(2.2.1)                                                                | SPDX(3.0) | Notes                                                                                                                                         |
| :-------------------------------------------- | :--------------------------- | :--------------------------------------------------------------------- | :------------------------------------------------------------------------- | :-------- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| 3.1 Definition of SBOM                        | `vuln`                       | vulnerabilities                                                        | non-deterministic                                                          | TBD       | Presence of Vuln Info is non-compliant, for SPDX package->externalReference->comment could be used, but non-deterministic                      |
| 4. SBOM formats                               | `specification`              | BomFormat                                                              | SPDXversion                                                                | TBD       | CycloneDX and SPDX only                                                                                                                       |
|                                               | `specification version`      | SpecVersion                                                            | SPDXversion                                                                | TBD       | CycloneDX 1.5 and above, SPDX 2.2.1 and above                                                                                                 |
| 5.1 Level of Detail                           | `Build SBOM`                 | metadata->lifecycles                                                   | no-deterministic-field                                                     | TBD       |                                                                                                                                               |
| 5.2.1 Required SBOM fields                    | `creator`                    | metadata->(authors/supplier/manufacturer)                              | creator->(Person/Organization)                                             | TBD       | Email or url only, if the name exists but email/url missing its deemed non-compliant                                                          |
|                                               | `timestamp`                  | metadata->timestamp                                                    | created                                                                    | TBD       | Non conformant time format is deemed non-compliant                                                                                            |
| 5.2.2 Required Component fields               | `creator`                    | component(supplier/authors)                                            | packageSupplier, packageOriginator                                         | TBD       | Looking for email or url, for spdx, we check supplier then originator(manufacturer)                                                           |
|                                               | `name`                       | component->name                                                        | package->name                                                              | TBD       |                                                                                                                                               |
|                                               | `version`                    | component->version                                                     | package->version                                                           | TBD       |                                                                                                                                               |
|                                               | `filename`                   | component->type(file), name                                            | PackageFileName                                                            | TBD       | For CycloneDX properties could be used                                                                                                        |
|                                               | `dependencies`               | dependencies, compositions                                             | relationships                                                              | TBD       | If a component declares dependencies, they must exist in the SBOM. Leaf components are valid.                                                 |
|                                               | `associated license`         | component->license->Expression                                         | packageConcluded                                                           | TBD       | we lookup sdpx,spdx-exceptions,aboutcode, and licenseRef-                                                                                     |
|                                               | `hash`                       | component->hashes                                                      | package->checksums                                                         | TBD       | we only look for sha-256                                                                                                                      |
|                                               | `executable`                 |                                                                        |                                                                            | TBD       | Open to suggestions                                                                                                                           |
|                                               | `archive`                    |                                                                        |                                                                            | TBD       | Open to suggestions                                                                                                                           |
|                                               | `structured`                 |                                                                        |                                                                            | TBD       | Open to suggestions                                                                                                                           |
| 5.3.1 Additional SBOM fields                  | `SBOM-URI`                   | serialNumber, version                                                  | namespace                                                                  | TBD       | for cdx bom-link is considered a URN                                                                                                          |
| 5.3.2 Additional Component fields             | `source code uri`            | component->externalReferences->type (vcs)                              | no-deterministic-field                                                     | TBD       |                                                                                                                                               |
|                                               | `URI of the executable form` | component->externalReferences->type (distribution/distribution-intake) | PackageDownloadLocation                                                    | TBD       |                                                                                                                                               |
|                                               | `hash of source code`        | no-deterministic-field                                                 | package->PackageVerificationCode                                           | TBD       |                                                                                                                                               |
|                                               | `other uniq identifiers`     | component->cpe, component->purl                                        | externalReference->security->cpe, externalReference->package_manager->purl | TBD       |                                                                                                                                               |
|                                               | `concluded licenses`         | license->acknowlegement(1.6+)                                          | PackagConcluded                                                            | TBD       | For cyclonedx only 1.6+ spec, it can be determined.                                                                                           |
| 5.4.1 Optional data fields for each component | `Declared licences`          | comp->license->acknowledgement(1.6+)                                   | PackageDeclared                                                            | TBD       | For cyclonedx only 1.6+ spec, it can be determined                                                                                            |
|                                               | `Sourcecode Hash`            | non-deterministic                                                      | packageVerificationCode                                                    | TBD       |                                                                                                                                               |
| 8.1.11 Optional Digital Signature             | `signature`                  | signature                                                              | non-deterministic                                                          | TBD       | DPX would normally provide this externally to the SBOM                                                                                        |
| 8.1.12 Optional Bom Links                     | `bomlinks`                   | externalReference->Type(Bom)                                           | externalDocumentRefs                                                       | TBD       | SPDX if packages are prefixed with external Doc, those should be referenced. In both specs, sbomqs will check existence via url & localfile   |

---

### [BSI TR-03183-2 v1.1](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.pdf)

- Released: Nov 28th 2023
- Contact: <TR03183@bsi.bund.de>

| TR-03183-2                        | TR-03183-2 field             | CycloneDx                                                              | SPDX(2.3)                                       | Notes                                                                                                                          |
| :-------------------------------- | :--------------------------- | :--------------------------------------------------------------------- | :---------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| 4. SBOM formats                   | `specification`              | BomFormat                                                              | SPDXversion                                     | CycloneDX and SPDX only                                                                                                        |
|                                   | `specification version`      | SpecVersion                                                            | SPDXversion                                     | CycloneDX 1.4 and above, SPDX 2.3 and above                                                                                    |
| 5.1 Level of Detail               | `Build SBOM`                 | metadata->lifecycles (1.5 and above)                                   | no-deterministic-field                          |                                                                                                                                |
| 5.2.1 Required SBOM fields        | `creator`                    | metadata->authors, metadata->supplier                                  | creator                                         | We are primarily looking for email or url from these fields, if the name exists but email/url missing its deemed non-compliant |
|                                   |                              | metadata->manufacturer                                                 |                                                 |                                                                                                                                |
|                                   | `timestamp`                  | metadata->timestamp                                                    | created                                         |                                                                                                                                |
| 5.2.2 Required Component fields   | `creator`                    | component->supplier                                                    | packageSupplier, packageOriginator              | Looking for email or url, for spdx, we check supplier then originatior(manufacturer)                                           |
|                                   | `name`                       | component->name                                                        | package->name                                   |                                                                                                                                |
|                                   | `version`                    | component->version                                                     | package->version                                |                                                                                                                                |
|                                   | `dependencies`               | dependencies, compositions                                             | relationships                                       | if a component declares dependencies, they must exist in the SBOM. Leaf components are valid |
|                                   | `license`                    | component->license                                                     | packageConcluded, packageDeclated               | we lookup sdpx,spdx-exceptions,aboutcode, and licenseRef-                                                                      |
|                                   | `hash`                       | component->hashes                                                      | package->checksums                              | we only look for sha-256                                                                                                       |
| 5.3.1 Additional SBOM fields      | `SBOM-URI`                   | serialNumber, version                                                  | namespace                                       | for cdx bom-link is considered a URN                                                                                           |
| 5.3.2 Additional Component fields | `source code uri`            | component->externalReferences->type (vcs)                              | no-deterministic-field                          |                                                                                                                                |
|                                   | `URI of the executable form` | component->externalReferences->type (distribution/distribution-intake) | PackageDownloadLocation                         |                                                                                                                                |
|                                   | `hash of source code`        | no-deterministic-field                                                 | package->PackageVerificationCode                |                                                                                                                                |
|                                   | `other uniq identifiers`     | component->cpe, component->purl                                        | package->externalReference->security (cpe/purl) |                                                                                                                                |

## OpenChain Telco: SBOM Requirements

The [OpenChain Telco](https://github.com/OpenChain-Project/Reference-Material/blob/master/SBOM-Quality-Management/Telco-SBOM-Guide/Version-1.1/en/OpenChain-Telco-SBOM-Guide_EN.md) specifies mandatory properties for an SBOM. Below is how we have derived all the values.

- Released: May 22nd 2024
- Contact: <https://lists.openchainproject.org/g/telco>

| OpenTelco                    | Section ID | OpenTelco field                   | SPDX(2.3)               | Notes                                                    |
| :--------------------------- | :--------- | :-------------------------------- | :---------------------- | :------------------------------------------------------- |
| DataFormat                   | 3.1        | `SBOM data format`                | specs                   | SPDX2.2 and SPDX2.3 only                                 |
| SPDX elements                | 3.2        | `SBOM info`                       | SBOM type               | SPDX only                                                |
|                              | 3.2.2      | `spec version field`              | SPDXVersion             | SPDX 2.3 and above                                       |
|                              | 3.2.3      | `SBOM license field`              | DataLicense             |                                                          |
|                              | 3.2.4      | `spec identifier field`           | SPDXID                  |                                                          |
|                              | 3.2.5      | `SBOM name field`                 | DocumentName            |                                                          |
|                              | 3.2.6      | `SBOM namespace field`            | DocumentNamespace       |                                                          |
|                              | 3.2.7      | `SBOM Creator field`              | creator                 | Tools and Organization must be present                   |
|                              | 3.2.8      | `SBOM Created field`              | created                 | Time at which document was created.                      |
|                              | 3.2.9      | `SBOM Creator comment field`      | comment                 | Some comment from the document creators                  |
|                              | 3.2.10     | `Package Info`                    | package info            |                                                          |
|                              | 3.2.11     | `Package name field`              | PackageName             |                                                          |
|                              | 3.2.12     | `Package SPDX identifier field`   | SPDXID                  |                                                          |
|                              | 3.2.13     | `Package version field`           | PackageVersion          |                                                          |
|                              | 3.2.14     | `Package supplier field`          | PackageSupplier         |                                                          |
|                              | 3.2.15     | `Package download location field` | PackageDownloadLocation |                                                          |
|                              | 3.2.16     | `Files analyzed field`            | FilesAnalyzed           |                                                          |
|                              | 3.2.17     | `Package checksum field`          | PackageChecksum         | we only look for sha-256                                 |
|                              | 3.2.18     | `Concluded license field`         | PackageLicenseConcluded |                                                          |
|                              | 3.2.19     | `Declared license field`          | PackageLicenseDeclared  |                                                          |
|                              | 3.2.20     | `Copyright text field`            | PackageCopyrightText    |                                                          |
|                              | 3.2.21     | `External reference field`        | ExternalRef             |                                                          |
| Machine Readable Data Format | 3.3        | `SBOM machine readable format`    | specs                   | SPDX data-format in Tag-value or JSON                    |
| Human Readable Data Format   | 3.4        | `SBOM human readable format`      | SBOM file format        | Tag:Value or JSON                                        |
| SBOM Build Information       | 3.5        | `SBOM Creator field`              | SBOM creator            | It must contain tool name, tool version and Organization |
| Timing of SBOM delivery      | 3.6        | `SBOM delivery time`              | delivery time           |                                                          |
| Method of SBOM delivery      | 3.7        | `SBOM delivery method`            | delivery method         |                                                          |
| SBOM Scope                   | 3.8        | `SBOM scope`                      | sbom scope              |                                                          |

## NTIA minimum elements: SBOM Requirements for NTIA

The [NTIA](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) specifies mandatory properties for an SBOM. Below is how we have derived all the values.

- Released:
- Contact:

| NTIA minimum elements   | Section ID | NTIA Fields               | CycloneDX                             | SPDX(2.3)                                               | Notes                                                          |
| :---------------------- | :--------- | :------------------------ | :------------------------------------ | :------------------------------------------------------ | :------------------------------------------------------------- |
| Automation Support      | 1.1        | `Machine Readable Format` | BomFormat & data forrmat              | SPDXversion & data forrmat                              | optional                                                       |
| SBOM Data Fields        | 2.1        | `SBOM Authors`            | metadata->authors, metadata->supplier | creator->Person, creator->organization or creator->tool | Mandatory                                                      |
|                         | 2.2        | `SBOM Timestamp`          | metadata->timestamp                   | created                                                 | Mandatory                                                      |
|                         | 2.3        | `SBOM Dependencies`       | dependencies                          | relationships                                           | Only the primary component’s direct dependencies are evaluated |
| Package Data Fields     | 2.4        | `Component Name`          | component->name                       | package->name                                           | Mandatory                                                      |
|                         | 2.3        | `Component Dependencies`  | dependencies                          | relationships                                           | Optional (Component to component dependencies)                 |
|                         | 2.6        | `Component Supplier Name` | component->supplier                   | packageSupplier, packageOriginator                      | Mandatory                                                      |
|                         | 2.7        | `Component Version`       | component->version                    | package->version                                        | Mandatory                                                      |
|                         | 2.8        | `Component with Uniq IDs` | component->cpe, component->purl       | externalRef->cpe, externalRef->purl                     | Mandatory                                                      |
| Practices and Processes | 3.1        | `Depth`                   | dependencies, compositions            | relationships                                           | optional                                                       |
|                         | 3.2        | `Known Unknowns`          |                                       |                                                         | optional                                                       |
