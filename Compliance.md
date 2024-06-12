# Compliance Reports

sbomqs now helps generating compliance reports for your SBOMs. We support industry standard requirements
like NTIA minimum elements, BSI TR-03183-2 v1.1 and OWASP SCVS.

The goal of compliance reports is to verify if the sbom file adheres to these standard, before they are distributed.

We have explained below how sbomqs approaches compliance reports for BSI TR-03183-2 v1.1. We are not going to explain
this technical guideline here, but rather go into our intepretation of it.

## TR-03183: SBOM Requirements for CRA

The [BSI TR-03183-2 v1.1](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.pdf) specifies mandatory properties for an SBOM. Below is how we have derived all the values.

| TR-03183-2 | TR-03183-2 field | CycloneDx | SPDX(2.3) | Notes |
| :---     | :---    |     :---      |          :--- | :--- |
|4. SBOM formats| `specification`  | BomFormat     | SPDXversion    | CycloneDX and SPDX only |
|| `specification version`  | SpecVersion     | SPDXversion    | CycloneDX 1.4 and above, SPDX 2.3 and above |
|5.1 Level of Detail| `Build SBOM`     | metadata->lifecycles (1.5 and above)       |  no-deterministic-field      | |
|| `Depth`   | dependencies, compositions     | relationships    | A complex topic, mostly resolved via attestations via compositions, but spdx lacks that field now|
|5.2.1 Required SBOM fields| `creator` | metadata->authors, metadata->supplier | creator | We are primarily looking for email or url from these fields, if the name exists but email/url missing its deemed non-compliant|
|    | | metadata->manufacturer | | |
|| `timestamp`| metadata->timestamp| created |  |
|5.2.2 Required Component fields| `creator` | component->supplier | packageSupplier, packageOriginator | Looking for email or url, for spdx, we check supplier then originatior(manufacturer)|
|| `name` | component->name| package->name| |
|| `version` | component->version| package->version| |
|| `dependencies` | dependencies, compositions| relationships| cdx we look for attestations via compositions, spdx nothing exists|
|| `license`| component->license| packageConcluded, packageDeclated| we lookup sdpx,spdx-exceptions,aboutcode, and licenseRef-|
|| `hash` | component->hashes | package->checksums | we only look for sha-256|
|5.3.1 Additional SBOM fields | `SBOM-URI`| serialNumber, version | namespace | for cdx bom-link is considered a URN |
| 5.3.2 Additional Component fields| `source code uri`| component->externalReferences->type (vcs) | no-deterministic-field | |
| | `URI of the executable form`| component->externalReferences->type (distribution/distribution-intake) | PackageDownloadLocation | |
| | `hash of source code`| no-deterministic-field | package->PackageVerificationCode | |
| | `other uniq identifiers`| component->cpe, component->purl| package->externalReference->security (cpe/purl) | |

## OpenChain Telco: SBOM Requirements for OCT

The [OpenChain Telco](https://github.com/OpenChain-Project/Reference-Material/blob/master/SBOM-Quality/Version-1/OpenChain-Telco-SBOM-Guide_EN.md) specifies mandatory properties for an SBOM. Below is how we have derived all the values.
| OpenTelco | Section ID | OpenTelco field | SPDX(2.3) | Notes |
| :---     | :---    | :---    |     :---      |          :--- |
| DataFormat |3.1 | `SBOM data format` | specs(SBOM_SPECS) | SPDX2.2 and SPDX2.3 only |
| SPDX elements | 3.2 | `SBOM info`  | SBOM type(SBOM_INFO)    | SPDX only |
| | 3.2.2 | `spec version field`  | SPDXVersion(SBOM_SPEC_VERSION) | SPDX 2.3 and above |
| | 3.2.3 | `SBOM license field` | DataLicense(SBOM_LICENSE) |  |
| | 3.2.4 | `spec identifier field`  | SPDXID(SBOM_SPDXID)   | |
| | 3.2.5 | `SBOM name field`| DocumentName(SBOM_NAME) |  |
| | 3.2.6 | `SBOM namespace field`| DocumentNamespace(SBOM_NAMESPACE) |  |
| | 3.2.7 | `SBOM Creator field`| creator(SBOM_CREATOR) | Tools and Organization must be present |
| | 3.2.8 | `SBOM Created field`| created(SBOM_TIMESTAMP) | Time at which document was created. |
| | 3.2.9 | `SBOM Creator comment field`| comment(SBOM_CREATOR_COMMENT) | Some comment from the document creators |
| | 3.2.10 | `Package Info` | package info(PACKAGE_INFO) | |
| | 3.2.11 | `Package name field` | PackageName(PACK_NAME) | |
| | 3.2.12 | `Package SPDX identifier field` | SPDXID(PACK_SPDXID) | |
| | 3.2.13 | `Package version field` | PackageVersion(PACK_VERSION) | |
| | 3.2.14 | `Package supplier field` | PackageSupplier(PACK_SUPPLIER) | |
| | 3.2.15 | `Package download location field` | PackageDownloadLocation(PACK_DOWNLOAD_URL) | |
| | 3.2.16 | `Files analyzed field` | FilesAnalyzed(FILE_ANALYZED) | |
| | 3.2.17 | `Package checksum field` | PackageChecksum(PACK_HASH) | we only look for sha-256 |
| | 3.2.18 | `Concluded license field`| PackageLicenseConcluded(PACK_LICENSE_CON) | |
| | 3.2.19 | `Declared license field`| PackageLicenseDeclared(PACK_LICENSE_DEC) | |
| | 3.2.20 | `Copyright text field` | PackageCopyrightText(PACK_COPYRIGHT) | |
| | 3.2.21 | `External reference field`| ExternalRef(EXTERNAL_REF) | |
| Machine Readable Data Format | 3.3 | `SBOM machine readable format` | specs(SBOM_FORMAT) | SPDX data-format in Tag-value or JSON |
| Human Readable Data Format | 3.4 | `SBOM human readable format` | SBOM file format(SBOM_FILE_FORMAT) | Tag:Value or JSON |
| SBOM Build Information | 3.5 | `SBOM Creator field` | SBOM creator(SBOM_CREATOR) | It must contain tool name, tool version and Organization |
| Timing of SBOM delivery | 3.6 | `SBOM delivery time` | delivery time(SBOM_DELIVERY_TIME) | |
| Method of SBOM delivery | 3.7 | `SBOM delivery method` | delivery method(SBOM_DELIVERY_METHOD) | |
| SBOM Scope | 3.8 | `SBOM scope` | sbom scope(SBOM_SCOPE) | |

