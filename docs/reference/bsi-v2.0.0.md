##  BSI TR-03183:2.0.0

### 1. SBOM Required Element

| BSI Field          | Required | SPDX 2.3                | SPDX 3.0                 | CycloneDX 1.6                            |
| ------------------ | -------- | ----------------------- | ------------------------ | ---------------------------------------- |
| SBOM Creator       | YES      | `CreationInfo.creators` | `CreationInfo.createdBy` | `metadata.manufacturer` / `tools.vendor` |
| Creation Timestamp | YES      | `CreationInfo.created`  | `CreationInfo.created`   | `metadata.timestamp`                     |

### 2. Required Component Fields 
| #  | BSI Required Component Field | Description (BSI intent)                       | SPDX 2.3 Mapping                       | SPDX 3.0 Mapping                                           | CycloneDX 1.6 Mapping                          |

| -- | ---------------------------- | ---------------------------------------------- | -------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------- |
| 1  | **Component creator**        | Email or URL of component creator / maintainer | `PackageSupplier` OR `FileContributor` | `software_Package.suppliedBy` / `software_File.suppliedBy` | `component.manufacturer` OR `component.author` |
| 2  | **Component name**           | Creator-defined name, else filename            | `PackageName` / `FileName`             | `software_Package.name` / `software_File.name`             | `component.name`                               |
| 3  | **Component version**        | Version string, else creation date             | `PackageVersion`                       | `software_Package.version`                                 | `component.version`                            |
| 4  | **Filename**                 | Deployable filename (no path)                  | `FileName`                             | `software_File.name`                                       | `component.name` (file components)             |
| 5  | **Dependencies**             | Direct dependencies or containment             | `Relationship: DEPENDS_ON / CONTAINS`  | `dependsOn`                                                | `dependencies`                                 |
| 6  | **Associated licence(s)**    | Distribution / concluded licences              | `PackageLicenseConcluded`              | `hasConcludedLicense`                                      | `licenses[]` (`acknowledgement=concluded`)     |
| 7  | **Hash (SHA-512)**           | Cryptographic hash of deployable file          | `FileChecksum: SHA512`                 | `verifiedUsing.algorithm = SHA512`                         | `component.hashes[alg=SHA-512]`                |
| 8  | **Executable flag**          | Whether component is executable                | `FileType`                             | `software_File.fileType`                                   | `properties` (`bsi:component:executable`)      |
| 9  | **Archive flag**             | Whether component is an archive                | Relationships / file semantics         | `software_File.fileType`                                   | `properties` (`bsi:component:archive`)         |
| 10 | **Structured flag**          | Structured vs unstructured component           |  (no native field)                    | `additionalPurpose`                                        | `properties` (`bsi:component:structured`)      |


### 3. Additional SBOM Fields

| # | BSI Additional SBOM Field | Description (BSI intent)                       | SPDX 2.3 Mapping    | SPDX 3.0 Mapping   | CycloneDX 1.6 Mapping |
| - | ------------------------- | ---------------------------------------------- | ------------------- | ------------------ | --------------------- |
| 1 | **SBOM-URI**              | URI that uniquely identifies the SBOM document | `DocumentNamespace` | `software_Sbom.id` | `serialNumber`        |



### 4. Additional Component Fields

| # | BSI Additional Component Field | Description (BSI intent)                                       | SPDX 2.3 Mapping                         | SPDX 3.0 Mapping                    | CycloneDX 1.6 Mapping                          |
| - | ------------------------------ | -------------------------------------------------------------- | ---------------------------------------- | ----------------------------------- | ---------------------------------------------- |
| 1 | **Source code URI**            | URI to the component’s source code (repo or specific revision) | `PackageHomePage` OR `ExternalRef (SCM)` | `software_Package.sourceRepository` | `externalReferences[type=source-distribution]` |
| 2 | **Deployable component URI**   | Direct URI to download the deployable artifact                 | `ExternalRef (DOWNLOAD_LOCATION)`        | `software_Package.downloadLocation` | `externalReferences[type=distribution]`        |
| 3 | **Other unique identifiers**   | Additional identifiers such as **purl** or **CPE**             | `ExternalRef (purl / cpe23Type)`         | `externalIdentifier`                | `purl`, `cpe`                                  |
| 4 | **Concluded licences**         | Licence(s) concluded by the SBOM creator (licensee view)       | `PackageLicenseConcluded`                | `hasConcludedLicense`               | `licenses[] (acknowledgement=concluded)`       |

### 5. Optional data fields for each component
| # | BSI Optional Component Field | Description (BSI intent)                                                    | SPDX 2.3 Mapping             | SPDX 3.0 Mapping                  | CycloneDX 1.6 Mapping                                 |
| - | ---------------------------- | --------------------------------------------------------------------------- | ---------------------------- | --------------------------------- | ----------------------------------------------------- |
| 1 | **Declared licences**        | Licences declared by the *component creator / licensor*                     | `PackageLicenseDeclared`     | `hasDeclaredLicense`              | `licenses[]` (`acknowledgement=declared`)             |
| 2 | **Hash of the source code**  | Cryptographic hash of the component’s source code (algorithm not specified) | `FileChecksum` (SOURCE file) | `verifiedUsing` (source artifact) | `externalReferences[type=source-distribution].hashes` |
