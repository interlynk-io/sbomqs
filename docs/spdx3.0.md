# SPDX:3.0 fields

- SBOM specification: @context

## SBOM document(type=SpdxDocument)

- SBOM SPDXID: `SpdxDocument.spdxId`
- SBOM name: `SpdxDocument.name`
- SBOM datalicense: `SpdxDocument.dataLicense`
- SBOM primary element: `SpdxDocument.rootElement`
- SBOM Specification Version: `CreationInfo.specVersion`
- SBOM creator:
  - Tool: `creationInfo.createdUsing`
  - Person: `creationInfo.createdBy`
- SBOM timestamp: `creationInfo.created`

<!-- - SBOM Namespace: `externalIdentifier` -->

## SBOM RootElement(type=software_Package)

RootElement is primary component of the SBOM.

- Package Name: `software_Package.name`
- Package Version: `software_Package.software_packageVersion`
- Package CopyRight: `software_Package.software_copyrightText`
- Package Supplier: `software_Package.suppliedBy`
  - `suppliedBy` is a `Agent`
- Package VerificationCode: `software_Package.verifiedUsing`
- Package licenseComments: `software_Package.comment`
- Package downloadLocation: `software_Package.software_downloadLocation`
- Package summary: `software_Package.summary`
- Package Homepage: `software_Package.software_homePage`
- Package originator: `software_Package.originatedBy`
  - `originatedBy` is a `Agent`
- Package License: `relationship`
  - Package license are refered as a relationship of types:
    - hasDeclaredLicense
    - hasConcludedLicense
- Package filesAnalyzed: This field has been removed
- Package externalRefs(referenceType=purl): `software_Package.software_packageUrl`
- Package Checksum: Checksum is seperated into Corresponding file for the package: `software_File.verifiedUsing`
  - and file is reference as a relationship with the corresponding package with a relationship type `hasDistributionArtifact` and `completeness` as `complete`.

## Relationship

- Package Relationship with License
  - relationshipType: `hasDeclaredLicense`
  - relationshipType: `hasConcludedLicense`
- Package Relationship with it's file with checksum
  - relationshipType: `hasDistributionArtifact`
- Package Relationship with other Package
  - relationshipType: `contains`
- SpdxDocument Relationship with Primary Component
  - relationshipType: `describes`
- Primary Component Relationship with it's elements


## Diff b/w 2.3 and 3.0

### SPDX 2.3 to 3.0 Structural Changes

- "SPDX" now means "System Package Data Exchange," expanding beyond software.
- `externalDocumentRef` replaced with `import` and `namespace` properties, using `NamespaceMap` and `ExternalMap` structures This enables independent element referencing.
- Document checksum replaced with `verifiedUsing` property on `ElementCollection`, using `IntegrityMethod` for checksums.
- `creator` replaced by `createdBy` and `createdUsing`, `supplier` by `suppliedBy`, all using structured `Agent` and `Tool` types.
- File handling changes:
  - `fileContributor` replaced by `originatedBy` on `Artifact`.
  - `FileType` replaced by `contentType` and `SoftwarePurpose`.
  - `packageFileName` and `packageChecksum` replaced by `hasDistributionArtifact` relationship.
- `externalIdentifier` and `contentIdentifier` properties introduced, separating identifiers and references.
- `Package URL` becomes a property of `Artifact` instead of an `ExternalRef` type.

- Annotations and relationships become subclasses of `Element`, gaining properties and independence.
- Snippet changes:
  - Range types change to `PositiveIntegerRange`, byte range optional.
  - `snippetFromFile` becomes a `CONTAINS` relationship.
- `SpecVersion` and `LicenseListVersion` become `SemVer` strings, enforcing Semantic Versioning.
- Serialization format changes:
  - JSON-LD format implemented.
  - Tag/Value, YAML, RDF/XML, and Spreadsheet formats no longer supported

## To write your first SPDX:3.0 SBOM:

- Follow this getting started material: <https://github.com/spdx/using/blob/main/docs/getting-started.md>

## References

- <https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes>
- <https://github.com/spdx/spdx-spec/blob/support/3.0/examples/jsonld/package_sbom.json>
- <https://github.com/spdx/using/blob/main/docs/diffs-from-previous-editions.md/>
- <https://docs.google.com/spreadsheets/d/1Xn6-BnDXRV0pLxLuj1-N_UvTGo6AUg4pSmX2UJ7VLbQ/edit?gid=0#gid=0>
- <https://github.com/spdx/spdx-3-model/>
- <https://youtu.be/foL8v1FMrrc?si=Z7gMuKI6o6xgEeJJ>
