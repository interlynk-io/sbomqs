# SPDX:3.0 fields

## SBOM Fields

- SBOM specification: 
- SBOM Specification Version: `CreationInfo.specVersion`
- SBOM creator: `creationInfo.createdBy`
- SBOM timestamp: `creationInfo.created`
- SBOM Namespace: `externalIdentifier`

### Package Fields

- Package Name: `name`
- PackageSPDXID: `spdxId`
- PackageVersion: `packageVersion`
- PackageFileName: 
- Package Dependencies: 
- PackageChecksum: `verifiedUsing`
- PackageSourceCodeURI: `sourceURI`
- PackageSupplier: `suppliedBy`
- PackageDownloadLocation: `downloadLocation`
- FilesAnalyzed: (Removed from SPDX:3.0)
- PackageLicenseConcluded: 
- PackageLicenseDeclared
- PackageCopyrightText: `copyrightText`
- ExternalRef: `externalRef`

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

## References

- <https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes>
- <https://github.com/spdx/spdx-spec/blob/support/3.0/examples/jsonld/package_sbom.json>
- <https://github.com/spdx/using/blob/main/docs/diffs-from-previous-editions.md/>
- <https://docs.google.com/spreadsheets/d/1Xn6-BnDXRV0pLxLuj1-N_UvTGo6AUg4pSmX2UJ7VLbQ/edit?gid=0#gid=0>
- <https://github.com/spdx/spdx-3-model/>
- <https://youtu.be/foL8v1FMrrc?si=Z7gMuKI6o6xgEeJJ>
