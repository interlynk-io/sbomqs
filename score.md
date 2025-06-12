# Score command

`sbomqs` tool score the provided SBOM for the list of the features that compliance has in a summarized manner. Currently, we support NTIA-minimum-elements compliance only. But we are extending it's supports for BSI-V1 and BSI-V2 also.

Let's look at the score command o/ps for different compliances.

## NTIA Minimum Elements

```bash
$ sbomqs score -c NTIA-minimum-elements  samples/photon.spdx.json
```

o/p:

```bash
SBOM Quality by Interlynk Score:8.5	components:38	samples/photon.spdx.json
+-----------------------+-------------------------+-----------+--------------------------------+
|       CATEGORY        |         FEATURE         |   SCORE   |              DESC              |
+-----------------------+-------------------------+-----------+--------------------------------+
| NTIA-minimum-elements | comp_with_name          | 10.0/10.0 | 38/38 have names               |
+                       +-------------------------+-----------+--------------------------------+
|                       | comp_with_supplier      | 0.0/10.0  | 0/38 have supplier names       |
+                       +-------------------------+-----------+--------------------------------+
|                       | comp_with_uniq_ids      | 10.0/10.0 | 38/38 have unique ID's         |
+                       +-------------------------+-----------+--------------------------------+
|                       | comp_with_version       | 9.7/10.0  | 37/38 have versions            |
+                       +-------------------------+-----------+--------------------------------+
|                       | sbom_authors            | 10.0/10.0 | doc has 1 authors              |
+                       +-------------------------+-----------+--------------------------------+
|                       | sbom_creation_timestamp | 10.0/10.0 | doc has creation timestamp     |
|                       |                         |           | 2023-01-12T22:06:03Z           |
+                       +-------------------------+-----------+--------------------------------+
|                       | sbom_dependencies       | 10.0/10.0 | doc has 1 dependencies         |
+-----------------------+-------------------------+-----------+--------------------------------+
```

## BSI-V1.0.0

```bash
$ sbomqs score -c bsi-v1.0.0 sbom.json 
```

o/p would be:

```bash
SBOM Quality by Interlynk Score:7.1     components:279  sbom.json
+-----------------------+----------------------------+-----------+-------------------------------------------+
|       CATEGORY        |         FEATURE            |   SCORE   |                  DESC                     |
+-----------------------+----------------------------+-----------+-------------------------------------------+
|          BSI-V2       | spec_compliant             | 5.0/10.0  | SPDX/CycloneDX version exists, but format |
|                       |                            |           | usage is partially non-deterministic      |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | sbom_authors               | 10.0/10.0 | doc has 1 author with email or URL        |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | sbom_creation_timestamp    | 10.0/10.0 | doc has creation timestamp                |
|                       |                            |           | 2023-01-12T22:06:03Z                      |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | sbom_dependencies          | 0.0/10.0  | doc has 10 dependencies                   |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | sbom_with_uri              | 0.0/10.0  | doc has 1 namespace(spdx)  or             |
|                       |                            |           | doc has 1 bom-links(cdx)                  | 
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_name             | 10.0/10.0 | 279/279 have names                        |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_uniq_ids         | 10.0/10.0 | 279/279 have PURLs or CPEs                |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_version          | 10.0/10.0 | 279/279 have versions                     |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_supplier         | 10.0/10.0 | 27/279 have supplier names                |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_licenses         | 5.0/10.0  | 100/279 have license compliant            |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_hashes           | 7.5/10.0  | 200/279 have checksum values              |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_source_code_uri  | 0.0/10.0  | 0/279 have extRef of type vcs(cdx) or     |
|                       |                            |           | no-deterministic-field (spdx)             |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_executable_uri   | 0.0/10.0  | 0/279 have extRef of type distribution(cdx|
|                       |                            |           | 22/279 have comp download location(spdx)  |
+                       +----------------------------+-----------+-------------------------------------------+
|                       | comp_with_source_code_hash | 0.0/10.0  | no-deterministic-field for cdx            |
|                       |                            |           | 20/279 have package verification code(spdx|
+-----------------------+----------------------------+-----------+-------------------------------------------+
```

## BSI:v2.0.0

```bash
$ sbomqs score --category bsi-v2.0.0  samples/photon.spdx.json
```

o/p would be:

```bash
SBOM Quality by Interlynk Score:7.1     components:279  sbom.json
+-----------------------+------------------------------+-----------+-------------------------------------------+
|       CATEGORY        |         FEATURE              |   SCORE   |                  DESC                     |
+-----------------------+------------------------------+-----------+-------------------------------------------+
|          BSI-V2       | sbom_with_vuln               | 10.0/10.0 | doc has no vulnerability                  |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | spec_compliant               | 5.0/10.0  | SPDX/CycloneDX version exists, but format |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | sbom_build_process           | 0.0/10.0  | doc build process is build type           |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | sbom_authors                 | 10.0/10.0 | doc has 1 author with email or URL        |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | sbom_creation_timestamp      | 10.0/10.0 | doc has creation timestamp                |
|                       |                              |           | 2023-01-12T22:06:03Z                      |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | sbom_dependencies            | 0.0/10.0  | primary comp has 10 dependencies          |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | sbom_with_uri                | 0.0/10.0  | doc has 1 namespace(spdx)  or             |
|                       |                              |           | doc has 1 bom-links(cdx)                  | 
+                       +------------------------------+-----------+-------------------------------------------+
|                       | sbom_with_bomlinks           | 0.0/10.0  | doc has 1 namespace(spdx)  or             |
|                       |                              |           | doc has 1 bom-links(cdx)                  | 
+                       +------------------------------+-----------+-------------------------------------------+
|                       | sbom_signature               | 0.0/10.0  | doc has no signature                      |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_name               | 10.0/10.0 | 279/279 have names                        |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_uniq_ids           | 10.0/10.0 | 279/279 have PURLs or CPEs                |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_version            | 10.0/10.0 | 279/279 have versions                     |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_supplier           | 10.0/10.0 | 27/279 have supplier names                |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_associated_license | 5.0/10.0  | 100/279 have license compliant            |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_concluded_license  | 5.0/10.0  | 100/279 have license compliant            |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_declared_license   | 5.0/10.0  | 100/279 have license compliant            |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_dependencies       | 7.5/10.0  | 200/279 have at least 1 deps              |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_hashes             | 7.5/10.0  | 200/279 have checksum values              |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_source_code_uri    | 0.0/10.0  | 0/279 have extRef of type vcs(cdx) or     |
|                       |                              |           | no-deterministic-field (spdx)             |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_executable_hash    | 7.5/10.0  | 200/279 have executable checksum values   |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_executable_uri     | 0.0/10.0  | 0/279 have extRef of type distribution(cdx|
|                       |                              |           | 22/279 have comp download location(spdx)  |
+                       +------------------------------+-----------+-------------------------------------------+
|                       | comp_with_source_code_hash   | 0.0/10.0  | no-deterministic-field for cdx            |
|                       |                              |           | 20/279 have package verification code(spdx|
+-----------------------+------------------------------+-----------+-------------------------------------------+
```

## List of checks in all categories

This section is to bring all the checks or feature at one place for easy readability. It would helps us to understand all list of features in one go and also able to differentiate b/w them.
Below is the following list of checks or features for all categories:

| **Feature**                      | **Description**                                                              | **SPDX**                                                 | **CycloneDX**                                                     |
| -------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------- |
| `comp_with_licenses`             | Ensures components list at least one license                                 | `PackageLicenseDeclared: MIT`  or `PackageLicenseConcluded: Apache-2`                            | `components[].licenses: [{ license: { id: "MIT" } }]`             |
| `comp_with_associated_license`   | Confirms that an associated license is present for each component            | `PackageLicenseInfoFromFiles: GPL-2.0`                   | `licenses[].license.id: GPL-2.0`                                  |
| `comp_with_concluded_license`    | Ensures a concluded license has been determined per component                | `PackageLicenseConcluded: Apache-2.0`                    | `components[].licenses: [{ license: { id: "MIT", Acknowledgement: LicenseAcknowledgementConcluded } }]`                 |
| `comp_with_declared_license`     | Ensures declared license is specified explicitly for components              | `PackageLicenseDeclared: MIT`                            | `components[].licenses: [{ license: { id: "MIT", Acknowledgement: LicenseAcknowledgementDeclared } }]`             |
| `comp_with_checksums_sha256`     | Confirms that components include SHA-256 checksums                           | `PackageChecksum: SHA256: abc123...`                     | `components[].hashes: [{ alg: "SHA-256", content: "abc123..." }]` |
| `comp_with_checksums`            | Confirms components include any valid checksum                               | `PackageChecksum: SHA1/SHA256/...`                       | `components[].hashes: [...]`                                      |
| `comp_with_source_code_uri`      | Verifies that a component provides a source code URL                         | `NONE`            | `externalReferences: [{ type: "vcs", url: "..." }]`       |
| `comp_with_source_code_hash`     | Ensures hash is available for source code (often as part of SLSA, integrity) | `PackageVerificationCode: "....."`           | `externalReferences: [{ type: "vcs", url: "...", hashes: [...] }]`               |
| `comp_with_executable_uri`       | Ensures executable download URL is provided                                  | `PackageDownloadLocation: "..."` | `externalReferences: [{ type: "distribution-intake", url: "..." }]`      |
| `comp_with_executable_hash`      | Ensures executable hash (e.g., SHA-256) is present                           | `PackageChecksum: SHA256`                                | `externalReferences: [{ type: "distribution-intake", url: "...", hashes: [...] }]`                     |
| `sbom_with_uri`                  | Confirms that SBOM references its canonical URL                              | `Namespace`                          | `"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"`, `"version": 1,`                |
| `sbom_with_signature`            | Checks if the SBOM contains a cryptographic signature                        | externally provideed with `--sig` `--pub`                   | `declarations.Signatures[{algorithm: "...", value: "...", publicKey: [{kty: "...", n: "...", e: "..."}]}]`                          |
| `sbom_with_vuln`                 | Checks if known vulnerabilities are attached or referenced                   | `NONE`                              | `vulnerabilities[]` block                                         |
| `sbom_build_process`             | Describes how the SBOM was created (e.g., tooling, steps)                    | `NONE`                    | `metadata.lifecycles: {"build" }`            |
| `sbom_required_fields`           | Validates that the SBOM includes required baseline fields                    | SPDXVersion, DataLicense, SPDXID, etc.                   | Format, version, metadata timestamp, etc.                         |
| `sbom_with_creator_and_version`  | Ensures both creator identity and version info are available                 | `Creator: ToolX v1.2.3`                                  | `metadata.tools: { name: "ToolX", version: "1.2.3" }`             |
| `sbom_with_primary_component`    | Identifies the primary component the SBOM is describing                      | `PackageName: my-app` if `RelationshipType: DESCRIBE`                                    | `metadata.component.name: "my-app"`                               |
| `comp_with_primary_purpose`      | Verifies components state their intended role (e.g., library, application)   | Not available in SPDX                                    | `components[].type: "library"`                                    |
| `comp_valid_licenses`            | Ensures license identifiers are valid and conform to SPDX license list       | `License: MIT, Apache-2.0`                               | `licenses[].license.id: MIT, Apache-2.0`                          |
| `comp_with_deprecated_licenses`  | Flags use of licenses that are deprecated or discouraged                     | `License: GPL-1.0+`                                      | `licenses[].license.id: GPL-1.0+`                                 |
| `comp_with_restrictive_licenses` | Flags licenses with strong copyleft or legal obligations                     | `License: AGPL-3.0, CC-BY-NC-4.0`                        | `licenses[].license.id: AGPL-3.0`                                 |
| `comp_with_any_vuln_lookup_id`   | Ensures component has at least one vulnerability lookup ID like PURL/CPE     | `ExternalRef: PURL/CPE:...`                              | `purl`, `externalReferences`                                      |
| `comp_with_multi_vuln_lookup_id` | Confirms component has multiple IDs for better lookup coverage               | Both PURL and CPE listed                                 | `externalReferences: [ { type: "purl" }, { type: "cpe23Type" } ]` |
| `sbom_sharable`                  | Checks if SBOM has an explicit license for sharing                           | `DocumentLicense: CC0-1.0`                               | `metadata.licenses: [ { id: "CC0-1.0" } ]`                        |
