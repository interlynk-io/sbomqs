<!--
 Copyright 2025 Interlynk.io
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
     http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

# SBOM Quality Checks

This page describes each SBOM Quality check in detail, including scoring criteria,
remediation steps, and an explanation of the potential impact associated with a low score.
The checks are continually changing, and we welcome community feedback.

If you have ideas for additions or new detection techniques,
please [contribute](https://github.com/interlynk-io/sbomqs#contributions)!

## Taxonomy

- A `Quality Check` is a test that can be performed on SBOM to return a binary result (e.g., A check for specification)
- A `Quality Check Category` is a logical grouping of Quality Checks (e.g., "NTIA-Minimum-Elements" Checks)
- A `Quality Check Set` is a collection of Quality Checks (e.g., "Default Check Set", "IoT Quality Set")

## Scoring Methodology

- Each Quality Check has an equal weight and a score range of 0.0 - 10.0. (Coming soon: Customization of weight per Quality Check)
- A Quality Check applied over a list of items (e.g., licenses) averages its score from the Check applied to each element.
- Quality Check Set Score is an average of scores over all Quality Checks in that Set.

## Check Set Versioning

Any Check Set, including the default Check Set, may change over time as new Checks are added, existing ones are removed and meaning of an existing one changes.
Such a breaking change is marked by incrementing `scoring_engine_version` in the output of `sbomqs`.

Therefore comparing Quality Scores across `scoring_engine_version` is not recommended.

## Quality Check Sets - Interlynk (Default)

### 1. Category: Structural

#### 1.1 Specification

This check determines whether the SBOM is in one of the specifications (CycloneDX, SPDX, SWID) recommended by the [CISA reference document](https://ntia.gov/sites/default/files/publications/ntia_sbom_framing_2nd_edition_20211021_0.pdf) .

CISA recommends limiting
the document to three commonly used formats to facilitate widespread adoption.

***Remediation***

- Re-create the document in CycloneDX, SPDX, or SWID.

#### 1.2 Specification Version

This check determines whether the given SBOM is in the specification version that can support fields necessary for typical SBOM operations.
The current check tests for:

- CycloneDX Versions: 1.0, 1.1, 1.2, 1.3, 1.4
- SPDX Versions: 2.1, 2.2, 2.3

While the earlier versions of specifications may exist, a document in an earlier version will not be able to carry all of the required fields.

***Remediation***

- Re-create the document in one of the versions listed above.

#### 1.3 Specification File Format

This check determines whether the given SBOM can be easily consumed by testing for the most common file formats associated with the specification.

- CycloneDX: XML, JSON
- SPDX: JSON, YAML, RDF, tag/value

Building and sharing SBOM in the most commonly used file format enables the use of SBOM in various conditions.

***Remediation steps***

- Re-create the document in one of the file formats listed above.

#### 1.4 Specification Syntax

This check determines whether the given SBOM meets all the requirements of the underlying specification and file format to be parsed.

A syntactic error in the SBOM will prevent it from being usable.

***Remediation***

- Check the SBOM generator tool's known issues and get the most recent version of the tool.
- Check options/setup of the environment variables required to use the tool.
- Build SBOM with a different tool.

### 2. Category: NTIA-Minimum-Elements

#### 2.1 Component Name

This check determines whether each component in the SBOM includes a name.

Components must have a name to be used meaningfully to assess compliance or security risk.

**Remediation**
Identify the component with a missing name and check its product page to get its name.

- CycloneDX field: [components:name](https://cyclonedx.org/docs/1.4/json/#components_items_name)
- SPDX field: [PackageName](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field)

#### 2.2 Supplier Name

This check determines whether each component in the SBOM includes a supplier name. Supplier name is not a well defined term
especially in the context of Open Source projects and we will update the recommendation here once a consensus emerges.

***Remediation***

Identify the component with a missing supplier name and check its product page to get its supplier name.

- CycloneDX field: [components:supplier](https://cyclonedx.org/docs/1.4/json/#components_items_supplier)
- SPDX field: [PackageSupplierName](https://spdx.github.io/spdx-spec/v2.3/package-information/#75-package-supplier-field)

#### 2.3 Unique Identifier

This check determines whether each component in the SBOM includes a unique identifier.

Unique component identifiers are essential to ensure the document can uniquely describe properties associated with the component.

***Remediation***

Identify the component with a missing/duplicate identifier.

- CycloneDX field: [components:bom-ref](https://cyclonedx.org/docs/1.4/json/#components_items_bom-ref)
- SPDX field: [SPDXID](https://spdx.github.io/spdx-spec/v2.3/package-information/#72-package-spdx-identifier-field)

#### 2.4 Component Version

This check determines whether each component in the SBOM includes a version.

Components without a version can not be checked for vulnerabilities.

***Remediation***
Identify the component with the missing version and populate the version field below.

- CycloneDX field: [components:version](https://cyclonedx.org/docs/1.4/json/#components_items_version)
- SPDX field: [PackageVersion](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field)

#### 2.4 Author Name

This check determines whether the document includes the name of the author.

The person, organization, or the tool that created the SBOM must be specified as the Author.

***Remediation***
Check and populate the following fields with the name of the person, organization, or tool creating the SBOM.

- CycloneDX field: [metadata:authors](https://cyclonedx.org/docs/1.4/json/#metadata_authors)
- SPDX field: [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field)

#### 2.5 Timestamp

This check determines if the document includes the timestamp of its creation.

The timestamp can be used to determine when the SBOM was created relative to the software itself.

***Remediation steps***

- Check and populate the following fields with the timestamp of the SBOM document.
- CycloneDX field: [metadata:timestamp](https://cyclonedx.org/docs/1.4/json/#metadata_timestamp)
- SPDX field: [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field)

#### 2.6 Relationship among Components

This check determines if the document describes the relationship among included components.

The dependency relationship can be critical in determining the order of inclusion and updates.

***Remediation***

- Check and populate the following fields with the relationship of components in the SBOM.
- CycloneDX field: [dependencies](https://cyclonedx.org/docs/1.4/json/#dependencies)
- SPDX field: [Relationship](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/#111-relationship-field)

### 3. Category: Semantic

#### 3.1 Component Checksum

This check determines whether each component in the SBOM includes a valid checksum.

A valid checksum can be used to independently identify the contents of the package among variations of the package.

***Remediation***

- Check and populate the following fields with the relationship of components in the SBOM.
- CycloneDX field: [dependencies](https://cyclonedx.org/docs/1.4/json/#dependencies)
- SPDX fields: [PackageChecksum](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field), (Coming Soon) [FileChecksum](https://spdx.github.io/spdx-spec/v2.3/file-information/#84-file-checksum-field)

#### 3.2 Component License

This check determines whether each component in the SBOM includes a valid license.

A declared valid SPDX license is the key to evaluating any compliance risks.

***Remediation steps***

Check and populate the following fields with the relationship of components in the SBOM.

- CycloneDX field: [component:licenses](https://cyclonedx.org/docs/1.4/json/#components_items_licenses)
- SPDX fields: [PackageLicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field), (Coming Soon) [LicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)

#### 3.3 Required Fields

This check determines whether several fields required by the underlying specification are present in the document.

With the required fields, the SBOM processing becomes consistent by different tools.

***Remediation***

Check and populate the following required fields:

- CycloneDX Fields: [bomFormat](https://cyclonedx.org/docs/1.4/json/#bomFormat), [SpecVersion](https://cyclonedx.org/docs/1.4/json/#specVersion), [Version](https://cyclonedx.org/docs/1.4/json/#version), [component:type](https://cyclonedx.org/docs/1.4/json/#components_items_type),[component:name](https://cyclonedx.org/docs/1.4/json/#components_items_name)
- SPDX Fields: [CreationInfo](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/), [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field), [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field), [SPDXVersion](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#61-spdx-version-field), [DataLicense](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field), [SPDXIdentifier](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field), [DocumentName](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#64-document-name-field), [DocumentNamespace](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field), [PackageName](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field), [PackageSPDXIdentifier](https://spdx.github.io/spdx-spec/v2.3/package-information/#72-package-spdx-identifier-field), [PackageDowloadLocation](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field), [PackageVerificationCode](https://spdx.github.io/spdx-spec/v2.3/package-information/#79-package-verification-code-field) (if applicable)

### 4. Category: Quality

#### 4.1 Vulnerability Lookup Identifier

This check determines whether at least one vulnerability lookup identifier (CPE/PURL) is present for each component.

A vulnerability lookup identifier is critical in mapping SBOM components to known vulnerability databases (e.g., NVD).

***Remediation***

- Check and populate the following fields:
- CycloneDX field: [components:cpe](https://cyclonedx.org/docs/1.4/json/#components_items_cpe) OR [components:purl](https://cyclonedx.org/docs/1.4/json/#components_items_purl)
- SPDX fields: [ExternalRef with CPE or PURL](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field)

#### 4.2 Multiple Vulnerability Lookup Identifier

This check determines whether multiple vulnerability lookup identifiers are present for each component.

Including more than one vulnerability lookup identifier can enable vulnerability lookup from multiple sources, reducing the risk of missing any vulnerability.

***Remediation***

Check and populate the following fields:

- CycloneDX field: [components:cpe](https://cyclonedx.org/docs/1.4/json/#components_items_cpe) AND [components:purl](https://cyclonedx.org/docs/1.4/json/#components_items_purl)
- SPDX fields: [ExternalRef with CPE AND PURL](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field)

#### 4.3 Valid SPDX License

This check determines whether all included licenses are valid SPDX [licenses or license expressions](https://spdx.org/licenses/).

Any license expression not found on the SPDX list is a commercial license and must be evaluated independently for compliance risks.

***Remediation***

- Check the following fields to confirm none of the licenses belong to the [SPDX license list](https://spdx.org/licenses/):
- CycloneDX field: [component:licenses](https://cyclonedx.org/docs/1.4/json/#components_items_licenses)
- SPDX fields: [PackageLicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field), (Coming Soon) [LicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)

#### 4.4 Deprecated License

This check determines whether any of the included licenses have been declared deprecated.

A deprecated license declaration can be considered a compliance risk.

***Remediation***

- Check the following fields to confirm none of the licenses belong to the [deprecated licenses](https://spdx.org/licenses/):
- CycloneDX field: [component:licenses](https://cyclonedx.org/docs/1.4/json/#components_items_licenses)
- SPDX fields: [PackageLicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field), (Coming Soon) [LicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)

#### 4.5 Restricted License

This check determines whether any included licenses have been declared restricted for use.

A restricted license declaration can be considered a compliance risk.

***Remediation***

- Check the following fields to confirm none of the licenses belong to the [restricted license list](https://opensource.google/documentation/reference/thirdparty/licenses):
- CycloneDX field: [component:licenses](https://cyclonedx.org/docs/1.4/json/#components_items_licenses)
- SPDX fields: [PackageLicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field), (Coming Soon) [LicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)

#### 4.6 Primary Purpose

This check determines whether the SBOM component includes the Primary Purpose field.

The primary purpose (or type) indicates the use of the component inside the application.

***Remediation steps***

Check the following fields to confirm none of the licenses belong to the [restricted license list](https://opensource.google/documentation/reference/thirdparty/licenses):

- CycloneDX field: [component:type](https://cyclonedx.org/docs/1.4/json/#components_items_type)
- SPDX fields: [PrimaryPackagePurpose](https://spdx.github.io/spdx-spec/v2.3/package-information/#724-primary-package-purpose-field)

#### 4.7 Primary Component Present

An sbom is expected to describe a primary component. This check determines if the sbom has
a primary component or not.

***Remediation steps***

- CycloneDX: ensure the metadata section has the primary [component](https://cyclonedx.org/docs/1.5/json/#metadata_component) defined
- SPDX: Should have a [DESCRIBES](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) relationship which points to a package, or have a documentDescribes field present.

### 5. Category: Sharing

#### 5.1 Unencumbered License

This check determines whether the SBOM can be shared easily because it includes an unencumbered license: [CC0](https://spdx.org/licenses/CC0-1.0), [Unlicense](https://spdx.org/licenses/Unlicense.html), [0BSD](https://spdx.org/licenses/0BSD.html)

Check the following fields to see if the license includes one of the above licenses:

- CycloneDX field: [metadata:licenses](https://cyclonedx.org/docs/1.4/json/#metadata_licenses)
- SPDX fields: [DataLicense](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field)

Got it! Here's the refined `bsi-v1.1` category following your exact style — with **"Corresponding Fields"** listed separately and a distinct **"Remediation"** section under each check.

### 6. Category: BSI-v1.1

#### 6.1 SBOM URI

This check ensures the SBOM contains a unique URI or identifier for the document itself.

**Corresponding Fields:**

- CycloneDX: `serialNumber`, `version`
- SPDX: `DocumentNamespace`

***Remediation***

Make sure your SBOM tool or generator includes a globally unique identifier in the fields listed above.

#### 6.2 Component Source Code URI

This check ensures that the SBOM contains a reference to the source code repository of each component.

**Corresponding Fields:**

- CycloneDX: `component.externalReferences` (type: `vcs`)
- SPDX: *Not supported*

***Remediation***

Verify the repository/source URI is included for each component. If your tool doesn’t support it, manually enrich the SBOM or switch to a more compliant generator.

#### 6.3 Component Executable URI

This check ensures the SBOM includes a URI where the executable or build artifact of the component can be found.

**Corresponding Fields:**

- CycloneDX: `component.externalReferences` (type: `distribution`, `distribution-intake`)
- SPDX: `PackageDownloadLocation`

***Remediation***

Ensure each component contains the URI pointing to the built binary or artifact. Add this manually or through SBOM generation tooling.

#### 6.4 Component Source Hash

This check validates that a hash of the source code is included for each component to support integrity verification.

**Corresponding Fields:**

- CycloneDX: *(Not explicitly standardized — under discussion)*
- SPDX: `PackageVerificationCode`

***Remediation***

Use SPDX’s `PackageVerificationCode` to represent the source hash. CycloneDX currently lacks an exact equivalent.

#### 6.5 Other Unique Identifiers

This check ensures the SBOM includes additional unique identifiers (like PURL or CPE) for better traceability and vulnerability lookups.

**Corresponding Fields:**

- CycloneDX: `component.cpe`, `component.purl`
- SPDX: `externalReferences` (type: `security` with CPE or PURL)

***Remediation***

Include either a CPE or PURL for each component to facilitate accurate vulnerability correlation.

#### 6.6 Component Hash

This check ensures the component’s binary artifact hash is captured to confirm its identity.

**Corresponding Fields:**

- CycloneDX: `component.hashes`
- SPDX: `PackageChecksum`

***Remediation***

Ensure each component entry includes a valid SHA hash. Most SBOM tools can generate this automatically during build time.

#### 6.7 Component License

This check ensures that each component declares a valid license.

**Corresponding Fields:**

- CycloneDX: `component.licenses`
- SPDX: `PackageLicenseConcluded`, `PackageLicenseDeclared`

***Remediation***

Verify that the license is present and valid. Use SPDX license identifiers and ensure both declared and concluded licenses are provided when possible.

#### 6.8 Component Dependencies

This check ensures the SBOM includes information about how components depend on each other.

**Corresponding Fields:**

- CycloneDX: `dependencies`, `compositions`
- SPDX: `relationships` (type: `DEPENDS_ON`)
  *Note: SPDX does not support `CONTAINS` here.*

***Remediation***

Use dependency information from build tools or SBOM generators to populate these fields correctly.

#### 6.9 Component Version

This check validates that a version is assigned to each component in the SBOM.

**Corresponding Fields:**

- CycloneDX: `component.version`
- SPDX: `PackageVersion`

***Remediation***

Ensure each component has an accurate version, especially for open source or third-party dependencies.

#### 6.10 Component Creator

This check ensures that the creator or supplier of each component is documented.

**Corresponding Fields:**

- CycloneDX: `component.supplier`
- SPDX: `PackageSupplier`, `PackageOriginator`

***Remediation***

Populate the supplier or originator fields for each component. This could be a person, organization, or project.

#### 6.11 SBOM Creator

This check ensures that the person or tool that created the SBOM is properly identified.

**Corresponding Fields:**

- CycloneDX: `metadata.authors`, `metadata.supplier`
- SPDX: `Creator`

***Remediation***

Make sure the metadata includes who or what created the SBOM. See [issue #448](https://github.com/interlynk-io/sbomqs/issues/448) for related discussion.

#### 6.12 SBOM Relationships

This check ensures that the SBOM describes relationships between components correctly.

**Corresponding Fields:**

- SPDX: `relationships` (type: `CONTAINS`)
  *Note: SPDX does **not** use `DEPENDS_ON` for SBOM-level relationships.*
- CycloneDX: `dependsOn`

***Remediation***

Make sure the SBOM expresses which components are part of the main software. CycloneDX typically uses `metadata.component` and `dependencies`; SPDX relies on `CONTAINS`.

Perfect, based on your table and formatting preference, here's a well-aligned **`BSI-v2.0`** section for your SBOM quality documentation — using **"Corresponding Fields"** and a **"Remediation"** section per check just like other categories:

### 7. Category: BSI-v2.0

#### 7.1 Vulnerability Information Present

This check verifies if the SBOM contains embedded vulnerability data. BSI v2.0 explicitly requires that SBOMs **must not** include vulnerability data.

**Corresponding Fields:**

- CycloneDX: `vulnerabilities`
- SPDX: *Non-deterministic*, `externalReference.comment` *(informal workaround)*

***Remediation***

Ensure the SBOM does **not** include embedded vulnerability information. If vulnerability analysis is needed, use a separate VEX or report artifact.

#### 7.2 SBOM Specification Format and Version

This check validates that the SBOM conforms to an accepted specification and version as per BSI guidelines.

**Corresponding Fields:**

- CycloneDX: `bomFormat`, `specVersion` (v1.5+)
- SPDX: `SPDXVersion` (v2.2.1+)

***Remediation***

Ensure the SBOM is created using SPDX 2.2.1+ or CycloneDX 1.5+. Re-generate using compliant tooling if needed.

#### 7.3 SBOM Creator Identity

This check verifies the SBOM includes an author with an email or URL — just a name is not sufficient.

**Corresponding Fields:**

- CycloneDX: `metadata.authors`, `metadata.supplier`, `metadata.manufacturer`
- SPDX: `Creator` (Person or Organization)

***Remediation***

Include a valid author with either an email or URL in the appropriate fields. Avoid using just plain names.

#### 7.4 SBOM Timestamp

This check ensures the SBOM includes a timestamp using a valid format.

**Corresponding Fields:**

- CycloneDX: `metadata.timestamp`
- SPDX: `Created`

***Remediation***

Ensure the timestamp is present and properly formatted in ISO 8601. Regenerate if your tooling produces an invalid format.

#### 7.5 Component Creator Identity

This check ensures each component includes a supplier or creator with a resolvable identity (preferably email or URL).

**Corresponding Fields:**

- CycloneDX: `component.supplier`, `component.authors`
- SPDX: `PackageSupplier`, `PackageOriginator`

***Remediation***

Make sure each component lists a responsible entity with contact information. Prefer using fields that support resolvable identities.

#### 7.6 Component Name

This check ensures each component includes a name.

**Corresponding Fields:**

- CycloneDX: `component.name`
- SPDX: `PackageName`

***Remediation***

All components should include a valid name. This is typically automatically populated by SBOM generators.

#### 7.7 Component Version

This check ensures each component includes a version string.

**Corresponding Fields:**

- CycloneDX: `component.version`
- SPDX: `PackageVersion`

***Remediation***

Make sure each component entry has a version. Empty or missing values should be addressed manually or via tooling fix.

#### 7.8 Component Filename

This check verifies the component includes a filename.

**Corresponding Fields:**

- CycloneDX: `component.name` (type: `file`) or in `properties`
- SPDX: `PackageFileName`

***Remediation***

If representing a file, ensure the filename is captured. In CycloneDX, consider including it via `component.properties`.

#### 7.9 Component Dependencies

This check ensures the SBOM documents relationships between components.

**Corresponding Fields:**

- CycloneDX: `dependencies`, `compositions`
- SPDX: `Relationships`

***Remediation***

Include dependency or composition information in your SBOM to reflect how components relate to each other.

#### 7.10 Component Associated License

This check ensures components have at least one associated license.

**Corresponding Fields:**

- CycloneDX: `component.licenses.expression`
- SPDX: `PackageLicenseConcluded`

***Remediation***

Ensure each component includes a valid SPDX license identifier in the specified fields.

#### 7.11 Component Hash

This check ensures components include at least one hash (preferably SHA-256).

**Corresponding Fields:**

- CycloneDX: `component.hashes`
- SPDX: `PackageChecksum`

***Remediation***

Use tooling that generates SHA-256 checksums for each component. Older hash algorithms may not meet compliance.

#### 7.12 Component Executable and Archive

This check validates if executables and archives are represented with relevant identifiers or references.

**Corresponding Fields:**

- CycloneDX / SPDX: *Open to vendor implementation*

***Remediation***

Use `externalReferences` to refer to executables or archives. Define this clearly if such artifacts are part of your SBOM scope.

#### 7.13 Structured Format

This check ensures the SBOM is delivered in a structured machine-readable format.

**Corresponding Fields:**

- CycloneDX / SPDX: JSON, XML, RDF, YAML

***Remediation***

Avoid free-text SBOMs. Ensure output is a structured format accepted by the consuming ecosystem.

#### 7.14 SBOM URI (Document Identifier)

This check validates the SBOM includes a globally unique identifier for the document.

**Corresponding Fields:**

- CycloneDX: `serialNumber`, `version`
- SPDX: `DocumentNamespace`

***Remediation***

Use a unique `serialNumber` or `namespace` to allow referencing the SBOM externally or across systems.

#### 7.15 Component Source Code URI

This check ensures the SBOM includes a link to the source code for each component.

**Corresponding Fields:**

- CycloneDX: `component.externalReferences` (type: `vcs`)
- SPDX: *Not deterministic*

***Remediation***

Make sure components include VCS links when applicable. For SPDX, consider using `externalReferences` with comments.

#### 7.16 Executable URI

This check ensures components point to their binary or installable versions.

**Corresponding Fields:**

- CycloneDX: `externalReferences` (type: `distribution`, `distribution-intake`)
- SPDX: `PackageDownloadLocation`

***Remediation***

Add proper links where executables are hosted. Most build tools can populate this automatically.

#### 7.17 Hash of Source Code

This check ensures a hash of the component source code is included.

**Corresponding Fields:**

- CycloneDX: *Not explicitly supported*
- SPDX: `PackageVerificationCode`

***Remediation***

Include `PackageVerificationCode` where possible. CycloneDX does not currently support this explicitly — monitor future spec updates.

#### 7.18 Other Unique Identifiers (CPE/PURL)

This check ensures components have unique identifiers like PURL or CPE.

**Corresponding Fields:**

- CycloneDX: `component.purl`, `component.cpe`
- SPDX: `externalReferences.security` (CPE), `package_manager` (PURL)

***Remediation***

Add either PURL or CPE to improve vulnerability mapping and cross-referencing.

#### 7.19 Concluded License

This check ensures components include a concluded license expression.

**Corresponding Fields:**

- CycloneDX: `licenses.acknowledgement` (only in v1.6+)
- SPDX: `PackageLicenseConcluded`

**Remediation:**

Make sure a license has been analyzed and concluded for each component. Use SPDX-compatible expressions.

#### 7.20 Declared License

This check ensures components declare the license they were distributed with.

**Corresponding Fields:**

- CycloneDX: `licenses.acknowledgement` (v1.6+)
- SPDX: `PackageLicenseDeclared`

***Remediation***

Populate declared license fields even if concluded licenses are also used. They serve different legal purposes.

#### 7.21 Signature

This check verifies whether the SBOM is digitally signed.

**Corresponding Fields:**

- CycloneDX: `signature`
- SPDX: *Non-deterministic / out-of-band*

***Remediation***

Consider signing the SBOM using a signing tool (e.g., cosign, sigstore). Attach signature metadata as recommended in CycloneDX 1.5+.

#### 7.22 External Bom Links

This check verifies whether external references to other SBOMs are included.

***Corresponding Fields***

- CycloneDX: `externalReferences` (type: `bom`)
- SPDX: `externalDocumentRefs`

***Remediation***

Reference other SBOMs using proper links, especially in multi-layered or composed software systems.
