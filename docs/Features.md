<!--
 Copyright 2023 Interlynk.io
 
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

### Category: Structural

---

#### Specification

This check determines whether the SBOM is in one of the specifications (CycloneDX, SPDX, SWID) recommended by the [CISA reference document](https://ntia.gov/sites/default/files/publications/ntia_sbom_framing_2nd_edition_20211021_0.pdf) .

CISA recommends limiting
the document to three commonly used formats to facilitate widespread adoption.

***Remediation***

- Re-create the document in CycloneDX, SPDX, or SWID.

---

#### Specification Version

This check determines whether the given SBOM is in the specification version that can support fields necessary for typical SBOM operations.
The current check tests for:

- CycloneDX Versions: 1.0, 1.1, 1.2, 1.3, 1.4
- SPDX Versions: 2.1, 2.2, 2.3

While the earlier versions of specifications may exist, a document in an earlier version will not be able to carry all of the required fields.

***Remediation***

- Re-create the document in one of the versions listed above.

---

#### Specification File Format

This check determines whether the given SBOM can be easily consumed by testing for the most common file formats associated with the specification.

- CycloneDX: XML, JSON
- SPDX: JSON, YAML, RDF, tag/value

Building and sharing SBOM in the most commonly used file format enables the use of SBOM in various conditions.

***Remediation steps***

- Re-create the document in one of the file formats listed above.

---

#### Specification Syntax

This check determines whether the given SBOM meets all the requirements of the underlying specification and file format to be parsed.

A syntactic error in the SBOM will prevent it from being usable.

***Remediation***

- Check the SBOM generator tool's known issues and get the most recent version of the tool.
- Check options/setup of the environment variables required to use the tool.
- Build SBOM with a different tool.

---

## Category: NTIA-Minimum-Elements

---

#### Component Name

This check determines whether each component in the SBOM includes a name.

Components must have a name to be used meaningfully to assess compliance or security risk.

**Remediation**
Identify the component with a missing name and check its product page to get its name.

- CycloneDX field: [components:name](https://cyclonedx.org/docs/1.4/json/#components_items_name)
- SPDX field: [PackageName](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field)

---

#### Supplier Name

This check determines whether each component in the SBOM includes a supplier name. Supplier name is not a well defined term
especially in the context of Open Source projects and we will update the recommendation here once a consensus emerges.

***Remediation***

Identify the component with a missing supplier name and check its product page to get its supplier name.

- CycloneDX field: [components:supplier](https://cyclonedx.org/docs/1.4/json/#components_items_supplier)
- SPDX field: [PackageSupplierName](https://spdx.github.io/spdx-spec/v2.3/package-information/#75-package-supplier-field)

---

#### Unique Identifier

This check determines whether each component in the SBOM includes a unique identifier.

Unique component identifiers are essential to ensure the document can uniquely describe properties associated with the component.

***Remediation***

Identify the component with a missing/duplicate identifier.

- CycloneDX field: [components:bom-ref](https://cyclonedx.org/docs/1.4/json/#components_items_bom-ref)
- SPDX field: [SPDXID](https://spdx.github.io/spdx-spec/v2.3/package-information/#72-package-spdx-identifier-field)

---

#### Component Version

This check determines whether each component in the SBOM includes a version.

Components without a version can not be checked for vulnerabilities.

***Remediation***
Identify the component with the missing version and populate the version field below.

- CycloneDX field: [components:version](https://cyclonedx.org/docs/1.4/json/#components_items_version)
- SPDX field: [PackageVersion](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field)

---

#### Author Name

This check determines whether the document includes the name of the author.

The person, organization, or the tool that created the SBOM must be specified as the Author.

***Remediation***
Check and populate the following fields with the name of the person, organization, or tool creating the SBOM.

- CycloneDX field: [metadata:authors](https://cyclonedx.org/docs/1.4/json/#metadata_authors)
- SPDX field: [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field)

---

#### Timestamp

This check determines if the document includes the timestamp of its creation.

The timestamp can be used to determine when the SBOM was created relative to the software itself.

***Remediation steps***

- Check and populate the following fields with the timestamp of the SBOM document.
- CycloneDX field: [metadata:timestamp](https://cyclonedx.org/docs/1.4/json/#metadata_timestamp)
- SPDX field: [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field)

---

#### Relationship among Components

This check determines if the document describes the relationship among included components.

The dependency relationship can be critical in determining the order of inclusion and updates.

***Remediation***

- Check and populate the following fields with the relationship of components in the SBOM.
- CycloneDX field: [dependencies](https://cyclonedx.org/docs/1.4/json/#dependencies)
- SPDX field: [Relationship](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/#111-relationship-field)

---

### Category: Semantic

---

#### Component Checksum

This check determines whether each component in the SBOM includes a valid checksum.

A valid checksum can be used to independently identify the contents of the package among variations of the package.

***Remediation***

- Check and populate the following fields with the relationship of components in the SBOM.
- CycloneDX field: [dependencies](https://cyclonedx.org/docs/1.4/json/#dependencies)
- SPDX fields: [PackageChecksum](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field), (Coming Soon) [FileChecksum](https://spdx.github.io/spdx-spec/v2.3/file-information/#84-file-checksum-field)


---

#### Component License

This check determines whether each component in the SBOM includes a valid license.

A declared valid SPDX license is the key to evaluating any compliance risks.

***Remediation steps***

Check and populate the following fields with the relationship of components in the SBOM.

- CycloneDX field: [component:licenses](https://cyclonedx.org/docs/1.4/json/#components_items_licenses)
- SPDX fields: [PackageLicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field), (Coming Soon) [LicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)

---

#### Required Fields

This check determines whether several fields required by the underlying specification are present in the document.

With the required fields, the SBOM processing becomes consistent by different tools.

***Remediation***

Check and populate the following required fields:

- CycloneDX Fields: [bomFormat](https://cyclonedx.org/docs/1.4/json/#bomFormat), [SpecVersion](https://cyclonedx.org/docs/1.4/json/#specVersion), [Version](https://cyclonedx.org/docs/1.4/json/#version), [component:type](https://cyclonedx.org/docs/1.4/json/#components_items_type),[component:name](https://cyclonedx.org/docs/1.4/json/#components_items_name)
- SPDX Fields: [CreationInfo](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/), [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field), [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field), [SPDXVersion](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#61-spdx-version-field), [DataLicense](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field), [SPDXIdentifier](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field), [DocumentName](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#64-document-name-field), [DocumentNamespace](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field), [PackageName](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field), [PackageSPDXIdentifier](https://spdx.github.io/spdx-spec/v2.3/package-information/#72-package-spdx-identifier-field), [PackageDowloadLocation](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field), [PackageVerificationCode](https://spdx.github.io/spdx-spec/v2.3/package-information/#79-package-verification-code-field) (if applicable)

---

### Category: Quality

---

#### Vulnerability Lookup Identifier

This check determines whether at least one vulnerability lookup identifier (CPE/PURL) is present for each component.

A vulnerability lookup identifier is critical in mapping SBOM components to known vulnerability databases (e.g., NVD).

***Remediation***

- Check and populate the following fields:
- CycloneDX field: [components:cpe](https://cyclonedx.org/docs/1.4/json/#components_items_cpe) OR [components:purl](https://cyclonedx.org/docs/1.4/json/#components_items_purl)
- SPDX fields: [ExternalRef with CPE or PURL](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field)

---

#### Multiple Vulnerability Lookup Identifier

This check determines whether multiple vulnerability lookup identifiers are present for each component.

Including more than one vulnerability lookup identifier can enable vulnerability lookup from multiple sources, reducing the risk of missing any vulnerability.

***Remediation***

Check and populate the following fields:

- CycloneDX field: [components:cpe](https://cyclonedx.org/docs/1.4/json/#components_items_cpe) AND [components:purl](https://cyclonedx.org/docs/1.4/json/#components_items_purl)
- SPDX fields: [ExternalRef with CPE AND PURL](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field)

---

#### Valid SPDX License

This check determines whether all included licenses are valid SPDX [licenses or license expressions](https://spdx.org/licenses/).

Any license expression not found on the SPDX list is a commercial license and must be evaluated independently for compliance risks.

***Remediation***

- Check the following fields to confirm none of the licenses belong to the [SPDX license list](https://spdx.org/licenses/):
- CycloneDX field: [component:licenses](https://cyclonedx.org/docs/1.4/json/#components_items_licenses)
- SPDX fields: [PackageLicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field), (Coming Soon) [LicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)

---

#### Deprecated License

This check determines whether any of the included licenses have been declared deprecated.

A deprecated license declaration can be considered a compliance risk.

***Remediation***

- Check the following fields to confirm none of the licenses belong to the [deprecated licenses](https://spdx.org/licenses/):
- CycloneDX field: [component:licenses](https://cyclonedx.org/docs/1.4/json/#components_items_licenses)
- SPDX fields: [PackageLicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field), (Coming Soon) [LicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)

---

#### Restricted License

This check determines whether any included licenses have been declared restricted for use.

A restricted license declaration can be considered a compliance risk.

***Remediation***

- Check the following fields to confirm none of the licenses belong to the [restricted license list](https://opensource.google/documentation/reference/thirdparty/licenses):
- CycloneDX field: [component:licenses](https://cyclonedx.org/docs/1.4/json/#components_items_licenses)
- SPDX fields: [PackageLicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field), (Coming Soon) [LicenseConcluded](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)

---

#### Primary Purpose

This check determines whether the SBOM component includes the Primary Purpose field.

The primary purpose (or type) indicates the use of the component inside the application.

***Remediation steps***

Check the following fields to confirm none of the licenses belong to the [restricted license list](https://opensource.google/documentation/reference/thirdparty/licenses):

- CycloneDX field: [component:type](https://cyclonedx.org/docs/1.4/json/#components_items_type)
- SPDX fields: [PrimaryPackagePurpose](https://spdx.github.io/spdx-spec/v2.3/package-information/#724-primary-package-purpose-field)

---

#### Primary Component Present

An sbom is expected to describe a primary component. This check determines if the sbom has
a primary component or not.

***Remediation steps***

- CycloneDX: ensure the metadata section has the primary [component](https://cyclonedx.org/docs/1.5/json/#metadata_component) defined
- SPDX: Should have a [DESCRIBES](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) relationship which points to a package, or have a documentDescribes field present.

---

### Category: Sharing

---

#### Unencumbered License

This check determines whether the SBOM can be shared easily because it includes an unencumbered license: [CC0](https://spdx.org/licenses/CC0-1.0), [Unlicense](https://spdx.org/licenses/Unlicense.html), [0BSD](https://spdx.org/licenses/0BSD.html)

Check the following fields to see if the license includes one of the above licenses:

- CycloneDX field: [metadata:licenses](https://cyclonedx.org/docs/1.4/json/#metadata_licenses)
- SPDX fields: [DataLicense](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field)

---
