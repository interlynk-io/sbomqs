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

Name        | Description                               | 
----------- | ----------------------------------------- | 
SBOM Specification | Checks if the sbom is in one of the currently supported formats : <br>- [**CycloneDX**](https://cyclonedx.org/),<br>- [**SPDX**](https://spdx.dev/) | 
SBOM Spec Version | Checks if the sbom is in currently supported version of the detected specification : <br>- **CycloneDX:** Versions [1.0](https://cyclonedx.org/docs/1.0/xml/), [1.1](https://cyclonedx.org/docs/1.1/xml/), [1.2](https://cyclonedx.org/docs/1.2/json/), [1.3](https://cyclonedx.org/docs/1.3/json/), [1.4](https://cyclonedx.org/docs/1.4/json/), <br>- **SPDX:** Versions [2.1](https://spdx.dev/spdx-specification-21-web-version/), [2.2](https://spdx.github.io/spdx-spec/v2.2.2), [2.3](https://spdx.github.io/spdx-spec/v2.3/)| 
SBOM Spec file format | Checks if the sbom is in a format compatible with the specification<br>- **CycloneDX:** XML, JSON,<br>- **SPDX:** JSON, YAML, RDF, tag/value | 
File is parsable | Checks if the sbom is valid and parsable following the detected specification | 
Components have Supplier Name | Checks if the sbom components include supplier names | 
Components have names | Checks if the sbom components include names |
Components have versions | Checks if the sbom components include versions | 
Components have uniq ids | Checks if the sbom components include unique identifiers (See [Table 1](https://www.ntia.gov/files/ntia/publications/sbom_formats_survey-version-2021.pdf)) | 
Components have licenses | Checks if the sbom components include licenses |
Components have checksums | Checks if the sbom components include checksums | 
Components have valid spdx licenses | Checks if the sbom components have licenses that match the [SPDX License List](https://spdx.org/licenses/) |
Components dont have deprecated licenses| Checks if the sbom components include deprecated licenses |
Components have multiple vulnerability lookup ids| Checks if the sbom includes multiple - PURL, CPE - identifiers for each component | 
Components have any vulnerability lookup ids| Checks if the sbom includes at least one idnetifier - PURL or CPE - for each component | 
Components have restricted licenses | Checks if the sbom components include restricted licenses from the [restricted license list](https://opensource.google/documentation/reference/thirdparty/licenses) |
Components have primary purpose defined | Checks if the sbom components include a valid primary purpose defined e.g application/library|
Doc has Relations | Checks if the sbom specifies relationships among its listed components | 
Doc has Authors | Checks if the sbom includes author information i.e  person/ org or tool | 
Doc has creation timestamp | Checks if the sbom includes a creation timestamp | 
Doc has require fields | Check if the sbom includes all of the required fields of the detected specification : <br>- **CycloneDX:** [bomFormat](https://cyclonedx.org/docs/1.4/json/#bomFormat), [SpecVersion](https://cyclonedx.org/docs/1.4/json/#specVersion), [Version](https://cyclonedx.org/docs/1.4/json/#version), [component:type](https://cyclonedx.org/docs/1.4/json/#components_items_type),[component:name](https://cyclonedx.org/docs/1.4/json/#components_items_name)<br>- **SPDX:** [CreationInfo](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/), [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field), [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field), [SPDXVersion](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#61-spdx-version-field), [DataLicense](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field), [SPDXIdentifier](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field), [DocumentName](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#64-document-name-field), [DocumentNamespace](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field), [PackageName](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field), [PackageSPDXIdentifier](https://spdx.github.io/spdx-spec/v2.3/package-information/#72-package-spdx-identifier-field), [PackageDowloadLocation](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field), [PackageVerificationCode](https://spdx.github.io/spdx-spec/v2.3/package-information/#79-package-verification-code-field) (if applicable) | 
Doc has sharable license | Checks if the sbom includes an unemcumbered license that can aid in sharing | 
Doc has creator tool name and version | If the sbom was created with a tool, it has the tool name and version | 
