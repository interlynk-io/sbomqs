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
SBOM Specification | This criteria checks if the sbom file supports SPDX or CycloneDX | 
SBOM Spec Version | This criteria checks if the sbom file is using the correct spec versions of the detected spec | 
SBOM Spec file format | checks if the sbom file is in a spec compatible format e.g json, xml, rdf | 
File is parsable | checks if the file can be parsed | 
Components have Supplier Name | checks if the sbom components have supplier names | 
Components have names | checks if the sbom components have names |
Components have versions | checks if the sbom components have versions | 
Components have uniq lookup ids | checks if the sbom components have either cpe or purl | 
Components have licenses | checks if the sbom components have licenses |
Components have checksums | checks if the sbom components have checksums | 
Components have valid spdx licenses | checks if the sbom components have licenses which match the spdx license list |
Components dont have deprecated licenses| checks if the sbom components dont have licenses that are deprecated |
Components have all uniq lookup ids| checks if the sbom components have both purl and cpe | 
Components have restricted licenses | checks if the sbom components have restricted licenses which match the restricted license list |
Components have primary purpose defined | checks if the sbom components have a primary purpose defined e.g application/library|
Doc has Relations | checks if sbom has specified relations between its components | 
Doc has Authors | checks if sbom has authors i.e  person/ org or tool | 
Doc has creation timestamp | check if the sbom has a creation timestamp | 
Doc has require fields | check if the sbom has all the required fields as specified by the (spdx/cdx) spec | 
Doc has sharable license | check if the sbom doc has an unemcumbered license which can aid in sharing | 