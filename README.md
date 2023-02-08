## Overview

### What is SBOM quality score
A quality SBOM is one that is accurate, complete, and up-to-date. It should accurately reflect the components and dependencies used in the software application, including their version and optionally any known vulnerabilities. In addition, it should be easily accessible to and understandable by stakeholders, such as developers, security teams, and compliance officers.

[Interlyk.io](mailto:hello@interlynk.io) has developed sbomqs to simplify the evaluation of SBOM quality for both producers and consumers. A higher score indicates greater usability of the SBOM contents.

### SBOM Support
We support SPDX and CycloneDX sbom standards, in various file formats.

### Installation 
Use the steps below to try out the tool.

#### Using Prebuild binaries 
We use go-release to compile pre-built binaries for Linux/Mac and Windows for AMD64. 
You can use this to try out the tool, without requiring to install golang. Find the binaries
in the releases link below. 

```
https://github.com/interlynk-io/sbomqs/releases
```

##### Using Go install
Using go install is an easy way to install the binary. Once compiled this will be installed 
in $(GOBIN) or $(GOPATH)/bin or $(GOROOT)/bin. 
```
go install github.com/interlynk-io/sbomqs@latest
```

##### Using repo
This approach invovles cloning the repo and building it. 

1. Clone the repo ```git clone git@github.com:interlynk-io/sbomqs.git```
2. `cd` into `sbomqs` folder 
3. make build
4. To test if the build was successful run the following command ```./build/sbomqs version```

### Getting access to SBOMS
For new users, we have listed a few places, where you could find sample sboms.
- This repo has a [samples](https://github.com/interlynk-io/sbomqs/tree/main/samples) directory
- If you use docker images and would like to generate an SBOM, follow the steps [here](https://docs.docker.com/engine/sbom/)
- [Syft](https://github.com/anchore/syft) / [Trivy](https://github.com/aquasecurity/trivy) are open source tools which can be used to generate SBOM from containers as well as repos. 
- Another public repository for SBOMS [bom-shelter](https://github.com/chainguard-dev/bom-shelter)

### Scoring
Each feature listed [below](#features) returns a score between 0 and 10. The more accurate, complete and up-to-date SBOM is the higher the score. 
The scores from each feature are averaged to provide an aggregate score. 

### Usage and examples
##### Using single file option
Sbomqs can run with just a single argument pointing to an sbom file 
```
➜  sbomqs git:(main) ./build/sbomqs score --filepath ./samples/julia.spdx.json
SBOM Quality Score: 6.9 ./samples/julia.spdx.json
+-----------------------+--------------------------------+-----------+--------------------------------+
|       CATEGORY        |            FEATURE             |   SCORE   |              DESC              |
+-----------------------+--------------------------------+-----------+--------------------------------+
| NTIA-minimum-elements | Doc has authors                | 10.0/10.0 | doc has 2 authors              |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have names          | 10.0/10.0 | 34/34 have names               |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have supplier names | 0.6/10.0  | 2/34 have supplier names       |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have uniq ids       | 0.0/10.0  | 0/34 have unique ID's          |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Doc has relationships          | 10.0/10.0 | doc has 1 relationships        |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have versions       | 0.3/10.0  | 1/34 have versions             |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Doc has creation timestamp     | 10.0/10.0 | doc has creation timestamp     |
|                       |                                |           | 2021-12-21T07:13:19Z           |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Quality               | Components have valid spdx     | 9.3/10.0  | 33/34 components with valid    |
|                       | licenses                       |           | license                        |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have primary        | 0.0/10.0  | 0/34 components have primary   |
|                       | purpose defined                |           | purpose specified              |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have no deprecated  | 9.7/10.0  | 1/34 components have           |
|                       | licenses                       |           | deprecated licenses            |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have no restricted  | 8.8/10.0  | 4/34 components have           |
|                       | licenses                       |           | restricted licenses            |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have multiple       | 0.0/10.0  | comp with uniq ids: cpe:0,     |
|                       | formats of uniq ids            |           | purl:0, total:34               |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Semantic              | Components have checksums      | 0.0/10.0  | 0/34 have checksums            |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Doc has all required fields    | 10.0/10.0 | Doc Fields:true Pkg            |
|                       |                                |           | Fields:true                    |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have licenses       | 10.0/10.0 | 34/34 have licenses            |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Sharing               | Doc sharable license           | 10.0/10.0 | doc has a sharable license     |
|                       |                                |           | free 1 :: of 1                 |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Structural            | Spec is parsable               | 10.0/10.0 | provided sbom is parsable      |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Spec File Format               | 10.0/10.0 | provided sbom should be in     |
|                       |                                |           | supported file format for      |
|                       |                                |           | spec: json and version:        |
|                       |                                |           | json,yaml,rdf,tag-value        |
+                       +--------------------------------+-----------+--------------------------------+
|                       | SBOM Specification             | 10.0/10.0 | provided sbom is in a          |
|                       |                                |           | supported sbom format of       |
|                       |                                |           | spdx,cyclonedx                 |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Spec Version                   | 10.0/10.0 | provided sbom should be in     |
|                       |                                |           | supported spec version for     |
|                       |                                |           | spec:SPDX-2.2 and versions:    |
|                       |                                |           | SPDX-2.1,SPDX-2.2,SPDX-2.3     |
+-----------------------+--------------------------------+-----------+--------------------------------+
```

##### Using directory option
You can point sbomqs to a directory containing sboms and just print out the score per file, instead of the details 
```
➜  sbomqs git:(main) ./build/sbomqs score --dirpath ../sbom-samples/repos --reportFormat basic | sort
6.3	../sbom-samples/repos/trivy-cartography.spdx
6.3	../sbom-samples/repos/trivy-cartography.spdx.json
6.8	../sbom-samples/repos/trivy-bom.spdx
6.8	../sbom-samples/repos/trivy-bom.spdx.json
6.8	../sbom-samples/repos/trivy-spdx-sbom-generator.spdx
6.8	../sbom-samples/repos/trivy-spdx-sbom-generator.spdx.json
6.8	../sbom-samples/repos/trivy-trivy-ci-test.spdx
6.8	../sbom-samples/repos/trivy-trivy-ci-test.spdx.json
7.2	../sbom-samples/repos/trivy-cartography.cdx.json
7.3	../sbom-samples/repos/trivy-trivy-ci-test.cdx.json
7.4	../sbom-samples/repos/trivy-bom.cdx.json
7.4	../sbom-samples/repos/trivy-spdx-sbom-generator.cdx.json
```

##### Using directory with category scoring option
You can evaluate your SBOM's based on specific categories, as described [here](#categories).
```
➜  sbomqs git:(main) ./build/sbomqs score --dirpath ../sbom-samples/repos --reportFormat basic --category NTIA-minimum-elements | sort
7.4	../sbom-samples/repos/trivy-cartography.spdx
7.4	../sbom-samples/repos/trivy-cartography.spdx.json
8.2	../sbom-samples/repos/trivy-cartography.cdx.json
8.4	../sbom-samples/repos/trivy-bom.spdx
8.4	../sbom-samples/repos/trivy-bom.spdx.json
8.4	../sbom-samples/repos/trivy-spdx-sbom-generator.spdx
8.4	../sbom-samples/repos/trivy-spdx-sbom-generator.spdx.json
8.4	../sbom-samples/repos/trivy-trivy-ci-test.spdx
8.4	../sbom-samples/repos/trivy-trivy-ci-test.spdx.json
8.5	../sbom-samples/repos/trivy-bom.cdx.json
8.5	../sbom-samples/repos/trivy-spdx-sbom-generator.cdx.json
8.5	../sbom-samples/repos/trivy-trivy-ci-test.cdx.json
```

#### Categories 
We have catergorizes scoring into 5 categories

Name        | Description                               | 
----------- | ----------------------------------------- | 
[NTIA-minimum-elements](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)  | NTIA has put forth certain minimum requirements that should exist in every SBOM, this category verifies if these requirements are satisfied  |
Structural| In this category, we check if the SBOM complies with basic SPEC guides, be it spdx or cdx |
Semantic| Semantic Quality covers test cases that check meaning of SBOM fields specific to specific standard and format | 
Quality | These series of checks, help determine the quaility of the data in the SBOM|
Sharing| These checks indicate if the sbom can be shared with someone else | 

#### Features 
Below is a listing of the various criteria we evaluate

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
Components have primary purpose defined | checks if the sbom components have a primary purpose defined e.g application/library|
Doc has Relations | checks if sbom has specified relations between its components | 
Doc has Authors | checks if sbom has authors i.e  person/ org or tool | 
Doc has creation timestamp | check if the sbom has a creation timestamp | 
Doc has require fields | check if the sbom has all the required fields as specified by the (spdx/cdx) spec | 
Doc has sharable license | check if the sbom doc has an unemcumbered license which can aid in sharing | 


## Stargazers over time

[![Stargazers over time](https://starchart.cc/interlynk-io/sbomqs.svg)](https://starchart.cc/interlynk-io/sbomqs)







