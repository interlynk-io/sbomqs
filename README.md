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

# `sbomqs`: Quality metrics for SBOMs

[![Go Reference](https://pkg.go.dev/badge/github.com/interlynk-io/sbomqs.svg)](https://pkg.go.dev/github.com/interlynk-io/sbomqs)
[![Go Report Card](https://goreportcard.com/badge/github.com/interlynk-io/sbomqs)](https://goreportcard.com/report/github.com/interlynk-io/sbomqs)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/interlynk-io/sbomqs/badge)](https://securityscorecards.dev/viewer/?uri=github.com/interlynk-io/sbomqs)
![GitHub all releases](https://img.shields.io/github/downloads/interlynk-io/sbomqs/total)

`sbomqs` is your primary tool to assess an SBOM's quality and compliance. The higher the score the more consumable & compliant your SBOMs are.

```console
brew tap interlynk-io/interlynk
brew install sbomqs
```

Other [installation options](#installation).

# SBOM Platform - Free Community Tier

Our SBOM Automation Platform has a free community tier that provides a comprehensive solution to manage SBOMs (Software Bill of Materials) effortlessly. From centralized SBOM storage, built-in SBOM editor, continuous vulnerability mapping and assessment, and support for organizational policies, all while ensuring compliance and enhancing software supply chain security using integrated SBOM quality scores. The community tier is ideal for small teams. Learn more [here](https://www.interlynk.io/community-tier) or [Sign up](https://app.interlynk.io/auth)

# SBOM Card

[![SBOMCard](https://api.interlynk.io/api/v1/badges.svg?type=hcard&project_group_id=7f52093e-3d78-49cb-aeb1-6c977de9442e
)](https://app.interlynk.io/customer/products?id=7f52093e-3d78-49cb-aeb1-6c977de9442e&signed_url_params=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqUmhPRGRoTjJNNExXSXpZekl0TkdVeE9TMDVNRGxoTFRKbFpHRmlPR1ZoWldReVl5ST0iLCJleHAiOm51bGwsInB1ciI6InNoYXJlX2x5bmsvc2hhcmVfbHluayJ9fQ==--daf6585ecf8013a0b2713a5cebb28c140d29eed904b15c84c0566b9ddd334e71)

# Usage

## Quality Score for a single SBOM

```sh
sbomqs score <sbom-file>
```

## Compliance Report: BSI TR-03183-2 v2.0.0

```sh
sbomqs compliance --bsi-v2 samples/photon.spdx.json
```

## Compliance Report: BSI TR-03183-2 v1.1 (legacy)

```sh
sbomqs compliance --bsi samples/photon.spdx.json
```

## Compliance Report: Framing Software Component Transparency (v3)

```sh
sbomqs compliance --fsct samples/photon.spdx.json --color
```

## List Components by Feature

```sh
sbomqs list samples/julia.spdx.json --feature comp_with_supplier
```

## List Components with Values

```sh
sbomqs list samples/julia.spdx.json --feature comp_valid_licenses --show
```

## Quality Score with a shareable link at [sbombenchmark.dev](https://sbombenchmark.dev/)

```sh
sbomqs share <sbom-file>
```

Example:

```sh
sbomqs share cdxgen-9.5.1_alpine-latest.cdx.json
```

```sh
5.9 cdxgen-9.5.1_alpine-latest.cdx.json
ShareLink: https://sbombenchmark.dev/user/score?id=a97af1bf-4c9d-4a55-8524-3d4bcee0b9a4
```

## Quality Score for your dependency track projects

```sh
sbomqs dtrackScore  -u <dt-host-url> -k <dt-api-key> <project-uuid>
```

Example:

```sh
sbomqs dtrackScore  -u "http://localhost:8080/" -k "IIcfPA9qc1F4IkQFa2FqQJoTwcfQI" bbd4434d-8062-4e59-a323-3b416701c948
```

![alt text](./images/dt.png "Depedency Track with sbomqs score")

## Quality Score in an AirGapped Environment

```sh
INTERLYNK_DISABLE_VERSION_CHECK=true ./build/sbomqs score ~/wrk/sbom*/samples/*.json  -b
```

## Quality Score using containers

```sh
docker run -v <path of sbom file or folder>:/app/inputfile ghcr.io/interlynk-io/sbomqs score /app/inputfile
```

Example

```sh
docker run -v $(pwd)/samples/sbomqs-cdx-cgomod.json:/app/inputfile ghcr.io/interlynk-io/sbomqs score -j /app/inputfile
```

```sh
Unable to find image 'ghcr.io/interlynk-io/sbomqs:latest' locally
latest: Pulling from interlynk-io/sbomqs
708d61464c72: Already exists
Digest: sha256:d47e3e936b3ef61c01fcf5cfd00d053c06bf1ded8c9ac3c0d148412126da3b3f
Status: Downloaded newer image for ghcr.io/interlynk-io/sbomqs:latest
{
  "run_id": "d1ccac27-323e-478a-afd2-7d33501997ea",
  "timestamp": "2023-05-23T06:11:25Z",
  "creation_info": {
    "name": "sbomqs",
    "version": "",
    "scoring_engine_version": "5"
  },
```

# List Command

The `list` command allows you to list and filter components based on specific features.

## List components with a feature

```sh
sbomqs list samples/julia.spdx.json --feature comp_with_supplier
```

## List components missing a feature

```sh
sbomqs list samples/julia.spdx.json --feature comp_with_licenses --missing
```

## Show feature values

```sh
sbomqs list samples/julia.spdx.json --feature comp_valid_licenses --show
```

### Available features for listing:
- `comp_with_supplier` - Components with supplier information
- `comp_with_licenses` - Components with license information
- `comp_valid_licenses` - Components with valid SPDX licenses
- `comp_with_version` - Components with version information
- `comp_with_purls` - Components with Package URLs
- `comp_with_cpes` - Components with CPE identifiers
- `comp_with_checksums` - Components with checksums
- `sbom_authors` - SBOM author information
- `sbom_creation_timestamp` - SBOM creation timestamp

# What is a high quality SBOM

A high quality SBOM should aptly support managing software assets, license information and Intellectual Property as well as provide a base for configuration management, vulnerability handling and incident response.

A quality SBOM is one that is accurate, complete, and up-to-date. There are many factors that go into constructing a high quality SBOM.

1. Identify & list all components of your product along with their transitive dependencies.
2. List all your components along with their versions & content checksums.
3. Include accurate component licenses.
4. Include accurate lookup identifiers e.g. [purls](https://github.com/package-url/purl-spec) or [CPEs](https://csrc.nist.gov/publications/detail/nistir/7698/final).
5. Quality SBOM depends a lot upon which stage of the lifecycle it has been generated at, we believe closer to the build time is ideal.
6. Signed SBOMs.
7. Should layout information based on industry standard specs like CycloneDX, SPDX and SWID.

# Goals

The main goals of the utility are:

1. Make it easy and fast to assess the quality if an SBOM, generated or acquired.
2. Support all well-known SBOM standards.
3. Scoring output should be customizable.
4. Scoring output should be consumable.

## Goal #1: Easy & Fast

SBOMs can be generated using both commercial and open-source tooling. As consumers of SBOMs we wanted a fast and easy way to assess the quality of an SBOM. An SBOM with a low score should be re-evaluated or rejected.

`sbomqs` makes getting a quick assessment effortless. Just point.

```sh
sbomqs score samples/julia.spdx.tv -b
```

```sh
6.9     samples/julia.spdx.json
```

## Goal #2: SBOM Standards

The NTIA recommends these standards for SBOMs:

- SPDX
- CycloneDX
- SWID

`sbomqs` supports SPDX and CycloneDX formats. Support for SWID is incoming.

In addition to supporting these SBOM formats, we support various formats for data representation.

- **SPDX**: json, yaml, rdf and tag-value
- **CycloneDX**: json and xml

## Goal #3: Customizable output

`sbomqs` scoring output can be customized by category or by feature. We understand everyone's needs for scoring differ, hence we allow to customize which categories or features should rsp. should not be included for scoring.

## Category scoring

We have categorized our current features as follows:

- **NTIA-minimum-elements**: Includes features, which help you to quickly understand if an SBOM complies with NTIA's minimum element guidelines.
- **Structural**: Checks if an SBOM complies with the underlying specifications, be it [SPDX](https://spdx.dev/specifications/) or [CycloneDX](https://cyclonedx.org/specification/overview/).
- **Semantic**: Checks meaning of SBOM fields specific to their standard.
- **Quality**: Helps to determine the quality of the data in an SBOM.
- **Sharing**: Helps to determine if an SBOM can be shared.
- [OWASP BOM Maturity Model](https://docs.google.com/spreadsheets/d/1wu6KbgwuokC5357ikrhFN-QkwQ7Pyb6z0zE80sTNNus/edit#gid=0): Work in progress

### Category Aliases

You can use these convenient aliases when specifying categories:
- `ntia` or `NTIA` → `NTIA-minimum-elements`
- `structural` → `Structural`
- `sharing` → `Sharing`
- `semantic` → `Semantic`
- `quality` → `Quality`
- `bsi-v1.1` → BSI TR-03183-2 v1.1 scoring
- `bsi-v2.0` → BSI TR-03183-2 v2.0.0 scoring

## Feature Scoring

We allow running any single feature to be tested against an SBOM.

1. `sbomqs generate features` generates a features.yaml file.
2. Open the features.yaml file and select the categories or features that you want to be enabled.
3. Save and close the file.
4. `sbomqs score  ~/data/app.spdx.json  --configpath features.yaml` use the features.yaml file to apply the changes.

For the list of features currently supported, visit [features.md](./Features.md).

## Goal #4: Consumable output

`sbomqs` provides its scoring output in basic and detailed forms.

The basic output is great for a quick check of the quality of an SBOMs. Once you get a good sense of how the tool works, this can also become the primary way of consuming data from this tool.

```sh
6.0     samples/blogifier-dotnet-SBOM.json
6.9     samples/julia.spdx.json
7.6     samples/sbom.spdx.yaml
```

Detailed output is presented in tabular and json formats, currently:

Tabular format: this format has been inspired by oss scorecard project.

```sh
SBOM Quality Score: 6.0 samples/blogifier-dotnet-SBOM.json
+-----------------------+--------------------------------+-----------+--------------------------------+
|       CATEGORY        |            FEATURE             |   SCORE   |              DESC              |
+-----------------------+--------------------------------+-----------+--------------------------------+
| NTIA-minimum-elements | Doc has creation timestamp     | 10.0/10.0 | doc has creation timestamp     |
|                       |                                |           | 2022-11-04T16:51:54Z           |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have supplier names | 0.0/10.0  | 0/1649 have supplier names     |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have names          | 10.0/10.0 | 1649/1649 have names           |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Doc has relationships          | 0.0/10.0  | doc has 0 relationships        |
+                       +--------------------------------+-----------+--------------------------------+
...
...
```

json format

```json
{
  "run_id": "fc86a94d-7490-4f20-a202-b04bb3cdfde9",
  "timestamp": "2023-02-17T14:58:55Z",
  "creation_info": {
    "name": "sbomqs",
    "version": "v0.0.6-3-g248d059",
    "scoring_engine_version": "1"
  },
  "files": [
    {
      "file_name": "samples/blogifier-dotnet-SBOM.json",
      "spec": "cyclonedx",
      "spec_version": "1.4",
      "file_format": "json",
      "avg_score": 6,
      "num_components" : 3,
      "scores": [
        {
          "category": "Structural",
          "feature": "Spec File Format",
          "score": 10,
          "max_score": 10,
          "description": "provided sbom should be in supported file format for spec: json and version: json,xml"
        }
      ]
    }
  ]
}
```

# Compliance Reports

sbomqs can produce compliance reports for industry standard requirements. Details about compliance implementation are [avaliable here](./Compliance.md).

## Reports

- [BSI TR-03183-2 v2.0.0](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.pdf) (September 2024)
- [BSI TR-03183-2 v1.1](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.pdf) (legacy)
- [Framing Software Component Transparency v3](https://www.cisa.gov/sites/default/files/2024-11/Framing-Software-Component-Transparency-V3-508c.pdf)
- [OpenChain Telco SBOM Guide Version 1.0](https://github.com/OpenChain-Project/Reference-Material/blob/master/SBOM-Quality/Version-1/OpenChain-Telco-SBOM-Guide_EN.md)
- [NTIA minimum element](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) - Coming soon.
- [OWASP SCVS](https://scvs.owasp.org/bom-maturity-model/) - Coming soon.

Example of a BSI v2.0.0 report

```json
{
  "report_name": "Cyber Resilience Requirements for Manufacturers and Products Report",
  "subtitle": "Part 2: Software Bill of Materials (SBOM)",
  "revision": "TR-03183-2 (2.0.0)",
  "run": {
    "id": "375c288b-0928-4066-9e3a-b8655ac29f91",
    "generated_at": "2024-04-18T03:22:56Z",
    "file_name": "samples/photon.spdx.json"
  },
  "tool": {
    "name": "sbomqs",
    "version": "v0.0.30-23-g344a584-dirty",
    "vendor": "Interlynk (https://interlynk.io)"
  },
  "summary": {
    "total_score": 4.20,
    "max_score": 10,
    "required_elements_score": 5.91,
    "optional_elements_score": 2.50
  },
"sections": [
    {
      "section_title": "SBOM formats",
      "section_id": "4",
      "section_data_field": "specification",
      "required": true,
      "element_id": "sbom",
      "element_result": "spdx",
      "score": 10
    },
...
```

Example of a OpenChain Telco SBOM Basic Report

```
➜  sbomqs git:(fix/command-line) ./build/sbomqs compliance -t -b constellation-spdx.json
OpenChain Telco Report
Score:3.1 RequiredScore:3.1 OptionalScore:0.0 for constellation-spdx.json
```

# SBOM Samples

- A sample set of SBOMs is present in the [samples](https://github.com/interlynk-io/sbomqs/tree/main/samples) directory above
- [SBOM Benchmark](https://www.sbombenchmark.dev) is a repository of SBOM and quality score for most popular containers and repositories
- [SBOM Explorer](https://github.com/interlynk-io/sbomex) is a command line utility to search and pull SBOMs
- [SBOM Assembler](https://github.com/interlynk-io/sbomasm) is a command line utility for assembling SBOMs into product SBOMs

# Installation

## Using Prebuilt binaries

```console
https://github.com/interlynk-io/sbomqs/releases
```

## Using Homebrew

```console
brew tap interlynk-io/interlynk
brew install sbomqs
```

## Using Go install

```console
go install github.com/interlynk-io/sbomqs@latest
```

## Using repo

This approach involves cloning the repo and building it.

1. Clone the repo `git clone git@github.com:interlynk-io/sbomqs.git`
2. `cd` into `sbomqs` folder
3. make build
4. To test if the build was successful run the following command `./build/sbomqs version`

# Contributions

We look forward to your contributions, below are a few guidelines on how to submit them

- Fork the repo
- Create your feature/bug branch (`git checkout -b feature/bug`)
- Commit your changes (`git commit -aSm "awesome new feature"`) - commits must be signed
- Push your changes (`git push origin feature/new-feature`)
- Create a new pull-request

# Other Open Source Software tools for SBOMs

- [SBOM Assembler](https://github.com/interlynk-io/sbomasm) - A tool for conditional edits and merging of SBOMs
- [SBOM Seamless Transfer](https://github.com/interlynk-io/sbommv) - A primary tool to transfer SBOM's between different systems.
- [SBOM Search Tool](https://github.com/interlynk-io/sbomgr) - A tool for context aware search in SBOM repositories.
- [SBOM Explorer](https://github.com/interlynk-io/sbomex) - A tool for discovering and downloading SBOM from a public SBOM repository
- [SBOM Benchmark](https://www.sbombenchmark.dev) is a repository of SBOM and quality score for most popular containers and repositories

# Contact

We appreciate all feedback. The best ways to get in touch with us:

- ❓& 🅰️ [Slack](https://join.slack.com/t/sbomqa/shared_invite/zt-2jzq1ttgy-4IGzOYBEtHwJdMyYj~BACA)
- :phone: [Live Chat](https://www.interlynk.io/#hs-chat-open)
- 📫 [Email Us](mailto:hello@interlynk.io)
- 🐛 [Report a bug or enhancement](https://github.com/interlynk-io/sbomex/issues)
- :x: [Follow us on X](https://twitter.com/InterlynkIo)

# Stargazers

If you like this project, please support us by starring it.

[![Stargazers](https://starchart.cc/interlynk-io/sbomqs.svg)](https://starchart.cc/interlynk-io/sbomqs)
