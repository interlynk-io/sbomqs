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

# `sbomqs`: Quality metrics for sbom's 
---
[![Go Reference](https://pkg.go.dev/badge/github.com/interlynk-io/sbomqs.svg)](https://pkg.go.dev/github.com/interlynk-io/sbomqs)
[![Go Report Card](https://goreportcard.com/badge/github.com/interlynk-io/sbomqs)](https://goreportcard.com/report/github.com/interlynk-io/sbomqs)

`sbomqs` is your primary tool to assess the quality of sboms. The higher the score the more consumable your sboms are. 

```sh
go install github.com/interlynk-io/sbomqs@latest
```
other installation [options](#installation).

# What is a high quality SBOM
A high quailty SBOM should allow for managements of assets, license, vulnerabilities, Intellectual Property, configuration management and incidence response. 

A quality SBOM is one that is accurate, complete, and up-to-date.There are many factors that go into constructing a good high quality sbom
1. Identify & list all components of your product along with their transitive dependencies. 
2. List all your components along with their versions & content checksums. 
3. Include accurate component licenses. 
4. Include accurate lookup identifiers i.e Purls/CPE. 
5. Quality SBOM depends a lot upon which stage of the lifecycle it has been generated at, we believe closer to the build time is ideal. 
6. Signed sboms.
7. Should layout information based on industry standard specs like CycloneDX, SPDX and SWID. 


# Goals

The main goals of the utility are
1. Make it easy and fast to asses the quality of your sboms, generated or acquired. 
2. Support all well known sbom standards. 
3. Scoring output should be customizable.
4. Scoring output should be consumable. 

## Goal #1: Easy & Fast 

SBOM can be generated using both commercial and open-source tooling. As consumers of SBOM we wanted a fast & easy way to assess the quality of an SBOM. An sbom with a low score, needs to be re-evaluated or rejected. 

`sbomqs` makes getting a quick assesment, relatively painless. Just point. 

```sh
sbomqs score --filepath samples/julia.spdx.tv --reportFormat basic 
6.9     samples/julia.spdx.json
```

## Goal #2: SBOM Standards

NTIA recommends the following standards for SBOM's
- SPDX
- CycloneDX
- SWID

`sbomqs` supports SPDX and CycloneDX formats. Support for SWID is incoming. 

In additon to supporting the sbom formats, we support various file formats 

- **SPDX**: json, yaml, rdf and tag-value
- **CycloneDX**: json and xml

## Goal #3: Customizable ouptut 

`sbomqs` scoring output can be customized by category or by feature. We understand everyone needs for scoring would not match ours, we have added customizability around which categories or features should or should not be included for scoring. 

#### Category Scoring
We have categorized our current features into the following categories 
- **NTIA-minimum-elements**: Includes features, which help you quickly understand if your sboms comply with NTIA minimum element guidelines. 
- **Structural**: We check if the SBOM complies with basic SPEC guides, be it SPDX or CycloneDX
- **Semantic**: We check meaning of sbom fields specific to their standard. 
- **Quality**: Help determine the quality of the data present in the sbom.
- **Sharing**: Helps determine if the sbom can be shared. 
- [OWASP BOM Maturity Model](https://docs.google.com/spreadsheets/d/1wu6KbgwuokC5357ikrhFN-QkwQ7Pyb6z0zE80sTNNus/edit#gid=0): Work in progress


#### Feature Scoring
At present individual features cannot be selected. We are working on adding this 
[here](https://github.com/interlynk-io/sbomqs/issues/19)

For the list of features currently supported, visit [features.md](./Features.md). 

## Goal #4: Consumable ouptut 

`sbomqs` provides its scoring output in basic and detailed forms. 

Basic output is great for a quick check of the quality of our sboms. Once you get a good sense of how the tool works, this could also be your primary way of consuming data from this tool. 

```sh 
6.0     samples/blogifier-dotnet-SBOM.json
6.9     samples/julia.spdx.json
7.6     samples/sbom.spdx.yaml
```

Detailed output is presented in tabular and json formats currently 

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


# Installation 

## Using Prebuilt binaries 

```console
https://github.com/interlynk-io/sbomqs/releases
```

## Using Go install

```console
go install github.com/interlynk-io/sbomqs@latest
```

## Using repo

This approach invovles cloning the repo and building it. 

1. Clone the repo `git clone git@github.com:interlynk-io/sbomqs.git`
2. `cd` into `sbomqs` folder 
3. make build
4. To test if the build was successful run the following command `./build/sbomqs version`


# Contributions
We look forward to your contributions, below are a few guidelines on how to submit them 

- Fork the repo
- Create your feature/bug branch (`git checkout -b feature/new-feature`)
- Commit your changes (`git commit -am "awesome new feature"`)
- Push your changes (`git push origin feature/new-feature`)
- Create a new pull-request

# Stargazers

[![Stargazers](https://starchart.cc/interlynk-io/sbomqs.svg)](https://starchart.cc/interlynk-io/sbomqs)
