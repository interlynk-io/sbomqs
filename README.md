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

`sbomqs` is your primary tool to assess the quality of sbom's. The higher the score the more consumable your sboms are. 

```sh
go install github.com/interlynk-io/sbomqs@latest
```
other installation [options](#installation).

# Usage
#### Quality Score for a single SBOM.
```sh
$sbomqs score <sbom-file>
```

#### Quality Score with a shareable link at [sbombenchmark.dev](https://sbombenchmark.dev/).  
```sh
sbomqs share <sbom-file>
```

Example:
```sh
$sbomqs share cdxgen-9.5.1_alpine-latest.cdx.json
5.9	cdxgen-9.5.1_alpine-latest.cdx.json
ShareLink: https://sbombenchmark.dev/user/score?id=a97af1bf-4c9d-4a55-8524-3d4bcee0b9a4
```

#### Quality Score for your dependency track projects.
```sh
$sbomqs dtrackScore  -u <dt-host-url> -k <dt-api-key> <project-uuid>
```

Example:
```sh
$sbomqs dtrackScore  -u "http://localhost:8080/" -k "IIcfPA9qc1F4IkQFa2FqQJoTwcfQI" bbd4434d-8062-4e59-a323-3b416701c948
```
![alt text](./images/dt.png "Depedency Track with sbomqs score")

#### Quality Score in an AirGapped Environment
```sh
$INTERLYNK_DISABLE_VERSION_CHECK=true ./build/sbomqs score ~/wrk/sbom*/samples/*.json  -b
```

#### Quality Score using containers
```sh
$docker run -v <path of sbom file or folder>:/app/inputfile ghcr.io/interlynk-io/sbomqs score /app/inputfile
```
Example
```sh
$docker run -v $(pwd)/samples/sbomqs-cdx-cgomod.json:/app/inputfile ghcr.io/interlynk-io/sbomqs score -j /app/inputfile
```
```
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

# What is a high quality SBOM
A high quality SBOM should allow for managements of assets, license, vulnerabilities, Intellectual Property, configuration management and incident response. 

A quality SBOM is one that is accurate, complete, and up-to-date. There are many factors that go into constructing a high quality sbom
1. Identify & list all components of your product along with their transitive dependencies. 
2. List all your components along with their versions & content checksums. 
3. Include accurate component licenses. 
4. Include accurate lookup identifiers e.g. [purls](https://github.com/package-url/purl-spec) or [CPEs](https://csrc.nist.gov/publications/detail/nistir/7698/final). 
5. Quality SBOM depends a lot upon which stage of the lifecycle it has been generated at, we believe closer to the build time is ideal. 
6. Signed sboms.
7. Should layout information based on industry standard specs like CycloneDX, SPDX and SWID. 


# Goals

The main goals of the utility are
1. Make it easy and fast to assess the quality of your sbom's, generated or acquired. 
2. Support all well known SBOM standards. 
3. Scoring output should be customizable.
4. Scoring output should be consumable. 

## Goal #1: Easy & Fast 

SBOM can be generated using both commercial and open-source tooling. As consumers of SBOM we wanted a fast & easy way to assess the quality of an SBOM. An SBOM with a low score, needs to be re-evaluated or rejected. 

`sbomqs` makes getting a quick assessment, relatively painless. Just point. 

```sh
sbomqs score samples/julia.spdx.tv -b 
6.9     samples/julia.spdx.json
```

## Goal #2: SBOM Standards

NTIA recommends the following standards for SBOM's
- SPDX
- CycloneDX
- SWID

`sbomqs` supports SPDX and CycloneDX formats. Support for SWID is incoming. 

In addition to supporting the SBOM formats, we support various file formats 

- **SPDX**: json, yaml, rdf and tag-value
- **CycloneDX**: json and xml

## Goal #3: Customizable output 

`sbomqs` scoring output can be customized by category or by feature. We understand everyone needs for scoring would not match ours, we have added customizability around which categories or features should or should not be included for scoring. 

#### Category Scoring
We have categorized our current features into the following categories 
- **NTIA-minimum-elements**: Includes features, which help you quickly understand if your sbom's comply with NTIA minimum element guidelines. 
- **Structural**: We check if the SBOM complies with the underlying specifications, be it [SPDX](https://spdx.dev/specifications/) or [CycloneDX](https://cyclonedx.org/specification/overview/)
- **Semantic**: We check meaning of SBOM fields specific to their standard. 
- **Quality**: Help determine the quality of the data present in the sbom.
- **Sharing**: Helps determine if the SBOM can be shared. 
- [OWASP BOM Maturity Model](https://docs.google.com/spreadsheets/d/1wu6KbgwuokC5357ikrhFN-QkwQ7Pyb6z0zE80sTNNus/edit#gid=0): Work in progress


#### Feature Scoring
We allow running any single feature to be tested against an SBOM.

1. `sbomqs generate features`, this generated a features.yaml file 
2. Open the features.yaml file and select the categories or features that you would like enabled 
3. Save & close the file.
4. `sbomqs score  ~/data/app.spdx.json  --configpath features.yaml` use the yaml file to apply the changes. 

For the list of features currently supported, visit [features.md](./Features.md). 

## Goal #4: Consumable output 

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


# SBOM Samples
- A sample set of SBOM is present in the [samples](https://github.com/interlynk-io/sbomqs/tree/main/samples) directory above
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
- Create your feature/bug branch (`git checkout -b feature/new-feature`)
- Commit your changes (`git commit -am "awesome new feature"`)
- Push your changes (`git push origin feature/new-feature`)
- Create a new pull-request

# Contact 
We appreciate all feedback, the best way to get in touch with us
- hello@interlynk.io
- https://github.com/interlynk-io/sbomqs/issues 
- https://twitter.com/InterlynkIo


# Stargazers

If you like this project, please support us by starring it. 

[![Stargazers](https://starchart.cc/interlynk-io/sbomqs.svg)](https://starchart.cc/interlynk-io/sbomqs)
