
## What is a high quality SBOM

A high quality SBOM should support managing software assets, license information and Intellectual Property as well as provide a base for configuration management, vulnerability handling and incident response.

A quality SBOM is one that is accurate, complete, and up-to-date. There are many factors that go into constructing a high quality SBOM.

1. Identify & list all components of your product along with their transitive dependencies.
2. List all your components along with their versions & content checksums.
3. Include accurate component licenses.
4. Include accurate lookup identifiers e.g. [purls](https://github.com/package-url/purl-spec) or [CPEs](https://csrc.nist.gov/publications/detail/nistir/7698/final).
5. Quality SBOM depends a lot upon which stage of the lifecycle it has been generated at, we believe closer to the build time is ideal.
6. Signed SBOMs.
7. Should layout information based on industry standard specs like CycloneDX, SPDX and SWID.

## Goals

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

## Compliance Reports

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
