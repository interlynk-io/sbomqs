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

## BSI-V1(Incomming)

```bash
$ sbomqs score -c bsi-v1 sbom.json 
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
