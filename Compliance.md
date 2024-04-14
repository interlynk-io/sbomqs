# Compliance Reports

sbomqs now helps generating compliance reports for your sboms. We support industry standard requirements
like NTIA minimum elements, BSI CRA TR-03183 v1.1 and OWASP SCVS. 

The goal of compliance reports is to verify if the sbom file adheres to these standard, before they are distributed. 

We have explained below how sbomqs approaches compliance reports for BSI CRA TR-03183 v1.1. We are not going to explain
the spec here, but rather go into our intepretation of it. 


The [BSI CRA TR-03183 v1.1](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.pdf?__blob=publicationFile&v=5) which is in draft currently specifies that the compilation of an SBOM is mandatory. Below is how we have derived all the values.

| TR-03183 | TR-03183 field | CycloneDx | SPDX(2.3) | Notes |
| :---     | :---    |     :---      |          :--- | :--- |
|4. SBOM formats| `specification`  | BomFormat     | SPDXversion    | CycloneDX and SPDX only |
|| `specification version`  | SpecVersion     | SPDXversion    | CycloneDX 1.4 and above, SPDX 2.3 and above |
|5.1 Level of Detail| `Build SBOM`     | metadata->lifecycles (1.5 and above)       |  no-deterministic-field      | |
|| `Depth`   | dependencies, compositions     | relationships    | A complex topic, mostly resolved via attestations via compositions, but spdx lacks that field now|
|5.2.1 Required SBOM fields| `creator` | metadata->authors, metadata->supplier | creator | We are primarily looking for email or url from these fields, if the name exists but email/url missing its deemed non-compliant|
|    | | metadata->manufacturer | | |
|| `timestamp`| metadata->timestamp| created |  |
|5.2.2 Required Component fields| `creator` | component->supplier | packageSupplier, packageOriginator | Looking for email or url, for spdx, we check supplier then originatior(manufacturer)|
|| `name` | component->name| package->name| |
|| `version` | component->version| package->version| |
|| `dependencies` | dependencies, compositions| relationships| cdx we look for attestations via compositions, spdx nothing exists|
|| `license`| component->license| packageConcluded, packageDeclated| we lookup sdpx,spdx-exceptions,aboutcode, and licenseRef-|
|| `hash` | component->hashes | package->checksums | we only look for sha-256|
|5.3.1 Additional Component fields | `SBOM-URI`| serialNumber, version | namespace | for cdx bom-link is considered a URN |
| | `source code uri`| component->externalReferences->type (vcs) | no-deterministic-field | |
| | `URI of the executable form`| component->externalReferences->type (distribution/distribution-intake) | PackageDownloadLocation | |
| | `hash of source code`| no-deterministic-field | package->PackageVerificationCode | |
| | `other uniq identifiers`| component->cpe, component->purl| package->externalReference->security (cpe/purl) | |