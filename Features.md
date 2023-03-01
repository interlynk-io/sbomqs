
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

  

Name | Description | Short name

----------- | ----------------------------------------- |

SBOM Specification | This criteria checks if the sbom file supports SPDX or CycloneDX | sbom-spec |

SBOM Spec Version | This criteria checks if the sbom file is using the correct spec versions of the detected spec | spec-version |

SBOM Spec file format | checks if the sbom file is in a spec compatible format e.g json, xml, rdf | spec-file-format |

File is parsable | checks if the file can be parsed | spec-parsable |

Components have Supplier Name | checks if the sbom components have supplier names | comp-supplier-name | 

Components have names | checks if the sbom components have names | comp-name |

Components have versions | checks if the sbom components have versions | comp-version |

Components have uniq ids | checks if the sbom components have unique identifiers (See [Table 1](https://www.ntia.gov/files/ntia/publications/sbom_formats_survey-version-2021.pdf)) |  comp-uniq-ids |

Components have licenses | checks if the sbom components have licenses | comp-licence |

Components have checksums | checks if the sbom components have checksums | comp-checksums |

Components have valid spdx licenses | checks if the sbom components have licenses which match the spdx license list | comp-valid-licence |

Components dont have deprecated licenses| checks if the sbom components dont have licenses that are deprecated | comp-no-deprecat-licence |

Components have multiple vulnerability lookup ids| checks if the sbom components have both purl and cpe |
 comp-multi-vulnerability-id |
Components have any vulnerability lookup ids| checks if the sbom components at least one of purl or cpe | comp-any-vulnerability-id |

Components have restricted licenses | checks if the sbom components have restricted licenses which match the restricted license list | comp-no-restric-licence |

Components have primary purpose defined | checks if the sbom components have a primary purpose defined e.g application/library| comp-primary-purpose |

Doc has Relations | checks if sbom has specified relations between its components | doc-relationship |

Doc has Authors | checks if sbom has authors i.e person/ org or tool | doc-author |

Doc has creation timestamp | check if the sbom has a creation timestamp | doc-timestamp |

Doc has require fields | check if the sbom has all the required fields as specified by the (spdx/cdx) spec | doc-all-req-fileds |

Doc has sharable license | check if the sbom doc has an unemcumbered license which can aid in sharing | doc-licence |


Now you generate specific category and features depends on the need, There are 2 way you can use this
1. Using Short name (doc-licence,comp-no-restric-licence,comp-primary-purpose,comp-no-deprecat-licence,comp-valid-licence,comp-checksums,comp-licence,doc-all-req-fileds,doc-timestamp,doc-author,doc-relationship,comp-uniq-ids,comp-version,comp-name,comp-supplier-name,spec-parsable,spec-file-format,spec-version,sbom-spec,comp-any-vulnerability-id,comp-multi-vulnerability-id)

          eg. ./sbomqs score --filepath ./samples/sbomqs.cdx-modtool.json --features comp-any-vulnerability-id,doc-licence
        SBOM Quality Score:5.0  components:14   ./samples/sbomqs.cdx-modtool.json
        +----------+--------------------------------+-----------+--------------------------------+
        | CATEGORY |            FEATURE             |   SCORE   |              DESC              |
        +----------+--------------------------------+-----------+--------------------------------+
        | Quality  | Components have any            | 10.0/10.0 | 14/14 components have any      |
        |          | vulnerability lookup id        |           | lookup id                      |
        +----------+--------------------------------+-----------+--------------------------------+
        | Sharing  | Doc sharable license           | 0.0/10.0  | doc has a sharable license     |
        |          |                                |           | free 0 :: of 0                 |
        +----------+--------------------------------+-----------+--------------------------------+

2. Using featue config, to use this follow below steps
   a. For getting default feature config used generate command with features ```./sbomqs generate features```
   b.  Now you will get the feature.yaml file with category and features with enabled true/faslse based on reuirement
            
        - name: NTIA-minimum-elements
          enabled: true
          criteria:
            - shortName: comp-supplier-name
              description: Components have supplier names
              enabled: true
            - shortName: comp-name
              description: Components have names
              enabled: true
            - shortName: comp-version
              description: Components have versions
              enabled: true
            - shortName: comp-uniq-ids
              description: Components have uniq ids
              enabled: true
            - shortName: doc-relationship
              description: Doc has relationships
              enabled: true
            - shortName: doc-author
              description: Doc has authors
              enabled: true
            - shortName: doc-timestamp
              description: Doc has creation timestamp
              enabled: true
        - name: Quality
          criteria:
            - shortName: comp-supplier-name
              description: Components have supplier names
              enabled: true
        - shortName: comp-name
          description: Components have names
          enabled: true
        - shortName: comp-version
          description: Components have versions
          enabled: true
        - shortName: comp-uniq-ids
          description: Components have uniq ids
          enabled: true
        - shortName: doc-relationship
          description: Doc has relationships
          enabled: true
        - shortName: doc-author
          description: Doc has authors
          enabled: true
        - shortName: doc-timestamp
          description: Doc has creation timestamp
          enabled: true
    
   ``` ./sbomqs score --filepath ./samples/sbomqs.cdx-modtool.json --configpath ./features.yaml ```

        SBOM Quality Score:0.0  components:14   ./samples/sbomqs.cdx-modtool.json
        +-----------------------+--------------------------------+----------+--------------------------+
        |       CATEGORY        |            FEATURE             |  SCORE   |           DESC           |
        +-----------------------+--------------------------------+----------+--------------------------+
        | NTIA-minimum-elements | Components have supplier names | 0.0/10.0 | 0/14 have supplier names |
        +-----------------------+--------------------------------+----------+--------------------------+
