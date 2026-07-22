// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package profiles

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cdxCompSupplierWithNameURLAndEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    }
  ]
}
`)

var spdxCompSupplierAsPersonWithNameAndEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "supplier": "Person: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

// SPDX 3.0 - Component Supplier with Person name and email
var spdx3CompSupplierWithPersonNameAndEmail = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "Person",
      "@id": "_:supplier1",
      "name": "Samantha Wright",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "john.doe@example.com"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "suppliedBy": "_:supplier1"
    }
  ]
}
`)

var spdxCompSupplierAsOrganizationWithNameAndEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "supplier": "Organization: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

// SPDX 3.0 - Component Supplier with Organization name and email
var spdx3CompSupplierWithOrganizationNameAndEmail = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "Organization",
      "@id": "_:supplier1",
      "name": "Example Organization Inc",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "contact@example.com"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "suppliedBy": "_:supplier1"
    }
  ]
}
`)

var cdxCompSupplierWithNameAndURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "supplier": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ] 
      }
    }
  ]
}
`)

var spdxCompSupplierWithPersonEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Person: (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

// SPDX 3.0 - Component Supplier with Person name and email
var spdx3CompSupplierWithPersonEmail = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "Person",
      "@id": "_:supplier1",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "john.doe@example.com"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "suppliedBy": "_:supplier1"
    }
  ]
}
`)

var spdxCompSupplierWithOrganizationEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Organization:  (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

// SPDX 3.0 - Component Supplier with Organization name and email
var spdx3CompSupplierWithOrganizationEmail = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "Organization",
      "@id": "_:supplier1",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "contact@example.com"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "suppliedBy": "_:supplier1"
    }
  ]
}
`)
var cdxCompSupplierWithNameAndEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "supplier": {
        "name": "Acme, Inc.",
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    }
  ]
}
`)

var cdxCompSupplierWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": {
        "name": "Acme, Inc."
      }
    }
  ]
}
`)

var spdxCompSupplierWithPersonName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Person: Samantha Wright",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

// SPDX 3.0 - Component Supplier with Person name
var spdx3CompSupplierWithPersonName = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "Person",
      "@id": "_:supplier1",
      "name": "Samantha Wright"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "suppliedBy": "_:supplier1"
    }
  ]
}
`)

var spdxCompSupplierWithOrganizationName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Organization: Samantha Wright",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

// SPDX 3.0 - Component Supplier with Organization name
var spdx3CompSupplierWithOrganizationName = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "Organization",
      "@id": "_:supplier1",
      "name": "Example Organization Inc"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "suppliedBy": "_:supplier1"
    }
  ]
}
`)

var cdxCompSupplierAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0"
    }
  ]
}
`)

var spdxCompSupplierAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person:  (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

// SPDX 3.0 - Component Supplier absent
var spdx3CompSupplierAbsent = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0"
    }
  ]
}
`)

var cdxCompSupplierWithEmptyName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {
        "name": ""
      }
    }
  ]
}
`)

var spdxCompSupplierWithPersonNameEmpty = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person:  (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Person:  ( )",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

// SPDX 3.0 - Component Supplier with Person name empty
var spdx3CompSupplierWithPersonNameEmpty = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "Person",
      "@id": "_:supplier1",
      "name": " "
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "suppliedBy": "_:supplier1"
    }
  ]
}
`)

var cdxCompSupplierWithWhiteSpaceName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {
        "name": "  "
      }
    }
  ]
}
`)

var cdxCompManufacturerWithNameURLAndEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "manufacturer": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    }
  ]
}
`)

var cdxCompManufacturerWithNameAndURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ] 
      }
    }
  ]
}
`)

var cdxCompManufacturerWithNameAndEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc.",
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    }
  ]
}
`)

var cdxCompManufacturerWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc."
      }
    }
  ]
}
`)

var cdxCompManufacturerAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1"
    }
  ]
}
`)

var cdxCompManufacturerWithEmptyName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": ""
      }
    }
  ]
}
`)

var cdxCompManufacturerWithWhiteSpaceName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "  "
      }
    }
  ]
}
`)

var cdxCompManufacturerMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {}
    }
  ]
}
`)

var cdxMultipleCompWithSupplierAndManufacturer = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "type": "application",
      "name": "STME Application",
      "version": "1.1.1",
      "supplier": {
        "name": "STME, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "STME Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    }
  ]
}
`)

var cdxMultipleCompWithBothSupplier = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "supplier": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "type": "application",
      "name": "STME Application",
      "version": "1.1.1",
      "supplier": {
        "name": "STME, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "STME Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    }
  ]
}
`)

var cdxMultipleCompWithOneSupplierAndAnotherMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "supplier": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "type": "application",
      "name": "STME Application",
      "version": "1.1.1"
    }
  ]
}
`)

var cdxMultipleCompWithBothManufacturer = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "type": "application",
      "name": "STME Application",
      "version": "1.1.1",
      "manufacturer": {
        "name": "STME, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "STME Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    }
  ]
}
`)

var cdxMultipleCompWithOneManufacturerAndAnotherMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "type": "application",
      "name": "STME Application",
      "version": "1.1.1"
    }
  ]
}
`)

var cdxMultipleCompWithOneSupplierOneManufacturerAndOneMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "supplier": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "type": "application",
      "name": "STME Application",
      "version": "1.1.1",
      "supplier": {
        "name": "STME, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "STME Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "type": "application",
      "name": "curl",
      "version": "4.1.1"
    }
  ]
}
`)

func TestNTIACompSupplier(t *testing.T) {
	ctx := context.Background()

	// cdxCompSupplierWithNameURLAndEmail
	t.Run("cdxCompSupplierWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierAsPersonWithNameAndEmail
	t.Run("spdxCompSupplierAsPersonWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAsPersonWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompSupplierWithPersonNameAndEmail
	t.Run("spdx3CompSupplierAsPersonWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompSupplierWithPersonNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierAsOrganizationWithNameAndEmail
	t.Run("spdxCompSupplierAsOrganizationWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAsOrganizationWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompSupplierWithOrganizationNameAndEmail
	t.Run("spdx3CompSupplierAsOrganizationWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompSupplierWithOrganizationNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithNameAndURL
	t.Run("cdxCompSupplierWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithPersonEmail
	t.Run("spdxCompSupplierWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompSupplierWithPersonEmail
	t.Run("spdx3CompSupplierWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompSupplierWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithOrganizationEmail
	t.Run("spdxCompSupplierWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompSupplierWithOrganizationEmail
	t.Run("spdx3CompSupplierWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompSupplierWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithNameAndEmail
	t.Run("cdxCompSupplierWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithName
	t.Run("cdxCompSupplierWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithPersonName
	t.Run("spdxCompSupplierWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompSupplierWithPersonName
	t.Run("spdx3CompSupplierWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompSupplierWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithOrganizationName
	t.Run("spdxCompSupplierWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompSupplierWithOrganizationName
	t.Run("spdx3CompSupplierWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompSupplierWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierAbsent
	t.Run("cdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierAbsent
	t.Run("spdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompSupplierAbsent
	t.Run("spdx3CompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithEmptyName
	t.Run("cdxCompSupplierWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithPersonNameEmpty
	t.Run("spdxCompSupplierWithPersonNameEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonNameEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompSupplierWithPersonNameEmpty
	t.Run("spdx3CompSupplierWithPersonNameEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompSupplierWithPersonNameEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithWhiteSpaceName
	t.Run("cdxCompSupplierWithWhiteSpaceName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithWhiteSpaceName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithNameURLAndEmail
	t.Run("cdxCompManufacturerWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "manufacturer information declared for all components (supplier not present)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithNameAndURL
	t.Run("cdxCompManufacturerWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "manufacturer information declared for all components (supplier not present)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithNameAndEmail
	t.Run("cdxCompManufacturerWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "manufacturer information declared for all components (supplier not present)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithName
	t.Run("cdxCompManufacturerWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "manufacturer information declared for all components (supplier not present)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerAbsent
	t.Run("cdxCompManufacturerAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithEmptyName
	t.Run("cdxCompManufacturerWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithWhiteSpaceName
	t.Run("cdxCompManufacturerWithWhiteSpaceName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithWhiteSpaceName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerMissingName
	t.Run("cdxCompManufacturerMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithSupplierAndManufacturer
	t.Run("cdxMultipleCompWithSupplierAndManufacturer", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithSupplierAndManufacturer, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for 1 components; manufacturer used as fallback for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithBothSupplier
	t.Run("cdxMultipleCompWithBothSupplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithBothSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithOneSupplierAndAnotherMissing
	t.Run("cdxMultipleCompWithOneSupplierAndAnotherMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithOneSupplierAndAnotherMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information declared for 1 of 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithBothManufacturer
	t.Run("cdxMultipleCompWithBothManufacturer", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithBothManufacturer, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "manufacturer information declared for all components (supplier not present)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithOneManufacturerAndAnotherMissing
	t.Run("cdxMultipleCompWithOneManufacturerAndAnotherMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithOneManufacturerAndAnotherMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information declared for 1 of 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithOneSupplierOneManufacturerAndOneMissing
	t.Run("cdxMultipleCompWithOneSupplierOneManufacturerAndOneMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithOneSupplierOneManufacturerAndOneMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 6.6666666666666, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information declared for 2 of 3 components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxMultipleCompWithValidPURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "purl": "pkg:golang/github.com/pkg/errors@0.9.1"
    },
    {
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
      "purl": "pkg:golang/cel.dev/expr@v0.19.1?type=module\u0026goos=linux\u0026goarch=amd64"
    }
  ]
}
`)

var cdxMultipleCompWithOnePURLAndAnotherCPE = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "purl": "pkg:golang/github.com/pkg/errors@0.9.1"
    },
    {
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
      "cpe": "cpe:/golang/cel.dev/expr:v0.19.1"
    }
  ]
}
`)

var cdxMultipleCompWithOnePURLAndAnotherMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "purl": "pkg:golang/github.com/pkg/errors@0.9.1"
    },
    {
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1"
    }
  ]
}
`)

var cdxMultipleCompWithOneCPEAndAnotherMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0"
    },
    {
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
      "cpe": "cpe:/golang/cel.dev/expr:v0.19.1"
    }
  ]
}
`)

// SPDX 3.0 - Component with valid PURL
var spdx3CompPURLValid = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "externalIdentifier": [
        {
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:golang/github.com/pkg/errors@0.9.1"
        }
      ]
    }
  ]
}
`)

// SPDX 3.0 - Component with invalid PURL
var spdx3CompInValidPURL = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "externalIdentifier": [
        {
          "externalIdentifierType": "packageUrl",
          "identifier": "kskowo2ke8eiemdndn"
        }
      ]
    }
  ]
}
`)

// SPDX 3.0 - Component with invalid PURL
var spdx3CompdPURLWhitespace = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "externalIdentifier": [
        {
          "externalIdentifierType": "packageUrl",
          "identifier": " "
        }
      ]
    }
  ]
}
`)

// SPDX 3.0 - Component with PURL absent
var spdx3CompPURLAbsent = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "my-application",
      "software_packageVersion": "1.0.0"
    }
  ]
}
`)

func TestNTIACompUniqueID(t *testing.T) {
	ctx := context.Background()

	// cdxCompValidPURL
	t.Run("cdxCompValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompPURLValid
	t.Run("spdxCompPURLValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLValid, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompPURLValid
	t.Run("spdx3CompPURLValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompPURLValid, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLInValid
	t.Run("cdxCompPURLInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLInValid, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompInValidPURL
	t.Run("spdxCompInValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompInValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompInValidPURL
	t.Run("spdx3CompInValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompInValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLWithEmptyString
	t.Run("cdxCompPURLWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLWhitespace
	t.Run("cdxCompPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompPURLWhitespace
	t.Run("spdxCompPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})
	// spdx3CompdPURLWhitespace
	t.Run("spdx3CompdPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompdPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLAbsent
	t.Run("cdxCompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompPURLAbsent
	t.Run("spdxCompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3CompPURLAbsent
	t.Run("spdx3CompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLWrongType
	t.Run("cdxCompPURLWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// spdxCompPURLWrongType
	t.Run("spdxCompPURLWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxMultipleCompWithValidPURL
	t.Run("cdxMultipleCompWithValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithOnePURLAndAnotherCPE
	t.Run("cdxMultipleCompWithOnePURLAndAnotherCPE", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithOnePURLAndAnotherCPE, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL, CPE)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithOnePURLAndAnotherMissing
	t.Run("cdxMultipleCompWithOnePURLAndAnotherMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithOnePURLAndAnotherMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for 1 of 2 components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxMultipleCompWithOneCPEAndAnotherMissing
	t.Run("cdxMultipleCompWithOneCPEAndAnotherMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxMultipleCompWithOneCPEAndAnotherMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithUniqID(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for 1 of 2 components (CPE)", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxSBOMAuthorWithNameAndEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "Samantha Wright",
        "email": "samantha.wright@example.com"
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMAuthorWithPersonNameAndEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author with Person email only
var spdx3SBOMAuthorWithPersonNameAndEmail = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:person1"]
    },
    {
      "type": "Person",
      "@id": "_:person1",
      "name": "Samantha Wright",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "samantha.wright@example.com"
        }
      ]
    }
  ]
}
`)

var spdxSBOMAuthorWithOrganizationNameAndEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Organization: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author with Organization name and email
var spdx3SBOMAuthorWithOrganizationNameAndEmail = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:org1"]
    },
    {
      "type": "Organization",
      "@id": "_:org1",
      "name": "samantha wright",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "samantha.wright@example.com"
        }
      ]
    }
  ]
}
`)

var cdxSBOMAuthorWithEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "authors": [
      {
        "bom-ref": "author-1",
        "email": "samantha.wright@example.com"
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMAuthorWithPersonEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Person: (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author with Person email only
var spdx3SBOMAuthorWithPersonEmail = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:person1"]
    },
    {
      "type": "Person",
      "@id": "_:person1",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "samantha.wright@example.com"
        }
      ]
    }
  ]
}
`)

var spdxSBOMAuthorWithOrganizationEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Organization:  (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author with Organization email only
var spdx3SBOMAuthorWithOrganizationEmail = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:org1"]
    },
    {
      "type": "Organization",
      "@id": "_:org1",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "samantha.wright@example.com"
        }
      ]
    }
  ]
}
`)

var cdxSBOMAuthorWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "Samantha Wright"
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMAuthorWithPersonName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Person: Samantha Wright"
    ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author with Person name only
var spdx3SBOMAuthorWithPersonName = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:person1"]
    },
    {
      "type": "Person",
      "@id": "_:person1",
      "name": "Samantha Wright"
    }
  ]
}
`)

var spdxSBOMAuthorWithOrganizationName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Organization: Samantha Wright"
    ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author with Organization name only
var spdx3SBOMAuthorWithOrganizationName = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:org1"]
    },
    {
      "type": "Organization",
      "@id": "_:org1",
      "name": "Samantha Wright"
    }
  ]
}
`)

// SPDX 3.0 - SBOM Author with Organization
var spdx3SBOMAuthorWithOrganization = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:org1"]
    },
    {
      "type": "Organization",
      "@id": "_:org1",
      "name": "Example Organization Inc"
    }
  ]
}
`)

// SPDX 3.0 - SBOM Author with Person
var spdx3SBOMAuthorWithPerson = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:person1"]
    },
    {
      "type": "Person",
      "@id": "_:person1",
      "name": "John Doe"
    }
  ]
}
`)

var spdxSBOMAuthorAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z"
    },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author absent
var spdx3SBOMAuthorAbsent = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": []
    }
  ]
}
`)

var cdxSBOMAuthorMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "authors": []
  },
  "components": []
}
`)

var spdxSBOMCreatorMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": []
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Creator missing (no createdBy)
var spdx3SBOMCreatorMissing = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z"
    }
  ]
}
`)

var spdxSBOMAuthorPersonMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Person: "
    ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author Person missing (empty name)
var spdx3SBOMAuthorPersonMissing = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:person1"]
    },
    {
      "type": "Person",
      "@id": "_:person1",
      "name": ""
    }
  ]
}
`)

var spdxSBOMAuthorOrganizationMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Organization: "
    ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Author Organization missing (empty name)
var spdx3SBOMAuthorOrganizationMissing = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:org1"]
    },
    {
      "type": "Organization",
      "@id": "_:org1",
      "name": ""
    }
  ]
}
`)

var cdxSBOMAuthorsWithNameAndEmailEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "",
        "email": ""
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMCreatorsWithEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [""]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Creators with empty string
var spdx3SBOMCreatorsWithEmptyString = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": []
    }
  ]
}
`)

var cdxSBOMAuthorsWithEmptyArray = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "authors": []
  },
  "components": []
}
`)

var cdxSBOMAuthorsWithEmptyArrayObject = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "authors": [{}]
  },
  "components": []
}
`)

var spdxSBOMAuthorsWithEmptyArray = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": []
  },
  "packages": []
}
`)

var cdxSBOMAuthorsWithWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "authors": {}
  },
  "components": []
}
`)

var spdxSBOMCreatorsWithWrongTypeSomeValue = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": ["foobar"]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Creators with wrong type (string instead of agent reference)
var spdx3SBOMCreatorsWithWrongType = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["foobar"]
    }
  ]
}
`)

var spdxSBOMCreatorsWithWhitespace = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": ["    "]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Creators with whitespace
var spdx3SBOMCreatorsWithWhitespace = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["    "]
    }
  ]
}
`)

var cdxSBOMToolWithNameAndVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "group": "Awesome Vendor",
          "name": "Awesome Tool",
          "version": "9.1.2"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolWithNameAndVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Tool: Awesome Tool-9.1.2"
    ]
  },
  packages: []
}
`)

// SPDX 3.0 - SBOM Tool with name and version (via createdUsing Tool)
// Note: SPDX 3.0 Tool has no software_version field; version is embedded in name
var spdx3SBOMToolWithNameAndVersion = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": [],
      "createdUsing": ["_:tool1"]
    },
    {
      "type": "Tool",
      "spdxId": "_:tool1",
      "name": "Awesome Tool-9.1.2"
    }
  ]
}
`)

var cdxSBOMToolWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "group": "Awesome Vendor",
          "name": "Awesome Tool"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolWithName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Tool: Awesome Tool"
    ]
  },
  packages: []
}
`)

// SPDX 3.0 - SBOM Tool with name only (via createdUsing Tool)
var spdx3SBOMToolWithName = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": [],
      "createdUsing": ["_:tool1"]
    },
    {
      "type": "Tool",
      "spdxId": "_:tool1",
      "name": "Awesome Tool"
    }
  ]
}
`)

var cdxSBOMToolWithVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "group": "Awesome Vendor",
          "version": "9.1.2"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolWithVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Tool: -9.1.2"
    ]
  },
  packages: []
}
`)

// SPDX 3.0 - SBOM Tool with version only (no name - edge case)
// Note: SPDX 3.0 Tool has no software_version field; version is embedded in name
var spdx3SBOMToolWithVersion = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": [],
      "createdUsing": ["_:tool1"]
    },
    {
      "type": "Tool",
      "spdxId": "_:tool1",
      "name": "-9.1.2"
    }
  ]
}
`)

var cdxSBOMToolAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMToolAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {},
  "packages": []
}
`)

// SPDX 3.0 - SBOM Tool absent (no createdUsing)
var spdx3SBOMToolAbsent = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": []
    }
  ]
}
`)

var cdxSBOMToolMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {}
  },
  "components": []
}
`)

var spdxSBOMToolMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": []
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Tool missing (creationInfo present but no tool)
var spdx3SBOMToolMissing = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": []
    }
  ]
}
`)

var spdxSBOMToolWithEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: "
      ]
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Tool with empty string
var spdx3SBOMToolWithEmptyString = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": [],
      "createdUsing": ["_:tool1"]
    },
    {
      "type": "Tool",
      "spdxId": "_:tool1",
      "name": ""
    }
  ]
}
`)

var cdxSBOMDeprecatedToolWithNameAndVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "vendor": "Awesome Vendor",
        "name": "Awesome Tool",
        "version": "9.1.2"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMDeprecatedToolWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "vendor": "Awesome Vendor",
        "name": "Awesome Tool"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMDeprecatedToolWithVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "vendor": "Awesome Vendor",
        "version": "9.1.2"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMDeprecatedToolWithNameAndVersionEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "vendor": "",
        "version": ""
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMDeprecatedToolAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var cdxSBOMToolWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "tools": []
  },
  "components": []
}
`)

var spdxSBOMToolWrongType = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": {}
  },
  "packages": []
}
`)

// SPDX 3.0 - SBOM Tool with wrong type (object instead of array for createdUsing)
var spdx3SBOMToolWrongType = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": [],
      "profileConformance": ["core"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": [],
      "createdUsing": {}
    }
  ]
}
`)

// fallback aythor as supplier, when not author or tool is present
var cdxSBOMSupplierWithNameAndURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": "Acme, Inc."
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierWithURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {}
  },
  "components": []
}
`)

var cdxSBOMSupplierAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var cdxSBOMSupplierWithNameEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": ""
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierWithURLEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "url": [
        ""
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierWithNameWhitespace = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1, 
  "metadata": {
    "supplier": {
      "name": "   "
    }
  }
}
`)

var cdxSBOMSupplierWithWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": []
  },
  "components": []
}
`)

// / fallback to manufactyrer
var cdxSBOMManufacturerWithNameAndURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMManufacturerWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "name": "Acme, Inc."
    }
  },
  "components": []
}
`)

var cdxSBOMManufactureWithURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMManufactureMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {}
  },
  "components": []
}
`)

var cdxSBOMManufactureAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var cdxSBOMManufactureWithNameEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "name": ""
    }
  },
  "components": []
}
`)

var cdxSBOMManufactureWithURLEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "url": [
        ""
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMManufactureWithNameWhitespace = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1, 
  "metadata": {
    "manufacture": {
      "name": "   "
    }
  }
}
`)

var cdxSBOMManufactureWithWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": []
  },
  "components": []
}
`)

func TestNTIASBOMAuthor(t *testing.T) {
	ctx := context.Background()

	// cdxSBOMAuthorWithNameAndEmail
	t.Run("cdxSBOMAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonNameAndEmail
	t.Run("spdxSBOMAuthorWithPersonNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorWithPersonNameAndEmail
	t.Run("spdx3SBOMAuthorWithPersonNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorWithPersonNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationNameAndEmail
	t.Run("spdxSBOMAuthorWithOrganizationNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorWithOrganizationNameAndEmail
	t.Run("spdx3SBOMAuthorWithOrganizationNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorWithOrganizationNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorWithEmail
	t.Run("cdxSBOMAuthorWithEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonEmail
	t.Run("spdxSBOMAuthorWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorWithPersonEmail
	t.Run("spdx3SBOMAuthorWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationEmail
	t.Run("spdxSBOMAuthorWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorWithOrganizationEmail
	t.Run("spdx3SBOMAuthorWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorWithName
	t.Run("cdxSBOMAuthorWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonName
	t.Run("spdxSBOMAuthorWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorWithPersonName
	t.Run("spdx3SBOMAuthorWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationName
	t.Run("spdxSBOMAuthorWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorWithOrganizationName
	t.Run("spdx3SBOMAuthorWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0 Tests
	// spdx3SBOMAuthorWithOrganization
	t.Run("spdx3SBOMAuthorWithOrganization", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorWithOrganization, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorWithPerson
	t.Run("spdx3SBOMAuthorWithPerson", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorWithPerson, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorAbsent
	t.Run("spdx3SBOMAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsAbsent
	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorAbsent
	t.Run("spdxSBOMAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorMissing
	t.Run("cdxSBOMAuthorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMCreatorMissing
	t.Run("spdxSBOMCreatorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMCreatorMissing
	t.Run("spdx3SBOMCreatorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMCreatorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorPersonMissing
	t.Run("spdxSBOMAuthorPersonMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorPersonMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorPersonMissing
	t.Run("spdx3SBOMAuthorPersonMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorPersonMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorOrganizationMissing
	t.Run("spdxSBOMAuthorOrganizationMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorOrganizationMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMAuthorOrganizationMissing
	t.Run("spdx3SBOMAuthorOrganizationMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMAuthorOrganizationMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithNameAndEmailEmptyString
	t.Run("cdxSBOMAuthorsWithNameAndEmailEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithNameAndEmailEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMCreatorsWithEmptyString
	t.Run("spdxSBOMCreatorsWithEmptyString", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorsWithEmptyString, sbom.Signature{})
		require.Error(t, err)
	})

	// spdx3SBOMCreatorsWithEmptyString
	t.Run("spdx3SBOMCreatorsWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMCreatorsWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithEmptyArray
	t.Run("cdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithEmptyArrayObject
	t.Run("cdxSBOMAuthorsWithEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorsWithEmptyArray
	t.Run("spdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithWrongType
	t.Run("cdxSBOMAuthorsWithWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// spdxSBOMCreatorsWithWrongTypeSomeValue
	t.Run("spdxSBOMCreatorsWithWrongTypeSomeValue", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorsWithWrongTypeSomeValue, sbom.Signature{})
		require.Error(t, err)
	})

	// spdx3SBOMCreatorsWithWrongType
	t.Run("spdx3SBOMCreatorsWithWrongType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMCreatorsWithWrongType, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMCreatorsWithWhitespace
	t.Run("spdxSBOMCreatorsWithWhitespace", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorsWithWhitespace, sbom.Signature{})
		require.Error(t, err)
	})

	// spdx3SBOMCreatorsWithWhitespace
	t.Run("spdx3SBOMCreatorsWithWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMCreatorsWithWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolWithNameAndVersion
	t.Run("cdxSBOMToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWithNameAndVersion
	t.Run("spdxSBOMToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMToolWithNameAndVersion
	t.Run("spdx3SBOMToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolWithName
	t.Run("cdxSBOMToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool (name only)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWithName
	t.Run("spdxSBOMToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool (name only)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMToolWithName
	t.Run("spdx3SBOMToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool (name only)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolWithVersion
	t.Run("cdxSBOMToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool (version only)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWithVersion
	t.Run("spdxSBOMToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool (version only)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMToolWithVersion
	t.Run("spdx3SBOMToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool (version only)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolAbsent
	t.Run("cdxSBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolAbsent
	t.Run("spdxSBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMToolAbsent
	t.Run("spdx3SBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolMissing
	t.Run("cdxSBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolMissing
	t.Run("spdxSBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMToolMissing
	t.Run("spdx3SBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWithEmptyString
	t.Run("spdxSBOMToolWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMToolWithEmptyString
	t.Run("spdx3SBOMToolWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMToolWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolWithNameAndVersion
	t.Run("cdxSBOMDeprecatedToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolWithName
	t.Run("cdxSBOMDeprecatedToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool (name only)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolWithVersion
	t.Run("cdxSBOMDeprecatedToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM generation tool (version only)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolWithNameAndVersionEmptyString
	t.Run("cdxSBOMDeprecatedToolWithNameAndVersionEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithNameAndVersionEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolAbsent
	t.Run("cdxSBOMDeprecatedToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolWrongType
	t.Run("cdxSBOMToolWrongType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWrongType, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWrongType
	t.Run("spdxSBOMToolWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// spdx3SBOMToolWrongType
	t.Run("spdx3SBOMToolWrongType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMToolWrongType, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithNameAndURL(fallback when neither author not tool is present)
	t.Run("cdxSBOMSupplierWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithName
	t.Run("cdxSBOMSupplierWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithURL
	t.Run("cdxSBOMSupplierWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierMissing
	t.Run("cdxSBOMSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierAbsent
	t.Run("cdxSBOMSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithNameEmptyString
	t.Run("cdxSBOMSupplierWithNameEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithURLEmptyString
	t.Run("cdxSBOMSupplierWithURLEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithURLEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithNameWhitespace
	t.Run("cdxSBOMSupplierWithNameWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithWrongType
	t.Run("cdxSBOMSupplierWithWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxSBOMManufacturerWithNameAndURL
	t.Run("cdxSBOMManufacturerWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from manufacturer (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufacturerWithName
	t.Run("cdxSBOMManufacturerWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from manufacturer (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithURL
	t.Run("cdxSBOMManufactureWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from manufacturer (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureMissing
	t.Run("cdxSBOMManufactureMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureAbsent
	t.Run("cdxSBOMManufactureAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithNameEmptyString
	t.Run("cdxSBOMManufactureWithNameEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithNameEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithURLEmptyString
	t.Run("cdxSBOMManufactureWithURLEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithURLEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithNameWhitespace
	t.Run("cdxSBOMManufactureWithNameWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithNameWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithWrongType
	t.Run("cdxSBOMManufactureWithWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithWrongType, sbom.Signature{})
		require.Error(t, err)
	})

}

var cdxCompWithPrimaryRelationships = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app-1.0",
      "dependsOn": [
        "library-a",
        "library-b"  
      ]
    },
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ]
}
`)

var spdxCompWithPrimaryRelationships = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },

  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    },
    {
      "SPDXID": "SPDXRef-LibA",
      "name": "library-a",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibB",
      "name": "library-b",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibC",
      "name": "library-c",
      "versionInfo": "1.0.0"
    }
  ],

  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-App"
    },
    {
      "spdxElementId": "SPDXRef-App",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibA"
    },
    {
      "spdxElementId": "SPDXRef-App",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibB"
    },
    {
      "spdxElementId": "SPDXRef-LibB",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    }
  ]
}
`)

var cdxCompWithNoPrimaryRelationships = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ]
}
`)

var spdxCompWithNoPrimaryRelationships = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },

  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    },
    {
      "SPDXID": "SPDXRef-LibA",
      "name": "library-a",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibB",
      "name": "library-b",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibC",
      "name": "library-c",
      "versionInfo": "1.0.0"
    }
  ],

  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-App"
    },
    {
      "spdxElementId": "SPDXRef-LibB",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    },
    {
      "spdxElementId": "SPDXRef-LibA",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    }

  ]
}
`)

var cdxCompWithPrimaryComponentMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ]
}
`)

var spdxCompWithPrimaryComponentMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },

  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    },
    {
      "SPDXID": "SPDXRef-LibA",
      "name": "library-a",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibB",
      "name": "library-b",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibC",
      "name": "library-c",
      "versionInfo": "1.0.0"
    }
  ],

  "relationships": [
    {
      "spdxElementId": "SPDXRef-LibB",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    },
    {
      "spdxElementId": "SPDXRef-LibA",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    }
  ]
}
`)

var cdxCompWithPrimaryRelationshipsAndDeclaredRelationships = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app-1.0",
      "dependsOn": [
        "library-a",
        "library-b"  
      ]
    },
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ],
  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": ["app"]
    }
  ]
}
`)

var cdxCompWithNoRelationshipButDeclaredRelationshipsComplete = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ],
  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": ["app-1.0"]
    }
  ]
}
`)

var cdxCompWithNoRelationshipsButDeclaredRelationshipsUnknown = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ],
  "compositions": [
    {
      "aggregate": "unknown",
      "dependencies": ["app-1.0"]
    }
  ]
}
`)

var cdxCompWithNoRelationshipsButDeclaredRelationshipsIncomplete = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ],
  "compositions": [
    {
      "aggregate": "incomplete",
      "dependencies": ["app-1.0"]
    }
  ]
}
`)

var cdxCompWithRelationshipsAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ]
}
`)

// SPDX 3.0 - Component with primary relationships (DEPENDS_ON)
var spdx3CompWithPrimaryRelationships = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-App", "SPDXRef-LibA", "SPDXRef-LibB"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-App",
      "name": "my-app",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibA",
      "name": "library-a",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibB",
      "name": "library-b",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-App"],
      "relationshipType": "DESCRIBES"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-App",
      "to": ["SPDXRef-LibA", "SPDXRef-LibB"],
      "relationshipType": "DEPENDS_ON"
    }
  ]
}
`)

// SPDX 3.0 - Component with no primary relationships
var spdx3CompWithNoPrimaryRelationships = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-App", "SPDXRef-LibA"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-App",
      "name": "my-app",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibA",
      "name": "library-a",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-App"],
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

// SPDX 3.0 - Component with primary component missing (no DESCRIBES relationship)
var spdx3CompWithPrimaryComponentMissing = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-App", "SPDXRef-LibA"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-App",
      "name": "my-app",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibA",
      "name": "library-a",
      "software_packageVersion": "1.0.0"
    }
  ]
}
`)

// SPDX 3.0 - Component with no relationships at all (only describes relationship)
var spdx3CompWithRelationshipsAbsent = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-App", "SPDXRef-LibA", "SPDXRef-LibB"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-App",
      "name": "my-app",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibA",
      "name": "library-a",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibB",
      "name": "library-b",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-App"],
      "relationshipType": "describes"
    }
  ]
}
`)

// SPDX 3.0 - Component with multiple dependencies (4 dependencies)
var spdx3CompWithMultipleDependencies = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-App", "SPDXRef-Lib1", "SPDXRef-Lib2", "SPDXRef-Lib3", "SPDXRef-Lib4"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-App",
      "name": "my-app",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Lib1",
      "name": "library-one",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Lib2",
      "name": "library-two",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Lib3",
      "name": "library-three",
      "software_packageVersion": "3.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Lib4",
      "name": "library-four",
      "software_packageVersion": "4.0.0"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-App"],
      "relationshipType": "describes"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-App",
      "to": ["SPDXRef-Lib1", "SPDXRef-Lib2", "SPDXRef-Lib3", "SPDXRef-Lib4"],
      "relationshipType": "dependsOn"
    }
  ]
}
`)

func TestNTIACompDependencies(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 direct (top-level) dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 direct (top-level) dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdx3CompWithPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 direct (top-level) dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares no direct dependencies and does not declare relationship completeness", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithNoPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithNoPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares no direct dependencies and does not declare relationship completeness", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdx3CompWithNoPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithNoPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares no direct dependencies and does not declare relationship completeness", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "define primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "define primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdx3CompWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "define primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryRelationshipsAndDeclaredRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryRelationshipsAndDeclaredRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 direct (top-level) dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoRelationshipButDeclaredRelationshipsComplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoRelationshipButDeclaredRelationshipsComplete, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares no direct dependencies and explicitly states relationship completeness (complete)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoRelationshipsButDeclaredRelationshipsUnknown", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoRelationshipsButDeclaredRelationshipsUnknown, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares no direct dependencies and states relationship completeness as unknown", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoRelationshipsButDeclaredRelationshipsIncomplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoRelationshipsButDeclaredRelationshipsIncomplete, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares no direct dependencies and states relationship completeness as incomplete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithRelationshipsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithRelationshipsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares no direct dependencies and does not declare relationship completeness", got.Desc)
		assert.False(t, got.Ignore)
	})

	// Additional SPDX 3.0 test cases
	t.Run("spdx3CompWithRelationshipsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithRelationshipsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares no direct dependencies and does not declare relationship completeness", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdx3CompWithMultipleDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithMultipleDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 4 direct (top-level) dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxSBOMWithCompleteFields = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "type": "application",
          "group": "Awesome Vendor",
          "name": "Awesome Tool",
          "version": "9.1.2"
        }
      ]
    },
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "Samantha Wright",
        "email": "samantha.wright@example.com"
      }
    ],
    "supplier": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    },
    "manufacture": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    },
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0",
      "supplier": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0",
      "manufacturer": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app-1.0",
      "dependsOn": [
        "library-a",
        "library-b"  
      ]
    },
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ]
}
`)

var spdxSBOMWithCompleteFields = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)",
      "Tool: Awesome Tool-9.1.2"
    ]
  },

  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0",
      "supplier": "Person: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    },
    {
      "SPDXID": "SPDXRef-LibA",
      "name": "library-a",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibB",
      "name": "library-b",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibC",
      "name": "library-c",
      "versionInfo": "1.0.0"
    }
  ],

  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-App"
    },
    {
      "spdxElementId": "SPDXRef-App",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibA"
    },
    {
      "spdxElementId": "SPDXRef-App",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibB"
    },
    {
      "spdxElementId": "SPDXRef-LibB",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    }
  ]
}
`)

// SPDX 3.0 - Complete SBOM with all NTIA fields
var spdx3SBOMWithCompleteFields = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-App", "SPDXRef-LibA", "SPDXRef-LibB", "SPDXRef-LibC"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Samantha Wright",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "samantha.wright@example.com"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-App",
      "name": "my-app",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibA",
      "name": "library-a",
      "software_packageVersion": "1.0.0",
      "suppliedBy": "_:supplier1"
    },
    {
      "type": "Organization",
      "@id": "_:supplier1",
      "name": "Acme, Inc.",
      "externalIdentifier": [
        {
          "externalIdentifierType": "email",
          "identifier": "professional.services@example.com"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibB",
      "name": "library-b",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-LibC",
      "name": "library-c",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-App"],
      "relationshipType": "DESCRIBES"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-App",
      "to": ["SPDXRef-LibA", "SPDXRef-LibB"],
      "relationshipType": "DEPENDS_ON"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-LibB",
      "to": ["SPDXRef-LibC"],
      "relationshipType": "DEPENDS_ON"
    }
  ]
}
`)

func TestNTIAComplete(t *testing.T) {
	ctx := context.Background()

	// --- 1. TEST DEPENDENCY RELATIONSHIPS ----
	// cdxSBOMWithCompleteFields
	t.Run("cdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 direct (top-level) dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMWithCompleteFields
	t.Run("spdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 direct (top-level) dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	// --- 2. TEST SBOM Author FIELDS ----
	// cdxSBOMWithCompleteFields
	t.Run("cdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMWithCompleteFields
	t.Run("spdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// 3. TEST Component Supplier FALLBACK ----
	t.Run("cdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information declared for 2 of 4 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMWithCompleteFields
	t.Run("spdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 2.5, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information declared for 1 of 4 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// --- SPDX 3.0 TESTS ----
	// spdx3SBOMWithCompleteFields - Dependency Relationships
	t.Run("spdx3SBOMWithCompleteFields-Dependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 direct (top-level) dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMWithCompleteFields - Authors
	t.Run("spdx3SBOMWithCompleteFields-Authors", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdx3SBOMWithCompleteFields - Supplier
	t.Run("spdx3SBOMWithCompleteFields-Supplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3SBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 2.5, got.Score, 1e-9)
		assert.Equal(t, "supplier or manufacturer information declared for 1 of 4 components", got.Desc)
		assert.False(t, got.Ignore)
	})
}
