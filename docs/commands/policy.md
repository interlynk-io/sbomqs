# `sbomqs policy` Command

The `sbomqs policy` command validates SBOMs against custom organizational policies. It enables automated enforcement of SBOM standards by checking components against rules you define, making it ideal for CI/CD pipeline gates.

## Overview

The policy command:

- Validates SBOMs against YAML-defined policies or inline CLI rules
- Supports whitelist, blacklist, and required field checks
- Provides detailed violation reports with specific component and field information
- Returns non-zero exit codes on policy failures for CI/CD integration
- Works with both SPDX and CycloneDX formats
- **Document-level policies** (`sbom_*` fields) are evaluated once per SBOM, not per-component

## Usage

```bash
sbomqs policy [flags] <SBOM file>
```

## Flags

### Policy Input Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--file, -f <path>` | | Path to YAML policy file |
| `--name <name>` | | Policy name (for inline CLI rules) |
| `--type <type>` | | Policy type: `whitelist`, `blacklist`, or `required` |
| `--rules <rule>` | `-r` | Rule definition (repeatable, for inline CLI rules) |
| `--action <action>` | | Action on violation: `fail`, `warn`, or `pass` |

### Output Format Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output, -o <format>` | | `basic` | Output format: `basic`, `table`, or `json` |
| `--debug, -D` | | `false` | Enable debug logging |

## Policy Types

### Whitelist

Ensures **ALL** field values are within an allowed set. A component passes only if every value is in the whitelist.

**Use case:** Enforce approved licenses, allowed component suppliers, permitted version patterns.

**Behavior:**

- Pass: All field values are in the whitelist
- Fail: Any field value is NOT in the whitelist

### Blacklist

Ensures **NO** field values are in a prohibited set.

**Use case:** Block banned components (e.g., log4j 1.x), prohibited licenses (e.g., GPL variants), deprecated packages.

**Behavior:**

- Pass: No field values match the blacklist
- Fail: Any field value matches the blacklist

### Required

Ensures a field is present (not missing or empty).

**Use case:** Enforce mandatory metadata like supplier, version, checksum, author.

**Behavior:**

- Pass: Field exists and has a non-empty value
- Fail: Field is missing or empty

## Actions

The action defines the outcome when violations are found:

| Action | Result | Exit Code | Use Case |
|--------|--------|-----------|----------|
| `fail` | Mark as failed | Non-zero (1) | **Block CI/CD pipelines** |
| `warn` | Mark as warning | Zero (0) | Report but continue |
| `pass` | Force pass | Zero (0) | Dry-runs, gradual adoption |

## Available Fields

Fields are evaluated at either the **component level** (checked for each component) or **document level** (checked once per SBOM). The `LEVEL` column in policy results indicates this:

- **`comp`**: Component-level: checked for every component
- **`doc`**: Document-level: checked once per SBOM

### Component-Level Fields (`comp`)

| Field | Description | Example Values |
|-------|-------------|----------------|
| `name` | Component name | `log4j-core`, `react` |
| `version` | Component version | `2.14.1`, `18.2.0` |
| `license` | License identifier(s) | `MIT`, `Apache-2.0` |
| `concluded_license` | Concluded license (CycloneDX 1.6+) | `MIT`, `Apache-2.0` |
| `declared_license` | Declared license (CycloneDX 1.6+) | `MIT`, `Apache-2.0` |
| `supplier` | Component supplier | `Apache Software Foundation` |
| `author` | Component author | `John Doe <john@example.com>` |
| `purl` | Package URL | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| `cpe` | Common Platform Enumeration | `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` |
| `checksum` | Hash values | `sha256:abc123...` |
| `copyright` | Copyright text | `Copyright 2024 Example Inc.` |
| `type` | Component type/purpose | `library`, `application` |
| `downloadlocation` | Download URL | `https://example.com/pkg-1.0.jar` |

### Document-Level Fields (`doc`)

Prefix with `sbom_` to check SBOM-level metadata. These are evaluated **once per SBOM**, not per-component:

| Field | Description | Example Values |
|-------|-------------|----------------|
| `sbom_timestamp` | SBOM creation timestamp | `2024-01-15T10:30:00Z` |
| `sbom_author` | SBOM author(s) | `Jane Smith <jane@example.com>` |
| `sbom_supplier` | SBOM supplier | `ACME Corporation` |
| `sbom_tool` | SBOM generation tool | `syft`, `trivy` |
| `sbom_lifecycle` | SBOM lifecycle phase | `build`, `deployed` |
| `sbom_pc` | Primary component | `my-application:1.0.0` |

> **Note:** Document-level policies show `-` in the `COMPONENTS` column since they don't apply to individual components.

## Policy File Format

### YAML Structure

```yaml
policy:
  - name: <policy_name>           # Unique identifier
    type: <policy_type>           # whitelist, blacklist, or required
    rules:
      - field: <field_name>       # Field to check
        values:                   # Exact values (for whitelist/blacklist)
          - value1
          - value2
        patterns:                 # Regex patterns (optional)
          - "pattern.*"
    action: <action>              # fail, warn, or pass
```

### Rule Evaluation Logic

- **Multiple rules in a policy**: Combined with **AND** (all must pass)
- **Multiple values/patterns in a rule**: Combined with **OR** (any value passes)
- **Multiple actual values**: For whitelist, ALL must match; for blacklist, NONE must match

## Examples

### From Policy File

#### License Whitelist (Block Unapproved Licenses)

Create `approved-licenses.yaml`:

```yaml
policy:
  - name: approved_licenses
    type: whitelist
    rules:
      - field: license
        values:
          - MIT
          - Apache-2.0
          - BSD-2-Clause
          - BSD-3-Clause
          - ISC
          - Unlicense
    action: fail
```

<details>

<summary><b>my-app.spdx.json</b></summary>

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-application",
  "documentNamespace": "https://example.com/my-app",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: sbomqs-test-1.0.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package1",
      "name": "react",
      "versionInfo": "18.2.0",
      "downloadLocation": "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package2",
      "name": "apache-commons-lang3",
      "versionInfo": "3.12.0",
      "downloadLocation": "https://repo.maven.apache.org/maven2/",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package3",
      "name": "lodash",
      "versionInfo": "4.17.21",
      "downloadLocation": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "copyrightText": "NOASSERTION"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
```

</details>

**To test a FAILURE case**, change one license to `GPL-3.0`:

```json
"licenseConcluded": "GPL-3.0"
```

Run:

```bash
$ sbomqs policy -f approved-licenses.yaml my-app.spdx.json

                                     BASIC POLICY REPORT
+-------------------+-----------+--------+--------+-------+------------+------------+---------------+
|      POLICY       |   TYPE    | ACTION | RESULT | LEVEL | COMPONENTS | VIOLATIONS | RULES APPLIED |
+-------------------+-----------+--------+--------+-------+------------+------------+---------------+
| approved_licenses | whitelist | fail   | fail   | comp  |          3 |          1 |             1 |
+-------------------+-----------+--------+--------+-------+------------+------------+---------------+
exit status 1
```

#### Block Banned Components (Security Policy)

Create `security-policy.yaml`:

```yaml
policy:
  - name: banned_log4j_versions
    type: blacklist
    rules:
      - field: name
        patterns:
          - "log4j-1\\..*"           # Log4j 1.x (EOL, vulnerable)
          - "log4j-core-2\\.1[0-6]\\..*"  # Log4j 2.10-2.16 (Log4Shell)
    action: fail

  - name: prohibited_licenses
    type: blacklist
    rules:
      - field: license
        values:
          - GPL-2.0
          - GPL-3.0
          - AGPL-3.0
          - SSPL-1.0
    action: fail

  - name: required_security_fields
    type: required
    rules:
      - field: checksum
      - field: purl
    action: warn
```

<details>

<summary><b>security-test.spdx.json</b></summary>

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "vulnerable-app",
  "documentNamespace": "https://example.com/vulnerable-app",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: test-generator-1.0.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package1",
      "name": "log4j-core-2.14.0",
      "versionInfo": "2.14.0",
      "downloadLocation": "https://repo1.maven.apache.org/maven2/",
      "filesAnalyzed": false,
      "licenseConcluded": "GPL-3.0",
      "copyrightText": "NOASSERTION",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "abc123def456..."
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Package2",
      "name": "safe-library",
      "versionInfo": "1.5.0",
      "downloadLocation": "https://example.com/safe-lib",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package3",
      "name": "log4j-1.2.17",
      "versionInfo": "1.2.17",
      "downloadLocation": "https://repo1.maven.apache.org/maven2/",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "copyrightText": "NOASSERTION",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "def789ghi012..."
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
```

</details>

Run:

```bash
$ sbomqs policy -f security-policy.yaml security-test.spdx.json -o table

                                 DETAILED POLICY REPORT

Policy: banned_log4j_versions (result=fail, level=comp, violations=2, total_checks=3, components=3, total_rules_applied=1)
+-------------------+-------+-------------------+--------------------------------------+
|     COMPONENT     | FIELD |      ACTUAL       |                REASON                |
+-------------------+-------+-------------------+--------------------------------------+
| log4j-1.2.17      | name  | log4j-1.2.17      | value(s) in blacklist: log4j-1.2.17  |
| log4j-core-2.14.0 | name  | log4j-core-2.14.0 | value(s) in blacklist:               |
|                   |       |                   | log4j-core-2.14.0                    |
| safe-library      | name  | safe-library      | present                              |
+-------------------+-------+-------------------+--------------------------------------+

Policy: prohibited_licenses (result=fail, level=comp, violations=1, total_checks=3, components=3, total_rules_applied=1)
+-------------------+---------+------------+--------------------------------+
|     COMPONENT     |  FIELD  |   ACTUAL   |             REASON             |
+-------------------+---------+------------+--------------------------------+
| log4j-1.2.17      | license | Apache-2.0 | present                        |
| log4j-core-2.14.0 | license | GPL-3.0    | value(s) in blacklist: GPL-3.0 |
| safe-library      | license | MIT        | present                        |
+-------------------+---------+------------+--------------------------------+

Policy: required_security_fields (result=warn, level=comp, violations=4, total_checks=6, components=3, total_rules_applied=2)
+-------------------+----------+-----------------+---------------+
|     COMPONENT     |  FIELD   |     ACTUAL      |    REASON     |
+-------------------+----------+-----------------+---------------+
| log4j-1.2.17      | checksum | def789ghi012... | present       |
| log4j-1.2.17      | purl     | -               | missing field |
| log4j-core-2.14.0 | checksum | abc123def456... | present       |
| log4j-core-2.14.0 | purl     | -               | missing field |
| safe-library      | checksum | -               | missing field |
| safe-library      | purl     | -               | missing field |
+-------------------+----------+-----------------+---------------+

                             --- SUMMARY TABLE ---
+--------------------------+--------+-------+------------+------------+---------------+
|          POLICY          | RESULT | LEVEL | COMPONENTS | VIOLATIONS | RULES APPLIED |
+--------------------------+--------+-------+------------+------------+---------------+
| banned_log4j_versions    | fail   | comp  |          3 |          2 |             1 |
| prohibited_licenses      | fail   | comp  |          3 |          1 |             1 |
| required_security_fields | warn   | comp  |          3 |          4 |             2 |
+--------------------------+--------+-------+------------+------------+---------------+
exit status 1
```

**Expected violations:**

- `log4j-core-2.14.0` -> matches pattern `log4j-core-2\.1[0-6]\..*` (vulnerable version)
- `log4j-core-2.14.0` -> license `GPL-3.0` is in prohibited list
- `log4j-1.2.17` -> matches pattern `log4j-1\..*` (EOL version)

**To test a PASS case**, use:

```json
{
  "name": "log4j-core",
  "versionInfo": "2.17.1",
  "licenseConcluded": "Apache-2.0"
}
```

#### Multi-Rule Policy (Supplier + License)

Create `enterprise-policy.yaml`:

```yaml
policy:
  - name: approved_suppliers_and_licenses
    type: whitelist
    rules:
      - field: supplier
        values:
          - Apache Software Foundation
          - MIT
          - Microsoft Corporation
          - Google LLC
      - field: license
        values:
          - MIT
          - Apache-2.0
          - BSD-3-Clause
    action: fail
```

Both rules must pass (AND logic).

#### Required Fields Policy

Create `metadata-policy.yaml`:

```yaml
policy:
  - name: required_component_metadata
    type: required
    rules:
      - field: supplier
      - field: version
      - field: license
      - field: checksum
    action: fail
```

<details>

<summary><b>incomplete.spdx.json</b></summary>

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "incomplete-sbom",
  "documentNamespace": "https://example.com/incomplete",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: incomplete-generator-1.0.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package1",
      "name": "component-without-supplier",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package2",
      "name": "component-without-checksum",
      "versionInfo": "2.0.0",
      "supplier": "Person: John Doe",
      "downloadLocation": "https://example.com/pkg",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package3",
      "name": "complete-component",
      "versionInfo": "3.0.0",
      "supplier": "Organization: Apache Software Foundation",
      "downloadLocation": "https://repo1.maven.apache.org/",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "copyrightText": "NOASSERTION",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
```

</details>

**Expected violations:**

- `component-without-supplier` -> Missing `supplier` field
- `component-without-checksum` -? Missing `checksum` field
- `complete-component` -> Passes all required field checks

**To fix violations**, add:

```json
"supplier": "Organization: Example Corp",
"checksums": [{ "algorithm": "SHA256", "checksumValue": "..." }]
```

### Inline CLI Rules

#### Quick License Check

```bash
$ sbomqs policy \
    --name approved_licenses \
    --type whitelist \
    --rules "field=license,values=MIT,Apache-2.0,BSD-3-Clause" \
    --action fail \
    my-app.spdx.json


                                     BASIC POLICY REPORT
+-------------------+-----------+--------+--------+-------+------------+------------+---------------+
|      POLICY       |   TYPE    | ACTION | RESULT | LEVEL | COMPONENTS | VIOLATIONS | RULES APPLIED |
+-------------------+-----------+--------+--------+-------+------------+------------+---------------+
| approved_licenses | whitelist | fail   | fail   | comp  |          3 |          1 |             1 |
+-------------------+-----------+--------+--------+-------+------------+------------+---------------+
exit status 1
```

#### Block Specific Component

```bash
$ sbomqs policy \
    --name no_deprecated_lib \
    --type blacklist \
    --rules "field=name,patterns=legacy-lib-.*" \
    --action fail \
    my-app.cdx.json
```

#### Multiple Rules Inline

```bash
$ sbomqs policy \
    --name secure_components \
    --type whitelist \
    --rules "field=supplier,values=Apache,Google" \
    --rules "field=license,values=MIT,Apache-2.0" \
    --action fail \
    my-app.spdx.json
```

### Complex Policy Examples

#### Comprehensive Security Policy

Create `comprehensive-security.yaml`:

```yaml
policy:
  # Block known vulnerable packages
  - name: block_vulnerable_packages
    type: blacklist
    rules:
      - field: name
        patterns:
          - "log4j-core-2\\.1[0-6]\\..*"   # Log4Shell versions
          - "log4j-core-2\\.0\\..*"         # Early 2.x
          - "commons-collections-3\\.2\\.1" # Known vuln
          - ".*-SNAPSHOT"                    # No snapshots in prod
    action: fail

  # Enforce approved licenses
  - name: license_compliance
    type: whitelist
    rules:
      - field: license
        values:
          - MIT
          - MIT-0
          - Apache-2.0
          - BSD-2-Clause
          - BSD-3-Clause
          - ISC
          - Unlicense
          - 0BSD
          - CC0-1.0
        patterns:
          - "Apache-\\d+\\..*"              # Any Apache version
          - "BSD-.*"                        # Any BSD variant
    action: fail

  # Require security metadata
  - name: security_metadata
    type: required
    rules:
      - field: checksum
      - field: purl
      - field: version
    action: warn

  # Ensure SBOM has required metadata
  - name: sbom_quality
    type: required
    rules:
      - field: sbom_timestamp
      - field: sbom_author
    action: warn
```

<details>

<summary><b>comprehensive-test.cdx.json</b></summary>

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "tools": [
      {
        "vendor": "test",
        "name": "generator",
        "version": "1.0.0"
      }
    ],
    "authors": [
      {
        "name": "Security Team",
        "email": "security@example.com"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "log4j-core-2.14.1",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ],
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        }
      ]
    },
    {
      "type": "library",
      "name": "legacy-snapshot-lib",
      "version": "1.0.0-SNAPSHOT",
      "licenses": [
        {
          "license": {
            "id": "GPL-3.0"
          }
        }
      ],
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        }
      ]
    },
    {
      "type": "library",
      "name": "insecure-lib",
      "version": "0.9.0",
      "purl": "pkg:npm/insecure-lib@0.9.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    },
    {
      "type": "library",
      "name": "safe-component",
      "version": "2.0.0",
      "purl": "pkg:maven/com.safe/safe-component@2.0.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
        }
      ]
    }
  ]
}
```

</details>

**Expected violations:**

| Component | Violation | Reason |
|-----------|-----------|--------|
| `log4j-core-2.14.1` | `block_vulnerable_packages` | Version 2.14.1 matches vulnerable pattern `2\.1[0-6]\..*` |
| `legacy-snapshot-lib` | `block_vulnerable_packages` | Version contains `-SNAPSHOT` |
| `legacy-snapshot-lib` | `license_compliance` | License `GPL-3.0` not in whitelist |
| `insecure-lib` | `license_compliance` | Version `0.9.0` triggers `old_versions_warning` (if using warnlist) |
| `insecure-lib` | `security_metadata` | WARN: Missing checksum |

**To test PASS**, fix all violations:

- Change `log4j-core` version to `2.17.1`
- Change `legacy-snapshot-lib` version to `1.0.0` (no SNAPSHOT)
- Change `legacy-snapshot-lib` license to `MIT`
- Add checksum to `insecure-lib`

#### Organization-Specific Policy

Create `acme-corp-policy.yaml`:

```yaml
policy:
  # ACME-approved suppliers only
  - name: approved_suppliers
    type: whitelist
    rules:
      - field: supplier
        values:
          - ACME Internal
          - Apache Software Foundation
          - Eclipse Foundation
          - Microsoft Corporation
          - Google LLC
          - Amazon Web Services
        patterns:
          - "ACME.*"                        # Any ACME department
    action: fail

  # No GPL in commercial products
  - name: no_copyleft
    type: blacklist
    rules:
      - field: license
        values:
          - GPL-2.0
          - GPL-2.0-only
          - GPL-2.0-or-later
          - GPL-3.0
          - GPL-3.0-only
          - GPL-3.0-or-later
          - AGPL-1.0
          - AGPL-3.0
          - LGPL-2.0
          - LGPL-2.1
          - LGPL-3.0
        patterns:
          - "GPL.*"
          - "AGPL.*"
          - "LGPL.*"
    action: fail
```

<details>

<summary><b>acme-test.spdx.json</b></summary>

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "acme-product",
  "documentNamespace": "https://acme.com/product",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: ACME-SBOM-Generator-1.0.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package1",
      "name": "acme-internal-lib",
      "versionInfo": "1.5.0",
      "supplier": "Organization: ACME Internal",
      "downloadLocation": "https://internal.acme.com/libs",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "copyrightText": "Copyright 2024 ACME Corporation",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "acme1234567890acme1234567890acme1234567890acme1234567890acme12"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Package2",
      "name": "apache-commons-lang3",
      "versionInfo": "3.12.0",
      "supplier": "Organization: Apache Software Foundation",
      "downloadLocation": "https://repo1.maven.apache.org/",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "copyrightText": "NOASSERTION",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "apache1234567890apache1234567890apache1234567890apache1234567890"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Package3",
      "name": "external-component",
      "versionInfo": "2.0.0",
      "supplier": "Person: Unknown Developer",
      "downloadLocation": "https://unknown-source.com/",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package4",
      "name": "legacy-gpl-lib",
      "versionInfo": "1.0.0",
      "supplier": "Organization: ACME Internal",
      "downloadLocation": "https://internal.acme.com/legacy",
      "filesAnalyzed": false,
      "licenseConcluded": "GPL-2.0",
      "copyrightText": "NOASSERTION"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
```

</details>

**Expected violations:**

| Component | Policy | Violation | Reason |
|-----------|--------|-----------|--------|
| `external-component` | `approved_suppliers` | FAIL | Supplier "Person: Unknown Developer" not in whitelist |
| `legacy-gpl-lib` | `no_copyleft` | FAIL | License `GPL-2.0` is in blacklist |
| `legacy-gpl-lib` | `complete_metadata` | FAIL | Missing `checksum` field |
| `external-component` | `complete_metadata` | FAIL | Missing `checksum` field |
| `acme-internal-lib` | All policies | PASS | ACME supplier + MIT license + has checksum |
| `apache-commons-lang3` | All policies | PASS | Apache supplier + Apache-2.0 license + has checksum |

**To fix violations:**

1. Change `external-component` supplier: `"supplier": "Organization: Google LLC"`
2. Change `legacy-gpl-lib` license: `"licenseConcluded": "MIT"`
3. Add checksums to both components above

## Output Formats

### Basic (Default)

Summary table showing policy results. The `LEVEL` column indicates whether the policy is evaluated at the component level (`comp`) or document level (`doc`). Document-level policies show `-` in the `COMPONENTS` column since they apply to the entire SBOM:

```bash
$ sbomqs policy -f policy.yaml sbom.json

                                     BASIC POLICY REPORT
+--------------------+-----------+--------+--------+-------+------------+------------+---------------+
|       POLICY       |   TYPE    | ACTION | RESULT | LEVEL | COMPONENTS | VIOLATIONS | RULES APPLIED |
+--------------------+-----------+--------+--------+-------+------------+------------+---------------+
| approved_suppliers | whitelist | fail   | fail   | comp  |          4 |          1 |             1 |
| no_copyleft        | blacklist | fail   | fail   | comp  |          4 |          1 |             1 |
| sbom_has_author    | required  | warn   | pass   | doc   |          - |          0 |             1 |
+--------------------+-----------+--------+--------+-------+------------+------------+---------------+
exit status 1
```

### Table (Detailed)

Per-component, per-violation details. Document-level policies show a single check result:

```bash
$ sbomqs policy -f policy.yaml sbom.json -o table

                                        DETAILED POLICY REPORT

Policy: approved_suppliers (result=fail, level=comp, violations=1, total_checks=4, components=4, total_rules_applied=1)
+----------------------+----------+----------------------------+--------------------------------------+
|      COMPONENT       |  FIELD   |           ACTUAL           |                REASON                |
+----------------------+----------+----------------------------+--------------------------------------+
| acme-internal-lib    | supplier | ACME Internal              | value in whitelist                   |
| apache-commons-lang3 | supplier | Apache Software Foundation | value in whitelist                   |
| external-component   | supplier | Unknown Developer          | value(s) not in whitelist: Unknown   |
|                      |          |                            | Developer                            |
| legacy-gpl-lib       | supplier | ACME Internal              | value in whitelist                   |
+----------------------+----------+----------------------------+--------------------------------------+

Policy: no_copyleft (result=fail, level=comp, violations=1, total_checks=4, components=4, total_rules_applied=1)
+----------------------+---------+------------+--------------------------------+
|      COMPONENT       |  FIELD  |   ACTUAL   |             REASON             |
+----------------------+---------+------------+--------------------------------+
| acme-internal-lib    | license | MIT        | not in blacklist               |
| apache-commons-lang3 | license | Apache-2.0 | not in blacklist               |
| external-component   | license | MIT        | not in blacklist               |
| legacy-gpl-lib       | license | GPL-2.0    | value(s) in blacklist: GPL-2.0 |
+----------------------+---------+------------+--------------------------------+

Policy: sbom_has_timestamp (result=fail, level=doc, violations=1, total_checks=1, total_rules_applied=1)
+-----------+----------------+---------+---------------+
| COMPONENT |     FIELD      | ACTUAL  |    REASON     |
+-----------+----------------+---------+---------------+
| document  | sbom_timestamp | -       | missing field |
+-----------+----------------+---------+---------------+

                          --- SUMMARY TABLE ---
+--------------------+--------+-------+------------+------------+---------------+
|       POLICY       | RESULT | LEVEL | COMPONENTS | VIOLATIONS | RULES APPLIED |
+--------------------+--------+-------+------------+------------+---------------+
| approved_suppliers | fail   | comp  |          4 |          1 |             1 |
| no_copyleft        | fail   | comp  |          4 |          1 |             1 |
| sbom_has_timestamp | fail   | doc   |          - |          1 |             1 |
+--------------------+--------+-------+------------+------------+---------------+
exit status 1

```

### JSON (Machine-Readable)

```bash
$ sbomqs policy -f policy.yaml sbom.json -o json
```

```json
[
  {
    "name": "approved_suppliers",
    "type": "whitelist",
    "action": "fail",
    "overall_result": "fail",
    "policy_results": [
      {
        "component_id": "Package1",
        "component_name": "acme-internal-lib",
        "declared_field": "supplier",
        "declared_values": "",
        "actual_values": [
          "ACME Internal"
        ],
        "result": "pass",
        "reason": "value in whitelist"
      },
      {
        "component_id": "Package2",
        "component_name": "apache-commons-lang3",
        "declared_field": "supplier",
        "declared_values": "",
        "actual_values": [
          "Apache Software Foundation"
        ],
        "result": "pass",
        "reason": "value in whitelist"
      },
      {
        "component_id": "Package3",
        "component_name": "external-component",
        "declared_field": "supplier",
        "declared_values": "",
        "actual_values": [
          "Unknown Developer"
        ],
        "result": "fail",
        "reason": "value(s) not in whitelist: Unknown Developer"
      },
      {
        "component_id": "Package4",
        "component_name": "legacy-gpl-lib",
        "declared_field": "supplier",
        "declared_values": "",
        "actual_values": [
          "ACME Internal"
        ],
        "result": "pass",
        "reason": "value in whitelist"
      }
    ],
    "total_checks": 4,
    "total_rules": 1,
    "total_components": 4,
    "violation_count": 1
  },
  {
    "name": "no_copyleft",
    "type": "blacklist",
    "action": "fail",
    "overall_result": "fail",
    "policy_results": [
      {
        "component_id": "Package1",
        "component_name": "acme-internal-lib",
        "declared_field": "license",
        "declared_values": "",
        "actual_values": [
          "MIT"
        ],
        "result": "pass",
        "reason": "not in blacklist"
      },
      {
        "component_id": "Package2",
        "component_name": "apache-commons-lang3",
        "declared_field": "license",
        "declared_values": "",
        "actual_values": [
          "Apache-2.0"
        ],
        "result": "pass",
        "reason": "not in blacklist"
      },
      {
        "component_id": "Package3",
        "component_name": "external-component",
        "declared_field": "license",
        "declared_values": "",
        "actual_values": [
          "MIT"
        ],
        "result": "pass",
        "reason": "not in blacklist"
      },
      {
        "component_id": "Package4",
        "component_name": "legacy-gpl-lib",
        "declared_field": "license",
        "declared_values": "",
        "actual_values": [
          "GPL-2.0"
        ],
        "result": "fail",
        "reason": "value(s) in blacklist: GPL-2.0"
      }
    ],
    "total_checks": 4,
    "total_rules": 1,
    "total_components": 4,
    "violation_count": 1
  }
]
exit status 1

```

<details>
<summary><b>📄 Example SBOM + Policy for JSON Output Testing (Click to expand)</b></summary>

**`json-test-policy.yaml`:**

```yaml
policy:
  - name: license_compliance
    type: whitelist
    rules:
      - field: license
        values:
          - MIT
          - Apache-2.0
          - BSD-3-Clause
    action: fail

  - name: approved_suppliers
    type: whitelist
    rules:
      - field: supplier
        values:
          - Apache Software Foundation
          - MIT
          - Google LLC
    action: warn
```

**`json-test.spdx.json`:**

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "json-test",
  "documentNamespace": "https://example.com/json-test",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: json-test-generator-1.0.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package1",
      "name": "compliant-component",
      "versionInfo": "1.0.0",
      "supplier": "Organization: Apache Software Foundation",
      "downloadLocation": "https://repo1.maven.apache.org/",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package2",
      "name": "gpl-component",
      "versionInfo": "2.0.0",
      "supplier": "Organization: Unknown Vendor",
      "downloadLocation": "https://example.com/gpl",
      "filesAnalyzed": false,
      "licenseConcluded": "GPL-3.0",
      "copyrightText": "NOASSERTION"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
```

**Run and parse JSON:**

```bash
# Run policy check and save JSON
sbomqs policy -f json-test-policy.yaml json-test.spdx.json -o json > results.json

# Parse results with jq
cat results.json | jq '.[] | {policy: .name, result: .overall_result, violations: .violation_count}'

{
  "policy": "approved_suppliers",
  "result": "warn",
  "violations": 1
}
{
  "policy": "license_compliance",
  "result": "fail",
  "violations": 1
}
```

</details>

## Sample Policies and Test SBOMs

The repository includes comprehensive sample policies and test SBOMs for reference:

### Sample Policies (`testdata/policy/`)

| Category | Policy File | Description |
|----------|-------------|-------------|
| **License** | `license-allowlist.yaml` | Permissive OSS licenses only |
| | `license-block-copyleft.yaml` | Blocks GPL variants |
| | `license-block-proprietary.yaml` | Blocks custom licenses |
| | `license-dual-check.yaml` | Requires both declared & concluded licenses |
| **Security** | `security-ban-vulnerables.yaml` | Blocks known vulnerable packages |
| | `security-required-fields.yaml` | Requires checksums, PURLs, versions |
| | `security-no-snapshots.yaml` | Blocks SNAPSHOT versions |
| | `security-verified-sources.yaml` | Requires source URLs and hashes |
| **Metadata** | `metadata-required.yaml` | Basic metadata completeness |
| | `metadata-provenance.yaml` | Author, supplier, timestamp |
| | `metadata-identifiers.yaml` | PURL or CPE required |
| **Enterprise** | `enterprise-approved-suppliers.yaml` | Vendor whitelist |
| | `enterprise-complete-sbom.yaml` | Production-ready SBOM gate |
| **Industry** | `industry-finance-compliance.yaml` | Finance sector requirements |
| **Community** | `open-source-distribution.yaml` | OSS compliance checks |
| | `community-health.yaml` | OSI-approved licenses |
| **Advanced** | `advanced-comprehensive.yaml` | All checks combined |

See `testdata/policy/README.md` for detailed documentation.

### Test SBOMs (`testdata/sboms/`)

Each policy has a corresponding `-violations.cdx.json` test file:

```bash
# Test license policies
sbomqs policy -f testdata/policy/license-allowlist.yaml testdata/sboms/license-allowlist-violations.cdx.json

# Test security policies
sbomqs policy -f testdata/policy/security-ban-vulnerables.yaml testdata/sboms/security-ban-vulnerables-violations.cdx.json

# Test comprehensive policy
sbomqs policy -f testdata/policy/advanced-comprehensive.yaml testdata/sboms/advanced-comprehensive-violations.cdx.json
```

## License Field Behavior

### Missing Licenses

When a component has **no license information**, the policy check returns an **empty value** (not `NOASSERTION`). This means:

- **Required field check** on `license` will fail (field is missing)
- **Whitelist check** will fail (empty value is not in the whitelist)
- **Blacklist check** will pass (empty value doesn't match any blacklist pattern)

### CycloneDX License Expressions

For CycloneDX 1.6+ SBOMs, license expressions with `acknowledgement: concluded` or `acknowledgement: declared` are supported:

```yaml
# Check concluded licenses
policy:
  - name: check-concluded-license
    type: required
    rules:
      - field: concluded_license
    action: fail

  - name: check-declared-license
    type: required
    rules:
      - field: declared_license
    action: warn
```

## CI/CD Integration

### GitHub Actions

Install sbomqs using the pre-built binary:

```yaml
name: SBOM Policy Check

on: [push, pull_request]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sbomqs
        run: |
          export VERSION=$(curl -s https://api.github.com/repos/interlynk-io/sbomqs/releases/latest | jq -r '.tag_name' | sed 's/v//')
          curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v${VERSION}/sbomqs_${VERSION}_Linux_x86_64.tar.gz
          tar -xzf sbomqs_${VERSION}_Linux_x86_64.tar.gz
          sudo mv sbomqs /usr/local/bin/
          sbomqs version

      - name: Run Policy Check
        run: sbomqs policy -f policies/security.yaml sbom.json

      - name: Upload Report (on failure)
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: policy-violations
          path: policy-report.json
```

Or install using `go install`:

```yaml
name: SBOM Policy Check

on: [push, pull_request]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install sbomqs
        run: go install github.com/interlynk-io/sbomqs/v2@latest

      - name: Run Policy Check
        run: sbomqs policy -f policies/security.yaml sbom.json
```

Or use Docker:

```yaml
name: SBOM Policy Check

on: [push, pull_request]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Policy Check with Docker
        run: |
          docker run --rm -v $(pwd):/app \
            ghcr.io/interlynk-io/sbomqs:latest \
            policy -f /app/policies/security.yaml /app/sbom.json
```

## Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | All policies passed or only warnings |
| 1 | One or more policies with `action: fail` failed |
| Other | Technical error (file not found, parse error, etc.) |

## Best Practices

### Policy Organization

```
policies/
├── security.yaml          # Security-focused policies
├── license-compliance.yaml # License policies
├── metadata.yaml          # Required field policies
└── organization.yaml      # Company-specific policies
```

### Progressive Enforcement

1. **Phase 1 - Audit Mode**: Use `action: warn` to identify issues without blocking
2. **Phase 2 - Partial Enforcement**: Use `action: fail` for critical policies only
3. **Phase 3 - Full Enforcement**: All policies use `action: fail`

### Policy Versioning

```yaml
# policies/security-v1.0.yaml
policy:
  - name: security_policy_v1
    type: blacklist
    rules:
      - field: name
        patterns:
          - "log4j-1\\..*"
    action: fail
```

## Related Commands

- [`score`](./score.md) - Get SBOM quality score
- [`list`](./list.md) - Inspect SBOM field values
- [`compliance`](./compliance.md) - Check regulatory compliance
- [`generate`](./generate.md) - Generate custom scoring profiles
