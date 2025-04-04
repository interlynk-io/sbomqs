# `sbomqs list` Command

The `sbomqs list` command allows users to list components or SBOM fileds based on a specified feature, making it easier to identify which components or properties(SBOM metadata) meet (or fail to meet) certain criteria. This command is particularly useful for pinpointing missing fields in SBOM components (e.g., suppliers, licenses) or verifying SBOM metadata (e.g., authors, creation timestamp).

## Usage

```bash
sbomqs list [flags] <SBOM file>
```

### Flags

- `--feature, -f <feature>`: Specifies the feature to list (required). See supported features below.
- `--missing, -m`: Lists components or properties that do not have the specified feature (default: false).
- `--basic, -b`: Outputs results in a single-line format (default: false).
- `--detailed, -d`: Outputs results in a detailed table format (default: true).
- `--json, -j`: Outputs results in JSON format (default: false).
- `--color, -l`: Enables colored output for the detailed format (default: false).
- `--debug, -D`: Enables debug logging (default: false).

### Supported Features

The list command supports the following features, categorized into **component-based** (`comp_`) and **SBOM-based** (`sbom_`) features:

#### Component-Based Features (comp_)

These features evaluate individual components in the SBOM:

- `comp_with_name`: Lists components with a name.
- `comp_with_version`: Lists components with a version.
- `comp_with_supplier`: Lists components with a supplier.
- `comp_with_uniq_ids`: Lists components with unique IDs.
- `comp_valid_licenses`: Lists components with at least one valid SPDX license.
- `comp_with_any_vuln_lookup_id`: Lists components with any vulnerability lookup ID (CPE or PURL).
- `comp_with_deprecated_licenses`: Lists components with deprecated licenses.
- `comp_with_multi_vuln_lookup_id`: Lists components with both CPE and PURL (multiple vulnerability lookup IDs).
- `comp_with_primary_purpose`: Lists components with a supported primary purpose.
- `comp_with_restrictive_licenses`: Lists components with restrictive licenses.
- `comp_with_checksums`: Lists components with checksums.
- `comp_with_licenses`: Lists components with licenses.

#### SBOM-Based Features (sbom_)

These features evaluate document-level properties of the SBOM:

- `sbom_creation_timestamp`: Lists the SBOM’s creation timestamp.
- `sbom_authors`: Lists the SBOM’s authors.
- `sbom_with_creator_and_version`: Lists the creator tool and its version.
- `sbom_with_primary_component`: Lists the primary component of the SBOM.
- `sbom_dependencies`: Lists the dependencies of the primary component.
- `sbom_sharable`: Lists whether the SBOM has a sharable license (all licenses must be free for any use).
- `sbom_parsable`: Lists whether the SBOM is parsable.
- `sbom_spec`: Lists the SBOM specification (e.g., SPDX, CycloneDX).
- `sbom_spec_file_format`: Lists the SBOM file format (e.g., JSON, YAML).
- `sbom_spec_version`: Lists the SBOM specification version (e.g., SPDX-2.2).

## Examples

### 1. List Components with Suppliers (Basic Format)

```bash
$ sbomqs list --feature comp_with_supplier --basic samples/photon.spdx.json

samples/photon.spdx.json:	 comp_with_supplier 	(present):	 0/39 components
```

### 2. List Components Missing Suppliers (Detailed Format)

```bash
$ sbomqs list --feature comp_with_supplier --missing samples/photon.spdx.json

File: samples/photon.spdx.json
Feature: comp_with_supplier (missing)
+----------------------------+-----------------+-----------------+
| Feature                    | Component Name  | Version         |
+----------------------------+-----------------+-----------------+
| comp_with_supplier (39/39) | abc             | v1              |
|                            | abe             | v2              |
|                            | abf             | v3              |
|                            | abg             | v4              |
|                            | abh             | v5              |
|                            | abi             | v6              |
|                            | abz             | v26             |
+----------------------------+-----------------+-----------------+
```

### 3. List SBOM Authors (JSON Format)

```bash
$ sbomqs list --feature sbom_authors --json samples/photon.spdx.json

{
  "run_id": "8af142e2-822f-4005-9612-42ddeb9394bf",
  "timestamp": "2025-04-03T10:00:00Z",
  "creation_info": {
    "name": "sbomqs",
    "version": "v1.0.0",
    "vendor": "Interlynk (support@interlynk.io)"
  },
  "files": [
    {
      "file_name": "samples/photon.spdx.json",
      "feature": "sbom_authors",
      "missing": false,
      "document_property": {
        "property": "Authors",
        "value": "John Doe",
        "present": true
      },
      "errors": []
    }
  ]
}
```

## Notes

- The `--missing` flag is particularly useful for identifying gaps in your SBOM, such as components missing suppliers or licenses, helping you improve compliance and quality.
- The `list` command supports the same input sources as the score command: local files, directories, and GitHub URLs.
