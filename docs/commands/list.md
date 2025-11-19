# `sbomqs list` Command

The `sbomqs list` command allows users to list components or SBOM fileds based on a specified feature, making it easier to identify which components or properties(SBOM metadata) meet (or fail to meet) certain criteria. This command is particularly useful for pinpointing missing fields in SBOM components (e.g., suppliers, licenses) or verifying SBOM metadata (e.g., authors, creation timestamp).

## Usage

```bash
sbomqs list [flags] <SBOM file>
```

### Autocompletion for `--feature` Flag

- **For Bash**:

  ```bash
  sbomqs completion bash > sbomqs_completion.sh
  ```

- **For Zsh**:

  ```bash
  sbomqs completion zsh > sbomqs_completion.sh
  ```

This creates a file (`sbomqs_completion.sh`) with the completion logic.

To enable autocompletion, source the script in your shell session:

- **Temporary (Current Session)**:

  ```bash
  source sbomqs_completion.sh
  ```

- **Permanent (All Sessions)**:

  - Move the script to a directory in your shell’s path:

    ```bash
    mv sbomqs_completion.sh ~/.zsh/  # For Zsh, or ~/.bash/ for Bash
    ```

  - Add it to your shell configuration:
    - **Bash**: Edit `~/.bashrc` or `~/.bash_profile`:
  
      ```bash
      echo "source ~/.bash/sbomqs_completion.sh" >> ~/.bashrc
      source ~/.bashrc
      ```

    - **Zsh**: Edit `~/.zshrc`:

      ```bash
      echo "source ~/.zsh/sbomqs_completion.sh" >> ~/.zshrc
      source ~/.zshrc
      ```

For Zsh, ensure completion is initialized by adding `autoload -Uz compinit && compinit` to `~/.zshrc` if not already present.

Run the following command and press `<Tab>`:

```bash
sbomqs list --feature=<Tab>
```

### Flags

- `--features, -f <feature>`: Specifies the feature to list (required). See supported features below.
- `--missing, -m`: Lists components or properties that do not have the specified feature (default: false).
- `--basic, -b`: Outputs results in a single-line format (default: false).
- `--detailed, -d`: Outputs results in a detailed table format (default: true).
- `--json, -j`: Outputs results in JSON format (default: false).
- `--color, -l`: Enables colored output for the detailed format (default: false).
- `--debug, -D`: Enables debug logging (default: false).

### Supported Features

The list command supports the following features, categorized into **component-based** (`comp_`) and **SBOM-based** (`sbom_`) features:

#### Supported Component features (canonical + aliases): "comp_"

```table
| Canonical feature                | Aliases                                                       | What it checks (short)                                                                         |
| -------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `comp_with_name`                 | `comp_name`                                                   | Component has a name.                                                                          |
| `comp_with_version`              | `comp_version`                                                | Component has a version.                                                                       |
| `comp_with_supplier`             | `comp_supplier`                                               | Component has a supplier.                                                                      |
| `comp_with_uniq_ids`             | –                                                             | Component has at least one unique identifier (SPDXID, PURL, CPE, etc. depending on your impl). |
| `comp_valid_licenses`            | `comp_license`                                                | Component has **valid / normalized** license info.                                             |
| `comp_with_licenses`             | `comp_with_valid_licenses`                                    | Component has one or more license expressions (may be looser than “valid_licenses”).           |
| `comp_with_any_vuln_lookup_id`   | –                                                             | Component has any vulnerability lookup identifier (e.g. PURL/CPE/other used for vuln lookup).  |
| `comp_with_multi_vuln_lookup_id` | –                                                             | Component has **multiple** vulnerability lookup identifiers.                                   |
| `comp_with_deprecated_licenses`  | `comp_no_deprecated_licenses`, `comp_no_restrictive_licenses` | Component has **deprecated** licenses (same underlying check for all three names).             |
| `comp_with_restrictive_licenses` | –                                                             | Component has **restrictive** licenses (separate check from deprecated).                       |
| `comp_with_primary_purpose`      | `comp_with_purpose`, `comp_purpose`                           | Component has a primary purpose / type set.                                                    |
| `comp_with_checksums`            | `comp_hash`                                                   | Component has at least one checksum.                                                           |
| `comp_with_checksums_sha256`     | –                                                             | Component has SHA-256 checksums in the checksum list.                                          |
| `comp_with_sha256`               | `comp_hash_sha256`                                            | Component has a SHA-256 hash (alt representation / helper).                                    |
| `comp_with_source_code_uri`      | `comp_with_source_code`, `comp_source_code_uri`               | Component has a source code URI (possibly resolved via doc + component).                       |
| `comp_with_source_code_hash`     | `comp_source_hash`                                            | Component/source has a hash of the source code.                                                |
| `comp_with_executable_uri`       | –                                                             | Component has an executable / artifact URI.                                                    |
| `comp_with_associated_license`   | `comp_associated_license`                                     | Component has an **associated** license (e.g. from files/attribution).                         |
| `comp_with_concluded_license`    | –                                                             | Component has a concluded license.                                                             |
| `comp_with_declared_license`     | `comp_with_declared_licenses`                                 | Component has a declared license (or list).                                                    |
| `comp_with_dependencies`         | `comp_dependencies`, `comp_depth`                             | Component has dependencies / is part of a dependency graph.                                    |
| `comp_with_purl`                 | `comp_purl`                                                   | Component has a Package URL (PURL).                                                            |
| `comp_with_cpe`                  | `comp_cpe`                                                    | Component has a CPE identifier.                                                                |
```

#### Supported SBOM features (canonical + aliases): "sbom_"

```table
| Canonical feature               | Aliases                                        | What it checks (short)                                           |
| ------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------- |
| `sbom_creation_timestamp`       | `sbom_timestamp`                               | SBOM has a creation timestamp.                                   |
| `sbom_authors`                  | `sbom_creator`                                 | SBOM has authors / creators.                                     |
| `sbom_with_creator_and_version` | `sbom_tool`                                    | SBOM includes creator/tool **and** its version.                  |
| `sbom_with_primary_component`   | `sbom_primary_component`                       | SBOM defines a primary component (and usually its version).      |
| `sbom_dependencies`             | `sbom_depth`                                   | SBOM contains dependency relationships.                          |
| `sbom_sharable`                 | –                                              | SBOM has information to determine if it’s sharable license-wise. |
| `sbom_parsable`                 | –                                              | SBOM is syntactically parsable.                                  |
| `sbom_spec`                     | `sbom_spec_declared`, `sbom_name`              | SBOM declares a spec/name (SPDX, CycloneDX, etc.).               |
| `sbom_file_format`              | `sbom_spec_file_format`, `sbom_machine_format` | Underlying file/machine format (JSON, XML, tag-value, etc.).     |
| `sbom_spec_version`             | –                                              | Declared SBOM specification version.                             |
| `spec_with_version_compliant`   | –                                              | SBOM spec + version are compliant (according to your checks).    |
| `sbom_with_uri`                 | `sbom_uri`                                     | SBOM or its main entity has an associated URI.                   |
| `sbom_with_vuln`                | `sbom_vulnerabilities`                         | SBOM contains vulnerability data.                                |
| `sbom_build_process`            | `sbom_build`                                   | SBOM has build lifecycle / build process information.            |
| `sbom_with_bomlinks`            | `sbom_bomlinks`                                | SBOM has BOM-Link style references.                              |
| `sbom_spdxid`                   | –                                              | SBOM has a document-level SPDXID (SPDX docs).                    |
| `sbom_organization`             | –                                              | SBOM lists an owning / producing organization.                   |
| `sbom_schema_valid`             | –                                              | SBOM validates against the corresponding schema.                 |
```

## Examples

### 1. List Components with Suppliers (Basic Format)

```bash
$ sbomqs list --features comp_with_supplier --basic samples/photon.spdx.json

samples/photon.spdx.json:	 comp_with_supplier 	(present):	 0/39 components
```

### 2. List Components Missing Suppliers (Detailed Format)

```bash
$ sbomqs list --features comp_with_supplier --missing samples/photon.spdx.json

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
$ sbomqs list --features sbom_authors --json samples/photon.spdx.json

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
