# `sbomqs list` Command

The `sbomqs list` command lets you inspect the actual field values of components or SBOM metadata for a specific feature. It is primarily used to identify which components have a field present (or missing) — for example, which components have no supplier, or what license expressions are declared.

Unlike `score`, which gives you a numeric grade, `list` shows you the raw values so you can act on them directly.

## Usage

```bash
sbomqs list --feature <feature> [flags] <sbom-file>
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--feature` | | _(required)_ | Feature to inspect. Run `sbomqs features` to see all supported features. |
| `--profile` | | | Compliance profile to use for feature extraction (`bsiv11`, `bsiv20`, `bsiv21`, `ntia`, `fsct`, `interlynk`). When set, only features defined for that profile are accepted. |
| `--missing` | `-m` | false | Show only components or properties that do NOT have the feature. |
| `--show` | `-s` | false | Show the actual field value alongside the presence indicator. |
| `--basic` | `-b` | false | Output results in single-line format. |
| `--detailed` | `-d` | true | Output results in table format (default). |
| `--json` | `-j` | false | Output results in JSON format. |
| `--color` | `-l` | false | Enable colored output. |
| `--debug` | `-D` | false | Enable debug logging. |

## Discovering Supported Features

Use the `features` subcommand to browse all available features, organized by profile section:

```bash
# List all features across all profiles
sbomqs features

# List features for a specific profile
sbomqs features --profile bsiv21
sbomqs features --profile ntia
sbomqs features --profile interlynk
```

## Profile Mode vs Generic Mode

### Generic mode (no `--profile`)

Without `--profile`, the command uses the generic feature registry. These features work across all SBOM formats and compliance contexts.

**SBOM-level generic features:**

| Feature | Description |
|---------|-------------|
| `sbom_authors` | SBOM authors/creators |
| `sbom_timestamp` | SBOM creation timestamp |
| `sbom_tool` | Tool that generated the SBOM (name + version) |
| `sbom_spec` | SBOM specification type (cyclonedx / spdx) |
| `sbom_spec_version` | SBOM specification version |
| `sbom_file_format` | SBOM file format (json / xml / tag-value) |
| `sbom_uri` | SBOM unique URI or namespace |
| `sbom_primary_comp` | Primary component name and version |
| `sbom_schema_valid` | Whether the SBOM validates against its schema |
| `sbom_dependencies` | SBOM-level dependency graph summary |
| `sbom_organization` | SBOM organization metadata |
| `sbom_build` | SBOM build / lifecycle metadata |
| `sbom_with_vuln` | Whether the SBOM contains vulnerability entries |

**Component-level generic features:**

| Feature | Description |
|---------|-------------|
| `comp_name` | Component name |
| `comp_version` | Component version |
| `comp_supplier` | Component supplier or manufacturer (with fallback) |
| `comp_author` | Component authors (name, email) |
| `comp_external_refs` | All external references as "type: locator" |
| `comp_license` | All licenses: concluded and declared, labeled by type |
| `comp_depth` | Direct dependency names, or "leaf component" if none |
| `comp_with_uniq_ids` | All unique identifiers: PURL, CPE, SWHID, SWID, OmniBOR |
| `comp_purl` | Component PURL |
| `comp_cpe` | Component CPE |
| `comp_hash` | Component checksum value |
| `comp_purpose` | Component purpose / type |
| `comp_with_source_code_uri` | Component source code URI |
| `comp_with_executable_uri` | Component executable / download URI |
| `comp_source_hash` | Source code hash |

---

### Profile mode (`--profile <profile>`)

When `--profile` is specified, feature extraction follows the rules of that compliance standard. Each profile has its own feature keys that reflect the field names and semantics of the underlying spec.

#### BSI TR-03183-2 v1.1 (`--profile bsiv11`) — 13 features

| Feature | Level | Description |
|---------|-------|-------------|
| `sbom_creator` | SBOM | SBOM creator contact (email or URL) |
| `sbom_timestamp` | SBOM | SBOM creation timestamp |
| `sbom_uri` | SBOM | SBOM URI |
| `comp_creator` | Component | Component creator contact |
| `comp_name` | Component | Component name |
| `comp_version` | Component | Component version |
| `comp_depth` | Component | Dependency relationships |
| `comp_license` | Component | License (concluded preferred, declared fallback) |
| `comp_hash` | Component | Component hash (any algorithm) |
| `comp_unique_identifiers` | Component | Unique identifiers (PURL, CPE) |
| `comp_source_url` | Component | Source code URL |
| `comp_executable_url` | Component | Executable / download URL |
| `comp_source_hash` | Component | Source code hash |

#### BSI TR-03183-2 v2.0 (`--profile bsiv20`) — 16 features

| Feature | Level | Tier | Description |
|---------|-------|------|-------------|
| `sbom_creator` | SBOM | Required | SBOM creator contact |
| `sbom_timestamp` | SBOM | Required | SBOM creation timestamp |
| `sbom_uri` | SBOM | Required | SBOM URI |
| `comp_creator` | Component | Required | Component creator contact |
| `comp_name` | Component | Required | Component name |
| `comp_version` | Component | Required | Component version |
| `comp_filename` | Component | Required | Filename of the component |
| `comp_depth` | Component | Required | Dependency relationships |
| `comp_associated_license` | Component | Required | Distribution licence |
| `comp_deployable_hash` | Component | Required | Hash of the deployable component |
| `comp_executable_property` | Component | Required | Executable property flag |
| `comp_archive_property` | Component | Required | Archive property flag |
| `comp_structured_property` | Component | Required | Structured property flag |
| `comp_source_code_url` | Component | Additional | Source code URL |
| `comp_download_url` | Component | Additional | Deployable download URL |
| `comp_other_identifiers` | Component | Additional | Other unique identifiers |
| `comp_concluded_license` | Component | Additional | Concluded licence |
| `comp_declared_license` | Component | Optional | Declared licence |
| `comp_source_hash` | Component | Optional | Source code hash |

#### BSI TR-03183-2 v2.1 (`--profile bsiv21`) — 21 features

| Feature | Level | Tier | Description |
|---------|-------|------|-------------|
| `sbom_spec_version` | SBOM | Required | Spec version (CycloneDX ≥ 1.6 / SPDX ≥ 3.0.1) |
| `sbom_creator` | SBOM | Required | SBOM creator contact |
| `sbom_timestamp` | SBOM | Required | SBOM creation timestamp |
| `sbom_uri` | SBOM | Additional | SBOM URI |
| `comp_creator` | Component | Required | Component creator contact |
| `comp_name` | Component | Required | Component name |
| `comp_version` | Component | Required | Component version |
| `comp_filename` | Component | Required | Filename of the component |
| `comp_depth` | Component | Required | Dependency relationships |
| `comp_distribution_license` | Component | Required | Distribution licence |
| `comp_deployable_hash` | Component | Required | SHA-512 hash of the deployable |
| `comp_executable_prop` | Component | Required | Executable property flag |
| `comp_archive_prop` | Component | Required | Archive property flag |
| `comp_structured_prop` | Component | Required | Structured property flag |
| `comp_source_code_url` | Component | Additional | Source code URL |
| `comp_download_url` | Component | Additional | Deployable download URL |
| `comp_other_identifiers` | Component | Additional | Other unique identifiers |
| `comp_original_licenses` | Component | Additional | Original (declared) licences |
| `comp_effective_license` | Component | Optional | Effective licence |
| `comp_source_hash` | Component | Optional | Source code hash |
| `comp_security_txt_url` | Component | Optional | security.txt URL |

#### NTIA 2021 (`--profile ntia`) — 7 features

| Feature | Level | Description |
|---------|-------|-------------|
| `sbom_authors` | SBOM | SBOM authors / suppliers |
| `sbom_relationships` | SBOM | Dependency relationship coverage |
| `sbom_timestamp` | SBOM | SBOM creation timestamp |
| `comp_supplier` | Component | Component supplier |
| `comp_name` | Component | Component name |
| `comp_version` | Component | Component version |
| `comp_uniq_id` | Component | Unique identifier (PURL or CPE) |

#### FSCT (`--profile fsct`) — 9 features

| Feature | Level | Description |
|---------|-------|-------------|
| `sbom_provenance` | SBOM | SBOM authorship / provenance |
| `sbom_primary_component` | SBOM | Primary component declared |
| `relationships_coverage` | SBOM | Completeness of dependency relationships |
| `comp_identity` | Component | Component identifiable by name + version |
| `supplier_attribution` | Component | Supplier attribution present |
| `comp_unique_id` | Component | Unique identifier (PURL or CPE) |
| `artifact_integrity` | Component | Checksum / hash present |
| `license_coverage` | Component | License information present |
| `copyright_coverage` | Component | Copyright information present |

#### Interlynk (`--profile interlynk`) — 29 features

| Feature | Level | Section | Description |
|---------|-------|---------|-------------|
| `comp_name` | Component | Identification | Component name |
| `comp_version` | Component | Identification | Component version |
| `comp_local_id` | Component | Identification | Local unique identifier |
| `sbom_timestamp` | SBOM | Provenance | SBOM creation timestamp |
| `sbom_authors` | SBOM | Provenance | SBOM authors |
| `sbom_tool` | SBOM | Provenance | Tool that generated the SBOM |
| `sbom_supplier` | SBOM | Provenance | SBOM supplier (CycloneDX only) |
| `sbom_namespace` | SBOM | Provenance | SBOM namespace / URI |
| `sbom_lifecycle` | SBOM | Provenance | Lifecycle phase (CycloneDX only) |
| `comp_checksums` | Component | Integrity | Component has checksums |
| `comp_sha256` | Component | Integrity | SHA-256 checksum present |
| `sbom_signature` | SBOM | Integrity | SBOM digital signature (CycloneDX only) |
| `comp_dependencies` | Component | Completeness | Dependency declarations |
| `sbom_completeness` | SBOM | Completeness | Dependency completeness (SPDX only) |
| `sbom_primary_component` | SBOM | Completeness | Primary component declared |
| `comp_source_code` | Component | Completeness | Source code reference |
| `comp_supplier` | Component | Completeness | Component supplier |
| `comp_purpose` | Component | Completeness | Component purpose / type |
| `comp_licenses` | Component | Licensing | License expressions |
| `comp_valid_licenses` | Component | Licensing | Valid SPDX license identifiers |
| `comp_no_deprecated_licenses` | Component | Licensing | No deprecated licenses |
| `comp_no_restrictive_licenses` | Component | Licensing | No restrictive licenses |
| `comp_declared_licenses` | Component | Licensing | Declared (original) licenses |
| `sbom_data_license` | SBOM | Licensing | SBOM data license |
| `comp_purl` | Component | Vulnerability | Component PURL |
| `comp_cpe` | Component | Vulnerability | Component CPE |
| `sbom_spec_declared` | SBOM | Structural | SBOM spec declared |
| `sbom_spec_version` | SBOM | Structural | SBOM spec version |
| `sbom_file_format` | SBOM | Structural | SBOM file format |
| `sbom_schema_valid` | SBOM | Structural | Schema validation |

---

## Examples

### List components with their suppliers (generic, detailed)

```bash
sbomqs list --feature comp_supplier samples/photon.spdx.json
```

### Find components missing suppliers

```bash
sbomqs list --feature comp_supplier --missing samples/photon.spdx.json
```

### Show actual supplier values

```bash
sbomqs list --feature comp_supplier --show samples/photon.spdx.json
```

### Show all license values per component

```bash
sbomqs list --feature comp_license --show samples/photon.spdx.json
```

### List all external references per component

```bash
sbomqs list --feature comp_external_refs --show samples/photon.spdx.json
```

### Show unique identifiers (PURL, CPE, SWHID, SWID)

```bash
sbomqs list --feature comp_with_uniq_ids --show samples/photon.spdx.json
```

### Inspect a BSI v2.1 field

```bash
# Show deployable hash for all components
sbomqs list --profile bsiv21 --feature comp_deployable_hash --show samples/app.cdx.json

# Find components missing the distribution licence
sbomqs list --profile bsiv21 --feature comp_distribution_license --missing samples/app.cdx.json
```

### NTIA compliance field inspection

```bash
# Find components without a unique identifier
sbomqs list --profile ntia --feature comp_uniq_id --missing samples/app.spdx.json
```

### Interlynk profile field inspection

```bash
# Show all component PURLs
sbomqs list --profile interlynk --feature comp_purl --show samples/app.cdx.json

# Find components missing declared licenses
sbomqs list --profile interlynk --feature comp_declared_licenses --missing samples/app.cdx.json
```

### JSON output

```bash
sbomqs list --feature comp_supplier --json samples/photon.spdx.json
```

### Basic (single-line) output

```bash
sbomqs list --feature comp_supplier --basic samples/photon.spdx.json
```

---

## Notes

- `--feature` accepts a single feature name. Use `sbomqs features` or `sbomqs features --profile <profile>` to discover valid names.
- When `--profile` is given, only feature keys defined for that profile are accepted. Using a generic key with a profile (or vice versa) will return a validation error listing the supported features.
- The `--missing` flag inverts the output — useful for finding gaps before remediation.
- The `--show` flag adds the actual field value to the output, not just presence/absence.
- FSCT feature keys (`supplier_attribution`, `artifact_integrity`, etc.) do not follow the `comp_`/`sbom_` prefix convention — they are routed correctly when `--profile fsct` is used.
- Some Interlynk profile features are CycloneDX-only: `sbom_supplier`, `sbom_lifecycle`, `sbom_signature`, `sbom_completeness`. On SPDX documents these return "not supported in SPDX".
