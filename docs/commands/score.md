# `sbomqs score` Command

The `sbomqs score` command is the primary tool for evaluating SBOM quality. It provides a comprehensive quality score on a 0-10 scale, helping you understand how complete, accurate, and compliant your SBOM is.

## Overview

The score command analyzes your SBOM across multiple categories:

### Version 2.0 Categories (default)
- **Identification**: Component identification and naming
- **Provenance**: SBOM creation and authorship information
- **Integrity**: Checksums and verification data
- **Completeness**: Coverage of key SBOM fields
- **Licensing**: License information quality
- **Vulnerability**: Security-related metadata
- **Structural**: Conformance to SBOM specification standards
- **Component Quality**: Component quality (API Key Required)

### Legacy Categories (with --legacy flag)
- **NTIA Minimum Elements**: Compliance with NTIA's minimum requirements
- **Structural**: Conformance to SBOM specification standards
- **Semantic**: Correctness of SBOM field meanings
- **Quality**: Completeness and accuracy of data
- **Sharing**: Readiness for distribution and consumption

## Usage

```bash
sbomqs score [flags] <SBOM file(s)>
```

## Flags

### Output Format Flags
- `--basic, -b`: Output only the numeric score (default: false)
- `--detailed, -d`: Show detailed breakdown by category and feature (default: true)
- `--json, -j`: Output in JSON format for automation (default: false)
- `--color, -l`: Output in colorful format

### Scoring Control Flags
- `--category, -c <category>`: Score only specific categories (comma-separated)
- `--feature, -f <features>`: Score only specific features (comma-separated)
- `--configpath <path>`: Use custom scoring configuration file
- `--profile <profiles>`: Apply specific compliance profiles (comma-separated: 'ntia', 'bsi', 'oct', 'interlynk', 'bsi-v2.0')
- `--legacy, -e`: Use legacy scoring mode (prior to sbomqs version 2.0)

### Input Flags
- `--sig, -v <path>`: Path to SBOM signature file
- `--pub, -p <path>`: Path to public key for signature verification

### Other Flags
- `--debug, -D`: Enable debug logging

### Deprecated Flags
These flags are deprecated but still available for backward compatibility:
- `--filepath <path>`: Use positional argument instead
- `--dirpath <path>`: Use positional argument instead
- `--reportFormat <format>`: Use `--json`, `--detailed`, or `--basic` instead
- `--sbomtype <type>`: Type is auto-detected
- `--recurse, -r`: Directories are automatically processed
- `--spdx`: Format is auto-detected
- `--cdx`: Format is auto-detected

## Categories

### Available Categories

#### Version 2.0 (default)
- `identification`: Component identification quality
- `provenance`: SBOM creation and authorship
- `integrity`: Hash and checksum coverage
- `completeness`: Field completeness metrics
- `licensing`: License information quality
- `vulnerability`: Security metadata presence
- `structural`: Specification conformance
- `component quality`: Component quality 

#### Legacy Mode (--legacy flag)
- `ntia` or `NTIA`: NTIA minimum elements
- `structural`: Specification compliance
- `semantic`: Field correctness  
- `quality`: Data quality metrics
- `sharing`: Distribution readiness
- `bsi-v1`: BSI TR-03183-2 v1.1 scoring

### Available Profiles
- `ntia`: NTIA minimum elements compliance
- `bsi`: BSI TR-03183-2 compliance (uses latest version)
- `bsi-v2.0`: BSI TR-03183-2 v2.0 specific
- `oct`: OpenChain Telco compliance
- `interlynk`: Interlynk comprehensive quality profile

## Examples

### Basic Usage

#### Get a Quick Score
```bash
$ sbomqs score my-app.spdx.json
7.2 my-app.spdx.json
```

#### Score Multiple Files
```bash
$ sbomqs score *.json --basic
6.5 app1.spdx.json
8.1 app2.cdx.json
7.9 app3.spdx.json
```

### Detailed Analysis

#### Full Breakdown
```bash
➜  sbomqs git:(feature/sbomqs-2.0-docs) ✗ ./build/sbomqs score samples/photon.spdx.json
SBOM Quality Score: 4.1/10.0     Grade: F       Components: 38   EngineVersion: 1       File: samples/photon.spdx.json

Profile Summary Scores:
+-----------------------+----------+-------+
|        PROFILE        |  SCORE   | GRADE |
+-----------------------+----------+-------+
| Interlynk Profile     | 4.5/10.0 | F     |
+-----------------------+----------+-------+
| NTIA Minimum Elements | 7.1/10.0 | C     |
+-----------------------+----------+-------+
| BSI TR-03183-2 v1.1   | 6.7/10.0 | D     |
+-----------------------+----------+-------+

Interlynk Detailed Score:
+-------------------+--------------------------------+---------------+-------------------------------------+
|     CATEGORY      |            FEATURE             |     SCORE     |                DESC                 |
+-------------------+--------------------------------+---------------+-------------------------------------+
| Identification    | comp_with_name                 | 10.0/10.0     | 38/38 have names                    |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_version              | 9.7/10.0      | 37/38 have versions                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_identifiers          | 10.0/10.0     | 38/38 have unique IDs               |
+-------------------+--------------------------------+---------------+-------------------------------------+
| Provenance        | sbom_creation_timestamp        | 10.0/10.0     | 2023-01-12T22:06:03Z                |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_authors                   | 0.0/10.0      | missing author                      |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_tool_version              | 10.0/10.0     | 1 tool                              |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_supplier                  | 0.0/10.0      | N/A (SPDX)                          |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_namespace                 | 10.0/10.0     | present namespace                   |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_lifecycle                 | 0.0/10.0      | N/A (SPDX)                          |
+-------------------+--------------------------------+---------------+-------------------------------------+
| Integrity         | comp_with_checksums            | 0.3/10.0      | 1/38 have SHA-1+                    |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_sha256               | 0.3/10.0      | 1/38 have SHA-256+                  |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_signature                 | 0.0/10.0      | missing signature                   |
+-------------------+--------------------------------+---------------+-------------------------------------+
| Completeness      | comp_with_dependencies         | 0.5/10.0      | 2/38 have dependencies              |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_completeness_declared     | 0.0/10.0      | N/A (SPDX)                          |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | primary_component              | 10.0/10.0     | identified                          |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_source_code          | 0.0/10.0      | 0/38 have source URIs               |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_supplier             | 0.0/10.0      | 0/38 have suppliers                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_purpose              | 0.0/10.0      | 0/38 have type                      |
+-------------------+--------------------------------+---------------+-------------------------------------+
| Licensing         | comp_with_licenses             | 0.0/10.0      | 0/38 have licenses                  |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_valid_licenses       | 0.0/10.0      | 0/38 have valid SPDX licenses       |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_declared_licenses    | 9.5/10.0      | 36/38 have declared licenses        |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_data_license              | 10.0/10.0     | present data license                |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_no_deprecated_licenses    | 0.0/10.0      | N/A                                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_no_restrictive_licenses   | 0.0/10.0      | N/A                                 |
+-------------------+--------------------------------+---------------+-------------------------------------+
| Vulnerability     | comp_with_purl                 | 0.0/10.0      | 0/38 have PURLs                     |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_with_cpe                  | 0.0/10.0      | 0/38 have CPEs                      |
+-------------------+--------------------------------+---------------+-------------------------------------+
| Structural        | sbom_spec_declared             | 10.0/10.0     | spdx                                |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_spec_version              | 10.0/10.0     | SPDX-2.3                            |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_file_format               | 10.0/10.0     | json                                |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | sbom_schema_valid              | 10.0/10.0     | schema valid                        |
+-------------------+--------------------------------+---------------+-------------------------------------+
| Component Quality | comp_eol_eos                   | Coming Soon.. | N/A                                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_malicious                 | Coming Soon.. | N/A                                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_vuln_sev_critical         | Coming Soon.. | N/A                                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_kev                       | Coming Soon.. | N/A                                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_purl_valid                | Coming Soon.. | N/A                                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | comp_cpe_valid                 | Coming Soon.. | N/A                                 |
+                   +--------------------------------+---------------+-------------------------------------+
|                   | NOTE: Register Interest for    |               | https://forms.gle/WVoB3DrX9NKnzfhV8 |
|                   | Component Analysis             |               |                                     |
+-------------------+--------------------------------+---------------+-------------------------------------+


Love to hear your feedback https://forms.gle/anFSspwrk7uSfD7Q6
```
### Category-Specific Scoring

#### Profile-Based Scoring
```bash
# NTIA Profile
$ sbomqs score --profile ntia my-app.spdx.json

# Multiple profiles
$ sbomqs score --profile ntia,bsi,oct my-app.spdx.json

# BSI v2.0 with signature verification
$ sbomqs score --profile bsi-v2.0 --sig sbom.sig --pub public_key.pem my-app.spdx.json
```

#### Category-Specific Scoring
```bash
# Version 2.0 categories
$ sbomqs score --category identification,integrity my-app.spdx.json

# Legacy mode for NTIA
$ sbomqs score --legacy --category ntia my-app.spdx.json
```

#### Specific Feature Scoring
```bash
# Score specific features
$ sbomqs score --feature comp_with_name,comp_with_version my-app.spdx.json

# Combine with categories
$ sbomqs score --category identification --feature comp_with_identifiers my-app.spdx.json
```

### Automation-Friendly Output

#### JSON Output for CI/CD
```bash
➜  sbomqs git:(feature/sbomqs-2.0-docs) ✗ ./build/sbomqs score -j samples/photon.spdx.json
{
  "run_id": "d3bfe80c-2cee-48ac-ab4b-e0ff895089f6",
  "timestamp": "2025-11-18T00:16:16Z",
  "creation_info": {
    "name": "sbomqs",
    "version": "v1.3.0-7-gd3509a9",
    "sbomqs_engine_version": "1",
    "vendor": "Interlynk (support@interlynk.io)"
  },
  "files": [
    {
      "sbom_quality_score": 4.1102469229026655,
      "grade": "F",
      "num_components": 38,
      "file_name": "samples/photon.spdx.json",
      "spec": "spdx",
      "spec_version": "SPDX-2.3",
      "file_format": "json",
      "creation_time": "2023-01-12T22:06:03Z",
      "comprehenssive": [
        
```

#### Parse JSON in Scripts
```bash
# Extract just the score
score=$(sbomqs score my-app.json --json | jq '.files[0].sbom_quality_score')

# Check if score meets threshold
if (( $(echo "$score < 7.0" | bc -l) )); then
    echo "SBOM quality too low: $score"
    exit 1
fi
```

### Custom Configuration

#### Generate Custom Profile
```bash
# Generate configuration template
$ sbomqs generate features > custom-profile.yaml

# Edit the file to enable/disable specific checks
$ vim custom-profile.yaml

# Use custom profile
$ sbomqs score my-app.json --configpath custom-profile.yaml
```

### Directory Processing

#### Score All SBOMs in Directory
```bash
$ sbomqs score ./sboms/ --basic
7.2 sboms/app1.json
8.5 sboms/app2.json
6.9 sboms/lib/dependency.json
```

### Working with Profiles

#### Apply Compliance Profiles
```bash
# Single profile
$ sbomqs score --profile ntia my-app.spdx.json

# Multiple profiles
$ sbomqs score --profile ntia,bsi,oct,interlynk my-app.spdx.json

# BSI with signature verification
$ sbomqs score --profile bsi-v2.0 \
    --sig samples/sbom.sig \
    --pub samples/public_key.pem \
    samples/app.spdx.json
```

### Version 2.0 vs Legacy Mode

#### Version 2.0 Mode (Default)
```bash
# Uses new comprehensive categories
$ sbomqs score my-app.spdx.json

# Filter by V2 categories
$ sbomqs score --category identification,integrity my-app.spdx.json
```

#### Legacy Mode
```bash
# Use pre-2.0 scoring system
$ sbomqs score --legacy my-app.spdx.json

# Legacy with NTIA category
$ sbomqs score --legacy --category ntia my-app.spdx.json
```

## Interpreting Scores

### Score Ranges and Grades

#### Numeric Scores (0-10)
- **9-10**: Excellent - SBOM is high quality and compliant
- **7-8.9**: Good - SBOM meets most requirements
- **5-6.9**: Fair - SBOM has gaps that should be addressed
- **3-4.9**: Poor - SBOM is missing critical information
- **0-2.9**: Failing - SBOM is severely incomplete

#### Letter Grades
- **A**: 8.0-10.0 - Excellent quality
- **B**: 6.0-7.9 - Good quality
- **C**: 4.0-5.9 - Fair quality
- **D**: 2.0-3.9 - Poor quality
- **F**: 0.0-1.9 - Failing quality

### Key Quality Indicators

#### High Priority Issues
- Missing component versions (affects vulnerability scanning)
- No supplier information (supply chain transparency)
- Invalid or missing licenses (legal compliance)
- No creation timestamp (traceability)

#### Medium Priority Issues
- Missing checksums (integrity verification)
- No CPE/PURL identifiers (vulnerability matching)
- Incomplete relationships (dependency understanding)

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Check SBOM Quality
  run: |
    sbomqs score sbom.json --json > results.json
    score=$(jq '.files[0].sbom_quality_score' results.json)
    echo "SBOM Score: $score"
    
    # Fail if score is below 7
    if (( $(echo "$score < 7" | bc -l) )); then
      echo "::error::SBOM quality score too low: $score"
      exit 1
    fi
    
    # Add score as PR comment
    echo "## SBOM Quality Score: $score/10" >> $GITHUB_STEP_SUMMARY
```

### Jenkins Pipeline
```groovy
stage('SBOM Quality Check') {
    steps {
        sh 'sbomqs score build/sbom.json --json > sbom-score.json'
        
        script {
            def scoreData = readJSON file: 'sbom-score.json'
            def score = scoreData.files[0].sbom_quality_score
            
            if (score < 7.0) {
                error("SBOM quality score too low: ${score}")
            }
            
            echo "SBOM quality score: ${score}/10"
        }
    }
}
```

## Best Practices

### Regular Quality Checks
```bash
# Add to pre-commit hooks
#!/bin/bash
sbom_score=$(sbomqs score sbom.json --basic | cut -d' ' -f1)
if (( $(echo "$sbom_score < 7" | bc -l) )); then
    echo "SBOM quality check failed: score $sbom_score/10"
    echo "Run 'sbomqs score sbom.json --detailed' for details"
    exit 1
fi
```

### Incremental Improvement
1. Start by checking NTIA compliance:
   ```bash
   sbomqs score --category ntia sbom.json
   ```

2. Address missing critical fields:
   ```bash
   # List components missing versions
   sbomqs list sbom.json --feature comp_with_version --missing
   
   # Check for missing supplier information
   sbomqs list sbom.json --feature comp_with_supplier --missing
   ```

3. Improve incrementally and re-score:
   ```bash
   sbomqs score sbom.json --detailed
   ```

## Troubleshooting

### Common Issues

#### Low Scores
If you're getting unexpectedly low scores:
1. Check NTIA minimum elements first
2. Ensure components have versions
3. Verify license information is present
4. Add supplier/manufacturer information

#### Parsing Errors
```bash
# Enable debug mode for more information
sbomqs score problematic.json --debug
```

#### Performance with Large SBOMs
```bash
# Process in basic mode for faster results
sbomqs score large-sbom.json --basic

# Or use JSON output and process programmatically
sbomqs score large-sbom.json --json | jq '.files[0].avg_score'
```

## Related Commands

- [`compliance`](./compliance.md) - Check regulatory compliance
- [`list`](./list.md) - Analyze specific SBOM features
- [`share`](./share.md) - Generate shareable score reports
- [`generate`](./generate.md) - Create custom scoring profiles