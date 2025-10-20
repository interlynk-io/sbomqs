# `sbomqs score` Command

The `sbomqs score` command is the primary tool for evaluating SBOM quality. It provides a comprehensive quality score on a 0-10 scale, helping you understand how complete, accurate, and compliant your SBOM is.

## Overview

The score command analyzes your SBOM across multiple categories:
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

### Scoring Control Flags
- `--category, -c <category>`: Score only specific categories
- `--features, -f <features>`: Score only specific features
- `--configpath <path>`: Use custom scoring configuration file

### Input Flags
- `--sbomtype <type>`: Specify SBOM type (spdx, cdx, or auto-detect)
- `--recurse, -r`: Process directories recursively

### Other Flags
- `--debug, -D`: Enable debug logging
- `--quiet, -q`: Suppress non-essential output

## Categories

### Available Categories
- `ntia` or `NTIA`: NTIA minimum elements
- `structural`: Specification compliance
- `semantic`: Field correctness
- `quality`: Data quality metrics
- `sharing`: Distribution readiness
- `bsi-v1.1`: BSI TR-03183-2 v1.1 scoring
- `bsi-v2.0`: BSI TR-03183-2 v2.0 scoring

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
$ sbomqs score my-app.spdx.json --detailed

SBOM Quality Score: 7.2 my-app.spdx.json
+-----------------------+--------------------------------+-----------+--------------------------------+
|       CATEGORY        |            FEATURE             |   SCORE   |              DESC              |
+-----------------------+--------------------------------+-----------+--------------------------------+
| NTIA-minimum-elements | Doc has creation timestamp     | 10.0/10.0 | doc has creation timestamp     |
|                       |                                |           | 2024-01-15T10:30:00Z           |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have supplier names | 5.0/10.0  | 125/250 have supplier names    |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have names          | 10.0/10.0 | 250/250 have names             |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Doc has relationships          | 8.0/10.0  | doc has 200 relationships      |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Structural            | Spec File Format               | 10.0/10.0 | supported format: json         |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Spec is Parsable               | 10.0/10.0 | spec is parsable               |
+-----------------------+--------------------------------+-----------+--------------------------------+
| Quality               | Components have versions       | 9.0/10.0  | 225/250 have versions          |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Components have licenses       | 7.0/10.0  | 175/250 have licenses          |
+                       +--------------------------------+-----------+--------------------------------+
|                       | Valid SPDX Licenses            | 6.0/10.0  | 150/250 have valid licenses    |
+-----------------------+--------------------------------+-----------+--------------------------------+
```

### Category-Specific Scoring

#### NTIA Compliance Only
```bash
$ sbomqs score --category ntia my-app.spdx.json

NTIA Compliance Score: 8.3 my-app.spdx.json
```

#### BSI Compliance Scoring
```bash
$ sbomqs score --category bsi-v2.0 my-app.spdx.json

BSI TR-03183-2 v2.0 Score: 6.8 my-app.spdx.json
```

### Automation-Friendly Output

#### JSON Output for CI/CD
```bash
$ sbomqs score my-app.spdx.json --json
{
  "run_id": "fc86a94d-7490-4f20-a202-b04bb3cdfde9",
  "timestamp": "2024-01-15T14:58:55Z",
  "creation_info": {
    "name": "sbomqs",
    "version": "v1.0.0",
    "scoring_engine_version": "5"
  },
  "files": [
    {
      "file_name": "my-app.spdx.json",
      "spec": "spdx",
      "spec_version": "2.3",
      "file_format": "json",
      "avg_score": 7.2,
      "num_components": 250,
      "scores": [
        {
          "category": "NTIA-minimum-elements",
          "feature": "Components have supplier names",
          "score": 5.0,
          "max_score": 10.0,
          "description": "125/250 have supplier names"
        }
      ]
    }
  ]
}
```

#### Parse JSON in Scripts
```bash
# Extract just the score
score=$(sbomqs score my-app.json --json | jq '.files[0].avg_score')

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
$ sbomqs score ./sboms/ --recurse --basic
7.2 sboms/app1.json
8.5 sboms/app2.json
6.9 sboms/lib/dependency.json
```

## Interpreting Scores

### Score Ranges
- **9-10**: Excellent - SBOM is high quality and compliant
- **7-8.9**: Good - SBOM meets most requirements
- **5-6.9**: Fair - SBOM has gaps that should be addressed
- **3-4.9**: Poor - SBOM is missing critical information
- **0-2.9**: Failing - SBOM is severely incomplete

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
    score=$(jq '.files[0].avg_score' results.json)
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
            def score = scoreData.files[0].avg_score
            
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
   sbomqs list sbom.json --feature comp_with_version --missing
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