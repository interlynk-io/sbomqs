# `sbomqs compliance` Command

The `sbomqs compliance` command validates SBOMs against industry standards and regulatory requirements. It generates detailed compliance reports showing which requirements are met and which need attention.

## Overview

The compliance command supports multiple standards:
- **BSI TR-03183-2 v2.0.0**: German Federal Office for Information Security (latest)
- **BSI TR-03183-2 v1.1**: German Federal Office for Information Security (legacy)
- **FSCT v3**: Framing Software Component Transparency
- **OpenChain Telco**: Telecommunications industry requirements
- **NTIA**: National Telecommunications and Information Administration (coming soon)

## Usage

```bash
sbomqs compliance [flags] <SBOM file>
```

## Flags

### Standard Selection (One Required)
- `--bsi-v2`: Check BSI TR-03183-2 v2.0.0 compliance
- `--bsi`: Check BSI TR-03183-2 v1.1 compliance (legacy)
- `--fsct`: Check FSCT v3 compliance
- `--telco, -t`: Check OpenChain Telco compliance
- `--ntia`: Check NTIA minimum elements (coming soon)

### Output Format Flags
- `--basic, -b`: Simplified output with score summary
- `--detailed, -d`: Detailed breakdown of all requirements (default)
- `--json, -j`: Machine-readable JSON format
- `--color, -l`: Enable colored output for better readability

### Other Flags
- `--output, -o <file>`: Save report to file
- `--debug, -D`: Enable debug logging

## Compliance Standards

### BSI TR-03183-2 v2.0.0

The latest German cybersecurity standard for manufacturers and products.

```bash
$ sbomqs compliance --bsi-v2 product.spdx.json

BSI TR-03183-2 v2.0.0 Compliance Report
=====================================
File: product.spdx.json
Total Score: 7.2/10
Required Elements: 8.1/10
Optional Elements: 6.3/10

Required Elements:
✓ SBOM formats (SPDX detected)
✓ SBOM delivery format (JSON)
✓ Author of SBOM (Present)
✗ Timestamp (Missing)
✓ Component name (250/250)
✗ Component version (200/250)
✓ Dependencies documented (Yes)
✗ Component supplier (125/250)
✗ Component hash (180/250)
✓ SBOM signature (Valid)

Optional Elements:
✓ Component license (200/250)
✗ Component source code URI (0/250)
✓ PURL identifiers (220/250)
✗ CPE identifiers (50/250)

Recommendations:
- Add creation timestamp to SBOM
- Ensure all components have version information
- Add supplier information for 125 components
- Include checksums for 70 components
```

### FSCT v3 (Framing Software Component Transparency)

CISA's framework for software transparency.

```bash
$ sbomqs compliance --fsct app.cdx.json --color

Framing Software Component Transparency v3 Report
================================================
File: app.cdx.json
Overall Compliance: 82%

Core Requirements:
┌─────────────────────────┬────────┬─────────────────────┐
│ Requirement             │ Status │ Details             │
├─────────────────────────┼────────┼─────────────────────┤
│ Automation Support      │ ✓ Pass │ Machine-readable    │
│ Component Identifier    │ ✓ Pass │ All components      │
│ Component Version       │ ⚠ Warn │ 95% have versions   │
│ Component Dependencies  │ ✓ Pass │ Fully documented    │
│ Author Name            │ ✓ Pass │ Present             │
│ Timestamp              │ ✓ Pass │ 2024-01-15T10:00:00Z│
│ Supplier Name          │ ✗ Fail │ Only 60% present    │
└─────────────────────────┴────────┴─────────────────────┘

Additional Requirements:
- Component Hash: 180/200 (90%)
- Lifecycle Phase: Build phase documented
- Security Contact: security@example.com
```

### OpenChain Telco

Telecommunications industry-specific requirements.

```bash
$ sbomqs compliance --telco telecom-app.spdx.json --basic

OpenChain Telco SBOM Basic Report
Score: 6.8/10
Required Score: 7.5/10
Optional Score: 6.1/10

Status: NON-COMPLIANT
Missing Requirements:
- Package verification codes
- External references
- Copyright text for some packages
```

## JSON Output Format

For automation and integration:

```bash
$ sbomqs compliance --bsi-v2 app.json --json
```

```json
{
  "report_name": "BSI TR-03183-2 v2.0.0 Compliance Report",
  "run": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2024-01-15T14:30:00Z",
    "file_name": "app.json"
  },
  "summary": {
    "total_score": 7.2,
    "max_score": 10.0,
    "required_elements_score": 8.1,
    "optional_elements_score": 6.3,
    "compliant": false
  },
  "sections": [
    {
      "section_title": "SBOM formats",
      "section_id": "4.1",
      "required": true,
      "element_result": "spdx",
      "score": 10,
      "status": "pass"
    },
    {
      "section_title": "Component version",
      "section_id": "4.5",
      "required": true,
      "element_result": "200/250",
      "score": 8,
      "status": "partial"
    }
  ],
  "recommendations": [
    "Add version information for 50 components",
    "Include supplier information for all components"
  ]
}
```

## Industry-Specific Examples

### Medical Device Compliance

```bash
# FDA submission preparation
$ sbomqs compliance --fsct medical-device.spdx.json --json > fda-compliance.json

# Check specific requirements
$ cat fda-compliance.json | jq '.sections[] | select(.required==true and .status!="pass")'
```

### Automotive Industry

```bash
# Check automotive software compliance
$ sbomqs compliance --bsi-v2 ecu-software.cdx.json --detailed

# Generate report for audit
$ sbomqs compliance --bsi-v2 ecu-software.cdx.json --json --output audit-report.json
```

### Critical Infrastructure

```bash
# Validate against multiple standards
for std in bsi-v2 fsct; do
  echo "Checking $std compliance..."
  sbomqs compliance --$std critical-system.json --basic
done
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Check BSI Compliance
  run: |
    sbomqs compliance --bsi-v2 sbom.json --json > compliance.json
    
    # Extract compliance status
    compliant=$(jq '.summary.compliant' compliance.json)
    score=$(jq '.summary.total_score' compliance.json)
    
    if [ "$compliant" != "true" ]; then
      echo "::error::BSI compliance check failed (score: $score/10)"
      
      # Show missing requirements
      jq '.sections[] | select(.status=="fail") | .section_title' compliance.json
      
      exit 1
    fi
    
    echo "✅ BSI compliant with score: $score/10"
```

### GitLab CI

```yaml
sbom-compliance:
  script:
    - sbomqs compliance --fsct $CI_PROJECT_DIR/sbom.json --json > compliance-report.json
    - score=$(jq '.summary.total_score' compliance-report.json)
    - 'echo "FSCT Compliance Score: $score/10"'
    - |
      if [ $(echo "$score < 7" | bc) -eq 1 ]; then
        echo "Compliance score too low"
        exit 1
      fi
  artifacts:
    reports:
      custom: compliance-report.json
```

## Generating Compliance Evidence

### Audit Package

Create a compliance evidence package:

```bash
#!/bin/bash
# generate-compliance-evidence.sh

SBOM="product.spdx.json"
OUTPUT_DIR="compliance-evidence"

mkdir -p $OUTPUT_DIR

# Generate all compliance reports
sbomqs compliance --bsi-v2 $SBOM --json > $OUTPUT_DIR/bsi-v2-compliance.json
sbomqs compliance --fsct $SBOM --json > $OUTPUT_DIR/fsct-compliance.json
sbomqs compliance --telco $SBOM --json > $OUTPUT_DIR/telco-compliance.json

# Generate summary
echo "Compliance Summary for $SBOM" > $OUTPUT_DIR/summary.txt
echo "Generated: $(date)" >> $OUTPUT_DIR/summary.txt
echo "" >> $OUTPUT_DIR/summary.txt

for report in $OUTPUT_DIR/*.json; do
  name=$(basename $report .json)
  score=$(jq '.summary.total_score' $report)
  compliant=$(jq '.summary.compliant' $report)
  echo "$name: Score $score/10 - Compliant: $compliant" >> $OUTPUT_DIR/summary.txt
done

# Create ZIP archive
zip -r compliance-evidence-$(date +%Y%m%d).zip $OUTPUT_DIR/
```

## Improving Compliance

### Step-by-Step Improvement

1. **Identify Gaps**:
   ```bash
   sbomqs compliance --bsi-v2 sbom.json --json | \
     jq '.sections[] | select(.status!="pass") | {title: .section_title, required: .required}'
   ```

2. **Focus on Required Elements**:
   ```bash
   # List components missing required fields
   sbomqs list sbom.json --feature comp_with_version --missing
   sbomqs list sbom.json --feature comp_with_supplier --missing
   ```

3. **Fix and Revalidate**:
   ```bash
   # After fixing issues
   sbomqs compliance --bsi-v2 sbom-fixed.json --basic
   ```

### Compliance Monitoring

```bash
#!/bin/bash
# monitor-compliance.sh

# Track compliance over time
DATE=$(date +%Y-%m-%d)
SBOM="current-sbom.json"

# Run compliance checks
for standard in bsi-v2 fsct telco; do
  sbomqs compliance --$standard $SBOM --json > "compliance-$standard-$DATE.json"
  
  score=$(jq '.summary.total_score' "compliance-$standard-$DATE.json")
  echo "$DATE,$standard,$score" >> compliance-history.csv
done

# Generate trend report
echo "Compliance Trend Report"
tail -30 compliance-history.csv | column -t -s,
```

## Understanding Compliance Scores

### Score Interpretation

- **9-10/10**: Fully compliant, exceeds requirements
- **7-8.9/10**: Compliant with minor gaps
- **5-6.9/10**: Partially compliant, needs improvement
- **3-4.9/10**: Non-compliant, significant gaps
- **0-2.9/10**: Severely non-compliant

### Priority Matrix

| Requirement Type | Priority | Action |
|-----------------|----------|---------|
| Required + Failed | Critical | Fix immediately |
| Required + Partial | High | Address soon |
| Optional + Failed | Medium | Plan improvement |
| Optional + Partial | Low | Consider enhancing |

## Troubleshooting

### Common Issues

#### Missing Required Fields
```bash
# Identify which components lack required fields
sbomqs compliance --bsi-v2 sbom.json --json | \
  jq '.sections[] | select(.required==true and .status!="pass")'
```

#### Format Compatibility
```bash
# Check if SBOM format is supported
sbomqs score sbom.json --category structural
```

#### Debug Mode
```bash
# Get detailed error information
sbomqs compliance --fsct problematic.json --debug
```

## Related Commands

- [`score`](./score.md) - Get overall quality score
- [`list`](./list.md) - Find components missing compliance fields
- [`share`](./share.md) - Share compliance reports