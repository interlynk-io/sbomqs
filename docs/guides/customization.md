# Customization Guide

This guide explains how to customize SBOMQS scoring, create organization-specific profiles, and tailor the tool to your specific requirements.

## Scoring Customization

### Understanding the Scoring System

SBOMQS uses a weighted scoring system across multiple categories:

- **Base Score**: 0-10 scale
- **Categories**: Groups of related features
- **Features**: Individual scoring criteria
- **Weights**: Importance multipliers (0.0-1.0)

### Default Scoring Categories

| Category | Default Weight | Focus |
|----------|---------------|-------|
| NTIA Minimum Elements | 1.0 | Regulatory compliance |
| Structural | 0.9 | Format validity |
| Semantic | 0.8 | Field correctness |
| Quality | 1.0 | Data completeness |
| Sharing | 0.7 | Distribution readiness |

## Creating Custom Profiles

### Generate Base Configuration

```bash
# Generate the default configuration
sbomqs generate features > custom-profile.yaml
```

### Customize Categories

Edit the generated YAML file to adjust category weights:

```yaml
# custom-profile.yaml
categories:
  ntia-minimum-elements:
    enabled: true
    weight: 0.8  # Reduce NTIA weight
    
  quality:
    enabled: true
    weight: 1.0  # Maximize quality weight
    
  sharing:
    enabled: false  # Disable sharing category
```

### Customize Features

Fine-tune individual feature weights:

```yaml
categories:
  quality:
    features:
      - id: comp_with_versions
        enabled: true
        weight: 1.0  # Critical for vulnerability scanning
        
      - id: comp_with_checksums
        enabled: true
        weight: 0.9  # Important for integrity
        
      - id: comp_with_licenses
        enabled: true
        weight: 0.5  # Less critical for internal use
```

## Industry-Specific Profiles

### Healthcare/Medical Devices

Focus on FDA requirements and patient safety:

```yaml
# medical-device-profile.yaml
profile:
  name: "Medical Device SBOM Profile"
  version: "1.0"
  description: "FDA-compliant SBOM requirements"

categories:
  ntia-minimum-elements:
    enabled: true
    weight: 1.0
    required: true  # Must pass all NTIA elements
    
  quality:
    enabled: true
    weight: 1.0
    features:
      - id: comp_with_versions
        enabled: true
        weight: 1.0
        required: true  # FDA requirement
        
      - id: comp_with_checksums
        enabled: true
        weight: 1.0
        required: true  # Integrity verification
        
      - id: sbom_creation_timestamp
        enabled: true
        weight: 1.0
        required: true  # Traceability
        
  regulatory:
    enabled: true
    weight: 1.0
    features:
      - id: fda_device_identifier
        enabled: true
        weight: 1.0
        
      - id: software_version
        enabled: true
        weight: 1.0
```

### Financial Services

Emphasis on compliance and risk management:

```yaml
# financial-services-profile.yaml
profile:
  name: "Financial Services SBOM Profile"
  version: "1.0"
  description: "PCI-DSS and DORA compliant"

categories:
  quality:
    enabled: true
    weight: 1.0
    features:
      - id: comp_valid_licenses
        enabled: true
        weight: 1.0
        required: true  # Legal compliance
        
      - id: comp_no_restrictive_licenses
        enabled: true
        weight: 0.9
        blacklist:
          - GPL-3.0
          - AGPL-3.0
          
      - id: comp_with_supplier
        enabled: true
        weight: 1.0
        required: true  # Vendor risk management
        
  security:
    enabled: true
    weight: 1.0
    features:
      - id: comp_with_cpes
        enabled: true
        weight: 1.0  # CVE tracking
        
      - id: comp_with_security_contact
        enabled: true
        weight: 0.9
```

### Open Source Projects

Focus on transparency and community standards:

```yaml
# open-source-profile.yaml
profile:
  name: "Open Source Project Profile"
  version: "1.0"
  description: "Community-focused SBOM requirements"

categories:
  sharing:
    enabled: true
    weight: 1.0
    features:
      - id: sbom_sharable
        enabled: true
        weight: 1.0
        
      - id: open_formats
        enabled: true
        weight: 1.0
        preferred:
          - SPDX
          - CycloneDX
          
  quality:
    enabled: true
    weight: 0.9
    features:
      - id: comp_with_source_urls
        enabled: true
        weight: 1.0
        
      - id: comp_with_licenses
        enabled: true
        weight: 1.0
        
      - id: comp_with_contributors
        enabled: true
        weight: 0.7
```

## Advanced Customization

### Conditional Scoring

Apply different weights based on component types:

```yaml
# conditional-scoring.yaml
categories:
  quality:
    features:
      - id: comp_with_checksums
        enabled: true
        conditions:
          - match:
              type: "library"
            weight: 1.0
          - match:
              type: "application"
            weight: 0.8
          - match:
              type: "container"
            weight: 1.0
          - match:
              language: "C"
            weight: 1.0  # Critical for memory-unsafe languages
          - match:
              language: "Python"
            weight: 0.5  # Less critical for interpreted languages
```

### Custom Thresholds

Define pass/fail thresholds:

```yaml
# thresholds.yaml
thresholds:
  overall:
    pass: 7.0
    warn: 5.0
    fail: 3.0
    
  categories:
    ntia-minimum-elements:
      pass: 8.0  # Stricter for compliance
    quality:
      pass: 6.0
    structural:
      pass: 9.0  # Must be well-formed
      
  features:
    comp_with_versions:
      min_coverage: 0.95  # 95% of components must have versions
    comp_with_licenses:
      min_coverage: 0.90  # 90% must have licenses
```

### Custom Policy

Add organization-specific policy rules:

```yaml
# policy.yaml
policy:
  - id: approved_licenses
    type: whitelist
    rules:
      - field: license
        values:
          - MIT
          - Apache-2.0
          - BSD-3-Clause
    action: warn  # or 'fail'
    
  - name: banned_components
    type: blacklist
    rules:
      - field: name
        patterns:
        - "log4j*"
        - "commons-collections-3.2.1"
    action: fail
    
  - name: required_metadata
    type: required
    rules:
      - field: supplier
      - field: version
      - field: license
      - field: checksum
    action: fail
```

For more, refer here: [policy.md](./policy.md)

## Organization Standards

### Creating a Company Standard

```yaml
# acme-corp-standard.yaml
standard:
  name: "ACME Corporation SBOM Standard"
  version: "2.0"
  effective_date: "2024-01-01"
  owner: "security@acme.com"
  
requirements:
  mandatory:
    - All components must have versions
    - All components must have valid SPDX licenses
    - SBOM must include creation timestamp
    - SBOM must include author information
    
  recommended:
    - Components should have checksums
    - Components should have CPE or PURL identifiers
    - SBOM should be signed
    
profiles:
  production:
    min_score: 8.0
    config: "production-profile.yaml"
    
  development:
    min_score: 6.0
    config: "development-profile.yaml"
    
  third_party:
    min_score: 7.0
    config: "vendor-profile.yaml"
```

### Department-Specific Profiles

```bash
# Create department profiles
mkdir -p profiles/{engineering,security,legal,ops}

# Engineering focus on technical quality
cat > profiles/engineering/config.yaml << 'EOF'
categories:
  quality:
    weight: 1.0
  structural:
    weight: 0.9
EOF

# Security focus on vulnerability management
cat > profiles/security/config.yaml << 'EOF'
categories:
  quality:
    features:
      - id: comp_with_cpes
        weight: 1.0
      - id: comp_with_checksums
        weight: 1.0
EOF

# Legal focus on licensing
cat > profiles/legal/config.yaml << 'EOF'
categories:
  quality:
    features:
      - id: comp_valid_licenses
        weight: 1.0
        required: true
      - id: comp_no_restrictive_licenses
        weight: 1.0
EOF
```

## Automation

### Profile Selection Script

```bash
#!/bin/bash
# select-profile.sh

PROJECT_TYPE=$1
ENVIRONMENT=$2

case "$PROJECT_TYPE" in
  "medical")
    PROFILE="medical-device-profile.yaml"
    ;;
  "financial")
    PROFILE="financial-services-profile.yaml"
    ;;
  "opensource")
    PROFILE="open-source-profile.yaml"
    ;;
  *)
    PROFILE="default-profile.yaml"
    ;;
esac

case "$ENVIRONMENT" in
  "production")
    MIN_SCORE=8.0
    ;;
  "staging")
    MIN_SCORE=7.0
    ;;
  "development")
    MIN_SCORE=5.0
    ;;
  *)
    MIN_SCORE=6.0
    ;;
esac

echo "Using profile: $PROFILE"
echo "Minimum score: $MIN_SCORE"

sbomqs score sbom.json --configpath "$PROFILE" --json | \
  jq --arg min "$MIN_SCORE" '
    if .files[0].avg_score >= ($min | tonumber) then
      "✅ PASSED: Score " + (.files[0].avg_score | tostring) + "/" + $min
    else
      "❌ FAILED: Score " + (.files[0].avg_score | tostring) + "/" + $min
    end
  '
```

### Dynamic Profile Generation

```python
#!/usr/bin/env python3
# generate-dynamic-profile.py

import yaml
import sys

def generate_profile(component_count, is_production, has_external_deps):
    profile = {
        'categories': {
            'quality': {
                'enabled': True,
                'weight': 1.0,
                'features': []
            }
        }
    }
    
    # Adjust based on component count
    if component_count > 1000:
        # Large projects need stricter controls
        profile['categories']['quality']['features'].append({
            'id': 'comp_with_checksums',
            'weight': 1.0,
            'required': True
        })
    
    # Production requirements
    if is_production:
        profile['categories']['quality']['features'].extend([
            {'id': 'comp_with_versions', 'weight': 1.0, 'required': True},
            {'id': 'comp_valid_licenses', 'weight': 1.0, 'required': True}
        ])
    
    # External dependencies
    if has_external_deps:
        profile['categories']['quality']['features'].append({
            'id': 'comp_with_supplier',
            'weight': 0.9,
            'required': True
        })
    
    return profile

if __name__ == '__main__':
    # Example usage
    profile = generate_profile(
        component_count=1500,
        is_production=True,
        has_external_deps=True
    )
    
    with open('dynamic-profile.yaml', 'w') as f:
        yaml.dump(profile, f, default_flow_style=False)
    
    print("Generated dynamic-profile.yaml")
```

## Testing Custom Profiles

### Validation Script

```bash
#!/bin/bash
# validate-profile.sh

PROFILE=$1
TEST_SBOM=$2

echo "Validating profile: $PROFILE"

# Check syntax
if ! yaml-lint "$PROFILE" 2>/dev/null; then
  echo "❌ Invalid YAML syntax"
  exit 1
fi

# Test with sample SBOM
if ! sbomqs score "$TEST_SBOM" --configpath "$PROFILE" --debug; then
  echo "❌ Profile failed to load"
  exit 1
fi

echo "✅ Profile is valid"

# Compare with default
DEFAULT_SCORE=$(sbomqs score "$TEST_SBOM" --json | jq '.files[0].avg_score')
CUSTOM_SCORE=$(sbomqs score "$TEST_SBOM" --configpath "$PROFILE" --json | jq '.files[0].avg_score')

echo "Default score: $DEFAULT_SCORE"
echo "Custom score: $CUSTOM_SCORE"
```

### A/B Testing Profiles

```python
#!/usr/bin/env python3
# ab-test-profiles.py

import subprocess
import json
import statistics

def test_profile(sbom_files, profile_path=None):
    scores = []
    
    for sbom in sbom_files:
        cmd = ['sbomqs', 'score', sbom, '--json']
        if profile_path:
            cmd.extend(['--configpath', profile_path])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(result.stdout)
        scores.append(data['files'][0]['avg_score'])
    
    return {
        'mean': statistics.mean(scores),
        'median': statistics.median(scores),
        'stdev': statistics.stdev(scores) if len(scores) > 1 else 0,
        'min': min(scores),
        'max': max(scores)
    }

# Test different profiles
sbom_files = ['sbom1.json', 'sbom2.json', 'sbom3.json']

default_stats = test_profile(sbom_files)
custom_stats = test_profile(sbom_files, 'custom-profile.yaml')

print(f"Default Profile: {default_stats}")
print(f"Custom Profile: {custom_stats}")
```

## Migration Guide

### Upgrading Profiles

```bash
#!/bin/bash
# migrate-profile.sh

OLD_PROFILE=$1
NEW_VERSION=$2

# Backup old profile
cp "$OLD_PROFILE" "$OLD_PROFILE.bak"

# Generate new template
sbomqs generate features > template.yaml

# Merge settings (pseudo-code)
echo "Migrating profile to version $NEW_VERSION"

# Add migration logic here
# - Map old feature IDs to new ones
# - Preserve custom weights
# - Add new required features

echo "Migration complete. Review the changes:"
diff "$OLD_PROFILE.bak" "$OLD_PROFILE"
```

## Best Practices

1. **Version Control**: Track all profile changes in Git
2. **Documentation**: Document why specific weights were chosen
3. **Testing**: Test profiles with representative SBOMs
4. **Review**: Regularly review and update profiles
5. **Standardization**: Create organization-wide standards
6. **Automation**: Automate profile selection based on context
7. **Monitoring**: Track score trends with different profiles
8. **Validation**: Validate profiles before deployment
