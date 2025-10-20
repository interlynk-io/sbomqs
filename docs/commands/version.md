# `sbomqs version` Command

The `sbomqs version` command displays version information about the sbomqs tool, including the build version, scoring engine version, and build metadata.

## Overview

The version command provides:
- Tool version number
- Scoring engine version
- Build commit hash
- Build date and time
- Go version used for compilation

## Usage

```bash
sbomqs version [flags]
```

## Flags

- `--json, -j`: Output version information in JSON format
- `--short, -s`: Display only the version number

## Examples

### Basic Usage

```bash
$ sbomqs version

sbomqs version: v1.0.0
Scoring Engine: v5
Build Commit: a1b2c3d4
Build Date: 2024-01-15T10:30:00Z
Go Version: go1.21.5
```

### Short Version

```bash
$ sbomqs version --short

v1.0.0
```

### JSON Output

```bash
$ sbomqs version --json
```

```json
{
  "version": "v1.0.0",
  "scoring_engine": "v5",
  "build": {
    "commit": "a1b2c3d4",
    "date": "2024-01-15T10:30:00Z",
    "go_version": "go1.21.5"
  }
}
```

## Use Cases

### Version Checking in Scripts

```bash
#!/bin/bash
# Check minimum version requirement

REQUIRED_VERSION="1.0.0"
CURRENT_VERSION=$(sbomqs version --short | sed 's/v//')

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$CURRENT_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: sbomqs version $REQUIRED_VERSION or higher is required"
    echo "Current version: $CURRENT_VERSION"
    exit 1
fi

echo "Version check passed: $CURRENT_VERSION"
```

### CI/CD Version Logging

```yaml
# GitHub Actions
- name: Log sbomqs version
  run: |
    echo "## SBOM Quality Scanner Version" >> $GITHUB_STEP_SUMMARY
    sbomqs version --json | jq -r '
      "- Version: \(.version)",
      "- Scoring Engine: \(.scoring_engine)",
      "- Build Date: \(.build.date)"
    ' >> $GITHUB_STEP_SUMMARY
```

### Debugging Information

```bash
# Include version in bug reports
$ sbomqs version --json > debug-info.json

# Add to support ticket
echo "Environment Information:" > support-ticket.txt
echo "========================" >> support-ticket.txt
sbomqs version >> support-ticket.txt
echo "" >> support-ticket.txt
echo "System: $(uname -a)" >> support-ticket.txt
```

## Version Compatibility

### Scoring Engine Versions

Different scoring engine versions may produce different scores:

```bash
# Check scoring engine compatibility
ENGINE_VERSION=$(sbomqs version --json | jq -r '.scoring_engine')

case $ENGINE_VERSION in
  "v5")
    echo "Using latest scoring algorithm"
    ;;
  "v4")
    echo "Warning: Older scoring engine, consider upgrading"
    ;;
  *)
    echo "Unknown scoring engine version: $ENGINE_VERSION"
    ;;
esac
```

### Feature Availability

```bash
#!/bin/bash
# Check if version supports specific features

VERSION=$(sbomqs version --short | sed 's/v//')

# Check for BSI v2 support (added in v0.1.0)
if [ "$(printf '%s\n' "0.1.0" "$VERSION" | sort -V | head -n1)" = "0.1.0" ]; then
    echo "BSI v2 compliance checking is available"
    sbomqs compliance --bsi-v2 sbom.json
else
    echo "BSI v2 not supported in version $VERSION"
    sbomqs compliance --bsi sbom.json  # Use v1 instead
fi
```

## Update Checking

### Manual Update Check

```bash
#!/bin/bash
# check-updates.sh

CURRENT=$(sbomqs version --short)
LATEST=$(curl -s https://api.github.com/repos/interlynk-io/sbomqs/releases/latest | jq -r '.tag_name')

if [ "$CURRENT" != "$LATEST" ]; then
    echo "Update available: $CURRENT → $LATEST"
    echo "Download: https://github.com/interlynk-io/sbomqs/releases/latest"
else
    echo "You are using the latest version: $CURRENT"
fi
```

### Automated Updates

```bash
#!/bin/bash
# auto-update.sh

# Check and update sbomqs
update_sbomqs() {
    local CURRENT=$(sbomqs version --short)
    local LATEST=$(curl -s https://api.github.com/repos/interlynk-io/sbomqs/releases/latest | jq -r '.tag_name')
    
    if [ "$CURRENT" != "$LATEST" ]; then
        echo "Updating sbomqs from $CURRENT to $LATEST..."
        
        # Update via Homebrew
        if command -v brew &> /dev/null; then
            brew upgrade sbomqs
        # Update via Go
        elif command -v go &> /dev/null; then
            go install github.com/interlynk-io/sbomqs@latest
        else
            echo "Please update sbomqs manually"
            return 1
        fi
        
        echo "Updated to: $(sbomqs version --short)"
    fi
}

update_sbomqs
```

## Version in Reports

### Include Version in Output

```bash
# Add version to reports for traceability
$ cat << EOF > sbom-report.md
# SBOM Quality Report

Generated: $(date)
Tool Version: $(sbomqs version --short)
Scoring Engine: $(sbomqs version --json | jq -r '.scoring_engine')

## Results
$(sbomqs score *.json --basic)
EOF
```

### Audit Trail

```bash
#!/bin/bash
# Create audit log with version info

LOG_FILE="sbom-audit.log"
VERSION_INFO=$(sbomqs version --json | jq -c .)

echo "[$(date -Iseconds)] Version: $VERSION_INFO" >> $LOG_FILE
echo "[$(date -Iseconds)] Scanning $(ls *.json | wc -l) SBOMs" >> $LOG_FILE

for sbom in *.json; do
    score=$(sbomqs score "$sbom" --basic | cut -d' ' -f1)
    echo "[$(date -Iseconds)] $sbom: $score/10" >> $LOG_FILE
done
```

## Troubleshooting

### Version Mismatch Issues

```bash
# Verify installation
$ which sbomqs
/usr/local/bin/sbomqs

$ sbomqs version

# Check for multiple installations
$ find / -name sbomqs -type f 2>/dev/null

# Ensure PATH is correct
$ echo $PATH
```

### Build Information

```bash
# Get detailed build info for debugging
$ sbomqs version --json | jq '.build'

{
  "commit": "a1b2c3d4",
  "date": "2024-01-15T10:30:00Z",
  "go_version": "go1.21.5"
}

# Report issues with commit hash
echo "Issue found in version $(sbomqs version --json | jq -r '.version') (commit: $(sbomqs version --json | jq -r '.build.commit'))"
```

## Docker Version

### Check Version in Container

```bash
# Run version command in Docker
$ docker run ghcr.io/interlynk-io/sbomqs:latest version

# Get specific version
$ docker run ghcr.io/interlynk-io/sbomqs:v1.0.0 version --short
```

### Multi-Architecture Support

```bash
# Check architecture support
$ docker run --rm ghcr.io/interlynk-io/sbomqs:latest sh -c "sbomqs version && uname -m"
```

## Environment Variables

### Version Check Override

```bash
# Disable automatic version checking
export INTERLYNK_DISABLE_VERSION_CHECK=true
sbomqs score sbom.json

# Force specific behavior based on version
VERSION=$(sbomqs version --short)
if [[ "$VERSION" == "v0."* ]]; then
    export SBOMQS_LEGACY_MODE=true
fi
```

## Integration with Other Tools

### Version Reporting in CI

```groovy
// Jenkins Pipeline
pipeline {
    stages {
        stage('Version Info') {
            steps {
                script {
                    def versionInfo = sh(
                        script: 'sbomqs version --json',
                        returnStdout: true
                    ).trim()
                    
                    def version = readJSON text: versionInfo
                    
                    echo "SBOMQS Version: ${version.version}"
                    echo "Scoring Engine: ${version.scoring_engine}"
                    
                    // Add to build description
                    currentBuild.description = "sbomqs ${version.version}"
                }
            }
        }
    }
}
```

## Related Commands

- [`score`](./score.md) - Score SBOMs with current version
- [`compliance`](./compliance.md) - Check compliance with version-specific features
- [`generate`](./generate.md) - Generate configs compatible with version