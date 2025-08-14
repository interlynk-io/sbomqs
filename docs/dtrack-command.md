# `sbomqs dtrackScore` Command

The `sbomqs dtrackScore` command integrates with Dependency-Track to score SBOMs directly from your Dependency-Track projects. This enables automated quality assessment within your existing vulnerability management workflow.

## Overview

The dtrackScore command:
- Connects to your Dependency-Track instance
- Downloads project SBOMs
- Calculates quality scores
- Optionally updates project properties with scores
- Supports batch processing of multiple projects

## Usage

```bash
sbomqs dtrackScore [flags] <project-uuid>
```

## Required Flags

- `-u, --url <url>`: Dependency-Track server URL
- `-k, --key <api-key>`: Dependency-Track API key

## Optional Flags

- `--basic, -b`: Output basic score only
- `--detailed, -d`: Show detailed scoring breakdown
- `--json, -j`: Output in JSON format
- `--category, -c <category>`: Score specific category only
- `--label`: Add score as project label in Dependency-Track
- `--property`: Add score as project property
- `--debug, -D`: Enable debug logging

## Authentication

### Getting an API Key

1. Log into Dependency-Track
2. Navigate to Administration → Access Management → Teams
3. Select your team and go to API Keys
4. Generate a new API key with appropriate permissions

### Required Permissions
- `VIEW_PORTFOLIO`: To read projects
- `PORTFOLIO_MANAGEMENT`: To update labels/properties (if using --label or --property)

## Examples

### Basic Usage

```bash
$ sbomqs dtrackScore -u "https://dtrack.example.com" \
                     -k "oGhWN0Y2OjE3MjQ5MzE1NTM4NjI6MWZhMWI5" \
                     "550e8400-e29b-41d4-a716-446655440000"

7.5 Project: my-application v2.0.1
```

### Detailed Score

```bash
$ sbomqs dtrackScore -u "https://dtrack.example.com" \
                     -k "$DT_API_KEY" \
                     "550e8400-e29b-41d4-a716-446655440000" \
                     --detailed

SBOM Quality Score: 7.5 my-application v2.0.1
+-----------------------+--------------------------------+-----------+
|       CATEGORY        |            FEATURE             |   SCORE   |
+-----------------------+--------------------------------+-----------+
| NTIA-minimum-elements | Components have names          | 10.0/10.0 |
|                       | Components have versions       | 9.0/10.0  |
|                       | Components have suppliers      | 6.0/10.0  |
|                       | Doc has creation timestamp     | 10.0/10.0 |
+-----------------------+--------------------------------+-----------+
| Quality               | Valid licenses                 | 7.0/10.0  |
|                       | Components have checksums      | 5.0/10.0  |
+-----------------------+--------------------------------+-----------+
```

### JSON Output for Automation

```bash
$ sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$PROJECT_ID" --json
```

```json
{
  "project_id": "550e8400-e29b-41d4-a716-446655440000",
  "project_name": "my-application",
  "project_version": "2.0.1",
  "score": 7.5,
  "timestamp": "2024-01-15T10:30:00Z",
  "categories": {
    "ntia": 8.5,
    "quality": 6.5,
    "structural": 9.0
  },
  "num_components": 250
}
```

## Updating Dependency-Track

### Add Score as Label

```bash
$ sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$PROJECT_ID" \
                     --label

Score: 7.5
Label "SBOM-Score-7.5" added to project
```

### Add Score as Property

```bash
$ sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$PROJECT_ID" \
                     --property

Score: 7.5
Property "sbom.quality.score" = "7.5" added to project
```

## Batch Processing

### Score Multiple Projects

```bash
#!/bin/bash
# score-all-projects.sh

DT_URL="https://dtrack.example.com"
DT_KEY="your-api-key"

# Get all project UUIDs
projects=$(curl -s -H "X-Api-Key: $DT_KEY" \
  "$DT_URL/api/v1/project" | jq -r '.[].uuid')

# Score each project
for uuid in $projects; do
  echo "Scoring project: $uuid"
  sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$uuid" --basic
done
```

### Filter by Score

```bash
#!/bin/bash
# find-low-quality-sboms.sh

THRESHOLD=7.0
DT_URL="https://dtrack.example.com"
DT_KEY="your-api-key"

# Get all projects
projects=$(curl -s -H "X-Api-Key: $DT_KEY" \
  "$DT_URL/api/v1/project" | jq -r '.[].uuid')

echo "Projects with low SBOM quality (<$THRESHOLD):"
for uuid in $projects; do
  result=$(sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$uuid" --json 2>/dev/null)
  if [ $? -eq 0 ]; then
    score=$(echo "$result" | jq -r '.score')
    name=$(echo "$result" | jq -r '.project_name')
    
    if (( $(echo "$score < $THRESHOLD" | bc -l) )); then
      echo "- $name: $score/10"
    fi
  fi
done
```

## CI/CD Integration

### Jenkins Pipeline

```groovy
pipeline {
    environment {
        DT_URL = credentials('dependency-track-url')
        DT_KEY = credentials('dependency-track-api-key')
    }
    
    stages {
        stage('SBOM Quality Check') {
            steps {
                script {
                    // Score SBOM in Dependency-Track
                    def result = sh(
                        script: "sbomqs dtrackScore -u $DT_URL -k $DT_KEY ${PROJECT_UUID} --json",
                        returnStdout: true
                    ).trim()
                    
                    def scoreData = readJSON text: result
                    def score = scoreData.score
                    
                    // Fail if score is too low
                    if (score < 7.0) {
                        error("SBOM quality score too low: ${score}/10")
                    }
                    
                    // Add score to build description
                    currentBuild.description = "SBOM Score: ${score}/10"
                    
                    // Update project in Dependency-Track
                    sh "sbomqs dtrackScore -u $DT_URL -k $DT_KEY ${PROJECT_UUID} --label"
                }
            }
        }
    }
}
```

### GitHub Actions

```yaml
- name: Score SBOM in Dependency-Track
  env:
    DT_URL: ${{ secrets.DEPENDENCY_TRACK_URL }}
    DT_KEY: ${{ secrets.DEPENDENCY_TRACK_API_KEY }}
  run: |
    # Upload SBOM to Dependency-Track first
    PROJECT_UUID=$(curl -X POST "$DT_URL/api/v1/bom" \
      -H "X-Api-Key: $DT_KEY" \
      -H "Content-Type: application/json" \
      -d "{
        \"projectName\": \"${{ github.repository }}\",
        \"projectVersion\": \"${{ github.sha }}\",
        \"autoCreate\": true,
        \"bom\": \"$(base64 -w 0 sbom.json)\"
      }" | jq -r '.token')
    
    # Wait for processing
    sleep 10
    
    # Score the SBOM
    score=$(sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$PROJECT_UUID" --json | jq -r '.score')
    
    echo "SBOM Score: $score/10"
    echo "sbom_score=$score" >> $GITHUB_OUTPUT
    
    # Update project with score
    sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$PROJECT_UUID" --label --property
```

## Dashboard Integration

### Create Quality Dashboard

```python
#!/usr/bin/env python3
# dt-quality-dashboard.py

import requests
import json
import subprocess
from datetime import datetime

DT_URL = "https://dtrack.example.com"
DT_KEY = "your-api-key"

# Get all projects
headers = {"X-Api-Key": DT_KEY}
projects = requests.get(f"{DT_URL}/api/v1/project", headers=headers).json()

# Score each project
results = []
for project in projects:
    uuid = project['uuid']
    name = project['name']
    version = project.get('version', 'unknown')
    
    # Get SBOM score
    cmd = f"sbomqs dtrackScore -u {DT_URL} -k {DT_KEY} {uuid} --json"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        score_data = json.loads(result.stdout)
        results.append({
            'name': name,
            'version': version,
            'score': score_data['score'],
            'categories': score_data.get('categories', {})
        })

# Generate HTML dashboard
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SBOM Quality Dashboard</title>
    <style>
        .good {{ background-color: #4CAF50; }}
        .warning {{ background-color: #FFC107; }}
        .bad {{ background-color: #F44336; }}
    </style>
</head>
<body>
    <h1>SBOM Quality Dashboard</h1>
    <p>Generated: {datetime.now()}</p>
    <table border="1">
        <tr>
            <th>Project</th>
            <th>Version</th>
            <th>Score</th>
            <th>NTIA</th>
            <th>Quality</th>
        </tr>
"""

for r in sorted(results, key=lambda x: x['score']):
    score_class = 'good' if r['score'] >= 7 else 'warning' if r['score'] >= 5 else 'bad'
    html += f"""
        <tr>
            <td>{r['name']}</td>
            <td>{r['version']}</td>
            <td class="{score_class}">{r['score']:.1f}/10</td>
            <td>{r['categories'].get('ntia', 'N/A'):.1f}</td>
            <td>{r['categories'].get('quality', 'N/A'):.1f}</td>
        </tr>
    """

html += """
    </table>
</body>
</html>
"""

with open("sbom-quality-dashboard.html", "w") as f:
    f.write(html)

print("Dashboard generated: sbom-quality-dashboard.html")
```

## Monitoring and Alerts

### Slack Notifications

```bash
#!/bin/bash
# dt-quality-monitor.sh

DT_URL="https://dtrack.example.com"
DT_KEY="your-api-key"
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
THRESHOLD=7.0

# Check critical projects
CRITICAL_PROJECTS=(
  "550e8400-e29b-41d4-a716-446655440000"
  "660e8400-e29b-41d4-a716-446655440001"
)

for uuid in "${CRITICAL_PROJECTS[@]}"; do
  result=$(sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$uuid" --json)
  score=$(echo "$result" | jq -r '.score')
  name=$(echo "$result" | jq -r '.project_name')
  
  if (( $(echo "$score < $THRESHOLD" | bc -l) )); then
    # Send Slack alert
    curl -X POST "$SLACK_WEBHOOK" \
      -H 'Content-Type: application/json' \
      -d "{
        \"text\": \"⚠️ Low SBOM Quality Alert\",
        \"attachments\": [{
          \"color\": \"danger\",
          \"fields\": [
            {\"title\": \"Project\", \"value\": \"$name\", \"short\": true},
            {\"title\": \"Score\", \"value\": \"$score/10\", \"short\": true}
          ]
        }]
      }"
  fi
done
```

## Best Practices

### Regular Scanning

```bash
# Add to crontab for daily scanning
0 2 * * * /usr/local/bin/sbomqs-dt-scan.sh
```

### Score Tracking

```bash
#!/bin/bash
# track-scores.sh

# Log scores over time
DATE=$(date +%Y-%m-%d)
LOG_FILE="sbom-scores-$DATE.csv"

echo "Project,Version,Score,Timestamp" > "$LOG_FILE"

projects=$(curl -s -H "X-Api-Key: $DT_KEY" "$DT_URL/api/v1/project" | jq -r '.[].uuid')

for uuid in $projects; do
  result=$(sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$uuid" --json)
  name=$(echo "$result" | jq -r '.project_name')
  version=$(echo "$result" | jq -r '.project_version')
  score=$(echo "$result" | jq -r '.score')
  
  echo "$name,$version,$score,$(date -Iseconds)" >> "$LOG_FILE"
done
```

## Troubleshooting

### Connection Issues

```bash
# Test connectivity
curl -H "X-Api-Key: $DT_KEY" "$DT_URL/api/version"

# Use proxy if needed
export HTTPS_PROXY=http://proxy.example.com:8080
sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$PROJECT_ID"
```

### Authentication Errors

```bash
# Verify API key permissions
curl -H "X-Api-Key: $DT_KEY" "$DT_URL/api/v1/permission"
```

### Debug Mode

```bash
# Get detailed error information
sbomqs dtrackScore -u "$DT_URL" -k "$DT_KEY" "$PROJECT_ID" --debug
```

## Related Commands

- [`score`](./score-command.md) - Score local SBOM files
- [`compliance`](./compliance-command.md) - Check compliance standards
- [`share`](./share-command.md) - Generate shareable reports