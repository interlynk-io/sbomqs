# `sbomqs share` Command

The `sbomqs share` command creates a permanent, shareable link to your SBOM quality score results. This allows you to share SBOM quality assessments with stakeholders without sharing the actual SBOM file.

## Overview

The share command:
- Uploads your SBOM score to [sbombenchmark.dev](https://sbombenchmark.dev)
- Generates a unique, permanent URL
- Provides a web-based visualization of your score
- Enables comparison with industry benchmarks
- Does NOT upload your actual SBOM content (only the score metadata)

## Usage

```bash
sbomqs share [flags] <SBOM file>
```

## Flags

- `--json, -j`: Output result in JSON format
- `--debug, -D`: Enable debug logging
- `--sbomtype <type>`: Specify SBOM type (spdx, cdx, or auto-detect)

## Examples

### Basic Usage

```bash
$ sbomqs share my-app.spdx.json

7.8 my-app.spdx.json
ShareLink: https://sbombenchmark.dev/user/score?id=a97af1bf-4c9d-4a55-8524-3d4bcee0b9a4
```

### JSON Output

```bash
$ sbomqs share my-app.spdx.json --json
```

```json
{
  "score": 7.8,
  "file": "my-app.spdx.json",
  "share_link": "https://sbombenchmark.dev/user/score?id=a97af1bf-4c9d-4a55-8524-3d4bcee0b9a4",
  "timestamp": "2024-01-15T10:30:00Z",
  "id": "a97af1bf-4c9d-4a55-8524-3d4bcee0b9a4"
}
```

## What Gets Shared

### Included in Share
- Quality score (0-10)
- Score breakdown by category
- Number of components
- SBOM specification type and version
- Creation timestamp
- Basic statistics (licenses, suppliers, etc.)

### NOT Included
- Actual SBOM content
- Component names or versions
- License details
- Supplier information
- Any sensitive data from your SBOM

## Use Cases

### Team Collaboration

Share quality scores with your team without exposing SBOM details:

```bash
# Generate shareable link for team review
$ sbomqs share release-v2.0.spdx.json

# Send link to team
echo "SBOM Quality Report: https://sbombenchmark.dev/user/score?id=..."
```

### Vendor Assessment

Evaluate and compare vendor-provided SBOMs:

```bash
# Score and share vendor SBOMs
for sbom in vendor-sboms/*.json; do
  echo "Processing: $sbom"
  sbomqs share "$sbom"
done
```

### Compliance Reporting

Generate shareable compliance evidence:

```bash
#!/bin/bash
# Create shareable compliance report

SBOM="product.spdx.json"

# Get quality score link
SHARE_URL=$(sbomqs share $SBOM --json | jq -r '.share_link')

# Generate compliance report
echo "Compliance Evidence Report" > compliance-report.md
echo "=========================" >> compliance-report.md
echo "" >> compliance-report.md
echo "SBOM Quality Score: $SHARE_URL" >> compliance-report.md
echo "" >> compliance-report.md

# Add compliance checks
sbomqs compliance --bsi-v2 $SBOM --basic >> compliance-report.md
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Share SBOM Score
  run: |
    # Generate and share score
    result=$(sbomqs share sbom.json --json)
    
    score=$(echo "$result" | jq -r '.score')
    link=$(echo "$result" | jq -r '.share_link')
    
    # Add to PR comment
    echo "## SBOM Quality Score: $score/10" >> pr-comment.md
    echo "[View detailed report]($link)" >> pr-comment.md
    
    # Post comment to PR
    gh pr comment ${{ github.event.pull_request.number }} --body-file pr-comment.md
```

### GitLab CI

```yaml
sbom-share:
  script:
    - |
      RESULT=$(sbomqs share sbom.json --json)
      SCORE=$(echo "$RESULT" | jq -r '.score')
      LINK=$(echo "$RESULT" | jq -r '.share_link')
      
      echo "SBOM Score: $SCORE/10"
      echo "Report: $LINK"
      
      # Add to merge request
      curl --request POST --header "PRIVATE-TOKEN: $CI_API_TOKEN" \
        "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes" \
        --data "body=SBOM Quality Score: $SCORE/10 - [View Report]($LINK)"
```

## Benchmark Comparison

The shared report on sbombenchmark.dev provides:

### Industry Comparison
- Compare your score against industry averages
- See percentile ranking
- View score distribution

### Historical Tracking
- Track score improvements over time
- Compare different versions
- Identify trends

### Category Analysis
- Detailed breakdown by scoring category
- Identify strengths and weaknesses
- Get improvement recommendations

## Automation Examples

### Batch Processing

Share scores for multiple SBOMs:

```bash
#!/bin/bash
# batch-share.sh

OUTPUT="share-results.csv"
echo "File,Score,URL" > $OUTPUT

for sbom in *.json; do
  result=$(sbomqs share "$sbom" --json)
  score=$(echo "$result" | jq -r '.score')
  url=$(echo "$result" | jq -r '.share_link')
  
  echo "$sbom,$score,$url" >> $OUTPUT
done

echo "Results saved to $OUTPUT"
```

### Weekly Reports

Generate weekly quality reports:

```bash
#!/bin/bash
# weekly-sbom-report.sh

REPORT_FILE="weekly-report-$(date +%Y-%W).md"

echo "# Weekly SBOM Quality Report" > $REPORT_FILE
echo "Week: $(date +%Y-%W)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

for sbom in current-sboms/*.json; do
  name=$(basename "$sbom")
  result=$(sbomqs share "$sbom")
  score=$(echo "$result" | head -1 | cut -d' ' -f1)
  url=$(echo "$result" | grep ShareLink | cut -d' ' -f2)
  
  echo "- **$name**: Score $score/10 - [View]($url)" >> $REPORT_FILE
done

# Send report
cat $REPORT_FILE | mail -s "Weekly SBOM Report" team@example.com
```

### Threshold Monitoring

Alert when scores are below threshold:

```bash
#!/bin/bash
# monitor-quality.sh

THRESHOLD=7.0
SBOM="latest-release.json"

result=$(sbomqs share $SBOM --json)
score=$(echo "$result" | jq -r '.score')
url=$(echo "$result" | jq -r '.share_link')

if (( $(echo "$score < $THRESHOLD" | bc -l) )); then
  # Send alert
  curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
    -H 'Content-Type: application/json' \
    -d "{
      \"text\": \"⚠️ SBOM Quality Alert\",
      \"attachments\": [{
        \"color\": \"warning\",
        \"fields\": [
          {\"title\": \"Score\", \"value\": \"$score/10\", \"short\": true},
          {\"title\": \"Threshold\", \"value\": \"$THRESHOLD/10\", \"short\": true},
          {\"title\": \"Report\", \"value\": \"<$url|View Details>\"}
        ]
      }]
    }"
fi
```

## Privacy and Security

### Data Handling
- Only score metadata is uploaded
- No component details are shared
- No license information is transmitted
- No supplier data is exposed

### URL Security
- URLs are randomly generated UUIDs
- Links are permanent but unlisted
- No authentication required to view
- No way to enumerate other reports

### Compliance
- Safe for regulated industries
- No PII or sensitive data exposure
- Compliant with data protection regulations

## Integration with Other Tools

### Dependency-Track

```bash
# Add score URL as project property
PROJECT_ID="your-project-id"
SCORE_URL=$(sbomqs share sbom.json --json | jq -r '.share_link')

curl -X POST "https://dtrack.example.com/api/v1/project/$PROJECT_ID/property" \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"groupName\": \"Quality\",
    \"propertyName\": \"SBOM Score\",
    \"propertyValue\": \"$SCORE_URL\",
    \"propertyType\": \"URL\"
  }"
```

### JIRA Integration

```bash
# Add score link to JIRA ticket
TICKET="PROJ-123"
SCORE_URL=$(sbomqs share sbom.json --json | jq -r '.share_link')

curl -X POST "https://your-domain.atlassian.net/rest/api/3/issue/$TICKET/comment" \
  -H "Authorization: Basic $JIRA_AUTH" \
  -H "Content-Type: application/json" \
  -d "{
    \"body\": {
      \"type\": \"doc\",
      \"version\": 1,
      \"content\": [{
        \"type\": \"paragraph\",
        \"content\": [{
          \"type\": \"text\",
          \"text\": \"SBOM Quality Score: \"
        }, {
          \"type\": \"text\",
          \"text\": \"View Report\",
          \"marks\": [{
            \"type\": \"link\",
            \"attrs\": {\"href\": \"$SCORE_URL\"}
          }]
        }]
      }]
    }
  }"
```

## Best Practices

### Regular Sharing
- Share scores for each release
- Track improvements over time
- Compare versions

### Documentation
- Include share links in release notes
- Add to compliance documentation
- Reference in security reports

### Communication
- Share with stakeholders
- Include in vendor assessments
- Use for team metrics

## Troubleshooting

### Connection Issues

```bash
# Check connectivity
curl -I https://sbombenchmark.dev

# Use proxy if needed
export HTTPS_PROXY=http://proxy.example.com:8080
sbomqs share sbom.json
```

### Large SBOMs

```bash
# For very large SBOMs, sharing might take longer
sbomqs share large-sbom.json --debug
```

### Error Handling

```bash
# Retry on failure
for i in {1..3}; do
  if sbomqs share sbom.json; then
    break
  fi
  echo "Retry $i failed, waiting..."
  sleep 5
done
```

## Related Commands

- [`score`](./score-command.md) - Calculate quality score
- [`compliance`](./compliance-command.md) - Check compliance
- [`list`](./list-command.md) - Analyze SBOM components