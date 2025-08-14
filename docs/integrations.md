# Integration Guide

This guide covers how to integrate SBOMQS into various CI/CD pipelines, development workflows, and third-party tools.

## CI/CD Integrations

### GitHub Actions

#### Basic Integration

```yaml
name: SBOM Quality Check

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  sbom-quality:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install SBOMQS
      run: |
        curl -LO https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_linux_amd64.tar.gz
        tar -xzf sbomqs_linux_amd64.tar.gz
        sudo mv sbomqs /usr/local/bin/
        
    - name: Generate SBOM
      run: |
        # Example using syft
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
        syft . -o spdx-json > sbom.json
        
    - name: Check SBOM Quality
      run: |
        score=$(sbomqs score sbom.json --json | jq '.files[0].avg_score')
        echo "SBOM Score: $score/10"
        
        if (( $(echo "$score < 7.0" | bc -l) )); then
          echo "::error::SBOM quality score too low: $score"
          exit 1
        fi
        
    - name: Check Compliance
      run: |
        sbomqs compliance --bsi-v2 sbom.json --json > compliance.json
        
        if [ $(jq '.summary.compliant' compliance.json) != "true" ]; then
          echo "::error::SBOM is not BSI compliant"
          jq '.recommendations[]' compliance.json
          exit 1
        fi
        
    - name: Upload Reports
      uses: actions/upload-artifact@v3
      with:
        name: sbom-reports
        path: |
          sbom.json
          compliance.json
```

#### Reusable Workflow

```yaml
# .github/workflows/sbom-quality-reusable.yml
name: SBOM Quality Check

on:
  workflow_call:
    inputs:
      sbom-file:
        required: true
        type: string
      min-score:
        required: false
        type: number
        default: 7.0
      compliance-standard:
        required: false
        type: string
        default: 'bsi-v2'
    outputs:
      score:
        value: ${{ jobs.check.outputs.score }}
      compliant:
        value: ${{ jobs.check.outputs.compliant }}

jobs:
  check:
    runs-on: ubuntu-latest
    outputs:
      score: ${{ steps.score.outputs.value }}
      compliant: ${{ steps.compliance.outputs.value }}
      
    steps:
    - name: Setup SBOMQS
      uses: interlynk-io/sbomqs-action@v1
      
    - name: Score SBOM
      id: score
      run: |
        score=$(sbomqs score ${{ inputs.sbom-file }} --json | jq '.files[0].avg_score')
        echo "value=$score" >> $GITHUB_OUTPUT
        
        if (( $(echo "$score < ${{ inputs.min-score }}" | bc -l) )); then
          exit 1
        fi
        
    - name: Check Compliance
      id: compliance
      run: |
        compliant=$(sbomqs compliance --${{ inputs.compliance-standard }} ${{ inputs.sbom-file }} --json | jq '.summary.compliant')
        echo "value=$compliant" >> $GITHUB_OUTPUT
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - build
  - sbom
  - quality

variables:
  SBOMQS_VERSION: "latest"
  MIN_SCORE: "7.0"

.install-sbomqs:
  before_script:
    - curl -LO https://github.com/interlynk-io/sbomqs/releases/${SBOMQS_VERSION}/download/sbomqs_linux_amd64.tar.gz
    - tar -xzf sbomqs_linux_amd64.tar.gz
    - mv sbomqs /usr/local/bin/

generate-sbom:
  stage: sbom
  image: alpine:latest
  script:
    - apk add --no-cache curl
    - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    - syft . -o spdx-json > sbom.json
  artifacts:
    paths:
      - sbom.json
    expire_in: 1 week

check-sbom-quality:
  stage: quality
  extends: .install-sbomqs
  dependencies:
    - generate-sbom
  script:
    - score=$(sbomqs score sbom.json --json | jq '.files[0].avg_score')
    - echo "SBOM Score: $score/10"
    - |
      if [ $(echo "$score < $MIN_SCORE" | bc) -eq 1 ]; then
        echo "SBOM quality score too low: $score"
        exit 1
      fi
    - sbomqs share sbom.json > share-result.txt
    - echo "Share URL: $(grep ShareLink share-result.txt | cut -d' ' -f2)"
  artifacts:
    reports:
      dotenv: sbom-score.env
    paths:
      - share-result.txt

compliance-check:
  stage: quality
  extends: .install-sbomqs
  dependencies:
    - generate-sbom
  script:
    - sbomqs compliance --bsi-v2 sbom.json --json > bsi-compliance.json
    - sbomqs compliance --fsct sbom.json --json > fsct-compliance.json
  artifacts:
    paths:
      - "*-compliance.json"
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        SBOMQS_VERSION = 'latest'
        MIN_SCORE = 7.0
    }
    
    stages {
        stage('Setup') {
            steps {
                sh '''
                    curl -LO https://github.com/interlynk-io/sbomqs/releases/${SBOMQS_VERSION}/download/sbomqs_linux_amd64.tar.gz
                    tar -xzf sbomqs_linux_amd64.tar.gz
                    chmod +x sbomqs
                '''
            }
        }
        
        stage('Generate SBOM') {
            steps {
                sh '''
                    # Using cdxgen as example
                    npm install -g @cyclonedx/cdxgen
                    cdxgen -o sbom.json
                '''
            }
        }
        
        stage('Quality Check') {
            steps {
                script {
                    def scoreOutput = sh(
                        script: './sbomqs score sbom.json --json',
                        returnStdout: true
                    ).trim()
                    
                    def scoreData = readJSON text: scoreOutput
                    def score = scoreData.files[0].avg_score
                    
                    echo "SBOM Score: ${score}/10"
                    
                    if (score < env.MIN_SCORE.toFloat()) {
                        error("SBOM quality score ${score} is below threshold ${env.MIN_SCORE}")
                    }
                    
                    // Add score to build description
                    currentBuild.description = "SBOM Score: ${score}/10"
                }
            }
        }
        
        stage('Compliance Check') {
            parallel {
                stage('BSI Compliance') {
                    steps {
                        sh './sbomqs compliance --bsi-v2 sbom.json --json > bsi-compliance.json'
                        
                        script {
                            def compliance = readJSON file: 'bsi-compliance.json'
                            if (!compliance.summary.compliant) {
                                unstable("BSI compliance check failed")
                            }
                        }
                    }
                }
                
                stage('FSCT Compliance') {
                    steps {
                        sh './sbomqs compliance --fsct sbom.json --json > fsct-compliance.json'
                        
                        script {
                            def compliance = readJSON file: 'fsct-compliance.json'
                            if (!compliance.summary.compliant) {
                                unstable("FSCT compliance check failed")
                            }
                        }
                    }
                }
            }
        }
        
        stage('Share Results') {
            steps {
                script {
                    def shareOutput = sh(
                        script: './sbomqs share sbom.json',
                        returnStdout: true
                    ).trim()
                    
                    def shareUrl = shareOutput.split('\n')[1].split(' ')[1]
                    
                    echo "SBOM Quality Report: ${shareUrl}"
                    
                    // Add to build summary
                    def summary = manager.createSummary("graph.png")
                    summary.appendText("<a href='${shareUrl}'>View SBOM Quality Report</a>", false)
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*.json', allowEmptyArchive: true
            
            // Publish test results if using JUnit format
            junit allowEmptyResults: true, testResults: '*-compliance.json'
        }
    }
}
```

### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
  sbomqsVersion: 'latest'
  minScore: 7.0

stages:
- stage: Build
  jobs:
  - job: GenerateSBOM
    steps:
    - task: Bash@3
      displayName: 'Install SBOM Generator'
      inputs:
        targetType: 'inline'
        script: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b $(Agent.ToolsDirectory)
          echo "##vso[task.prependpath]$(Agent.ToolsDirectory)"
          
    - task: Bash@3
      displayName: 'Generate SBOM'
      inputs:
        targetType: 'inline'
        script: |
          syft . -o spdx-json > $(Build.ArtifactStagingDirectory)/sbom.json
          
    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: '$(Build.ArtifactStagingDirectory)/sbom.json'
        artifactName: 'sbom'

- stage: Quality
  dependsOn: Build
  jobs:
  - job: CheckQuality
    steps:
    - task: DownloadBuildArtifacts@0
      inputs:
        artifactName: 'sbom'
        downloadPath: '$(System.DefaultWorkingDirectory)'
        
    - task: Bash@3
      displayName: 'Install SBOMQS'
      inputs:
        targetType: 'inline'
        script: |
          curl -LO https://github.com/interlynk-io/sbomqs/releases/$(sbomqsVersion)/download/sbomqs_linux_amd64.tar.gz
          tar -xzf sbomqs_linux_amd64.tar.gz
          chmod +x sbomqs
          
    - task: Bash@3
      displayName: 'Check SBOM Quality'
      inputs:
        targetType: 'inline'
        script: |
          score=$(./sbomqs score sbom/sbom.json --json | jq '.files[0].avg_score')
          echo "SBOM Score: $score/10"
          echo "##vso[task.setvariable variable=sbomScore;isOutput=true]$score"
          
          if (( $(echo "$score < $(minScore)" | bc -l) )); then
            echo "##vso[task.logissue type=error]SBOM quality score $score is below threshold $(minScore)"
            exit 1
          fi
      name: scoreCheck
      
    - task: Bash@3
      displayName: 'Check Compliance'
      inputs:
        targetType: 'inline'
        script: |
          ./sbomqs compliance --bsi-v2 sbom/sbom.json --json > bsi-compliance.json
          ./sbomqs compliance --fsct sbom/sbom.json --json > fsct-compliance.json
          
          # Check BSI compliance
          bsi_compliant=$(jq '.summary.compliant' bsi-compliance.json)
          if [ "$bsi_compliant" != "true" ]; then
            echo "##vso[task.logissue type=warning]SBOM is not BSI compliant"
          fi
          
    - task: PublishTestResults@2
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: '*-compliance.json'
        failTaskOnFailedTests: false
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1

orbs:
  sbomqs: interlynk/sbomqs@1.0.0

jobs:
  generate-sbom:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install Syft
          command: |
            curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/bin
            echo 'export PATH=~/bin:$PATH' >> $BASH_ENV
      - run:
          name: Generate SBOM
          command: syft . -o spdx-json > sbom.json
      - persist_to_workspace:
          root: .
          paths:
            - sbom.json

  check-quality:
    docker:
      - image: cimg/base:stable
    steps:
      - attach_workspace:
          at: .
      - run:
          name: Install SBOMQS
          command: |
            curl -LO https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_linux_amd64.tar.gz
            tar -xzf sbomqs_linux_amd64.tar.gz
            chmod +x sbomqs
      - run:
          name: Score SBOM
          command: |
            score=$(./sbomqs score sbom.json --json | jq '.files[0].avg_score')
            echo "SBOM Score: $score/10"
            
            if (( $(echo "$score < 7.0" | bc -l) )); then
              echo "SBOM quality score too low: $score"
              exit 1
            fi
      - run:
          name: Check Compliance
          command: |
            ./sbomqs compliance --bsi-v2 sbom.json --json > bsi-compliance.json
            ./sbomqs compliance --fsct sbom.json --json > fsct-compliance.json
      - store_artifacts:
          path: bsi-compliance.json
      - store_artifacts:
          path: fsct-compliance.json

workflows:
  sbom-quality:
    jobs:
      - generate-sbom
      - check-quality:
          requires:
            - generate-sbom
```

## Container Integration

### Dockerfile

```dockerfile
# Multi-stage build with SBOM generation and quality check
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Generate SBOM
FROM anchore/syft:latest AS sbom-generator
COPY --from=builder /app /app
RUN syft /app -o spdx-json > /sbom.json

# Check SBOM quality
FROM ghcr.io/interlynk-io/sbomqs:latest AS sbom-checker
COPY --from=sbom-generator /sbom.json /sbom.json
RUN sbomqs score /sbom.json --json > /score.json && \
    score=$(cat /score.json | jq '.files[0].avg_score') && \
    if [ $(echo "$score < 7.0" | bc) -eq 1 ]; then \
        echo "SBOM quality score too low: $score"; \
        exit 1; \
    fi

# Final image
FROM alpine:latest
COPY --from=builder /app/myapp /usr/local/bin/
COPY --from=sbom-generator /sbom.json /sbom.json
COPY --from=sbom-checker /score.json /sbom-score.json
ENTRYPOINT ["myapp"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  app:
    build: .
    volumes:
      - ./sboms:/sboms
      
  sbom-quality:
    image: ghcr.io/interlynk-io/sbomqs:latest
    volumes:
      - ./sboms:/sboms
    command: score /sboms/*.json --basic
    
  sbom-compliance:
    image: ghcr.io/interlynk-io/sbomqs:latest
    volumes:
      - ./sboms:/sboms
      - ./reports:/reports
    command: compliance --bsi-v2 /sboms/*.json --json > /reports/compliance.json
```

## Kubernetes Integration

### Job Definition

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: sbom-quality-check
spec:
  template:
    spec:
      containers:
      - name: sbomqs
        image: ghcr.io/interlynk-io/sbomqs:latest
        command: 
        - sh
        - -c
        - |
          sbomqs score /sboms/*.json --json > /reports/scores.json
          sbomqs compliance --bsi-v2 /sboms/*.json --json > /reports/compliance.json
        volumeMounts:
        - name: sboms
          mountPath: /sboms
        - name: reports
          mountPath: /reports
      volumes:
      - name: sboms
        configMap:
          name: sbom-files
      - name: reports
        emptyDir: {}
      restartPolicy: Never
```

### CronJob for Regular Checks

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: daily-sbom-quality-check
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: sbomqs
            image: ghcr.io/interlynk-io/sbomqs:latest
            env:
            - name: SLACK_WEBHOOK
              valueFrom:
                secretKeyRef:
                  name: slack-secrets
                  key: webhook-url
            command:
            - sh
            - -c
            - |
              # Score all SBOMs
              for sbom in /sboms/*.json; do
                score=$(sbomqs score "$sbom" --json | jq '.files[0].avg_score')
                name=$(basename "$sbom")
                
                if (( $(echo "$score < 7.0" | bc -l) )); then
                  # Send alert
                  curl -X POST "$SLACK_WEBHOOK" \
                    -H 'Content-Type: application/json' \
                    -d "{\"text\": \"⚠️ Low SBOM score for $name: $score/10\"}"
                fi
              done
            volumeMounts:
            - name: sboms
              mountPath: /sboms
          volumes:
          - name: sboms
            persistentVolumeClaim:
              claimName: sbom-storage
          restartPolicy: OnFailure
```

## IDE Integration

### VS Code Task

```json
// .vscode/tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Check SBOM Quality",
      "type": "shell",
      "command": "sbomqs",
      "args": [
        "score",
        "${workspaceFolder}/sbom.json",
        "--detailed"
      ],
      "group": {
        "kind": "test",
        "isDefault": true
      },
      "presentation": {
        "reveal": "always",
        "panel": "new"
      }
    },
    {
      "label": "Check BSI Compliance",
      "type": "shell",
      "command": "sbomqs",
      "args": [
        "compliance",
        "--bsi-v2",
        "${workspaceFolder}/sbom.json"
      ]
    }
  ]
}
```

### Git Hooks

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check if SBOM exists
if [ -f "sbom.json" ]; then
    echo "Checking SBOM quality..."
    
    score=$(sbomqs score sbom.json --json | jq '.files[0].avg_score')
    
    if (( $(echo "$score < 7.0" | bc -l) )); then
        echo "Error: SBOM quality score ($score) is below threshold (7.0)"
        echo "Run 'sbomqs score sbom.json --detailed' for details"
        exit 1
    fi
    
    echo "SBOM quality check passed: $score/10"
fi
```

## Third-Party Tool Integration

### Dependency-Track

See [dtrack-command.md](./dtrack-command.md) for detailed integration.

### SonarQube

```groovy
// Add to sonar-project.properties
sonar.externalIssuesReportPaths=sbom-quality-report.json

// Generate report in SonarQube format
stage('SBOM Analysis') {
    steps {
        sh '''
            sbomqs score sbom.json --json > sbom-score.json
            
            # Convert to SonarQube format
            jq '{
              issues: [
                .files[0].scores[] | 
                select(.score < .max_score) |
                {
                  engineId: "sbomqs",
                  ruleId: .feature,
                  severity: (if .score < 5 then "MAJOR" else "MINOR" end),
                  type: "CODE_SMELL",
                  primaryLocation: {
                    message: .description,
                    filePath: "sbom.json"
                  }
                }
              ]
            }' sbom-score.json > sbom-quality-report.json
        '''
    }
}
```

## API Integration

### REST API Wrapper

```python
#!/usr/bin/env python3
# sbomqs-api.py

from flask import Flask, request, jsonify
import subprocess
import json
import tempfile

app = Flask(__name__)

@app.route('/score', methods=['POST'])
def score_sbom():
    sbom_content = request.json
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sbom_content, f)
        temp_path = f.name
    
    try:
        result = subprocess.run(
            ['sbomqs', 'score', temp_path, '--json'],
            capture_output=True,
            text=True,
            check=True
        )
        
        return jsonify(json.loads(result.stdout))
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.stderr}), 500
    finally:
        os.unlink(temp_path)

@app.route('/compliance/<standard>', methods=['POST'])
def check_compliance(standard):
    sbom_content = request.json
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sbom_content, f)
        temp_path = f.name
    
    try:
        result = subprocess.run(
            ['sbomqs', 'compliance', f'--{standard}', temp_path, '--json'],
            capture_output=True,
            text=True,
            check=True
        )
        
        return jsonify(json.loads(result.stdout))
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.stderr}), 500
    finally:
        os.unlink(temp_path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

## Monitoring Integration

### Prometheus Metrics

```python
#!/usr/bin/env python3
# sbomqs-exporter.py

from prometheus_client import start_http_server, Gauge
import subprocess
import json
import time
import glob

# Create metrics
sbom_score = Gauge('sbom_quality_score', 'SBOM quality score', ['file'])
sbom_compliance = Gauge('sbom_compliance_status', 'SBOM compliance status', ['file', 'standard'])

def collect_metrics():
    for sbom_file in glob.glob('/sboms/*.json'):
        # Get quality score
        result = subprocess.run(
            ['sbomqs', 'score', sbom_file, '--json'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            score = data['files'][0]['avg_score']
            sbom_score.labels(file=sbom_file).set(score)
        
        # Check compliance
        for standard in ['bsi-v2', 'fsct']:
            result = subprocess.run(
                ['sbomqs', 'compliance', f'--{standard}', sbom_file, '--json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                compliant = 1 if data['summary']['compliant'] else 0
                sbom_compliance.labels(file=sbom_file, standard=standard).set(compliant)

if __name__ == '__main__':
    start_http_server(8000)
    
    while True:
        collect_metrics()
        time.sleep(300)  # Collect every 5 minutes
```

## Best Practices

1. **Automate Early**: Integrate SBOM quality checks as early as possible in your pipeline
2. **Set Thresholds**: Define minimum acceptable scores for your organization
3. **Track Trends**: Monitor score changes over time
4. **Share Reports**: Use the share command to create accessible reports for stakeholders
5. **Custom Profiles**: Create organization-specific scoring profiles
6. **Regular Updates**: Keep SBOMQS updated to get latest features and scoring improvements