# sbomqs: The Comprehensive SBOM Quality & Compliance Tool


[![Go Reference](https://pkg.go.dev/badge/github.com/interlynk-io/sbomqs.svg)](https://pkg.go.dev/github.com/interlynk-io/sbomqs)
[![Go Report Card](https://goreportcard.com/badge/github.com/interlynk-io/sbomqs)](https://goreportcard.com/report/github.com/interlynk-io/sbomqs)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/interlynk-io/sbomqs/badge)](https://securityscorecards.dev/viewer/?uri=github.com/interlynk-io/sbomqs)
![GitHub all releases](https://img.shields.io/github/downloads/interlynk-io/sbomqs/total)

**sbomqs** is the industry-leading tool for evaluating SBOM quality, ensuring compliance, and managing your software supply chain security. From quality scoring to compliance validation, component analysis to vulnerability tracking - sbomqs provides everything you need to work with SBOMs effectively.

> "sbomqs is listed as a relevant tool in the SBOM ecosystem" - [SBOM Generation White Paper, 2025](https://github.com/SBOM-Community/SBOM-Generation)

## Quick Start

```bash
# Install via Homebrew
brew tap interlynk-io/interlynk
brew install sbomqs

# Get your first quality score
sbomqs score your-sbom.json
```

## Table of Contents

- [sbomqs: The Comprehensive SBOM Quality \& Compliance Tool](#sbomqs-the-comprehensive-sbom-quality--compliance-tool)
  - [Quick Start](#quick-start)
  - [Table of Contents](#table-of-contents)
  - [Why sbomqs?](#why-sbomqs)
  - [Key Features](#key-features)
  - [sbomqs Blog](#sbomqs-blog)
  - [Getting Started](#getting-started)
    - [Basic Usage](#basic-usage)
      - [1. Check Your SBOM Quality Score](#1-check-your-sbom-quality-score)
      - [2. Understand Why Your Score Is Low](#2-understand-why-your-score-is-low)
      - [3. Check Compliance](#3-check-compliance)
    - [Essential Commands](#essential-commands)
  - [Industry Use Cases](#industry-use-cases)
    - [Healthcare \& Medical Devices](#healthcare--medical-devices)
    - [Automotive Industry](#automotive-industry)
    - [Financial Services](#financial-services)
    - [Telecommunications](#telecommunications)
  - [Advanced Features](#advanced-features)
    - [Compliance Validation](#compliance-validation)
      - [BSI TR-03183-2 v2.0 (Latest)](#bsi-tr-03183-2-v20-latest)
      - [Framing Software Component Transparency v3](#framing-software-component-transparency-v3)
    - [Component Analysis](#component-analysis)
    - [Integration \& Automation](#integration--automation)
      - [CI/CD Pipeline Integration](#cicd-pipeline-integration)
      - [Dependency-Track Integration](#dependency-track-integration)
      - [Docker Container Scanning](#docker-container-scanning)
    - [Customization](#customization)
      - [Custom Scoring Profiles](#custom-scoring-profiles)
      - [Category-Based Scoring](#category-based-scoring)
      - [Output Formats](#output-formats)
  - [Command Reference](#command-reference)
    - [Core Commands](#core-commands)
    - [Quick Examples](#quick-examples)
  - [SBOM Card](#sbom-card)
  - [SBOM Platform - Free Community Tier](#sbom-platform---free-community-tier)
  - [Installation](#installation)
    - [Recommended: Homebrew](#recommended-homebrew)
    - [Using Go](#using-go)
    - [Using Docker](#using-docker)
    - [Pre-built Binaries](#pre-built-binaries)
    - [Building from Source](#building-from-source)
  - [Contributions](#contributions)
  - [Community Recognition](#community-recognition)
    - [Enterprise Adoptions](#enterprise-adoptions)
    - [CI/CD Integrations](#cicd-integrations)
    - [Package Manager Support](#package-manager-support)
    - [Compliance Standards](#compliance-standards)
  - [Other SBOM Open Source tools](#other-sbom-open-source-tools)
  - [Contact](#contact)
  - [Stargazers](#stargazers)

## Why sbomqs?

In today's software landscape, understanding and managing your software supply chain is critical. Whether you're in healthcare dealing with FDA requirements, automotive following NHTSA guidelines, or any regulated industry, sbomqs helps you:

- **Instantly assess SBOM quality** - Know if your SBOMs meet quality standards
- **Ensure compliance** - Validate against BSI, NTIA, FSCT, and industry standards
- **Find vulnerabilities** - Identify components missing security identifiers
- **Automate workflows** - Integrate into CI/CD pipelines with ease
- **Share results** - Generate shareable reports and quality scores

## Key Features

✅ **Multi-Standard Support**: SPDX, CycloneDX, SWID (coming soon)  
✅ **Compliance Validation**: BSI TR-03183-2 (v1.1 & v2.0), FSCT v3, OpenChain Telco, NTIA  
✅ **Quality Scoring**: 0-10 scale with detailed breakdowns  
✅ **Component Analysis**: List, filter, and analyze SBOM components  
✅ **Integration Ready**: Docker, CI/CD, Dependency-Track, GitHub Actions  
✅ **Shareable Reports**: Generate public quality score links  
✅ **Air-Gapped Support**: Works in isolated environments  

## sbomqs Blog

- [What’s Missing in Your SBOM? sbomqs list can help you in inspecting...](https://www.linkedin.com/pulse/whats-missing-your-sbom-sbomqs-list-can-help-you-inspecting-sahu-e6rcc/)
- [sbomqs scoring support for BSI-1.1 and BSI-2.0 in a summarized way](https://www.linkedin.com/pulse/sbomqs-scoring-support-bsi-11-bsi-20-summarized-way-vivek-kumar-sahu-apc8c/)

## Getting Started

### Basic Usage

sbomqs makes it easy to get started with SBOM quality assessment. Here are the most common use cases:

#### 1. Check Your SBOM Quality Score

```bash
# Get a quick quality score (0-10 scale)
sbomqs score my-application.spdx.json

# Output:
# 7.8 my-application.spdx.json
```

#### 2. Understand Why Your Score Is Low

```bash
# Get detailed scoring breakdown
sbomqs score my-application.spdx.json --detailed

# See which categories are affecting your score
sbomqs score my-application.spdx.json --category ntia
```

#### 3. Check Compliance

```bash
# Check if your SBOM meets regulatory requirements
sbomqs compliance --bsi-v2 my-application.spdx.json
sbomqs compliance --fsct my-application.spdx.json
```

### Essential Commands

Here are the commands you'll use most often:

```bash
# Quality scoring
sbomqs score <sbom-file>                    # Basic score
sbomqs score <sbom-file> --detailed         # Detailed breakdown
sbomqs score <sbom-file> --json             # JSON output for automation

# Compliance checking
sbomqs compliance --bsi-v2 <sbom-file>      # BSI TR-03183-2 v2.0
sbomqs compliance --fsct <sbom-file>        # FSCT v3 compliance

# Component listing
sbomqs list <sbom-file> --feature comp_with_licenses  # Components with licenses
sbomqs list <sbom-file> --feature comp_with_version   # Components with versions

# Sharing
sbomqs share <sbom-file>                    # Get a shareable link
```

## Industry Use Cases

sbomqs addresses critical needs across various industries:

### Healthcare & Medical Devices

The FDA requires SBOMs for medical device submissions. Use sbomqs to:

```bash
# Validate FDA compliance requirements
sbomqs score medical-device.spdx.json --category ntia

# Check for components without versions (critical for vulnerability tracking)
sbomqs list medical-device.spdx.json --feature comp_with_version --missing

# Generate compliance report for FDA submission
sbomqs compliance --fsct medical-device.spdx.json > fda-compliance-report.json
```

**Real-world example**: A medical device manufacturer uses sbomqs in their CI/CD pipeline to ensure all software releases meet FDA's SBOM requirements before submission.

### Automotive Industry

Following NHTSA's cybersecurity guidelines, automotive manufacturers need comprehensive SBOMs:

```bash
# Check automotive ECU software SBOM
sbomqs score ecu-software.cdx.json --detailed

# List all components with security identifiers (CPE/PURL)
sbomqs list ecu-software.cdx.json --feature comp_with_cpes --show

# Validate against industry standards
sbomqs compliance --bsi-v2 ecu-software.cdx.json
```

### Financial Services

Meeting DORA and PCI DSS requirements for software transparency:

```bash
# Assess payment system SBOM quality
sbomqs score payment-system.spdx.json

# Check for components with valid licenses
sbomqs list payment-system.spdx.json --feature comp_valid_licenses --show

# Generate compliance evidence
sbomqs compliance --fsct payment-system.spdx.json --output-format json
```

### Telecommunications

Ensuring critical infrastructure security:

```bash
# Validate NTIA minimum elements
sbomqs score --category ntia telecom-app.cdx.json

# Check OpenChain Telco compliance
sbomqs compliance --telco telecom-app.cdx.json
```

## Advanced Features

### Compliance Validation

sbomqs supports multiple compliance standards with detailed reporting:

#### BSI TR-03183-2 v2.0 (Latest)

```bash
# Full compliance check with detailed report
sbomqs compliance --bsi-v2 application.spdx.json

# Output includes:
# - Total score and breakdown
# - Required vs optional elements
# - Specific missing fields
# - Recommendations for improvement
```

#### Framing Software Component Transparency v3

```bash
# FSCT compliance with color-coded output
sbomqs compliance --fsct application.spdx.json --color

# Generate machine-readable report
sbomqs compliance --fsct application.spdx.json --json > fsct-report.json
```

[📖 Detailed Compliance Documentation](./docs/Compliance.md)

### Component Analysis

Powerful filtering and analysis capabilities:

```bash
# Find components without suppliers (supply chain risk)
sbomqs list app.spdx.json --feature comp_with_supplier --missing

# Show all license values for validation
sbomqs list app.spdx.json --feature comp_valid_licenses --show

# Export component list for further analysis
sbomqs list app.spdx.json --feature comp_with_purls --show --json > components.json
```

Available features for analysis:

- `comp_with_supplier` - Supply chain transparency
- `comp_with_licenses` - License compliance
- `comp_valid_licenses` - License validation
- `comp_with_version` - Vulnerability management
- `comp_with_purls` - Package identification
- `comp_with_cpes` - CVE matching
- `comp_with_checksums` - Integrity verification

[📖 Detailed List Command Documentation](./docs/list.md)

### Integration & Automation

#### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
- name: Check SBOM Quality
  run: |
    sbomqs score ${{ github.workspace }}/sbom.json --json > sbom-score.json
    score=$(jq '.avg_score' sbom-score.json)
    if (( $(echo "$score < 7" | bc -l) )); then
      echo "SBOM quality score too low: $score"
      exit 1
    fi
```

#### Dependency-Track Integration

```bash
# Score all projects in Dependency-Track
sbomqs dtrackScore -u "https://dtrack.company.com" \
                   -k "$DT_API_KEY" \
                   "project-uuid"

# Automated labeling based on quality scores
sbomqs dtrackScore --label-prefix "sbom-quality" \
                   --min-score 7.0 \
                   "project-uuid"
```

#### Docker Container Scanning

```bash
# Scan container SBOM
docker sbom nginx:latest | sbomqs score -

# Batch process multiple containers
for image in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
  echo "Scoring $image"
  docker sbom "$image" | sbomqs score - --basic
done
```

[📖 Detailed Integration Documentation](./docs/integrations.md)

### Customization

#### Custom Scoring Profiles

```bash
# Generate configuration file
sbomqs generate features > my-profile.yaml

# Edit profile to enable/disable specific checks
# Then use custom profile
sbomqs score app.spdx.json --configpath my-profile.yaml
```

#### Category-Based Scoring

```bash
# Focus on specific categories
sbomqs score app.spdx.json --category ntia      # NTIA compliance only
sbomqs score app.spdx.json --category quality   # Quality metrics only
sbomqs score app.spdx.json --category bsi-v2.0  # BSI v2.0 scoring
```

#### Output Formats

```bash
# JSON for automation
sbomqs score app.spdx.json --json

# Detailed table format
sbomqs score app.spdx.json --detailed

# Basic score only
sbomqs score app.spdx.json --basic
```

[📖 Detailed Customization Documentation](./docs/customization.md)

## Command Reference

### Core Commands

| Command | Description | Documentation |
|---------|-------------|---------------|
| `score` | Calculate SBOM quality score | [Details](./docs/score-command.md) |
| `compliance` | Check regulatory compliance | [Details](./docs/compliance-command.md) |
| `list` | List and filter components | [Details](./docs/list.md) |
| `share` | Generate shareable report link | [Details](./docs/share-command.md) |
| `dtrackScore` | Dependency-Track integration | [Details](./docs/dtrack-command.md) |
| `generate` | Generate configuration files | [Details](./docs/generate-command.md) |
| `version` | Display version information | [Details](./docs/version-command.md) |

### Quick Examples

```bash
# Score multiple SBOMs at once
sbomqs score *.json --basic

# Check compliance for all SBOMs in a directory
for sbom in ./sboms/*.json; do
  sbomqs compliance --bsi-v2 "$sbom" > "reports/$(basename $sbom .json)-compliance.json"
done

# Air-gapped environment usage
INTERLYNK_DISABLE_VERSION_CHECK=true sbomqs score app.spdx.json
```

## SBOM Card

[![SBOMCard](https://api.interlynk.io/api/v1/badges.svg?type=hcard&project_group_id=7f52093e-3d78-49cb-aeb1-6c977de9442e
)](https://app.interlynk.io/customer/products?id=7f52093e-3d78-49cb-aeb1-6c977de9442e&signed_url_params=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqUmhPRGRoTjJNNExXSXpZekl0TkdVeE9TMDVNRGxoTFRKbFpHRmlPR1ZoWldReVl5ST0iLCJleHAiOm51bGwsInB1ciI6InNoYXJlX2x5bmsvc2hhcmVfbHluayJ9fQ==--daf6585ecf8013a0b2713a5cebb28c140d29eed904b15c84c0566b9ddd334e71)

## SBOM Platform - Free Community Tier

Our SBOM Automation Platform has a free community tier that provides a comprehensive solution to manage SBOMs (Software Bill of Materials) effortlessly. From centralized SBOM storage, built-in SBOM editor, continuous vulnerability mapping and assessment, and support for organizational policies, all while ensuring compliance and enhancing software supply chain security using integrated SBOM quality scores. The community tier is ideal for small teams. Learn more [here](https://www.interlynk.io/community-tier) or [Sign up](https://app.interlynk.io/auth)

## Installation

### Recommended: Homebrew

```bash
brew tap interlynk-io/interlynk
brew install sbomqs
```

### Using Go

```bash
go install github.com/interlynk-io/sbomqs@latest
```

### Using Docker

```bash
docker run -v $(pwd):/app ghcr.io/interlynk-io/sbomqs score /app/your-sbom.json
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/interlynk-io/sbomqs/releases)

### Building from Source

```bash
git clone https://github.com/interlynk-io/sbomqs.git
cd sbomqs
make build
./build/sbomqs version
```

[📖 Detailed Installation Guide](./docs/installation.md)

## Contributions

We welcome contributions! Here's how to get started:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -sam 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure:

- All commits are signed
- Tests pass (`make test`)
- Code follows our style guide (`make lint`)

[📖 Contributing Guidelines](./CONTRIBUTING.md)

## Community Recognition

sbomqs has gained significant adoption across the industry for SBOM quality assessment and compliance validation:

### Enterprise Adoptions

- **[Harness Software Supply Chain Assurance (SSCA)](https://developer.harness.io/docs/software-supply-chain-assurance/sbom/sbom-score/)** - Harness, the leader in AI-powered Modern CI/CD, uses sbomqs to power their SBOM quality scoring, providing quality scores from 1-10 for generated SBOMs with SBOM drift detection capabilities.

- **[SBOM Benchmark Platform](https://sbombenchmark.dev)** - Uses the sbomqs engine for scoring CycloneDX and SPDX SBOMs, providing shareable quality reports without requiring SBOM uploads.

### CI/CD Integrations

sbomqs integrates seamlessly with major CI/CD platforms:

- **GitHub Actions** - Native Docker support via `ghcr.io/interlynk-io/sbomqs`
- **Jenkins** - Feature request for Dependency-Track plugin integration
- **Docker/Kubernetes** - Official container image for containerized workflows
- **GitLab CI, Azure DevOps, CircleCI** - Compatible via Docker or command-line execution

### Package Manager Support

Available through multiple package managers for easy installation:

- Homebrew (`brew install sbomqs`)
- Go modules (`go install`)
- Docker Hub & GitHub Container Registry
- Uniget tools repository

### Compliance Standards

Trusted for validating compliance with major standards:

- NTIA Minimum Elements
- BSI TR-03183-2 (v1.1 & v2.0)
- OpenChain Telco (OCT)
- Framing Software Component Transparency (FSCT v3)

## Other SBOM Open Source tools


Interlynk provides a comprehensive suite of SBOM tools:

- [**SBOM Assembler**](https://github.com/interlynk-io/sbomasm) - Merge and edit SBOMs conditionally
- [**SBOM Explorer**](https://github.com/interlynk-io/sbomex) - Search and download SBOMs from public repositories
- [**SBOM Search Tool**](https://github.com/interlynk-io/sbomgr) - Context-aware SBOM repository search
- [**SBOM Seamless Transfer**](https://github.com/interlynk-io/sbommv) - Transfer SBOMs between systems
- [**SBOM Benchmark**](https://www.sbombenchmark.dev) - Repository of SBOM quality scores for popular containers

## Contact

We're here to help! Reach out through:

- ❓ [Community Slack](https://join.slack.com/t/sbomqa/shared_invite/zt-2jzq1ttgy-4IGzOYBEtHwJdMyYj~BACA) - Get answers from the community
- 💬 [Live Chat](https://www.interlynk.io/#hs-chat-open) - Talk to our team
- 📧 [Email](mailto:hello@interlynk.io) - Direct support
- 🐛 [GitHub Issues](https://github.com/interlynk-io/sbomqs/issues) - Report bugs or request features
- 🐦 [Follow us on X](https://twitter.com/InterlynkIo) - Latest updates

## Stargazers

If sbomqs helps you improve your SBOM quality and compliance, please ⭐ this repository!

[![Stargazers](https://starchart.cc/interlynk-io/sbomqs.svg)](https://starchart.cc/interlynk-io/sbomqs)

---

**sbomqs** - Building trust in software supply chains, one SBOM at a time.

Made with ❤️ by [Interlynk.io](https://www.interlynk.io)
