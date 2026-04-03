# sbomqs: The Comprehensive SBOM Quality & Compliance Tool

[![Go Reference](https://pkg.go.dev/badge/github.com/interlynk-io/sbomqs.svg)](https://pkg.go.dev/github.com/interlynk-io/sbomqs)
[![Go Report Card](https://goreportcard.com/badge/github.com/interlynk-io/sbomqs)](https://goreportcard.com/report/github.com/interlynk-io/sbomqs)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/interlynk-io/sbomqs/badge)](https://securityscorecards.dev/viewer/?uri=github.com/interlynk-io/sbomqs)
![GitHub all releases](https://img.shields.io/github/downloads/interlynk-io/sbomqs/total)

**sbomqs** is the industry-leading tool for evaluating SBOM quality, ensuring compliance, and managing your software supply chain security. From quality scoring to compliance validation, component analysis to vulnerability tracking - sbomqs provides everything you need to work with SBOMs effectively.

> "sbomqs is listed as a relevant tool in the SBOM ecosystem" - [SBOM Generation White Paper, 2025](https://github.com/SBOM-Community/SBOM-Generation)

## Interlynk Free Tier — Full SBOM Compliance, Zero Friction

Get started with SBOM compliance in under two minutes — no credit card, no time limit. Interlynk's free plan includes a guided setup where you pick your compliance standard (CRA/EU, FDA Cybersecurity, NTIA, or Telecom), upload your SBOM, and instantly see your compliance score with actionable gaps highlighted. You get compliance scoring against one standard, up to 5 products with 5 versions each, unlimited users, built-in vulnerability detection, API access for CI/CD integration, weekly compliance digests, and ShareLynk — a public link to share your compliance posture with customers and partners. Everything beyond the free tier is visible with a clear upgrade path, and you can start a 15-day Enterprise trial anytime to unlock unlimited products, SBOM automation, RBAC, analytics, license management, and workflow integrations. [**Get Started Free →**](https://app.interlynk.io)

## Quick Start

```bash
# Install via Homebrew
brew tap interlynk-io/interlynk
brew install sbomqs

# Get your first quality score
sbomqs score your-sbom.json
```

📚 **[Full Getting Started Guide](docs/getting-started.md)** - Installation for all platforms and basic usage

## Why sbomqs?

In today's software landscape, understanding and managing your software supply chain is critical. Whether you're in healthcare dealing with FDA requirements, automotive following NHTSA guidelines, or any regulated industry, sbomqs helps you:

- **Instantly assess SBOM quality** - Know if your SBOMs meet quality standards
- **Ensure compliance** - Validate against BSI, NTIA, FSCT, and industry standards
- **Find vulnerabilities** - Identify components missing security identifiers
- **Automate workflows** - Integrate into CI/CD pipelines with ease
- **Share results** - Generate shareable reports and quality scores
- **Using as library** - Integrating sbomqs into your software programatically

## Key Features

✅ **Multi-Standard Support**: SPDX, CycloneDX  
✅ **Compliance Validation**: BSI TR-03183-2 (v2.1.0, v2.0 & v1.1), FSCT v3, OpenChain Telco, NTIA  
✅ **Quality Scoring**: 0-10 scale with detailed breakdowns  
✅ **Component Analysis**: List, filter, and analyze SBOM components  
✅ **Integration Ready**: Docker, CI/CD, Dependency-Track, GitHub Actions  
✅ **Shareable Reports**: Generate public quality score links  
✅ **Air-Gapped Support**: Works in isolated environments  

## Documentation

📚 **[Getting Started](docs/getting-started.md)** - Installation and basic usage

### 📖 Command Reference

- **[score](docs/commands/score.md)** - Calculate SBOM quality score
- **[compliance](docs/commands/compliance.md)** - Check regulatory compliance  
- **[list](docs/commands/list.md)** - List and filter components
- **[share](docs/commands/share.md)** - Generate shareable reports
- **[dtrackScore](docs/commands/dtrack.md)** - Dependency-Track integration
- **[generate](docs/commands/generate.md)** - Generate configuration files
- **[version](docs/commands/version.md)** - Version information

### 🎯 Guides

- **[Customization](docs/guides/customization.md)** - Create custom scoring profiles
- **[Integrations](docs/guides/integrations.md)** - CI/CD and tool integrations
- **[Policy](docs/guides/policy.md)** - Policy enforcement and validation

### 📋 Reference

- **[Quality Checks](docs/reference/quality-checks.md)** - All scoring criteria explained
- **[Compliance Standards](docs/reference/compliance-standards.md)** - BSI, NTIA, FSCT mappings

## Basic Examples

### Check SBOM Quality

```bash
# Get a quality score (0-10)
sbomqs score -b my-app.spdx.json

# See detailed breakdown
sbomqs score my-app.spdx.json

# Check specific category
sbomqs score my-app.spdx.json --category integrity

# check specific profile 
sbomqs score my-app.spdx.json --category NTIA-minimum-elements --profile ntia
```

### Verify Compliance

```bash
# BSI TR-03183-2 v2.0
sbomqs compliance --bsi-v2 my-app.spdx.json

# FSCT v3
sbomqs compliance --fsct my-app.spdx.json

# OpenChain Telco
sbomqs compliance --oct my-app.spdx.json
```

### Find Missing Data

```bash
# Components without versions
sbomqs list my-app.spdx.json --feature comp_with_version --missing

# Components without suppliers
sbomqs list my-app.spdx.json --feature comp_with_supplier --missing
```

### Share Results

```bash
# Generate shareable link (doesn't upload SBOM content)
sbomqs share my-app.spdx.json
```

### Integrating sbomqs into your software

```go
package main

import (
   "context"
   "fmt"

   "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/config"
   "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/score"
)

func main() {
   cfg := config.Config{}
   // make sure current dir has sbom file: `sbom.cdx.json`
   paths := []string{"sbom.cdx.json"}

   results, err := score.ScoreSBOM(context.Background(), cfg, paths)
   if err != nil {
      log.Fatalf("scoring failed: %v", err)
   }

   for _, r := range results {
      // Comprehensive result is the default evaluation
      if r.Comprehensive != nil {
         fmt.Printf("Interlynk score: %.2f  Grade: %s\n", r.Comprehensive.InterlynkScore, r.Comprehensive.Grade)
      }
   }
```

For more examples, refer here: <https://github.com/interlynk-io/sbomqs/blob/main/docs/guides/integrations.md>

## Industry Use Cases

- **Healthcare & Medical Devices**: Meet FDA SBOM requirements for medical device submissions
- **Automotive**: Comply with NHTSA cybersecurity guidelines for vehicle software
- **Financial Services**: Support DORA and PCI DSS software transparency requirements
- **Telecommunications**: Ensure critical infrastructure security with OpenChain Telco
- **Enterprise Software**: Manage supply chain risk with comprehensive quality metrics

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

📖 [Contributing Guidelines](./CONTRIBUTING.md)

## Community Recognition

sbomqs has gained significant adoption across the industry for SBOM quality assessment and compliance validation:

## 📚 Academic Research & Publications

### Peer-Reviewed Papers Using sbomqs

1. **Soeiro, L., Robert, T., & Zacchiroli, S. (2025)**  
   *Wild SBOMs: a Large-scale Dataset of Software Bills of Materials from Public Code*  
   22nd IEEE/ACM International Conference on Mining Software Repositories (MSR 2025)  
   **DOI:** [arXiv:2503.15021](https://arxiv.org/abs/2503.15021)  
   **Usage:** Uses sbomqs to compute quality scores for over 78,000 SBOMs in their large-scale dataset from 94 million GitHub repositories.
1. **Novikov, O., Fucci, D., Adamov, O., & Mendez, D. (2025)**
     POLICY-DRIVEN SOFTWARE BILL OF MATERIALS ON GITHUB: AN EMPIRICAL STUDY
     arXiv preprint
     **DOI:**  [arXiv:2509.01255](https://arxiv.org/abs/2509.01255)
     **Usage:** Uses sbomqs to assess the quality of 620 policy-driven SBOMs found on GitHub, calculating a quality score based on structural and
     semantic completeness.

### White Papers & Technical Documents

2. **SBOM Generation White Paper (2025)**  
   *SBOM Community, February 2025*  
   **Citation:** Lists sbomqs as a "relevant tool in the SBOM ecosystem" and highlights it as demonstrating best practices in SBOM quality assessment.

3. **OpenChain Telco SBOM Guide v1.1 (2025)**  
   *OpenChain Project*  
   **URL:** [OpenChain Project](https://openchainproject.org/)  
   **Usage:** References sbomqs as a recommended tool for telecommunications operators managing complex software supply chains, particularly for its ability to validate SBOMs across multiple formats.
   
### Major Platforms & Companies

### 1. **Harness Software Supply Chain Assurance (SSCA)**

- **Company:** Harness Inc.
- **Usage:** Uses sbomqs as the engine powering their SBOM quality scoring feature
- **Features:** Provides quality scores from 1-10 for generated SBOMs with SBOM drift detection capabilities
- **Reference:** [Harness Developer Hub](https://developer.harness.io/docs/software-supply-chain-assurance/open-source-management/generate-sbom-for-artifacts)
- **Blog Post:** [Level Up your Zero-day Vulnerability Remediation and SBOM Quality](https://www.harness.io/blog/level-up-your-zero-day-vulnerability-remediation-and-sbom-quality-for-a-more-secure-software-supply-chain) (May 2025)

### 2. **sbom.sh**

- **Platform:** [sbom.sh](https://sbom.sh)
- **Usage:** Uses the sbomqs engine to evaluate and score uploaded SBOMs
- **Features:** Automatically generates a quality score (1–10) based on metadata completeness, component coverage, and spec compliance (SPDX/CycloneDX), displaying results directly in the web interface

### 3. **SBOM Benchmark Platform**

- **Platform:** [sbombenchmark.dev](https://sbombenchmark.dev/)
- **Usage:** Uses the sbomqs engine for scoring CycloneDX and SPDX SBOMs
- **Features:** Provides shareable quality reports without requiring SBOM uploads

### 4. **Interlynk Platform**

- **Company:** Interlynk Inc.
- **Milestone:** Reached 100 customers on community tier, including four Fortune 500 companies
- **Integration:** sbomqs integrated for SBOM quality assessment across the platform

### 5. **SBOMly**

- **Platform:**  [SBOMly](https://sbomly.com/).
- **Usage:** Uses the sbomqs engine for scoring CycloneDX and SPDX SBOMs to check how complete and useful SBOMs are.
- **Features:** SBOMly makes it easy to scan your project dependencies for known vulnerabilities. It generates SBOM using Syft, then scan it for vulnerabilities using both Grype and OSV-Scanner for comprehensive coverage and gives detailed report showing all components, vulnerabilities, severity levels, and fix commands you can run to remediate issues.

### CI/CD & Package Manager Support

- GitHub Actions via Docker (`ghcr.io/interlynk-io/sbomqs`)
- Homebrew (`brew install sbomqs`)
- Go modules (`go install`)
- Docker Hub & GitHub Container Registry
- Uniget tools repository

### Compliance Standards

Trusted for validating compliance with:

- NTIA Minimum Elements
- BSI TR-03183-2 (v1.1 & v2.0)
- OpenChain Telco (OCT)
- Framing Software Component Transparency (FSCT v3)

## Other SBOM Open Source Tools

Interlynk provides a comprehensive suite of SBOM tools:

- [**SBOM Assembler**](https://github.com/interlynk-io/sbomasm) - Complete SBOM toolkit (Merging/Enriching/Signing and Editing)
- [**SBOM Explorer**](https://github.com/interlynk-io/sbomex) - Search and download from public repositories  
- [**SBOM Search Tool**](https://github.com/interlynk-io/sbomgr) - Context-aware repository search
- [**SBOM Seamless Transfer**](https://github.com/interlynk-io/sbommv) - Transfer between systems
- [**SBOM Benchmark**](https://www.sbombenchmark.dev) - Repository of SBOM quality scores

## Blog Posts

- [sbomqs and SBOM Policies](https://sbom-insights.dev/posts/sbomqs-and-sbom-policies-turning-transparency-into-action/)
- [sbomqs scoring support for BSI-1.1 and BSI-2.0](https://sbom-insights.dev/posts/sbomqs-scoring-support-for-bsi-1.1-and-bsi-2.0-in-a-summarized-way/)
- [What’s Missing in Your SBOM](https://sbom-insights.dev/posts/whats-missing-in-your-sbom-sbomqs-list-can-help-you-in-inspecting.../)

## Contact

- ❓ [Community Slack](https://join.slack.com/t/sbomqa/shared_invite/zt-2jzq1ttgy-4IGzOYBEtHwJdMyYj~BACA)
- 💬 [Live Chat](https://www.interlynk.io/#hs-chat-open)
- 📧 [Email](mailto:hello@interlynk.io)
- 🐛 [GitHub Issues](https://github.com/interlynk-io/sbomqs/issues)
- 🐦 [Follow us on X](https://twitter.com/InterlynkIo)

## Stargazers

If sbomqs helps you improve your SBOM quality and compliance, please ⭐ this repository!

[![Stargazers](https://starchart.cc/interlynk-io/sbomqs.svg)](https://starchart.cc/interlynk-io/sbomqs)

---

**sbomqs** - Building trust in software supply chains, one SBOM at a time.

Made with ❤️ by [Interlynk.io](https://www.interlynk.io)
