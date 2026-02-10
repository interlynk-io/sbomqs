# Getting Started Guide

This comprehensive guide covers installing sbomqs and getting started with SBOM quality assessment.

## Quick Installation

### macOS (Homebrew) - Recommended

```bash
brew tap interlynk-io/interlynk
brew install sbomqs
```

### Linux/Windows (Go Install)

```bash
go install github.com/interlynk-io/sbomqs@latest
```

### Docker

```bash
docker pull ghcr.io/interlynk-io/sbomqs:latest
```

## Platform-Specific Installation

### macOS

#### Using Homebrew (Recommended)

```bash
# Add the Interlynk tap
brew tap interlynk-io/interlynk

# Install sbomqs
brew install sbomqs

# Verify installation
sbomqs version
```

#### Using Pre-built Binary

```bash
# Download latest release for macOS (Intel)
curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v2.0.4/sbomqs_2.0.4_Darwin_x86_64.tar.gz
tar -xzf sbomqs_2.0.4_Darwin_x86_64.tar.gz

# For Apple Silicon (M1/M2)
curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v2.0.4/sbomqs_2.0.4_Darwin_arm64.tar.gz
tar -xzf sbomqs_2.0.4_Darwin_arm64.tar.gz

# Move to PATH
sudo mv sbomqs /usr/local/bin/

# Verify
sbomqs version
```

#### Verifying sbomqs artifacts with cosign

```bash
export VERSION=$(curl -s https://api.github.com/repos/interlynk-io/sbomqs/releases/latest | jq -r '.tag_name' | sed 's/v//')

curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v${VERSION}/sbomqs_${VERSION}_Linux_x86_64.tar.gz
curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v${VERSION}/sbomqs_${VERSION}_Linux_x86_64.tar.gz.sigstore.json

cosign verify-blob \
  sbomqs_${VERSION}_Linux_x86_64.tar.gz --bundle sbomqs_${VERSION}_Linux_x86_64.tar.gz.sigstore.json \
  --certificate-identity="https://github.com/interlynk-io/sbomqs/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### Linux

#### Using Package Managers

##### Debian/Ubuntu (via .deb package)

```bash
# Download the .deb package (x86_64)
export VERSION=$(curl -s https://api.github.com/repos/interlynk-io/sbomqs/releases/latest | jq -r '.tag_name' | sed 's/v//')

curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v${VERSION}/sbomqs_${VERSION}_amd64.deb

# For ARM64
curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v${VERSION}/sbomqs_${VERSION}_arm64.deb

# Install
sudo dpkg -i sbomqs_*.deb

# Fix any dependency issues
sudo apt-get install -f
```

##### RedHat/CentOS/Fedora (via .rpm package)

```bash
# Download the .rpm package (x86_64)
export VERSION=$(curl -s https://api.github.com/repos/interlynk-io/sbomqs/releases/latest | jq -r '.tag_name' | sed 's/v//')

     
curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v${VERSION}/sbomqs-${VERSION}-1.x86_64.rpm

# For ARM64/aarch64
curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v${VERSION}/sbomqs-${VERSION}-1.aarch64.rpm

# Install
sudo rpm -i sbomqs-*.rpm
```

#### Using Pre-built Binary

```bash
# Download for Linux (x86_64)
curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v2.0.4/sbomqs_2.0.4_Linux_x86_64.tar.gz
tar -xzf sbomqs_2.0.4_Linux_x86_64.tar.gz

# For ARM64
curl -LO https://github.com/interlynk-io/sbomqs/releases/download/v2.0.4/sbomqs_2.0.4_Linux_arm64.tar.gz
tar -xzf sbomqs_2.0.4_Linux_arm64.tar.gz


# Move to PATH
sudo mv sbomqs /usr/local/bin/

# Verify
sbomqs version
```

#### Using Snap

```bash
# Please request
```

### Windows

#### Using Scoop

```powershell
# Add the bucket (if not already added)
scoop bucket add interlynk https://github.com/interlynk-io/scoop-bucket

# Install sbomqs
scoop install sbomqs
```

#### Using Pre-built Binary

```powershell
# Download the Windows binary
Invoke-WebRequest -Uri "https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs-windows-amd64.exe" -OutFile "sbomqs.exe"

# Create directory and move executable
New-Item -ItemType Directory -Force -Path "C:\Program Files\sbomqs"
Move-Item -Path "sbomqs.exe" -Destination "C:\Program Files\sbomqs\sbomqs.exe"

# Add to PATH
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\sbomqs", [EnvironmentVariableTarget]::Machine)

# Verify (restart PowerShell first)
sbomqs version
```

#### Using Chocolatey

```powershell
# Please request
```

## Docker Installation

### Pull the Image

```bash
# Latest version
docker pull ghcr.io/interlynk-io/sbomqs:latest

# Specific version
docker pull ghcr.io/interlynk-io/sbomqs:v2.0.4
```

### Create an Alias

```bash
# Add to ~/.bashrc or ~/.zshrc
alias sbomqs='docker run --rm -v $(pwd):/app ghcr.io/interlynk-io/sbomqs:latest'

# Reload shell configuration
source ~/.bashrc
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  sbomqs:
    image: ghcr.io/interlynk-io/sbomqs:latest
    volumes:
      - ./sboms:/app
    command: score /app/my-sbom.json
```

## Building from Source

### Prerequisites

- Go 1.21 or higher
- Git
- Make (optional but recommended)

### Build Steps

```bash
# Clone the repository
git clone https://github.com/interlynk-io/sbomqs.git
cd sbomqs

# Build using Make
make build

# Or build directly with Go
go build -o sbomqs

# Install to system
sudo make install

# Or manually move to PATH
sudo mv ./build/sbomqs /usr/local/bin/

# Verify
sbomqs version
```

### Development Build

```bash
# Build with debug symbols
go build -gcflags="all=-N -l" -o sbomqs

# Build for different platforms
GOOS=linux GOARCH=amd64 go build -o sbomqs-linux
GOOS=darwin GOARCH=arm64 go build -o sbomqs-mac-m1
GOOS=windows GOARCH=amd64 go build -o sbomqs.exe
```

## Go Install Method

### Requirements

- Go 1.21 or higher

### Installation

```bash
# Install latest version
go install github.com/interlynk-io/sbomqs@latest

# Install specific version
go install github.com/interlynk-io/sbomqs@v1.0.0

# Verify installation
$(go env GOPATH)/bin/sbomqs version

# Add to PATH if needed
export PATH=$PATH:$(go env GOPATH)/bin
```

## Shell Completion

### Bash

```bash
# Generate completion script
sbomqs completion bash > sbomqs_completion.bash

# Install for current user
mkdir -p ~/.local/share/bash-completion/completions
mv sbomqs_completion.bash ~/.local/share/bash-completion/completions/sbomqs

# Or install system-wide
sudo mv sbomqs_completion.bash /etc/bash_completion.d/sbomqs
```

### Zsh

```bash
# Generate completion script
sbomqs completion zsh > _sbomqs

# Install
mkdir -p ~/.zsh/completions
mv _sbomqs ~/.zsh/completions/

# Add to ~/.zshrc
echo 'fpath=(~/.zsh/completions $fpath)' >> ~/.zshrc
echo 'autoload -Uz compinit && compinit' >> ~/.zshrc

# Reload
source ~/.zshrc
```

### Fish

```bash
# Generate completion script
sbomqs completion fish > sbomqs.fish

# Install
mkdir -p ~/.config/fish/completions
mv sbomqs.fish ~/.config/fish/completions/
```

### PowerShell

```powershell
# Generate completion script
sbomqs completion powershell > sbomqs.ps1

# Install
mkdir -p "$HOME\Documents\PowerShell\Completions"
Move-Item sbomqs.ps1 "$HOME\Documents\PowerShell\Completions"

# Add to profile
Add-Content $PROFILE ". $HOME\Documents\PowerShell\Completions\sbomqs.ps1"
```

## Verification

### Basic Verification

```bash
# Check version
sbomqs version

# Run help
sbomqs --help

# Test with sample SBOM
curl -LO https://raw.githubusercontent.com/interlynk-io/sbomqs/main/samples/photon.spdx.json
sbomqs score photon.spdx.json
```

### Complete Test Suite

```bash
#!/bin/bash
# verify-installation.sh

echo "Verifying SBOMQS installation..."

# Check if sbomqs is in PATH
if ! command -v sbomqs &> /dev/null; then
    echo "❌ sbomqs not found in PATH"
    exit 1
fi
echo "✅ sbomqs found in PATH"

# Check version
VERSION=$(sbomqs version --short)
echo "✅ Version: $VERSION"

# Test basic scoring
TEMP_SBOM=$(mktemp)
cat > $TEMP_SBOM << 'EOF'
{
  "spdxVersion": "SPDX-2.3",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z"
  },
  "name": "Test",
  "packages": []
}
EOF

if sbomqs score $TEMP_SBOM --basic &> /dev/null; then
    echo "✅ Basic scoring works"
else
    echo "❌ Basic scoring failed"
fi

rm $TEMP_SBOM
echo "Installation verified successfully!"
```

## Updating

### Homebrew

```bash
brew update
brew upgrade sbomqs
```

### Go Install

```bash
go install github.com/interlynk-io/sbomqs@latest
```

### Docker

```bash
docker pull ghcr.io/interlynk-io/sbomqs:latest
```

### Manual Update

```bash
#!/bin/bash
# update-sbomqs.sh

# Get current version
CURRENT=$(sbomqs version --short)

# Get latest version
LATEST=$(curl -s https://api.github.com/repos/interlynk-io/sbomqs/releases/latest | jq -r '.tag_name')

if [ "$CURRENT" != "$LATEST" ]; then
    echo "Updating from $CURRENT to $LATEST..."
    
    # Detect OS and architecture
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    if [ "$ARCH" = "x86_64" ]; then
        ARCH="amd64"
    fi
    
    # Download latest
    URL="https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs-${OS}-${ARCH}"
    if [ "$OS" = "windows" ]; then
        URL="${URL}.exe"
    fi
    curl -LO "$URL"
    
    # Install
    chmod +x "sbomqs-${OS}-${ARCH}"*
    sudo mv "sbomqs-${OS}-${ARCH}"* /usr/local/bin/sbomqs
    
    echo "Updated to: $(sbomqs version --short)"
else
    echo "Already on latest version: $CURRENT"
fi
```

## Uninstallation

### Homebrew

```bash
brew uninstall sbomqs
brew untap interlynk-io/interlynk
```

### Manual Removal

```bash
# Remove binary
sudo rm /usr/local/bin/sbomqs

# Remove completions
rm ~/.local/share/bash-completion/completions/sbomqs
rm ~/.zsh/completions/_sbomqs
rm ~/.config/fish/completions/sbomqs.fish
```

### Docker

```bash
docker rmi ghcr.io/interlynk-io/sbomqs:latest
```

## Troubleshooting

### Command Not Found

```bash
# Check if installed
which sbomqs

# Check PATH
echo $PATH

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
```

### Permission Denied

```bash
# Make executable
chmod +x /usr/local/bin/sbomqs

# Check permissions
ls -la /usr/local/bin/sbomqs
```

### Version Conflicts

```bash
# Find all installations
find / -name sbomqs -type f 2>/dev/null

# Check which one is being used
which -a sbomqs

# Remove duplicates
```

### Docker Issues

```bash
# Check Docker is running
docker version

# Check image is downloaded
docker images | grep sbomqs

# Test with simple command
docker run --rm ghcr.io/interlynk-io/sbomqs:latest version
```

## Environment Variables

```bash
# Disable version checking
export INTERLYNK_DISABLE_VERSION_CHECK=true

# Set custom config directory
export SBOMQS_CONFIG_DIR=$HOME/.config/sbomqs

# Enable debug logging
export SBOMQS_DEBUG=true
```

## Basic Usage

Now that you have sbomqs installed, let's start with some basic commands.

### Your First Quality Score

```bash
# Score a single SBOM
sbomqs score my-app.spdx.json

# Get just the numeric score
sbomqs score my-app.spdx.json --basic
```

### Understanding Your Score

Scores range from 0-10:
- **9-10**: Excellent quality
- **7-8.9**: Good, minor improvements needed  
- **5-6.9**: Fair, has gaps to address
- **0-4.9**: Poor, missing critical information

### Check What's Missing

```bash
# See detailed breakdown
sbomqs score my-app.spdx.json

# Find components missing versions
sbomqs list my-app.spdx.json --feature comp_with_version --missing

# Find components missing suppliers
sbomqs list my-app.spdx.json --feature comp_with_supplier --missing
```

### Verify Compliance

```bash
# Check NTIA minimum elements
sbomqs score my-app.spdx.json --category ntia

# Check BSI compliance
sbomqs compliance --bsi-v2 my-app.spdx.json

# Check FSCT compliance  
sbomqs compliance --fsct my-app.spdx.json
```

### Share Your Results

```bash
# Generate a shareable link (doesn't upload SBOM content)
sbomqs share my-app.spdx.json
```

## Common Use Cases

### CI/CD Integration

Add to your pipeline to fail builds with low-quality SBOMs:

```yaml
# GitHub Actions example
- name: Check SBOM Quality
  run: |
    score=$(sbomqs score sbom.json --json | jq '.files[0].avg_score')
    if (( $(echo "$score < 7.0" | bc -l) )); then
      echo "SBOM quality too low: $score"
      exit 1
    fi
```

### Vendor SBOM Assessment

```bash
# Score all vendor SBOMs
for sbom in vendor-sboms/*.json; do
  echo "$(sbomqs score "$sbom" --basic) - $(basename "$sbom")"
done | sort -rn
```

### Progressive Improvement

```bash
# 1. Get baseline score
sbomqs score app.spdx.json

# 2. Identify issues
sbomqs score app.spdx.json

# 3. Fix missing data
sbomqs list app.spdx.json --feature comp_with_version --missing

# 4. Re-score to verify improvement
sbomqs score app-fixed.spdx.json
```

## Next Steps

- **[Command Reference](./commands/)** - Detailed documentation for all commands
- **[Customization Guide](./guides/customization.md)** - Create organization-specific profiles
- **[Integration Guide](./guides/integrations.md)** - CI/CD and tool integrations
- **[Compliance Standards](./reference/compliance-standards.md)** - Detailed compliance mappings
