# Installation Guide

This guide covers all installation methods for SBOMQS, including platform-specific instructions, Docker usage, and building from source.

## Quick Start

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
curl -LO https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_darwin_amd64.tar.gz

# For Apple Silicon (M1/M2)
curl -LO https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_darwin_arm64.tar.gz

# Extract
tar -xzf sbomqs_darwin_*.tar.gz

# Move to PATH
sudo mv sbomqs /usr/local/bin/

# Make executable
chmod +x /usr/local/bin/sbomqs

# Verify
sbomqs version
```

### Linux

#### Using Package Managers

##### Debian/Ubuntu (via .deb package)

```bash
# Download the .deb package
wget https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_linux_amd64.deb

# Install
sudo dpkg -i sbomqs_linux_amd64.deb

# Fix any dependency issues
sudo apt-get install -f
```

##### RedHat/CentOS/Fedora (via .rpm package)

```bash
# Download the .rpm package
wget https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_linux_amd64.rpm

# Install
sudo rpm -i sbomqs_linux_amd64.rpm
```

#### Using Pre-built Binary

```bash
# Download for Linux (x86_64)
curl -LO https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_linux_amd64.tar.gz

# For ARM64
curl -LO https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_linux_arm64.tar.gz

# Extract
tar -xzf sbomqs_linux_*.tar.gz

# Move to PATH
sudo mv sbomqs /usr/local/bin/

# Make executable
chmod +x /usr/local/bin/sbomqs

# Verify
sbomqs version
```

#### Using Snap

```bash
# Coming soon
snap install sbomqs
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
Invoke-WebRequest -Uri "https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_windows_amd64.zip" -OutFile "sbomqs.zip"

# Extract
Expand-Archive -Path "sbomqs.zip" -DestinationPath "C:\Program Files\sbomqs"

# Add to PATH
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\sbomqs", [EnvironmentVariableTarget]::Machine)

# Verify (restart PowerShell first)
sbomqs version
```

#### Using Chocolatey

```powershell
# Coming soon
choco install sbomqs
```

## Docker Installation

### Pull the Image

```bash
# Latest version
docker pull ghcr.io/interlynk-io/sbomqs:latest

# Specific version
docker pull ghcr.io/interlynk-io/sbomqs:v1.0.0
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
    URL="https://github.com/interlynk-io/sbomqs/releases/latest/download/sbomqs_${OS}_${ARCH}.tar.gz"
    curl -LO "$URL"
    
    # Extract and install
    tar -xzf "sbomqs_${OS}_${ARCH}.tar.gz"
    sudo mv sbomqs /usr/local/bin/
    
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

## Next Steps

After installation:

1. [Read the Quick Start Guide](../README.md#quick-start)
2. [Try the score command](./score-command.md)
3. [Check compliance](./compliance-command.md)
4. [Generate custom configurations](./generate-command.md)