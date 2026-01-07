# Prerequisites and Dependencies

This document lists all tools, libraries, and dependencies required for building, testing, and developing the OLS uCentral Client.

---

## Table of Contents

1. [Core Build Requirements](#core-build-requirements)
2. [Testing Framework Requirements](#testing-framework-requirements)
3. [Property Database Generation Requirements](#property-database-generation-requirements)
4. [Schema Repository Access](#schema-repository-access)
5. [Optional Tools](#optional-tools)
6. [Quick Setup Guide](#quick-setup-guide)
7. [Verification Commands](#verification-commands)

---

## Core Build Requirements

### Required for Building the Application

| Tool | Version | Purpose | Installation |
|------|---------|---------|-------------|
| **Docker** | 20.10+ | Dockerized build environment | [Install Docker](https://docs.docker.com/get-docker/) |
| **Docker Compose** | 1.29+ (optional) | Multi-container orchestration | Included with Docker Desktop |
| **Make** | 3.81+ | Build system | Usually pre-installed on Linux/macOS |
| **Git** | 2.20+ | Version control and schema fetching | `apt install git` or `brew install git` |
| **Bash** | 4.0+ | Shell scripts | Usually pre-installed |

### Build Process Dependencies (Inside Docker)

These are **automatically installed** inside the Docker build environment (no manual installation required):

- **GCC/G++** - C/C++ compiler
- **CMake** - Build system generator
- **cJSON** - JSON parsing library
- **libwebsockets** - WebSocket client library
- **OpenSSL** - TLS/SSL support
- **gRPC** - RPC framework (platform-specific)
- **Protocol Buffers** - Serialization (platform-specific)
- **jsoncpp** - JSON library (C++)

**Note:** You do NOT need to install these manually - Docker handles everything!

---

## Testing Framework Requirements

### Required for Running Tests

| Tool | Version | Purpose | Required For |
|------|---------|---------|-------------|
| **Python 3** | 3.7+ | Test scripts and schema validation | All testing |
| **PyYAML** | 5.1+ | YAML schema parsing | Schema-based database generation |
| **Docker** | 20.10+ | Consistent test environment | Recommended (but optional) |

### Python Package Dependencies

Install via pip:

```bash
# Install all Python dependencies
pip3 install pyyaml

# Or if you prefer using requirements file (see below)
pip3 install -r tests/requirements.txt
```

**Detailed breakdown:**

1. **PyYAML** (`yaml` module)
   - Used by: `tests/tools/extract-schema-properties.py`
   - Purpose: Parse YAML schema files from ols-ucentral-schema
   - Installation: `pip3 install pyyaml`
   - Version: 5.1 or later

2. **Standard Library Only** (no additional packages needed)
   - Used by: `tests/schema/validate-schema.py`
   - Built-in modules: `json`, `sys`, `argparse`, `os`
   - Used by: Most other Python scripts
   - Built-in modules: `pathlib`, `typing`, `re`, `subprocess`

### Test Configuration Files

These are **included in the repository** (no installation needed):

- Configuration samples: `config-samples/*.json`
- JSON schema: `config-samples/ucentral.schema.pretty.json`
- Test framework: `tests/config-parser/test-config-parser.c`

---

## Property Database Generation Requirements

### Required for Database Generation/Regeneration

| Tool | Version | Purpose | When Needed |
|------|---------|---------|-------------|
| **Python 3** | 3.7+ | Database generation scripts | Database regeneration |
| **PyYAML** | 5.1+ | Schema parsing | Schema-based generation |
| **Git** | 2.20+ | Fetch ols-ucentral-schema | Schema access |
| **Bash** | 4.0+ | Schema fetch script | Automated schema fetching |

### Scripts Overview

1. **Schema Extraction:**
   - `tests/tools/extract-schema-properties.py` - Extract properties from YAML schema
   - Dependencies: Python 3.7+, PyYAML
   - Input: ols-ucentral-schema YAML files
   - Output: Property list (text)

2. **Line Number Finder:**
   - `tests/tools/find-property-line-numbers.py` - Find property parsing locations
   - Dependencies: Python 3.7+ (standard library only)
   - Input: proto.c + property list
   - Output: Property database with line numbers

3. **Database Regeneration:**
   - `tests/tools/rebuild-property-database.py` - Master regeneration script
   - Dependencies: Python 3.7+ (standard library only)
   - Input: proto.c + config files
   - Output: Complete property database

4. **Database Updater:**
   - `tests/tools/update-test-config-parser.py` - Update test file with new database
   - Dependencies: Python 3.7+ (standard library only)
   - Input: test-config-parser.c + new database
   - Output: Updated test file

5. **Schema Fetcher:**
   - `tests/tools/fetch-schema.sh` - Fetch/update ols-ucentral-schema
   - Dependencies: Bash, Git
   - Input: Current branch name
   - Output: Downloaded schema repository

---

## Schema Repository Access

### ols-ucentral-schema Repository

The uCentral configuration schema is maintained in a separate GitHub repository:

**Repository:** https://github.com/Telecominfraproject/ols-ucentral-schema

### Access Methods

#### Method 1: Automatic Fetching (Recommended)

Use the provided script with intelligent branch matching:

```bash
cd tests/tools

# Auto-detect branch (matches client branch to schema branch)
./fetch-schema.sh

# Force specific branch
./fetch-schema.sh --branch main
./fetch-schema.sh --branch release-1.0

# Check what branch would be used
./fetch-schema.sh --check-only

# Force re-download
./fetch-schema.sh --force
```

**Branch Matching Logic:**
- Client on `main` → Uses schema `main`
- Client on `release-x` → Tries schema `release-x`, falls back to `main`
- Client on feature branch → Uses schema `main`

#### Method 2: Manual Clone

```bash
# Clone to recommended location (peer to ols-ucentral-client)
cd /path/to/projects
git clone https://github.com/Telecominfraproject/ols-ucentral-schema.git

# Or clone to custom location and set path in tools
git clone https://github.com/Telecominfraproject/ols-ucentral-schema.git /custom/path
```

#### Method 3: Web Access (Read-Only)

View schema files directly on GitHub:
- Browse: https://github.com/Telecominfraproject/ols-ucentral-schema/tree/main/schema
- Raw files: `https://raw.githubusercontent.com/Telecominfraproject/ols-ucentral-schema/main/schema/ucentral.yml`

### Schema Directory Structure

Expected schema layout:
```
ols-ucentral-schema/
├── schema/
│   ├── ucentral.yml           # Root schema
│   ├── ethernet.yml
│   ├── interface.ethernet.yml
│   ├── switch.yml
│   ├── unit.yml
│   └── ... (40+ YAML files)
└── README.md
```

### Schema Location Configuration

Default location (peer to client repository):
```
/path/to/projects/
├── ols-ucentral-client/       # This repository
│   └── tests/tools/
└── ols-ucentral-schema/        # Schema repository (default)
    └── schema/
```

Custom location (set in scripts):
```bash
# Edit schema path in tools
SCHEMA_DIR="/custom/path/to/ols-ucentral-schema"
```

---

## Optional Tools

### Development and Debugging

| Tool | Purpose | Installation |
|------|---------|-------------|
| **GDB** | C debugger | `apt install gdb` or `brew install gdb` |
| **Valgrind** | Memory leak detection | `apt install valgrind` |
| **clang-format** | Code formatting | `apt install clang-format` |
| **cppcheck** | Static analysis | `apt install cppcheck` |

### Documentation

| Tool | Purpose | Installation |
|------|---------|-------------|
| **Doxygen** | API documentation | `apt install doxygen` |
| **Graphviz** | Diagram generation | `apt install graphviz` |
| **Pandoc** | Markdown conversion | `apt install pandoc` |

### CI/CD Integration

| Tool | Purpose | Notes |
|------|---------|-------|
| **GitHub Actions** | Automated testing | Configuration in `.github/workflows/` |
| **Jenkins** | Build automation | JUnit XML output supported |
| **GitLab CI** | CI/CD pipeline | Docker-based builds supported |

---

## Quick Setup Guide

### For Building Only

```bash
# 1. Install Docker
# Follow: https://docs.docker.com/get-docker/

# 2. Clone repository
git clone https://github.com/Telecominfraproject/ols-ucentral-client.git
cd ols-ucentral-client

# 3. Build everything
make all

# Done! The .deb package is in output/
```

### For Testing

```bash
# 1. Install Python 3 and pip (if not already installed)
# Ubuntu/Debian:
sudo apt update
sudo apt install python3 python3-pip

# macOS:
brew install python3

# 2. Install Python dependencies
pip3 install pyyaml

# 3. Run tests
cd tests/config-parser
make test-config-full

# Or use Docker (recommended)
docker exec ucentral_client_build_env bash -c \
    "cd /root/ols-nos/tests/config-parser && make test-config-full"
```

### For Database Generation

```bash
# 1. Ensure Python 3 and PyYAML are installed (see above)

# 2. Fetch schema repository
cd tests/tools
./fetch-schema.sh

# 3. Extract properties from schema
python3 extract-schema-properties.py \
    ../../ols-ucentral-schema/schema \
    ucentral.yml \
    --filter switch --filter ethernet

# 4. Follow property database generation guide
# See: tests/PROPERTY_DATABASE_GENERATION_GUIDE.md
```

---

## Verification Commands

### Verify Docker Installation

```bash
docker --version
# Expected: Docker version 20.10.0 or later

docker ps
# Expected: No errors (should list running containers or empty list)
```

### Verify Python Installation

```bash
python3 --version
# Expected: Python 3.7.0 or later

pip3 --version
# Expected: pip 20.0.0 or later
```

### Verify Python Dependencies

```bash
python3 -c "import yaml; print('PyYAML:', yaml.__version__)"
# Expected: PyYAML: 5.1 or later

python3 -c "import json; print('JSON: built-in')"
# Expected: JSON: built-in (no errors)
```

### Verify Git Installation

```bash
git --version
# Expected: git version 2.20.0 or later

git config --get user.name
# Expected: Your name (if configured)
```

### Verify Build Environment

```bash
# Check if Docker image exists
docker images | grep ucentral-client-build-env
# Expected: ucentral-client-build-env image listed (after first build)

# Check if container is running
docker ps | grep ucentral_client_build_env
# Expected: Container listed (if build-host-env was run)
```

### Verify Schema Access

```bash
# Check schema repository
cd tests/tools
./fetch-schema.sh --check-only
# Expected: Shows which branch would be used

# Verify schema files
ls -la ../../ols-ucentral-schema/schema/ucentral.yml
# Expected: File exists (after fetch-schema.sh)
```

---

## Troubleshooting

### Docker Issues

**Problem:** "Cannot connect to Docker daemon"
```bash
# Solution: Start Docker Desktop or daemon
sudo systemctl start docker  # Linux
# Or open Docker Desktop app (macOS/Windows)
```

**Problem:** "Permission denied" when running Docker
```bash
# Solution: Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Log out and back in for changes to take effect
```

### Python Issues

**Problem:** "ModuleNotFoundError: No module named 'yaml'"
```bash
# Solution: Install PyYAML
pip3 install pyyaml

# If pip3 install fails, try:
python3 -m pip install pyyaml
```

**Problem:** "python3: command not found"
```bash
# Solution: Install Python 3
# Ubuntu/Debian:
sudo apt install python3

# macOS:
brew install python3
```

### Schema Access Issues

**Problem:** "Schema repository not found"
```bash
# Solution: Fetch schema manually
cd tests/tools
./fetch-schema.sh --force

# Or clone manually
git clone https://github.com/Telecominfraproject/ols-ucentral-schema.git ../../ols-ucentral-schema
```

**Problem:** "Branch 'release-x' not found in schema repository"
```bash
# Solution: Use main branch
./fetch-schema.sh --branch main

# Or check available branches
git ls-remote --heads https://github.com/Telecominfraproject/ols-ucentral-schema.git
```

---

## Platform-Specific Notes

### Ubuntu/Debian

```bash
# Install all required tools
sudo apt update
sudo apt install -y \
    docker.io \
    docker-compose \
    python3 \
    python3-pip \
    git \
    make \
    bash

# Install Python dependencies
pip3 install pyyaml

# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### macOS

```bash
# Install Docker Desktop
# Download from: https://docs.docker.com/desktop/mac/install/

# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install python3 git

# Install Python dependencies
pip3 install pyyaml
```

### Windows (WSL2)

```bash
# Install Docker Desktop for Windows with WSL2 backend
# Download from: https://docs.docker.com/desktop/windows/install/

# Inside WSL2 Ubuntu:
sudo apt update
sudo apt install -y python3 python3-pip git make

# Install Python dependencies
pip3 install pyyaml
```

---

## Dependencies Summary

### Minimal (Build Only)
- Docker

### Standard (Build + Test)
- Docker
- Python 3.7+
- PyYAML

### Full (Build + Test + Database Generation)
- Docker
- Python 3.7+
- PyYAML
- Git
- Bash

### Everything Included in Repository
- Test framework (C code)
- Test configurations
- JSON schema
- Python scripts
- Shell scripts
- Documentation

---

## See Also

- **[README.md](README.md)** - Main project documentation
- **[TESTING_FRAMEWORK.md](TESTING_FRAMEWORK.md)** - Testing overview
- **[tests/MAINTENANCE.md](tests/MAINTENANCE.md)** - Schema-based database generation workflow
- **[tests/README.md](tests/README.md)** - Complete testing documentation

---

## Questions or Issues?

- **GitHub Issues:** https://github.com/Telecominfraproject/ols-ucentral-client/issues
- **Schema Issues:** https://github.com/Telecominfraproject/ols-ucentral-schema/issues
- **Documentation:** Check the `tests/` directory for detailed guides
