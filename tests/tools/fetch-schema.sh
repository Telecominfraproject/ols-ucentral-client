#!/bin/bash
#
# Schema Repository Helper
#
# Simple helper script to fetch the uCentral schema from GitHub.
# This repository includes default schema files in config-samples/, so fetching
# is optional and only needed when updating to a newer schema version.
#
# Usage:
#   ./fetch-schema.sh [BRANCH]
#
# Examples:
#   ./fetch-schema.sh              # Clone using 'main' branch
#   ./fetch-schema.sh release-1.0  # Clone specific branch
#   ./fetch-schema.sh --help       # Show this help
#

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCHEMA_REPO="https://github.com/Telecominfraproject/ols-ucentral-schema.git"
SCHEMA_DIR="../../ols-ucentral-schema"
DEFAULT_BRANCH="main"

# Show help
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    grep '^#' "$0" | sed 's/^# \?//'
    echo ""
    echo -e "${BLUE}Repository Information:${NC}"
    echo "  Location: $SCHEMA_REPO"
    echo "  Clone to: $SCHEMA_DIR"
    echo ""
    echo -e "${BLUE}Manual Alternative:${NC}"
    echo "  cd tests/tools"
    echo "  git clone $SCHEMA_REPO"
    echo "  cd ols-ucentral-schema && git checkout <branch>"
    echo ""
    exit 0
fi

# Determine branch
BRANCH="${1:-$DEFAULT_BRANCH}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}uCentral Schema Fetcher${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Repository:${NC} $SCHEMA_REPO"
echo -e "${BLUE}Branch:${NC} $BRANCH"
echo -e "${BLUE}Target:${NC} $SCHEMA_DIR"
echo ""

# Check if directory exists
if [[ -d "$SCHEMA_DIR" ]]; then
    echo -e "${YELLOW}⚠️  Schema directory already exists: $SCHEMA_DIR${NC}"
    echo ""
    echo "Options:"
    echo "  1. Update existing clone:  cd $SCHEMA_DIR && git pull"
    echo "  2. Switch branch:          cd $SCHEMA_DIR && git checkout <branch>"
    echo "  3. Remove and re-clone:    rm -rf $SCHEMA_DIR && ./fetch-schema.sh $BRANCH"
    echo ""
    exit 1
fi

# Clone the repository
echo -e "${BLUE}ℹ️  Cloning schema repository...${NC}"
git clone --branch "$BRANCH" --depth 1 "$SCHEMA_REPO" "$SCHEMA_DIR"

echo ""
echo -e "${GREEN}✓ Schema cloned successfully${NC}"
echo ""
echo -e "${BLUE}Schema location:${NC} $SCHEMA_DIR"
echo -e "${BLUE}Branch:${NC} $(cd "$SCHEMA_DIR" && git rev-parse --abbrev-ref HEAD)"
echo -e "${BLUE}Commit:${NC} $(cd "$SCHEMA_DIR" && git rev-parse --short HEAD)"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  # Extract properties from schema"
echo "  python3 extract-schema-properties.py $SCHEMA_DIR/schema ucentral.yml"
echo ""
echo "  # See full workflow in documentation"
echo "  cat ../MAINTENANCE.md"
echo ""
