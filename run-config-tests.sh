#!/bin/bash
#
# run-config-tests.sh - Run uCentral configuration tests in Docker
#
# Usage: ./run-config-tests.sh [format] [config-file]
#
# Arguments:
#   format      - Output format: html, json, human (default: human)
#   config-file - Optional specific config file to test (default: all configs)
#
# Examples:
#   ./run-config-tests.sh human                    # Test all configs, human output
#   ./run-config-tests.sh html                     # Test all configs, HTML report
#   ./run-config-tests.sh json cfg0.json           # Test single config, JSON output
#

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="ucentral_client_build_env"
BUILD_DIR="/root/ols-nos/tests/config-parser"
CONFIG_DIR="/root/ols-nos/config-samples"
OUTPUT_DIR="$SCRIPT_DIR/output"
DOCKERFILE_PATH="$SCRIPT_DIR/Dockerfile"

# Parse arguments
FORMAT="${1:-human}"
SINGLE_CONFIG="${2:-}"

# Validate format
case "$FORMAT" in
    html|json|human)
        ;;
    *)
        echo -e "${RED}Error: Invalid format '$FORMAT'. Must be 'html', 'json', or 'human'${NC}"
        echo "Usage: $0 [html|json|human] [config-file]"
        exit 1
        ;;
esac

# Function to print status messages
print_status() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to check if container exists
container_exists() {
    docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Function to check if container is running
container_running() {
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Function to get Dockerfile SHA
get_dockerfile_sha() {
    if [ -f "$DOCKERFILE_PATH" ]; then
        shasum -a 1 "$DOCKERFILE_PATH" | awk '{print $1}' | cut -c1-8
    else
        echo "unknown"
    fi
}

# Function to build Docker environment if needed
build_environment() {
    local current_sha=$(get_dockerfile_sha)
    local image_tag="ucentral-build-env:${current_sha}"

    # Check if image exists
    if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${image_tag}$"; then
        print_success "Build environment image already exists (${image_tag})"
        return 0
    fi

    print_status "Building Docker build environment..."
    print_status "This may take several minutes on first run..."

    if make build-host-env; then
        print_success "Build environment created"
    else
        print_error "Failed to build environment"
        exit 1
    fi
}

# Function to start container if not running
start_container() {
    if container_running; then
        print_success "Container is already running"
        return 0
    fi

    if container_exists; then
        print_status "Starting existing container..."
        docker start "$CONTAINER_NAME" > /dev/null
        print_success "Container started"
    else
        print_status "Creating and starting new container..."
        if make run-host-env; then
            print_success "Container created and started"
        else
            print_error "Failed to start container"
            exit 1
        fi
    fi

    # Wait for container to be ready
    sleep 2
}

# Function to run tests in Docker
run_tests() {
    local test_cmd=""
    local output_file=""
    local copy_files=()

    if [ -n "$SINGLE_CONFIG" ]; then
        print_status "Running test for single config: $SINGLE_CONFIG"

        # Verify config exists in container
        if ! docker exec "$CONTAINER_NAME" bash -c "test -f $CONFIG_DIR/$SINGLE_CONFIG"; then
            print_error "Config file not found in container: $SINGLE_CONFIG"
            print_status "Available configs:"
            docker exec "$CONTAINER_NAME" bash -c "ls $CONFIG_DIR/*.json 2>/dev/null | xargs -n1 basename" || true
            exit 1
        fi

        case "$FORMAT" in
            html)
                output_file="test-report-${SINGLE_CONFIG%.json}.html"
                test_cmd="cd $BUILD_DIR && make test-config-parser && LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser --html $CONFIG_DIR/$SINGLE_CONFIG > $BUILD_DIR/$output_file"
                copy_files=("$output_file")
                ;;
            json)
                output_file="test-results-${SINGLE_CONFIG%.json}.json"
                test_cmd="cd $BUILD_DIR && make test-config-parser && LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser --json $CONFIG_DIR/$SINGLE_CONFIG > $BUILD_DIR/$output_file"
                copy_files=("$output_file")
                ;;
            human)
                output_file="test-results-${SINGLE_CONFIG%.json}.txt"
                test_cmd="cd $BUILD_DIR && make test-config-parser && LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser $CONFIG_DIR/$SINGLE_CONFIG 2>&1 | tee $BUILD_DIR/$output_file"
                copy_files=("$output_file")
                ;;
        esac
    else
        print_status "Running tests for all configurations (format: $FORMAT)"

        case "$FORMAT" in
            html)
                output_file="test-report.html"
                test_cmd="cd $BUILD_DIR && make test-config-html"
                copy_files=("$output_file")
                ;;
            json)
                output_file="test-report.json"
                test_cmd="cd $BUILD_DIR && make test-config-json"
                copy_files=("$output_file")
                ;;
            human)
                output_file="test-results.txt"
                test_cmd="cd $BUILD_DIR && make test-config-full 2>&1 | tee $BUILD_DIR/$output_file"
                copy_files=("$output_file")
                ;;
        esac
    fi

    print_status "Executing tests in container..."
    echo ""

    # Run the test command
    if docker exec "$CONTAINER_NAME" bash -c "$test_cmd"; then
        print_success "Tests completed successfully"
        TEST_EXIT_CODE=0
    else
        TEST_EXIT_CODE=$?
        print_warning "Tests completed with issues (exit code: $TEST_EXIT_CODE)"
    fi

    echo ""

    # Create output directory if it doesn't exist
    mkdir -p "$OUTPUT_DIR"

    # Copy output files from container to host
    for file in "${copy_files[@]}"; do
        if docker exec "$CONTAINER_NAME" bash -c "test -f $BUILD_DIR/$file"; then
            print_status "Copying $file from container to host..."
            docker cp "$CONTAINER_NAME:$BUILD_DIR/$file" "$OUTPUT_DIR/$file"
            print_success "Output saved: $OUTPUT_DIR/$file"

            # Show file info
            local file_size=$(du -h "$OUTPUT_DIR/$file" | cut -f1)
            echo "  Size: $file_size"
        else
            print_warning "Output file not found in container: $file"
        fi
    done

    return $TEST_EXIT_CODE
}

# Function to print summary
print_summary() {
    local exit_code=$1
    echo ""
    echo "========================================"
    echo "Test Run Summary"
    echo "========================================"
    echo "Format:     $FORMAT"
    if [ -n "$SINGLE_CONFIG" ]; then
        echo "Config:     $SINGLE_CONFIG"
    else
        echo "Config:     All configurations"
    fi
    echo "Output Dir: $OUTPUT_DIR"
    echo ""

    if [ $exit_code -eq 0 ]; then
        print_success "All tests passed!"
    else
        print_warning "Some tests failed or had issues"
    fi

    echo ""
    echo "Output files:"
    ls -lh "$OUTPUT_DIR" | tail -n +2 | while read -r line; do
        echo "  $line"
    done
}

# Main execution
main() {
    print_status "uCentral Configuration Test Runner"
    echo ""

    # Check prerequisites
    check_docker

    # Build environment if needed
    build_environment

    # Start container if needed
    start_container

    # Run tests
    run_tests
    TEST_RESULT=$?

    # Print summary
    print_summary $TEST_RESULT

    exit $TEST_RESULT
}

# Run main function
main
