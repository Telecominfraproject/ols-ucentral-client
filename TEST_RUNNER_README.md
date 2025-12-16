# Test Runner Script Documentation

## Overview

`run-config-tests.sh` is a comprehensive Docker-based test runner for uCentral configuration validation. It automates the entire testing workflow: building the Docker environment, running tests with various output formats, and copying results to the host.

## Features

- **Automatic Docker Environment Management**
  - Builds Docker environment only when needed (checks Dockerfile SHA)
  - Starts/reuses existing containers intelligently
  - No manual Docker commands required

- **Multiple Output Formats**
  - **human**: Human-readable console output with colors and detailed analysis
  - **html**: Interactive HTML report with test results and property tracking
  - **json**: Machine-readable JSON for automation and metrics

- **Flexible Testing**
  - Test all configurations in one run
  - Test a single configuration file
  - Automatic result file naming and organization

- **Production-Ready**
  - Exit codes for CI/CD integration (0 = pass, non-zero = fail/issues)
  - Colored output for readability
  - Comprehensive error handling
  - Results automatically copied to `output/` directory

## Usage

### Basic Syntax

```bash
./run-config-tests.sh [format] [config-file]
```

**Parameters:**
- `format` (optional): Output format - `html`, `json`, or `human` (default: `human`)
- `config-file` (optional): Specific config file to test (default: test all configs)

### Examples

#### Test All Configurations

```bash
# Human-readable output (default)
./run-config-tests.sh

# Human-readable output (explicit)
./run-config-tests.sh human

# HTML report
./run-config-tests.sh html

# JSON output
./run-config-tests.sh json
```

#### Test Single Configuration

```bash
# Test single config with human output
./run-config-tests.sh human cfg0.json

# Test single config with HTML report
./run-config-tests.sh html ECS4150-TM.json

# Test single config with JSON output
./run-config-tests.sh json ECS4150-ACL.json
```

## Output Files

All output files are saved to the `output/` directory in the repository root.

### Output File Naming

**All Configs:**
- `test-results.txt` - Human-readable output
- `test-report.html` - HTML report
- `test-report.json` - JSON output

**Single Config:**
- `test-results-{config-name}.txt` - Human-readable output
- `test-report-{config-name}.html` - HTML report
- `test-results-{config-name}.json` - JSON output

### Output Directory Structure

```
output/
├── test-results.txt                    # All configs, human format
├── test-report.html                    # All configs, HTML format
├── test-report.json                    # All configs, JSON format
├── test-results-cfg0.txt              # Single config results
├── test-report-ECS4150-TM.html        # Single config HTML
└── test-results-ECS4150-ACL.json      # Single config JSON
```

## How It Works

### Workflow Steps

1. **Docker Check**: Verifies Docker daemon is running
2. **Environment Build**: Builds Docker environment if needed (caches based on Dockerfile SHA)
3. **Container Start**: Starts or reuses existing container
4. **Test Execution**: Runs tests inside container with specified format
5. **Result Copy**: Copies output files from container to host `output/` directory
6. **Summary**: Displays test summary and output file locations

### Docker Environment Management

The script intelligently manages the Docker environment:

```
Dockerfile unchanged → Skip build (use existing image)
Dockerfile modified  → Build new image with new SHA tag
Container exists     → Reuse existing container
Container missing    → Create new container
Container stopped    → Start existing container
```

This ensures fast subsequent runs while detecting when rebuilds are necessary.

## Output Format Details

### Human Format (default)

Human-readable console output with:
- Color-coded pass/fail indicators
- Detailed error messages
- Property usage reports
- Feature coverage analysis
- Schema validation results

**Best for:** Interactive development, debugging, manual testing

**Example:**
```
[TEST] config-samples/cfg0.json
  ✓ PASS - Schema validation
  ✓ PASS - Parser validation
  Properties: 42 configured, 5 unknown

Total tests: 37
Passed: 37
Failed: 0
```

### HTML Format

Interactive web report with:
- Test result summary table
- Pass/fail status with colors
- Expandable test details
- Property tracking information
- Feature coverage matrix
- Timestamp and metadata

**Best for:** Test reports, sharing results, archiving, presentations

**Open with:**
```bash
open output/test-report.html           # macOS
xdg-open output/test-report.html       # Linux
start output/test-report.html          # Windows
```

### JSON Format

Machine-readable structured data with:
- Test results array
- Pass/fail status
- Error details
- Property usage data
- Timestamps
- Exit codes

**Best for:** CI/CD integration, automation, metrics, analysis

**Structure:**
```json
{
  "summary": {
    "total": 37,
    "passed": 37,
    "failed": 0,
    "timestamp": "2025-12-15T10:30:00Z"
  },
  "tests": [
    {
      "config": "cfg0.json",
      "passed": true,
      "schema_valid": true,
      "parser_valid": true,
      "properties": { "configured": 42, "unknown": 5 }
    }
  ]
}
```

## Exit Codes

The script uses exit codes for CI/CD integration:

- `0` - All tests passed successfully
- `1` - Some tests failed or had validation errors
- `2` - System errors (Docker not running, file not found, etc.)

**CI/CD Example:**
```bash
./run-config-tests.sh json
if [ $? -eq 0 ]; then
    echo "All tests passed!"
else
    echo "Tests failed, see output/test-report.json"
    exit 1
fi
```

## Performance

### First Run (Cold Start)

```
Build Docker environment: 5-10 minutes (one-time)
Run all config tests:     10-30 seconds
Total first run:          ~10 minutes
```

### Subsequent Runs (Warm Start)

```
Environment check:        1-2 seconds (skipped if unchanged)
Container startup:        1-2 seconds (or reuse running container)
Run all config tests:     10-30 seconds
Total subsequent run:     ~15 seconds
```

### Single Config Test

```
Test single config:       1-3 seconds
Total time:              ~5 seconds (with running container)
```

## Troubleshooting

### Docker Not Running

**Error:**
```
✗ Docker is not running. Please start Docker and try again.
```

**Solution:**
- Start Docker Desktop (macOS/Windows)
- Start Docker daemon: `sudo systemctl start docker` (Linux)

### Container Build Failed

**Error:**
```
✗ Failed to build environment
```

**Solution:**
```bash
# Clean Docker and rebuild
docker system prune -a
make clean
./run-config-tests.sh
```

### Config File Not Found

**Error:**
```
✗ Config file not found in container: myconfig.json
```

**Solution:**
- Check available configs: `ls config-samples/*.json`
- Ensure config file is in `config-samples/` directory
- Use correct filename (case-sensitive)

### Test Output Not Copied

**Error:**
```
⚠ Output file not found in container: test-report.html
```

**Solution:**
- Check test execution logs for errors
- Verify test completed successfully inside container
- Try running tests manually: `docker exec ucentral_client_build_env bash -c "cd /root/ols-nos/tests/config-parser && make test-config"`

### Permission Denied

**Error:**
```
Permission denied: ./run-config-tests.sh
```

**Solution:**
```bash
chmod +x run-config-tests.sh
```

## Integration with Existing Workflows

### With Makefile

The script is independent of the Makefile but uses the same Docker infrastructure:

```bash
# Build environment (Makefile or script)
make build-host-env
# OR let script build it automatically

# Run tests (script provides better output management)
./run-config-tests.sh html
```

### With CI/CD

#### GitHub Actions

```yaml
name: Configuration Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run config tests
        run: ./run-config-tests.sh json
      - name: Upload test results
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: output/test-report.json
```

#### GitLab CI

```yaml
test-configs:
  stage: test
  script:
    - ./run-config-tests.sh json
  artifacts:
    paths:
      - output/test-report.json
    when: always
```

#### Jenkins

```groovy
stage('Test Configurations') {
    steps {
        sh './run-config-tests.sh html'
        publishHTML([
            reportDir: 'output',
            reportFiles: 'test-report.html',
            reportName: 'Config Test Report'
        ])
    }
}
```

### With Git Hooks

**Pre-commit hook** (test before commit):
```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running configuration tests..."
./run-config-tests.sh human

if [ $? -ne 0 ]; then
    echo "Tests failed. Commit aborted."
    exit 1
fi
```

## Advanced Usage

### Custom Output Directory

Modify the `OUTPUT_DIR` variable in the script:

```bash
# Edit run-config-tests.sh
OUTPUT_DIR="$SCRIPT_DIR/my-custom-output"
```

### Test Specific Config Pattern

```bash
# Test all ACL configs
for config in config-samples/*ACL*.json; do
    ./run-config-tests.sh json "$(basename $config)"
done
```

### Parallel Testing (Multiple Containers)

```bash
# Start multiple containers for parallel testing
docker exec ucentral_client_build_env_1 bash -c "cd /root/ols-nos/src/ucentral-client && ./test-config-parser config1.json" &
docker exec ucentral_client_build_env_2 bash -c "cd /root/ols-nos/src/ucentral-client && ./test-config-parser config2.json" &
wait
```

### Automated Report Generation

```bash
# Generate all format reports
for format in human html json; do
    ./run-config-tests.sh $format
done

# Timestamp reports
mv output/test-report.html output/test-report-$(date +%Y%m%d-%H%M%S).html
```

## Comparison with Direct Make Commands

| Feature | run-config-tests.sh | Direct Make |
|---------|---------------------|-------------|
| Docker management | Automatic | Manual |
| Output to host | Automatic | Manual copy |
| Format selection | Command-line arg | Multiple make targets |
| Single config test | Built-in | Manual setup |
| Result organization | Automatic | Manual |
| Error handling | Comprehensive | Basic |
| CI/CD ready | Yes (exit codes) | Requires scripting |

**Recommendation:** Use `run-config-tests.sh` for all testing workflows. It provides a better user experience and handles Docker complexity automatically.

## Related Documentation

- **TESTING_FRAMEWORK.md** - Overview of testing framework
- **tests/config-parser/TEST_CONFIG_README.md** - Complete testing guide
- **TEST_CONFIG_PARSER_DESIGN.md** - Test framework architecture
- **tests/MAINTENANCE.md** - Schema and property database maintenance
- **QUICK_START_TESTING.md** - Quick start guide
- **README.md** - Project overview and build instructions

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review test output in `output/` directory
3. Check Docker container logs: `docker logs ucentral_client_build_env`
4. File issue in repository issue tracker

## Version

Script version: 1.0.0
Last updated: 2025-12-15
Compatible with: uCentral schema 4.1.0-rc1 and later
