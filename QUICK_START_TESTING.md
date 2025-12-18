# Quick Start: Testing Guide

## TL;DR

```bash
# Test all configs with human-readable output
./run-config-tests.sh

# Generate HTML report
./run-config-tests.sh html

# Test single config
./run-config-tests.sh human ECS4150-TM.json

# Results are in: output/
```

## Common Commands

### Test All Configurations

```bash
./run-config-tests.sh human    # Console output with colors
./run-config-tests.sh html     # Interactive HTML report
./run-config-tests.sh json     # Machine-readable JSON
```

### Test Single Configuration

```bash
./run-config-tests.sh human cfg0.json
./run-config-tests.sh html ECS4150-ACL.json
./run-config-tests.sh json ECS4150-TM.json
```

### View Results

```bash
# Open HTML report in browser
open output/test-report.html                    # macOS
xdg-open output/test-report.html                # Linux

# View text results
cat output/test-results.txt

# Parse JSON results
cat output/test-report.json | jq '.summary'
```

## What the Script Does

1. ✅ Checks Docker is running
2. ✅ Builds Docker environment (only if needed)
3. ✅ Starts/reuses container
4. ✅ Runs tests inside container
5. ✅ Copies results to `output/` directory
6. ✅ Shows summary

## Output Formats

| Format | Use Case | Output File |
|--------|----------|-------------|
| `human` | Interactive development, debugging | `output/test-results.txt` |
| `html` | Reports, sharing, presentations | `output/test-report.html` |
| `json` | CI/CD, automation, metrics | `output/test-report.json` |

## First Run vs Subsequent Runs

**First Run (cold start):**
- Builds Docker environment: ~10 minutes (one-time)
- Runs tests: ~30 seconds
- **Total: ~10 minutes**

**Subsequent Runs (warm start):**
- Reuses environment: ~2 seconds
- Runs tests: ~30 seconds
- **Total: ~30 seconds**

## Troubleshooting

### Docker not running
```bash
# Start Docker Desktop (macOS/Windows)
# OR
sudo systemctl start docker  # Linux
```

### Permission denied
```bash
chmod +x run-config-tests.sh
```

### Config not found
```bash
# List available configs
ls config-samples/*.json
```

## CI/CD Integration

### Exit Codes
- `0` = All tests passed ✅
- `1` = Tests failed ❌
- `2` = System error ⚠️

### Example Pipeline
```yaml
- name: Run tests
  run: ./run-config-tests.sh json
- name: Check results
  run: |
    if [ $? -eq 0 ]; then
      echo "✅ All tests passed"
    else
      echo "❌ Tests failed"
      exit 1
    fi
```

## Available Test Configs

```bash
# List all configs
ls -1 config-samples/*.json | xargs -n1 basename

# Common test configs:
cfg0.json                          # Basic config
ECS4150-TM.json                    # Traffic management
ECS4150-ACL.json                   # Access control lists
ECS4150STP_RSTP.json              # Spanning tree
ECS4150_IGMP_Snooping.json        # IGMP snooping
ECS4150_POE.json                   # Power over Ethernet
ECS4150_VLAN.json                  # VLAN configuration
```

## What Gets Tested

✅ JSON schema validation (structure, types, constraints)
✅ Parser validation (actual C parser implementation)
✅ Property tracking (configured vs unknown properties)
✅ Feature coverage (implemented vs documented features)
✅ Error handling (invalid configs, missing fields)

## Quick Reference

| Task | Command |
|------|---------|
| Test everything | `./run-config-tests.sh` |
| HTML report | `./run-config-tests.sh html` |
| JSON output | `./run-config-tests.sh json` |
| Single config | `./run-config-tests.sh human cfg0.json` |
| View HTML | `open output/test-report.html` |
| View results | `cat output/test-results.txt` |
| Parse JSON | `cat output/test-report.json \| jq` |

## Full Documentation

- **TEST_RUNNER_README.md** - Complete script documentation
- **TESTING_FRAMEWORK.md** - Testing framework overview
- **tests/config-parser/TEST_CONFIG_README.md** - Detailed testing guide
- **TEST_CONFIG_PARSER_DESIGN.md** - Test framework architecture
- **tests/MAINTENANCE.md** - Maintenance procedures
- **README.md** - Project overview and build instructions

## Directory Structure

```
ols-ucentral-client/
├── run-config-tests.sh              ← Test runner script
├── output/                           ← Test results go here
├── config-samples/                   ← Test configurations
└── tests/
    ├── config-parser/
    │   ├── test-config-parser.c      ← Test implementation
    │   ├── test-stubs.c              ← Platform stubs
    │   ├── config-parser.h           ← Test header
    │   ├── Makefile                  ← Test build system
    │   └── TEST_CONFIG_README.md     ← Detailed guide
    ├── schema/
    │   ├── validate-schema.py        ← Schema validator
    │   └── SCHEMA_VALIDATOR_README.md
    ├── tools/                        ← Property database tools
    └── MAINTENANCE.md                ← Maintenance procedures
```

---

**Need help?** Check TEST_RUNNER_README.md for troubleshooting and advanced usage.
