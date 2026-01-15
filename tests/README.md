# Configuration Testing Framework

## Overview

The OLS uCentral Client includes a comprehensive configuration testing framework that provides two-layer validation of JSON configurations:

1. **Schema Validation** - Structural validation against the uCentral JSON schema
2. **Parser Testing** - Implementation validation of the C parser with property tracking

This framework enables automated testing, continuous integration, and tracking of configuration feature implementation status.

## Documentation Index

This testing framework includes multiple documentation files, each serving a specific purpose:

### Primary Documentation

1. **[TEST_CONFIG_README.md](config-parser/TEST_CONFIG_README.md)** - Complete testing framework guide
   - Overview of two-layer validation approach
   - Quick start and running tests
   - Property tracking system
   - Configuration-specific validators
   - Test output interpretation
   - CI/CD integration
   - **Start here** for understanding the testing framework

2. **[SCHEMA_VALIDATOR_README.md](schema/SCHEMA_VALIDATOR_README.md)** - Schema validator detailed documentation
   - Standalone validator usage
   - Command-line interface
   - Programmatic API
   - Porting guide for other repositories
   - Common validation errors
   - **Start here** for schema validation specifics

3. **[MAINTENANCE.md](MAINTENANCE.md)** - Maintenance procedures guide
   - Schema update procedures
   - Property database update procedures
   - Version synchronization
   - Testing after updates
   - Troubleshooting common issues
   - **Start here** when updating schema or property database

4. **[TEST_CONFIG_PARSER_DESIGN.md](../TEST_CONFIG_PARSER_DESIGN.md)** - Test framework architecture
   - Multi-layer validation design
   - Property metadata system (560+ entries)
   - Property inspection engine
   - Test execution flow diagrams
   - Data structures and algorithms
   - Output format implementations
   - **Start here** for understanding the test framework internals

### Supporting Documentation

## Quick Reference

### Test Modes

The testing framework supports two modes:

**Stub Mode (Default - Fast)**
- Tests proto.c parsing only
- Uses simple platform stubs (test-stubs.c)
- Shows base properties only (proto.c)
- Fast execution (~30 seconds)
- Use for: Quick validation, CI/CD pipelines

**Platform Mode (Integration)**
- Tests proto.c + platform implementation (plat-gnma.c)
- Uses platform code with hardware mocks
- Shows base AND platform properties (proto.c → plat-gnma.c)
- Tracks hardware application functions called
- Slower execution (~45 seconds)
- Use for: Platform-specific validation, integration testing

### Running Tests

**RECOMMENDED: Run tests inside Docker build environment** to eliminate OS-specific issues (works on macOS, Linux, Windows):

```bash
# Build the Docker environment first (if not already built)
make build-host-env

# Run all tests in STUB mode (default - fast)
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-full"

# Run all tests in PLATFORM mode (integration)
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-full USE_PLATFORM=brcm-sonic"

# Run individual test suites
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make validate-schema"

docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config"

docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test"

# Generate test reports
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-html"

docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-json"

# Copy report files out of container to view
docker cp ucentral_client_build_env:/root/ols-nos/tests/config-parser/test-report.html ./
docker cp ucentral_client_build_env:/root/ols-nos/tests/config-parser/test-results.json ./
```

**Alternative: Run tests locally** (may have OS-specific dependencies):

```bash
# Navigate to test directory
cd tests/config-parser

# Run all tests in STUB mode (default)
make test-config-full

# Run all tests in PLATFORM mode
make test-config-full USE_PLATFORM=brcm-sonic

# Run individual test suites
make validate-schema  # Schema validation only
make test-config      # Parser tests only
make test              # Unit tests

# Generate test reports (stub mode)
make test-config-html  # HTML report (browser-viewable)
make test-config-json  # JSON report (machine-readable)
make test-config-junit # JUnit XML (CI/CD integration)

# Generate test reports (platform mode)
make test-config-html USE_PLATFORM=brcm-sonic
make test-config-json USE_PLATFORM=brcm-sonic
```

**Note:** Running tests in Docker is the preferred method as it provides a consistent, reproducible environment regardless of your host OS (macOS, Linux, Windows).

### Key Files

**Test Implementation:**
- `tests/config-parser/test-config-parser.c` (3445 lines) - Parser test framework with property tracking
- `tests/config-parser/test-stubs.c` (214 lines) - Platform function stubs for testing
- `tests/schema/validate-schema.py` (649 lines) - Standalone schema validator with undefined property detection
- `tests/config-parser/config-parser.h` - Test header exposing cfg_parse()

**Configuration Files:**
- `config-samples/ucentral.schema.pretty.json` - uCentral JSON schema (human-readable)
- `config-samples/ols.ucentral.schema.json` - uCentral JSON schema (compact)
- `config-samples/*.json` - Test configuration files (37+ configs)
- `config-samples/*invalid*.json` - Negative test cases

**Build System:**
- `tests/config-parser/Makefile` - Test targets and build rules

**Production Code (Minimal Changes):**
- `src/ucentral-client/proto.c` - Added TEST_STATIC macro (2 lines changed)
- `src/ucentral-client/include/router-utils.h` - Added extern declarations (minor change)

## Features

### Schema Validation
- Validates JSON structure against official uCentral schema
- Checks property types, required fields, constraints
- Standalone tool, no dependencies on C code
- Exit codes for CI/CD integration

### Parser Testing
- Tests actual C parser implementation
- Multiple output formats (human-readable, HTML, JSON, JUnit XML)
- Interactive HTML reports with detailed analysis
- Machine-readable JSON for automation
- JUnit XML for CI/CD integration
- Validates configuration processing and struct population
- Configuration-specific validators for business logic
- Memory leak detection
- Hardware constraint validation

### Property Tracking System
- Database of all schema properties and their implementation status (398 canonical properties)
- Tracks which properties are parsed by which functions
- Identifies unimplemented features
- Status classification: CONFIGURED, IGNORED, SYSTEM, INVALID, Unknown
- Property usage reports across all test configurations

### Two-Layer Validation Strategy

**Why Both Layers?**

Each layer catches different types of errors:

- **Schema catches**: Type mismatches, missing required fields, constraint violations
- **Parser catches**: Implementation bugs, hardware limits, cross-field dependencies
- **Property tracking catches**: Missing implementations, platform-specific features

See TEST_CONFIG_README.md section "Two-Layer Validation Strategy" for detailed explanation.

## Test Coverage

Current test suite includes:
- 37+ configuration files covering various features
- Positive tests (configs that should parse successfully)
- Negative tests (configs that should fail)
- Feature-specific validators for critical configurations
- Platform stub with 54-port simulation (matches ECS4150 hardware)

### Tested Features
- Port configuration (enable/disable, speed, duplex)
- VLAN configuration and membership
- Spanning Tree Protocol (STP, RSTP, PVST, RPVST)
- IGMP Snooping
- Power over Ethernet (PoE)
- IEEE 802.1X Authentication
- DHCP Relay
- Static routing
- System configuration (timezone, hostname, etc.)

### Platform-Specific Features (Schema-Valid, Platform Implementation Required)
- LLDP (Link Layer Discovery Protocol)
- LACP (Link Aggregation Control Protocol)
- ACLs (Access Control Lists)
- DHCP Snooping
- Loop Detection
- Port Mirroring
- Voice VLAN

These features pass schema validation but show as "Unknown" in property reports, indicating they require platform-specific implementation.

## Changes from Base Repository

The testing framework was added with minimal impact to production code:

### New Files Added
1. `tests/config-parser/test-config-parser.c` - Complete test framework (3445 lines)
2. `tests/config-parser/test-stubs.c` - Platform stubs (214 lines)
3. `tests/schema/validate-schema.py` - Schema validator (649 lines)
4. `tests/config-parser/config-parser.h` - Test header
5. `tests/config-parser/TEST_CONFIG_README.md` - Framework documentation
6. `tests/schema/SCHEMA_VALIDATOR_README.md` - Validator documentation
7. `tests/MAINTENANCE.md` - Maintenance procedures
8. `tests/config-parser/Makefile` - Test build system
9. `tests/tools/` - Property database generation tools
10. `TESTING_FRAMEWORK.md` - Documentation index (in repository root)
11. `TEST_CONFIG_PARSER_DESIGN.md` - Test framework architecture and design (in repository root)

### Modified Files
1. `src/ucentral-client/proto.c` - Added TEST_STATIC macro pattern (2 lines)
   ```c
   // Changed from:
   static struct plat_cfg *cfg_parse(...)

   // Changed to:
   #ifdef UCENTRAL_TESTING
   #define TEST_STATIC
   #else
   #define TEST_STATIC static
   #endif

   TEST_STATIC struct plat_cfg *cfg_parse(...)
   ```
   This allows test code to call cfg_parse() while keeping it static in production builds.

2. `src/ucentral-client/include/router-utils.h` - Added extern declarations
   - Exposed necessary functions for test stubs

3. `tests/config-parser/Makefile` - Test build system
   ```makefile
   test-config-parser:    # Build parser test tool
   test-config:           # Run parser tests
   validate-schema:       # Run schema validation
   test-config-full:      # Run both schema + parser tests
   ```

### Configuration Files
- Added `config-samples/cfg_invalid_*.json` - Negative test cases
- Added `config-samples/ECS4150_*.json` - Feature-specific test configs
- No changes to existing valid configurations

### Zero Impact on Production
- Production builds: No functional changes, cfg_parse() remains static
- Test builds: cfg_parse() becomes visible with -DUCENTRAL_TESTING flag
- No ABI changes, no performance impact
- No runtime dependencies added

## Integration with Development Workflow

### During Development
```bash
# 1. Make code changes to proto.c
vi src/ucentral-client/proto.c

# 2. Run tests
cd tests/config-parser
make test-config-full

# 3. Review property tracking report
# Check for unimplemented features or errors

# 4. If adding new parser function, update property database
vi test-config-parser.c
# Add property entries for new function

# 5. Create test configuration
vi ../../config-samples/test-new-feature.json

# 6. Retest
make test-config-full
```

### Before Committing
```bash
# Ensure all tests pass
cd tests/config-parser
make clean
make test-config-full

# Check for property database accuracy
make test-config | grep -A 50 "PROPERTY USAGE REPORT"
# Look for unexpected "Unknown" properties
```

### In CI/CD Pipeline
```yaml
test-configurations:
  stage: test
  script:
    - make build-host-env
    - docker exec ucentral_client_build_env bash -c
        "cd /root/ols-nos/tests/config-parser && make test-config-full"
  artifacts:
    paths:
      - tests/config-parser/test-results.txt
```

## Property Database Management

The property database is a critical component tracking which JSON properties are parsed by which functions.

### Database Structure
```c
static struct property_info properties[] = {
    {
        .path = "interfaces.ethernet.enabled",
        .parser_function = "cfg_ethernet_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Enable/disable ethernet interface"
    },
    // ... entries for all 398 schema properties ...
};
```

### Key Rules
1. **Only track properties for functions that exist in this repository's proto.c**
2. **Remove entries when parser functions are removed**
3. **Add entries immediately when adding new parser functions**
4. **Use accurate function names** - different platforms may use different names
5. **Properties not in database show as "Unknown"** - this is correct for platform-specific features

See MAINTENANCE.md for complete property database update procedures.

## Schema Management

The schema file defines what configurations are structurally valid.

### Schema Location
- `config-samples/ucentral.schema.pretty.json` - Human-readable version (recommended)
- `config-samples/ols.ucentral.schema.json` - Compact version

### Schema Source
Schema is maintained in the external [ols-ucentral-schema](https://github.com/Telecominfraproject/ols-ucentral-schema) repository.

### Schema Updates
When ols-ucentral-schema releases a new version:
1. Copy new schema to config-samples/
2. Run schema validation on all test configs
3. Fix any configs that fail new requirements
4. Document breaking changes
5. Update property database if new properties are implemented

See MAINTENANCE.md section "Schema Update Procedures" for complete process.

## Platform-Specific Repositories

This is the **base repository** providing the core framework. Platform-specific repositories (like Edgecore EC platform) can:

1. **Fork the test framework** - Copy test files to their repository
2. **Extend property database** - Add entries for platform-specific parser functions
3. **Add platform configs** - Create configs testing platform features
4. **Maintain separate tracking** - Properties "Unknown" in base become "CONFIGURED" in platform

### Example: LLDP Property Status

**In base repository (this repo):**
```
Property: interfaces.ethernet.lldp
  Status: Unknown (not in property database)
  Note: May require platform-specific implementation
```

**In Edgecore EC platform repository:**
```
Property: interfaces.ethernet.lldp
  Parser: cfg_ethernet_lldp_parse()
  Status: CONFIGURED
  Note: Per-interface LLDP transmit/receive configuration
```

Each platform tracks only the properties it actually implements.

## Troubleshooting

### Common Issues

**Tests fail in Docker but pass locally:**
- Check schema file exists in container
- Verify paths are correct in container environment
- Rebuild container: `make build-host-env`

**Property shows as "Unknown" when it should be CONFIGURED:**
- Verify parser function exists: `grep "function_name" proto.c`
- Check property path matches JSON exactly
- Ensure property entry is in properties[] array

**Schema validation fails for valid config:**
- Schema may be outdated - check version
- Config may use vendor extensions not in base schema
- Validate against specific schema: `./validate-schema.py config.json --schema /path/to/schema.json`

See MAINTENANCE.md "Troubleshooting" section for complete troubleshooting guide.

## Documentation Maintenance

When updating the testing framework:

1. **Update relevant documentation:**
   - New features → TEST_CONFIG_README.md
   - Schema changes → MAINTENANCE.md + SCHEMA_VALIDATOR_README.md
   - Property database changes → MAINTENANCE.md + TEST_CONFIG_README.md

2. **Keep version information current:**
   - Update compatibility matrices
   - Document breaking changes
   - Maintain changelogs

3. **Update examples:**
   - Refresh command output examples
   - Update property counts
   - Keep test results current

## Contributing

When contributing to the testing framework:

1. **Maintain property database accuracy** - Update when changing parser functions
2. **Add test configurations** - Create configs demonstrating new features
3. **Update documentation** - Keep docs synchronized with code changes
4. **Follow conventions** - Use established patterns for validators and property entries
5. **Test thoroughly** - Run full test suite before committing

## License

BSD-3-Clause (same as parent project)

## See Also

- **TEST_CONFIG_README.md** - Complete testing framework guide
- **TEST_CONFIG_PARSER_DESIGN.md** - Test framework architecture and design
- **SCHEMA_VALIDATOR_README.md** - Schema validator documentation
- **MAINTENANCE.md** - Update procedures and troubleshooting
- **ols-ucentral-schema repository** - Official schema source
