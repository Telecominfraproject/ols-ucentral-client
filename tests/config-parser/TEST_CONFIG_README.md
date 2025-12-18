# Configuration Testing Framework

## Overview

The OLS uCentral Client configuration testing framework provides comprehensive validation through two complementary layers:

1. **Schema Validation** (`validate-schema.py`) - Validates JSON structure against the uCentral schema
2. **Parser Testing** (`test-config-parser`) - Tests actual C parser implementation and tracks property usage

This two-layer approach ensures configurations are both structurally valid and correctly processed by the implementation.

## Prerequisites

**Docker Build Fix:** If you encounter Docker build errors with "404 Not Found" or repository errors:

```bash
# The Dockerfile may need updating due to Debian Buster EOL
# Edit Dockerfile line 1:
FROM debian:bullseye  # (was: FROM debian:buster)
```

This is a pre-existing infrastructure issue unrelated to the test suite.

## Quick Start

### RECOMMENDED: Run Tests in Docker

Running tests inside the Docker build environment is the **preferred method** as it eliminates OS-specific issues and provides a consistent, reproducible environment across macOS, Linux, and Windows.

#### Run All Tests (Schema + Parser)
```bash
# Build Docker environment first (if not already built)
make build-host-env

# Run all tests - RECOMMENDED
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-full"
```

#### Run Individual Test Suites
```bash
# Schema validation only
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make validate-schema"

# Parser tests only
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config"

# Unit tests
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test"
```

#### Generate Test Reports
```bash
# Generate HTML report (viewable in browser)
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-html"

# Generate JSON report (machine-readable)
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-json"

# Copy reports out of container to view
docker cp ucentral_client_build_env:/root/ols-nos/tests/config-parser/test-report.html ./
docker cp ucentral_client_build_env:/root/ols-nos/tests/config-parser/test-results.json ./
```

### Alternative: Run Tests Locally

**Note:** Running tests locally may encounter OS-specific dependency issues. Docker is the recommended approach.

```bash
cd tests/config-parser

# Run all tests (schema + parser)
make test-config-full

# Run individual test suites
make validate-schema  # Schema validation only
make test-config      # Parser tests only
make test              # Unit tests

# Generate test reports
make test-config-html  # HTML report
make test-config-json  # JSON report
# Output: test-report.json

# Generate JUnit XML report (for CI/CD)
make test-config-junit
# Output: test-report.xml
```

The HTML report provides:
- Visual summary of all test results
- Color-coded pass/fail indicators
- Detailed property analysis for each configuration
- Feature coverage statistics
- Property tracking reports
- Comprehensive documentation of parsing behavior

## Running Tests in Docker

The parser tests must be run inside the Docker build environment where all dependencies (cJSON, libwebsockets, etc.) are available. Schema validation can run anywhere Python 3 is installed.

### Method 1: Run Inside Build Container

```bash
# Start the build environment container
cd /path/to/ols-ucentral-client
make run-host-env

# In another terminal, exec into the container
docker exec -it ucentral_client_build_env bash

# Navigate to test directory and run tests
cd /root/ols-nos/tests/config-parser
make test-config-full
```

### Method 2: One-Shot Test Execution

```bash
# Build the container if not already built
make build-host-env

# Run tests in container
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-full"
```

## Test Features

### JSON Schema Validation
- **NEW**: All configurations are validated against the official uCentral schema before parsing
- Uses `ucentral.schema.pretty.json` from the ols-ucentral-schema repository
- Validates:
  - JSON is well-formed
  - All properties are valid per schema
  - Required fields are present
  - Field types match schema (string, number, array, object, etc.)
- Catches invalid configurations before they reach cfg_parse()

### Automatic Config Discovery
- Scans `config-samples/` for all `.json` files
- Automatically tests new configs when added to the directory
- No code changes needed to add new test cases

### Positive Tests
All configuration files without "invalid" in the filename are expected to parse successfully:
- `cfg0.json` - Port disable configuration
- `cfg1.json` - Basic port enable
- `cfg_igmp.json` - IGMP snooping
- `cfg7_ieee8021x.json` - IEEE 802.1X authentication
- `cfg_rpvstp.json` - Rapid Per-VLAN Spanning Tree
- `cfg5_poe.json` - Power over Ethernet
- And all other valid configs...

### Negative Tests
Configuration files that are expected to fail parsing fall into two categories:

**Intentional Negative Tests** (contain "invalid" in filename):
- `cfg_invalid_missing_required.json` - Missing required "interfaces" field
- `cfg_invalid_wrong_type.json` - "ethernet" is object instead of array
- `cfg_invalid_interfaces_wrong_type.json` - "interfaces" has wrong type
- `cfg_invalid_services_wrong_type.json` - "services" has wrong type

**Known Problematic Configurations** (deferred for fixing):
- `ECS4150_port_isoltaon.json` - Port isolation feature has parsing bugs
  - Passes schema validation (structurally correct)
  - Fails parser validation (implementation bug in proto.c)
  - Marked as expected failure until parsing bug is fixed
  - Configuration validity uncertain - may need revision

### Validation Levels

**Basic Validation** (all configs):
- Configuration parses without errors
- `cfg_parse()` returns non-NULL result
- Memory is properly cleaned up

**Moderate Validation** (select configs):
Specific validators check key fields for important configurations:
- **cfg0.json**: Verifies ports are disabled
- **cfg_igmp.json**: Validates IGMP version, query interval, snooping/querier settings
- **cfg7_ieee8021x.json**: Checks 802.1X auth control and RADIUS server config
- **cfg_rpvstp.json**: Validates STP mode and per-VLAN STP state
- **cfg5_poe.json**: Checks PoE power management and per-port settings
- **cfg6_dhcp.json**: Validates DHCP relay configuration

### Property Tracking System

The test framework includes a comprehensive property database that tracks all JSON configuration properties and their processing status. This helps identify:
- Which properties are actively configured
- Which properties are intentionally ignored
- Which properties require platform-specific implementation
- Missing or unimplemented features

**Property Status Values:**

- **CONFIGURED** - Property is actively parsed and configured by the implementation
- **IGNORED** - Property is intentionally ignored (deprecated, unsupported, etc.)
- **SYSTEM** - Property is system-generated or reserved for specific use cases
- **INVALID** - Property causes validation errors
- **Unknown** - Property not in database (likely requires platform-specific implementation)

**Example Property Tracking Output:**
```
[PROPERTY USAGE REPORT]
========================================
Property: interfaces.ethernet.enabled
  Parser: cfg_ethernet_parse()
  Status: CONFIGURED
  Used in: cfg0.json, ECS4150-TM.json, cfg1.json
  Count: 23/37 configs

Property: interfaces.ethernet.speed
  Parser: cfg_ethernet_parse()
  Status: CONFIGURED
  Used in: ECS4150_ethernet_speed.json, cfg1.json
  Count: 8/37 configs

Property: interfaces.ethernet.lldp
  Status: Unknown (not in property database)
  Used in: MJH-ECS415028P.json, ecs4150_lldp.json
  Count: 2/37 configs
  Note: May require platform-specific implementation

Property: services.lldp
  Status: Unknown (not in property database)
  Used in: ecs4150_lldp.json
  Count: 1/37 configs
  Note: May require platform-specific implementation
```

This report helps identify:
- **Implementation gaps**: Properties in configs but not in the database
- **Feature usage**: Which properties are commonly used across configs
- **Platform requirements**: Properties that may need vendor-specific code

See "Property Database Management" section below for details on maintaining the database.

## Adding New Tests

### Adding a New Valid Configuration

1. Simply drop a new `.json` file in `config-samples/`
2. Run `make test-config` - it will automatically be tested
3. (Optional) Add a custom validator function if you want to validate specific fields

### Adding a Negative Test

1. Create a config file with "invalid" in the name: `cfg_invalid_<description>.json`
2. Ensure the JSON is valid but the configuration should fail `cfg_parse()`
3. Run `make test-config` - it will expect this to fail

### Adding a Custom Validator

To add detailed validation for a specific config:

1. Add a validation function in `test-config-parser.c`:
```c
static int validate_my_config(const struct plat_cfg *cfg, const char *filename)
{
    // Check specific fields
    if (cfg->some_field != expected_value) {
        fprintf(stderr, "    ERROR: Expected X, got Y\n");
        return -1;
    }
    printf("    Validated my config\n");
    return 0;
}
```

2. Register it in the `validators` array:
```c
static const struct config_validator validators[] = {
    { "my_config.json", validate_my_config, "Description" },
    // ... other validators
};
```

3. Recompile and run tests

### Adding JSON Feature Detection

To detect additional features that may not be in the plat_cfg structure:

1. Add a field to `struct json_feature_presence` in `test-config-parser.c`:
```c
struct json_feature_presence {
    // ... existing fields ...
    bool has_my_feature;
};
```

2. Add detection logic in `detect_json_features()`:
```c
if (cJSON_GetObjectItemCaseSensitive(switch_obj, "my-feature")) {
    features->has_my_feature = true;
}
```

3. Add reporting in `print_config_processing_summary()`:
```c
if (json_features->has_my_feature) {
    printf("     • My Feature configuration present\n");
    global_stats.configs_with_my_feature++;
}
```

4. Add stats tracking in `struct feature_stats` and update the summary report.

This allows validation of schema-correct features even before they're fully implemented in cfg_parse().

## Property Database Management

The property database is a critical component that tracks which JSON properties are processed by the parser. It must be kept synchronized with the actual parser implementation in `proto.c`.

### Adding Properties to the Database

When implementing a new configuration feature, add corresponding entries to the property database in `test-config-parser.c`:

```c
static struct property_info properties[] = {
    // ... existing entries ...

    // New feature properties
    {
        .path = "services.new_feature.enabled",
        .parser_function = "cfg_new_feature_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Enable/disable new feature"
    },
    {
        .path = "services.new_feature.mode",
        .parser_function = "cfg_new_feature_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Operating mode: auto, manual, disabled"
    },
};
```

**Guidelines:**
- Only add properties for functions that exist in **this repository's** `proto.c`
- Each property entry should reference the actual parser function name
- Use descriptive notes to explain the property's purpose
- Set appropriate status (CONFIGURED for active features)

### Removing Invalid Properties

If a property entry references a non-existent function, it must be removed. **Do not mark it as IGNORED or add platform-specific notes** - simply remove the entry entirely.

**Rationale:** Different platforms may implement the same feature using different function names or approaches. The base repository should only track properties that are actually parsed by its own code.

**Example - What NOT to do:**
```c
// WRONG: Don't mark non-existent functions as IGNORED
{
    .path = "interfaces.ethernet.lldp",
    .parser_function = "cfg_ethernet_lldp_parse()",  // Function doesn't exist!
    .status = PROP_IGNORED,
    .notes = "Requires platform-specific implementation"
}
```

**Correct approach:**
```c
// CORRECT: Simply don't include the property entry
// If cfg_ethernet_lldp_parse() doesn't exist, there should be no entry
// The property will automatically show as "Unknown (not in property database)"
```

### Platform-Specific Properties

When a vendor adds platform-specific features:

1. Vendor implements parser function in their platform directory
2. Vendor adds property entries to their fork's database
3. Base repository continues to show these as "Unknown"
4. This is the correct behavior - no synchronization needed

### Verifying Database Accuracy

To check if the database is accurate:

1. **Search for function references:**
```bash
cd src/ucentral-client
grep "cfg_ethernet_lldp_parse" proto.c
# If this returns nothing, the function doesn't exist in the base repository
```

2. **Run property usage report:**
```bash
make test-config
# Look for "Unknown (not in property database)" entries
# These indicate either:
#   a) Missing database entries for implemented features
#   b) Properties requiring platform-specific implementation
```

3. **Check function implementation:**
```bash
# List all cfg_*_parse functions in proto.c
grep -n "^cfg_.*_parse\|^static.*cfg_.*_parse" proto.c
```

### Database Maintenance Workflow

**When adding a new feature:**
1. Implement parser function in `proto.c`
2. Add property entries to database
3. Create test configuration demonstrating the feature
4. Run tests to verify

**When discovering invalid entries:**
1. Verify function doesn't exist in `proto.c`
2. Remove all entries referencing that function
3. Rebuild and run tests
4. Property will correctly show as "Unknown"

**When porting to platform-specific repo:**
1. Copy base database as starting point
2. Add entries for platform-specific functions
3. Update status and notes for platform context
4. Maintain separate database for platform

### Common Pitfalls

❌ **Don't assume function names across platforms**
```c
// EC platform might use: cfg_ethernet_lldp_parse()
// Broadcom might use: cfg_lldp_interface_apply()
// Each platform tracks only their own functions
```

❌ **Don't mark non-existent functions as IGNORED**
```c
// Wrong: Adding entries for functions that don't exist
.parser_function = "cfg_some_feature()",  // Doesn't exist
.status = PROP_IGNORED,
```

✅ **Do maintain accurate function references**
```c
// Correct: Only list functions that actually exist
.parser_function = "cfg_ethernet_parse()",  // Exists in proto.c
.status = PROP_CONFIGURED,
```

✅ **Do use "Unknown" status appropriately**
```
// Properties not in database automatically show as:
Property: interfaces.ethernet.lldp
  Status: Unknown (not in property database)
  Note: May require platform-specific implementation
```

### Database Statistics

Current base repository property database:
- Total properties tracked: ~450+
- CONFIGURED: Properties actively parsed
- IGNORED: Intentionally unused properties
- SYSTEM: Reserved/auto-generated properties

Run `make test-config` and check the `[PROPERTY USAGE REPORT]` section for current statistics.

## Test Flow

For each configuration file, the test suite performs the following steps:

1. **Schema Validation** - Validate JSON against uCentral schema
   - Ensures JSON is well-formed
   - Checks all properties are defined in schema
   - Validates required fields and types
2. **JSON Parsing** - Parse JSON with cJSON library
3. **Config Parsing** - Parse with `cfg_parse()` function
4. **Unprocessed Property Detection** - Identify valid schema properties not processed by parser
5. **Specific Validation** - Run config-specific validators if registered

## Test Output

The test suite provides three levels of detailed reporting:

### 1. Per-Test Output

For each configuration file tested:

```
[TEST] cfg_rpvstp.json
  ✓ Schema validation: PASS
  ⚠  UNPROCESSED PROPERTIES: (1)
     The following valid schema properties were not processed by cfg_parse():
       ⚠ switch.loop-detection
     Note: These may indicate features not yet implemented or in development
    Validating: Rapid Per-VLAN STP
    Validated RPVSTP configuration
      - STP mode: RPVSTP
      - VLAN 1: STP enabled
      - VLAN 2: STP disabled
  📊 Processing Summary:
     • Ports configured: 59
     • VLANs configured: 2
     • STP: RPVST

  📝 Features in Config (schema-valid, processing status unknown):
     • LLDP configuration present [global] [interface]
     • Link Aggregation present [LACP] [trunk-group]
  ✓ PASS: Configuration parsed and validated successfully
```

Key information shown:
- **Schema validation**: Whether JSON matches the uCentral schema
- **Unprocessed properties**: Valid schema properties that cfg_parse() doesn't handle yet
- **Feature-specific validation**: Detailed checks for specific configs (IGMP settings, STP mode, etc.)
- **Processing summary**: What was actually configured (ports, VLANs, features)
- **JSON-detected features**: Features present in config that pass schema validation but aren't in plat_cfg structure

### 2. Test Summary

Overall pass/fail statistics:

```
========================================
Test Summary
========================================
Total tests:  20
Passed:       14
Failed:       6
========================================
✗ Some tests failed
```

### 3. Feature Support Summary (NEW)

A comprehensive report showing which features are supported and tested:

```
========================================
Feature Support Summary
========================================
This summary shows which features were
successfully processed across all configs:

✓ SUPPORTED & TESTED:
  • Port Configuration (12 configs)
    - Port enable/disable
    - Speed and duplex settings
  • VLAN Configuration (10 configs)
    - VLAN creation and membership
  • Spanning Tree Protocol (1 config)
    - PVST and RPVST modes
    - Per-VLAN STP configuration
  • IGMP Snooping (1 config)
    - Per-VLAN IGMP configuration
    - Querier and version settings
  • Power over Ethernet (1 config)
    - Per-port PoE enable/disable
    - Detection mode and power limits
  • IEEE 802.1X Authentication (1 config)
    - Port authenticator mode
    - RADIUS server configuration
  • DHCP Relay (1 config)
    - Per-VLAN DHCP relay

📝 PRESENT IN CONFIGS (schema-valid, processing verification needed):
  • LLDP (3 configs)
    - Present in config, may be partially processed
  • ACL - Access Control Lists (2 configs)
    - Present in config, processing status unknown
  • Link Aggregation (LACP/Trunk Groups) (1 config)
    - Present in config, processing status unknown
  • DHCP Snooping (1 config)
    - Present in config, processing status unknown
  • Loop Detection (2 configs)
    - Present in config, processing status unknown

  Note: These features passed schema validation and are present in
  config files. Further testing needed to confirm they are fully
  processed by cfg_parse() and applied to the hardware.

⚠  PARTIALLY SUPPORTED / NOT YET IMPLEMENTED:
  Total unprocessed properties across all configs: 5

  Common unprocessed properties include:
    • switch.port-isolation - Port isolation/private VLAN
    • unit.power-management - System-wide PoE power management
    • switch.acl - Access Control Lists
    • ethernet[].trunk-group - Trunk aggregation groups
    • ethernet[].lacp-config - LACP configuration
    • switch.loop-detection - Loop detection protocol
    • services.lldp - LLDP service configuration
    • switch.dhcp-snooping - DHCP snooping (global config)

  Note: These properties pass schema validation but are not
  yet fully processed by cfg_parse(). This may indicate:
    - Features planned but not yet implemented
    - Features in development
    - Platform-specific features not applicable to all switches

📋 FEATURE COVERAGE:
  Fully processed & tested features: 7
  Schema-valid features in configs: 5
  Total unprocessed properties found: 5
  ✓ Good core feature coverage!
  ℹ  Additional features present in configs need processing verification
========================================
```

This summary helps identify:
- **Fully processed features**: Confirmed to be parsed into plat_cfg and ready for hardware
- **Schema-valid features**: Present in configs and pass validation, but processing needs verification
- **Unprocessed properties**: In schema but not yet handled by cfg_parse()
- Overall feature coverage and implementation status

### Understanding Feature Categories

**1. Fully Processed & Tested**: These features are:
- Present in JSON config
- Successfully parsed by cfg_parse()
- Stored in plat_cfg structure
- Verified through structure inspection

**2. Schema-Valid Features in Configs**: These features are:
- Present in JSON config
- Pass schema validation
- May or may not be fully processed
- Detected by direct JSON inspection
- Need manual verification or hardware testing to confirm processing

Examples: LLDP, ACL, LACP, DHCP Snooping, Loop Detection

**3. Unprocessed Properties**: These are:
- Valid in schema
- Present in some configs
- Not processed by cfg_parse() (confirmed by absence in plat_cfg)

This three-tier classification helps prioritize testing and development efforts.

### Verifying "Processing Status Unknown" Features

When a feature shows "processing status unknown", you can verify if it's actually processed:

1. **Check cfg_parse() source code** (`proto.c`): Search for the property name to see if it's handled
2. **Inspect plat_cfg structure** (`ucentral-platform.h`): Check if there's a corresponding field
3. **Hardware testing**: Deploy a config and verify the feature works on actual hardware
4. **State retrieval**: Use state/telemetry commands to see if the feature appears in device state

If you confirm a feature IS processed:
- The structure field may be in a nested or differently-named location
- Consider adding explicit verification to `print_config_processing_summary()`

If you confirm a feature is NOT processed:
- It will appear in the "unprocessed properties" list
- This is expected for features not yet implemented

The JSON detection approach gives you early visibility into:
- Features present in your production configs
- Schema changes before implementation
- Testing scope for new features

## Implementation Details

### Production Code Impact

The test suite uses a minimal-impact approach to expose `cfg_parse()` for testing:

**Changes to production code (proto.c):**
- Added `TEST_STATIC` macro (expands to `static` in production builds)
- Changed `cfg_parse` from `static` to `TEST_STATIC`

**Result:**
- Production builds: Zero change - cfg_parse remains static
- Test builds: cfg_parse becomes visible with `-DUCENTRAL_TESTING` flag
- No ABI changes, no performance impact, no functional changes to production

### Files

- `test-config-parser.c` - Test framework and validators (3445 lines)
- `test-stubs.c` - Platform function stubs for testing (214 lines)
- `validate-schema.py` - Modular schema validation tool (305 lines)
- `include/config-parser.h` - Header declaring cfg_parse
- `Makefile` - Test targets: test-config, validate-schema, test-config-full
- `proto.c` - Added TEST_STATIC macro pattern (2 lines modified)
- `config-samples/cfg_invalid_*.json` - Negative test configurations (intentional failures)
- `config-samples/ECS4150_port_isoltaon.json` - Known problematic config (deferred for fixing)
- `config-samples/ucentral.schema.pretty.json` - uCentral JSON schema
- `TEST_CONFIG_README.md` - This documentation
- `SCHEMA_VALIDATOR_README.md` - Schema validator detailed documentation

## Two-Layer Validation Strategy

The testing framework uses a complementary two-layer approach:

### Layer 1: Schema Validation (validate-schema.py)

**Purpose:** Structural validation of JSON against the official uCentral schema

**What it validates:**
- JSON is well-formed and parseable
- All properties exist in the schema
- Required fields are present
- Field types match schema definitions (string, number, array, object)
- Value constraints (min/max, enums, patterns)
- Object structure and nesting

**What it doesn't validate:**
- Whether the parser actually processes the properties
- Hardware-specific constraints (port counts, VLAN ranges)
- Configuration-specific business logic
- Cross-field dependencies

**When to use:**
- Pre-flight validation before deployment
- CI/CD pipeline checks
- Configuration authoring tools
- Quick structural validation

**Exit codes:**
- `0` = All valid
- `1` = Schema validation errors
- `2` = File/schema errors

### Layer 2: Parser Testing (test-config-parser)

**Purpose:** Implementation validation of actual C parser

**What it validates:**
- Configuration is successfully parsed by cfg_parse()
- Properties are correctly extracted and stored in plat_cfg
- Config-specific business logic requirements
- Hardware constraints (port counts, feature availability)
- Memory management (no leaks)
- Cross-field dependencies and relationships

**What it doesn't validate:**
- JSON structure (assumes Layer 1 passed)
- Whether properties are in the schema

**When to use:**
- Development testing
- Regression testing after code changes
- Verifying parser implementation
- Testing platform-specific behavior

**Exit codes:**
- `0` = All tests passed
- Non-zero = Tests failed

### Why Both Layers?

The two layers catch different types of errors:

**Schema catches:**
```json
{
  "unit": {
    "timezone": 123  // Error: Should be string, not number
  }
}
```

**Parser catches:**
```json
{
  "unit": {
    "timezone": "America/Los_Angeles"  // Valid schema
  },
  "switch": {
    "spanning-tree": {
      "forward-delay": 2  // Error: Below minimum (4 seconds)
    }
  }
}
```

**Property tracking catches:**
```json
{
  "interfaces": {
    "ethernet": [{
      "name": "Ethernet0",
      "lldp": {  // Property not in database
        "transmit": true  // May require platform implementation
      }
    }]
  }
}
```

### Validation Flow

**Important:** Schema validation is a prerequisite for parser testing. The test framework enforces this rule:

1. **Schema validation runs first** on every configuration
2. **If schema validation fails:**
   - For positive tests: Test fails immediately, parser is NOT invoked
   - For negative tests: Test passes immediately (expected failure), parser is NOT invoked
3. **If schema validation passes:**
   - Parser testing proceeds
   - Configuration is parsed by cfg_parse()
   - Parser results are validated

This ensures that the parser only processes structurally valid JSON, preventing spurious errors from malformed configurations.

### Recommended Workflow

**During development:**
```bash
# 1. Validate schema first (fast)
make validate-schema
# If this passes...

# 2. Run parser tests
make test-config
# Review property tracking report for unknowns
```

**In CI/CD:**
```bash
# Run both together
make test-config-full
```

**For quick checks:**
```bash
# Single file schema check
./validate-schema.py ../../config-samples/my-config.json

# Single file parser test
./test-config-parser ../../config-samples/
```

## Relationship to Platform Implementation

### Base Repository (this repo)

**Scope:**
- Core parsing framework
- Base protocol implementation
- Platform-agnostic features
- Testing infrastructure

**Property Database:**
- Tracks only properties implemented in base proto.c
- Shows platform-specific properties as "Unknown"
- No assumptions about vendor implementations

**Test Configurations:**
- Include all schema-valid properties
- Some properties will show as "Unknown" (expected)
- Vendors add implementation, properties become "Known"

### Platform-Specific Repositories

**Scope:**
- Vendor-specific features (LLDP, LACP, ACLs, etc.)
- Platform hardware abstractions
- Extended property implementations

**Property Database:**
- Fork base database
- Add vendor-specific parser functions
- Mark properties as CONFIGURED for their platform
- May mark base properties as IGNORED if unsupported

**Test Configurations:**
- May add platform-specific test configs
- Validate vendor extensions
- Test hardware-specific constraints

### Property Status Across Repos

**Example: LLDP Configuration**

In base repository:
```
Property: interfaces.ethernet.lldp
  Status: Unknown (not in property database)
  Note: May require platform-specific implementation
```

In Edgecore platform repository:
```
Property: interfaces.ethernet.lldp
  Parser: cfg_ethernet_lldp_parse()
  Status: CONFIGURED
  Note: Per-interface LLDP configuration
```

In Broadcom platform repository:
```
Property: interfaces.ethernet.lldp
  Parser: cfg_lldp_interface_apply()
  Status: CONFIGURED
  Note: LLDP via gNMI interface configuration
```

Each platform maintains its own property database reflecting its own implementation.

## Continuous Integration

### Example CI Pipeline

```yaml
test-configs:
  stage: test
  script:
    # Build test environment
    - make build-host-env

    # Run schema validation
    - docker exec ucentral_client_build_env bash -c
        "cd /root/ols-nos/tests/config-parser && make validate-schema"

    # Run parser tests
    - docker exec ucentral_client_build_env bash -c
        "cd /root/ols-nos/tests/config-parser && make test-config"

    # Generate JSON reports
    - docker exec ucentral_client_build_env bash -c
        "cd /root/ols-nos/tests/schema &&
         python3 validate-schema.py ../../config-samples/ --format json > schema-report.json"

  artifacts:
    paths:
      - tests/schema/schema-report.json
      - tests/config-parser/test-results.txt
    when: always

  coverage: '/Property coverage: (\d+\.\d+)%/'
```

## Troubleshooting

### Schema Validation Passes, Parser Test Fails

**Possible causes:**
1. Config-specific validator requirements not met
2. Hardware constraints exceeded (too many ports/VLANs)
3. Cross-field dependency violations
4. Platform-specific feature not implemented

**Debug steps:**
```bash
# Run parser test with verbose output
./test-config-parser ../../config-samples/failing-config.json

# Check which properties are being parsed
grep "cfg_.*_parse" test-config-parser.c

# Verify plat_cfg structure
grep -A 20 "struct plat_cfg" include/ucentral-platform.h
```

### Parser Test Passes, Schema Validation Fails

**Possible causes:**
1. Configuration doesn't conform to official schema
2. Schema is outdated
3. Using vendor extensions not in base schema

**Debug steps:**
```bash
# Get detailed schema errors
./validate-schema.py ../../config-samples/failing-config.json

# Check schema version
head ../../config-samples/ucentral.schema.pretty.json

# Validate against specific schema version
./validate-schema.py my-config.json --schema /path/to/specific/schema.json
```

### Property Shows as "Unknown"

**Expected for:**
- Platform-specific features (LLDP, LACP, ACLs)
- Features not yet implemented
- Vendor extensions

**Unexpected for:**
- Properties in base proto.c implementation
- Properties with existing parser functions

**Resolution:**
```bash
# Check if parser function exists
grep "cfg_my_feature_parse" src/ucentral-client/proto.c

# If function exists, add to property database
# Edit test-config-parser.c and add property entry
```

### Many Properties Showing as "Unknown"

**If in base repository:** This is expected - many features require platform implementation

**If in platform repository:** Property database may need updating with platform-specific functions

```bash
# List all cfg_*_parse functions in your proto.c
grep -n "^static.*cfg_.*_parse\|^cfg_.*_parse" proto.c

# Compare to property database
grep "parser_function" test-config-parser.c | sort | uniq
```

## See Also

- **SCHEMA_VALIDATOR_README.md** - Detailed schema validator documentation, porting guide, API reference
- **../../config-samples/ucentral.schema.pretty.json** - Official uCentral JSON schema
- **include/ucentral-platform.h** - Platform API and plat_cfg structure definitions
- **proto.c** - Configuration parser implementation

## License

BSD-3-Clause (same as parent project)
