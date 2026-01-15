# Design of test-config-parser.c

The `tests/config-parser/test-config-parser.c` file implements a comprehensive configuration testing framework with a sophisticated multi-layered design. This document describes the architecture and implementation details.

## 1. **Core Architecture: Multi-Layer Validation**

The framework validates configurations through three complementary layers:

### Layer 1: Schema Validation
- Invokes external `tests/schema/validate-schema.py` to verify JSON structure against uCentral schema
- Catches: JSON syntax errors, type mismatches, missing required fields, constraint violations
- If schema validation fails, parsing is skipped to ensure clean error isolation

### Layer 2: Parser Testing
- Calls production `cfg_parse()` function from `src/ucentral-client/proto.c`
- Tests actual C parser implementation with real platform data structures
- Catches: Parser bugs, memory issues, hardware constraints, cross-field dependencies

### Layer 3: Property Tracking
- Deep recursive inspection of JSON tree to classify every property
- Maps properties to property metadata database (398 schema properties)
- Tracks which properties are CONFIGURED, IGNORED, INVALID, UNKNOWN, etc.
- Properties with line numbers are implemented in proto.c; line_number=0 means not yet implemented

## 2. **Property Metadata System**

### Property Database Structure
```c
struct property_metadata {
    const char *path;              // JSON path: "ethernet[].speed"
    enum property_status status;    // CONFIGURED, IGNORED, UNKNOWN, etc.
    const char *source_file;        // Where processed: "proto.c"
    const char *source_function;    // Function: "cfg_ethernet_parse"
    int source_line;               // Line number in proto.c (if available)
    const char *notes;             // Context/rationale
};
```

**Database contains entries for all 398 schema properties** documenting:
- Which properties are actively parsed (PROP_CONFIGURED with line numbers)
- Which are not yet implemented (line_number=0)
- Which are intentionally ignored (PROP_IGNORED)
- Which need platform implementation (PROP_UNKNOWN)
- Which are structural containers (PROP_SYSTEM)

### Property Status Classification
- **PROP_CONFIGURED**: Successfully processed by parser
- **PROP_MISSING**: Required but absent
- **PROP_IGNORED**: Present but intentionally not processed
- **PROP_INVALID**: Invalid value (out of bounds, wrong type)
- **PROP_INCOMPLETE**: Missing required sub-fields
- **PROP_UNKNOWN**: Needs manual classification/testing (may require platform implementation)
- **PROP_SYSTEM**: Structural container (not leaf value)

## 3. **Property Inspection Engine**

### scan_json_tree_recursive() (lines 1399-1459)
Recursive descent through JSON tree:
1. Traverses entire JSON configuration structure
2. For each property, builds full dot-notation path (e.g., `"interfaces[].ipv4.subnet[].prefix"`)
3. Looks up property in metadata database via `lookup_property_metadata()`
4. Records property validation result with status, value, source location
5. Continues recursion into nested objects/arrays

### lookup_property_metadata() (lines 1314-1348)
Smart property matching:
1. Normalizes path by replacing `[N]` with `[]` (e.g., `ethernet[5].speed` → `ethernet[].speed`)
2. Searches property database for matching canonical path
3. Returns metadata if found, NULL if unknown property

### scan_for_unprocessed_properties() (lines 1666-1765)
Legacy unprocessed property detection:
- Checks properties against known property lists at each config level
- Reports properties that exist in JSON but aren't in "known" lists
- Used alongside property database for comprehensive coverage

## 4. **Test Execution Flow**

### Main Test Function: test_config_file() (lines 1790-1963)

```
┌─────────────────────────────────────────┐
│ 1. Schema Validation                    │
│    - validate_against_schema()          │
│    - If fails: mark test, skip parsing  │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 2. JSON Parsing                         │
│    - read_json_file()                   │
│    - cJSON_Parse()                      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 3. Feature Detection                    │
│    - detect_json_features()             │
│    - Find LLDP, ACL, LACP, etc.         │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 4. Property Inspection                  │
│    - scan_json_tree_recursive()         │
│    - Build property validation list     │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 5. Parser Invocation                    │
│    - cfg = cfg_parse(json)              │
│    - Invoke production parser           │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 6. Feature Statistics                   │
│    - update_feature_statistics()        │
│    - Count ports, VLANs, features       │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 7. Validation (Optional)                │
│    - run_validator() for specific       │
│      configs (cfg0, PoE, DHCP, etc.)    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 8. Result Recording                     │
│    - finalize_test_result()             │
│    - Store in linked list               │
└─────────────────────────────────────────┘
```

## 5. **Data Structures**

### test_result (lines 94-128)
Per-test result tracking:
```c
struct test_result {
    char filename[256];
    int passed;
    char error_message[512];
    int ports_configured, vlans_configured;
    int unprocessed_properties;

    // Property counters
    int properties_configured;
    int properties_missing;
    int properties_ignored;
    // ... etc

    // Feature presence flags
    int has_port_config, has_vlan_config;
    int has_stp, has_igmp, has_poe;
    // ... etc

    // Linked list of property validations
    struct property_validation *property_validations;
    struct test_result *next;
};
```

### property_validation (lines 85-92)
Individual property validation record:
```c
struct property_validation {
    char path[128];                    // "unit.hostname"
    enum property_status status;
    char value[512];                   // "\"switch01\""
    char details[256];                 // Additional context
    char source_location[128];         // "proto.c:cfg_unit_parse()"
    struct property_validation *next;
};
```

## 6. **Feature Statistics Tracking**

### Global Statistics (lines 40-56)
```c
struct feature_stats {
    int configs_with_ports;
    int configs_with_vlans;
    int configs_with_stp;
    int configs_with_igmp;
    int configs_with_poe;
    int configs_with_ieee8021x;
    int configs_with_dhcp_relay;
    int configs_with_lldp;      // JSON-detected
    int configs_with_acl;        // JSON-detected
    int configs_with_lacp;       // JSON-detected
    // ... etc
};
```

**Two detection methods:**
1. **Parser-based**: Check `plat_cfg` structure for configured values (ports, VLANs, STP mode)
2. **JSON-based**: Detect schema-valid features in JSON that may not be parsed (LLDP, ACL, LACP)

## 7. **Output Formats** (lines 26-31)

### OUTPUT_HUMAN (default)
- Colorful console output with emojis
- Detailed property analysis
- Processing summaries
- Feature statistics

### OUTPUT_JSON (lines 2015-2097)
- Machine-readable JSON report
- Full test results with property details
- CI/CD integration friendly

### OUTPUT_HTML (lines 2099+)
- Interactive web report
- Full test details with styling
- Browser-viewable (982KB typical size)

### OUTPUT_JUNIT (planned)
- JUnit XML format for Jenkins/GitLab CI

## 8. **Validator Registry** (lines 302-343)

Optional per-config validators for deep validation:
```c
static const struct config_validator validators[] = {
    { "cfg0.json", validate_cfg0, "Port disable configuration" },
    { "cfg5_poe.json", validate_cfg_poe, "PoE configuration" },
    { "cfg6_dhcp.json", validate_cfg_dhcp, "DHCP relay" },
    // ... etc
};
```

Validators inspect `plat_cfg` structure to verify specific features were correctly parsed.

## 9. **Test Discovery** (lines 1968-2010)

`test_directory()` auto-discovers test configs:
- Scans directory for `.json` files
- Skips `schema.json`, `Readme.json`
- Invokes `test_config_file()` for each config

## 10. **Key Design Patterns**

### Negative Test Support (lines 445-458)
```c
static int is_negative_test(const char *filename) {
    if (strstr(filename, "invalid") != NULL) return 1;
    if (strstr(filename, "ECS4150_port_isoltaon.json") != NULL) return 1;
    return 0;
}
```
Configs expected to fail are marked as "PASS" if parsing fails.

### Schema-First Validation (lines 1818-1836)
Schema validation is a **prerequisite** for parser testing. If schema fails, parser is never invoked, ensuring clean error isolation.

### Linked List Result Storage (lines 221-242)
All test results stored in linked list for:
- Multiple output format generation from same data
- Summary statistics calculation
- Report generation after all tests complete

## 11. **Critical Integration Points**

### With Production Code (minimal impact):
- **proto.c**: Uses `cfg_parse()` exposed via `TEST_STATIC` macro
- **ucentral-log.h**: Registers `test_log_callback()` to capture parser errors (lines 134-160)
- **ucentral-platform.h**: Inspects `struct plat_cfg` to verify parsing results

### With Schema Validator:
- **tests/schema/validate-schema.py**: External Python script invoked via `system()` call
- Schema path: `config-samples/ols.ucentral.schema.pretty.json`

## 12. **Property Database Maintenance Rules**

**Critical Rule**:
> The property database must only contain entries for parser functions that exist in this repository's proto.c. Do not add entries for platform-specific functions that don't exist in the base implementation.

This keeps the base repository clean and allows platform-specific forks to extend the database with their own implementations.

---

## Summary

The design elegantly separates concerns:

1. **Schema layer** validates JSON structure (delegated to Python)
2. **Parser layer** tests C implementation (calls production code)
3. **Property layer** tracks implementation status (metadata database)
4. **Validation layer** verifies specific features (optional validators)
5. **Reporting layer** generates multiple output formats

The property metadata database is the **crown jewel** - it documents the implementation status of all 398 schema properties, enabling automated detection of unimplemented features and validation of parser coverage.

## Related Documentation

For additional information about the testing framework:

- **TESTING_FRAMEWORK.md** - Overview and documentation index
- **tests/config-parser/TEST_CONFIG_README.md** - Complete testing framework guide
- **tests/schema/SCHEMA_VALIDATOR_README.md** - Schema validator documentation
- **tests/MAINTENANCE.md** - Schema and property database update procedures
- **TEST_RUNNER_README.md** - Test runner script documentation
- **QUICK_START_TESTING.md** - Quick start guide
- **README.md** - Project overview and testing framework integration
