# uCentral Schema Validator

A modular, portable tool for validating JSON configuration files against the uCentral schema with advanced undefined property detection and typo suggestions.

## Features

- **Schema Validation**: Full JSON Schema Draft-7 validation (types, enums, constraints, etc.)
- **Undefined Property Detection**: Identifies properties in config not defined in schema
- **Smart Typo Detection**: Suggests corrections for likely misspellings
  - Separator mismatches: `lldp_admin_status` → `lldp-admin-status` (underscore vs dash)
  - Case mismatches: `lacpEnable` → `lacp-enable` (camelCase vs dash-case)
  - Similar spelling: Edit distance analysis with confidence scoring
- **Multiple Output Formats**: Human-readable and machine-readable JSON
- **Directory Validation**: Validate entire directories of configs at once
- **CI/CD Ready**: Exit codes and strict mode for pipeline integration
- **Schema Auto-Detection**: Automatically finds schema in common locations
- **Modular Design**: Easy to port to other repositories (platform-specific implementations, etc.)
- **Standalone Operation**: Works independently without external dependencies beyond Python 3 + jsonschema

## Installation

The validator requires Python 3 and the `jsonschema` module:

```bash
# In Docker build environment (already installed)
pip3 install jsonschema

# On host system
pip3 install jsonschema
```

## Usage

### Basic Usage

```bash
# Schema validation only (default behavior)
python3 validate-schema.py config.json

# Check for undefined properties (informational warnings)
python3 validate-schema.py config.json --check-undefined

# Strict mode: treat undefined properties as errors (for CI/CD)
python3 validate-schema.py config.json --strict-schema

# Validate all configs in a directory
python3 validate-schema.py ../../config-samples/ --check-undefined

# Specify custom schema
python3 validate-schema.py config.json --schema path/to/schema.json
```

### Understanding Undefined Properties

**Undefined properties are NOT validation errors** - they are informational warnings that help identify:

1. **Typos/Misspellings**: Properties that won't be applied even though config is valid
   - Example: `lldp_admin_status` instead of `lldp-admin-status`
   - Example: `lacpEnable` instead of `lacp-enable`

2. **Vendor-Specific Extensions**: ODM/vendor proprietary properties not in schema
   - Risk: May change without notice, not portable across platforms
   - Recommendation: Document and coordinate with schema maintainers

3. **Deprecated Properties**: Properties removed from newer schema versions
   - Check schema version compatibility

**When to use each mode:**
- **Default mode** (no flags): Standard validation, undefined properties ignored
- **`--check-undefined`**: Development mode, see warnings but don't fail builds
- **`--strict-schema`**: CI/CD enforcement mode, fail on any undefined properties

### Output Formats

```bash
# Human-readable output (default)
python3 validate-schema.py config.json --check-undefined

# Machine-readable JSON output
python3 validate-schema.py config.json --check-undefined --format json > report.json
```

### Via Makefile

```bash
# Schema validation only
make validate-schema

# Configuration parser tests only
make test-config

# Both schema validation + parser tests
make test-config-full
```

## Exit Codes

- `0`: All configurations are valid
  - Undefined properties don't affect exit code unless `--strict-schema` is used
- `1`: Validation errors OR (strict mode AND undefined properties found)
- `2`: File/schema errors (file not found, invalid schema, etc.)

## Output Examples

### Valid Configuration (Schema Only)

```
✓ Schema Valid: cfg0.json
```

### Valid Configuration with Undefined Properties Check

```
✓ Schema Valid: cfg0.json
✓ All properties defined in schema
```

### Configuration with Undefined Properties

```
✓ Schema Valid: test_config.json

ℹ️  Undefined Properties (informational):
  Found 3 property/properties not in schema
  These may be:
    • Typos/misspellings (won't be applied even though config is valid)
    • Vendor-specific extensions (not portable, may change)
    • Deprecated properties (check schema version)

  1. ethernet[].lldp_admin_status
     → Not defined in schema
     → Possible matches:
       ✓ ethernet[].lldp-interface-config.lldp-admin-status (use '-' not '_')

  2. ethernet[].lacpEnable
     → Not defined in schema
     → Possible matches:
       ✓ ethernet[].lacp-config.lacp-enable (use dash-case not camelCase)
       ? interfaces[].ipv4.ip-arp-inspect-vlan.vlan-enable (similar spelling)

  3. ethernet[].custom-property
     → Not defined in schema
```

**Note**: This config is schema-valid (exit code 0), but has informational warnings about undefined properties.

### Invalid Configuration (Schema Errors)

```
✗ Schema Invalid: bad-config.json
  Found 2 validation error(s):

  Error 1:
    Path: $.ethernet
    Message: {'speed': 1000} is not of type 'array'
    Validator: type

  Error 2:
    Path: $.interfaces[0].vlan.id
    Message: 5000 is greater than the maximum of 4094
    Validator: maximum
```

**Note**: This config fails schema validation (exit code 1).

### Directory Summary

```
Summary: 37 file(s) checked, 34 valid, 3 invalid
         5 file(s) with undefined properties
```

## Integration with test-config-parser.c

The test-config-parser.c tool automatically calls the schema validator before running parser tests. This provides two-layer validation:

1. **Layer 1 (Schema)**: Structural validation - is the JSON valid per schema?
2. **Layer 2 (Parser)**: Implementation validation - can proto.c process it?

## Porting to Other Repositories

The validator is designed to be repository-agnostic. To port to another repository:

1. Copy `validate-schema.py` to the target repository
2. Ensure the schema file is in one of the search paths, or specify with `--schema`
3. Update Makefile targets if desired

### Default Schema Search Paths

Relative to the validator script location:

- `../../config-samples/ucentral.schema.pretty.json`
- `../../config-samples/ols.ucentral.schema.json`
- `../../../config-samples/ucentral.schema.pretty.json`
- `./ols.ucentral.schema.json`

## Python API

The `SchemaValidator` class can be imported and used programmatically:

```python
from validate_schema import SchemaValidator

# Initialize validator
validator = SchemaValidator(schema_path="/path/to/schema.json")

# Validate a file
is_valid, errors = validator.validate_file("config.json")

# Validate a config dict
config = {"uuid": 123, "ethernet": []}
is_valid, errors = validator.validate_config(config)

# Validate directory
results = validator.validate_directory("/path/to/configs")
```

## Typo Detection Features

The validator includes intelligent typo detection that identifies naming mistakes and suggests corrections:

### Separator Mismatches

**Underscore vs Dash:**
```
ethernet[].lldp_admin_status  ❌ Underscore
ethernet[].lldp-admin-status  ✓ Correct (dash-case)
```

**camelCase vs dash-case:**
```
ethernet[].lacpEnable         ❌ camelCase
ethernet[].lacp-enable        ✓ Correct (dash-case)
```

### Similar Spelling

Uses Levenshtein distance algorithm to find properties with similar spelling:
```
services.logSettings.enabled  ❌ Not in schema
services.log.enabled          ✓ Possible match (edit distance: 1)
```

### Confidence Levels

- **✓ High confidence**: Exact match after normalization (separator/case fix)
- **? Medium confidence**: Similar spelling (edit distance 2-3)
- **No suggestion**: No similar properties found (likely vendor-specific)

## Common Validation Errors

### Schema Validation Errors (Exit Code 1)

These are actual schema violations that must be fixed:

**Type Errors:**
```
$.ethernet is not of type 'array'
```
**Fix**: Ensure `ethernet` is an array: `"ethernet": [...]`

**Out of Range:**
```
$.interfaces[0].vlan.id is greater than the maximum of 4094
```
**Fix**: VLAN IDs must be between 1-4094

**Required Property Missing:**
```
'uuid' is a required property
```
**Fix**: Add the required field: `"uuid": 1234567890`

**Additional Properties Not Allowed:**
```
Additional properties are not allowed ('unknown_field' was unexpected)
```
**Fix**: Remove the field or check spelling (only if schema has `additionalProperties: false`)

### Undefined Properties (Exit Code 0 by default)

These are informational warnings that don't cause validation failure:

**Typo/Misspelling:**
```
ℹ️  ethernet[].lldp_admin_status not in schema
   Suggestion: ethernet[].lldp-interface-config.lldp-admin-status
```
**Impact**: Property won't be applied even though config is valid

**Vendor Extension:**
```
ℹ️  ethernet[].edgecore-specific-property not in schema
   No suggestions found
```
**Impact**: Not portable, may change without notice

## CI/CD Integration

### Basic Pipeline

```yaml
validate-configs:
  stage: test
  script:
    # Standard validation (undefined properties are warnings)
    - python3 validate-schema.py config-samples/
  artifacts:
    when: on_failure
    paths:
      - validation-report.json
```

### Strict Enforcement Pipeline

```yaml
validate-configs-strict:
  stage: test
  script:
    # Strict mode: fail on undefined properties
    - python3 validate-schema.py config-samples/ --strict-schema
    # Generate JSON report for analysis
    - python3 validate-schema.py config-samples/ --check-undefined --format json > report.json
  artifacts:
    always:
      paths:
        - report.json
```

### Development Workflow

```bash
# Before committing: check for typos
python3 validate-schema.py my-config.json --check-undefined

# Review suggestions and fix obvious typos
# Document any intentional vendor-specific properties

# CI/CD will enforce with --strict-schema
```

## Files

- **validate-schema.py**: Standalone schema validator script (649 lines)
- **Makefile**: Build targets for schema validation
- **test-config-parser.c**: Enhanced with schema validation integration
- **SCHEMA_VALIDATOR_README.md**: This documentation

## See Also

- [TEST_CONFIG_README.md](../config-parser/TEST_CONFIG_README.md) - Configuration parser testing guide
- [ucentral.schema.pretty.json](../../config-samples/ucentral.schema.pretty.json) - Official uCentral schema

## License

BSD-3-Clause
