# uCentral Schema Validator

A modular, portable tool for validating JSON configuration files against the uCentral schema.

## Features

- **Standalone Operation**: Works independently without external dependencies beyond Python 3 + jsonschema
- **Modular Design**: Easy to port to other repositories (EC, etc.)
- **Multiple Output Formats**: Human-readable and machine-readable JSON
- **Directory Validation**: Validate entire directories of configs at once
- **CI/CD Ready**: Exit codes suitable for automated testing
- **Schema Auto-Detection**: Automatically finds schema in common locations

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
# Validate a single file
python3 validate-schema.py config.json

# Validate all configs in a directory
python3 validate-schema.py ../../config-samples/

# Specify custom schema
python3 validate-schema.py config.json --schema path/to/schema.json
```

### Output Formats

```bash
# Human-readable output (default)
python3 validate-schema.py config.json

# Machine-readable JSON output
python3 validate-schema.py config.json --format json > report.json
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
- `1`: One or more configurations failed validation
- `2`: File/schema errors (file not found, invalid schema, etc.)

## Output Examples

### Valid Configuration

```
✓ Valid: cfg0.json
```

### Invalid Configuration

```
✗ Invalid: bad-config.json
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

### Directory Summary

```
Summary: 37 file(s) checked, 34 valid, 3 invalid
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

### Example: Porting to EC Repository

```bash
# Copy validator
cp validate-schema.py /path/to/ec-repo/src/ucentral-client/

# Use with EC's schema location
cd /path/to/ec-repo/src/ucentral-client
python3 validate-schema.py --schema ../../config-tests/schema.json ../../config-tests/
```

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

## Common Validation Errors

### Type Errors

```
$.ethernet is not of type 'array'
```

**Fix**: Ensure `ethernet` is an array: `"ethernet": [...]`

### Out of Range

```
$.interfaces[0].vlan.id is greater than the maximum of 4094
```

**Fix**: VLAN IDs must be between 1-4094

### Required Property Missing

```
'uuid' is a required property
```

**Fix**: Add the required field: `"uuid": 1234567890`

### Additional Properties Not Allowed

```
Additional properties are not allowed ('unknown_field' was unexpected)
```

**Fix**: Remove the field or check spelling

## Files

- **validate-schema.py**: Standalone schema validator script (305 lines)
- **Makefile**: Build targets for schema validation
- **test-config-parser.c**: Enhanced with schema validation integration
- **SCHEMA_VALIDATOR_README.md**: This documentation

## See Also

- [TEST_CONFIG_README.md](TEST_CONFIG_README.md) - Configuration parser testing guide
- [ucentral.schema.pretty.json](../../config-samples/ucentral.schema.pretty.json) - Official uCentral schema

## License

BSD-3-Clause
