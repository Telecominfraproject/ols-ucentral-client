# Configuration Testing Framework Maintenance Guide

This document provides procedures for maintaining the configuration testing framework as the software evolves.

## Overview

**Current Approach (December 2024): Schema-Based Property Database Generation**

The framework uses the **uCentral schema as the single source of truth** for property databases. This ensures complete coverage of all 398 schema properties, whether implemented or not.

### Key Components

1. **Schema Files** - JSON/YAML schema definitions from ols-ucentral-schema repository
2. **Property Databases** - Generated from schema, tracking implementation status:
   - `property-database-base.c` - Proto.c parsing (102 found, 296 not implemented)
   - `property-database-platform-brcm-sonic.c` - Platform application (141 found, 257 not implemented)

### Schema-Based Workflow

```
ols-ucentral-schema (YAML)
    ↓
fetch-schema.sh → ols-ucentral-schema/
    ↓
extract-schema-properties.py → 398 properties
    ↓
generate-database-from-schema.py → base database
generate-platform-database-from-schema.py → platform database
    ↓
Property databases with line numbers
```

## Table of Contents

- [Quick Start: Schema-Based Regeneration](#quick-start-schema-based-regeneration)
- [Schema Update Procedures](#schema-update-procedures)
- [Property Database Regeneration](#property-database-regeneration)
- [Adding New Parser Functions](#adding-new-parser-functions)
- [Platform-Specific Updates](#platform-specific-updates)
- [Version Synchronization](#version-synchronization)
- [Testing After Updates](#testing-after-updates)
- [Troubleshooting](#troubleshooting)
- [Legacy Approach](#legacy-approach)

---

## Quick Start: Schema-Based Regeneration

**This repository includes default schema files in `config-samples/`**, so you can regenerate property databases immediately without fetching external repositories.

**Complete regeneration of both property databases from scratch:**

```bash
cd tests/tools

# 1. Obtain schema (use included version OR fetch newer version)
# Option A: Use included schema (recommended for most cases)
SCHEMA_SOURCE="../../config-samples/ucentral.schema.pretty.json"

# Option B: Fetch newer schema if needed (optional)
# ./fetch-schema.sh main
# SCHEMA_SOURCE="../../ols-ucentral-schema/schema"

# 2. Extract all properties from schema
# For JSON schema file:
python3 -c "import json; print('\n'.join(sorted(set(
    k for d in json.load(open('$SCHEMA_SOURCE'))['properties'].values()
    for k in d.get('properties', {}).keys()
))))" | sed 's/\[\]$//' > /tmp/all-schema-properties.txt

# For YAML schema directory (if using ols-ucentral-schema repo):
# python3 extract-schema-properties.py ../../ols-ucentral-schema/schema ucentral.yml \
#     2>/dev/null | sed 's/\[\]$//' > /tmp/all-schema-properties.txt

# 3. Generate base database (proto.c)
python3 generate-database-from-schema.py \
    ../../src/ucentral-client/proto.c \
    /tmp/all-schema-properties.txt \
    /tmp/base-database-new.c

# 4. Fix array name
sed -i '' 's/property_database\[\]/base_property_database[]/' \
    /tmp/base-database-new.c

# 5. Generate platform database (plat-gnma.c)
python3 generate-platform-database-from-schema.py \
    ../../src/ucentral-client/platform/brcm-sonic/plat-gnma.c \
    /tmp/all-schema-properties.txt \
    /tmp/platform-database-new.c

# 6. Install new databases
cp /tmp/base-database-new.c ../config-parser/property-database-base.c
cp /tmp/platform-database-new.c ../config-parser/property-database-platform-brcm-sonic.c

# 7. Test in Docker
docker exec ucentral_client_build_env bash -c \
    "cd /root/ols-nos/tests/config-parser && make clean && make test-config-full"
```

**Result:** Both databases regenerated with all schema properties, showing which are implemented (with line numbers) and which are not (line_number=0).

---

## Property Database Regeneration

### When to Regenerate

Regenerate property databases when:
- **New parser functions added** to proto.c or platform code
- **Schema updated** with new properties
- **Parser functions renamed or refactored**
- **Starting fresh** after major refactoring
- **Periodic audit** (quarterly recommended)

### Why Schema-Based?

1. **Complete Coverage** - Tracks ALL 398 schema properties
2. **Single Source of Truth** - Schema defines what's possible
3. **Shows Gaps** - Properties with line_number=0 are not yet implemented
4. **Consistent** - Same properties across all platforms
5. **Maintainable** - Automatic updates when schema changes

### Base Database Generation

Generates `property-database-base.c` from proto.c:

```bash
cd tests/tools

# Extract schema properties from included JSON file (strip trailing [])
python3 -c "import json; print('\n'.join(sorted(set(
    k for d in json.load(open('../../config-samples/ucentral.schema.pretty.json'))['properties'].values()
    for k in d.get('properties', {}).keys()
))))" | sed 's/\[\]$//' > /tmp/schema-props.txt

# OR if using YAML from ols-ucentral-schema repository:
# python3 extract-schema-properties.py \
#     ../../ols-ucentral-schema/schema ucentral.yml 2>/dev/null | \
#     sed 's/\[\]$//' > /tmp/schema-props.txt

# Generate database
python3 generate-database-from-schema.py \
    ../../src/ucentral-client/proto.c \
    /tmp/schema-props.txt \
    /tmp/base-db.c

# Fix array name and install
sed -i '' 's/property_database\[\]/base_property_database[]/' /tmp/base-db.c
cp /tmp/base-db.c ../config-parser/property-database-base.c
```

**What it does:**
- Searches proto.c for cJSON property access patterns
- Finds line numbers where each property is parsed
- Marks unimplemented properties with line_number=0
- Generates complete C array with all schema properties

### Platform Database Generation

Generates `property-database-platform-*.c` from platform code:

```bash
cd tests/tools

# Generate platform database (brcm-sonic example)
python3 generate-platform-database-from-schema.py \
    ../../src/ucentral-client/platform/brcm-sonic/plat-gnma.c \
    /tmp/schema-props.txt \
    /tmp/platform-db.c

cp /tmp/platform-db.c ../config-parser/property-database-platform-brcm-sonic.c
```

**What it does:**
- Analyzes platform code for config_*_apply() functions
- Maps properties to platform functions by feature area
- Platform code doesn't parse JSON directly
- Uses feature-based matching (poe → config_poe_port_apply)

---

## Adding New Parser Functions

When you add a new parser function to proto.c:

```c
// Example: New parser function
static int cfg_new_feature_parse(cJSON *obj, struct plat_cfg *cfg) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, "new-property");
    // ...parse new-property...
}
```

**Steps:**

1. **Implement the parser** in proto.c
2. **Regenerate database** using schema-based approach (see Quick Start)
3. **Verify** the new property appears with correct line number:
   ```bash
   grep "new-property" tests/config-parser/property-database-base.c
   # Should show: {"path.to.new-property", PROP_CONFIGURED, "proto.c", "cfg_new_feature_parse", LINE, "..."}
   ```
4. **Test** with a config containing the new property
5. **Commit** proto.c changes and regenerated database together

---

## Platform-Specific Updates

Platform vendors (Edgecore, Dell, etc.) maintain their own platform databases.

### For Platform Developers

When adding platform-specific features:

```bash
cd tests/tools

# Regenerate YOUR platform database
python3 generate-platform-database-from-schema.py \
    ../../src/ucentral-client/platform/YOUR-PLATFORM/plat-YOUR.c \
    /tmp/schema-props.txt \
    /tmp/platform-db-YOUR.c

# Install it
cp /tmp/platform-db-YOUR.c ../config-parser/property-database-platform-YOUR.c
```

**Note:** Each platform tracks only its own implementation. Properties showing as "Unknown" in base repo may be "CONFIGURED" in your platform.

---

## Schema Update Procedures

### Included Schema File

This repository includes a default schema file in `config-samples/`:
- `ucentral.schema.pretty.json` - uCentral JSON schema (human-readable format)

This file allows immediate use of the testing framework without fetching external repositories.

### When to Update Schema

Update the schema when:
- New version of ols-ucentral-schema is released
- New configuration properties are added to the schema
- Property definitions change (type, constraints, etc.)
- Schema validation errors appear for valid configurations
- Preparing for new feature development

### Schema Update Process

#### Step 1: Identify Current Schema Version

```bash
cd /path/to/ols-ucentral-client

# Check current schema version
head -20 config-samples/ucentral.schema.pretty.json | grep -i version

# Note the current version for rollback if needed
```

#### Step 2: Obtain New Schema

**Repository Location:**
- GitHub: https://github.com/Telecominfraproject/ols-ucentral-schema
- Schema files are in the `schema/` directory (YAML format)
- Built/converted JSON schemas may be in releases or build artifacts

**Option A: Using fetch-schema.sh Helper (Recommended)**

```bash
cd tests/tools

# Fetch main branch
./fetch-schema.sh

# OR fetch specific branch
./fetch-schema.sh release-1.0

# View help
./fetch-schema.sh --help
```

The script clones the schema repository to `tests/tools/ols-ucentral-schema/`.

**Option B: Manual Git Clone**

```bash
cd tests/tools

# Clone the schema repository
git clone https://github.com/Telecominfraproject/ols-ucentral-schema.git

# Checkout specific version (recommended for stability)
cd ols-ucentral-schema
git tag -l                    # List available versions
git checkout v4.2.0           # Checkout specific version

# OR use specific branch
git checkout release-1.0
```

**Option C: Download Specific File**

If you only need the JSON schema file:
```bash
# Download directly from GitHub
cd config-samples
wget https://raw.githubusercontent.com/Telecominfraproject/ols-ucentral-schema/main/schema/ucentral.schema.json \
    -O ucentral.schema.pretty.json
```

#### Step 3: Validate Schema File

```bash
cd /path/to/ols-ucentral-client/tests/config-parser

# Verify schema is valid JSON
python3 -c "import json; json.load(open('../../config-samples/ucentral.schema.pretty.json'))"

# Test that validator can load it
python3 validate-schema.py --schema ../../config-samples/ucentral.schema.pretty.json \
    ../../config-samples/cfg0.json
```

#### Step 4: Test Against Existing Configurations

```bash
# Run schema validation on all test configs
make validate-schema

# Review results for new validation errors
```

**Expected outcomes:**
- **All valid**: Schema is backward compatible
- **Some failures**: Schema may have added requirements or changed definitions
- **Many failures**: Schema may be incompatible - review changes carefully

#### Step 5: Address Validation Failures

If existing valid configs now fail validation:

**A. Investigate Schema Changes**
```bash
# Compare old and new schema
cd config-samples
diff <(jq . ols.ucentral.schema.json.old) <(jq . ols.ucentral.schema.json) > schema-changes.diff

# Look for:
# - New required fields
# - Changed property types
# - New constraints (min/max, enums)
# - Removed properties
```

**B. Update Affected Configurations**
```bash
# For each failing config:
# 1. Review the validation error
./validate-schema.py ../../config-samples/failing-config.json

# 2. Fix the configuration to meet new requirements
vi ../../config-samples/failing-config.json

# 3. Revalidate
./validate-schema.py ../../config-samples/failing-config.json
```

**C. Document Breaking Changes**

Create or update SCHEMA_CHANGES.md:
```markdown
## Schema Update: v4.1.0 → v4.2.0

### Breaking Changes
- `unit.timezone` now required (was optional)
- `interfaces.ethernet.speed` changed from string to enum
- New required field: `switch.system-name`

### Configurations Updated
- cfg0.json - Added unit.timezone
- ECS4150-TM.json - Changed speed format
- All configs - Added switch.system-name with default value

### Migration Guide
For existing configurations:
1. Add `"timezone": "UTC"` to unit section
2. Change speed: `"1000"` → `"1G"`
3. Add `"system-name": "switch"` to switch section
```

#### Step 6: Update Schema Reference in Code

If schema location or format changed:

```bash
# Update validate-schema.py search paths if needed
vi tests/schema/validate-schema.py

# Update _find_default_schema() method:
#   script_dir / "../../config-samples/ucentral.schema.pretty.json",
#   script_dir / "../../config-samples/ols.ucentral.schema.json",
```

#### Step 7: Commit Schema Update

```bash
cd /path/to/ols-ucentral-client

# Add updated schema
git add config-samples/ols.ucentral.schema*.json

# Add any fixed configurations
git add config-samples/*.json

# Add documentation
git add src/ucentral-client/SCHEMA_CHANGES.md

# Commit with clear message
git commit -m "Update uCentral schema to v4.2.0

- Updated schema from ols-ucentral-schema v4.2.0
- Fixed 5 test configurations for new requirements
- Added timezone, updated speed enums, added system-name
- See SCHEMA_CHANGES.md for migration guide"
```

### Schema Rollback Procedure

If new schema causes major issues:

```bash
# Revert to previous schema
git checkout HEAD~1 -- config-samples/ols.ucentral.schema*.json

# Or restore from backup
cp config-samples/ucentral.schema.pretty.json.backup \
   config-samples/ucentral.schema.pretty.json

# Verify old schema works
make validate-schema
```

---

## Property Database Update Procedures

### When to Update Property Database

Update the property database when:
- New parser functions added to proto.c
- Existing parser functions modified (name change, scope change)
- Properties removed from parser implementation
- Parser refactoring changes function organization
- Adding support for new configuration features

### Property Database Update Process

#### Step 1: Identify Parser Changes

**A. New Feature Development**

If you're actively developing:
```bash
# You know what functions you added
# Example: Added cfg_port_mirroring_parse()
grep -n "cfg_port_mirroring_parse" src/ucentral-client/proto.c
```

**B. Code Update/Merge**

If updating from upstream or merging branches:
```bash
cd /path/to/ols-ucentral-client/tests/config-parser

# Compare parser functions between versions
git diff HEAD~1 proto.c | grep "^+.*cfg_.*_parse"

# List all current parser functions
grep -n "^static.*cfg_.*_parse\|^cfg_.*_parse" proto.c | awk '{print $3}' | sort
```

**C. Comprehensive Audit**

Periodically audit all functions:
```bash
# Extract all cfg_*_parse functions from proto.c
grep -o "cfg_[a-z_]*_parse" proto.c | sort -u > current-functions.txt

# Extract all parser_function references from property database
grep "parser_function" test-config-parser.c | \
    sed 's/.*"\(cfg_[^"]*\)".*/\1/' | sort -u > database-functions.txt

# Find functions in proto.c but NOT in database (missing entries)
comm -23 current-functions.txt database-functions.txt > missing-from-database.txt

# Find functions in database but NOT in proto.c (invalid entries)
comm -13 current-functions.txt database-functions.txt > invalid-in-database.txt

# Review both files
cat missing-from-database.txt
cat invalid-in-database.txt
```

#### Step 2: Remove Invalid Property Entries

For functions that no longer exist:

**A. Identify Properties to Remove**

```bash
# For each invalid function, find its properties
INVALID_FUNC="cfg_old_feature_parse"

grep -n "\"$INVALID_FUNC\"" test-config-parser.c

# This shows line numbers of all property entries using this function
```

**B. Remove Property Entries**

```python
#!/usr/bin/env python3
# remove-properties.py - Helper script to remove property entries

import sys
import re

if len(sys.argv) < 2:
    print("Usage: ./remove-properties.py <function_name>")
    sys.exit(1)

function_name = sys.argv[1]

with open('test-config-parser.c', 'r') as f:
    lines = f.readlines()

# Find and remove entries for this function
output_lines = []
skip_entry = False
brace_count = 0

for line in lines:
    # Check if this line starts a property entry with our function
    if f'parser_function = "{function_name}"' in line:
        # Find the start of this struct (previous { )
        # Mark to skip this entire entry
        skip_entry = True
        # Walk back to find the opening brace
        idx = len(output_lines) - 1
        while idx >= 0:
            if '{' in output_lines[idx]:
                output_lines = output_lines[:idx]
                break
            idx -= 1
        continue

    if skip_entry:
        if '},' in line:
            skip_entry = False
        continue

    output_lines.append(line)

with open('test-config-parser.c', 'w') as f:
    f.writelines(output_lines)

print(f"Removed entries for {function_name}")
```

**Usage:**
```bash
cd /path/to/ols-ucentral-client/tests/config-parser

# Remove entries for obsolete function
python3 remove-properties.py cfg_old_feature_parse

# Verify compilation still works
make clean
make test-config-parser
```

**Manual Removal Alternative:**

```bash
# Edit test-config-parser.c
vi test-config-parser.c

# Search for the function name: /cfg_old_feature_parse
# Delete the entire property entry (from opening { to closing },)

# Example - DELETE THIS ENTIRE BLOCK:
# {
#     .path = "some.old.property",
#     .parser_function = "cfg_old_feature_parse()",
#     .status = PROP_CONFIGURED,
#     .notes = "Old feature"
# },
```

#### Step 3: Add New Property Entries

For new parser functions:

**A. Determine What Properties the Function Handles**

```bash
# Read the function to understand what it parses
vi proto.c
# Search for: /cfg_new_feature_parse

# Look for cJSON_GetObjectItem calls to find property names
grep -A 50 "cfg_new_feature_parse" proto.c | grep "cJSON_GetObjectItem"

# Example output:
# cJSON_GetObjectItem(obj, "enabled")
# cJSON_GetObjectItem(obj, "mode")
# cJSON_GetObjectItem(obj, "timeout")
```

**B. Determine Property Paths**

Property paths follow JSON structure:
```
services.new-feature.enabled     → "services.new-feature.enabled"
interfaces.ethernet.speed        → "interfaces.ethernet.speed"
switch.spanning-tree.enabled     → "switch.spanning-tree.enabled"
```

For array items:
```
interfaces.ethernet[].name       → "interfaces.ethernet.name"
vlans[].id                       → "vlans.id"
```

**C. Add Property Entries to Database**

```bash
vi test-config-parser.c

# Find the properties[] array definition
# Add new entries in logical grouping with related properties

# Template:
# {
#     .path = "full.property.path",
#     .parser_function = "cfg_function_name()",
#     .status = PROP_CONFIGURED,
#     .notes = "Description of what this property does"
# },
```

**Example Addition:**

```c
static struct property_info properties[] = {
    // ... existing entries ...

    // Port Mirroring Configuration (NEW)
    {
        .path = "services.port-mirroring.enabled",
        .parser_function = "cfg_port_mirroring_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Enable/disable port mirroring service"
    },
    {
        .path = "services.port-mirroring.sessions",
        .parser_function = "cfg_port_mirroring_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Array of mirroring session configurations"
    },
    {
        .path = "services.port-mirroring.sessions.id",
        .parser_function = "cfg_port_mirroring_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Session identifier (1-4)"
    },
    {
        .path = "services.port-mirroring.sessions.source-ports",
        .parser_function = "cfg_port_mirroring_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Array of source port names to mirror"
    },
    {
        .path = "services.port-mirroring.sessions.destination-port",
        .parser_function = "cfg_port_mirroring_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Destination port name for mirrored traffic"
    },
    {
        .path = "services.port-mirroring.sessions.direction",
        .parser_function = "cfg_port_mirroring_parse()",
        .status = PROP_CONFIGURED,
        .notes = "Mirror direction: rx, tx, or both"
    },

    // ... rest of entries ...
};
```

**Guidelines for Property Entries:**

1. **Grouping**: Keep related properties together with a comment header
2. **Ordering**: Follow JSON structure hierarchy (parent before children)
3. **Naming**: Use exact JSON property names (hyphens, not underscores)
4. **Status**: Use PROP_CONFIGURED for actively parsed properties
5. **Notes**: Provide clear, concise description including valid values/ranges
6. **Arrays**: Use singular form without [] in path (e.g., "sessions.id" not "sessions[].id")

#### Step 4: Verify Property Database Accuracy

```bash
cd /path/to/ols-ucentral-client/tests/config-parser

# Rebuild test suite
make clean
make test-config-parser

# Run tests to see property usage report
make test-config

# Review the [PROPERTY USAGE REPORT] section
# Check for:
# - "Unknown (not in property database)" - missing entries
# - Properties with correct parser_function references
# - Properties marked as CONFIGURED that should be
```

#### Step 5: Test with Configurations Using New Properties

**A. Create Test Configuration**

```bash
cd config-samples

# Create test config demonstrating new feature
cat > test-new-feature.json <<'EOF'
{
  "uuid": 1,
  "unit": {
    "name": "test-new-feature",
    "timezone": "UTC"
  },
  "interfaces": {
    "ethernet": [
      {"name": "Ethernet0", "enabled": true}
    ]
  },
  "services": {
    "port-mirroring": {
      "enabled": true,
      "sessions": [
        {
          "id": 1,
          "source-ports": ["Ethernet0", "Ethernet1"],
          "destination-port": "Ethernet10",
          "direction": "both"
        }
      ]
    }
  }
}
EOF
```

**B. Validate Configuration**

```bash
cd /path/to/ols-ucentral-client/tests/config-parser

# Schema validation
./validate-schema.py ../../config-samples/test-new-feature.json

# Parser test
./test-config-parser ../../config-samples/test-new-feature.json

# Check property report shows properties as CONFIGURED
make test-config | grep -A 5 "port-mirroring"
```

#### Step 6: Document Property Database Changes

Create or update PROPERTY_DATABASE_CHANGES.md:

```markdown
## Property Database Update: 2025-12-12

### Added Properties
- `services.port-mirroring.*` (6 properties)
  - Parser: cfg_port_mirroring_parse()
  - Feature: Port mirroring/SPAN configuration
  - Test config: test-new-feature.json

### Removed Properties
- `services.legacy-feature.*` (4 properties)
  - Reason: cfg_legacy_feature_parse() removed in commit abc123
  - Migration: Feature deprecated, no replacement

### Modified Properties
- `switch.spanning-tree.mode`
  - Changed parser: cfg_stp_parse() → cfg_spanning_tree_parse()
  - Reason: Parser function renamed for consistency
```

#### Step 7: Commit Property Database Changes

```bash
cd /path/to/ols-ucentral-client

# Add modified test file
git add tests/config-parser/test-config-parser.c

# Add test configuration if created
git add config-samples/test-new-feature.json

# Add documentation if created
git add tests/PROPERTY_DATABASE_CHANGES.md

# Commit
git commit -m "Update property database for port mirroring feature

- Added 6 property entries for services.port-mirroring
- Properties handled by cfg_port_mirroring_parse()
- Added test-new-feature.json demonstrating configuration
- All tests passing"
```

### Property Database Maintenance Best Practices

1. **Update Immediately**: When adding new parser functions, add property entries immediately
2. **Remove Promptly**: When removing parser functions, clean up property entries in same commit
3. **Test Always**: Run full test suite after any property database changes
4. **Document Changes**: Maintain changelog of database modifications
5. **Review Periodically**: Audit database accuracy quarterly or after major updates
6. **Platform Sync**: If porting to platform repos, document platform-specific additions

---

## Version Synchronization

### Keeping Schema and Property Database in Sync

The schema and property database serve different but complementary purposes:

**Schema** - Defines what's structurally valid
**Property Database** - Tracks what's actually implemented

### Version Compatibility Matrix

Maintain a compatibility matrix:

```markdown
## Version Compatibility

| Client Version | Schema Version | Property Count | Notes |
|----------------|----------------|----------------|-------|
| 1.0.0          | v4.0.0         | 420            | Initial release |
| 1.1.0          | v4.1.0         | 450            | Added STP, IGMP |
| 1.2.0          | v4.1.0         | 465            | Added PoE, 802.1X |
| 2.0.0          | v4.2.0         | 510            | Major feature update |
```

### Update Coordination

When updating both schema and property database:

1. **Schema First**: Update schema, verify existing configs
2. **Implement Features**: Add parser functions for new schema properties
3. **Update Database**: Add property entries for new implementations
4. **Test Thoroughly**: Run complete test suite
5. **Document Together**: Update documentation explaining the changes

### Tracking Implementation Status

Use property reports to track implementation progress:

```bash
# Generate property usage report
make test-config > report.txt

# Count properties by status
grep "Status: CONFIGURED" report.txt | wc -l
grep "Status: Unknown" report.txt | wc -l

# Identify unimplemented schema properties
grep "Unknown (not in property database)" report.txt
```

---

## Testing After Updates

### Complete Test Sequence

After updating schema or property database:

```bash
cd /path/to/ols-ucentral-client

# 1. Clean build
cd tests/config-parser
make clean

# 2. Rebuild test tools
make test-config-parser

# 3. Validate schema file
python3 -c "import json; json.load(open('../../config-samples/ucentral.schema.pretty.json'))"

# 4. Run schema validation
make validate-schema

# 5. Run parser tests
make test-config

# 6. Run full test suite
make test-config-full

# 7. Review property usage report
make test-config | grep -A 100 "PROPERTY USAGE REPORT"
```

### Validation Checklist

- [ ] Schema file is valid JSON
- [ ] Schema validator loads successfully
- [ ] All positive test configs pass schema validation
- [ ] All negative test configs fail schema validation (expected)
- [ ] All positive test configs pass parser tests
- [ ] Property database has no references to non-existent functions
- [ ] New properties appear in usage report with correct status
- [ ] No unexpected "Unknown" properties for implemented features
- [ ] Test results match expectations (pass/fail counts)
- [ ] No memory leaks (valgrind if available)

### Regression Testing

Keep baseline test results:

```bash
# Save baseline before changes
make test-config-full > test-results-baseline.txt

# After changes, compare
make test-config-full > test-results-new.txt
diff test-results-baseline.txt test-results-new.txt

# Expected differences:
# - New properties in usage report
# - Updated parser function references
# - New test configs results

# Unexpected differences:
# - Previously passing tests now fail
# - Properties changing status unexpectedly
# - Parser errors on existing configs
```

---

## Troubleshooting

### Schema Update Issues

**Issue: Schema validation fails for all configs**

Possible causes:
- Schema file is corrupted or invalid JSON
- Schema path incorrect in validate-schema.py
- Schema format changed (Draft-7 vs Draft-4)

Resolution:
```bash
# Verify schema is valid JSON
python3 -m json.tool config-samples/ucentral.schema.pretty.json > /dev/null

# Check schema path detection
python3 validate-schema.py --schema ../../config-samples/ucentral.schema.pretty.json \
    ../../config-samples/cfg0.json

# Compare schema $schema property
grep '$schema' config-samples/ucentral.schema.pretty.json
```

**Issue: New schema rejects previously valid configs**

Possible causes:
- Schema added new required fields
- Schema changed property types
- Schema added constraints (min/max, enums)

Resolution:
```bash
# Get detailed error
./validate-schema.py ../../config-samples/failing-config.json

# Compare schemas to find changes
diff old-schema.json new-schema.json

# Update configs to meet new requirements
```

### Property Database Issues

**Issue: Compilation fails after property database update**

Possible causes:
- Syntax error in property entry (missing comma, quote)
- Invalid struct member
- Property array not properly terminated

Resolution:
```bash
# Check compilation error message
make test-config-parser 2>&1 | head -20

# Common fixes:
# - Add missing comma after previous entry
# - Ensure notes string has closing quote
# - Check .path, .parser_function, .status, .notes are all present
```

**Issue: Tests fail after property database update**

Possible causes:
- Removed properties still referenced elsewhere
- Added properties with wrong parser function
- Property paths don't match JSON structure

Resolution:
```bash
# Run specific config test
./test-config-parser ../../config-samples/failing-config.json

# Check property usage report
make test-config | grep -A 10 "property-name"

# Verify parser function exists
grep "function_name" proto.c
```

**Issue: Properties showing as "Unknown" after adding to database**

Possible causes:
- Property path doesn't match JSON exactly
- Parser function name has typo
- Property entry not in properties[] array

Resolution:
```bash
# Check property path in JSON
cat config-samples/test-config.json | jq '.path.to.property'

# Verify parser function name exactly
grep -n "cfg_function_name" proto.c

# Ensure property entry is within properties[] array bounds
# (Check that it's before the closing }; )
```

### General Maintenance Issues

**Issue: Test results inconsistent between runs**

Possible causes:
- Configs modified between runs
- Schema file changed
- Test order dependency (should not happen)

Resolution:
```bash
# Check for uncommitted changes
git status

# Verify schema hasn't changed
git diff config-samples/ucentral.schema.pretty.json

# Run tests multiple times
for i in {1..3}; do make test-config; done
```

**Issue: Docker environment tests fail but local tests pass**

Possible causes:
- Different schema version in container
- Path differences
- Missing dependencies

Resolution:
```bash
# Check schema in container
docker exec ucentral_client_build_env bash -c \
    "cat /root/ols-nos/config-samples/ucentral.schema.pretty.json" | head -20

# Verify paths in container
docker exec ucentral_client_build_env bash -c \
    "cd /root/ols-nos/tests/config-parser && ls -la ../../config-samples/*.json"

# Rebuild container if needed
make clean
make build-host-env
```

---

## Quick Reference

### Schema Update Commands

```bash
# Check current version
head -20 config-samples/ucentral.schema.pretty.json | grep version

# Update schema
cp /path/to/new/schema.json config-samples/ucentral.schema.pretty.json

# Validate schema
python3 -m json.tool config-samples/ucentral.schema.pretty.json > /dev/null

# Test with configs
make validate-schema
```

### Property Database Commands

```bash
# List all parser functions
grep -n "^static.*cfg_.*_parse\|^cfg_.*_parse" proto.c | awk '{print $3}' | sort

# Find function in database
grep -n "function_name" test-config-parser.c

# Rebuild and test
make clean && make test-config

# View property report
make test-config | grep -A 100 "PROPERTY USAGE REPORT"
```

### Testing Commands

```bash
# Full test suite
make test-config-full

# Schema only
make validate-schema

# Parser only
make test-config

# Single config
./test-config-parser ../../config-samples/specific-config.json
```

---

## See Also

- **TEST_CONFIG_README.md** - Testing framework documentation
- **SCHEMA_VALIDATOR_README.md** - Schema validator documentation
- **proto.c** - Parser implementation
- **test-config-parser.c** - Property database location
- **ols-ucentral-schema repository** - Official schema source

## Legacy Approach

**Note:** The config-based approach described below has been superseded by the schema-based approach (see above). Legacy tools are archived in `tests/tools/legacy/`.

### Old Config-Based Method (Pre-December 2024)

The original approach extracted properties FROM configuration files:

```bash
# OLD METHOD - No longer recommended
cd tests/tools/legacy
python3 generate-property-database.py ../../config-samples/*.json > /tmp/props.txt
python3 find-property-line-numbers.py ../../src/ucentral-client/proto.c /tmp/props.txt
```

**Limitations of config-based approach:**
- Only tracked properties that appeared in test configs (628 properties)
- Missed properties defined in schema but not in configs
- No way to identify unimplemented schema properties  
- Inconsistent property paths (array indices varied)
- Required manual curation

**Migration to schema-based:**
- December 2024: Switched to schema as source of truth
- Now tracks all 398 schema properties consistently
- Shows implementation status for each property
- Fully automated regeneration

**For historical reference**, see `tests/tools/legacy/README.md`.

