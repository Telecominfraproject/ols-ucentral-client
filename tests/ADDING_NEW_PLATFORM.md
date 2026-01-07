# Adding New Platform to Test Framework

This document explains how to add support for a new platform to the configuration testing framework.

## Overview

The test framework supports two modes:
- **Stub mode**: Fast testing with simple stubs (no platform code)
- **Platform mode**: Integration testing with real platform implementation

To add a new platform, you need to:
1. Implement the platform in `src/ucentral-client/platform/your-platform/`
2. Create platform mocks in `tests/config-parser/platform-mocks/your-platform.c`
3. Test the integration

## What Gets Tested vs Mocked

### ✅ Your Platform Code is TESTED
When you add platform support, these parts of your code are **fully tested**:
- `plat_config_apply()` - Main configuration application function
- All `config_*_apply()` functions - VLAN, port, STP, etc.
- Configuration parsing and validation logic
- Business rules and error handling
- All the code in `platform/your-platform/*.c`

### ❌ Only Hardware Interface is MOCKED
Only the lowest-level hardware abstraction layer is mocked:
- gNMI/gNOI calls (for SONiC-based platforms)
- REST API calls (if your platform uses REST)
- System calls (ioctl, sysfs, etc.)
- Hardware driver calls

**Important**: You're testing real platform code, just not sending commands to actual hardware.

## Prerequisites

Your platform must:
- Implement `plat_config_apply()` in `platform/your-platform/`
- Build a `plat.a` static library
- Follow the platform interface defined in `include/ucentral-platform.h`

## Step-by-Step Guide

### Step 1: Verify Platform Implementation

Ensure your platform builds successfully:

```bash
cd src/ucentral-client/platform/your-platform
make clean
make
ls -la plat.a  # Should exist
```

### Step 2: Create Platform Mock File

Create a mock file for your platform's hardware abstraction layer:

```bash
cd tests/config-parser/platform-mocks
cp example-platform.c your-platform.c
```

Edit `your-platform.c` and add mock implementations for your platform's HAL functions.

**Strategy:**
1. Start with empty file (just includes)
2. Try to build: `make clean && make test-config-parser USE_PLATFORM=your-platform`
3. For each "undefined reference" error, add a mock function
4. Repeat until it links successfully

**Example mock function:**

```c
/* Mock your platform's port configuration function */
int your_platform_port_set(int port_id, int speed, int duplex)
{
    fprintf(stderr, "[MOCK:your-platform] port_set(port=%d, speed=%d, duplex=%d)\n",
            port_id, speed, duplex);
    return 0;  /* Success */
}
```

### Step 3: Test Your Platform Integration

```bash
cd tests/config-parser

# Try to build
make clean
make test-config-parser USE_PLATFORM=your-platform

# If build fails, check for:
# - Missing mock functions (add to your-platform.c)
# - Missing includes (add to Makefile PLAT_INCLUDES)
# - Missing libraries (add to Makefile PLAT_LDFLAGS)

# When build succeeds, run tests
make test-config-full USE_PLATFORM=your-platform
```

### Step 4: Verify Test Results

Your tests should:
- ✓ Parse configurations successfully
- ✓ Call `plat_config_apply()` from your platform
- ✓ Exercise your platform's configuration logic
- ✓ Report apply success/failure correctly

Check test output for:
```
[TEST] cfg0.json
  ✓ SCHEMA: Valid
  ✓ PARSER: Success
  ✓ APPLY: Success
```

### Step 5: Add Platform-Specific Test Configurations

Create test configurations that exercise your platform's specific features:

```bash
cd config-samples
vim cfg_your_platform_feature.json
```

Run tests to verify:
```bash
cd tests/config-parser
make test-config-full USE_PLATFORM=your-platform
```

## Platform Mock Guidelines

### What to Mock

Mock your platform's **hardware abstraction layer** (HAL) functions - the lowest-level functions that would normally talk to hardware or external services.

**Examples:**
- gNMI/gNOI calls (brcm-sonic platform)
- REST API calls (if your platform uses REST)
- System calls (ioctl, sysfs access, etc.)
- Hardware driver calls

### What NOT to Mock

Don't mock your platform's **configuration logic** - that's what we're testing!

**Don't mock:**
- `plat_config_apply()` - This is the function under test
- `config_vlan_apply()`, `config_port_apply()`, etc. - Platform logic
- Validation functions - These should run normally

### Mock Strategies

#### Strategy 1: Success Stubs (Simple)
Return success for all operations, no state tracking.

```c
int platform_hal_function(...)
{
    fprintf(stderr, "[MOCK] platform_hal_function(...)\n");
    return 0;  /* Success */
}
```

**Pros:** Simple, fast to implement
**Cons:** Doesn't catch validation errors in platform code
**Use when:** Getting started, CI/CD

#### Strategy 2: Validation Mocks (Moderate)
Check parameters, return errors for invalid inputs.

```c
int platform_hal_port_set(int port_id, int speed)
{
    fprintf(stderr, "[MOCK] platform_hal_port_set(port=%d, speed=%d)\n",
            port_id, speed);

    /* Validate parameters */
    if (port_id < 0 || port_id >= MAX_PORTS) {
        fprintf(stderr, "[MOCK] ERROR: Invalid port ID\n");
        return -1;  /* Error */
    }

    if (speed != 100 && speed != 1000 && speed != 10000) {
        fprintf(stderr, "[MOCK] ERROR: Invalid speed\n");
        return -1;  /* Error */
    }

    return 0;  /* Success */
}
```

**Pros:** Catches some validation bugs
**Cons:** More code to maintain
**Use when:** Pre-release testing, debugging

#### Strategy 3: Stateful Mocks (Complex)
Track configuration state, simulate hardware behavior.

```c
/* Mock hardware state */
static struct {
    int port_speed[MAX_PORTS];
    bool port_enabled[MAX_PORTS];
} mock_hw_state = {0};

int platform_hal_port_set(int port_id, int speed)
{
    fprintf(stderr, "[MOCK] platform_hal_port_set(port=%d, speed=%d)\n",
            port_id, speed);

    /* Validate */
    if (port_id < 0 || port_id >= MAX_PORTS)
        return -1;

    /* Update mock state */
    mock_hw_state.port_speed[port_id] = speed;

    return 0;
}

int platform_hal_port_get(int port_id, int *speed)
{
    if (port_id < 0 || port_id >= MAX_PORTS)
        return -1;

    /* Return mock state */
    *speed = mock_hw_state.port_speed[port_id];

    return 0;
}
```

**Pros:** Full platform behavior simulation
**Cons:** Significant effort, complex maintenance
**Use when:** Comprehensive integration testing

## Troubleshooting

### Build Errors

**Problem:** `undefined reference to 'some_function'`
**Solution:** Add mock implementation to `platform-mocks/your-platform.c`

**Problem:** `fatal error: your_platform.h: No such file or directory`
**Solution:** Add include path to Makefile `PLAT_INCLUDES`

If your platform has additional include directories, update the Makefile:
```makefile
# In tests/config-parser/Makefile, update the platform mode section:
PLAT_INCLUDES = -I $(PLAT_DIR) -I $(PLAT_DIR)/your_extra_dir
```

**Problem:** `undefined reference to 'pthread_create'` (or other library)
**Solution:** Add library to Makefile `PLAT_LDFLAGS`

If your platform needs additional libraries, update the Makefile:
```makefile
# In tests/config-parser/Makefile, update the platform mode section:
PLAT_LDFLAGS = -lgrpc++ -lprotobuf -lyour_library
```

### Runtime Errors

**Problem:** Segmentation fault in platform code
**Solution:** Check mock functions return valid pointers, not NULL

**Problem:** Tests always pass even with bad configurations
**Solution:** Your mocks might be too simple - add validation logic

**Problem:** Tests fail but should pass
**Solution:** Check if mock functions are returning correct values

## Example: Adding Your Platform

Let's walk through adding support for your platform (we'll use "myvendor" as an example):

### 1. Check platform exists

```bash
$ ls src/ucentral-client/platform/
brcm-sonic/  example-platform/  myvendor/
```

Platform exists. Good!

### 2. Create mock file

```bash
$ cd tests/config-parser/platform-mocks
$ touch myvendor.c
```

### 3. Try building (will fail with undefined references)

```bash
$ cd ..
$ make clean
$ make test-config-parser USE_PLATFORM=myvendor
...
undefined reference to `myvendor_port_config_set'
undefined reference to `myvendor_vlan_create'
...
```

### 4. Add mocks iteratively

Edit `platform-mocks/myvendor.c`:

```c
/* platform-mocks/myvendor.c */
#include <stdio.h>

int myvendor_port_config_set(int port, int speed, int duplex)
{
    fprintf(stderr, "[MOCK:myvendor] port_config_set(%d, %d, %d)\n",
            port, speed, duplex);
    return 0;
}

int myvendor_vlan_create(int vlan_id)
{
    fprintf(stderr, "[MOCK:myvendor] vlan_create(%d)\n", vlan_id);
    return 0;
}

/* Add more as linker reports undefined references */
```

### 5. Build until successful

```bash
$ make clean
$ make test-config-parser USE_PLATFORM=myvendor
# Add more mocks for any remaining undefined references
# Repeat until build succeeds
```

### 6. Run tests

```bash
$ make test-config-full USE_PLATFORM=myvendor
========= running schema validation  =========
[SCHEMA] cfg0.json: VALID
...
========= running config parser tests  =========
Mode: platform
Platform: myvendor
================================================
[TEST] cfg0.json
  [MOCK:myvendor] port_config_set(1, 1000, 1)
  [MOCK:myvendor] vlan_create(100)
  ✓ SCHEMA: Valid
  ✓ PARSER: Success
  ✓ APPLY: Success
...
Total tests: 25
Passed: 25
Failed: 0
```

Success! Your platform is now integrated into the test framework.

## Property Database

### Overview

The testing framework uses property databases to track where configuration properties are parsed in the codebase. This enables detailed test reports showing the exact source location (file, function, line number) for each property.

Property tracking uses **separate databases**:
- **Base database** (`property-database-base.c`): Tracks properties parsed in proto.c
- **Platform database** (`property-database-platform-PLATFORM.c`): Tracks platform-specific properties

### Database Architecture

**Stub mode (no platform):**
- Only uses `base_property_database` from property-database-base.c
- Shows proto.c source locations in test reports

**Platform mode (with USE_PLATFORM):**
- Uses both `base_property_database` AND `platform_property_database_PLATFORM`
- Shows both proto.c and platform source locations in test reports

### When to Regenerate Property Databases

**Regenerate base database if you:**
- Modified proto.c parsing code
- Added vendor-specific #ifdef code to proto.c
- Line numbers changed significantly
- Want updated line numbers in test reports

**Regenerate platform database when:**
- Modified platform parsing code (plat-*.c)
- Added new configuration features to platform
- Want updated line numbers in test reports

### How to Regenerate Databases

```bash
# Regenerate base database (if you modified proto.c)
cd tests/config-parser
make regenerate-property-db

# Regenerate platform database (requires USE_PLATFORM)
make regenerate-platform-property-db USE_PLATFORM=myvendor
```

**What happens:**
- Base: Extracts properties from proto.c and finds line numbers
- Platform: Extracts properties from platform/myvendor/plat-*.c and finds line numbers
- Generated database files are C arrays included by test-config-parser.c

### Test Reports with Property Tracking

**Stub mode shows only proto.c properties:**
```
✓ Successfully Configured: 3 properties
   - ethernet[0].speed = 1000 [proto.c:cfg_ethernet_parse():line 1119]
   - ethernet[0].duplex = "full" [proto.c:cfg_ethernet_parse():line 1120]
   - ethernet[0].enabled = false [proto.c:cfg_ethernet_parse():line 1119]
```

**Platform mode shows both proto.c AND platform properties:**
```
✓ Successfully Configured: 3 properties (proto.c)
   - ethernet[0].speed = 1000 [proto.c:cfg_ethernet_parse():line 1119]
   - ethernet[0].duplex = "full" [proto.c:cfg_ethernet_parse():line 1120]

✓ Platform Applied: 2 properties (platform/myvendor)
   - ethernet[0].lldp.enabled [platform/myvendor/plat-config.c:config_lldp_apply():line 1234]
   - ethernet[0].lacp.mode [platform/myvendor/plat-config.c:config_lacp_apply():line 567]
```

### Property Database Template Structure

Property databases are C arrays with this structure:

```c
static const struct property_metadata base_property_database[] = {
    {"ethernet[].speed", PROP_CONFIGURED, "proto.c", "cfg_ethernet_parse", 1119, ""},
    {"ethernet[].duplex", PROP_CONFIGURED, "proto.c", "cfg_ethernet_parse", 1120, ""},
    // ... more entries ...
    {NULL, 0, NULL, NULL, 0, NULL}  /* Terminator */
};
```

Each entry maps:
- JSON property path → Source file → Parser function → Line number

### Vendor Modifications to proto.c

**Important for vendors:** If your platform adds #ifdef code to proto.c:

```c
/* In proto.c - vendor-specific code */
#ifdef VENDOR_MYVENDOR
    /* Parse vendor-specific property */
    if (cJSON_HasObjectItem(obj, "my-vendor-feature")) {
        cfg->vendor_feature = cJSON_GetNumber...
    }
#endif
```

You should regenerate the base property database in your repository:

```bash
cd tests/config-parser
make regenerate-property-db
```

This captures your proto.c modifications in the base database, ensuring accurate test reports showing your vendor-specific parsing code.

## Testing Workflow

### Development Workflow (Fast Iteration)

```bash
# Use stub mode for quick testing during development
make test-config-full

# Fast, no platform dependencies
# Edit code → test → repeat
```

### Pre-Release Workflow (Comprehensive Testing)

```bash
# Use platform mode for integration testing before release
make test-config-full USE_PLATFORM=your-platform

# Slower, but exercises real platform code
# Catches platform-specific bugs
```

### CI/CD Workflow (Automated)

```yaml
# .gitlab-ci.yml or similar

test-parser:
  script:
    - cd tests/config-parser
    - make test-config-full  # Stub mode for speed

test-platform:
  script:
    - cd tests/config-parser
    - make test-config-full USE_PLATFORM=brcm-sonic
  allow_failure: true  # Platform mode may need special environment
```

## Advanced: Platform-Specific Makefile Configuration

If your platform needs special build configuration, you can add conditional logic to the Makefile:

```makefile
# In tests/config-parser/Makefile, in the platform mode section:

ifeq ($(PLATFORM_NAME),your-platform)
    # Add your-platform specific includes
    PLAT_INCLUDES += -I $(PLAT_DIR)/special_dir
    # Add your-platform specific libraries
    PLAT_LDFLAGS += -lyour_special_lib
endif
```

## Summary Checklist

Before considering your platform integration complete:

- [ ] Platform implementation exists in `platform/your-platform/`
- [ ] Platform builds successfully and produces `plat.a`
- [ ] Created `platform-mocks/your-platform.c` with mock HAL functions
- [ ] Build succeeds: `make test-config-parser USE_PLATFORM=your-platform`
- [ ] Tests run: `make test-config-full USE_PLATFORM=your-platform`
- [ ] All existing test configs pass (or expected failures documented)
- [ ] Generated platform property database: `make regenerate-platform-property-db USE_PLATFORM=your-platform`
- [ ] Test reports show platform source locations (file, function, line number)
- [ ] If modified proto.c with #ifdef, regenerated base database: `make regenerate-property-db`
- [ ] Added platform-specific test configurations (optional)
- [ ] Documented platform-specific requirements (optional)
- [ ] Tested in Docker environment (if applicable)

## Getting Help

- **Build issues**: Check Makefile configuration and include paths
- **Link issues**: Add missing mock functions to platform mock file
- **Runtime issues**: Check mock function return values and pointers
- **Test failures**: Verify platform code validation logic

For more help, see:
- `tests/config-parser/TEST_CONFIG_README.md` - Test framework documentation
- `TESTING_FRAMEWORK.md` - Overall testing architecture
- `platform/example-platform/` - Platform implementation template
- `tests/config-parser/platform-mocks/README.md` - Mock implementation guide

## FAQ

**Q: Why do I need to create mocks? Can't the test just call the platform code directly?**
A: The platform code calls hardware abstraction functions (like gNMI APIs). Those functions need hardware or external services. Mocks let us test the platform logic without requiring actual hardware.

**Q: How do I know which functions to mock?**
A: Try building - the linker will tell you with "undefined reference" errors. Mock those functions.

**Q: Can I reuse mocks from another platform?**
A: Not usually - each platform has its own HAL. But you can use another platform's mock file as a reference for structure.

**Q: Do I need to mock every function perfectly?**
A: No! Start with simple success stubs (return 0). Add validation later if needed.

**Q: My platform doesn't use gNMI. Can I still add it?**
A: Yes! Mock whatever your platform uses (REST API, system calls, etc.). The same principles apply.

**Q: The tests pass but I want more validation. What should I do?**
A: Add validation logic to your mock functions (Strategy 2 or 3 above). Check parameters and return errors for invalid inputs.

**Q: Can I test multiple platforms in the same test run?**
A: Not currently. Run separate test commands for each platform: `make test-config-full USE_PLATFORM=platform1` then `make test-config-full USE_PLATFORM=platform2`
