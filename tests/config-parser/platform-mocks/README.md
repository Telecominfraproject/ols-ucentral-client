# Platform Mocks Directory

This directory contains mock implementations of platform-specific hardware abstraction layers (HAL) for integration testing.

## Purpose

Platform mocks allow the test framework to link against real platform implementation code without requiring actual hardware or external services (like gNMI servers). This enables:

- **Integration testing** - Test real platform code paths
- **Development** - Test platform changes without hardware
- **CI/CD** - Run comprehensive tests in automated pipelines

## What Gets Tested vs Mocked

### ✅ TESTED (Real Production Code)
- All platform implementation code in `src/ucentral-client/platform/`
- `plat_config_apply()` and all `config_*_apply()` functions
- Configuration parsing and validation logic
- Business rules and error handling
- Everything except the hardware interface calls

### ❌ MOCKED (Hardware Interface)
- Lowest-level HAL functions (gNMI, REST, system calls)
- Functions that would talk to actual hardware
- External service calls (gNMI server, etc.)

**Example:** When testing brcm-sonic platform, `config_vlan_apply()` runs real code, but `gnma_vlan_create()` is mocked.

## Available Platform Mocks

| File | Platform | Description |
|------|----------|-------------|
| `brcm-sonic.c` | Broadcom SONiC | Mocks for gNMI/gNOI APIs |
| `example-platform.c` | Template | Template for creating new platform mocks |

## How to Use

### Using Existing Platform Mocks

```bash
cd tests/config-parser

# Run tests with brcm-sonic platform
make test-config-full USE_PLATFORM=brcm-sonic
```

### Creating Platform Mocks for a New Platform

See `../ADDING_NEW_PLATFORM.md` for complete documentation.

**Quick steps:**

1. Copy the template:
   ```bash
   cp example-platform.c your-platform.c
   ```

2. Try building (will fail):
   ```bash
   make clean
   make test-config-parser USE_PLATFORM=your-platform
   ```

3. Add mock functions for each "undefined reference" error

4. Repeat until it builds successfully

## Mock Strategy

### What to Mock

Mock the **lowest-level HAL functions** that would normally interact with hardware or external services:

- gNMI/gNOI calls (brcm-sonic)
- REST API calls
- System calls (ioctl, sysfs, etc.)
- Hardware driver calls

### What NOT to Mock

Don't mock the platform's **configuration logic** - that's what we're testing!

- ❌ Don't mock: `plat_config_apply()`
- ❌ Don't mock: `config_vlan_apply()`, `config_port_apply()`, etc.
- ✅ Do mock: `gnma_vlan_create()`, `gnma_port_speed_set()`, etc.

### Mock Patterns

**Pattern 1: Simple Success Stub**
```c
int hal_function(...)
{
    fprintf(stderr, "[MOCK:platform] hal_function(...)\n");
    return 0;  /* Success */
}
```

**Pattern 2: With Parameter Logging**
```c
int hal_port_set(int port, int speed)
{
    fprintf(stderr, "[MOCK:platform] hal_port_set(port=%d, speed=%d)\n",
            port, speed);
    return 0;
}
```

**Pattern 3: With Validation**
```c
int hal_port_set(int port, int speed)
{
    fprintf(stderr, "[MOCK:platform] hal_port_set(port=%d, speed=%d)\n",
            port, speed);

    if (port < 0 || port >= MAX_PORTS) {
        fprintf(stderr, "[MOCK:platform] ERROR: Invalid port\n");
        return -1;  /* Error */
    }

    return 0;  /* Success */
}
```

## Tips

- **Start simple**: Return success for everything
- **Add logging**: Use `fprintf(stderr, ...)` to see what's called
- **Iterate**: Build, check for undefined references, add mocks, repeat
- **Test frequently**: Run tests after adding each mock function
- **Reference existing mocks**: Look at `brcm-sonic.c` for examples

## Troubleshooting

**Problem**: Undefined reference errors
**Solution**: Add mock functions for the missing symbols

**Problem**: Tests crash with segfault
**Solution**: Check that mock functions return valid values/pointers

**Problem**: Tests always pass
**Solution**: Your mocks might be too simple - consider adding validation logic

## See Also

- `../ADDING_NEW_PLATFORM.md` - Complete guide for adding platform support
- `../TEST_CONFIG_README.md` - Testing framework documentation
- `../../TESTING_FRAMEWORK.md` - Overall testing architecture
