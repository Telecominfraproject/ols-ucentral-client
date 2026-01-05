# Configuration Parser Test Suite Makefile
# Supports two testing modes:
#   1. Stub mode (default) - Fast testing with simple stubs
#   2. Platform mode - Integration testing with real platform code

.PHONY: test test-config validate-schema test-config-full test-config-html test-config-json test-config-junit clean config help

# Compiler flags
export CFLAGS+= -Werror -Wall -Wextra

# ============================================================================
# PLATFORM SELECTION
# ============================================================================
# USE_PLATFORM can be:
#   - Not set (default): Use stub mode
#   - "brcm-sonic": Use Broadcom SONiC platform
#   - "example-platform": Use example platform
#   - Custom platform name from platform/ directory
#
# Example usage:
#   make test-config-full                           # Stub mode
#   make test-config-full USE_PLATFORM=brcm-sonic   # Platform mode
# ============================================================================

ifdef USE_PLATFORM
    TEST_MODE = platform
    PLATFORM_NAME = $(USE_PLATFORM)
else
    TEST_MODE = stub
endif

# Paths relative to tests/config-parser/
SRC_DIR = ../../src/ucentral-client
CONFIG_SAMPLES = ../../config-samples
SCHEMA_VALIDATOR = ../schema/validate-schema.py

# Source files from production code (common to both modes)
SRC_OBJS = $(SRC_DIR)/ucentral-json-parser.o \
           $(SRC_DIR)/ucentral-log.o \
           $(SRC_DIR)/router-utils.o \
           $(SRC_DIR)/base64.o

# ============================================================================
# MODE-SPECIFIC CONFIGURATION
# ============================================================================

ifeq ($(TEST_MODE),stub)
    # Stub mode: Use simple test stubs
    PLAT_OBJS = test-stubs.o
    PLAT_INCLUDES =
    PLAT_CFLAGS =
    PLAT_LDFLAGS =
    MODE_INFO = "STUB MODE - Fast testing with simple stubs"
else
    # Platform mode: Use real platform implementation
    PLAT_DIR = $(SRC_DIR)/platform/$(PLATFORM_NAME)
    # Link only platform logic (plat-gnma.o), not full plat.a with hardware libs
    PLAT_LOGIC = $(PLAT_DIR)/plat-gnma.o
    PLAT_MOCK = platform-mock-$(PLATFORM_NAME).o
    PLAT_OBJS = $(PLAT_MOCK) $(PLAT_LOGIC)
    PLAT_INCLUDES = -I $(PLAT_DIR) -I $(PLAT_DIR)/gnma -I $(PLAT_DIR)/netlink
    # Define platform macro to enable platform property database lookup
    # Convert platform name to uppercase and replace hyphens with underscores
    # e.g., brcm-sonic -> USE_PLATFORM_BRCM_SONIC
    PLAT_MACRO = $(shell echo "$(PLATFORM_NAME)" | tr '[:lower:]-' '[:upper:]_')
    PLAT_CFLAGS = -DUSE_PLATFORM_$(PLAT_MACRO)
    PLAT_LDFLAGS =
    MODE_INFO = "PLATFORM MODE - Integration testing with $(PLATFORM_NAME)"
endif

# ============================================================================
# BUILD TARGETS
# ============================================================================

# Default target
all: test-config-parser

# Display current configuration
config:
	@echo "============================================"
	@echo "Test Configuration"
	@echo "============================================"
	@echo "Test mode:        $(TEST_MODE)"
ifdef USE_PLATFORM
	@echo "Platform:         $(PLATFORM_NAME)"
endif
	@echo "Platform objects: $(PLAT_OBJS)"
	@echo "Info:             $(MODE_INFO)"
	@echo "============================================"

# Build test files with TEST_STATIC to expose cfg_parse() for testing
test-config-parser.o: test-config-parser.c
	gcc -c -o $@ ${CFLAGS} -DUCENTRAL_TESTING $(PLAT_CFLAGS) $(PLAT_INCLUDES) \
	    -I $(SRC_DIR) -I $(SRC_DIR)/include -I ./ $<

proto-test.o: $(SRC_DIR)/proto.c
	gcc -c -o $@ ${CFLAGS} -DUCENTRAL_TESTING \
	    -I $(SRC_DIR) -I $(SRC_DIR)/include $<

# Stub mode: build test-stubs.o
test-stubs.o: test-stubs.c
	gcc -c -o $@ ${CFLAGS} -DUCENTRAL_TESTING \
	    -I $(SRC_DIR) -I $(SRC_DIR)/include $<

# Platform mode: build platform-specific mock
platform-mock-%.o: platform-mocks/%.c
	@if [ ! -f platform-mocks/$*.c ]; then \
		echo "ERROR: Platform mock file platform-mocks/$*.c not found"; \
		echo "Please create platform-mocks/$*.c with required mock functions"; \
		echo "See tests/ADDING_NEW_PLATFORM.md for guidance"; \
		exit 1; \
	fi
	gcc -c -o $@ ${CFLAGS} $(PLAT_INCLUDES) \
	    -I $(SRC_DIR) -I $(SRC_DIR)/include $<

# Platform mode: build platform logic object if needed
$(PLAT_LOGIC):
	@echo "Building platform logic: $(PLATFORM_NAME)"
	@if [ ! -d $(PLAT_DIR) ]; then \
		echo "ERROR: Platform directory $(PLAT_DIR) not found"; \
		echo "Available platforms:"; \
		ls -1 $(SRC_DIR)/platform/; \
		exit 1; \
	fi
	$(MAKE) -C $(PLAT_DIR) plat-gnma.o

# Build production source files (if not already built)
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(MAKE) -C $(SRC_DIR) $*.o

# Link test binary (mode-dependent)
test-config-parser: test-config-parser.o proto-test.o $(SRC_OBJS) $(PLAT_OBJS)
	@echo "Linking test binary: $(TEST_MODE) mode"
	g++ -o $@ $^ -lcurl -lwebsockets -lcjson -lssl -lcrypto -lpthread -ljsoncpp -lresolv $(PLAT_LDFLAGS)

# ============================================================================
# TEST TARGETS
# ============================================================================

# Run configuration parser tests
test-config:
	@echo "=========================================="
	@echo "Configuration Parser Tests"
	@echo "=========================================="
	@echo "Mode:     $(TEST_MODE)"
ifdef USE_PLATFORM
	@echo "Platform: $(PLATFORM_NAME)"
endif
	@echo "=========================================="
	$(MAKE) test-config-parser
	LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser $(CONFIG_SAMPLES)
	@echo "=========================================="
	@echo "Tests completed"
	@echo "=========================================="

# Run schema validation
validate-schema:
	@echo "========= Schema Validation  ========="
	@python3 $(SCHEMA_VALIDATOR) $(CONFIG_SAMPLES) || true
	@echo "========= Schema validation completed ========"

# Combined validation: schema + parser
test-config-full: validate-schema test-config
	@echo "========= All validation completed ========"

# Generate HTML test report
test-config-html:
	@echo "========= Generating HTML test report  ========="
	$(MAKE) test-config-parser
	LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser --html $(CONFIG_SAMPLES) > test-report.html
	@echo "========= HTML report: test-report.html ========"

# Generate JSON test report
test-config-json:
	@echo "========= Generating JSON test report  ========="
	$(MAKE) test-config-parser
	LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser --json $(CONFIG_SAMPLES) > test-report.json
	@echo "========= JSON report: test-report.json ========"

# Generate JUnit XML test report
test-config-junit:
	@echo "========= Generating JUnit XML test report  ========="
	$(MAKE) test-config-parser
	LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser --junit $(CONFIG_SAMPLES) > test-report.xml
	@echo "========= JUnit XML report: test-report.xml ========"

# ============================================================================
# PROPERTY DATABASE REGENERATION
# ============================================================================

# Regenerate base property database from proto.c
.PHONY: regenerate-property-db
regenerate-property-db:
	@echo "==========================================="
	@echo "Regenerating base property database"
	@echo "==========================================="
	@echo "Source: ../../src/ucentral-client/proto.c"
	@echo "Configs: ../../config-samples/cfg*.json"
	@echo "==========================================="
	cd ../tools && python3 rebuild-property-database.py \
		../../src/ucentral-client/proto.c \
		../../config-samples/cfg*.json \
		> ../config-parser/property-database-base.c
	@echo "Base property database regenerated"
	@echo "==========================================="

# Regenerate platform-specific property database
.PHONY: regenerate-platform-property-db
ifdef USE_PLATFORM
regenerate-platform-property-db:
	@echo "==========================================="
	@echo "Regenerating platform property database"
	@echo "==========================================="
	@echo "Platform: $(PLATFORM_NAME)"
	@echo "Source:   ../../src/ucentral-client/platform/$(PLATFORM_NAME)/plat-*.c"
	@echo "Configs:  ../../config-samples/cfg*.json"
	@echo "==========================================="
	cd ../tools && python3 rebuild-property-database.py \
		../../src/ucentral-client/platform/$(PLATFORM_NAME)/plat-*.c \
		../../config-samples/cfg*.json \
		> ../config-parser/property-database-platform-$(PLATFORM_NAME).c
	@echo "Platform property database regenerated"
	@echo "==========================================="
else
regenerate-platform-property-db:
	@echo "ERROR: USE_PLATFORM not set"
	@echo "Usage: make regenerate-platform-property-db USE_PLATFORM=brcm-sonic"
	@exit 1
endif

# ============================================================================
# CLEANUP
# ============================================================================

clean:
	rm -f test-config-parser proto-test.o test-config-parser.o test-stubs.o
	rm -f platform-mock-*.o
	rm -f test-report.html test-report.json test-report.xml test-results.txt
	@echo "Test artifacts cleaned"

# ============================================================================
# HELP
# ============================================================================

help:
	@echo "Configuration Parser Test Suite"
	@echo ""
	@echo "Testing Modes:"
	@echo "  Stub mode (default)    - Fast testing with simple stubs"
	@echo "  Platform mode          - Integration testing with real platform"
	@echo ""
	@echo "Usage:"
	@echo "  make test-config-full                         # Stub mode"
	@echo "  make test-config-full USE_PLATFORM=brcm-sonic # Platform mode"
	@echo ""
	@echo "Available targets:"
	@echo "  config                        - Show current build configuration"
	@echo "  test-config                   - Run configuration parser tests"
	@echo "  validate-schema               - Run schema validation only"
	@echo "  test-config-full              - Run both schema validation and parser tests"
	@echo "  test-config-html              - Generate HTML test report"
	@echo "  test-config-json              - Generate JSON test report"
	@echo "  test-config-junit             - Generate JUnit XML test report"
	@echo "  regenerate-property-db        - Regenerate base property database from proto.c"
	@echo "  regenerate-platform-property-db - Regenerate platform property database (requires USE_PLATFORM)"
	@echo "  clean                         - Remove test artifacts"
	@echo "  help                          - Show this help message"
	@echo ""
	@echo "Supported platforms:"
	@echo "  brcm-sonic         - Broadcom SONiC platform (gNMI-based)"
	@echo "  example-platform   - Template for new platforms"
	@echo ""
	@echo "For more information, see tests/ADDING_NEW_PLATFORM.md"
