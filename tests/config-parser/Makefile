# Configuration Parser Test Suite Makefile
# This Makefile builds and runs tests for the uCentral configuration parser

.PHONY: test test-config validate-schema test-config-full test-config-html test-config-json test-config-junit clean

# Compiler flags
export CFLAGS+= -Werror -Wall -Wextra

# Paths relative to tests/config-parser/
SRC_DIR = ../../src/ucentral-client
CONFIG_SAMPLES = ../../config-samples
SCHEMA_VALIDATOR = ../schema/validate-schema.py

# Source files from production code
SRC_OBJS = $(SRC_DIR)/ucentral-json-parser.o \
           $(SRC_DIR)/ucentral-log.o \
           $(SRC_DIR)/router-utils.o \
           $(SRC_DIR)/base64.o

# Default target
all: test-config-parser

# Build test files with TEST_STATIC to expose cfg_parse() for testing
test-config-parser.o: test-config-parser.c
	gcc -c -o $@ ${CFLAGS} -DUCENTRAL_TESTING -I $(SRC_DIR) -I $(SRC_DIR)/include -I ./ $<

proto-test.o: $(SRC_DIR)/proto.c
	gcc -c -o $@ ${CFLAGS} -DUCENTRAL_TESTING -I $(SRC_DIR) -I $(SRC_DIR)/include $<

test-stubs.o: test-stubs.c
	gcc -c -o $@ ${CFLAGS} -DUCENTRAL_TESTING -I $(SRC_DIR) -I $(SRC_DIR)/include $<

# Build production source files (if not already built)
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(MAKE) -C $(SRC_DIR) $*.o

# Link test binary
test-config-parser: test-config-parser.o proto-test.o test-stubs.o $(SRC_OBJS)
	g++ -o $@ $^ -lcurl -lwebsockets -lcjson -lssl -lcrypto -lpthread -ljsoncpp -lresolv

# Run configuration parser tests
test-config:
	@echo "========= running config parser tests  ========="
	$(MAKE) test-config-parser
	LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser $(CONFIG_SAMPLES)
	@echo "========= config parser tests completed ========"

# Run schema validation
validate-schema:
	@echo "========= running schema validation  ========="
	@python3 $(SCHEMA_VALIDATOR) $(CONFIG_SAMPLES) || true
	@echo "========= schema validation completed ========"

# Combined validation: schema + parser
test-config-full: validate-schema test-config
	@echo "========= all validation completed ========"

# Generate HTML test report
test-config-html:
	@echo "========= generating HTML test report  ========="
	$(MAKE) test-config-parser
	LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser --html $(CONFIG_SAMPLES) > test-report.html
	@echo "========= HTML report generated: test-report.html ========"

# Generate JSON test report
test-config-json:
	@echo "========= generating JSON test report  ========="
	$(MAKE) test-config-parser
	LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser --json $(CONFIG_SAMPLES) > test-report.json
	@echo "========= JSON report generated: test-report.json ========"

# Generate JUnit XML test report
test-config-junit:
	@echo "========= generating JUnit XML test report  ========="
	$(MAKE) test-config-parser
	LD_LIBRARY_PATH=/usr/local/lib ./test-config-parser --junit $(CONFIG_SAMPLES) > test-report.xml
	@echo "========= JUnit XML report generated: test-report.xml ========"

# Clean test artifacts
clean:
	rm -f test-config-parser proto-test.o test-config-parser.o test-stubs.o
	rm -f test-report.html test-report.json test-report.xml test-results.txt
	@echo "Test artifacts cleaned"

# Help target
help:
	@echo "Configuration Parser Test Suite"
	@echo ""
	@echo "Available targets:"
	@echo "  test-config        - Run configuration parser tests"
	@echo "  validate-schema    - Run schema validation only"
	@echo "  test-config-full   - Run both schema validation and parser tests"
	@echo "  test-config-html   - Generate HTML test report"
	@echo "  test-config-json   - Generate JSON test report"
	@echo "  test-config-junit  - Generate JUnit XML test report"
	@echo "  clean              - Remove test artifacts"
	@echo "  help               - Show this help message"
