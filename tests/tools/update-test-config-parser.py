#!/usr/bin/env python3
"""
Update test-config-parser.c with new property database.

This script replaces the property_database[] array in test-config-parser.c
with the newly generated one from rebuild-property-database.py.
"""

import sys
import re


def main():
    if len(sys.argv) < 3:
        print("Usage: update-test-config-parser.py <test-config-parser.c> <new-property-database.c>", file=sys.stderr)
        sys.exit(1)

    test_parser_file = sys.argv[1]
    new_database_file = sys.argv[2]

    # Read the test-config-parser.c file
    with open(test_parser_file, 'r') as f:
        content = f.read()

    # Read the new property database
    with open(new_database_file, 'r') as f:
        new_database = f.read()

    # Remove comment lines starting with #
    new_database_lines = [line for line in new_database.split('\n') if not line.startswith('#')]
    new_database_clean = '\n'.join(new_database_lines)

    # Find and replace the property_database array
    # Pattern: from "/* Property database:" to "};" after the sentinel
    pattern = r'(/\* Property database:.*?\*/\s*static const struct property_metadata property_database\[\] = \{.*?/\* Sentinel \*/\s*\{NULL.*?\}\s*\};)'

    match = re.search(pattern, content, re.DOTALL)

    if not match:
        print("ERROR: Could not find property_database array in test-config-parser.c", file=sys.stderr)
        sys.exit(1)

    # Replace with new database
    new_content = content[:match.start()] + new_database_clean + content[match.end():]

    # Write back
    with open(test_parser_file, 'w') as f:
        f.write(new_content)

    print(f"SUCCESS: Updated {test_parser_file} with new property database", file=sys.stderr)
    print(f"  Old database: {len(match.group(1).split(chr(10)))} lines", file=sys.stderr)
    print(f"  New database: {len(new_database_clean.split(chr(10)))} lines", file=sys.stderr)


if __name__ == '__main__':
    main()
