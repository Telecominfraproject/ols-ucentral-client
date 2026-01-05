#!/usr/bin/env python3
"""
Generate complete property database from schema.

This script takes ALL properties from the schema and generates a complete
property database with line numbers from the source code.

Usage:
    python3 generate-database-from-schema.py <source-file> <schema-properties-file> <output-file>

Example:
    # For base database (proto.c)
    python3 generate-database-from-schema.py \
        ../../src/ucentral-client/proto.c \
        /tmp/all-schema-properties.txt \
        /tmp/base-database-new.c

    # For platform database (plat-gnma.c)
    python3 generate-database-from-schema.py \
        ../../src/ucentral-client/platform/brcm-sonic/plat-gnma.c \
        /tmp/all-schema-properties.txt \
        /tmp/platform-database-new.c
"""

import re
import sys
from pathlib import Path
from typing import Optional, Tuple, Dict

def extract_json_key(property_path: str) -> str:
    """Extract the JSON key from a property path."""
    # Remove array brackets first
    path = property_path.replace('[]', '')

    # Get last component
    if '.' in path:
        key = path.split('.')[-1]
    else:
        key = path

    # Return the key - it may contain hyphens which are valid in JSON keys
    return key

def find_function_containing_line(source_lines: list, target_line: int) -> Optional[str]:
    """
    Find which function contains a given line number.

    Searches backward from target line to find the nearest function definition.
    Handles multiple function definition styles:
        static int function_name(params)                    # Single line
        static int                                          # Return type on one line
        function_name(params)                               # Function name on next line
    """
    for i in range(target_line - 1, -1, -1):
        line_raw = source_lines[i]
        line = line_raw.strip()

        # Skip empty lines
        if not line:
            continue

        # IMPORTANT: Function definitions must start at column 0 (or only whitespace before)
        # This excludes indented function calls inside function bodies

        # Pattern 1: Function name with opening paren on its own line (line 2 of split definition)
        # Example: "cfg_ethernet_ieee8021x_parse(cJSON *ieee8021x, struct plat_port *port)"
        # Must be at column 0 (no leading whitespace in original line)
        if line_raw[0] not in (' ', '\t'):
            match = re.match(r'^([a-z_][a-z0-9_]*)\s*\(', line, re.IGNORECASE)
            if match:
                func_name = match.group(1)
                # Check if previous line has return type (static int, void, etc.)
                if i > 0:
                    prev_line = source_lines[i - 1].strip()
                    # If previous line looks like a return type, this is a function definition
                    # Examples: "static int", "void", "static char *", "struct foo"
                    if re.match(r'^(static\s+)?(\w+\s*\**\s*)+$', prev_line):
                        # Make sure it's not followed by semicolon (declaration)
                        # Check next few lines for opening brace or statements
                        for j in range(i + 1, min(i + 5, len(source_lines))):
                            next_line = source_lines[j].strip()
                            if next_line == '{' or (next_line and not next_line.endswith(';')):
                                return func_name
                            if next_line.endswith(';'):
                                break  # It's a declaration

            # Pattern 2: Complete function definition on one line
            # Example: "static int cfg_ethernet_poe_parse(cJSON *poe,"
            match = re.match(r'^(static\s+)?(\w+\s+\**)+([a-z_][a-z0-9_]*)\s*\(', line, re.IGNORECASE)
            if match:
                func_name = match.group(3)
                # Check it's not followed by a semicolon (declaration)
                for j in range(i + 1, min(i + 10, len(source_lines))):
                    next_line = source_lines[j].strip()
                    if ')' in next_line:
                        if next_line.endswith(';') or (j + 1 < len(source_lines) and source_lines[j + 1].strip() == ';'):
                            break  # It's a declaration
                        return func_name

    return None

def find_property_in_source(source_file: Path, property_path: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Find where a property is accessed in source file.

    Returns:
        (line_number, function_name) or (None, None) if not found
    """
    json_key = extract_json_key(property_path)

    try:
        with open(source_file, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {source_file}: {e}", file=sys.stderr)
        return None, None

    # Search patterns for cJSON property access
    patterns = [
        rf'cJSON_GetObjectItem\s*\([^,]+,\s*"{json_key}"\)',
        rf'cJSON_GetObjectItemCaseSensitive\s*\([^,]+,\s*"{json_key}"\)',
        rf'cJSON_GetStringValue\s*\(.*"{json_key}".*\)',
        rf'cJSON_GetNumberValue\s*\(.*"{json_key}".*\)',
        rf'cJSON_IsTrue\s*\(.*"{json_key}".*\)',
        rf'cJSON_IsFalse\s*\(.*"{json_key}".*\)',
    ]

    for line_num, line in enumerate(lines, 1):
        for pattern in patterns:
            if re.search(pattern, line):
                # Found it!
                function = find_function_containing_line(lines, line_num)
                return line_num, function

    return None, None

def generate_database_entry(property_path: str, line_num: Optional[int],
                           function: Optional[str], source_file: str) -> str:
    """Generate a C database entry for a property."""
    if line_num and function:
        status = "PROP_CONFIGURED"
        description = f"Parsed in {function}()"
    else:
        status = "PROP_CONFIGURED"
        line_num = 0
        function = "NULL"
        description = "Not yet implemented"

    return f'    {{"{property_path}", {status}, "{source_file}", "{function}", {line_num}, "{description}"}},'

def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)

    source_file = Path(sys.argv[1])
    properties_file = Path(sys.argv[2])
    output_file = Path(sys.argv[3])

    if not source_file.exists():
        print(f"Error: Source file not found: {source_file}", file=sys.stderr)
        sys.exit(1)

    if not properties_file.exists():
        print(f"Error: Properties file not found: {properties_file}", file=sys.stderr)
        sys.exit(1)

    # Read all properties
    with open(properties_file, 'r') as f:
        properties = [line.strip() for line in f if line.strip()]

    print(f"Processing {len(properties)} properties from schema...", file=sys.stderr)
    print(f"Searching in: {source_file}", file=sys.stderr)

    # Find line numbers for all properties
    results = {}
    found_count = 0
    not_found_count = 0

    for i, prop in enumerate(properties, 1):
        if i % 50 == 0:
            print(f"  Processed {i}/{len(properties)} properties...", file=sys.stderr)

        line_num, function = find_property_in_source(source_file, prop)
        results[prop] = (line_num, function)

        if line_num:
            found_count += 1
        else:
            not_found_count += 1

    print(f"\nResults:", file=sys.stderr)
    print(f"  Found: {found_count} properties", file=sys.stderr)
    print(f"  Not found: {not_found_count} properties", file=sys.stderr)
    print(f"  Total: {len(properties)} properties", file=sys.stderr)

    # Generate database
    source_filename = source_file.name
    database_entries = []

    for prop in sorted(properties):
        line_num, function = results[prop]
        entry = generate_database_entry(prop, line_num, function, source_filename)
        database_entries.append(entry)

    # Write output
    with open(output_file, 'w') as f:
        f.write(f"/*\n")
        f.write(f" * Property Database Generated from Schema\n")
        f.write(f" *\n")
        f.write(f" * Source: {source_file}\n")
        f.write(f" * Properties: {len(properties)} from schema\n")
        f.write(f" * Found: {found_count} implemented\n")
        f.write(f" * Not found: {not_found_count} not yet implemented\n")
        f.write(f" *\n")
        f.write(f" * This database tracks ALL properties in the uCentral schema,\n")
        f.write(f" * whether implemented or not. Properties with line_number=0\n")
        f.write(f" * are in the schema but not yet implemented in the code.\n")
        f.write(f" */\n\n")
        f.write(f"static const struct property_metadata base_property_database[] = {{\n")

        for entry in database_entries:
            f.write(entry + "\n")

        f.write(f"\n    /* Sentinel */\n")
        f.write(f'    {{NULL, PROP_CONFIGURED, NULL, NULL, 0, NULL}}\n')
        f.write(f"}};\n")

    print(f"\nDatabase written to: {output_file}", file=sys.stderr)
    print(f"  Total entries: {len(database_entries)}", file=sys.stderr)

if __name__ == "__main__":
    main()
