#!/usr/bin/env python3
"""
Find line numbers where properties are accessed in proto.c.

This script searches proto.c for cJSON property access patterns and returns
the line number where each property is first accessed.

Usage:
    python3 find-property-line-numbers.py <proto.c> <property-path>
"""

import re
import sys
from typing import Optional, Tuple


def extract_json_key(property_path: str) -> str:
    """
    Extract the JSON key from a property path.

    Args:
        property_path: Full path like "ethernet[].enabled" or "unit.hostname"

    Returns:
        JSON key like "enabled" or "hostname"
    """
    # Remove array brackets
    path = property_path.replace('[]', '')

    # Get last component
    if '.' in path:
        return path.split('.')[-1]
    return path


def find_function_containing_line(proto_lines: list, target_line: int) -> Optional[str]:
    """
    Find which function contains a given line number.

    Args:
        proto_lines: List of lines from proto.c
        target_line: Line number to find (1-indexed)

    Returns:
        Function name or None if not found
    """
    # Search backwards from target line to find function definition
    for i in range(target_line - 1, -1, -1):
        line = proto_lines[i]

        # Look for function definition patterns
        # static int cfg_*_parse(...)
        # static void cfg_*_parse(...)
        # TEST_STATIC struct plat_cfg *cfg_parse(...)
        match = re.search(r'(static|TEST_STATIC)\s+\w+\s+\*?(\w+)\s*\(', line)
        if match:
            return match.group(2)

    return None


def find_property_line(proto_file: str, property_path: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Find the line number and function where a property is accessed in proto.c.

    Args:
        proto_file: Path to proto.c
        property_path: Property path like "ethernet[].enabled"

    Returns:
        Tuple of (line_number, function_name) or (None, None) if not found
    """
    json_key = extract_json_key(property_path)

    with open(proto_file, 'r') as f:
        proto_lines = f.readlines()

    # Search patterns for cJSON property access
    patterns = [
        # Most common: cJSON_GetObjectItemCaseSensitive(obj, "key")
        rf'cJSON_GetObjectItemCaseSensitive\([^,]+,\s*"{re.escape(json_key)}"\)',

        # Also check for cJSON_GetObjectItem (without CaseSensitive)
        rf'cJSON_GetObjectItem\([^,]+,\s*"{re.escape(json_key)}"\)',

        # Check for string literal in assignments
        rf'["\']' + re.escape(json_key) + rf'["\']',
    ]

    # Search for first occurrence
    for i, line in enumerate(proto_lines, 1):
        for pattern in patterns:
            if re.search(pattern, line):
                # Found it! Get the function name
                func_name = find_function_containing_line(proto_lines, i)
                return (i, func_name)

    return (None, None)


def main():
    if len(sys.argv) < 3:
        print("Usage: find-property-line-numbers.py <proto.c> <property-path>", file=sys.stderr)
        sys.exit(1)

    proto_file = sys.argv[1]
    property_path = sys.argv[2]

    line_num, func_name = find_property_line(proto_file, property_path)

    if line_num:
        if func_name:
            print(f"{property_path}: line {line_num} in {func_name}()")
        else:
            print(f"{property_path}: line {line_num} (function unknown)")
    else:
        print(f"{property_path}: NOT FOUND")


if __name__ == '__main__':
    main()
