#!/usr/bin/env python3
"""
Rebuild the property database with line numbers from config files.

This script:
1. Extracts all properties from config files
2. Finds line numbers in proto.c for each property
3. Generates the property_database[] array in C format

Usage:
    python3 rebuild-property-database.py <proto.c> <config-files...>
    python3 rebuild-property-database.py proto.c ../../config-samples/*.json
"""

import re
import sys
from pathlib import Path
from typing import Set, Dict, Tuple, Optional
import subprocess


def run_property_extractor(config_files: list) -> Set[str]:
    """
    Run generate-property-database.py to extract properties from config files.

    Args:
        config_files: List of config file paths

    Returns:
        Set of property paths
    """
    try:
        # Run the property extractor
        result = subprocess.run(
            ['python3', 'generate-property-database.py'] + config_files,
            capture_output=True,
            text=True,
            check=True
        )

        # Parse output (one property per line)
        properties = set()
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                properties.add(line)

        return properties

    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to extract properties: {e}", file=sys.stderr)
        return set()


def find_property_line(proto_file: str, property_path: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Find line number and function for a property.

    Args:
        proto_file: Path to proto.c
        property_path: Property path like "ethernet[].enabled"

    Returns:
        Tuple of (line_number, function_name) or (None, None)
    """
    try:
        result = subprocess.run(
            ['python3', 'find-property-line-numbers.py', proto_file, property_path],
            capture_output=True,
            text=True,
            check=True
        )

        output = result.stdout.strip()

        # Parse output: "property: line N in function()"
        match = re.match(r'.+: line (\d+) in (\w+)\(\)', output)
        if match:
            return (int(match.group(1)), match.group(2))

        return (None, None)

    except subprocess.CalledProcessError:
        return (None, None)


def classify_property(property_path: str) -> str:
    """
    Determine the status of a property.

    Args:
        property_path: Property path

    Returns:
        Property status: PROP_CONFIGURED, PROP_SYSTEM, PROP_UNKNOWN, etc.
    """
    # System properties (exact matches only)
    if property_path in ['uuid', 'strict', 'public_ip_lookup', 'third-party']:
        return 'PROP_SYSTEM'

    # Container objects (top-level only, no nested properties)
    top_level_containers = [
        'ethernet', 'ethernet[]',
        'unit', 'globals', 'interfaces', 'interfaces[]', 'services', 'metrics', 'switch',
        'ssids', 'ssids[]',
        'config-raw', 'config-raw[]'
    ]
    if property_path in top_level_containers:
        return 'PROP_SYSTEM'

    # All other properties are configured
    return 'PROP_CONFIGURED'


def get_property_notes(property_path: str, line_num: Optional[int]) -> str:
    """
    Generate notes for a property.

    Args:
        property_path: Property path
        line_num: Line number where property is accessed (or None)

    Returns:
        Notes string
    """
    if line_num is None:
        return "Property not found in proto.c (may be platform-specific or unimplemented)"

    # Container objects
    if property_path in ['ethernet', 'unit', 'interfaces', 'services', 'globals', 'switch', 'metrics']:
        return "Container object (not a leaf value)"

    if property_path.endswith('[]') and not '.' in property_path.replace('[]', ''):
        return "Array container"

    return ""


def main():
    if len(sys.argv) < 3:
        print("Usage: rebuild-property-database.py <proto.c> <config-files...>", file=sys.stderr)
        sys.exit(1)

    proto_file = sys.argv[1]
    config_files = [f for f in sys.argv[2:] if 'invalid' not in f.lower()]

    print(f"# Extracting properties from {len(config_files)} config files...", file=sys.stderr)
    properties = run_property_extractor(config_files)

    if not properties:
        print("ERROR: No properties extracted", file=sys.stderr)
        sys.exit(1)

    print(f"# Found {len(properties)} unique properties", file=sys.stderr)
    print(f"# Finding line numbers in {proto_file}...", file=sys.stderr)

    # Build property database entries
    entries = []
    found_count = 0

    for prop in sorted(properties):
        line_num, func_name = find_property_line(proto_file, prop)

        if line_num:
            found_count += 1

        status = classify_property(prop)
        notes = get_property_notes(prop, line_num)

        entries.append({
            'path': prop,
            'status': status,
            'file': 'proto.c',
            'function': func_name or 'cfg_parse',
            'line': line_num or 0,
            'notes': notes
        })

    print(f"# Found line numbers for {found_count}/{len(properties)} properties", file=sys.stderr)
    print("", file=sys.stderr)

    # Generate C code
    print("/* Property database: " + str(len(entries)) + " entries mapping JSON paths to parsing status and source location */")
    print("static const struct property_metadata property_database[] = {")

    for entry in entries:
        # Format: {"path", STATUS, "file", "function", line_number, "notes"},
        path = entry['path'].replace('"', '\\"')
        notes = entry['notes'].replace('"', '\\"')

        print(f'    {{"{path}", {entry["status"]}, "{entry["file"]}", "{entry["function"]}", {entry["line"]}, "{notes}"}},')

    # Sentinel
    print("    /* Sentinel */")
    print("    {NULL, PROP_CONFIGURED, NULL, NULL, 0, NULL}")
    print("};")


if __name__ == '__main__':
    main()
