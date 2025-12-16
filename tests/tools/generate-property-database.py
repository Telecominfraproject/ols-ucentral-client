#!/usr/bin/env python3
"""
Extract all property paths from JSON configuration files.

This script recursively parses JSON config files and extracts all property paths,
converting array indices to [] notation for use in the property database.

Usage:
    python3 generate-property-database.py <config-file1> [config-file2 ...]
    python3 generate-property-database.py ../../config-samples/*.json
"""

import json
import sys
from pathlib import Path
from typing import Set, Any, List


def extract_properties(obj: Any, prefix: str = "", properties: Set[str] = None) -> Set[str]:
    """
    Recursively extract all property paths from a JSON object.

    Args:
        obj: JSON object (dict, list, or primitive)
        prefix: Current path prefix
        properties: Set to accumulate property paths

    Returns:
        Set of property paths in format like "unit.hostname", "ethernet[].enabled"
    """
    if properties is None:
        properties = set()

    if isinstance(obj, dict):
        for key, value in obj.items():
            # Build the path
            if prefix:
                path = f"{prefix}.{key}"
            else:
                path = key

            # Add this property
            properties.add(path)

            # Recurse into the value
            extract_properties(value, path, properties)

    elif isinstance(obj, list):
        # For arrays, use [] notation and process first element as template
        # e.g., ethernet[0] becomes ethernet[]
        if obj:  # If array is not empty
            # Add array itself
            array_path = prefix + "[]"
            properties.add(array_path)

            # Process first element to get array item properties
            extract_properties(obj[0], array_path, properties)

    # For primitives (str, int, bool, null), just return - already added
    return properties


def normalize_property_path(path: str) -> str:
    """
    Normalize property path by converting [N] to [].

    Args:
        path: Property path like "ethernet[0].enabled"

    Returns:
        Normalized path like "ethernet[].enabled"
    """
    import re
    # Replace [N] with []
    return re.sub(r'\[\d+\]', '[]', path)


def extract_from_file(filepath: str) -> Set[str]:
    """
    Extract all property paths from a single JSON file.

    Args:
        filepath: Path to JSON config file

    Returns:
        Set of property paths found in the file
    """
    try:
        with open(filepath, 'r') as f:
            config = json.load(f)

        properties = extract_properties(config)

        # Normalize all paths (convert [N] to [])
        normalized = {normalize_property_path(p) for p in properties}

        return normalized

    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse {filepath}: {e}", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"ERROR: Failed to read {filepath}: {e}", file=sys.stderr)
        return set()


def main():
    if len(sys.argv) < 2:
        print("Usage: generate-property-database.py <config-file1> [config-file2 ...]", file=sys.stderr)
        print("       generate-property-database.py ../../config-samples/*.json", file=sys.stderr)
        sys.exit(1)

    # Collect properties from all config files
    all_properties: Set[str] = set()
    files_processed = 0

    for filepath in sys.argv[1:]:
        # Skip invalid/negative test configs
        if 'invalid' in filepath.lower():
            continue

        path = Path(filepath)
        if not path.exists():
            print(f"WARNING: File not found: {filepath}", file=sys.stderr)
            continue

        if not path.suffix == '.json':
            continue

        properties = extract_from_file(filepath)
        if properties:
            all_properties.update(properties)
            files_processed += 1
            print(f"Processed {path.name}: {len(properties)} properties", file=sys.stderr)

    print(f"\nTotal: {len(all_properties)} unique properties from {files_processed} files\n", file=sys.stderr)

    # Output sorted list of properties
    for prop in sorted(all_properties):
        print(prop)


if __name__ == '__main__':
    main()
