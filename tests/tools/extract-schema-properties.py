#!/usr/bin/env python3
"""
Extract property paths from uCentral schema (JSON or YAML).

This script extracts all leaf property paths from the schema to use as a basis
for property database generation. Unlike config-file extraction (which only gets
properties that exist in test configs), this gets ALL schema-defined properties.

Supports both JSON and YAML schema formats:
- JSON: Single file with all definitions (e.g., ucentral.schema.pretty.json)
- YAML: Multi-file schema with $ref resolution (e.g., ols-ucentral-schema/schema/)

Usage:
    # From JSON schema file (included in repository)
    python3 extract-schema-properties.py ../../config-samples/ucentral.schema.pretty.json

    # From YAML schema directory (ols-ucentral-schema repo)
    python3 extract-schema-properties.py /path/to/ols-ucentral-schema/schema ucentral.yml

    # Filter by prefix
    python3 extract-schema-properties.py schema.json --filter switch --filter ethernet

Output:
    One property path per line, suitable for piping to other tools
"""

import sys
import json
import yaml
import argparse
from pathlib import Path
from typing import Set, Dict, Any


def schema_filename(ref_uri: str) -> str:
    """
    Convert schema $ref URI to filename.

    Example: "https://ucentral.io/schema/v1/ethernet/" -> "ethernet.yml"
             "https://ucentral.io/schema/v1/interface/ethernet/" -> "interface.ethernet.yml"
    """
    file_parts = ref_uri.split("v1/")
    if len(file_parts) < 2:
        return None
    filename = file_parts[1].rstrip("/").replace("/", ".") + ".yml"
    return filename


def schema_load(schema_dir: Path, filename: str, loaded_cache: Dict[str, Any]) -> Dict[str, Any]:
    """Load a schema YAML file with caching."""
    cache_key = str(schema_dir / filename)

    if cache_key in loaded_cache:
        return loaded_cache[cache_key]

    schema_path = schema_dir / filename
    if not schema_path.exists():
        print(f"WARNING: Schema file not found: {schema_path}", file=sys.stderr)
        return {}

    try:
        with open(schema_path) as f:
            schema = yaml.safe_load(f)
            loaded_cache[cache_key] = schema
            return schema
    except yaml.YAMLError as exc:
        print(f"ERROR loading {schema_path}: {exc}", file=sys.stderr)
        return {}


def resolve_schema(schema: Any, schema_dir: Path, loaded_cache: Dict[str, Any], depth: int = 0, root_schema: Any = None) -> Any:
    """
    Recursively resolve $ref references in schema.

    Supports both:
    - External refs (YAML): https://ucentral.io/schema/v1/ethernet/
    - Internal refs (JSON): #/$defs/ethernet

    Based on merge-schema.py from ols-ucentral-schema repo.
    """
    if depth > 20:  # Prevent infinite recursion
        return schema

    # Keep root schema for resolving internal $defs references
    if root_schema is None:
        root_schema = schema

    if isinstance(schema, dict):
        resolved = {}

        for key, value in schema.items():
            if key == "$ref" and isinstance(value, str):
                if value.startswith("https://"):
                    # External reference (YAML multi-file schema)
                    filename = schema_filename(value)
                    if filename:
                        ref_schema = schema_load(schema_dir, filename, loaded_cache)
                        # Recursively resolve the referenced schema
                        resolved_ref = resolve_schema(ref_schema, schema_dir, loaded_cache, depth + 1, root_schema)
                        # Merge resolved reference into current dict
                        for ref_key, ref_value in resolved_ref.items():
                            resolved[ref_key] = ref_value
                    else:
                        resolved[key] = value
                elif value.startswith("#/$defs/"):
                    # Internal reference (JSON schema $defs)
                    def_name = value.replace("#/$defs/", "")
                    if '$defs' in root_schema and def_name in root_schema['$defs']:
                        ref_schema = root_schema['$defs'][def_name]
                        # Recursively resolve the referenced schema
                        resolved_ref = resolve_schema(ref_schema, schema_dir, loaded_cache, depth + 1, root_schema)
                        # Merge resolved reference into current dict
                        for ref_key, ref_value in resolved_ref.items():
                            resolved[ref_key] = ref_value
                    else:
                        print(f"WARNING: $defs reference not found: {def_name}", file=sys.stderr)
                        resolved[key] = value
                else:
                    # Unknown reference format
                    resolved[key] = value
            elif isinstance(value, (dict, list)):
                resolved[key] = resolve_schema(value, schema_dir, loaded_cache, depth + 1, root_schema)
            else:
                resolved[key] = value

        return resolved

    elif isinstance(schema, list):
        return [resolve_schema(item, schema_dir, loaded_cache, depth + 1, root_schema) for item in schema]

    else:
        return schema


def extract_properties(schema: Any, base_path: str = "", properties: Set[str] = None) -> Set[str]:
    """
    Recursively extract all property paths from resolved schema.
    """
    if properties is None:
        properties = set()

    if not isinstance(schema, dict):
        return properties

    schema_type = schema.get("type")

    if schema_type == "object":
        # Object with properties
        obj_properties = schema.get("properties", {})

        if not obj_properties:
            # Leaf object with no sub-properties
            if base_path:
                properties.add(base_path)
        else:
            for prop_name, prop_schema in obj_properties.items():
                new_path = f"{base_path}.{prop_name}" if base_path else prop_name
                extract_properties(prop_schema, new_path, properties)

    elif schema_type == "array":
        # Array - add [] and recurse into items
        items_schema = schema.get("items", {})
        array_path = f"{base_path}[]" if base_path else "[]"
        extract_properties(items_schema, array_path, properties)

    else:
        # Leaf property (string, number, boolean, etc.)
        if base_path and schema_type:
            properties.add(base_path)

    return properties


def filter_properties(properties: Set[str], filters: list) -> Set[str]:
    """Filter properties by prefix."""
    if not filters:
        return properties

    filtered = set()
    for prop in properties:
        for f in filters:
            if prop.startswith(f):
                filtered.add(prop)
                break
    return filtered


def exclude_containers(properties: Set[str]) -> Set[str]:
    """
    Remove container properties (keep only leaves).

    For example, if we have both:
        - interfaces[].ipv4
        - interfaces[].ipv4.subnet

    We only keep interfaces[].ipv4.subnet (the leaf).
    """
    leaf_properties = set()

    for prop in properties:
        # Check if this property is a prefix of any other property
        is_container = any(
            other != prop and other.startswith(prop + ".")
            for other in properties
        )

        if not is_container:
            leaf_properties.add(prop)

    return leaf_properties


def main():
    parser = argparse.ArgumentParser(
        description="Extract property paths from uCentral schema (JSON or YAML)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract from JSON schema file (included in repo)
  python3 extract-schema-properties.py ../../config-samples/ucentral.schema.pretty.json

  # Extract from YAML schema directory (ols-ucentral-schema repo)
  python3 extract-schema-properties.py /path/to/ols-ucentral-schema/schema ucentral.yml

  # Filter by prefix (works with both JSON and YAML)
  python3 extract-schema-properties.py schema.json --filter switch --filter ethernet
"""
    )
    parser.add_argument(
        "schema_path",
        help="Path to JSON schema file OR directory containing YAML files"
    )
    parser.add_argument(
        "root_schema",
        nargs="?",
        default=None,
        help="Root schema filename (required for YAML, e.g., ucentral.yml)"
    )
    parser.add_argument(
        "--filter",
        action="append",
        help="Filter properties by prefix (can specify multiple times)"
    )
    parser.add_argument(
        "--include-containers",
        action="store_true",
        help="Include container properties (not just leaves)"
    )
    parser.add_argument(
        "--no-sort",
        action="store_true",
        help="Don't sort output"
    )

    args = parser.parse_args()

    schema_path = Path(args.schema_path)
    if not schema_path.exists():
        print(f"ERROR: Schema path not found: {schema_path}", file=sys.stderr)
        sys.exit(1)

    # Determine if JSON file or YAML directory
    if schema_path.is_file() and schema_path.suffix in ['.json', '.JSON']:
        # JSON schema file
        print(f"Loading JSON schema from {schema_path}...", file=sys.stderr)
        try:
            with open(schema_path) as f:
                root_schema = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"ERROR loading JSON: {exc}", file=sys.stderr)
            sys.exit(1)

        # Resolve all $ref references (including internal #/$defs/)
        print("Resolving schema references...", file=sys.stderr)
        resolved_schema = resolve_schema(root_schema, schema_path.parent, {}, 0, root_schema)

    elif schema_path.is_dir():
        # YAML schema directory
        if not args.root_schema:
            print("ERROR: For YAML schema directory, you must specify root schema filename", file=sys.stderr)
            print("Example: python3 extract-schema-properties.py /path/to/schema ucentral.yml", file=sys.stderr)
            sys.exit(1)

        root_schema_path = schema_path / args.root_schema
        if not root_schema_path.exists():
            print(f"ERROR: Root schema not found: {root_schema_path}", file=sys.stderr)
            sys.exit(1)

        print(f"Loading YAML schema from {root_schema_path}...", file=sys.stderr)

        # Load root schema
        loaded_cache = {}
        root_schema = schema_load(schema_path, args.root_schema, loaded_cache)

        # Resolve all $ref references
        print("Resolving schema references...", file=sys.stderr)
        resolved_schema = resolve_schema(root_schema, schema_path, loaded_cache)

    else:
        print(f"ERROR: Schema path must be either JSON file or YAML directory: {schema_path}", file=sys.stderr)
        sys.exit(1)

    # Extract properties
    print("Extracting properties...", file=sys.stderr)
    properties = extract_properties(resolved_schema)

    # Filter if requested
    if args.filter:
        properties = filter_properties(properties, args.filter)

    # Remove containers unless explicitly requested
    if not args.include_containers:
        properties = exclude_containers(properties)

    # Output
    if not args.no_sort:
        properties = sorted(properties)

    for prop in properties:
        print(prop)

    # Print summary to stderr
    print(f"\nExtracted {len(properties)} leaf properties from schema", file=sys.stderr)
    if args.filter:
        print(f"Filtered by: {', '.join(args.filter)}", file=sys.stderr)


if __name__ == "__main__":
    main()
