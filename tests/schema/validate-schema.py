#!/usr/bin/env python3
"""
uCentral Configuration Schema Validator

A modular, standalone tool for validating JSON configuration files against
the uCentral schema. Can be used independently or integrated into test suites.

Usage:
    # Validate a single file (schema validation only)
    ./validate-schema.py config.json

    # Check for undefined properties (informational, doesn't affect exit code)
    ./validate-schema.py config.json --check-undefined

    # Strict mode: treat undefined properties as errors (for CI/CD)
    ./validate-schema.py config.json --strict-schema

    # Validate with specific schema
    ./validate-schema.py config.json --schema path/to/schema.json

    # Validate directory of configs
    ./validate-schema.py config-dir/

    # Machine-readable JSON output
    ./validate-schema.py config.json --format json

Exit codes:
    0 = all valid (undefined properties don't affect this unless --strict-schema)
    1 = validation errors OR (strict mode AND undefined properties found)
    2 = file/schema errors (file not found, invalid schema, etc.)

Undefined Properties:
    Properties in config but not defined in schema are INFORMATIONAL warnings,
    not validation errors. They may indicate:
      • Typos/misspellings (property won't be applied even though config is valid)
      • Vendor-specific extensions (not portable across platforms)
      • Deprecated properties (check schema version)

    Use --strict-schema in CI/CD pipelines to enforce schema compliance.

Author: Generated for OLS uCentral Client
License: BSD-3-Clause
"""

import sys
import json
import argparse
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict

try:
    import jsonschema
    from jsonschema import Draft7Validator, validators
except ImportError:
    print("ERROR: jsonschema module not found. Install with: pip3 install jsonschema", file=sys.stderr)
    sys.exit(2)


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein distance between two strings.
    Returns minimum number of single-character edits needed to change s1 into s2.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Cost of insertions, deletions, or substitutions
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_separator(s: str, target: str = '-') -> str:
    """Convert string separators. Default converts underscores and camelCase to dashes."""
    # Handle camelCase: insert dash before uppercase letters
    result = []
    for i, char in enumerate(s):
        if i > 0 and char.isupper() and s[i-1].islower():
            result.append('-')
        result.append(char.lower())

    normalized = ''.join(result)
    # Replace underscores with target separator
    normalized = normalized.replace('_', target)
    return normalized


def detect_naming_issue(config_prop: str, schema_prop: str) -> Optional[Dict[str, str]]:
    """
    Detect if config_prop is a likely typo/variation of schema_prop.
    Returns dict with issue type and confidence, or None if no clear match.
    """
    # Extract just the property name (last component after last dot or bracket)
    def get_prop_name(path: str) -> str:
        # Handle array notation: ethernet[].lldp-config -> lldp-config
        if '.' in path:
            return path.split('.')[-1]
        return path

    config_name = get_prop_name(config_prop)
    schema_name = get_prop_name(schema_prop)

    # Check for exact match after normalization
    config_normalized = normalize_separator(config_name, '-')
    schema_normalized = normalize_separator(schema_name, '-')

    if config_normalized == schema_normalized and config_name != schema_name:
        # Separator mismatch (dash vs underscore vs camelCase)
        if '_' in config_name and '-' in schema_name:
            return {'type': 'separator_mismatch', 'detail': 'underscore_vs_dash', 'confidence': 'high'}
        elif any(c.isupper() for c in config_name) and '-' in schema_name:
            return {'type': 'separator_mismatch', 'detail': 'camelCase_vs_dash', 'confidence': 'high'}
        else:
            return {'type': 'separator_mismatch', 'detail': 'format_difference', 'confidence': 'high'}

    # Check Levenshtein distance
    distance = levenshtein_distance(config_name.lower(), schema_name.lower())
    if distance <= 2:
        return {'type': 'similar_spelling', 'detail': f'edit_distance_{distance}', 'confidence': 'high' if distance == 1 else 'medium'}
    elif distance <= 3:
        return {'type': 'similar_spelling', 'detail': f'edit_distance_{distance}', 'confidence': 'medium'}

    return None


class SchemaValidator:
    """
    Modular schema validator for uCentral configurations.

    This class is designed to be easily portable across repositories.
    It has no dependencies on specific file paths or repository structure.
    """

    def __init__(self, schema_path: Optional[str] = None, check_undefined: bool = False,
                 similarity_threshold: int = 3):
        """
        Initialize validator with schema.

        Args:
            schema_path: Path to JSON schema file. If None, attempts to find
                        schema in common locations relative to this script.
            check_undefined: If True, check for properties in config not defined in schema
            similarity_threshold: Maximum Levenshtein distance for suggesting similar properties
        """
        self.schema_path = schema_path
        self.schema = None
        self.validator = None
        self.check_undefined = check_undefined
        self.similarity_threshold = similarity_threshold
        self._schema_properties = None  # Cache of all valid schema property paths
        self._load_schema()

    def _find_default_schema(self) -> Optional[str]:
        """Find schema in common locations relative to script."""
        script_dir = Path(__file__).parent

        # Search paths (relative to script location)
        search_paths = [
            script_dir / "../../config-samples/ucentral.schema.pretty.json",
            script_dir / "../../config-samples/ucentral.schema.json",
            script_dir / "../../../config-samples/ucentral.schema.pretty.json",
            script_dir / "ucentral.schema.json",
        ]

        for path in search_paths:
            if path.exists():
                return str(path.resolve())

        return None

    def _load_schema(self):
        """Load and parse the JSON schema."""
        if self.schema_path is None:
            self.schema_path = self._find_default_schema()
            if self.schema_path is None:
                raise FileNotFoundError(
                    "Could not find schema file. Please specify --schema path"
                )

        try:
            with open(self.schema_path, 'r') as f:
                self.schema = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in schema file {self.schema_path}: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Schema file not found: {self.schema_path}")

        # Create validator
        self.validator = Draft7Validator(self.schema)

    def _extract_schema_properties(self, schema: Dict = None, path: str = "", visited: Set[str] = None) -> Set[str]:
        """
        Recursively extract all valid property paths from the schema.

        Args:
            schema: Schema object (or sub-schema) to process
            path: Current path prefix
            visited: Set of visited $ref paths to prevent infinite recursion

        Returns:
            Set of all valid property paths in the schema
        """
        if schema is None:
            schema = self.schema

        if visited is None:
            visited = set()

        properties = set()

        # Handle $ref references
        if '$ref' in schema:
            ref_path = schema['$ref']

            # Prevent infinite recursion
            if ref_path in visited:
                return properties
            visited.add(ref_path)

            # Resolve $ref (handle #/$defs/name references)
            if ref_path.startswith('#/'):
                ref_parts = ref_path[2:].split('/')
                ref_schema = self.schema
                for part in ref_parts:
                    ref_schema = ref_schema.get(part, {})

                # Recursively extract from referenced schema
                return self._extract_schema_properties(ref_schema, path, visited)

        # Handle object properties
        if 'properties' in schema:
            for prop_name, prop_schema in schema['properties'].items():
                prop_path = f"{path}.{prop_name}" if path else prop_name
                properties.add(prop_path)

                # Recursively process nested properties
                nested = self._extract_schema_properties(prop_schema, prop_path, visited.copy())
                properties.update(nested)

        # Handle arrays with items schema
        if 'items' in schema:
            items_schema = schema['items']
            # Use [] notation for arrays
            array_path = f"{path}[]" if path else "[]"

            # Extract properties from array items
            nested = self._extract_schema_properties(items_schema, array_path, visited.copy())
            properties.update(nested)

        # Handle additional properties (if true, allows any property)
        # We don't add these to valid properties as they're wildcards

        return properties

    def _extract_config_properties(self, config: Dict, path: str = "") -> Set[str]:
        """
        Recursively extract all property paths from a configuration object.

        Args:
            config: Configuration object to analyze
            path: Current path prefix

        Returns:
            Set of all property paths in the configuration
        """
        properties = set()

        if isinstance(config, dict):
            for key, value in config.items():
                prop_path = f"{path}.{key}" if path else key
                properties.add(prop_path)

                # Recursively process nested values
                nested = self._extract_config_properties(value, prop_path)
                properties.update(nested)

        elif isinstance(config, list):
            # For arrays, use [] notation and process all items
            array_path = f"{path}[]" if path else "[]"

            for item in config:
                nested = self._extract_config_properties(item, array_path)
                properties.update(nested)

        return properties

    def _find_similar_properties(self, config_prop: str, schema_props: Set[str]) -> List[Dict]:
        """
        Find schema properties similar to a config property.

        Args:
            config_prop: Property path from configuration
            schema_props: Set of all valid schema property paths

        Returns:
            List of suggestions with similarity information
        """
        suggestions = []

        for schema_prop in schema_props:
            issue = detect_naming_issue(config_prop, schema_prop)
            if issue:
                suggestions.append({
                    'schema_property': schema_prop,
                    'issue_type': issue['type'],
                    'detail': issue['detail'],
                    'confidence': issue['confidence']
                })

        # Sort by confidence (high first) and then alphabetically
        confidence_order = {'high': 0, 'medium': 1, 'low': 2}
        suggestions.sort(key=lambda x: (confidence_order.get(x['confidence'], 3), x['schema_property']))

        return suggestions

    def _check_undefined_properties(self, config: Dict) -> Dict[str, any]:
        """
        Check for properties in config that are not defined in schema.

        Args:
            config: Configuration object to check

        Returns:
            Dict with undefined property analysis results
        """
        # Extract all valid schema properties (with caching)
        if self._schema_properties is None:
            self._schema_properties = self._extract_schema_properties()

        # Extract all config properties
        config_props = self._extract_config_properties(config)

        # Find undefined properties
        undefined = []

        for config_prop in sorted(config_props):
            # Check if property or its array form exists in schema
            is_defined = False

            # Direct match
            if config_prop in self._schema_properties:
                is_defined = True
            else:
                # Check with array index normalization: ethernet[0].speed -> ethernet[].speed
                normalized_prop = config_prop
                import re
                # Replace array indices with []
                normalized_prop = re.sub(r'\[\d+\]', '[]', normalized_prop)

                if normalized_prop in self._schema_properties:
                    is_defined = True

            if not is_defined:
                # Find similar properties
                suggestions = self._find_similar_properties(config_prop, self._schema_properties)

                undefined.append({
                    'path': config_prop,
                    'suggestions': suggestions[:3]  # Top 3 suggestions
                })

        return {
            'total_config_properties': len(config_props),
            'total_schema_properties': len(self._schema_properties),
            'undefined_count': len(undefined),
            'undefined_properties': undefined
        }

    def validate_file(self, config_path: str) -> Tuple[bool, List[Dict], Optional[Dict]]:
        """Validate a single configuration file against the schema."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            return False, [{
                'path': '$',
                'message': f'Invalid JSON: {e}',
                'validator': 'json_parse'
            }], None
        except FileNotFoundError:
            return False, [{
                'path': '$',
                'message': f'File not found: {config_path}',
                'validator': 'file_access'
            }], None

        return self.validate_config(config)

    def validate_config(self, config: Dict) -> Tuple[bool, List[Dict], Optional[Dict]]:
        """
        Validate a configuration object against the schema.

        Returns:
            Tuple of (is_valid, errors, undefined_analysis)
            - is_valid: True if no schema validation errors
            - errors: List of schema validation errors
            - undefined_analysis: Dict with undefined property analysis (if check_undefined=True)
        """
        errors = []

        for error in sorted(self.validator.iter_errors(config), key=str):
            # Build JSON path
            path = '$.' + '.'.join(str(p) for p in error.absolute_path) if error.absolute_path else '$'

            errors.append({
                'path': path,
                'message': error.message,
                'validator': error.validator,
                'schema_path': '.'.join(str(p) for p in error.absolute_schema_path) if error.absolute_schema_path else '$'
            })

        # Check for undefined properties if enabled
        undefined_analysis = None
        if self.check_undefined:
            undefined_analysis = self._check_undefined_properties(config)

        return len(errors) == 0, errors, undefined_analysis

    def validate_directory(self, dir_path: str, pattern: str = "*.json") -> Dict[str, Tuple[bool, List[Dict], Optional[Dict]]]:
        """Validate all JSON files in a directory."""
        results = {}
        dir_path_obj = Path(dir_path)

        if not dir_path_obj.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path}")

        # Find all matching files
        for file_path in sorted(dir_path_obj.glob(pattern)):
            # Skip schema files
            if 'schema' in file_path.name.lower():
                continue

            results[file_path.name] = self.validate_file(str(file_path))

        return results


def format_human_output(filename: str, is_valid: bool, errors: List[Dict],
                        undefined_analysis: Optional[Dict] = None) -> str:
    """Format validation results in human-readable format."""
    output = []

    # Schema validation results
    if is_valid:
        output.append(f"✓ Schema Valid: {filename}")
    else:
        output.append(f"✗ Schema Invalid: {filename}")
        output.append(f"  Found {len(errors)} validation error(s):")

        for i, error in enumerate(errors, 1):
            output.append(f"\n  Error {i}:")
            output.append(f"    Path: {error['path']}")
            output.append(f"    Message: {error['message']}")
            if error.get('validator'):
                output.append(f"    Validator: {error['validator']}")

    # Undefined properties analysis (informational warnings, not errors)
    if undefined_analysis and undefined_analysis['undefined_count'] > 0:
        output.append(f"\nℹ️  Undefined Properties (informational):")
        output.append(f"  Found {undefined_analysis['undefined_count']} property/properties not in schema")
        output.append(f"  These may be:")
        output.append(f"    • Typos/misspellings (won't be applied even though config is valid)")
        output.append(f"    • Vendor-specific extensions (not portable, may change)")
        output.append(f"    • Deprecated properties (check schema version)\n")

        for i, item in enumerate(undefined_analysis['undefined_properties'], 1):
            output.append(f"  {i}. {item['path']}")
            output.append(f"     → Not defined in schema")

            if item['suggestions']:
                output.append(f"     → Possible matches:")
                for suggestion in item['suggestions']:
                    confidence_icon = "✓" if suggestion['confidence'] == 'high' else "?"
                    detail_msg = ""
                    if suggestion['issue_type'] == 'separator_mismatch':
                        if 'underscore_vs_dash' in suggestion['detail']:
                            detail_msg = " (use '-' not '_')"
                        elif 'camelCase_vs_dash' in suggestion['detail']:
                            detail_msg = " (use dash-case not camelCase)"
                    elif suggestion['issue_type'] == 'similar_spelling':
                        detail_msg = f" (similar spelling)"

                    output.append(f"       {confidence_icon} {suggestion['schema_property']}{detail_msg}")
            output.append("")  # Blank line between items

    elif undefined_analysis and undefined_analysis['undefined_count'] == 0:
        output.append(f"✓ All properties defined in schema")

    return '\n'.join(output)


def format_json_output(results: Dict[str, Tuple[bool, List[Dict], Optional[Dict]]]) -> str:
    """Format validation results as JSON."""
    output = {
        'summary': {
            'total': len(results),
            'valid': sum(1 for is_valid, _, _ in results.values() if is_valid),
            'invalid': sum(1 for is_valid, _, _ in results.values() if not is_valid),
            'with_undefined_properties': sum(1 for _, _, undefined in results.values()
                                            if undefined and undefined['undefined_count'] > 0)
        },
        'results': {}
    }

    for filename, (is_valid, errors, undefined_analysis) in results.items():
        result_data = {
            'schema_valid': is_valid,
            'errors': errors
        }

        if undefined_analysis:
            result_data['schema_compliance'] = {
                'total_config_properties': undefined_analysis['total_config_properties'],
                'undefined_count': undefined_analysis['undefined_count'],
                'undefined_properties': undefined_analysis['undefined_properties']
            }

        output['results'][filename] = result_data

    return json.dumps(output, indent=2)


def main():
    """Main entry point for standalone usage."""
    parser = argparse.ArgumentParser(
        description='Validate uCentral JSON configurations against schema',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s config.json
  %(prog)s config.json --schema my-schema.json
  %(prog)s config-samples/
  %(prog)s config-samples/ --format json > report.json
        """
    )

    parser.add_argument('path',
                       help='Configuration file or directory to validate')
    parser.add_argument('--schema', '-s',
                       help='Path to JSON schema file (auto-detected if not specified)')
    parser.add_argument('--format', '-f',
                       choices=['human', 'json'],
                       default='human',
                       help='Output format (default: human)')
    parser.add_argument('--pattern', '-p',
                       default='*.json',
                       help='File pattern for directory validation (default: *.json)')
    parser.add_argument('--check-undefined', '-u',
                       action='store_true',
                       help='Check for properties not defined in schema (informational, does not affect exit code)')
    parser.add_argument('--strict-schema',
                       action='store_true',
                       help='Treat undefined properties as errors (exit code 1). Use for CI/CD enforcement. (implies --check-undefined)')
    parser.add_argument('--similarity-threshold', '-t',
                       type=int,
                       default=3,
                       help='Maximum edit distance for suggesting similar properties (default: 3)')

    args = parser.parse_args()

    # --strict-schema implies --check-undefined
    check_undefined = args.check_undefined or args.strict_schema

    # Initialize validator
    try:
        validator = SchemaValidator(args.schema, check_undefined=check_undefined,
                                   similarity_threshold=args.similarity_threshold)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    # Determine if path is file or directory
    path_obj = Path(args.path)

    if not path_obj.exists():
        print(f"ERROR: Path not found: {args.path}", file=sys.stderr)
        return 2

    # Validate
    results = {}

    if path_obj.is_file():
        is_valid, errors, undefined_analysis = validator.validate_file(args.path)
        results[path_obj.name] = (is_valid, errors, undefined_analysis)
    elif path_obj.is_dir():
        try:
            results = validator.validate_directory(args.path, args.pattern)
        except NotADirectoryError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
    else:
        print(f"ERROR: Path is neither file nor directory: {args.path}", file=sys.stderr)
        return 2

    # Format and output results
    if args.format == 'json':
        print(format_json_output(results))
    else:
        for filename, (is_valid, errors, undefined_analysis) in results.items():
            print(format_human_output(filename, is_valid, errors, undefined_analysis))
            print()  # Blank line between files

        # Summary for multiple files
        if len(results) > 1:
            valid_count = sum(1 for is_valid, _, _ in results.values() if is_valid)
            invalid_count = len(results) - valid_count
            undefined_count = sum(1 for _, _, undefined in results.values()
                                 if undefined and undefined['undefined_count'] > 0)

            print(f"Summary: {len(results)} file(s) checked, {valid_count} valid, {invalid_count} invalid")
            if check_undefined:
                print(f"         {undefined_count} file(s) with undefined properties")

    # Exit code logic
    # Only schema validation errors cause failure by default
    all_valid = all(is_valid for is_valid, _, _ in results.values())

    # In strict mode, undefined properties also cause failure
    has_undefined = False
    if args.strict_schema:
        has_undefined = any(undefined and undefined['undefined_count'] > 0
                           for _, _, undefined in results.values())

    # Exit codes:
    # 0 = all valid (undefined properties don't affect this unless --strict-schema)
    # 1 = validation errors OR (strict mode AND undefined properties found)
    if not all_valid:
        return 1
    elif args.strict_schema and has_undefined:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
