#!/usr/bin/env python3
"""
uCentral Configuration Schema Validator

A modular, standalone tool for validating JSON configuration files against
the uCentral schema. Can be used independently or integrated into test suites.

Usage:
    # Validate a single file
    ./validate-schema.py config.json

    # Validate with specific schema
    ./validate-schema.py config.json --schema path/to/schema.json

    # Validate directory of configs
    ./validate-schema.py config-dir/

    # Machine-readable JSON output
    ./validate-schema.py config.json --format json

    # Exit code: 0 = all valid, 1 = validation errors, 2 = file/schema errors

Author: Generated for OLS uCentral Client
License: BSD-3-Clause
"""

import sys
import json
import argparse
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional

try:
    import jsonschema
    from jsonschema import Draft7Validator, validators
except ImportError:
    print("ERROR: jsonschema module not found. Install with: pip3 install jsonschema", file=sys.stderr)
    sys.exit(2)


class SchemaValidator:
    """
    Modular schema validator for uCentral configurations.

    This class is designed to be easily portable across repositories.
    It has no dependencies on specific file paths or repository structure.
    """

    def __init__(self, schema_path: Optional[str] = None):
        """
        Initialize validator with schema.

        Args:
            schema_path: Path to JSON schema file. If None, attempts to find
                        schema in common locations relative to this script.
        """
        self.schema_path = schema_path
        self.schema = None
        self.validator = None
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

    def validate_file(self, config_path: str) -> Tuple[bool, List[Dict]]:
        """Validate a single configuration file against the schema."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            return False, [{
                'path': '$',
                'message': f'Invalid JSON: {e}',
                'validator': 'json_parse'
            }]
        except FileNotFoundError:
            return False, [{
                'path': '$',
                'message': f'File not found: {config_path}',
                'validator': 'file_access'
            }]

        return self.validate_config(config)

    def validate_config(self, config: Dict) -> Tuple[bool, List[Dict]]:
        """Validate a configuration object against the schema."""
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

        return len(errors) == 0, errors

    def validate_directory(self, dir_path: str, pattern: str = "*.json") -> Dict[str, Tuple[bool, List[Dict]]]:
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


def format_human_output(filename: str, is_valid: bool, errors: List[Dict]) -> str:
    """Format validation results in human-readable format."""
    output = []

    if is_valid:
        output.append(f"✓ Valid: {filename}")
    else:
        output.append(f"✗ Invalid: {filename}")
        output.append(f"  Found {len(errors)} validation error(s):")

        for i, error in enumerate(errors, 1):
            output.append(f"\n  Error {i}:")
            output.append(f"    Path: {error['path']}")
            output.append(f"    Message: {error['message']}")
            if error.get('validator'):
                output.append(f"    Validator: {error['validator']}")

    return '\n'.join(output)


def format_json_output(results: Dict[str, Tuple[bool, List[Dict]]]) -> str:
    """Format validation results as JSON."""
    output = {
        'summary': {
            'total': len(results),
            'valid': sum(1 for is_valid, _ in results.values() if is_valid),
            'invalid': sum(1 for is_valid, _ in results.values() if not is_valid)
        },
        'results': {}
    }

    for filename, (is_valid, errors) in results.items():
        output['results'][filename] = {
            'valid': is_valid,
            'errors': errors
        }

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

    args = parser.parse_args()

    # Initialize validator
    try:
        validator = SchemaValidator(args.schema)
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
        is_valid, errors = validator.validate_file(args.path)
        results[path_obj.name] = (is_valid, errors)
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
        for filename, (is_valid, errors) in results.items():
            print(format_human_output(filename, is_valid, errors))
            print()  # Blank line between files

        # Summary for multiple files
        if len(results) > 1:
            valid_count = sum(1 for is_valid, _ in results.values() if is_valid)
            invalid_count = len(results) - valid_count
            print(f"Summary: {len(results)} file(s) checked, {valid_count} valid, {invalid_count} invalid")

    # Exit code: 0 if all valid, 1 if any invalid
    all_valid = all(is_valid for is_valid, _ in results.values())
    return 0 if all_valid else 1


if __name__ == '__main__':
    sys.exit(main())
