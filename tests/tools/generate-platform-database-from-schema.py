#!/usr/bin/env python3
"""
Generate platform property database from schema.

Platform code doesn't parse JSON directly - it receives structured data from proto.c
and applies it to hardware. This script searches for platform application patterns:
- config_*_apply() functions
- plat_*_set() functions
- gnma_*() hardware API calls

Usage:
    python3 generate-platform-database-from-schema.py <platform-file> <schema-properties> <output-file>

Example:
    python3 generate-platform-database-from-schema.py \
        ../../src/ucentral-client/platform/brcm-sonic/plat-gnma.c \
        /tmp/all-schema-properties.txt \
        /tmp/platform-database-new.c
"""

import re
import sys
from pathlib import Path
from typing import Optional, Tuple, Dict, List

def extract_property_components(property_path: str) -> Tuple[str, str, str]:
    """
    Extract components from property path.

    Returns:
        (top_level, mid_level, leaf) - e.g., ("ethernet", "poe", "admin-mode")
    """
    path = property_path.replace('[]', '')
    parts = path.split('.')

    top_level = parts[0] if len(parts) > 0 else ""
    mid_level = parts[1] if len(parts) > 1 else ""
    leaf = parts[-1] if len(parts) > 0 else ""

    return top_level, mid_level, leaf

def find_function_containing_line(source_lines: list, target_line: int) -> Optional[str]:
    """Find which function contains a given line number."""
    for i in range(target_line - 1, -1, -1):
        line = source_lines[i]
        # Look for function definition patterns
        match = re.search(r'^\s*(static\s+)?(int|void|struct\s+\w+\s+\*?)\s+(\w+)\s*\([^)]*\)\s*{?\s*$', line)
        if match:
            func_name = match.group(3)
            return func_name
    return None

def analyze_platform_code(source_file: Path) -> Dict[str, List[Tuple[int, str]]]:
    """
    Analyze platform code to find configuration application patterns.

    Returns:
        Dict mapping feature areas to list of (line_number, function_name) tuples
    """
    try:
        with open(source_file, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {source_file}: {e}", file=sys.stderr)
        return {}

    feature_map = {
        # STP/Loop Detection
        'loop-detection': [],
        'stp': [],
        'rstp': [],
        'mstp': [],

        # VLAN
        'vlan': [],

        # Port configuration
        'port': [],
        'ethernet': [],
        'speed': [],
        'duplex': [],
        'enabled': [],

        # PoE
        'poe': [],
        'power': [],

        # 802.1X
        'ieee8021x': [],
        'authenticator': [],
        'radius': [],

        # DHCP
        'dhcp': [],
        'relay': [],

        # Routing
        'routing': [],
        'route': [],
        'static': [],

        # Multicast/IGMP
        'igmp': [],
        'multicast': [],
        'querier': [],

        # Metrics
        'metrics': [],
        'health': [],
        'statistics': [],

        # Services
        'syslog': [],
        'log': [],

        # Port isolation
        'isolation': [],

        # Unit/System
        'unit': [],
        'threshold': [],
    }

    # Search for config_*_apply and plat_*_set functions
    function_patterns = [
        r'(config_\w+_apply|plat_\w+_set|plat_\w+_config)',
    ]

    for line_num, line in enumerate(lines, 1):
        # Find function definitions
        for pattern in function_patterns:
            match = re.search(r'^\s*(static\s+)?(int|void)\s+(' + pattern + r')\s*\(', line)
            if match:
                func_name = match.group(3)

                # Map function to feature areas based on name
                func_lower = func_name.lower()

                for feature, locations in feature_map.items():
                    if feature in func_lower:
                        locations.append((line_num, func_name))

    return feature_map

def find_property_in_platform(property_path: str, feature_map: Dict[str, List[Tuple[int, str]]]) -> Tuple[Optional[int], Optional[str]]:
    """
    Find which platform function likely handles this property.

    Returns:
        (line_number, function_name) or (None, None) if not found
    """
    top_level, mid_level, leaf = extract_property_components(property_path)

    # Search feature map for matching functions
    search_terms = [leaf, mid_level, top_level]
    search_terms = [term for term in search_terms if term]  # Remove empty

    for term in search_terms:
        term_lower = term.replace('-', '_').replace('-', '').lower()

        # Check if any feature matches
        for feature, locations in feature_map.items():
            if term_lower in feature or feature in term_lower:
                if locations:
                    # Return first matching function
                    return locations[0]

    return None, None

def generate_database_entry(property_path: str, line_num: Optional[int],
                           function: Optional[str], source_file: str) -> str:
    """Generate a C database entry for a property."""
    if line_num and function:
        status = "PROP_CONFIGURED"
        description = f"Applied in {function}()"
    else:
        status = "PROP_CONFIGURED"
        line_num = 0
        function = "NULL"
        description = "Not yet implemented in platform"

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
    print(f"Analyzing platform code: {source_file}", file=sys.stderr)

    # Analyze platform code to find configuration functions
    feature_map = analyze_platform_code(source_file)

    total_functions = sum(len(locations) for locations in feature_map.values())
    print(f"Found {total_functions} configuration functions in platform code", file=sys.stderr)

    # Find which function handles each property
    results = {}
    found_count = 0
    not_found_count = 0

    for i, prop in enumerate(properties, 1):
        if i % 50 == 0:
            print(f"  Processed {i}/{len(properties)} properties...", file=sys.stderr)

        line_num, function = find_property_in_platform(prop, feature_map)
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
        f.write(f" * Platform Property Database Generated from Schema\n")
        f.write(f" *\n")
        f.write(f" * Platform: brcm-sonic\n")
        f.write(f" * Source: {source_file}\n")
        f.write(f" * Properties: {len(properties)} from schema\n")
        f.write(f" * Found: {found_count} potentially implemented\n")
        f.write(f" * Not found: {not_found_count} not yet implemented\n")
        f.write(f" *\n")
        f.write(f" * This database tracks ALL properties in the uCentral schema.\n")
        f.write(f" * Platform code doesn't parse JSON - it applies structured config\n")
        f.write(f" * from proto.c to hardware. Functions are matched by feature area.\n")
        f.write(f" *\n")
        f.write(f" * Properties with line_number=0 are not yet implemented in platform.\n")
        f.write(f" */\n\n")
        f.write(f"static const struct property_metadata platform_property_database_brcm_sonic[] = {{\n")

        for entry in database_entries:
            f.write(entry + "\n")

        f.write(f"\n    /* Sentinel */\n")
        f.write(f'    {{NULL, PROP_CONFIGURED, NULL, NULL, 0, NULL}}\n')
        f.write(f"}};\n")

    print(f"\nDatabase written to: {output_file}", file=sys.stderr)
    print(f"  Total entries: {len(database_entries)}", file=sys.stderr)

if __name__ == "__main__":
    main()
