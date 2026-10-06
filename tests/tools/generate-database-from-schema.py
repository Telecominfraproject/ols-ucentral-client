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
from typing import Dict, List, Optional, Set, Tuple

GET_ITEM_RE = re.compile(
    r'cJSON_GetObjectItem(?:CaseSensitive)?\s*\(\s*[^,;]+?\s*,\s*"([^"]+)"\s*\)', re.S)
GET_ITEM_CALL_RE = re.compile(r'\bcJSON_GetObjectItem(?:CaseSensitive)?\s*\(')
IDENT_RE = re.compile(r'[A-Za-z_]\w*')


def strip_comments(text: str) -> str:
    """Blank out C comments, keeping newlines so line numbers stay valid."""
    def blank(m):
        return re.sub(r'[^\n]', ' ', m.group(0))
    return re.sub(r'/\*.*?\*/|//[^\n]*', blank, text, flags=re.S)


def call_args(text: str, open_paren: int) -> Tuple[List[str], int]:
    """Split the arguments of the call whose '(' is at open_paren; also return the index after ')'."""
    args, depth, start = [], 0, open_paren + 1
    i = open_paren
    while i < len(text):
        ch = text[i]
        if ch == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
        elif ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
            if depth == 0:
                args.append(text[start:i].strip())
                return args, i + 1
        elif ch == ',' and depth == 1:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    return args, len(text)


def rhs_expr(text: str, start: int) -> str:
    """The expression starting at start, ending at ';', ',' or an unmatched ')' (assignments in conditions)."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
        elif ch in '([{':
            depth += 1
        elif ch in ')]}':
            if depth == 0:
                break
            depth -= 1
        elif ch in ';,' and depth == 0:
            break
        i += 1
    return text[start:i].strip()


def strip_expr(expr: str) -> str:
    """Drop casts, address-of and redundant parentheses around an expression."""
    expr = expr.strip()
    while True:
        new = re.sub(r'^\(\s*(?:const\s+)?\w+\s*\*+\s*\)\s*', '', expr).lstrip('&').strip()
        if new.startswith('(') and new.endswith(')') and call_args(new, 0)[1] == len(new):
            new = new[1:-1].strip()
        if new == expr:
            return expr
        expr = new


class SourceIndex:
    """
    Traces which cJSON object each key is read from.

    For cJSON_GetObjectItem(obj, "leaf") the object expression is followed back
    through assignments, cJSON_ArrayForEach / ->child iteration, and function
    parameters to their call sites, and every parent key in the property path
    must be found along that chain. A bare leaf-name match is not enough:
    "enabled" read for ethernet[] says nothing about switch.rt-events.stp.

    This is regex-level analysis, not a C parser. Objects reached through
    struct fields, macros, or keys held in variables are not followed, so a
    miss means "not proven parsed", and a hit is backed by a concrete chain.
    """

    def __init__(self, source_file: Path):
        text = strip_comments(source_file.read_text())
        self.lines = text.split('\n')
        self.functions = self._find_functions()
        self.bodies: Dict[str, str] = {}
        self.params: Dict[str, List[str]] = {}
        # function -> [(line, key, object expression)]
        self.item_reads: Dict[str, List[Tuple[int, str, str]]] = {}
        # function -> {key: [line, ...]}
        self.reads: Dict[str, Dict[str, List[int]]] = {}

        for name, (first, last, header) in self.functions.items():
            body = '\n'.join(self.lines[first - 1:last])
            self.bodies[name] = body
            m = re.search(rf'\b{re.escape(name)}\s*\(', header)
            plist = call_args(header, m.end() - 1)[0] if m else []
            self.params[name] = [(IDENT_RE.findall(p) or [''])[-1] for p in plist]

            reads = []
            for m in GET_ITEM_CALL_RE.finditer(body):
                args, _ = call_args(body, m.end() - 1)
                if len(args) == 2:
                    lit = re.fullmatch(r'"([^"]+)"', args[1])
                    if lit:
                        reads.append((first + body.count('\n', 0, m.start()), lit.group(1), args[0]))
            self.item_reads[name] = reads
            keys: Dict[str, List[int]] = {}
            for line, key, _ in reads:
                keys.setdefault(key, []).append(line)
            self.reads[name] = keys

        # callee -> [(caller, [arg expressions])]
        self.call_sites: Dict[str, List[Tuple[str, List[str]]]] = {f: [] for f in self.functions}
        for caller, body in self.bodies.items():
            for callee in self.functions:
                for m in re.finditer(rf'(?<![\w.>]){re.escape(callee)}\s*\(', body):
                    self.call_sites[callee].append((caller, call_args(body, m.end() - 1)[0]))

    def _find_functions(self) -> Dict[str, Tuple[int, int, str]]:
        """
        Locate function bodies by brace depth. A '{' at depth 0 opens a
        function when the text since the previous top-level ';' or '}' looks
        like a definition: name(...) with no '=' (which would be an initializer).
        """
        code = re.sub(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'',
                      lambda m: ' ' * len(m.group(0)), '\n'.join(self.lines))
        code = re.sub(r'^[ \t]*#[^\n]*', lambda m: ' ' * len(m.group(0)), code, flags=re.M)
        functions: Dict[str, Tuple[int, int, str]] = {}
        depth = 0
        header_start = 0
        open_line = 0
        name = header = None
        line = 1
        for i, ch in enumerate(code):
            if ch == '\n':
                line += 1
            elif ch == '{':
                if depth == 0:
                    header = code[header_start:i]
                    m = re.search(r'([A-Za-z_]\w*)\s*\([^;]*\)\s*$', header, re.S)
                    name = m.group(1) if m and '=' not in header else None
                    open_line = line
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    if name:
                        functions[name] = (open_line, line, header)
                    header_start = i + 1
            elif ch == ';' and depth == 0:
                header_start = i + 1
        return functions

    def _sources(self, func: str, var: str) -> List[Tuple[str, str]]:
        """Expressions var may hold in func, as (function, expression) pairs."""
        body = self.bodies[func]
        v = re.escape(var)
        out = []
        for m in re.finditer(rf'(?<![\w.>]){v}\s*=(?!=)', body):
            rhs = rhs_expr(body, m.end())
            # Iteration over an array/object: elements share the container's path
            it = re.match(r'(.+?)\s*->\s*child\b', rhs) or \
                re.match(r'cJSON_GetArrayItem\s*\(\s*([^,]+),', rhs)
            out.append((func, it.group(1) if it else rhs))
        for m in re.finditer(rf'cJSON_ArrayForEach\s*\(\s*{v}\s*,', body):
            args, _ = call_args(body, m.end() - len(m.group(0)) + m.group(0).index('('))
            if len(args) == 2:
                out.append((func, args[1]))
        if var in self.params[func]:
            idx = self.params[func].index(var)
            for caller, args in self.call_sites[func]:
                if idx < len(args):
                    out.append((caller, args[idx]))
        return out

    def _resolves(self, func: str, expr: str, keys: Tuple[str, ...], seen: Set) -> bool:
        """True if expr in func is the object at path keys (outermost first)."""
        if not keys:
            return True
        expr = strip_expr(expr)
        state = (func, expr, keys)
        if state in seen:
            return False
        seen.add(state)

        m = GET_ITEM_CALL_RE.match(expr)
        if m:
            args, end = call_args(expr, m.end() - 1)
            lit = re.fullmatch(r'"([^"]+)"', args[1]) if len(args) == 2 else None
            if end == len(expr) and lit:
                return lit.group(1) == keys[-1] and \
                    self._resolves(func, args[0], keys[:-1], seen)
            return False
        if IDENT_RE.fullmatch(expr):
            return any(self._resolves(f, e, keys, seen) for f, e in self._sources(func, expr))
        return False

    def find_property(self, property_path: str) -> Tuple[Optional[int], Optional[str]]:
        """Return (line, function) of a read of this exact property path, or (None, None)."""
        keys = tuple(k for k in property_path.replace('[]', '').split('.') if k)
        if not keys:
            return None, None
        for func in sorted(self.functions, key=lambda f: self.functions[f][0]):
            for line, key, obj in self.item_reads[func]:
                if key == keys[-1] and self._resolves(func, obj, keys[:-1], set()):
                    return line, func
        return None, None

def generate_database_entry(property_path: str, line_num: Optional[int],
                           function: Optional[str], source_file: str) -> str:
    """Generate a C database entry for a property."""
    if line_num and function:
        status = "PROP_CONFIGURED"
        description = f"Parsed in {function}()"
    else:
        status = "PROP_IGNORED"
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

    index = SourceIndex(source_file)

    for i, prop in enumerate(properties, 1):
        if i % 50 == 0:
            print(f"  Processed {i}/{len(properties)} properties...", file=sys.stderr)

        line_num, function = index.find_property(prop)
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
