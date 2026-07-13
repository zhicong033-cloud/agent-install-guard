#!/usr/bin/env python3
"""
scan-ast.py - AST-based behavioral analysis + taint tracking for install-guard

Deterministic. No LLM. Uses Python's built-in `ast` module to analyze Python
files at the syntax level. Complements scan-code.sh (grep) by adding:

1. Behavioral analysis: eval/exec/subprocess with literal args -> low severity,
   with variable/tainted args -> high severity. This eliminates the biggest
   grep false-positive source.

2. Taint tracking: traces data flow from sources (input(), request.args,
   sys.argv, os.environ, open().read()) to sinks (eval, exec, os.system,
   subprocess with shell=True, SQL execution). Only flags when tainted data
   reaches a sink.

3. Context-aware severity: same function call gets different severity based
   on whether the argument is a constant, a local variable, or tainted input.

Output: JSON array of findings on stdout, same format as scan-code.sh:
  [{"category":"...","file":"...","line":N,"snippet":"...","severity":"high|medium|low"}]

Usage: scan-ast.py <source-directory>
"""

import ast
import json
import os
import sys
from collections import defaultdict

MAX_PER_CATEGORY = 20

# --- Taint sources ----------------------------------------------------------
# Functions/attributes that return user-controlled or external data
TAINT_SOURCES = {
    "input",                    # builtin input()
    "request",                  # Flask/Django request object
    "getrequest",               # various HTTP request getters
    "args",                     # request.args
    "form",                     # request.form
    "cookies",                  # request.cookies
    "headers",                  # request.headers
    "getenv",                   # os.getenv()
    "environ",                  # os.environ
    "argv",                     # sys.argv
    "read",                     # file.read() - could be external data
    "readline",                 # file.readline()
    "readlines",                # file.readlines()
    "getvalue",                 # cgi.FieldStorage.getvalue()
    "GET",                      # request.GET (Django)
    "POST",                     # request.POST (Django)
    "QUERY_STRING",             # CGI
    "stdin",                    # sys.stdin
}

# --- Dangerous sinks --------------------------------------------------------
# Functions where tainted data should never flow
TAINT_SINKS = {
    "eval": "high",
    "exec": "high",
    "compile": "medium",
    "os": {
        "system": "high",
        "popen": "high",
    },
    "subprocess": {
        "call": "high",
        "run": "high",
        "Popen": "high",
        "check_output": "high",
        "check_call": "high",
    },
    "commands": {
        "getoutput": "high",
        "getstatusoutput": "high",
    },
    "popen": "high",
}

# --- Behavioral analysis: dangerous calls -----------------------------------
# AST node types for dangerous function calls
DANGEROUS_CALLS = {
    "eval": "dynamic_exec",
    "exec": "dynamic_exec",
    "compile": "dynamic_exec",
    "__import__": "dynamic_exec",
    "globals": "dynamic_exec",
    "locals": "dynamic_exec",
}

# os.system, os.popen, subprocess.* with shell=True
OS_DANGEROUS = {"system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe"}
SUBPROCESS_DANGEROUS = {"call", "run", "Popen", "check_output", "check_call"}

# --- File collection --------------------------------------------------------

EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", "vendor", "target",
    ".venv", "venv", "dist", "build", "test", "tests", "__tests__",
    "spec", "specs", "examples", "example", "demo", "fixtures", "mocks",
}

EXCLUDE_EXTENSIONS = {
    ".min.js", ".min.css", ".bundle.js", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
    ".gz", ".tar",
}


def find_python_files(source_dir):
    """Find all .py files, excluding noise directories."""
    result = []
    for root, dirs, files in os.walk(source_dir):
        # Filter excluded dirs in-place (prunes the walk)
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fname in files:
            if fname.endswith(".py"):
                # Skip test files
                if fname.startswith("test_") or fname == "tests.py":
                    continue
                filepath = os.path.join(root, fname)
                result.append(filepath)
    return result


def get_relative_path(filepath, source_dir):
    """Get path relative to source directory."""
    rel = os.path.relpath(filepath, source_dir)
    return rel


def get_source_segment(source, lineno, context=0):
    """Get the source line at lineno, truncated to 200 chars."""
    lines = source.split("\n")
    if 0 <= lineno - 1 < len(lines):
        line = lines[lineno - 1].strip()
        if len(line) > 200:
            return line[:200] + "..."
        return line
    return ""


# --- Taint tracker ----------------------------------------------------------

class TaintTracker:
    """
    Tracks which variables are tainted (contain user/external input).
    Uses simple intraprocedural dataflow analysis.
    """

    def __init__(self):
        self.tainted_vars = set()
        # Map function name -> whether it returns tainted data
        self.taint_returning_funcs = set()

    def is_tainted(self, node):
        """Check if an AST node represents tainted data."""
        if node is None:
            return False

        # Name node: check if it's in tainted set
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars

        # Attribute access: check if the attribute is a known source
        if isinstance(node, ast.Attribute):
            # os.environ, sys.argv, request.args etc.
            if node.attr in TAINT_SOURCES:
                return True
            # Check if the value chain leads to a source or tainted var
            return self.is_tainted(node.value)

        # Subscript: request['key'], os.environ['KEY']
        if isinstance(node, ast.Subscript):
            return self.is_tainted(node.value)

        # Call: input(), request.get(), os.getenv(), raw.strip()
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            if func_name in TAINT_SOURCES:
                return True
            # Check if calling a known taint-returning function
            if func_name in self.taint_returning_funcs:
                return True
            # open().read() pattern
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "read" and isinstance(node.func.value, ast.Call):
                    if self._get_call_name(node.func.value.func) == "open":
                        return True
                # Method calls on tainted objects: raw.strip(), data.upper(),
                # request.args.get("key"), user_input.split()
                # The object the method is called on may be tainted
                if self.is_tainted(node.func.value):
                    return True
            return False

        # BinOp: string concatenation with tainted data
        if isinstance(node, ast.BinOp):
            return self.is_tainted(node.left) or self.is_tainted(node.right)

        # JoinedStr (f-string): check if any value is tainted
        if isinstance(node, ast.JoinedStr):
            return any(self.is_tainted(v.value) for v in node.values if hasattr(v, "value"))

        # FormattedValue (f-string expression)
        if isinstance(node, ast.FormattedValue):
            return self.is_tainted(node.value)

        # IfExp: ternary - tainted if either branch is tainted
        if isinstance(node, ast.IfExp):
            return self.is_tainted(node.body) or self.is_tainted(node.orelse)

        return False

    def _get_call_name(self, func_node):
        """Extract function name from a Call's func attribute."""
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            return func_node.attr
        return ""

    def mark_tainted(self, var_name):
        """Mark a variable as tainted."""
        self.tainted_vars.add(var_name)

    def reset(self):
        """Reset tainted state (call per function)."""
        self.tainted_vars.clear()


# --- AST Analyzer -----------------------------------------------------------

class ASTAnalyzer(ast.NodeVisitor):
    """Analyzes a Python AST for security issues."""

    def __init__(self, filepath, source):
        self.filepath = filepath
        self.source = source
        self.findings = []
        self.tracker = TaintTracker()

    def add_finding(self, category, lineno, snippet, severity):
        self.findings.append({
            "category": category,
            "file": self.filepath,
            "line": lineno,
            "snippet": snippet,
            "severity": severity,
        })

    def get_source_line(self, lineno):
        return get_source_segment(self.source, lineno)

    # --- Visit assignments: track taint propagation ---

    def visit_Assign(self, node):
        # Check if RHS is tainted, mark LHS variables
        if self.tracker.is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tracker.mark_tainted(target.id)
                # Tuple unpacking: a, b = input(), x
                elif isinstance(target, (ast.Tuple, ast.List)):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tracker.mark_tainted(elt.id)
        self.generic_visit(node)

    # --- Visit with/for: track taint in loops and context managers ---

    def visit_For(self, node):
        # for x in input().split(): -> x is tainted
        if self.tracker.is_tainted(node.iter):
            if isinstance(node.target, ast.Name):
                self.tracker.mark_tainted(node.target.id)
        self.generic_visit(node)

    def visit_With(self, node):
        # with open(...) as f: -> f.read() is tainted (handled in call detection)
        self.generic_visit(node)

    # --- Visit function definitions: reset taint, check args ---

    def visit_FunctionDef(self, node):
        # Save and reset taint state for each function
        old_tainted = self.tracker.tainted_vars.copy()
        self.tracker.reset()

        # Function parameters that are likely user input
        for arg in node.args.args:
            if arg.arg in ("request", "req", "input_data", "data", "payload",
                           "body", "query", "params", "user_input", "user_data"):
                self.tracker.mark_tainted(arg.arg)

        self.generic_visit(node)

        # Restore
        self.tracker.tainted_vars = old_tainted

    visit_AsyncFunctionDef = visit_FunctionDef

    # --- Visit calls: check for dangerous sinks ---

    def visit_Call(self, node):
        func_name = self.tracker._get_call_name(node.func)
        lineno = node.lineno
        snippet = self.get_source_line(lineno)

        # --- eval / exec / compile ---
        if func_name in ("eval", "exec", "compile"):
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant):
                    # Literal argument: safe eval("1+1") -> low severity
                    self.add_finding("dynamic_exec", lineno, snippet, "low")
                elif self.tracker.is_tainted(arg):
                    # Tainted data flowing to eval/exec -> critical
                    self.add_finding("dynamic_exec", lineno, snippet, "high")
                else:
                    # Variable argument: medium risk (could be tainted via
                    # complex path we don't track)
                    self.add_finding("dynamic_exec", lineno, snippet, "medium")
            self.generic_visit(node)
            return

        # --- __import__ with dynamic module name ---
        if func_name == "__import__":
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.add_finding("dynamic_exec", lineno, snippet, "medium")
            self.generic_visit(node)
            return

        # --- getattr with dynamic attribute (reflection escape) ---
        if func_name == "getattr":
            if len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
                self.add_finding("dynamic_exec", lineno, snippet, "medium")
            self.generic_visit(node)
            return

        # --- os.system / os.popen ---
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            # Check if it's os.XXX or imported from os
            if attr in OS_DANGEROUS:
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant):
                        self.add_finding("dynamic_exec", lineno, snippet, "medium")
                    elif self.tracker.is_tainted(arg):
                        self.add_finding("dynamic_exec", lineno, snippet, "high")
                    else:
                        self.add_finding("dynamic_exec", lineno, snippet, "high")
                self.generic_visit(node)
                return

            # --- subprocess.call/run/Popen with shell=True ---
            if attr in SUBPROCESS_DANGEROUS:
                # Check for shell=True keyword
                shell_true = False
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            shell_true = True
                    elif kw.arg == "shell" and isinstance(kw.value, ast.Name):
                        if kw.value.id in self.tracker.tainted_vars:
                            shell_true = True  # shell=variable is risky

                if shell_true:
                    if node.args and self.tracker.is_tainted(node.args[0]):
                        self.add_finding("dynamic_exec", lineno, snippet, "high")
                    elif node.args and isinstance(node.args[0], ast.Constant):
                        self.add_finding("dynamic_exec", lineno, snippet, "medium")
                    else:
                        self.add_finding("dynamic_exec", lineno, snippet, "high")
                self.generic_visit(node)
                return

            # --- .system() on subprocess module ---
            if attr == "system" and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "subprocess":
                    self.add_finding("dynamic_exec", lineno, snippet, "high")

        # --- open() of sensitive files ---
        if func_name == "open" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                filepath = arg.value.lower()
                sensitive_paths = [
                    ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/authorized_keys",
                    ".aws/credentials", ".env", ".netrc", ".gnupg/",
                    ".npmrc", ".pypirc", ".kube/config", ".git-credentials",
                    ".docker/config.json", "credentials.json",
                    "/etc/shadow", "/etc/passwd",
                ]
                for sp in sensitive_paths:
                    if sp in filepath:
                        self.add_finding("sensitive_access", lineno, snippet, "high")
                        break

        self.generic_visit(node)


# --- Main -------------------------------------------------------------------

def analyze_file(filepath, source_dir):
    """Analyze a single Python file, return list of findings."""
    rel_path = get_relative_path(filepath, source_dir)
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception:
        return []

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        # Can't parse (maybe not valid Python or different version)
        return []

    analyzer = ASTAnalyzer(rel_path, source)
    analyzer.visit(tree)
    return analyzer.findings


def main():
    source_dir = sys.argv[1] if len(sys.argv) > 1 else ""
    if not source_dir or not os.path.isdir(source_dir):
        print(json.dumps({"error": "crash", "message": "source directory not provided or does not exist"}))
        sys.exit(0)

    all_findings = []
    counts = defaultdict(int)

    for filepath in find_python_files(source_dir):
        findings = analyze_file(filepath, source_dir)
        for f in findings:
            counts[f["category"]] += 1
            if counts[f["category"]] <= MAX_PER_CATEGORY:
                all_findings.append(f)

    # Add truncation markers
    for cat, total in sorted(counts.items()):
        if total > MAX_PER_CATEGORY:
            all_findings.append({"truncated": True, "category": cat, "total": total})

    print(json.dumps(all_findings, ensure_ascii=False))


if __name__ == "__main__":
    main()
