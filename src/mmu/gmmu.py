"""Public AST-based G-MMU Context Rendering Engine.

Generates 4-layer Mipmap Resolution context bundles (L0 - L3):
- L0: Ghost scope overview (file path, line count, byte size, language, imports summary).
- L1: Structural outline (symbols & dependencies):
  - Python: AST-parsed classes, methods (as Class.method(args)), top-level functions, first-line docstrings.
  - JS/TS: regex-extracted classes, methods, functions, types, interfaces.
  - Capped at ~40 entries with truncation notice.
- L2: Enclosing context & scope isolation:
  - If target window is inside a class: class declaration line + constructor (__init__ / constructor).
  - If inside top-level function: function signature line.
  - If module level: module level scope note.
- L3: Verbatim edit window with 1-based line numbers preserving exact copy-pasteable lines.
"""

from __future__ import annotations

import ast
from pathlib import Path
import re
from typing import Any


def detect_language(file_path: str) -> str:
    """Detects programming language from file extension."""
    ext = Path(file_path).suffix.lower()
    if ext == ".py":
        return "Python"
    if ext in (".ts", ".tsx"):
        return "TypeScript"
    if ext in (".js", ".jsx", ".mjs", ".cjs"):
        return "JavaScript"
    if ext == ".rs":
        return "Rust"
    if ext == ".go":
        return "Go"
    if ext == ".json":
        return "JSON"
    if ext in (".html", ".htm"):
        return "HTML"
    if ext == ".css":
        return "CSS"
    if ext == ".md":
        return "Markdown"
    return "Unknown"


def _format_py_args(args: ast.arguments) -> str:
    """Formats Python AST argument list into a concise parameter signature."""
    params: list[str] = []
    posonly = getattr(args, "posonlyargs", [])
    for a in posonly:
        params.append(a.arg)
    if posonly:
        params.append("/")
    for a in args.args:
        params.append(a.arg)
    if args.vararg:
        params.append(f"*{args.vararg.arg}")
    for a in args.kwonlyargs:
        params.append(a.arg)
    if args.kwarg:
        params.append(f"**{args.kwarg.arg}")
    return "(" + ", ".join(params) + ")"


def _extract_python_symbols(all_content: str) -> list[str]:
    """Extracts classes, Class.method(args), top-level functions, and first-line docstrings via AST."""
    symbols: list[str] = []
    try:
        tree = ast.parse(all_content)
    except SyntaxError:
        return _extract_regex_symbols(all_content)

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            base_names = [b.id for b in node.bases if isinstance(b, ast.Name)]
            bases_str = f"({', '.join(base_names)})" if base_names else ""
            doc = ast.get_docstring(node)
            first_doc = f"  # {doc.strip().splitlines()[0]}" if doc else ""
            symbols.append(f"class {node.name}{bases_str}{first_doc}")
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    m_args = _format_py_args(item.args)
                    m_doc = ast.get_docstring(item)
                    m_first_doc = f"  # {m_doc.strip().splitlines()[0]}" if m_doc else ""
                    prefix = "async " if isinstance(item, ast.AsyncFunctionDef) else ""
                    symbols.append(f"  {prefix}{node.name}.{item.name}{m_args}{m_first_doc}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            f_args = _format_py_args(node.args)
            f_doc = ast.get_docstring(node)
            f_first_doc = f"  # {f_doc.strip().splitlines()[0]}" if f_doc else ""
            prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
            symbols.append(f"{prefix}def {node.name}{f_args}{f_first_doc}")

    return symbols


def _extract_jsts_symbols(content: str) -> list[str]:
    """Extracts classes, interfaces, types, functions, and Class.method signatures from JS/TS."""
    symbols: list[str] = []
    lines = content.splitlines()
    current_class: str | None = None
    brace_depth = 0
    class_brace_depth = 0

    for line in lines:
        stripped = line.strip()
        # Class declaration
        cls_m = re.match(r"^(?:export\s+)?(?:default\s+)?class\s+([A-Za-z0-9_$]+)", stripped)
        if cls_m:
            current_class = cls_m.group(1)
            symbols.append(f"class {current_class}")
            class_brace_depth = brace_depth

        # Interface declaration
        iface_m = re.match(r"^(?:export\s+)?interface\s+([A-Za-z0-9_$]+)", stripped)
        if iface_m:
            symbols.append(f"interface {iface_m.group(1)}")

        # Type declaration
        type_m = re.match(r"^(?:export\s+)?type\s+([A-Za-z0-9_$]+)\s*=", stripped)
        if type_m:
            symbols.append(f"type {type_m.group(1)}")

        # Top-level function
        fn_m = re.match(
            r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*(\([^)]*\))",
            stripped,
        )
        if fn_m and not current_class:
            symbols.append(f"function {fn_m.group(1)}{fn_m.group(2)}")

        # Arrow function constant
        arrow_m = re.match(
            r"^(?:export\s+)?(?:const|let)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?(\([^)]*\))\s*=>",
            stripped,
        )
        if arrow_m and not current_class:
            symbols.append(f"const {arrow_m.group(1)} = {arrow_m.group(2)} => ...")

        # Method inside class
        if current_class and brace_depth > class_brace_depth:
            meth_m = re.match(
                r"^(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*([A-Za-z0-9_$]+)\s*(\([^)]*\))\s*(?::\s*[^{]+)?\{",
                stripped,
            )
            if meth_m:
                mname = meth_m.group(1)
                if mname not in ("if", "for", "while", "switch", "catch", "function", "return"):
                    symbols.append(f"  {current_class}.{mname}{meth_m.group(2)}")

        brace_depth += line.count("{") - line.count("}")
        if current_class and brace_depth <= class_brace_depth:
            current_class = None

    return symbols


def _extract_regex_symbols(content: str) -> list[str]:
    """Fallback symbol extractor for other languages or unparseable source files."""
    symbols: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if (
            re.match(r"^(?:async\s+)?def\s+[a-zA-Z0-9_]+", stripped)
            or re.match(r"^class\s+[a-zA-Z0-9_]+", stripped)
            or re.match(r"^(?:export\s+)?(?:function|class|interface|type)\s+", stripped)
            or re.match(r"^(?:pub\s+)?(?:fn|func)\s+", stripped)
        ):
            symbols.append(stripped)
    return symbols


def _extract_imports_summary(all_content: str, language: str) -> str:
    """Summarizes imported modules/packages."""
    if language == "Python":
        try:
            tree = ast.parse(all_content)
            imported_mods: set[str] = set()
            for node in tree.body:
                if isinstance(node, ast.Import):
                    for n in node.names:
                        imported_mods.add(n.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported_mods.add(node.module.split(".")[0])
            if imported_mods:
                return ", ".join(sorted(imported_mods)[:12])
        except SyntaxError:
            pass

    # Regex fallback for imports (JS/TS, Python syntax errors, Rust, Go)
    imports: list[str] = []
    for line in all_content.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            imports.append(stripped)
        elif "require(" in stripped:
            imports.append(stripped)
        if len(imports) >= 8:
            break

    if imports:
        return "; ".join(imports[:5])
    return "(no imports found)"


def _find_enclosing_context(
    all_content: str,
    start_line: int,
    end_line: int,
    language: str,
) -> str:
    """Extracts L2 enclosing context: class header + constructor, or function signature, or module scope."""
    lines = all_content.splitlines()

    if language == "Python":
        try:
            tree = ast.parse(all_content)
            # Find innermost class containing start_line
            enclosing_class: ast.ClassDef | None = None
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    end_l = getattr(node, "end_lineno", node.lineno + 1000)
                    if node.lineno <= start_line <= end_l:
                        enclosing_class = node
                        break

            if enclosing_class:
                cls_decl = lines[enclosing_class.lineno - 1].strip()
                ctor_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
                for item in enclosing_class.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__init__":
                        ctor_node = item
                        break

                res_parts = [f"Enclosing Class: {cls_decl}"]
                if ctor_node:
                    ctor_end = getattr(ctor_node, "end_lineno", ctor_node.lineno + 8)
                    ctor_lines = lines[ctor_node.lineno - 1 : min(ctor_end, ctor_node.lineno + 10)]
                    res_parts.append("Constructor:\n" + "\n".join(ctor_lines))
                return "\n".join(res_parts)

            # Check if inside top-level function
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end_l = getattr(node, "end_lineno", node.lineno + 500)
                    if node.lineno <= start_line <= end_l:
                        fn_sig = lines[node.lineno - 1].strip()
                        return f"Enclosing Function: {fn_sig}"

        except SyntaxError:
            pass

    elif language in ("TypeScript", "JavaScript"):
        # Backwards scan for enclosing class
        enclosing_class_decl: str | None = None
        for i in range(min(start_line - 1, len(lines) - 1), -1, -1):
            stripped = lines[i].strip()
            if re.match(r"^(?:export\s+)?(?:default\s+)?class\s+[A-Za-z0-9_$]+", stripped):
                enclosing_class_decl = stripped
                break

        if enclosing_class_decl:
            res_parts = [f"Enclosing Class: {enclosing_class_decl}"]
            # Find constructor in file
            for i, line in enumerate(lines):
                if re.search(r"\bconstructor\s*\(", line):
                    ctor_lines: list[str] = []
                    depth = 0
                    for l in lines[i : min(len(lines), i + 15)]:
                        ctor_lines.append(l)
                        depth += l.count("{") - l.count("}")
                        if depth <= 0 and "}" in l:
                            break
                    res_parts.append("Constructor:\n" + "\n".join(ctor_lines))
                    break
            return "\n".join(res_parts)

        # Check top-level function
        for i in range(min(start_line - 1, len(lines) - 1), -1, -1):
            stripped = lines[i].strip()
            if re.match(r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+[A-Za-z0-9_$]+", stripped):
                return f"Enclosing Function: {stripped}"

    return "Module level scope (no enclosing class or function)"


def render_gmmu_bundle(
    file_path: str,
    all_content: str,
    start_line: int,
    end_line: int,
    target_snippet: str | None = None,
    committed: bool = False,
) -> str:
    """Renders a 4-layer G-MMU Context Bundle (L0 - L3) for a given file and line range.

    Layers:
    - L0: Ghost scope overview (file path, line count, byte size, language, imports summary).
    - L1: Structural outline (symbols & dependencies, capped at ~40 entries).
    - L2: Enclosing context & scope isolation (class header + constructor, or function, or module scope).
    - L3: Verbatim edit window with 1-based line numbers.
    """
    norm_path = file_path.replace("\\", "/")
    lines = all_content.splitlines()
    total_lines = len(lines)
    byte_size = len(all_content.encode("utf-8"))
    language = detect_language(norm_path)

    s_line = max(1, start_line)
    e_line = min(total_lines, max(s_line, end_line))
    line_range_str = f"[Lines {s_line}-{e_line}]"

    # --- L0: Ghost Scope Overview ---
    imports_summary = _extract_imports_summary(all_content, language)
    committed_banner = "\n[G-MMU L3 -> L1: Committed & Verified]" if committed else ""
    l0 = (
        f"=== [G-MMU L0: Ghost Scope Overview] ==={committed_banner}\n"
        f"File: {norm_path} ({total_lines} total lines, {byte_size} bytes, Language: {language})\n"
        f"Imports: {imports_summary}"
    )

    # --- L1: Structural Outline (Symbols & Dependencies) ---
    if language == "Python":
        raw_symbols = _extract_python_symbols(all_content)
    elif language in ("TypeScript", "JavaScript"):
        raw_symbols = _extract_jsts_symbols(all_content)
    else:
        raw_symbols = _extract_regex_symbols(all_content)

    max_symbols = 40
    if len(raw_symbols) > max_symbols:
        remaining = len(raw_symbols) - max_symbols
        displayed_symbols = raw_symbols[:max_symbols] + [f"... and {remaining} more symbols"]
    elif raw_symbols:
        displayed_symbols = raw_symbols
    else:
        displayed_symbols = ["# (no symbols detected)"]

    l1 = (
        "=== [G-MMU L1: Structural Outline (Symbols & Dependencies)] ===\n"
        + "\n".join(displayed_symbols)
    )

    # --- L2: Enclosing Context & Scope Isolation ---
    enclosing_text = _find_enclosing_context(all_content, s_line, e_line, language)
    l2 = f"=== [G-MMU L2: Enclosing Context & Scope Isolation] ===\n{enclosing_text}"

    # --- L3: Verbatim Edit Window ---
    if target_snippet is not None:
        verbatim_code = target_snippet
    else:
        verbatim_code = "\n".join(lines[s_line - 1 : e_line]) if lines else ""

    l3 = (
        f"=== [G-MMU L3: Verbatim Edit Window: {norm_path} {line_range_str}] ===\n"
        f"=== Verbatim Edit Window: {norm_path} {line_range_str} ===\n"
        f"{verbatim_code}"
    )

    return f"{l0}\n\n{l1}\n\n{l2}\n\n{l3}"


def render_gmmu_grouped_bundle(
    file_path: str,
    all_content: str,
    windows: list[tuple[int, int, str | None]],
    committed: bool = False,
    detail: str = "standard",
) -> str:
    """Renders one or more verbatim windows for a single file without duplicating L0/L1/L2.

    - detail="minimal": emits concise 1-line header `--- <rel_path> [Lines X-Y / Total Z] ---`
      + exact verbatim source lines.
    - detail="standard" | "full": renders L0 + L1 + L2 once per file, followed by all
      [Lines X-Y] verbatim windows for that file.
    """
    norm_path = file_path.replace("\\", "/")
    lines = all_content.splitlines()
    total_lines = len(lines)
    committed_tag = " [Committed]" if committed else ""

    if detail == "minimal":
        parts: list[str] = []
        for start_line, end_line, target_snippet in windows:
            s_line = max(1, start_line)
            e_line = min(total_lines, max(s_line, end_line))
            verbatim_code = (
                target_snippet
                if target_snippet is not None
                else ("\n".join(lines[s_line - 1 : e_line]) if lines else "")
            )
            parts.append(
                f"--- {norm_path} [Lines {s_line}-{e_line} / Total {total_lines}]{committed_tag} ---\n"
                f"{verbatim_code}"
            )
        return "\n\n".join(parts)

    if not windows:
        return ""

    byte_size = len(all_content.encode("utf-8"))
    language = detect_language(norm_path)
    imports_summary = _extract_imports_summary(all_content, language)
    committed_banner = "\n[G-MMU L3 -> L1: Committed & Verified]" if committed else ""
    l0 = (
        f"=== [G-MMU L0: Ghost Scope Overview] ==={committed_banner}\n"
        f"File: {norm_path} ({total_lines} total lines, {byte_size} bytes, Language: {language})\n"
        f"Imports: {imports_summary}"
    )

    if language == "Python":
        raw_symbols = _extract_python_symbols(all_content)
    elif language in ("TypeScript", "JavaScript"):
        raw_symbols = _extract_jsts_symbols(all_content)
    else:
        raw_symbols = _extract_regex_symbols(all_content)

    max_symbols = 20 if detail == "standard" else 40
    if len(raw_symbols) > max_symbols:
        remaining = len(raw_symbols) - max_symbols
        displayed_symbols = raw_symbols[:max_symbols] + [f"... and {remaining} more symbols"]
    elif raw_symbols:
        displayed_symbols = raw_symbols
    else:
        displayed_symbols = ["# (no symbols detected)"]

    l1 = (
        "=== [G-MMU L1: Structural Outline (Symbols & Dependencies)] ===\n"
        + "\n".join(displayed_symbols)
    )

    first_s = max(1, windows[0][0])
    first_e = min(total_lines, max(first_s, windows[0][1]))
    enclosing_text = _find_enclosing_context(all_content, first_s, first_e, language)
    l2 = f"=== [G-MMU L2: Enclosing Context & Scope Isolation] ===\n{enclosing_text}"

    l3_parts: list[str] = []
    for start_line, end_line, target_snippet in windows:
        s_line = max(1, start_line)
        e_line = min(total_lines, max(s_line, end_line))
        line_range_str = f"[Lines {s_line}-{e_line}]"
        verbatim_code = (
            target_snippet
            if target_snippet is not None
            else ("\n".join(lines[s_line - 1 : e_line]) if lines else "")
        )
        l3_parts.append(
            f"=== [G-MMU L3: Verbatim Edit Window: {norm_path} {line_range_str}] ===\n"
            f"=== Verbatim Edit Window: {norm_path} {line_range_str} ===\n"
            f"{verbatim_code}"
        )

    return f"{l0}\n\n{l1}\n\n{l2}\n\n" + "\n\n".join(l3_parts)
