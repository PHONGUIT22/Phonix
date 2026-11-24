"""Deterministic Tree-sitter AST Slicer for Phonix v2.0 Context MMU.

Slices source code files into semantic AST frames strictly bounded to < 512 tokens per frame.
Extracts function, method, and class definitions along with caller/callee dependencies.
NO Z3 is used for code transpilation; purely deterministic AST slicing.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
from typing import Any

try:
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover
    class _FieldInfo:
        def __init__(self, default: Any = ..., default_factory: Any = None) -> None:
            self.default = default
            self.default_factory = default_factory

    def Field(default: Any = ..., default_factory: Any = None, **kwargs: Any) -> Any:  # type: ignore
        return _FieldInfo(default=default, default_factory=default_factory)

    class BaseModel:  # type: ignore
        def __init__(self, **kwargs: Any) -> None:
            for attr, val in self.__class__.__dict__.items():
                if isinstance(val, _FieldInfo):
                    if val.default_factory is not None:
                        setattr(self, attr, val.default_factory())
                    elif val.default is not ...:
                        setattr(self, attr, val.default)
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> dict[str, Any]:
            return self.__dict__


class ASTFrame(BaseModel):
    """A discrete semantic AST frame managed by Context MMU."""

    frame_id: str = Field(description="Deterministic ID (file_path::symbol_name::hash)")
    file_path: str = Field(description="Source file path")
    symbol_name: str = Field(description="Name of the function, class, or symbol")
    symbol_type: str = Field(
        default="function", description="Type of AST node: function, class, method, import"
    )
    start_line: int = Field(default=1, description="1-indexed starting line")
    end_line: int = Field(default=1, description="1-indexed ending line")
    token_count: int = Field(
        default=0, description="Estimated token count, guaranteed < 512 tokens"
    )
    raw_code: str = Field(default="", description="Source code text of this frame")
    docstring: str | None = Field(default=None, description="Extracted docstring if present")
    dependencies: list[str] = Field(
        default_factory=list, description="Symbols referenced or called by this frame"
    )
    relevance_score: float = Field(
        default=0.0, description="Dynamic relevance score for eviction/routing"
    )


class ASTSlicer:
    """Deterministic AST slicer enforcing < 512 tokens per semantic frame.

    Utilizes Tree-sitter where available and Python AST / token boundaries
    for deterministic semantic frame decomposition.
    """

    MAX_FRAME_TOKENS: int = 512
    APPROX_CHARS_PER_TOKEN: int = 4

    LANGUAGE_EXTENSIONS: dict[str, str] = {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".h": "c",
        ".hpp": "cpp",
    }

    BRACE_LANGUAGES: set[str] = {
        "typescript",
        "javascript",
        "go",
        "rust",
        "java",
        "c",
        "cpp",
    }

    KEYWORD_EXCLUSIONS: set[str] = {
        "if", "for", "while", "switch", "match", "return", "catch", "sizeof",
        "typeof", "instanceof", "new", "throw", "case", "let", "const", "var",
        "function", "fn", "func", "import", "from", "export", "type", "struct",
        "class", "interface", "package", "else", "println", "print", "fmt",
        "make", "len", "panic", "recover", "pub", "impl", "enum", "trait",
    }

    # TypeScript / JavaScript definitions
    TS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("function", re.compile(r"^\s*(?:export\s+|default\s+|declare\s+)*(?:async\s+)?function\s+([a-zA-Z0-9_$]+)")),
        ("class", re.compile(r"^\s*(?:export\s+|default\s+)*(?:abstract\s+)?class\s+([a-zA-Z0-9_$]+)")),
        ("interface", re.compile(r"^\s*(?:export\s+)?interface\s+([a-zA-Z0-9_$]+)")),
        ("type", re.compile(r"^\s*(?:export\s+)?type\s+([a-zA-Z0-9_$]+)\s*=")),
        ("function", re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_$]+)?\s*=>")),
    ]

    # Go definitions
    GO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("function", re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?([a-zA-Z0-9_]+)\s*\(")),
        ("struct", re.compile(r"^\s*type\s+([a-zA-Z0-9_]+)\s+(?:struct|interface)\b")),
    ]

    # Rust definitions
    RUST_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("function", re.compile(r"^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([a-zA-Z0-9_]+)")),
        ("struct", re.compile(r"^\s*(?:pub(?:\([^)]+\))?\s+)?(?:struct|enum|trait|union)\s+([a-zA-Z0-9_]+)")),
        ("impl", re.compile(r"^\s*impl(?:\s*<[^>]+>)?\s+(?:[a-zA-Z0-9_:]+\s+for\s+)?([a-zA-Z0-9_:]+)")),
    ]

    # Java / C / C++ definitions
    CPP_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("class", re.compile(r"^\s*(?:public|private|protected|static|final|abstract|\s)*class\s+([a-zA-Z0-9_]+)")),
        ("interface", re.compile(r"^\s*(?:public|private|protected|static|final|\s)*interface\s+([a-zA-Z0-9_]+)")),
        ("struct", re.compile(r"^\s*(?:typedef\s+)?(?:struct|enum)\s+([a-zA-Z0-9_]+)")),
        ("function", re.compile(r"^\s*(?:[a-zA-Z0-9_*&:<>]+\s+)+([a-zA-Z0-9_]+)\s*\([^;]*\)\s*(?:const)?\s*\{?")),
    ]

    def __init__(self, max_tokens_per_frame: int = 512) -> None:
        self.max_tokens_per_frame: int = min(max_tokens_per_frame, self.MAX_FRAME_TOKENS)
        self._ts_parsers: dict[str, Any] = {}

    def _get_tree_sitter_parser(self, language: str, file_path: str) -> Any | None:
        """Lazily resolves a Tree-sitter parser for TS/TSX/JS/JSX/Go/Rust if installed."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".tsx", ".jsx"):
            ts_lang = "tsx"
        elif language in ("typescript", "javascript", "go", "rust"):
            ts_lang = language
        else:
            return None

        if ts_lang in self._ts_parsers:
            return self._ts_parsers[ts_lang]

        parser = None
        try:
            import tree_sitter_language_pack as tslp  # type: ignore

            parser = tslp.get_parser(ts_lang)
        except Exception:
            try:
                import tree_sitter  # type: ignore

                lang_obj = None
                if ts_lang in ("typescript", "tsx"):
                    import tree_sitter_typescript as tst  # type: ignore

                    lang_fn = tst.language_tsx if ts_lang == "tsx" else tst.language_typescript
                    lang_obj = tree_sitter.Language(lang_fn())
                elif ts_lang == "javascript":
                    import tree_sitter_javascript as tsj  # type: ignore

                    lang_obj = tree_sitter.Language(tsj.language())
                elif ts_lang == "go":
                    import tree_sitter_go as tsg  # type: ignore

                    lang_obj = tree_sitter.Language(tsg.language())
                elif ts_lang == "rust":
                    import tree_sitter_rust as tsr  # type: ignore

                    lang_obj = tree_sitter.Language(tsr.language())

                if lang_obj is not None:
                    try:
                        parser = tree_sitter.Parser(lang_obj)
                    except TypeError:
                        parser = tree_sitter.Parser()
                        parser.set_language(lang_obj)
            except Exception:
                parser = None

        self._ts_parsers[ts_lang] = parser
        return parser

    def detect_language(self, file_path: str, default: str = "python") -> str:
        """Detects programming language from file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        return self.LANGUAGE_EXTENSIONS.get(ext, default)

    def estimate_tokens(self, text: str) -> int:
        """Heuristic token estimator (~4 chars per token for code/text)."""
        if not text:
            return 0
        return max(1, len(text) // self.APPROX_CHARS_PER_TOKEN)

    def generate_frame_id(self, file_path: str, symbol_name: str, code: str) -> str:
        """Generates a deterministic frame ID."""
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()[:8]
        return f"{file_path}::{symbol_name}::{digest}"

    def slice_file(self, file_path: str) -> list[ASTFrame]:
        """Reads a file from disk and slices it into AST frames."""
        if not os.path.exists(file_path):
            return []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
            return self.slice_code(code, file_path=file_path)
        except OSError:
            return []

    def slice_code(
        self, code: str, file_path: str = "<memory>", language: str | None = None
    ) -> list[ASTFrame]:
        """Slices source code into discrete AST frames with token budget enforcement.

        Detects language from file extension and routes to Python AST,
        brace-language AST parser, or generic text block fallback.
        """
        if not code.strip():
            return []

        lang = language or self.detect_language(file_path, default="python")

        if lang == "python" or file_path.endswith(".py"):
            return self._slice_python_ast(code, file_path)

        if lang in ("typescript", "javascript", "go", "rust"):
            ts_frames = self._slice_with_tree_sitter(code, file_path, lang)
            if ts_frames is not None:
                return ts_frames

        if lang in self.BRACE_LANGUAGES:
            return self._slice_brace_language_ast(code, file_path, lang)

        return self._slice_generic_text(code, file_path)

    def _slice_with_tree_sitter(
        self, code: str, file_path: str, language: str
    ) -> list[ASTFrame] | None:
        """Slices TS/TSX/JS/JSX/Go/Rust using Tree-sitter CST when grammars are installed."""
        parser = self._get_tree_sitter_parser(language, file_path)
        if parser is None:
            return None

        try:
            code_bytes = code.encode("utf-8", errors="replace")
            tree = parser.parse(code_bytes)
        except Exception:
            return None

        root = getattr(tree, "root_node", None)
        if root is None:
            return None

        lines = code.splitlines(keepends=True)
        frames: list[ASTFrame] = []

        def _node_text(n: Any) -> str:
            return code_bytes[n.start_byte : n.end_byte].decode("utf-8", errors="replace")

        def _find_name(n: Any) -> str | None:
            name_node = n.child_by_field_name("name") if hasattr(n, "child_by_field_name") else None
            if name_node is not None:
                return _node_text(name_node).strip()
            for ch in getattr(n, "children", []):
                if ch.type in ("identifier", "type_identifier", "property_identifier"):
                    return _node_text(ch).strip()
            return None

        def _extract_calls(n: Any, self_sym: str) -> list[str]:
            calls: set[str] = set()
            stack = [n]
            while stack:
                cur = stack.pop()
                if cur.type == "call_expression":
                    fn_node = cur.child_by_field_name("function") if hasattr(cur, "child_by_field_name") else None
                    if fn_node is not None:
                        txt = _node_text(fn_node).strip()
                        if txt and txt not in self.KEYWORD_EXCLUSIONS and txt != self_sym:
                            calls.add(txt.split(".")[-1] if "." in txt else txt)
                            if "." in txt:
                                calls.add(txt)
                stack.extend(getattr(cur, "children", []))
            return sorted(calls)

        decl_type_map = {
            "function_declaration": "function",
            "function_item": "function",
            "method_declaration": "function",
            "class_declaration": "class",
            "interface_declaration": "interface",
            "type_alias_declaration": "type",
            "struct_item": "struct",
            "enum_item": "struct",
            "trait_item": "interface",
            "impl_item": "impl",
        }

        for child in getattr(root, "children", []):
            target = child
            if child.type == "export_statement":
                for sub in getattr(child, "children", []):
                    if sub.type in decl_type_map or sub.type in ("lexical_declaration", "variable_declaration"):
                        target = sub
                        break

            sym_name: str | None = None
            sym_type: str = "function"

            if target.type in decl_type_map:
                sym_type = decl_type_map[target.type]
                if target.type == "impl_item":
                    type_node = target.child_by_field_name("type") if hasattr(target, "child_by_field_name") else None
                    sym_name = _node_text(type_node).strip() if type_node is not None else _find_name(target)
                else:
                    sym_name = _find_name(target)
            elif target.type == "type_declaration":
                for sub in getattr(target, "children", []):
                    if sub.type == "type_spec":
                        sym_name = _find_name(sub)
                        sub_txt = _node_text(sub)
                        sym_type = "interface" if "interface" in sub_txt else "struct"
                        break
            elif target.type in ("lexical_declaration", "variable_declaration"):
                for sub in getattr(target, "children", []):
                    if sub.type == "variable_declarator":
                        val_node = sub.child_by_field_name("value") if hasattr(sub, "child_by_field_name") else None
                        if val_node is not None and val_node.type in ("arrow_function", "function_expression", "function"):
                            sym_name = _find_name(sub)
                            sym_type = "function"
                            break

            if not sym_name:
                continue

            start_line = child.start_point[0] + 1
            end_line = min(len(lines), child.end_point[0] + 1)
            raw_code = "".join(lines[start_line - 1 : end_line])
            if not raw_code.strip():
                continue

            deps = _extract_calls(target, sym_name)
            token_count = self.estimate_tokens(raw_code)
            if token_count > self.max_tokens_per_frame:
                frames.extend(
                    self._subdivide_oversized_frame(
                        file_path=file_path,
                        symbol_name=sym_name,
                        raw_code=raw_code,
                        start_line=start_line,
                        dependencies=deps,
                    )
                )
            else:
                frames.append(
                    ASTFrame(
                        frame_id=self.generate_frame_id(file_path, sym_name, raw_code),
                        file_path=file_path,
                        symbol_name=sym_name,
                        symbol_type=sym_type,
                        start_line=start_line,
                        end_line=end_line,
                        token_count=token_count,
                        raw_code=raw_code,
                        dependencies=deps,
                    )
                )

        return frames if frames else None

    def _find_matching_brace_end(self, lines: list[str], start_idx: int) -> int:
        """Finds the ending line index (0-indexed) where braces balance to zero."""
        depth = 0
        found_open = False
        in_string = None
        in_block_comment = False

        for i in range(start_idx, min(len(lines), start_idx + 2000)):
            line = lines[i]
            j = 0
            line_len = len(line)
            while j < line_len:
                c = line[j]

                if in_block_comment:
                    if c == "*" and j + 1 < line_len and line[j + 1] == "/":
                        in_block_comment = False
                        j += 2
                        continue
                    j += 1
                    continue

                if in_string:
                    if c == "\\":
                        j += 2
                        continue
                    if c == in_string:
                        in_string = None
                    j += 1
                    continue

                if c == "/" and j + 1 < line_len:
                    if line[j + 1] == "/":
                        break
                    elif line[j + 1] == "*":
                        in_block_comment = True
                        j += 2
                        continue

                if c in ('"', "'", "`"):
                    in_string = c
                    j += 1
                    continue

                if c == "{":
                    depth += 1
                    found_open = True
                elif c == "}" and found_open:
                    depth -= 1
                    if depth == 0:
                        return i

                j += 1

            if not found_open and i - start_idx > 10:
                break

        return -1

    def _slice_brace_language_ast(
        self, code: str, file_path: str, language: str
    ) -> list[ASTFrame]:
        """Extracts semantic frames (functions, structs, interfaces, classes) from brace-delimited languages."""
        lines = code.splitlines(keepends=True)
        if not lines:
            return []

        patterns: list[tuple[str, re.Pattern[str]]] = []
        if language in ("typescript", "javascript"):
            patterns = self.TS_PATTERNS
        elif language == "go":
            patterns = self.GO_PATTERNS
        elif language == "rust":
            patterns = self.RUST_PATTERNS
        else:
            patterns = self.CPP_PATTERNS

        frames: list[ASTFrame] = []
        idx = 0
        n_lines = len(lines)

        while idx < n_lines:
            line = lines[idx]
            matched_sym: str | None = None
            matched_type: str = "function"

            for sym_type, pat in patterns:
                m = pat.match(line)
                if m:
                    matched_sym = m.group(1)
                    matched_type = sym_type
                    break

            if matched_sym:
                start_line = idx + 1
                end_idx = self._find_matching_brace_end(lines, idx)
                if end_idx != -1 and end_idx >= idx:
                    end_line = end_idx + 1
                    raw_code = "".join(lines[idx:end_line])

                    # Extract callee dependencies using regex
                    raw_calls = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", raw_code)
                    dependencies = sorted(
                        set(
                            d for d in raw_calls
                            if d not in self.KEYWORD_EXCLUSIONS and d != matched_sym
                        )
                    )

                    token_count = self.estimate_tokens(raw_code)

                    if token_count > self.max_tokens_per_frame:
                        sub_frames = self._subdivide_oversized_frame(
                            file_path=file_path,
                            symbol_name=matched_sym,
                            raw_code=raw_code,
                            start_line=start_line,
                            dependencies=dependencies,
                        )
                        frames.extend(sub_frames)
                    else:
                        frames.append(
                            ASTFrame(
                                frame_id=self.generate_frame_id(file_path, matched_sym, raw_code),
                                file_path=file_path,
                                symbol_name=matched_sym,
                                symbol_type=matched_type,
                                start_line=start_line,
                                end_line=end_line,
                                token_count=token_count,
                                raw_code=raw_code,
                                dependencies=dependencies,
                            )
                        )
                    idx = end_idx + 1
                    continue

            idx += 1

        if not frames:
            return self._slice_generic_text(code, file_path)

        return frames

    @staticmethod
    def _extract_python_dependencies(node: ast.AST, class_name: str | None = None) -> list[str]:
        """Extracts called symbols and attribute accesses from a Python AST node."""
        dependencies: list[str] = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                dependencies.append(sub.func.id)
            elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                dependencies.append(f"{sub.value.id}.{sub.attr}")
                if class_name and sub.value.id == "self":
                    dependencies.append(f"{class_name}.{sub.attr}")
        return sorted(set(dependencies))

    def _slice_python_ast(self, code: str, file_path: str) -> list[ASTFrame]:
        """Python-specific deterministic AST slicing using Python's native AST engine.

        Extracts top-level functions and decomposes classes into a concise
        `ClassName.__header__` frame plus method-level frames (`ClassName.method_name`).
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return self._slice_generic_text(code, file_path)

        lines = code.splitlines(keepends=True)
        frames: list[ASTFrame] = []

        def _append_bounded(
            symbol_name: str,
            symbol_type: str,
            start_line: int,
            end_line: int,
            docstring: str | None,
            dependencies: list[str],
        ) -> None:
            raw_code = "".join(lines[start_line - 1 : end_line])
            if not raw_code.strip():
                return
            token_count = self.estimate_tokens(raw_code)
            if token_count > self.max_tokens_per_frame:
                frames.extend(
                    self._subdivide_oversized_frame(
                        file_path=file_path,
                        symbol_name=symbol_name,
                        raw_code=raw_code,
                        start_line=start_line,
                        dependencies=dependencies,
                    )
                )
            else:
                frames.append(
                    ASTFrame(
                        frame_id=self.generate_frame_id(file_path, symbol_name, raw_code),
                        file_path=file_path,
                        symbol_name=symbol_name,
                        symbol_type=symbol_type,
                        start_line=start_line,
                        end_line=end_line,
                        token_count=token_count,
                        raw_code=raw_code,
                        docstring=docstring,
                        dependencies=dependencies,
                    )
                )

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = (
                    node.decorator_list[0].lineno if node.decorator_list else node.lineno
                )
                end_line = getattr(node, "end_lineno", node.lineno)
                _append_bounded(
                    symbol_name=node.name,
                    symbol_type="function",
                    start_line=start_line,
                    end_line=end_line,
                    docstring=ast.get_docstring(node),
                    dependencies=self._extract_python_dependencies(node),
                )
            elif isinstance(node, ast.ClassDef):
                cls_start = (
                    node.decorator_list[0].lineno if node.decorator_list else node.lineno
                )
                cls_end = getattr(node, "end_lineno", node.lineno)
                cls_doc = ast.get_docstring(node)
                methods = [
                    item for item in node.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]

                if not methods:
                    _append_bounded(
                        symbol_name=node.name,
                        symbol_type="class",
                        start_line=cls_start,
                        end_line=cls_end,
                        docstring=cls_doc,
                        dependencies=self._extract_python_dependencies(node, class_name=node.name),
                    )
                    continue

                first_method = methods[0]
                first_method_start = (
                    first_method.decorator_list[0].lineno
                    if first_method.decorator_list
                    else first_method.lineno
                )
                header_end = max(cls_start, first_method_start - 1)
                _append_bounded(
                    symbol_name=f"{node.name}.__header__",
                    symbol_type="class",
                    start_line=cls_start,
                    end_line=header_end,
                    docstring=cls_doc,
                    dependencies=[],
                )

                for item in methods:
                    m_start = (
                        item.decorator_list[0].lineno
                        if item.decorator_list
                        else item.lineno
                    )
                    m_end = getattr(item, "end_lineno", item.lineno)
                    _append_bounded(
                        symbol_name=f"{node.name}.{item.name}",
                        symbol_type="method",
                        start_line=m_start,
                        end_line=m_end,
                        docstring=ast.get_docstring(item),
                        dependencies=self._extract_python_dependencies(item, class_name=node.name),
                    )

        if not frames:
            return self._slice_generic_text(code, file_path)

        return frames

    def _subdivide_oversized_frame(
        self,
        file_path: str,
        symbol_name: str,
        raw_code: str,
        start_line: int,
        dependencies: list[str],
    ) -> list[ASTFrame]:
        """Splits an oversized symbol into valid sub-frames under max_tokens_per_frame."""
        lines = raw_code.splitlines(keepends=True)
        sub_frames: list[ASTFrame] = []
        chunk_lines: list[str] = []
        chunk_start = start_line
        part_idx = 1

        for line in lines:
            test_chunk = "".join(chunk_lines + [line])
            if self.estimate_tokens(test_chunk) >= self.max_tokens_per_frame and chunk_lines:
                chunk_code = "".join(chunk_lines)
                sub_symbol = f"{symbol_name}#part{part_idx}"
                sub_frames.append(
                    ASTFrame(
                        frame_id=self.generate_frame_id(file_path, sub_symbol, chunk_code),
                        file_path=file_path,
                        symbol_name=sub_symbol,
                        symbol_type="sub_block",
                        start_line=chunk_start,
                        end_line=chunk_start + len(chunk_lines) - 1,
                        token_count=self.estimate_tokens(chunk_code),
                        raw_code=chunk_code,
                        dependencies=dependencies,
                    )
                )
                chunk_start += len(chunk_lines)
                chunk_lines = [line]
                part_idx += 1
            else:
                chunk_lines.append(line)

        if chunk_lines:
            chunk_code = "".join(chunk_lines)
            sub_symbol = f"{symbol_name}#part{part_idx}"
            sub_frames.append(
                ASTFrame(
                    frame_id=self.generate_frame_id(file_path, sub_symbol, chunk_code),
                    file_path=file_path,
                    symbol_name=sub_symbol,
                    symbol_type="sub_block",
                    start_line=chunk_start,
                    end_line=chunk_start + len(chunk_lines) - 1,
                    token_count=self.estimate_tokens(chunk_code),
                    raw_code=chunk_code,
                    dependencies=dependencies,
                )
            )

        return sub_frames

    def _slice_generic_text(self, code: str, file_path: str) -> list[ASTFrame]:
        """Fallback chunker for non-python or unparseable files."""
        lines = code.splitlines(keepends=True)
        frames: list[ASTFrame] = []
        chunk: list[str] = []
        start_line = 1
        part_idx = 1

        for idx, line in enumerate(lines, 1):
            test_chunk = "".join(chunk + [line])
            if self.estimate_tokens(test_chunk) >= self.max_tokens_per_frame and chunk:
                raw_code = "".join(chunk)
                sym = f"chunk_{part_idx}"
                frames.append(
                    ASTFrame(
                        frame_id=self.generate_frame_id(file_path, sym, raw_code),
                        file_path=file_path,
                        symbol_name=sym,
                        symbol_type="block",
                        start_line=start_line,
                        end_line=idx - 1,
                        token_count=self.estimate_tokens(raw_code),
                        raw_code=raw_code,
                        dependencies=[],
                    )
                )
                start_line = idx
                chunk = [line]
                part_idx += 1
            else:
                chunk.append(line)

        if chunk:
            raw_code = "".join(chunk)
            sym = f"chunk_{part_idx}"
            frames.append(
                ASTFrame(
                    frame_id=self.generate_frame_id(file_path, sym, raw_code),
                    file_path=file_path,
                    symbol_name=sym,
                    symbol_type="block",
                    start_line=start_line,
                    end_line=len(lines),
                    token_count=self.estimate_tokens(raw_code),
                    raw_code=raw_code,
                    dependencies=[],
                )
            )

        return frames
