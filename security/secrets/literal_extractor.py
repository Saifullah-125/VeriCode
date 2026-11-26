"""Phase 2: Syntax-aware literal extraction across C, C++, Python, and Java."""

import ast
import io
import re
import tokenize
from dataclasses import dataclass
from typing import List, Tuple

try:
    from compiler.c_cpp_lexer import build_c_lexer
except Exception:
    build_c_lexer = None


@dataclass
class ExtractedLiteral:
    value: str
    raw_snippet: str
    line: int
    column: int
    language: str
    context_name: str = ""
    context_kind: str = "literal"
    is_env_lookup: bool = False


_ENV_CALL_NAMES = {
    "getenv",
    "environ",
    "get",
    "getproperty",
    "get_secret",
    "secret",
    "vault",
}

_IDENTIFIER_BEFORE_EQ_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*(?:=|:)\s*$"
)
_FUNC_CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\s*\([^()]*$")


def _infer_line_context(line_text: str, col_zero_based: int) -> Tuple[str, str, bool]:
    prefix = line_text[:max(0, col_zero_based)]
    lower_line = line_text.lower()
    is_env = any(fn in lower_line for fn in ("getenv(", "os.environ", "system.getenv", "process.env"))

    eq_match = _IDENTIFIER_BEFORE_EQ_RE.search(prefix)
    if eq_match:
        return eq_match.group(1), "assignment", is_env

    call_match = _FUNC_CALL_RE.search(prefix)
    if call_match:
        return call_match.group(1), "call_arg", is_env

    return "", "literal", is_env


def _unquote_c_java_literal(raw_tok: str) -> str:
    s = raw_tok.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    s = s.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\\\", "\\")
    return s


def extract_python_literals(code: str) -> List[ExtractedLiteral]:
    results: List[ExtractedLiteral] = []
    source_lines = code.splitlines()

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return _extract_python_via_tokenize(code)

    parent_map = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value
            if not val:
                continue
            line = getattr(node, "lineno", 1)
            col = getattr(node, "col_offset", 0) + 1
            raw_line = source_lines[line - 1].strip() if 0 < line <= len(source_lines) else repr(val)

            ctx_name = ""
            ctx_kind = "literal"
            is_env = False

            parent = parent_map.get(node)
            if isinstance(parent, ast.Assign):
                if parent.value is node and parent.targets:
                    target = parent.targets[0]
                    if isinstance(target, ast.Name):
                        ctx_name = target.id
                        ctx_kind = "assignment"
                    elif isinstance(target, ast.Attribute):
                        ctx_name = target.attr
                        ctx_kind = "assignment"
            elif isinstance(parent, ast.AnnAssign):
                if parent.value is node and isinstance(parent.target, ast.Name):
                    ctx_name = parent.target.id
                    ctx_kind = "assignment"
            elif isinstance(parent, ast.keyword):
                if parent.value is node and parent.arg:
                    ctx_name = parent.arg
                    ctx_kind = "call_arg"
            elif isinstance(parent, ast.Dict):
                for k_node, v_node in zip(parent.keys, parent.values):
                    if v_node is node and isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                        ctx_name = k_node.value
                        ctx_kind = "dict_key"
                        break
            elif isinstance(parent, ast.Call):
                func = parent.func
                func_name = ""
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr
                ctx_name = func_name
                ctx_kind = "call_arg"
                if func_name.lower() in _ENV_CALL_NAMES:
                    is_env = True

            results.append(
                ExtractedLiteral(
                    value=val,
                    raw_snippet=raw_line,
                    line=line,
                    column=col,
                    language="Python",
                    context_name=ctx_name,
                    context_kind=ctx_kind,
                    is_env_lookup=is_env,
                )
            )

    return results


def _extract_python_via_tokenize(code: str) -> List[ExtractedLiteral]:
    results: List[ExtractedLiteral] = []
    source_lines = code.splitlines()
    try:
        tokens = tokenize.generate_tokens(io.StringIO(code).readline)
        for tok in tokens:
            if tok.type == tokenize.STRING:
                try:
                    val = ast.literal_eval(tok.string)
                except Exception:
                    val = tok.string.strip("'\"")
                if not isinstance(val, str) or not val:
                    continue
                line, col0 = tok.start
                line_text = source_lines[line - 1] if 0 < line <= len(source_lines) else tok.string
                ctx_name, ctx_kind, is_env = _infer_line_context(line_text, col0)
                results.append(
                    ExtractedLiteral(
                        value=val,
                        raw_snippet=line_text.strip(),
                        line=line,
                        column=col0 + 1,
                        language="Python",
                        context_name=ctx_name,
                        context_kind=ctx_kind,
                        is_env_lookup=is_env,
                    )
                )
    except Exception:
        pass
    return results


def extract_c_cpp_literals(code: str, language: str = "C") -> List[ExtractedLiteral]:
    results: List[ExtractedLiteral] = []
    source_lines = code.splitlines()

    if build_c_lexer is not None:
        try:
            lexer = build_c_lexer()
            lexer.input(code)
            while True:
                tok = lexer.token()
                if not tok:
                    break
                if tok.type in ("STRING_LITERAL", "STRING", "STR_LITERAL"):
                    raw_val = str(tok.value)
                    val = _unquote_c_java_literal(raw_val)
                    if not val:
                        continue
                    line = getattr(tok, "lineno", 1)
                    line_text = source_lines[line - 1] if 0 < line <= len(source_lines) else raw_val
                    col0 = line_text.find(raw_val)
                    if col0 < 0:
                        col0 = line_text.find('"')
                    ctx_name, ctx_kind, is_env = _infer_line_context(line_text, max(0, col0))
                    results.append(
                        ExtractedLiteral(
                            value=val,
                            raw_snippet=line_text.strip(),
                            line=line,
                            column=max(0, col0) + 1,
                            language=language,
                            context_name=ctx_name,
                            context_kind=ctx_kind,
                            is_env_lookup=is_env,
                        )
                    )
            if results:
                return results
        except Exception:
            pass

    return _extract_quoted_literals_fallback(code, language)


_C_JAVA_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
_JAVA_TEXT_BLOCK_RE = re.compile(r'"""(.*?)"""', re.DOTALL)


def extract_java_literals(code: str) -> List[ExtractedLiteral]:
    results: List[ExtractedLiteral] = []
    source_lines = code.splitlines()
    covered_lines = set()

    for tb_match in _JAVA_TEXT_BLOCK_RE.finditer(code):
        val = tb_match.group(1).strip("\r\n")
        if not val:
            continue
        start_pos = tb_match.start()
        line = code.count("\n", 0, start_pos) + 1
        last_nl = code.rfind("\n", 0, start_pos)
        col0 = start_pos - (last_nl + 1)
        line_text = source_lines[line - 1] if 0 < line <= len(source_lines) else ""
        ctx_name, ctx_kind, is_env = _infer_line_context(line_text, col0)
        covered_lines.add(line)
        results.append(
            ExtractedLiteral(
                value=val,
                raw_snippet=line_text.strip() or '"""..."""',
                line=line,
                column=col0 + 1,
                language="Java",
                context_name=ctx_name,
                context_kind=ctx_kind,
                is_env_lookup=is_env,
            )
        )

    for idx, line_text in enumerate(source_lines, start=1):
        if idx in covered_lines:
            continue
        stripped = line_text.strip()
        if stripped.startswith("//"):
            continue
        for m in _C_JAVA_STRING_RE.finditer(line_text):
            val = _unquote_c_java_literal(m.group(0))
            if not val:
                continue
            col0 = m.start()
            ctx_name, ctx_kind, is_env = _infer_line_context(line_text, col0)
            results.append(
                ExtractedLiteral(
                    value=val,
                    raw_snippet=stripped,
                    line=idx,
                    column=col0 + 1,
                    language="Java",
                    context_name=ctx_name,
                    context_kind=ctx_kind,
                    is_env_lookup=is_env,
                )
            )

    return results


def _extract_quoted_literals_fallback(code: str, language: str) -> List[ExtractedLiteral]:
    results: List[ExtractedLiteral] = []
    source_lines = code.splitlines()
    for idx, line_text in enumerate(source_lines, start=1):
        stripped = line_text.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for m in _C_JAVA_STRING_RE.finditer(line_text):
            val = _unquote_c_java_literal(m.group(0))
            if not val:
                continue
            col0 = m.start()
            ctx_name, ctx_kind, is_env = _infer_line_context(line_text, col0)
            results.append(
                ExtractedLiteral(
                    value=val,
                    raw_snippet=stripped,
                    line=idx,
                    column=col0 + 1,
                    language=language,
                    context_name=ctx_name,
                    context_kind=ctx_kind,
                    is_env_lookup=is_env,
                )
            )
    return results


def extract_literals(code: str, language: str) -> List[ExtractedLiteral]:
    """Extract syntax-aware string literals with source locations for C, C++, Python, or Java."""
    if not code or not code.strip():
        return []

    lang_norm = (language or "").strip().lower()
    if lang_norm == "python":
        return extract_python_literals(code)
    if lang_norm == "c":
        return extract_c_cpp_literals(code, language="C")
    if lang_norm in ("cpp", "c++"):
        return extract_c_cpp_literals(code, language="C++")
    if lang_norm == "java":
        return extract_java_literals(code)
    return _extract_quoted_literals_fallback(code, language or "Unknown")
