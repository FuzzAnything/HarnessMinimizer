"""Source-language policy shared by preparation, compilation and export."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    from tree_sitter import Language, Node, Parser
except ImportError:  # pragma: no cover - optional on minimal Rust-only test hosts
    Language = Any  # type: ignore[misc, assignment]
    Node = Any  # type: ignore[misc, assignment]
    Parser = Any  # type: ignore[misc, assignment]


@dataclass(frozen=True)
class SourceLanguage:
    name: str
    suffix: str
    compiler: str
    pch_language: str
    perses_language: str

    def parser(self) -> Parser:
        # Cache immutable grammar handles, never mutate a shared parser's language.
        return Parser(_grammar(self))

    @property
    def has_tree_sitter(self) -> bool:
        return self.name in {"c", "c++"}

    def source_args(self, path: str | Path) -> list[str]:
        # Preserve existing C++ commands. C's explicit language is scoped so
        # following object/archive inputs are still treated as linker inputs.
        if self.name == "c":
            return ["-x", "c", str(path), "-x", "none"]
        return [str(path)]


C = SourceLanguage("c", ".c", "clang", "c-header", "c")
CPP = SourceLanguage("c++", ".cpp", "clang++", "c++-header", "cpp")
RUST = SourceLanguage("rust", ".rs", "cargo", "", "rust")
_CURRENT = ContextVar("harnessminimizer_source_language", default=CPP)


def language_for_path(path: str | Path) -> SourceLanguage:
    suffix = Path(path).suffix
    if suffix == ".c":
        return C
    if suffix in {".cpp", ".cc", ".cxx", ".c++", ".C"}:
        return CPP
    if suffix == ".rs":
        return RUST
    raise ValueError(
        f"Unsupported harness suffix {suffix!r}: use .c for C, "
        ".cpp, .cc, .cxx, .c++, .C for C++, or .rs for Rust."
    )


@lru_cache(maxsize=3)
def _grammar(language: SourceLanguage) -> Language:
    if language == RUST:
        try:
            import tree_sitter_rust
        except ImportError as exc:
            raise RuntimeError(
                "Optional tree-sitter-rust is not installed; Rust reduction uses "
                "Perses's native Rust grammar and pure-Python helpers."
            ) from exc
        return Language(tree_sitter_rust.language())
    if language == C:
        try:
            import tree_sitter_c
        except ImportError as exc:
            raise RuntimeError(
                "Native C support requires tree-sitter-c; reinstall HarnessMinimizer "
                "with its dependencies (or run uv sync)."
            ) from exc
        return Language(tree_sitter_c.language())
    import tree_sitter_cpp
    return Language(tree_sitter_cpp.language())


def current_language() -> SourceLanguage:
    """Language for source-free helpers such as the current checkpoint path."""
    return _CURRENT.get()


@contextmanager
def language_scope(language: SourceLanguage):
    token = _CURRENT.set(language)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def iter_nodes(root: Node):
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.children))


def node_text(source: bytes, node: Node) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8")
