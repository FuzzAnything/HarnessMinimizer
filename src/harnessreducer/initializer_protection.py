"""One-time, source-level initializer protection. Never used by candidate checks."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from contextlib import contextmanager
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from harnessreducer.fdp_transform import PARSER, _iter_nodes
from harnessreducer.macro_headers import _directives
from harnessreducer.process_supervisor import run_supervised


POLICY = "whole-local-declaration-v1"
_LEX = re.compile(
    r"(?P<space>\s+)|(?P<comment>//[^\r\n]*|/\*[\s\S]*?\*/)"
    r'|(?P<raw>(?:u8|u|U|L)?R"([^\s()\\]{0,16})\()'
    r"""|(?P<string>(?:u8|u|U|L)?(?:"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*')(?:[^\W\d]\w*)?)"""
    r"|(?P<number>(?:\d|\.\d)(?:[eEpP][+-]|[\w.'])*)"
    r"|(?P<identifier>[^\W\d]\w*)"
    r"|(?P<operator>%:%:|<=>|>>=|<<=|->\*|\.\.\.|::|->|\.\*|"
    r"\+\+|--|&&|\|\||<=|>=|==|!=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<|>>|##|<:|:>|<%|%>|%:)"
    r"|(?P<other>[\s\S])"
)
_RAW_START = re.compile(r'(?:u8|u|U|L)?R"([^\s()\\]{0,16})\(')
_LOCATION_BUILTINS = {"__LINE__", "__FILE__", "__COUNTER__", "__BASE_FILE__", "__INCLUDE_LEVEL__"}


def source_tokens(source: str):
    """Yield (start, end, spelling, kind), excluding whitespace and comments."""
    index = 0
    while index < len(source):
        match = _LEX.match(source, index)
        assert match is not None
        end = match.end()
        kind = match.lastgroup
        # The inner delimiter capture does not change lastgroup on CPython,
        # but detect the raw prefix explicitly for clarity.
        if match.group("raw") is not None:
            raw = _RAW_START.match(source, index)
            assert raw is not None
            closing = ")" + raw.group(1) + '"'
            close = source.find(closing, raw.end())
            if close < 0:
                raise ValueError("Unterminated raw string")
            end = close + len(closing)
            suffix = re.match(r"[^\W\d]\w*", source[end:])
            if suffix is not None:
                end += suffix.end()
            kind = "string"
        if kind not in {"space", "comment"}:
            yield index, end, source[index:end], kind
        index = end


@dataclass(frozen=True)
class ProtectedDeclaration:
    marker: str
    original: str  # declaration without its final semicolon
    padding: str
    line: int


@dataclass(frozen=True)
class InitializerProtection:
    source: Path
    original_source: Path
    header: Path
    declarations: tuple[ProtectedDeclaration, ...]
    skipped: tuple[dict, ...]
    prefix: str
    preparation_ns: int

    def metadata(self) -> dict:
        return {
            "policy": POLICY, "protected_count": len(self.declarations),
            "skipped": list(self.skipped), "prepared_source": str(self.source),
            "original_source": str(self.original_source), "header": str(self.header),
            "preparation_ns": self.preparation_ns,
        }

    def restore(self, source: str) -> str:
        declarations = {item.marker: item for item in self.declarations}
        edits = []
        directives = _directives(source)
        for directive in directives:
            if directive.keyword != "include":
                continue
            tokens = list(source_tokens(directive.argument))
            if len(tokens) == 1 and tokens[0][2].startswith('"'):
                try:
                    target = json.loads(tokens[0][2])
                except ValueError:
                    continue
                if Path(target).resolve() == self.header:
                    edits.append((directive.start, directive.end, ""))
        for start, end, token, kind in source_tokens(source):
            if kind != "identifier" or not token.startswith(self.prefix):
                continue
            declaration = declarations.get(token)
            if declaration is None:
                raise ValueError(f"Unknown initializer-protection marker: {token}")
            if any(d.start <= start < d.end for d in directives):
                raise ValueError("Initializer marker moved into a preprocessor directive")
            if declaration.padding and source.startswith(declaration.padding + ";", end):
                end += len(declaration.padding)
            edits.append((start, end, declaration.original))
        for start, end, replacement in sorted(edits, reverse=True):
            source = source[:start] + replacement + source[end:]
        return source

    def restore_file(self, path: str | Path) -> None:
        path = Path(path)
        if path.is_file():
            source = path.read_text(encoding="utf-8")
            restored = self.restore(source)
            if restored != source:
                path.write_text(restored, encoding="utf-8")


def prepare_initializer_protection(source: Path, directory: Path) -> InitializerProtection:
    started = time.perf_counter_ns()
    source = source.resolve()
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    original = source.read_bytes()
    tree = PARSER.parse(original)
    prefix = "HR_KEEP_INIT_" + uuid.uuid4().hex + "_"
    header = directory / "initializer_definitions.h"
    declarations = []
    skipped = []
    edits = []
    covered_end = -1
    nodes = sorted(
        (n for n in _iter_nodes(tree.root_node) if n.type == "declaration"),
        key=lambda n: (n.start_byte, -n.end_byte),
    )
    for node in nodes:
        if node.start_byte < covered_end:
            continue
        if not any(n.type == "init_declarator" for n in node.named_children):
            continue
        ancestor = node.parent
        while ancestor and ancestor.type not in {"function_definition", "lambda_expression", "translation_unit"}:
            ancestor = ancestor.parent
        if ancestor is None or ancestor.type != "function_definition":
            continue
        parent = node.parent
        while parent and parent.type.startswith("preproc_"):
            parent = parent.parent
        text = original[node.start_byte:node.end_byte].decode("utf-8")
        reason = None
        if parent is None or parent.type != "compound_statement":
            reason = "not-a-standalone-local-declaration"
        elif node.has_error or not text.endswith(";"):
            reason = "ambiguous-declaration"
        elif any(
            n.type in {"structured_binding_declarator", "lambda_expression", "attribute_specifier",
                       "class_specifier", "struct_specifier", "union_specifier"}
            or n.type.startswith("preproc_") for n in _iter_nodes(node)
        ):
            reason = "unsupported-nested-or-preprocessor-syntax"
        elif "\\\n" in text or "\\\r\n" in text:
            reason = "line-spliced-declaration"
        tokens = list(source_tokens(text[:-1]))
        if any(token in _LOCATION_BUILTINS for _, _, token, kind in tokens if kind == "identifier"):
            reason = "location-sensitive-initializer"
        if any(("\n" in token or "\r" in token) for _, _, token, _ in tokens):
            reason = "multiline-literal"
        if reason:
            skipped.append({"line": node.start_point.row + 1, "reason": reason})
            continue
        marker = prefix + str(len(declarations))
        core = text[:-1]
        padding = "\n" * core.count("\n")
        declarations.append(ProtectedDeclaration(marker, core, padding, node.start_point.row + 1))
        edits.append((node.start_byte, node.end_byte, (marker + padding + ";").encode()))
        covered_end = node.end_byte
    prepared = original
    for start, end, replacement in reversed(edits):
        prepared = prepared[:start] + replacement + prepared[end:]
    definitions = [
        "#define " + item.marker + " " + " ".join(t[2] for t in source_tokens(item.original))
        for item in declarations
    ]
    header.write_text("\n".join(definitions) + "\n", encoding="utf-8")
    output = directory / "protected.cpp"
    output.write_bytes(
        ('#include ' + json.dumps(str(header), ensure_ascii=False) + "\n").encode() + prepared
    )
    result = InitializerProtection(
        output, source, header, tuple(declarations), tuple(skipped), prefix,
        time.perf_counter_ns() - started,
    )
    (directory / "initializer_protection.json").write_text(
        json.dumps({**result.metadata(), "declarations": [asdict(d) for d in declarations]}, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


@contextmanager
def preparation_compile_flags(flags: str | None, original: Path, directory: Path):
    """Add a source include root without changing the existing flag parser.

    A Clang response file can represent a directory containing spaces even
    though the legacy checker splits its flag string on whitespace. Preserve
    its interpretation of user flags, including quotes in -D string values.
    The durable copy allows replaying commands after the temporary alias ends.
    """
    from harnessreducer.reducer_runner import _split_flags
    contents = "\n".join(
        json.dumps(arg, ensure_ascii=False)
        for arg in ["-iquote", str(original.resolve().parent), *_split_flags(flags)]
    ) + "\n"
    (directory / "compile_flags.rsp").write_text(contents, encoding="utf-8")
    # HarnessReducer runs on Linux; /tmp gives this legacy parser a whitespace-
    # free alias even when the user's work directory or TMPDIR contains spaces.
    with tempfile.TemporaryDirectory(prefix="hr-initializer-flags-", dir="/tmp") as tmp:
        response = Path(tmp) / "flags.rsp"
        response.write_text(contents, encoding="utf-8")
        yield "@" + str(response)


def phase_flags(compile_flags: str | None, *, replay: bool, plugin: bool = False) -> list[str]:
    from harnessreducer.reducer_runner import (
        PHASE3_SANITIZER_FLAGS, PHASE3_PLUGIN_SANITIZER_FLAGS,
        PHASE3_SPLIT_OPT_FLAGS, PHASE3_WARNING_FLAGS, _phase3_replay_flags,
        _split_flags,
    )
    return [
        "-Qunused-arguments", *_phase3_replay_flags(replay, external_replay_runtime=replay and plugin),
        *(PHASE3_PLUGIN_SANITIZER_FLAGS if plugin else PHASE3_SANITIZER_FLAGS),
        *PHASE3_SPLIT_OPT_FLAGS, *PHASE3_WARNING_FLAGS,
        *(["-fPIC"] if plugin else []), *_split_flags(compile_flags),
    ]


def verify_preparation(
    protection: InitializerProtection, compile_flags: str | None, *, replay: bool, plugin: bool,
) -> None:
    """One-time compiler preprocessing check; no object build or execution."""
    commands = []
    outputs = []
    with tempfile.TemporaryDirectory(prefix="initializer-preprocess-") as tmp:
        for index, source in enumerate((protection.original_source, protection.source)):
            output = Path(tmp) / f"{index}.ii"
            command = [
                "clang++", *phase_flags(compile_flags, replay=replay, plugin=plugin),
                "-E", "-P", "-x", "c++", str(source), "-o", str(output),
            ]
            commands.append(command)
            proc = run_supervised(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60, check=False,
            )
            if proc.returncode:
                raise ValueError(f"Initializer preprocessing failed:\n{proc.stderr}")
            outputs.append(output.read_text(encoding="utf-8"))
    # Token spelling, not whitespace/line-marker differences, determines whether
    # the macro encoding preserved the prepared translation unit.
    from itertools import zip_longest
    original_tokens = (item[2] for item in source_tokens(outputs[0]))
    prepared_tokens = (item[2] for item in source_tokens(outputs[1]))
    matched = all(a == b for a, b in zip_longest(original_tokens, prepared_tokens))
    (protection.source.parent / "preparation_check.json").write_text(
        json.dumps({"commands": commands, "tokens_match": matched}, indent=2) + "\n",
        encoding="utf-8",
    )
    if not matched:
        raise ValueError("Initializer protection changes preprocessed tokens; recovery was not started.")
