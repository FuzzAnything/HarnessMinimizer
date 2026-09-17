"""Hide harness #defines behind includes while a source reducer is running.

The headers are ordinary compiler inputs, not PCHs. Definitions stay in their
original order/conditional context, and are restored before post-processing.
No include guards are added: a definition can legitimately be evaluated again
after an #undef. The user's source and original #includes are never edited.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
import json
from pathlib import Path
import re
import tempfile


_SPLICE = re.compile(r"\\(?:\r\n|\n|\r)")
_NEWLINE = re.compile(r"\r\n|\n|\r")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_RAW_STRING = re.compile(r'(?:u8|u|U|L)?R"([^\s()\\]{0,16})\(')


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="surrogateescape")


def _write(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8", errors="surrogateescape"))


@dataclass(frozen=True)
class Directive:
    start: int
    end: int
    keyword: str
    argument: str


def _directives(source: str) -> list[Directive]:
    """Find real directives, rather than #defines inside comments or literals.

    Scan after C/C++ line splicing, retaining offsets into the original text.
    This handles continued directives/comments and even a split directive name.
    Raw-string contents are scanned in the original text because C++ undoes line
    splicing inside raw strings. Block comments and raw strings can span lines.
    """
    pieces: list[str] = []
    offsets: list[int] = []
    previous = 0
    for match in _SPLICE.finditer(source):
        pieces.append(source[previous:match.start()])
        offsets.extend(range(previous, match.start()))
        previous = match.end()
    pieces.append(source[previous:])
    offsets.extend(range(previous, len(source)))
    text = "".join(pieces)
    offsets.append(len(source))
    size = len(text)

    def token_end(index: int) -> int:
        if text.startswith("//", index):
            match = _NEWLINE.search(text, index + 2)
            return match.start() if match else size
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            return size if end == -1 else end + 2
        raw = _RAW_STRING.match(source, offsets[index])
        if raw:
            closing = ')' + raw.group(1) + '"'
            end = source.find(closing, raw.end())
            return size if end == -1 else bisect_left(offsets, end + len(closing))
        if text[index] in "\"'":
            quote = text[index]
            end = index + 1
            while end < size:
                if text[end] == "\\":
                    end += 2
                elif text[end] == quote:
                    return end + 1
                else:
                    end += 1
            return size
        if text[index].isdigit() or (text[index] == "." and text[index:index + 2][1:].isdigit()):
            # Do not mistake the digit separator in 1'000 for a character literal.
            end = index + 1
            while end < size and (text[end].isalnum() or text[end] in "_.'"):
                end += 1
            return end
        identifier = _IDENTIFIER.match(text, index)
        return identifier.end() if identifier else index + 1

    def skip_space_and_comments(index: int) -> int:
        while index < size:
            if text[index] in " \t\v\f":
                index += 1
            elif text.startswith("/*", index):
                index = token_end(index)
            else:
                break
        return index

    result: list[Directive] = []
    index = 0
    at_line_start = True
    while index < size:
        char = text[index]
        if char in "\r\n":
            at_line_start = True
            index += 1
        elif char in " \t\v\f" or (index == 0 and char == "\ufeff"):
            index += 1
        elif text.startswith(("/*", "//"), index):
            end = token_end(index)
            if _NEWLINE.search(text[index:end]):
                at_line_start = True
            index = end
        elif at_line_start and (char == "#" or text.startswith("%:", index)):
            start = index
            name_start = skip_space_and_comments(index + (1 if char == "#" else 2))
            name = _IDENTIFIER.match(text, name_start)
            keyword = name.group() if name else ""
            argument_start = name.end() if name else name_start
            end = argument_start
            while end < size and text[end] not in "\r\n":
                # Header names are not comments (e.g. #include <dir//file.h>).
                if keyword in {"include", "include_next", "import"} and text[end] == "<":
                    closing = text.find(">", end + 1)
                    newline = _NEWLINE.search(text, end + 1)
                    if closing != -1 and (newline is None or closing < newline.start()):
                        end = closing + 1
                        continue
                end = token_end(end)
            argument = text[argument_start:end]
            newline = _NEWLINE.match(text, end)
            if newline:
                end = newline.end()
            result.append(Directive(offsets[start], offsets[end], keyword, argument))
            index = end
            at_line_start = True
        else:
            index = token_end(index)
            at_line_start = False
    return result


@dataclass(frozen=True)
class MacroHeader:
    path: Path
    definition: str
    padding: str


@dataclass(frozen=True)
class MacroPreparation:
    source: Path
    headers: tuple[MacroHeader, ...] = ()
    manifest: Path | None = None

    def metadata(self) -> dict[str, object]:
        return {
            "policy": "external-define-headers-v1",
            "definition_count": len(self.headers),
            "prepared_source": str(self.source.resolve()),
            "manifest": str(self.manifest) if self.manifest else None,
        }

    def restore(self, source: str) -> str:
        if not self.headers:
            return source
        definitions = {str(header.path): header for header in self.headers}
        edits: list[tuple[int, int, str]] = []
        for directive in _directives(source):
            if directive.keyword != "include":
                continue
            argument = directive.argument.strip()
            match = re.match(r'"([^"\r\n]+)"|<([^>\r\n]+)>', argument)
            if match is None:
                continue
            header = definitions.get(match.group(1) or match.group(2))
            if header is None:
                continue
            end = directive.end
            # Remove our blank-line padding if it survived reduction. No line
            # numbers or comment markers are needed to identify a definition.
            if header.padding and source.startswith(header.padding, end):
                end += len(header.padding)
            definition = header.definition
            if not definition.endswith(("\n", "\r")) and end < len(source):
                definition += "\n"
            edits.append((directive.start, end, definition))
        for start, end, definition in reversed(edits):
            source = source[:start] + definition + source[end:]
        return source

    def restore_file(self, path: Path) -> None:
        if not self.headers or not path.is_file():
            return
        source = _read(path)
        restored = self.restore(source)
        if restored != source:
            _write(path, restored)


def prepare_macro_headers(source_path: Path, work_dir: Path) -> MacroPreparation:
    source = _read(source_path)
    definitions = [directive for directive in _directives(source) if directive.keyword == "define"]
    if not definitions:
        return MacroPreparation(source_path)

    directory = Path(tempfile.mkdtemp(prefix="reducer-macros-", dir=work_dir.resolve()))
    prepared = directory / f"prepared{source_path.suffix or '.cpp'}"
    headers: list[MacroHeader] = []
    edits: list[tuple[int, int, str]] = []
    for index, directive in enumerate(definitions):
        path = directory / f"macro_{index:04d}.h"
        name = str(path)
        if '"' not in name and "\n" not in name and "\r" not in name:
            operand = f'"{name}"'
        elif ">" not in name and "\n" not in name and "\r" not in name:
            operand = f"<{name}>"
        else:
            raise ValueError("The work-directory path cannot be represented in a C++ #include")
        definition = source[directive.start:directive.end]
        newlines = _NEWLINE.findall(definition)
        padding = "".join(newlines[1:])
        replacement = f"#include {operand}" + "".join(newlines)
        headers.append(MacroHeader(path, definition, padding))
        # Even an EOF definition needs a terminating newline in its header.
        _write(path, definition if definition.endswith(("\n", "\r")) else definition + "\n")
        edits.append((directive.start, directive.end, replacement))
    for start, end, replacement in reversed(edits):
        source = source[:start] + replacement + source[end:]
    _write(prepared, source)
    manifest = directory / "macro_headers.json"
    manifest.write_text(json.dumps({
        "policy": "external-define-headers-v1",
        "original_source": str(source_path.resolve()),
        "prepared_source": str(prepared),
        "headers": [
            {"path": str(header.path), "definition": header.definition, "padding": header.padding}
            for header in headers
        ],
    }, indent=2) + "\n", encoding="utf-8")
    return MacroPreparation(prepared, tuple(headers), manifest)
