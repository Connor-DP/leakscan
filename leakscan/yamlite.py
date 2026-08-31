"""A deliberately small YAML subset loader.

Rule packs are YAML because a compliance lead should be able to add their own
client names and codenames without touching Python. Rule packs are *not* full
YAML because we ship no dependencies, and a full YAML implementation is a large
piece of code to put inside a security tool's audit boundary.

Supported: mappings, sequences, nesting by indentation, comments, plain and
quoted scalars, inline sequences (``[a, b]``), and the scalar types ``true``,
``false``, ``null``, integers and floats.

Not supported: anchors, aliases, tags, multiple documents, flow mappings
(``{a: 1}``), block scalars (``|``, ``>``), and tabs for indentation.

Anything unsupported raises :class:`YamlError` with a line number. That strictness
is the point: a rule pack that parses *differently* from what its author intended
is a detection that silently never fires, which is the failure this tool exists
to avoid. Better to refuse the file.
"""

from __future__ import annotations

from typing import Any

__all__ = ["YamlError", "loads"]


class YamlError(ValueError):
    """Raised when input uses syntax this loader does not support."""

    def __init__(self, message: str, line: int | None = None) -> None:
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)


# A parsed line: (indent, content, original line number).
_Line = tuple[int, str, int]


def _strip_comment(text: str) -> str:
    """Remove a trailing ``#`` comment, respecting quotes."""
    quote: str | None = None
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index]
    return text


def _prepare(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        content = _strip_comment(raw).rstrip()
        if not content.strip():
            continue
        leading = content[: len(content) - len(content.lstrip(" \t"))]
        if "\t" in leading:
            raise YamlError("tabs cannot be used for indentation", number)
        lines.append((len(leading), content.strip(), number))
    return lines


def _split_key(text: str, line_number: int) -> tuple[str, str]:
    """Split ``key: value`` at the first unquoted colon."""
    quote: str | None = None
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == ":" and (index + 1 == len(text) or text[index + 1] in " \t"):
            return text[:index].strip(), text[index + 1:].strip()
    raise YamlError(f"expected 'key: value', got {text!r}", line_number)


def _split_flow(text: str, line_number: int) -> list[str]:
    """Split the inside of ``[a, b, 'c, d']`` on unquoted commas."""
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
            current.append(char)
        elif char == ",":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quote:
        raise YamlError("unterminated quote in inline sequence", line_number)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return [part for part in parts if part]


def _unquote(text: str, line_number: int) -> str:
    quote = text[0]
    if len(text) < 2 or text[-1] != quote:
        raise YamlError("unterminated quoted string", line_number)
    body = text[1:-1]
    if quote == "'":
        # In YAML, '' is the only escape inside single quotes — which is exactly
        # why regexes belong in single quotes: backslashes stay literal.
        return body.replace("''", "'")
    result: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            following = body[index + 1]
            result.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(following, following))
            index += 2
        else:
            result.append(char)
            index += 1
    return "".join(result)


def _scalar(text: str, line_number: int) -> Any:
    text = text.strip()
    if not text:
        return None
    if text[0] == "{":
        raise YamlError("flow mappings ({a: 1}) are not supported", line_number)
    if text[0] in "|>":
        raise YamlError("block scalars (| and >) are not supported; quote the value", line_number)
    if text[0] in "\"'":
        return _unquote(text, line_number)
    if text[0] == "[":
        if not text.endswith("]"):
            raise YamlError("unterminated inline sequence", line_number)
        return [_scalar(part, line_number) for part in _split_flow(text[1:-1], line_number)]

    lowered = text.lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if lowered in ("null", "~"):
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _parse_block(lines: list[_Line], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return None, index
    if lines[index][1].startswith("- ") or lines[index][1] == "-":
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_mapping(lines: list[_Line], index: int, indent: int) -> tuple[dict, int]:
    result: dict[str, Any] = {}
    while index < len(lines):
        line_indent, content, number = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise YamlError("unexpected indentation", number)
        if content.startswith("- "):
            break

        key, rest = _split_key(content, number)
        if key in result:
            raise YamlError(f"duplicate key {key!r}", number)

        if rest:
            result[key] = _scalar(rest, number)
            index += 1
            continue

        # Value is a nested block on the following lines. A sequence may sit at
        # the same indentation as its key, which is idiomatic YAML.
        if index + 1 < len(lines) and lines[index + 1][0] > line_indent:
            value, index = _parse_block(lines, index + 1, lines[index + 1][0])
        elif index + 1 < len(lines) and lines[index + 1][0] == line_indent and lines[index + 1][1].startswith("- "):
            value, index = _parse_sequence(lines, index + 1, line_indent)
        else:
            value, index = None, index + 1
        result[key] = value
    return result, index


def _parse_sequence(lines: list[_Line], index: int, indent: int) -> tuple[list, int]:
    items: list[Any] = []
    while index < len(lines):
        line_indent, content, number = lines[index]
        if line_indent != indent or not (content.startswith("- ") or content == "-"):
            break

        body = content[2:].strip() if content.startswith("- ") else ""

        # Gather the lines belonging to this item: anything indented further.
        following: list[_Line] = []
        cursor = index + 1
        while cursor < len(lines) and lines[cursor][0] > indent:
            following.append(lines[cursor])
            cursor += 1

        if body and ":" in body and not body[0] in "\"'[":
            try:
                _split_key(body, number)
            except YamlError:
                items.append(_scalar(body, number))
                index = cursor
                continue
            child_indent = following[0][0] if following else indent + 2
            block = [(child_indent, body, number), *following]
            value, _ = _parse_mapping(block, 0, child_indent)
            items.append(value)
        elif body:
            if following:
                raise YamlError("a scalar sequence item cannot have child lines", number)
            items.append(_scalar(body, number))
        else:
            if not following:
                items.append(None)
            else:
                value, _ = _parse_block(following, 0, following[0][0])
                items.append(value)
        index = cursor
    return items, index


def loads(text: str) -> Any:
    """Parse a YAML subset document. Returns dicts, lists and scalars."""
    lines = _prepare(text)
    if not lines:
        return None
    value, index = _parse_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise YamlError("could not parse the whole document", lines[index][2])
    return value
