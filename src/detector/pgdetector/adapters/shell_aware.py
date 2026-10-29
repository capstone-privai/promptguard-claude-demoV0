"""Shell/context-aware credential candidate generator.

This adapter raises evidence-backed candidates; it is not a final secret
classifier. It tokenizes command structure before applying command/option and
source/sink semantics, and never logs or retains candidate values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..adapter import DetectorAdapter, RawFinding


LONG_OPTIONS = {
    "password": "PASSWORD", "passwd": "PASSWORD", "passphrase": "PASSWORD",
    "token": "TOKEN", "access-token": "TOKEN", "secret": "SECRET",
    "client-secret": "SECRET", "api-key": "API_KEY",
}
SHORT_PASSWORD_COMMANDS = {
    ("sshpass", None), ("mysql", None), ("mysqldump", None), ("docker", "login"),
}
CREDENTIAL_CUE = re.compile(r"(?i)\b(?:password|passwd|passphrase|credential|authentication|authenticate|login|secret|token)\b")
FUNCTION_CUE = re.compile(r"(?i)(?:password|passwd|credential|login|authenticate|auth|secret|token)")
STRING_LITERAL = re.compile(r"(?P<prefix>[bBrRuUfF]?)(?P<quote>['\"])(?P<value>.*?)(?P=quote)")
SEND_CALL = re.compile(r"(?i)\b(?:send|sendline)\s*(?:\(\s*)?[bBrRuUfF]?(?P<quote>['\"])(?P<value>.*?)(?P=quote)")
FUNCTION_CALL = re.compile(r"(?is)\b(?P<name>[A-Za-z_][A-Za-z0-9_.]*)\s*\((?P<args>[^\r\n()]*)\)")
HEREDOC_OPEN = re.compile(r"(?P<head>[^\r\n]*?)<<-?\s*['\"]?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)['\"]?\s*$", re.M)
VARIABLE_REFERENCE = re.compile(r"^(?:\$\{?(?:PASSWORD|PASSWD|PASS|PASSPHRASE|TOKEN|SECRET|API_KEY)\}?|%\w*(?:PASS|TOKEN|SECRET|KEY)\w*%)$", re.I)
PLACEHOLDER = re.compile(r"^(?:<[^<>]+>|\[[A-Z][A-Z0-9_]*_\d+\]|\*+)$")

TOKEN = re.compile(
    r"(?P<space>[ \t]+)|(?P<op><<<|<<-|<<|\|\||&&|[|;&])|"
    r"(?P<single>'[^']*')|(?P<double>\"(?:\\.|[^\"\\])*\")|(?P<bare>[^\s|;&<>]+)"
)


@dataclass(frozen=True)
class ShellToken:
    raw: str
    value: str
    start: int
    end: int
    value_start: int
    value_end: int
    operator: bool = False


def tokenize(line: str, base: int = 0) -> list[ShellToken]:
    tokens: list[ShellToken] = []
    for match in TOKEN.finditer(line):
        if match.lastgroup == "space":
            continue
        raw = match.group()
        start, end = base + match.start(), base + match.end()
        if match.lastgroup in {"single", "double"}:
            tokens.append(ShellToken(raw, raw[1:-1], start, end, start + 1, end - 1))
        else:
            tokens.append(ShellToken(raw, raw, start, end, start, end, match.lastgroup == "op"))
    return tokens


def segments(tokens: Iterable[ShellToken]) -> list[list[ShellToken]]:
    output: list[list[ShellToken]] = [[]]
    for token in tokens:
        if token.operator:
            output.append([])
        else:
            output[-1].append(token)
    return [part for part in output if part]


def command_pair(tokens: list[ShellToken]) -> tuple[str, str | None]:
    words = [token.value.lower() for token in tokens if not token.operator]
    while words and ("=" in words[0] and not words[0].startswith("--")):
        words.pop(0)
    if not words:
        return "", None
    command = Path(words[0]).name.removesuffix(".exe")
    subcommand = words[1] if command == "docker" and len(words) > 1 else None
    return command, subcommand


def semantic_sink(tokens: list[ShellToken]) -> tuple[bool, str]:
    command, subcommand = command_pair(tokens)
    values = {token.value.lower() for token in tokens}
    if command == "sudo" and "-s" in values:
        return True, "sudo -S"
    if command == "docker" and subcommand == "login" and "--password-stdin" in values:
        return True, "docker login --password-stdin"
    if command == "passwd" and "--stdin" in values:
        return True, "passwd --stdin"
    return False, command


def plausible(value: str) -> bool:
    stripped = value.strip()
    return bool(stripped and "\x00" not in stripped and not PLACEHOLDER.fullmatch(stripped))


def finding(start: int, end: int, kind: str, family: str, strength: str, **evidence: str) -> RawFinding:
    return RawFinding(start, end, kind, f"shell-{family}", strength, family, evidence)


def token_finding(token: ShellToken, kind: str, family: str, strength: str, **evidence: str) -> RawFinding | None:
    if not plausible(token.value):
        return None
    return finding(token.value_start, token.value_end, kind, family, strength, **evidence)


class ShellAwareAdapter(DetectorAdapter):
    version = "0.1.0"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path) -> None:
        super().__init__(name, options, config_dir)
        self.min_value_length = max(1, int(options.get("min_value_length", 1)))

    def scan(self, text: str) -> list[RawFinding]:
        output: list[RawFinding] = []
        line_start = 0
        for raw_line in text.splitlines(keepends=True) or [text]:
            line = raw_line.removesuffix("\r\n").removesuffix("\n").removesuffix("\r")
            line_tokens = tokenize(line, line_start)
            output.extend(self._long_options(line_tokens))
            output.extend(self._short_options(line_tokens))
            output.extend(self._pipes(line_tokens))
            output.extend(self._here_strings(line_tokens))
            line_start += len(raw_line)
        output.extend(self._heredocs(text))
        output.extend(self._send_calls(text))
        output.extend(self._function_calls(text))
        return self._dedupe(output)

    def _long_options(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        for index, token in enumerate(tokens):
            if token.operator or not token.raw.startswith("--"):
                continue
            option, separator, attached = token.raw[2:].partition("=")
            normalized = option.lower().replace("_", "-")
            kind = LONG_OPTIONS.get(normalized)
            if not kind:
                continue
            if separator:
                quote = attached[0] if attached[:1] in {"'", '\"'} and attached[-1:] == attached[:1] else ""
                value = attached[1:-1] if quote else attached
                value_start = token.start + token.raw.index("=") + 1 + (1 if quote else 0)
                candidate = finding(value_start, value_start + len(value), kind, "long_option", "strong", option=f"--{normalized}") if plausible(value) else None
            else:
                value_token = tokens[index + 1] if index + 1 < len(tokens) and not tokens[index + 1].operator else None
                candidate = token_finding(value_token, kind, "long_option", "strong", option=f"--{normalized}") if value_token else None
            if candidate and candidate.end - candidate.start >= self.min_value_length:
                output.append(candidate)
        return output

    def _short_options(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        for part in segments(tokens):
            command, subcommand = command_pair(part)
            if (command, subcommand) not in SHORT_PASSWORD_COMMANDS and (command, None) not in SHORT_PASSWORD_COMMANDS:
                continue
            for index, token in enumerate(part):
                raw = token.raw
                if raw == "-p":
                    value_token = part[index + 1] if index + 1 < len(part) else None
                    candidate = token_finding(value_token, "PASSWORD", "short_option", "strong", command=command, option="-p") if value_token else None
                elif raw.startswith("-p") and len(raw) > 2:
                    attached = raw[2:]
                    quote = attached[0] if attached[:1] in {"'", '\"'} and attached[-1:] == attached[:1] else ""
                    value = attached[1:-1] if quote else attached
                    value_start = token.start + 2 + (1 if quote else 0)
                    candidate = finding(value_start, value_start + len(value), "PASSWORD", "short_option", "strong", command=command, option="-p") if plausible(value) else None
                else:
                    candidate = None
                if candidate and candidate.end - candidate.start >= self.min_value_length:
                    output.append(candidate)
        return output

    def _pipes(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        pipe_indexes = [index for index, token in enumerate(tokens) if token.raw == "|"]
        for index in pipe_indexes:
            left = [token for token in tokens[:index] if not token.operator]
            right = [token for token in tokens[index + 1:] if not token.operator]
            is_sink, sink = semantic_sink(right)
            command, _ = command_pair(left)
            if not is_sink or command not in {"echo", "printf"}:
                continue
            args = left[1:]
            if command == "echo":
                values = [token for token in args if not token.value.startswith("-")]
                value_token = values[0] if values else None
            else:
                # printf's first argument is normally the format; the final one is data.
                value_token = args[-1] if len(args) >= 2 else None
            strength = "ambiguous" if value_token and VARIABLE_REFERENCE.fullmatch(value_token.value) else "strong"
            candidate = token_finding(value_token, "PASSWORD", "stdin_sink", strength, source=command, sink=sink) if value_token else None
            if candidate:
                output.append(candidate)
        return output

    def _here_strings(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        for index, token in enumerate(tokens):
            if token.raw != "<<<" or index + 1 >= len(tokens):
                continue
            left = [item for item in tokens[:index] if not item.operator]
            value_token = tokens[index + 1]
            is_sink, sink = semantic_sink(left)
            semantic_reference = bool(VARIABLE_REFERENCE.fullmatch(value_token.value))
            if not is_sink and not semantic_reference:
                continue
            candidate = token_finding(value_token, "PASSWORD", "here_string", "strong" if is_sink else "ambiguous", sink=sink)
            if candidate:
                output.append(candidate)
        return output

    def _heredocs(self, text: str) -> list[RawFinding]:
        output = []
        for opened in HEREDOC_OPEN.finditer(text):
            head_tokens = tokenize(opened.group("head"), opened.start("head"))
            is_sink, sink = semantic_sink(head_tokens)
            if not is_sink:
                continue
            body_start = opened.end()
            if text[body_start:body_start + 2] == "\r\n":
                body_start += 2
            elif text[body_start:body_start + 1] in {"\r", "\n"}:
                body_start += 1
            closing = re.search(rf"(?m)^[ \t]*{re.escape(opened.group('tag'))}[ \t]*$", text[body_start:])
            if not closing:
                continue
            body_end = body_start + closing.start()
            for line in re.finditer(r"[^\r\n]+", text[body_start:body_end]):
                value = line.group().strip()
                if not plausible(value):
                    continue
                start = body_start + line.start() + line.group().index(value)
                output.append(finding(start, start + len(value), "PASSWORD", "heredoc", "strong", sink=sink))
        return output

    def _send_calls(self, text: str) -> list[RawFinding]:
        output = []
        for match in SEND_CALL.finditer(text):
            context = text[max(0, match.start() - 256):match.start()]
            if not CREDENTIAL_CUE.search(context):
                continue
            value = match.group("value")
            suffix = next((item for item in (r"\r", r"\n") if value.endswith(item)), "")
            end = match.end("value") - len(suffix)
            if plausible(value[:-len(suffix)] if suffix else value):
                output.append(finding(match.start("value"), end, "PASSWORD", "expect_send", "ambiguous", call="send"))
        return output

    def _function_calls(self, text: str) -> list[RawFinding]:
        output = []
        for match in FUNCTION_CALL.finditer(text):
            name = match.group("name").split(".")[-1]
            lowered = name.lower()
            if lowered in {"send", "sendline"} or not FUNCTION_CUE.search(lowered):
                continue
            literals = list(STRING_LITERAL.finditer(match.group("args")))
            if not literals:
                continue
            literal = literals[-1]
            value = literal.group("value")
            if not plausible(value):
                continue
            start = match.start("args") + literal.start("value")
            strong = any(cue in lowered for cue in ("password", "passwd", "credential", "secret", "token"))
            kind = "TOKEN" if "token" in lowered else "SECRET" if "secret" in lowered else "PASSWORD"
            output.append(finding(start, start + len(value), kind, "function_argument", "strong" if strong else "ambiguous", function=lowered))
        return output

    @staticmethod
    def _dedupe(items: list[RawFinding]) -> list[RawFinding]:
        seen = set()
        output = []
        for item in items:
            key = (item.start, item.end, item.rule_id)
            if key not in seen:
                seen.add(key)
                output.append(item)
        return output
