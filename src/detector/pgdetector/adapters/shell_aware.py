"""Shell/context-aware credential candidate generator.

This adapter raises evidence-backed candidates; it is not a final secret
classifier. It tokenizes command structure before applying command/option and
source/sink semantics, and never logs or retains candidate values.

0.2.0 changes (2026-10-29 review):
- Words may mix bare and quoted segments (``--password="a b"``) so a quoted
  value containing spaces is covered entirely instead of partially.
- Backslash-newline continuations are joined before tokenizing.
- mysql/mysqldump accept only an attached ``-pVALUE``; a separate token after
  ``-p`` is the database name. sshpass and ``docker login`` accept both forms.
- Option values that start with ``-`` or that are shell/env references
  (``$VAR``, ``${VAR}``, ``$(...)``, ``%VAR%``, ``$env:VAR``) are not
  candidates: the secret value is not present in the text.
- sudo ``-S`` is case-sensitive and recognised inside combined short flags
  (``-kS``); only sudo's own options are inspected.
- A heredoc feeding a credential sink (directly or through ``cat ... |``)
  yields only its first non-empty line, which is what the sink reads.
- send/sendline needs a password-like cue in the most recent ``expect``
  pattern, not anywhere in the previous 256 characters.
- Function names are split into words (snake_case/camelCase); a cue must be a
  whole word, so ``tokenize``/``count_tokens``/``set_author`` do not match.
  Keyword arguments with non-credential names (``username=``) are ignored.
- PowerShell ``ConvertTo-SecureString "..."`` and single-dash credential
  parameters (``-Password``, ``-token=``) are recognised.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..adapter import DetectorAdapter, RawFinding


LONG_OPTIONS = {
    "password": "PASSWORD", "passwd": "PASSWORD", "passphrase": "PASSWORD",
    "token": "TOKEN", "access-token": "TOKEN", "secret": "SECRET",
    "client-secret": "SECRET", "api-key": "API_KEY",
}
# (command, subcommand) -> whether a separate token after ``-p`` is the password.
# Prose that names an option ("the --password option of mysql", "--api-key of the account") puts an ordinary
# word where a separated value would go. Those words are never taken as the value; a value written with "="
# (--password=of) is still taken as written.
PROSE_WORDS = frozenset("""
a an the of by or and nor on in at to for from with without into onto over under via per than then
is are was were be been being am do does did has have had can could may might must shall should will would
it its this that these those which who whom whose what when where while if as so not no only also just
flag flags option options argument arguments arg args parameter parameters param value values field fields
instead here there each every any all some such etc e.g i.e
""".split())

SHORT_PASSWORD_COMMANDS = {
    ("sshpass", None): True,
    ("docker", "login"): True,
    ("mysql", None): False,
    ("mysqldump", None): False,
}
# sudo options that consume the following token.
SUDO_ARG_OPTIONS = {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"}
STDIN_PASSTHROUGH = {"cat", "echo", "printf"}

EXPECT_CUE = re.compile(r"(?i)pass|assword|token|secret|\bpin\b")
EXPECT_CALL = re.compile(r"(?i)(?:\bexpect\b|\.expect(?:_exact)?\s*\()")
SEND_CALL = re.compile(r"(?i)\b(?:send|sendline)\s*(?:\(\s*)?[bBrRuUfF]?(?P<quote>['\"])(?P<value>.*?)(?P=quote)")
FUNCTION_CALL = re.compile(r"(?s)\b(?P<name>[A-Za-z_][A-Za-z0-9_.]*)\s*\((?P<args>[^\r\n()]*)\)")
STRING_LITERAL = re.compile(r"[bBrRuUfF]?(?P<quote>['\"])(?P<value>.*?)(?P=quote)")
KEYWORD_ARG = re.compile(r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*")
STRONG_FUNCTION_WORDS = {"password", "passwd", "passphrase", "credential", "credentials", "secret", "token"}
AMBIGUOUS_FUNCTION_WORDS = {"login", "authenticate", "auth"}
CREDENTIAL_KEY_WORDS = STRONG_FUNCTION_WORDS | {"pw", "pwd"}
CREDENTIAL_KEY_NAMES = {"apikey", "accesstoken", "authtoken", "clientsecret", "secretkey"}
PROMPT_MARKER = re.compile(r"^(?:\$|#|>|%|PS|[A-Za-z]:\\[^\s]*>)$")
POWERSHELL_PARAMS = {
    "password": "PASSWORD", "passwd": "PASSWORD", "token": "TOKEN", "accesstoken": "TOKEN",
    "secret": "SECRET", "clientsecret": "SECRET", "apikey": "API_KEY",
}
REFERENCE = re.compile(r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\(.*\)|`.*`|%[A-Za-z_][A-Za-z0-9_]*%|\$env:[A-Za-z_][A-Za-z0-9_]*)$", re.S)
PLACEHOLDER = re.compile(r"^(?:<[^<>]+>|\[[A-Z][A-Z0-9_]*_\d+\]|\*+)$")
CONTINUATION = re.compile(r"\\\r?\n")
INLINE_CODE = re.compile(r"`([^`\r\n]+)`")

# Quotes may be left unterminated at end of line; the rest of the line then
# belongs to the word so an unclosed quoted value is masked, not exposed.
WORD = r"(?:\$\([^()]*\)|<[^<>\s]+>|[^\s'\"|;&<>\\]|\\.|'[^']*'?|\"(?:\\.|[^\"\\])*\"?)+"
TOKEN = re.compile(rf"(?P<space>[ \t]+)|(?P<op><<<|<<-|<<|\|\||&&|[|;&])|(?P<word>{WORD})")
SEGMENT = re.compile(r"'[^']*'?|\"(?:\\.|[^\"\\])*\"?|\\.|[^'\"\\]+")


@dataclass(frozen=True)
class ShellToken:
    raw: str
    value: str          # logical value with quotes removed
    start: int          # absolute offset of raw
    end: int
    value_start: int    # absolute span to mask
    value_end: int
    operator: bool = False


def unquote(raw: str) -> str:
    parts = []
    for segment in SEGMENT.findall(raw):
        if len(segment) >= 2 and segment[0] == segment[-1] and segment[0] in "'\"":
            parts.append(segment[1:-1])
        elif segment.startswith("\\") and len(segment) == 2:
            parts.append(segment[1])
        else:
            parts.append(segment)
    return "".join(parts)


def value_span(raw: str, start: int) -> tuple[str, int, int]:
    """Logical value and the absolute span to mask for a raw word fragment.

    A fragment that is exactly one quoted string masks only its inside;
    anything else masks the whole fragment, quotes included, so no part of a
    mixed bare/quoted value is left exposed.
    """
    if len(raw) >= 2 and raw[0] in "'\"" and SEGMENT.fullmatch(raw) and raw[-1] == raw[0]:
        return raw[1:-1], start + 1, start + len(raw) - 1
    return unquote(raw), start, start + len(raw)


def tokenize(line: str, base: int = 0) -> list[ShellToken]:
    tokens: list[ShellToken] = []
    for match in TOKEN.finditer(line):
        if match.lastgroup == "space":
            continue
        raw = match.group()
        start, end = base + match.start(), base + match.end()
        if match.lastgroup == "op":
            tokens.append(ShellToken(raw, raw, start, end, start, end, True))
        else:
            value, value_start, value_end = value_span(raw, start)
            tokens.append(ShellToken(raw, value, start, end, value_start, value_end))
    return tokens


def segments(tokens: Iterable[ShellToken], split_on: frozenset[str] | None = None) -> list[list[ShellToken]]:
    output: list[list[ShellToken]] = [[]]
    for token in tokens:
        if token.operator and (split_on is None or token.raw in split_on):
            output.append([])
        elif not token.operator:
            output[-1].append(token)
    return [part for part in output if part]


def left_segment(tokens: list[ShellToken], index: int) -> list[ShellToken]:
    """Words between the previous operator and ``tokens[index]`` (O(segment))."""
    start = index
    while start > 0 and not tokens[start - 1].operator:
        start -= 1
    return tokens[start:index]


def right_segment(tokens: list[ShellToken], index: int) -> list[ShellToken]:
    """Words between ``tokens[index]`` and the next operator."""
    end = index + 1
    while end < len(tokens) and not tokens[end].operator:
        end += 1
    return tokens[index + 1:end]


# A .env line keeps a whole command in one unquoted value: DEPLOY_CMD=mysql -u deploy -p<password> ... A shell
# would read that as an assignment followed by the command "-u"; the password is exposed all the same, so an
# assignment whose value is one of these commands starts the command instead.
ASSIGNED_COMMANDS = frozenset({"mysql", "mysqldump", "sshpass", "docker", "sudo"})


def command_words(tokens: list[ShellToken]) -> list[ShellToken]:
    words = [token for token in tokens if not token.operator]
    while words and PROMPT_MARKER.fullmatch(words[0].value):
        words.pop(0)  # "$ sshpass ...", "PS C:\\> ..."
    while words and "=" in words[0].value and not words[0].value.startswith("-"):
        _, _, assigned = words[0].value.partition("=")
        if Path(assigned.lower()).name.removesuffix(".exe") in ASSIGNED_COMMANDS:
            words[0] = replace(words[0], value=assigned)
            break
        words.pop(0)
    return words


def command_pair(tokens: list[ShellToken]) -> tuple[str, str | None]:
    words = command_words(tokens)
    if not words:
        return "", None
    command = Path(words[0].value.lower().lstrip("`")).name.removesuffix(".exe")
    subcommand = words[1].value.lower() if command == "docker" and len(words) > 1 else None
    return command, subcommand


def sudo_reads_stdin(words: list[ShellToken]) -> bool:
    index = 1
    while index < len(words):
        option = words[index].value
        if option == "--":
            return False
        if option == "--stdin":
            return True
        if option.startswith("--"):
            index += 1
            continue
        if not option.startswith("-") or option == "-":
            return False
        if "S" in option[1:]:
            return True
        index += 2 if option in SUDO_ARG_OPTIONS else 1
    return False


def semantic_sink(tokens: list[ShellToken]) -> tuple[bool, str]:
    words = command_words(tokens)
    command, subcommand = command_pair(tokens)
    values = {token.value for token in words}
    if command == "sudo" and sudo_reads_stdin(words):
        return True, "sudo -S"
    if command == "docker" and subcommand == "login" and "--password-stdin" in values:
        return True, "docker login --password-stdin"
    if command == "passwd" and "--stdin" in values:
        return True, "passwd --stdin"
    return False, command


def is_reference(value: str) -> bool:
    return bool(REFERENCE.fullmatch(value.strip()))


def plausible(value: str) -> bool:
    stripped = value.strip()
    return bool(
        stripped
        and "\x00" not in stripped
        and not PLACEHOLDER.fullmatch(stripped)
        and not is_reference(stripped)
        and stripped not in {"\\", "-"}
    )


def prose_word(token: ShellToken) -> bool:
    """A bare (unquoted) ordinary word after an option name, as in prose about the option."""
    return token.raw == token.value and token.value.lower().rstrip(".,;:)") in PROSE_WORDS


def finding(start: int, end: int, kind: str, family: str, strength: str, **evidence: str) -> RawFinding:
    return RawFinding(start, end, kind, f"shell-{family}", strength, family, evidence)


def token_finding(token: ShellToken | None, kind: str, family: str, strength: str, **evidence: str) -> RawFinding | None:
    if token is None or token.operator or not plausible(token.value):
        return None
    return finding(token.value_start, token.value_end, kind, family, strength, **evidence)


def attached_finding(token: ShellToken, prefix_length: int, kind: str, family: str, strength: str, **evidence: str) -> RawFinding | None:
    fragment = token.raw[prefix_length:]
    value, start, end = value_span(fragment, token.start + prefix_length)
    if not plausible(value):
        return None
    return finding(start, end, kind, family, strength, **evidence)


def split_identifier(name: str) -> set[str]:
    words: set[str] = set()
    for part in re.split(r"[_\W]+", name):
        for word in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", part):
            words.add(word.lower())
    return words


def split_args(args: str) -> list[str]:
    parts, current, quote = [], [], ""
    for char in args:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
            current.append(char)
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


class ShellAwareAdapter(DetectorAdapter):
    version = "0.2.2"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path) -> None:
        super().__init__(name, options, config_dir)
        self.min_value_length = max(1, int(options.get("min_value_length", 1)))

    def scan(self, text: str) -> list[RawFinding]:
        output: list[RawFinding] = []
        # Same-length replacement keeps every offset valid against ``text``.
        joined = CONTINUATION.sub(lambda match: " " * len(match.group()), text)
        lines = list(self._lines(joined))
        for index, (line_start, line) in enumerate(lines):
            # The whole line, plus each markdown inline-code span, is a command
            # context, so "run `sshpass -p ...`" in prose is still parsed.
            contexts = [(line_start, line)] + [
                (line_start + code.start(1), code.group(1)) for code in INLINE_CODE.finditer(line)
            ]
            for context_start, context in contexts:
                line_tokens = tokenize(context, context_start)
                output.extend(self._long_options(line_tokens))
                output.extend(self._short_options(line_tokens))
                output.extend(self._pipes(line_tokens))
                output.extend(self._here_strings(line_tokens))
                output.extend(self._powershell(line_tokens))
            output.extend(self._heredocs(tokenize(line, line_start), lines[index + 1:]))
        output.extend(self._send_calls(text))
        output.extend(self._function_calls(text))
        return self._dedupe([item for item in output if item.end - item.start >= self.min_value_length])

    @staticmethod
    def _lines(text: str):
        offset = 0
        for raw_line in text.splitlines(keepends=True) or [text]:
            yield offset, raw_line.rstrip("\r\n")
            offset += len(raw_line)

    def _long_options(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        for index, token in enumerate(tokens):
            if token.operator or not token.raw.startswith("--"):
                continue
            option, separator, _ = token.raw[2:].partition("=")
            normalized = option.lower().replace("_", "-")
            kind = LONG_OPTIONS.get(normalized)
            if not kind:
                continue
            if separator:
                candidate = attached_finding(token, 2 + len(option) + 1, kind, "long_option", "strong", option=f"--{normalized}")
            else:
                value_token = tokens[index + 1] if index + 1 < len(tokens) else None
                if value_token is not None and (value_token.value.startswith("-") or prose_word(value_token)):
                    value_token = None
                candidate = token_finding(value_token, kind, "long_option", "strong", option=f"--{normalized}")
            if candidate:
                output.append(candidate)
        return output
    def _short_options(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        for part in segments(tokens):
            command, subcommand = command_pair(part)
            separate_allowed = SHORT_PASSWORD_COMMANDS.get((command, subcommand), SHORT_PASSWORD_COMMANDS.get((command, None)))
            if separate_allowed is None:
                continue
            for index, token in enumerate(part):
                if token.raw == "-p":
                    if not separate_allowed:
                        continue  # mysql: next token is the database, password is prompted
                    value_token = part[index + 1] if index + 1 < len(part) else None
                    if value_token is not None and value_token.value.startswith("-"):
                        continue
                    candidate = token_finding(value_token, "PASSWORD", "short_option", "strong", command=command, option="-p")
                elif token.raw.startswith("-p") and len(token.raw) > 2:
                    candidate = attached_finding(token, 2, "PASSWORD", "short_option", "strong", command=command, option="-p")
                else:
                    candidate = None
                if candidate:
                    output.append(candidate)
        return output

    def _pipes(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        for index, token in enumerate(tokens):
            if token.raw != "|":
                continue
            left, right = left_segment(tokens, index), right_segment(tokens, index)
            if not left or not right:
                continue
            is_sink, sink = semantic_sink(right)
            command, _ = command_pair(left)
            if not is_sink or command not in {"echo", "printf"}:
                continue
            args = command_words(left)[1:]
            if command == "echo":
                values = [item for item in args if not item.value.startswith("-")]
                value_token = values[0] if values else None
            else:
                # printf's first argument is the format; the final one is data.
                value_token = args[-1] if len(args) >= 2 else None
            candidate = token_finding(value_token, "PASSWORD", "stdin_sink", "strong", source=command, sink=sink)
            if candidate:
                output.append(candidate)
        return output

    def _here_strings(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        for index, token in enumerate(tokens):
            if token.raw != "<<<" or index + 1 >= len(tokens):
                continue
            left = left_segment(tokens, index)
            is_sink, sink = semantic_sink(left) if left else (False, "")
            if not is_sink:
                continue
            candidate = token_finding(tokens[index + 1], "PASSWORD", "here_string", "strong", sink=sink)
            if candidate:
                output.append(candidate)
        return output

    def _heredocs(self, tokens: list[ShellToken], following: list[tuple[int, str]]) -> list[RawFinding]:
        output = []
        if not any(token.raw in {"<<", "<<-"} for token in tokens):
            return output
        pipeline = segments(tokens, frozenset({"|"}))
        part_ends = [part[-1].end for part in pipeline]
        sinks = [semantic_sink(part) for part in pipeline]
        commands = [command_pair(part)[0] for part in pipeline]
        for index, token in enumerate(tokens):
            if token.raw not in {"<<", "<<-"} or index + 1 >= len(tokens) or tokens[index + 1].operator:
                continue
            tag = tokens[index + 1].value
            receiver_index = bisect.bisect_left(part_ends, token.start)
            if receiver_index >= len(pipeline):
                continue
            receiver_sink, sink = sinks[receiver_index]
            if not receiver_sink:
                downstream = [item for item in sinks[receiver_index + 1:] if item[0]]
                if commands[receiver_index] not in STDIN_PASSTHROUGH or not downstream:
                    continue
                sink = downstream[0][1]
            strip_tabs = token.raw == "<<-"
            for line_start, line in following:
                body_line = line.lstrip("\t") if strip_tabs else line
                if body_line.strip() == tag:
                    break
                value = line.strip()
                if not value:
                    continue
                if plausible(value):
                    start = line_start + line.index(value)
                    output.append(finding(start, start + len(value), "PASSWORD", "heredoc", "strong", sink=sink))
                break  # the sink reads only the first line as the password
        return output

    def _powershell(self, tokens: list[ShellToken]) -> list[RawFinding]:
        output = []
        for index, token in enumerate(tokens):
            if token.operator:
                continue
            name = token.value.lstrip("(").lower()
            if name == "convertto-securestring":
                rest = tokens[index + 1:]
                for position, item in enumerate(rest):
                    if item.operator:
                        break
                    if item.value.lower() == "-string" and position + 1 < len(rest):
                        item = rest[position + 1]
                    elif item.value.startswith("-"):
                        continue
                    candidate = self._powershell_value(item, "PASSWORD", "ConvertTo-SecureString")
                    if candidate:
                        output.append(candidate)
                    break
                continue
            if not token.raw.startswith("-") or token.raw.startswith("--"):
                continue
            option, separator, _ = token.raw[1:].partition("=")
            option = option.rstrip(":")
            kind = POWERSHELL_PARAMS.get(option.lower().replace("-", "").replace("_", ""))
            if not kind:
                continue
            if separator:
                candidate = attached_finding(token, 1 + len(option) + 1, kind, "powershell_param", "strong", option=f"-{option}")
            else:
                value_token = tokens[index + 1] if index + 1 < len(tokens) else None
                candidate = self._powershell_value(value_token, kind, f"-{option}") if value_token else None
            if candidate:
                output.append(candidate)
        return output

    @staticmethod
    def _powershell_value(token: ShellToken | None, kind: str, option: str) -> RawFinding | None:
        if token is None or token.operator:
            return None
        raw = token.raw.rstrip(")")
        if raw.startswith(("-", "(", "$", "@")):
            return None
        value, start, end = value_span(raw, token.start)
        if not plausible(value):
            return None
        family = "powershell_securestring" if option == "ConvertTo-SecureString" else "powershell_param"
        return finding(start, end, kind, family, "strong", option=option)

    def _send_calls(self, text: str) -> list[RawFinding]:
        output = []
        for match in SEND_CALL.finditer(text):
            window_start = max(0, match.start() - 256)
            expects = list(EXPECT_CALL.finditer(text, window_start, match.start()))
            if not expects:
                continue
            prompt = text[expects[-1].start():match.start()]
            if not EXPECT_CUE.search(prompt):
                continue
            value = match.group("value")
            suffix = next((item for item in (r"\r\n", r"\r", r"\n") if value.endswith(item)), "")
            core = value[:-len(suffix)] if suffix else value
            if plausible(core):
                start = match.start("value")
                output.append(finding(start, start + len(core), "PASSWORD", "expect_send", "ambiguous", call="send"))
        return output

    def _function_calls(self, text: str) -> list[RawFinding]:
        output = []
        for match in FUNCTION_CALL.finditer(text):
            name = match.group("name").split(".")[-1]
            words = split_identifier(name)
            strong_name = bool(words & STRONG_FUNCTION_WORDS)
            cue_name = strong_name or bool(words & AMBIGUOUS_FUNCTION_WORDS)
            args_start = match.start("args")
            keyword_hits, positional = [], []
            offset = 0
            for part in split_args(match.group("args")):
                keyword = KEYWORD_ARG.match(part)
                literal = STRING_LITERAL.search(part, keyword.end() if keyword else 0)
                is_whole_arg = literal is not None and (
                    literal.start() == keyword.end() if keyword else part[:literal.start()].strip() == ""
                )
                if is_whole_arg:
                    entry = (args_start + offset + literal.start("value"), literal.group("value"))
                    if keyword is None:
                        positional.append(entry)
                    elif self._credential_key(keyword.group("key")):
                        keyword_hits.append(entry)
                offset += len(part) + 1
            # A credential-named keyword argument is evidence on its own; a
            # positional literal needs a credential-meaning function name.
            chosen = [(item, "strong") for item in keyword_hits]
            if not chosen and cue_name and positional:
                chosen = [(positional[-1], "strong" if strong_name else "ambiguous")]
            for (start, value), strength in chosen:
                if not plausible(value):
                    continue
                kind = "TOKEN" if "token" in words else "SECRET" if "secret" in words else "PASSWORD"
                output.append(finding(start, start + len(value), kind, "function_argument", strength, function=name.lower()))
        return output

    @staticmethod
    def _credential_key(key: str) -> bool:
        words = split_identifier(key)
        return bool(words & CREDENTIAL_KEY_WORDS) or key.lower().replace("_", "") in CREDENTIAL_KEY_NAMES

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

