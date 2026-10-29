"""Regression tests for shell_aware 0.2.0 (2026-10-29 review).

All values are synthetic, non-functional fixtures. Failure messages print
case names and families only, never candidate values.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector.adapters.shell_aware import ShellAwareAdapter  # noqa: E402

PW = "Zq7xPw1234x"  # synthetic


def scan(text: str):
    return ShellAwareAdapter("shell-aware", {}, Path(".")).scan(text)


def values(text: str) -> list[str]:
    return [text[item.start:item.end] for item in scan(text)]


def mask(text: str) -> str:
    spans = sorted((item.start, item.end) for item in scan(text))
    out, cursor, counter = [], 0, 0
    for start, end in spans:
        if start < cursor:
            continue
        counter += 1
        out.append(text[cursor:start])
        out.append(f"[PASSWORD_{counter}]")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


POSITIVES = {
    # name: (text, exact value that must be fully covered)
    "long_option_space": (f"app --password {PW} run", PW),
    "long_option_equals": (f"app --api-key={PW}", PW),
    "long_option_quoted_space": ('app --password="correct horse battery" run', "correct horse battery"),
    "long_option_single_quoted": ("app --token 'p@ss;word&x'", "p@ss;word&x"),
    "long_option_unterminated_quote": ('app --password "abc def', "abc def"),
    "sshpass_separate": (f"sshpass -p {PW} ssh host", PW),
    "sshpass_attached": (f"sshpass -p{PW} ssh host", PW),
    "docker_login_p": (f"docker login -u bot -p {PW} registry.example.invalid", PW),
    "mysql_attached": (f"mysql -u root -p{PW} shopdb", PW),
    "mysql_attached_quoted_space": ('mysql -u root -p"my secret pw" db', "my secret pw"),
    "echo_sudo_S": (f"echo {PW} | sudo -S apt update", PW),
    "echo_sudo_kS": (f"echo {PW} | sudo -kS apt update", PW),
    "echo_sudo_u_S": (f"echo {PW} | sudo -u admin -S true", PW),
    "printf_docker_stdin": (f"printf '%s' {PW} | docker login -u bot --password-stdin", PW),
    "here_string_sudo": (f"sudo -S true <<< {PW}", PW),
    "heredoc_sudo": (f"sudo -S bash <<EOF\n{PW}\napt update\nEOF", PW),
    "heredoc_cat_pipe_sudo": (f"cat <<EOF | sudo -S apt update\n{PW}\nEOF", PW),
    "line_continuation": (f"sshpass -p \\\n  {PW} ssh host", PW),
    "line_continuation_crlf": (f"sshpass -p \\\r\n  {PW} ssh host", PW),
    "expect_password": (f'expect "Password:"\nsend "{PW}\\r"', PW),
    "pexpect_password": (f"child.expect('Password: ')\nchild.sendline('{PW}')", PW),
    "function_login_positional": (f'login("admin", "{PW}")', PW),
    "function_set_password": (f'client.set_password("{PW}")', PW),
    "function_keyword_password": (f'connect(host="db.local", password="{PW}")', PW),
    "function_camel": (f'getApiToken("{PW}")', PW),
    "function_kw_api_key": (f'Client(api_key="{PW}")', PW),
    "powershell_securestring": (f'(ConvertTo-SecureString "{PW}" -AsPlainText -Force)', PW),
    "powershell_param": (f'Connect-Thing -Password "{PW}" -Server x', PW),
    "hashicorp_single_dash": (f"vault login -token={PW}", PW),
    "korean_context_offsets": (f"서버 접속 비번 예시:\n$ sshpass -p {PW} ssh 서버", PW),
    "markdown_inline_code": (f"이렇게 실행해: `sshpass -p {PW} ssh host`", PW),
    "emoji_context_offsets": (f'echo "🚀{PW}" | sudo -S true', PW),
}

NEGATIVES = {
    "mkdir_p": "mkdir -p build",
    "ssh_port": "ssh -p 2222 localhost",
    "docker_run_port": "docker run -p 8080:80 nginx",
    "pytest_plugin": "pytest -p plugin_name",
    "cp_preserve": "cp -p source target",
    "sendline_no_cue": 'sendline("hello world")',
    "mysql_p_then_db": "mysql -u root -p mydb",
    "mysqldump_p_then_db": "mysqldump -u root -p shopdb > dump.sql",
    "long_option_then_option": "mysql --password --user root",
    "long_option_variable": 'gh api --token "$GITHUB_TOKEN" /user',
    "long_option_braced_variable": "app --password ${DB_PASSWORD}",
    "long_option_substitution": "app --password $(cat pw.txt)",
    "tokenize_call": 'ids = tokenize("hello world")',
    "count_tokens_call": 'n = count_tokens("some prompt text")',
    "set_author_call": 'set_author("Kim Sehun")',
    "authenticate_username_kw": 'authenticate(request, username="bob")',
    "sudo_lowercase_s": "echo hello | sudo -s",
    "sudo_S_after_command": "echo hello | sudo psql -S",
    "expect_yes_no": 'expect "login:"\nsend "admin\\r"\nexpect "(yes/no)"\nsend "yes\\r"',
    "echo_variable_sudo": 'echo "$PASSWORD" | sudo -S true',
    "placeholder_rescan": "sshpass -p [PASSWORD_1] ssh host",
    "angle_placeholder": "app --password <your-password>",
    "powershell_variable": "Connect-Thing -Password $securePw",
    "heredoc_not_sink": "cat <<EOF > notes.txt\nhello\nEOF",
    "sorted_key_kw": 'sorted(items, key="name")',
    "pass_through_kw": 'run(pass_through="yes")',
    "prose_mentions_mysql_p": "mysql 옵션 중 -p 는 비밀번호 프롬프트를 띄운다",
}

HEREDOC_EXTRA_LINES = f"sudo -S bash <<EOF\n{PW}\napt update\nEOF"


class ShellAwareRegression(unittest.TestCase):
    def test_positives_fully_covered(self):
        for name, (text, secret) in POSITIVES.items():
            with self.subTest(case=name):
                start = text.index(secret)
                end = start + len(secret)
                covering = [item for item in scan(text) if item.start <= start and item.end >= end]
                self.assertTrue(covering, f"{name}: value not fully covered")

    def test_no_partial_leak(self):
        for name, (text, secret) in POSITIVES.items():
            with self.subTest(case=name):
                self.assertFalse(secret in mask(text), f"{name}: value still visible after masking")
                # no fragment of a multi-word secret left behind either
                for word in re.split(r"\s+", secret):
                    if len(word) >= 3:
                        self.assertFalse(word in mask(text), f"{name}: fragment visible")

    def test_negatives_produce_nothing(self):
        for name, text in NEGATIVES.items():
            with self.subTest(case=name):
                self.assertEqual([item.family for item in scan(text)], [], f"{name}: unexpected candidate(s)")

    def test_heredoc_only_first_line(self):
        found = values(HEREDOC_EXTRA_LINES)
        self.assertEqual(found, [PW])

    def test_expect_only_password_prompt(self):
        text = f'expect "login:"\nsend "admin\\r"\nexpect "assword:"\nsend "{PW}\\r"'
        self.assertEqual(values(text), [PW])

    def test_rescan_after_mask_is_empty(self):
        for name, (text, _) in POSITIVES.items():
            with self.subTest(case=name):
                self.assertEqual(scan(mask(text)), [], f"{name}: masked output re-triggers")

    def test_offsets_are_code_points(self):
        text, secret = POSITIVES["emoji_context_offsets"]
        item = scan(text)[0]
        # Python code-point offsets: the quoted value (emoji included) is exact.
        self.assertEqual(text[item.start:item.end], "\U0001F680" + secret)

    def test_evidence_has_no_raw_value(self):
        for name, (text, secret) in POSITIVES.items():
            with self.subTest(case=name):
                for item in scan(text):
                    self.assertNotIn(secret, repr(item.evidence))
                    self.assertNotIn(secret, item.rule_id)


if __name__ == "__main__":
    unittest.main()
