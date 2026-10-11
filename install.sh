#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_python_312() {
  local candidate version

  if [[ -n "${PROMPTGUARD_PYTHON:-}" ]]; then
    candidate="$PROMPTGUARD_PYTHON"
    if [[ "$candidate" != */* ]]; then
      candidate="$(command -v "$candidate" 2>/dev/null || true)"
    fi
    if [[ -x "$candidate" ]]; then
      version="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || true)"
      if [[ "$version" == 3.12.* ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
    printf 'PROMPTGUARD_PYTHON must point to Python 3.12.\n' >&2
    return 1
  fi

  for candidate in python3.12 python3 python; do
    candidate="$(command -v "$candidate" 2>/dev/null || true)"
    [[ -n "$candidate" ]] || continue
    version="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || true)"
    if [[ "$version" == 3.12.* ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

PYTHON_BIN="$(find_python_312 || true)"
if [[ -z "$PYTHON_BIN" ]]; then
  printf 'Python 3.12 was not found. Install it and run this script again.\n' >&2
  printf 'Homebrew example: brew install python@3.12\n' >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  printf 'Node.js was not found. Install Node.js LTS and run this script again.\n' >&2
  exit 1
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  if ! command -v xcrun >/dev/null 2>&1 || ! xcrun --find clang >/dev/null 2>&1; then
    printf 'Xcode Command Line Tools are required to build a CredSweeper dependency.\n' >&2
    printf 'Run: xcode-select --install\n' >&2
    exit 1
  fi
fi

VENV="$ROOT/.venv"
VENV_PYTHON="$VENV/bin/python"
if [[ ! -x "$VENV_PYTHON" ]]; then
  "$PYTHON_BIN" -m venv "$VENV"
fi

"$VENV_PYTHON" -m pip install --disable-pip-version-check -r "$ROOT/requirements.txt"

if ! command -v claude >/dev/null 2>&1; then
  printf '\nWARNING: Claude Code CLI was not found. Install the validated version with:\n' >&2
  printf 'npm install -g @anthropic-ai/claude-code@2.1.291\n' >&2
else
  CLAUDE_VERSION="$(claude --version 2>/dev/null || true)"
  if [[ "$CLAUDE_VERSION" != *2.1.291* ]]; then
    printf 'WARNING: validated Claude Code version is 2.1.291; current: %s\n' "$CLAUDE_VERSION" >&2
  fi
fi

GITLEAKS_STATUS="not found (optional detector module will be skipped; macOS: brew install gitleaks)"
if command -v gitleaks >/dev/null 2>&1; then
  GITLEAKS_STATUS="$(gitleaks version 2>/dev/null || printf 'unknown version')"
fi

PYTHON_VERSION="$("$VENV_PYTHON" -c 'import platform; print(platform.python_version())')"
printf '\nPromptGuard Demo V0 installation complete\n'
printf 'Python: %s\n' "$PYTHON_VERSION"
printf 'CredSweeper: 1.19.0 (ML OFF)\n'
printf 'Gitleaks: %s\n' "$GITLEAKS_STATUS"
printf 'Next: cd sample-protected-project && ../start-promptguard.sh\n'
