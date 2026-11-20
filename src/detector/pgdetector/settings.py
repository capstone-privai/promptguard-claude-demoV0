"""The detector's PG_* settings and their defaults, in one place (release/defaults-1120).

The Native Mod's (transform) and the Final Guard's (verification) workers run this same code, so they read the same
defaults; the supervisor still compares what each reports (filters.filter_settings). An unset or empty variable takes
the default; any other value is used as given, and for an on/off setting only "on" is on (so "off" turns it off).

The Mod-side defaults (PG_REMASK, PG_REMASK_SHORT, PG_PLACEHOLDER_GUIDE, PG_RESTORE_ESCAPED) are in
src/native-mod/hooks/register.mjs (DEFAULTS) and the Guard's PG_GUARD_COUNT_TOKENS in src/guard/lib.cjs;
tests/launcher/defaults.test.cjs checks all three against one table.
"""

from __future__ import annotations

import os

DEFAULTS = {
    "PG_DETECTOR_FILTERS": "on",
    "PG_DETECTOR_FILTER_DUMMY": "off",
    "PG_RULE_HEX_KEY": "on",
    "PG_SHELL_POSITIONAL_MIN": "4",
    "PG_PLACEHOLDER_PUBLIC_PREFIX": "off",
}


def value(name: str) -> str:
    raw = os.environ.get(name)
    return DEFAULTS[name] if raw is None or raw.strip() == "" else raw.strip()


def enabled(name: str) -> bool:
    return value(name) == "on"
