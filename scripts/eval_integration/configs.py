"""The eight configurations of the integration measurement (eval/integration-1118, release/defaults-1120).

1 is main as it was before the four PRs; 2 is this branch with every setting off; 3-6 turn on one thing each on top
of 2; 7 turns everything on; 8 is the new defaults (release/defaults-1120) with PG_REMASK=off, against 7 for the gold
spans only the re-mask covered. Every setting is set explicitly (or removed, for 1) so neither the shell nor a default
can change a run. 9 is the new defaults with candidate_policy "verifier" (#28, promptguard run --policy verifier): the
back-end verifier re-judges the ambiguous candidates; its bundle comes from PG_VERIFIER_BUNDLE. Every other configuration
sets the policy to union, the default.
"""

from __future__ import annotations

MAIN_COMMIT = "668c2c1"

# name: (value when off, value when on). "off" is the behaviour before the four PRs.
SETTINGS = {
    "PG_DETECTOR_FILTERS": ("off", "on"),
    "PG_DETECTOR_FILTER_DUMMY": ("off", "on"),
    "PG_REMASK_SHORT": ("substring", "boundary"),
    "PG_SHELL_POSITIONAL_MIN": ("1", "4"),
    "PG_RULE_HEX_KEY": ("off", "on"),
    # No effect on the detection scorer (system prompt, tool input restore, count_tokens); set in 7 for completeness.
    "PG_PLACEHOLDER_GUIDE": ("off", "on"),
    "PG_RESTORE_ESCAPED": ("off", "on"),
    "PG_GUARD_COUNT_TOKENS": ("block", "mask"),
}
# The defaults of release/defaults-1120 (README, tests/launcher/defaults.test.cjs).
NEW_DEFAULTS = {
    "PG_DETECTOR_FILTERS": "on",
    "PG_DETECTOR_FILTER_DUMMY": "off",
    "PG_REMASK_SHORT": "boundary",
    "PG_SHELL_POSITIONAL_MIN": "4",
    "PG_RULE_HEX_KEY": "on",
    "PG_PLACEHOLDER_GUIDE": "on",
    "PG_RESTORE_ESCAPED": "on",
    "PG_GUARD_COUNT_TOKENS": "block",
}
# The re-mask switch (release/defaults-1120). Not one of the four PRs' settings: on in 2-7 as it always was.
REMASK = "PG_REMASK"
# #28's policy switch (PG_DETECTOR_CANDIDATE_POLICY, what --policy sets). union is the default and stays it.
POLICY = "PG_DETECTOR_CANDIDATE_POLICY"
ALL_SETTINGS = (*SETTINGS, REMASK, POLICY)


def _env(*on: str, remask: str = "on") -> dict[str, str]:
    return {**{name: (values[1] if name in on else values[0]) for name, values in SETTINGS.items()}, REMASK: remask, POLICY: "union"}


# name -> (system root: "main" or "branch", environment, short label)
CONFIGS = {
    "1-main": ("main", None, f"main {MAIN_COMMIT}"),
    "2-off": ("branch", _env(), "integration, all off"),
    "3-filters": ("branch", _env("PG_DETECTOR_FILTERS"), "+FILTERS"),
    "4-filters-dummy": ("branch", _env("PG_DETECTOR_FILTERS", "PG_DETECTOR_FILTER_DUMMY"), "+FILTERS+DUMMY"),
    "5-floor": ("branch", _env("PG_REMASK_SHORT", "PG_SHELL_POSITIONAL_MIN"), "+REMASK_SHORT=boundary+POSITIONAL_MIN=4"),
    "6-hex": ("branch", _env("PG_RULE_HEX_KEY"), "+HEX_KEY"),
    "7-all": ("branch", _env(*SETTINGS), "all on"),
    "8-defaults-no-remask": ("branch", {**NEW_DEFAULTS, REMASK: "off", POLICY: "union"}, "new defaults + REMASK=off"),
    "9-defaults-verifier": ("branch", {**NEW_DEFAULTS, REMASK: "on", POLICY: "verifier"}, "new defaults + --policy verifier"),
}
# Configurations that need the verifier bundle (PG_VERIFIER_BUNDLE).
NEEDS_VERIFIER = ("9-defaults-verifier",)
# Newly missed gold is counted against this configuration.
BASELINE = {"2-off": "1-main", "3-filters": "2-off", "4-filters-dummy": "2-off", "5-floor": "2-off", "6-hex": "2-off", "7-all": "2-off",
            "8-defaults-no-remask": "7-all", "9-defaults-verifier": "7-all"}
# Configurations run on every set of --nine, not only on CredData-trajectory and real traffic.
ALL_SETS = ("1-main", "7-all", "8-defaults-no-remask", "9-defaults-verifier")
