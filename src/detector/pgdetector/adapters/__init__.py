"""Built-in adapters, imported lazily so a disabled tool is never loaded."""

ADAPTER_TYPES = {
    "credsweeper": "pgdetector.adapters.credsweeper:CredSweeperAdapter",
    "gitleaks": "pgdetector.adapters.gitleaks:GitleaksAdapter",
    "patterns": "pgdetector.adapters.patterns:PatternAdapter",
    "shell-aware": "pgdetector.adapters.shell_aware:ShellAwareAdapter",
}
