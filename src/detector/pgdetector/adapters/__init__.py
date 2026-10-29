"""Built-in adapters, imported lazily so a disabled tool is never loaded."""

ADAPTER_TYPES = {
    "credsweeper": "pgdetector.adapters.credsweeper:CredSweeperAdapter",
    "gitleaks": "pgdetector.adapters.gitleaks:GitleaksAdapter",
    "patterns": "pgdetector.adapters.patterns:PatternAdapter",
    "shell-aware": "pgdetector.adapters.shell_aware:ShellAwareAdapter",
    "ml-v9": "pgdetector.adapters.span_models:MLV9Adapter",
    "ml-qwen": "pgdetector.adapters.span_models:QwenAdapter",
}
