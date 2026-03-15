"""
YAML configuration loader with ${ENV_VAR} and ${ENV_VAR:default} interpolation.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .models import AppConfig

# Matches ${VAR} and ${VAR:default}
_ENV_VAR_RE = re.compile(r"\$\{([^}:]+)(?::([^}]*))?\}")


def _interpolate(value: Any) -> Any:
    """Recursively walk a parsed YAML structure and expand env-var placeholders."""
    if isinstance(value, str):
        def _replace(match: re.Match) -> str:
            var_name = match.group(1)
            default = match.group(2)  # may be None
            env_value = os.environ.get(var_name)
            if env_value is not None:
                return env_value
            if default is not None:
                return default
            raise ValueError(
                f"Required environment variable '{var_name}' is not set "
                f"and no default was provided in config"
            )

        return _ENV_VAR_RE.sub(_replace, value)

    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}

    if isinstance(value, list):
        return [_interpolate(item) for item in value]

    return value


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load and validate the application configuration.

    Resolution order for the config file path:
    1. The ``path`` argument (if provided).
    2. The ``CONFIG_PATH`` environment variable.
    3. ``./config.yaml`` relative to the current working directory.
    """
    if path is None:
        path = os.environ.get("CONFIG_PATH", "config.yaml")

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path.resolve()}")

    with config_path.open("r") as fh:
        raw = yaml.safe_load(fh)

    if raw is None:
        raw = {}

    interpolated = _interpolate(raw)
    return AppConfig.model_validate(interpolated)
