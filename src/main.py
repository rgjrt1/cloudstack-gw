"""
Uvicorn entry point and logging setup.
"""
from __future__ import annotations

import logging
import os
import sys

import uvicorn

from .cache import build_cache
from .cloudstack_client import CloudStackClient
from .config import load_config
from .middleware import build_app
from .oidc_auth import OidcProvider


def _configure_logging(level: str) -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )


def main() -> None:
    # Load configuration
    config_path = os.environ.get("CONFIG_PATH", "config.yaml")
    try:
        config = load_config(config_path)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR loading config: {exc}", file=sys.stderr)
        sys.exit(1)

    _configure_logging(config.server.log_level)
    logger = logging.getLogger(__name__)
    logger.info("Loaded config from %s", config_path)

    # Build dependencies
    cs_client = CloudStackClient(
        api_url=config.cloudstack.api_url,
        api_key=config.cloudstack.api_key,
        secret_key=config.cloudstack.secret_key,
        verify_ssl=config.cloudstack.verify_ssl,
        timeout=config.cloudstack.timeout,
    )
    cache = build_cache(config)
    oidc_provider = OidcProvider(config.oidc) if config.oidc else None

    # Build FastAPI app
    app = build_app(config, cs_client, cache, oidc_provider)

    # Run with uvicorn
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level=config.server.log_level.lower(),
    )


if __name__ == "__main__":
    main()
