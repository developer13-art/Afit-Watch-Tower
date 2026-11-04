"""Entry point for `python -m watchtower.cloud serve|worker|verify|service-key`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
