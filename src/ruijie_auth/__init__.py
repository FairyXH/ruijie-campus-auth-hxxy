"""Ruijie-compatible campus network authentication client."""

from __future__ import annotations

from typing import Any

__all__ = ["RuijieClient", "login"]
__version__ = "0.2.0"


def __getattr__(name: str) -> Any:
    if name in __all__:
        from .api import RuijieClient, login

        return {"RuijieClient": RuijieClient, "login": login}[name]
    raise AttributeError(name)
