"""Public Python API for the Ruijie campus authenticator."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import get_if_hwaddr
from scapy.interfaces import resolve_iface

from .cli import LOG, Supplicant, choose_interface, send_logoff, setup_logging


class _MemoryLogHandler(logging.Handler):
    def __init__(self, records: list[str]) -> None:
        super().__init__(logging.DEBUG)
        self.records = records
        self.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
            )
        )

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(self.format(record))


class RuijieClient:
    """Stateful, reusable client for login, logout, and status inspection."""

    def __init__(
        self,
        username: str,
        password: str,
        *,
        interface: str | None = None,
        encoding: str = "gb18030",
        timeout: float = 30.0,
        retries: int = 3,
        repeats: int = 3,
        log_file: str | Path | None = "ruijie-auth.log",
        verbose: bool = False,
    ) -> None:
        self.username = username
        self._password = password
        self.requested_interface = interface
        self.encoding = encoding
        self.timeout = timeout
        self.retries = max(1, retries)
        self.repeats = max(1, repeats)
        self.logs: list[str] = []
        self._handler = _MemoryLogHandler(self.logs)
        self._interface: str | None = None
        self._status: dict[str, Any] = {
            "state": "idle",
            "authenticated": False,
            "message": "尚未开始认证",
            "interface": None,
            "interface_description": None,
            "ip": None,
            "mac": None,
            "started_at": None,
            "finished_at": None,
            "logs": self.logs,
        }
        if log_file is not None:
            setup_logging(Path(log_file), verbose)

    def _select_interface(self) -> str:
        if self._interface is None:
            self._interface = choose_interface(self.requested_interface)
        info = resolve_iface(self._interface)
        self._status.update(
            interface=self._interface,
            interface_description=str(getattr(info, "description", info.name)),
            ip=str(getattr(info, "ip", "") or ""),
            mac=get_if_hwaddr(self._interface),
        )
        return self._interface

    def login(self) -> bool:
        """Authenticate synchronously and return whether authentication succeeded."""
        if not self.username:
            raise ValueError("username cannot be empty")
        if not self._password:
            raise ValueError("password cannot be empty")

        self.logs.clear()
        self._status.update(
            state="authenticating",
            authenticated=False,
            message="正在认证",
            started_at=datetime.now().astimezone().isoformat(timespec="seconds"),
            finished_at=None,
        )
        LOG.addHandler(self._handler)
        try:
            interface = self._select_interface()
            identity = self.username.encode(self.encoding)
            password = self._password.encode(self.encoding)
            ok = Supplicant(
                interface=interface,
                identity=identity,
                password=password,
                timeout=self.timeout,
                retries=self.retries,
                repeats=self.repeats,
            ).authenticate()
            self._status.update(
                state="authenticated" if ok else "failed",
                authenticated=ok,
                message="认证成功" if ok else "认证失败",
            )
            return ok
        except Exception as exc:
            self._status.update(state="error", authenticated=False, message=str(exc))
            LOG.exception("认证过程中发生错误")
            return False
        finally:
            self._status["finished_at"] = datetime.now().astimezone().isoformat(
                timespec="seconds"
            )
            LOG.removeHandler(self._handler)

    def logout(self) -> None:
        """Send EAPOL-Logoff on the selected interface."""
        LOG.addHandler(self._handler)
        try:
            send_logoff(self._select_interface())
            self._status.update(
                state="logged_out", authenticated=False, message="已注销"
            )
        finally:
            LOG.removeHandler(self._handler)

    def status(self) -> dict[str, Any]:
        """Return a snapshot suitable for JSON serialization."""
        result = dict(self._status)
        result["logs"] = list(self.logs)
        return result

    def stat(self) -> dict[str, Any]:
        """Compatibility alias for :meth:`status`."""
        return self.status()


def login(username: str, password: str, **options: Any) -> RuijieClient:
    """Create a client, authenticate immediately, and return the client."""
    client = RuijieClient(username, password, **options)
    client.login()
    return client
