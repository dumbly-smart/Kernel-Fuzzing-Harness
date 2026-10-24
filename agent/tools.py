"""Explicit local tools used by the scripted driver and future ReAct policy."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import socket
import subprocess
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from agent.call_log import ToolCallContext, ToolCallLogger


MAX_HTTP_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 10


class _LoopbackRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_loopback_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _validate_loopback_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("HTTP tool accepts only credential-free loopback http URLs")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 80, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"loopback host could not be resolved: {parsed.hostname}") from exc
    if not addresses or any(not ipaddress.ip_address(item[4][0].split("%", 1)[0]).is_loopback
                            for item in addresses):
        raise ValueError("HTTP tool is restricted to loopback destinations")


class AgentTools:
    """Run file tools under workspace root and network requests to loopback only."""

    def __init__(self, workspace: Path, logger: ToolCallLogger):
        self.workspace = workspace.resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError("workspace must be an existing directory")
        self.logger = logger

    def _workspace_path(self, relative_path: str) -> Path:
        if not isinstance(relative_path, str) or not relative_path:
            raise ValueError("path must be a non-empty relative path inside the workspace")
        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise ValueError("path must remain inside the workspace")
        resolved = (self.workspace / candidate).resolve(strict=False)
        if not resolved.is_relative_to(self.workspace):
            raise ValueError("path must remain inside the workspace")
        return resolved

    def read_file(self, path: str) -> str:
        args = {"path": path}

        def action(_context: ToolCallContext) -> str:
            resolved = self._workspace_path(path)
            if not resolved.is_file():
                raise ValueError(f"not a workspace file: {path}")
            return resolved.read_text(encoding="utf-8")

        return self.logger.invoke("file_read", args, action)

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        args = {"path": path, "content": content}

        def action(_context: ToolCallContext) -> dict[str, Any]:
            resolved = self._workspace_path(path)
            if not isinstance(content, str):
                raise ValueError("file content must be a string")
            resolved.parent.mkdir(parents=True, exist_ok=True)
            data = content.encode("utf-8")
            resolved.write_bytes(data)
            return {"path": path, "bytes_written": len(data)}

        return self.logger.invoke("file_write", args, action)

    def shell(self, command: str, *, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
        args = {"command": command, "timeout_seconds": timeout_seconds}

        def action(context: ToolCallContext) -> dict[str, Any]:
            if not isinstance(command, str) or not command:
                raise ValueError("shell command must be a non-empty string")
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
                raise ValueError("timeout_seconds must be a positive integer")
            process = subprocess.Popen(
                command,
                shell=True,
                executable="/bin/bash",
                cwd=self.workspace,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                close_fds=True,
            )
            context.set_process(process.pid, tgid=process.pid)
            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                return {"stdout": stdout, "stderr": stderr, "return_code": 124,
                        "timed_out": True}
            return {"stdout": stdout, "stderr": stderr,
                    "return_code": process.returncode, "timed_out": False}

        return self.logger.invoke("shell", args, action)

    def http_get(self, url: str, *, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
        args = {"url": url, "timeout_seconds": timeout_seconds}

        def action(_context: ToolCallContext) -> dict[str, Any]:
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
                raise ValueError("timeout_seconds must be a positive integer")
            _validate_loopback_url(url)
            request = Request(url, headers={"User-Agent": "tripwire-agent/1"})
            opener = build_opener(_LoopbackRedirectHandler())
            try:
                response = opener.open(request, timeout=timeout_seconds)
            except HTTPError as exc:
                response = exc
            with response:
                body = response.read(MAX_HTTP_BYTES + 1)
                if len(body) > MAX_HTTP_BYTES:
                    raise ValueError(f"HTTP response exceeds {MAX_HTTP_BYTES} bytes")
                return {"status": response.status,
                        "body": body.decode("utf-8", errors="replace"),
                        "bytes_read": len(body),
                        "url": response.geturl()}

        return self.logger.invoke("http_get", args, action)
