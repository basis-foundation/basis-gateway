"""Process-management harness for the Phase 1B.2 real-NGINX integration
suite (tests/integration/test_producer_mtls_trusted_proxy_boundary.py).

Launches two real, independent processes for each test module run:

  1. ``TrustedProxyBackend`` -- the minimal ASGI test application
     (``tests/integration/trusted_proxy_app.py``) under a real Uvicorn
     subprocess, bound ONLY to a Unix domain socket (``--uds``). No TCP
     application listener exists in this topology (ADR-0009 §9).
  2. ``NginxProducerIngress`` -- a real ``nginx`` subprocess, rendered from
     ``examples/producer-mtls/nginx.conf.template``, terminating producer
     mTLS and proxying only ``POST /v1/evaluate/operation-aware`` to the
     backend's Unix socket.

All ports, socket paths, certificate paths, and nginx runtime paths
(pid/log/temp directories) are ephemeral and scoped to a single test
session's temporary directory -- nothing here depends on, or writes to, a
system-wide nginx installation, a privileged port, or a running system nginx
daemon.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_HARNESS_DIR = Path(__file__).parent
_TEMPLATE_PATH = _HARNESS_DIR.parent.parent / "examples" / "producer-mtls" / "nginx.conf.template"
_STARTUP_TIMEOUT_SECONDS = 10.0
_REPO_SRC = _HARNESS_DIR.parent.parent / "src"


def free_port() -> int:
    """Reserve an ephemeral TCP port on 127.0.0.1.

    Same small, accepted TOCTOU race as the Phase 1A spike's equivalent
    helper (tests/integration/test_producer_mtls_transport.py) -- the
    standard approach used throughout this repository's other integration
    tests.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def render_nginx_config(substitutions: dict[str, str]) -> str:
    """Render ``examples/producer-mtls/nginx.conf.template`` by replacing
    every ``@@TOKEN@@`` placeholder with its value from *substitutions*.

    Deliberately a plain string-replace, not ``str.format``/
    ``string.Template`` -- nginx configuration syntax itself uses ``{``/
    ``}`` for block delimiters and ``$`` extensively for its own variables
    (``$ssl_client_escaped_cert``, ``$host``), so either of those templating
    mechanisms would collide with the configuration's own syntax. See the
    template file's own header comment.

    Raises:
        ValueError: the template contains a placeholder not present in
            *substitutions*, or *substitutions* contains a key the template
            does not reference (fail closed on a mismatched template/harness
            pair rather than silently rendering a partially-substituted
            configuration).
    """
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    for key, value in substitutions.items():
        token = f"@@{key}@@"
        if token not in text:
            raise ValueError(
                f"nginx.conf.template does not reference placeholder {token!r}; "
                "the harness and the template have drifted apart"
            )
        text = text.replace(token, value)

    remaining = [
        line for line in text.splitlines() if "@@" in line and not line.strip().startswith("#")
    ]
    if remaining:
        raise ValueError(
            "nginx.conf.template still contains unsubstituted @@TOKEN@@ placeholders "
            f"after rendering: {remaining!r}"
        )
    return text


@dataclass
class TrustedProxyTopologyPaths:
    """Every ephemeral filesystem path a single test-run topology needs,
    all rooted under one pytest tmp_path."""

    root: Path

    @property
    def backend_socket_path(self) -> Path:
        return self.root / "gateway-backend.sock"

    @property
    def request_log_path(self) -> Path:
        return self.root / "backend-requests.log"

    @property
    def nginx_prefix_dir(self) -> Path:
        return self.root / "nginx"

    @property
    def nginx_config_path(self) -> Path:
        return self.nginx_prefix_dir / "nginx.conf"

    @property
    def nginx_pid_path(self) -> Path:
        return self.nginx_prefix_dir / "nginx.pid"

    @property
    def nginx_error_log_path(self) -> Path:
        return self.nginx_prefix_dir / "error.log"

    @property
    def nginx_access_log_path(self) -> Path:
        return self.nginx_prefix_dir / "access.log"

    @property
    def nginx_client_body_temp_path(self) -> Path:
        return self.nginx_prefix_dir / "client_body_temp"

    @property
    def nginx_proxy_temp_path(self) -> Path:
        return self.nginx_prefix_dir / "proxy_temp"

    def ensure_directories(self) -> None:
        self.nginx_prefix_dir.mkdir(parents=True, exist_ok=True)
        self.nginx_client_body_temp_path.mkdir(parents=True, exist_ok=True)
        self.nginx_proxy_temp_path.mkdir(parents=True, exist_ok=True)


class TrustedProxyBackend:
    """Launches an ASGI app (``trusted_proxy_app:app`` by default) under a
    real Uvicorn subprocess, bound only to a Unix domain socket. No TCP
    application listener is opened in this topology (ADR-0009 §9) -- this
    is the property the direct-backend-bypass test (Step 11) verifies.

    Phase 1B.3 (``tests/integration/test_producer_mtls_live_gateway.py``)
    reuses this exact class, unmodified in behavior for its default
    arguments, to instead launch the real ``basis_gateway.main:app`` by
    passing ``app_module="basis_gateway.main:app"`` and the additional
    environment variables that application's own ``GatewayConfig`` requires
    -- via *extra_env*, additive on top of ``BASIS_TEST_REQUEST_LOG_PATH``
    and ``PYTHONPATH``, never replacing them.
    """

    def __init__(
        self,
        socket_path: Path,
        request_log_path: Path,
        *,
        app_module: str = "trusted_proxy_app:app",
        extra_env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> None:
        self._socket_path = socket_path
        self._request_log_path = request_log_path
        self._app_module = app_module
        self._extra_env = dict(extra_env) if extra_env else {}
        self._cwd = cwd if cwd is not None else _HARNESS_DIR
        self._process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        if self._socket_path.exists():
            self._socket_path.unlink()
        self._request_log_path.write_text("", encoding="utf-8")

        env = dict(os.environ)
        env["BASIS_TEST_REQUEST_LOG_PATH"] = str(self._request_log_path)
        existing_pythonpath = env.get("PYTHONPATH", "")
        repo_src = str(_REPO_SRC)
        env["PYTHONPATH"] = (
            f"{repo_src}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else repo_src
        )
        env.update(self._extra_env)

        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            self._app_module,
            "--uds",
            str(self._socket_path),
            "--log-level",
            "warning",
        ]
        self._process = subprocess.Popen(  # noqa: S603
            cmd,
            cwd=str(self._cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._wait_until_socket_exists()
        # Restrictive filesystem permissions (0770 or stricter), per
        # producer-mtls-proxy-trust-boundary.md §9. Owner (this test
        # process) and group may read/write/connect; everyone else is
        # denied. This bounds, but does not eliminate, same-host access --
        # see this harness module's and the completion report's residual-risk
        # discussion.
        os.chmod(self._socket_path, 0o770)  # noqa: S103

    def _wait_until_socket_exists(self) -> None:
        deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            assert self._process is not None
            if self._process.poll() is not None:
                output = self._process.stdout.read().decode() if self._process.stdout else ""
                raise RuntimeError(
                    f"trusted-proxy backend exited early (code={self._process.returncode}): "
                    f"{output}"
                )
            if self._socket_path.exists():
                return
            time.sleep(0.05)
        raise RuntimeError(
            f"trusted-proxy backend did not create its Unix socket in time: {self._socket_path}"
        )

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)

    @property
    def pid(self) -> int:
        assert self._process is not None, "backend has not been started"
        return self._process.pid

    def read_request_log(self) -> list[str]:
        if not self._request_log_path.exists():
            return []
        return [
            line for line in self._request_log_path.read_text(encoding="utf-8").splitlines() if line
        ]


class NginxConfigurationError(Exception):
    """``nginx -t`` reported the rendered configuration is invalid."""


class NginxProducerIngress:
    """Launches a real ``nginx`` subprocess from a rendered copy of
    ``examples/producer-mtls/nginx.conf.template``, running as the current
    (unprivileged) test user against an unprivileged localhost port, with
    every runtime path (pid, logs, temp directories) confined to the test's
    own temporary directory.
    """

    def __init__(self, config_path: Path, prefix_dir: Path) -> None:
        self._config_path = config_path
        self._prefix_dir = prefix_dir
        self._process: subprocess.Popen[bytes] | None = None

    def validate_config(self) -> None:
        """Run ``nginx -t`` against the rendered configuration before
        starting it (Phase 1B.2 Step 17). Raises ``NginxConfigurationError``
        with nginx's own diagnostic output on failure.
        """
        result = subprocess.run(  # noqa: S603
            ["nginx", "-t", "-c", str(self._config_path), "-p", str(self._prefix_dir)],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise NginxConfigurationError(
                f"nginx -t failed (exit={result.returncode}):\n{result.stdout}\n{result.stderr}"
            )

    def start(self, listen_port: int) -> None:
        cmd = ["nginx", "-c", str(self._config_path), "-p", str(self._prefix_dir)]  # noqa: S607
        self._process = subprocess.Popen(  # noqa: S603
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._wait_until_listening(listen_port)

    def _wait_until_listening(self, listen_port: int) -> None:
        deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            assert self._process is not None
            if self._process.poll() is not None:
                output = self._process.stdout.read().decode() if self._process.stdout else ""
                raise RuntimeError(
                    f"nginx exited early (code={self._process.returncode}): {output}"
                )
            try:
                with socket.create_connection(("127.0.0.1", listen_port), timeout=0.5):
                    return
            except OSError as exc:  # noqa: PERF203
                last_error = exc
                time.sleep(0.1)
        raise RuntimeError(f"nginx did not start listening in time: {last_error}")

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)
