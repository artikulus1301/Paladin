"""
SIFT Sandbox Manager — Security boundary #3 and #4.

Manages Docker containers for isolated forensic analysis.
Each investigation gets its own ephemeral container with:
  /evidence  → read-only bind mount (kernel-level protection)
  /cases     → tmpfs (RAM-only, destroyed with container)
  /output    → write-only bind mount for results
  network    → none (no exfiltration possible)

Lifecycle: create_sandbox → exec_in_sandbox (N times) → destroy_sandbox
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Optional

import structlog

from paladin.config.settings import settings

log = structlog.get_logger(__name__)


class SandboxManager:
    """
    Manages ephemeral Docker containers for SIFT forensic analysis.
    Each container is isolated: read-only evidence, no network, tmpfs scratch.
    """

    def __init__(self) -> None:
        self._active_containers: dict[str, str] = {}  # incident_id → container_id

    async def create_sandbox(
        self,
        incident_id: str,
        evidence_path: str,
        output_path: str | None = None,
    ) -> str:
        """
        Create an isolated SIFT sandbox container for a forensic investigation.

        Args:
            incident_id: Unique incident identifier
            evidence_path: Host path to evidence directory (mounted read-only)
            output_path: Host path for output (mounted read-write)

        Returns:
            container_id: Docker container ID
        """
        container_name = f"sift-sandbox-{incident_id}"
        if output_path is None:
            output_path = f"{settings.forensic_output_base}/{incident_id}"

        cmd = [
            "docker", "create",
            "--name", container_name,
            # ── Network isolation (Boundary #4) ─────────────────────────
            "--network", "none",
            # ── Security hardening ──────────────────────────────────────
            "--security-opt", "no-new-privileges:true",
            "--read-only",
            # ── CPU/Memory limits ───────────────────────────────────────
            "--cpus", str(settings.sandbox_cpu_limit),
            "--memory", settings.sandbox_memory_limit,
            "--pids-limit", "256",
            # ── Capability restrictions ─────────────────────────────────
            "--cap-drop", "ALL",
            "--cap-add", "DAC_READ_SEARCH",   # needed for forensic tools to read files
            # ── Volume mounts ───────────────────────────────────────────
            # Boundary #3: /evidence is read-only at kernel level
            "-v", f"{evidence_path}:/evidence:ro",
            # tmpfs for scratch work — lives only in RAM
            "--tmpfs", f"/cases:rw,noexec,nosuid,size={settings.sandbox_tmpfs_size}",
            # /tmp also needs to be writable for some tools
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
            # Output directory
            "-v", f"{output_path}:/output:rw",
            # ── Environment ─────────────────────────────────────────────
            "-e", f"INCIDENT_ID={incident_id}",
            "-e", "LANG=C.UTF-8",
            # ── Image ──────────────────────────────────────────────────
            settings.sift_sandbox_image,
            # Keep container alive (we use docker exec)
            "sleep", "infinity",
        ]

        try:
            # Ensure output directory exists
            await self._run_cmd(["docker", "run", "--rm", "-v",
                                 f"{output_path}:/out", "alpine",
                                 "sh", "-c", "mkdir -p /out"])
        except Exception:
            pass  # May already exist or docker may handle it

        # Create container
        result = await self._run_cmd(cmd)
        container_id = result.strip()

        # Start container
        await self._run_cmd(["docker", "start", container_name])

        self._active_containers[incident_id] = container_name
        log.info("sandbox_created",
                 incident_id=incident_id,
                 container=container_name,
                 evidence_path=evidence_path,
                 network="none",
                 evidence_mount="read-only")

        return container_name

    async def exec_in_sandbox(
        self,
        container_id: str,
        command: list[str],
        timeout: int | None = None,
    ) -> tuple[str, int]:
        """
        Execute a command inside the sandbox container.

        Args:
            container_id: Container name or ID
            command: Command and arguments as list (no shell!)
            timeout: Execution timeout in seconds

        Returns:
            (stdout_output, return_code)
        """
        if timeout is None:
            timeout = settings.sandbox_exec_timeout

        exec_cmd = [
            "docker", "exec",
            "--user", "siftuser",   # non-root user inside container
            container_id,
        ] + command

        start_time = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *exec_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            duration_ms = int((time.monotonic() - start_time) * 1000)

            output = stdout.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")
                log.warning("sandbox_exec_nonzero",
                            container=container_id,
                            command=command[0] if command else "?",
                            returncode=proc.returncode,
                            stderr=err[:500],
                            duration_ms=duration_ms)

            log.debug("sandbox_exec",
                      container=container_id,
                      command=command[0] if command else "?",
                      returncode=proc.returncode,
                      output_bytes=len(output),
                      duration_ms=duration_ms)

            return output, proc.returncode

        except asyncio.TimeoutError:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            log.error("sandbox_exec_timeout",
                      container=container_id,
                      command=command,
                      timeout=timeout,
                      duration_ms=duration_ms)
            # Kill the timed-out process
            try:
                await self._run_cmd(["docker", "exec", container_id, "kill", "-9", "-1"])
            except Exception:
                pass
            return f"ERROR: Command timed out after {timeout}s", -1

    async def destroy_sandbox(self, incident_id: str) -> None:
        """
        Stop and remove the sandbox container.
        /cases (tmpfs) is destroyed automatically.
        /output is preserved on the host for the investigation archive.
        """
        container_name = self._active_containers.pop(incident_id, None)
        if not container_name:
            container_name = f"sift-sandbox-{incident_id}"

        try:
            await self._run_cmd(["docker", "stop", "-t", "5", container_name])
        except Exception as e:
            log.warning("sandbox_stop_failed", container=container_name, error=str(e))

        try:
            await self._run_cmd(["docker", "rm", "-f", container_name])
        except Exception as e:
            log.warning("sandbox_rm_failed", container=container_name, error=str(e))

        log.info("sandbox_destroyed",
                 incident_id=incident_id,
                 container=container_name)

    async def is_sandbox_alive(self, incident_id: str) -> bool:
        """Check if a sandbox container is still running."""
        container_name = self._active_containers.get(
            incident_id, f"sift-sandbox-{incident_id}"
        )
        try:
            result = await self._run_cmd([
                "docker", "inspect", "-f", "{{.State.Running}}", container_name
            ])
            return result.strip().lower() == "true"
        except Exception:
            return False

    def get_container_name(self, incident_id: str) -> str | None:
        """Get the container name for an incident."""
        return self._active_containers.get(incident_id)

    @staticmethod
    def hash_output(output: str) -> str:
        """Create SHA256 hash of command output for verification."""
        return hashlib.sha256(output.encode("utf-8")).hexdigest()

    @staticmethod
    async def _run_cmd(cmd: list[str]) -> str:
        """Run a host command and return stdout."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Command failed (rc={proc.returncode}): {' '.join(cmd[:4])}... — {err[:300]}"
            )
        return stdout.decode("utf-8", errors="replace")
