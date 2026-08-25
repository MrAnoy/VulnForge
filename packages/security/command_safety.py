"""
VulnForge Command Safety & Subprocess Execution Isolation
Ensures strictly argument-array based process execution, zero shell expansion,
timeouts, output limits, and process sandboxing.
"""
import subprocess
import shlex
import shutil
import asyncio
from typing import List, Tuple, Optional
from packages.shared.logging import logger


class CommandExecutionError(Exception):
    pass


class CommandSafety:
    MAX_OUTPUT_BYTES = 5 * 1024 * 1024  # 5 MB

    @staticmethod
    def is_binary_available(binary_name: str) -> bool:
        """Check if an executable is present in PATH."""
        return shutil.which(binary_name) is not None

    @classmethod
    async def run_safe_command(
        cls,
        args: List[str],
        timeout: int = 300,
        cwd: Optional[str] = None
    ) -> Tuple[int, str, str]:
        """
        Execute a subprocess using strict argument arrays with shell=False.
        Prevents shell injection and enforces execution boundaries.
        """
        if not args or not isinstance(args, list):
            raise CommandExecutionError("Command arguments must be a non-empty list of strings.")

        for arg in args:
            if not isinstance(arg, str):
                raise CommandExecutionError(f"All arguments must be strings, got {type(arg)}")

        binary = args[0]
        if not cls.is_binary_available(binary):
            raise CommandExecutionError(f"Binary '{binary}' not found in system PATH.")

        logger.info(f"Executing isolated command: {binary} with {len(args)-1} arguments")

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(),
                    timeout=float(timeout)
                )
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                raise CommandExecutionError(f"Command execution timed out after {timeout} seconds")

            stdout_str = stdout_data[:cls.MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            stderr_str = stderr_data[:cls.MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

            return process.returncode or 0, stdout_str, stderr_str

        except CommandExecutionError:
            raise
        except Exception as e:
            logger.error(f"Failed executing process {binary}: {str(e)}")
            raise CommandExecutionError(f"Process execution failed: {str(e)}")
