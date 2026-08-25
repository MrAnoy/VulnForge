"""
Security Tests: Command Injection Prevention & Process Isolation
"""
import pytest
import asyncio
from packages.security.command_safety import CommandSafety, CommandExecutionError


@pytest.mark.asyncio
async def test_command_safety_rejects_string_commands():
    # Attempting to pass raw string instead of argument vector must fail
    with pytest.raises(CommandExecutionError):
        await CommandSafety.run_safe_command("nmap -sT 127.0.0.1; calc.exe")  # type: ignore


@pytest.mark.asyncio
async def test_command_safety_non_executable_binary():
    # Requesting non-existent binary fails safely
    with pytest.raises(CommandExecutionError) as exc_info:
        await CommandSafety.run_safe_command(["non_existent_binary_xyz_123", "arg1"])
    assert "not found in system PATH" in str(exc_info.value)


@pytest.mark.asyncio
async def test_malicious_shell_characters_are_not_evaluated():
    # Python executable is in PATH
    import sys
    # Passing malicious shell metacharacters as an argument string should NOT trigger shell execution
    # because shell=False is enforced
    code, stdout, stderr = await CommandSafety.run_safe_command(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "; echo INJECTED & echo OWNED"],
        timeout=5
    )
    assert code == 0
    # The output should literally echo the argument string, not execute the injected commands
    assert "; echo INJECTED & echo OWNED" in stdout
