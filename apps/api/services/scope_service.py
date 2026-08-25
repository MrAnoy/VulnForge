"""
VulnForge Scope & Target Authorization Engine
"""
from typing import List, Tuple
from packages.security.ssrf_guard import SSRFGuard, TargetValidationError
from packages.schemas.models import ScopeValidationResult
from packages.shared.logging import logger


class ScopeService:
    @staticmethod
    def validate_target_scope(
        target: str,
        allowed_targets: List[str],
        excluded_targets: List[str],
        allow_local_lab: bool = False
    ) -> ScopeValidationResult:
        """
        Perform strict target scope, SSRF, and authorization checks.
        """
        try:
            # 1. SSRF and Resolution check
            resolved_ips = SSRFGuard.resolve_and_validate(target, allow_local_lab=allow_local_lab)
            
            # 2. Scope allowlist/denylist match
            in_scope, message = SSRFGuard.is_target_in_scope(
                target=target,
                allowed_targets=allowed_targets,
                excluded_targets=excluded_targets
            )

            return ScopeValidationResult(
                target=target,
                in_scope=in_scope,
                resolved_ips=resolved_ips,
                message=message
            )

        except TargetValidationError as e:
            return ScopeValidationResult(
                target=target,
                in_scope=False,
                resolved_ips=[],
                message=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error during scope validation for {target}: {e}")
            return ScopeValidationResult(
                target=target,
                in_scope=False,
                resolved_ips=[],
                message=f"Scope validation failed: {str(e)}"
            )
