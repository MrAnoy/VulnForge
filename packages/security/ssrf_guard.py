"""
VulnForge SSRF & Target Scope Guard
Validates target IP ranges, domains, and CIDRs to prevent SSRF and unauthorized scanning.
"""
import ipaddress
import socket
import urllib.parse
from typing import Tuple, List, Optional
from packages.shared.config import settings
from packages.shared.logging import logger


BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata & Link-local
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),    # Multicast
    ipaddress.ip_network("240.0.0.0/4"),    # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 blocked ranges
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),       # IPv6 Multicast
]


class TargetValidationError(Exception):
    pass


class SSRFGuard:
    @staticmethod
    def normalize_target(target: str) -> Tuple[str, Optional[int], str]:
        """
        Normalize target string into (host, port, protocol).
        Accepts: example.com, https://example.com:8443, 192.0.2.1, 192.0.2.1:8080
        """
        target = target.strip()
        if not target:
            raise TargetValidationError("Target cannot be empty")

        if not target.startswith(("http://", "https://")):
            # Check if it looks like host:port or just host
            if "://" not in target:
                parsed = urllib.parse.urlsplit(f"tcp://{target}")
            else:
                parsed = urllib.parse.urlsplit(target)
        else:
            parsed = urllib.parse.urlsplit(target)

        host = parsed.hostname or parsed.netloc.split(":")[0]
        port = parsed.port
        protocol = parsed.scheme if parsed.scheme in ["http", "https"] else "http"

        if not host:
            raise TargetValidationError(f"Could not parse valid hostname or IP from: {target}")

        return host.lower().strip("."), port, protocol

    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        """Check if an IP address belongs to private or reserved ranges, including IPv6 and mapped addresses."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            
            # If IPv6, check if it maps to an IPv4 address
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                mapped_v4 = ip_obj.ipv4_mapped
                return cls.is_private_ip(str(mapped_v4))

            for network in BLOCKED_IP_NETWORKS:
                if ip_obj in network:
                    return True

            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            )
        except ValueError:
            return False

    @classmethod
    def resolve_and_validate(cls, target: str, allow_local_lab: Optional[bool] = None) -> List[str]:
        """
        Resolve domain or IP and enforce SSRF validation rules.
        Returns list of resolved validated IP strings.
        """
        host, _, _ = cls.normalize_target(target)

        # If allow_local_lab is None, fallback to settings.ALLOW_LOCAL_TARGETS.
        # If allow_local_lab is explicitly False, strict blocking is enforced.
        is_lab_allowed = settings.ALLOW_LOCAL_TARGETS if allow_local_lab is None else allow_local_lab

        resolved_ips = []
        # Check if direct IP
        try:
            ipaddress.ip_address(host)
            resolved_ips.append(host)
        except ValueError:
            # It is a domain/hostname
            try:
                addr_info = socket.getaddrinfo(host, None)
                for res in addr_info:
                    ip_str = res[4][0]
                    if ip_str not in resolved_ips:
                        resolved_ips.append(ip_str)
            except socket.gaierror as e:
                raise TargetValidationError(f"DNS resolution failed for {host}: {str(e)}")

        if not resolved_ips:
            raise TargetValidationError(f"No IP addresses resolved for target: {host}")

        # Check each resolved IP
        for ip_str in resolved_ips:
            if cls.is_private_ip(ip_str):
                if not is_lab_allowed:
                    raise TargetValidationError(
                        f"SSRF Protection: Target '{host}' resolves to restricted/private IP '{ip_str}'. "
                        "Scanning private/internal networks is restricted. Enable authorized Local Lab Mode if this is an intentional local assessment."
                    )
                else:
                    logger.warning(f"Target '{host}' ({ip_str}) is in local/private network. Allowed under authorized local lab mode.")

        return resolved_ips

    @classmethod
    def is_target_in_scope(
        cls,
        target: str,
        allowed_targets: List[str],
        excluded_targets: List[str]
    ) -> Tuple[bool, str]:
        """
        Check if target is authorized in scope allowlist and not in denylist.
        """
        host, _, _ = cls.normalize_target(target)

        # Check explicit exclusions first
        for excluded in excluded_targets:
            ex_host, _, _ = cls.normalize_target(excluded)
            if ex_host == host or (ex_host.startswith("*.") and host.endswith(ex_host[1:])):
                return False, f"Target '{host}' matches excluded scope rule '{excluded}'"

        # Check allowlist
        if not allowed_targets:
            return False, "Scope allowlist is empty. No targets authorized."

        in_scope = False
        matching_rule = ""
        for allowed in allowed_targets:
            allowed = allowed.strip()
            # CIDR check
            if "/" in allowed:
                try:
                    net = ipaddress.ip_network(allowed, strict=False)
                    # Resolve target and check
                    try:
                        target_ip = ipaddress.ip_address(host)
                        if target_ip in net:
                            in_scope = True
                            matching_rule = allowed
                            break
                    except ValueError:
                        pass
                except ValueError:
                    pass
            elif allowed.startswith("*."):
                suffix = allowed[1:].lower().strip(".")
                if host.endswith("." + suffix) or host == suffix:
                    in_scope = True
                    matching_rule = allowed
                    break
            else:
                al_host, _, _ = cls.normalize_target(allowed)
                if al_host == host:
                    in_scope = True
                    matching_rule = allowed
                    break

        if not in_scope:
            return False, f"Target '{host}' is outside the authorized allowed scope list."

        return True, f"Target '{host}' is in scope (matched '{matching_rule}')"
