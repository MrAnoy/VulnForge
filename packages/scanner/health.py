"""
VulnForge Scanner Health & Capability Detector
"""
import shutil
import subprocess
from typing import List
from packages.schemas.models import ScannerHealth
from packages.shared.config import settings


class ScannerHealthDetector:
    @staticmethod
    def check_nmap() -> ScannerHealth:
        path = shutil.which(settings.NMAP_PATH or "nmap")
        if not path:
            return ScannerHealth(
                name="Nmap Network Scanner",
                available=False,
                version=None,
                details="Binary 'nmap' not found in system PATH. Install nmap or run via Docker worker container to enable network port/service scanning."
            )
        try:
            res = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
            first_line = res.stdout.splitlines()[0] if res.stdout else "Nmap"
            return ScannerHealth(
                name="Nmap Network Scanner",
                available=True,
                version=first_line,
                details=f"Executable located at {path}"
            )
        except Exception as e:
            return ScannerHealth(
                name="Nmap Network Scanner",
                available=False,
                version=None,
                details=f"Error checking nmap: {str(e)}"
            )

    @staticmethod
    def check_nuclei() -> ScannerHealth:
        path = shutil.which(settings.NUCLEI_PATH or "nuclei")
        if not path:
            return ScannerHealth(
                name="Nuclei Template Scanner",
                available=False,
                version=None,
                details="Binary 'nuclei' not found in system PATH. Install nuclei or run via Docker worker container to enable automated vulnerability template checks."
            )
        try:
            res = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=5)
            first_line = res.stdout.splitlines()[0] if res.stdout else "Nuclei"
            return ScannerHealth(
                name="Nuclei Template Scanner",
                available=True,
                version=first_line,
                details=f"Executable located at {path}"
            )
        except Exception as e:
            return ScannerHealth(
                name="Nuclei Template Scanner",
                available=False,
                version=None,
                details=f"Error checking nuclei: {str(e)}"
            )

    @staticmethod
    def check_zap() -> ScannerHealth:
        # ZAP API is an external service/daemon
        return ScannerHealth(
            name="OWASP ZAP Scanner",
            available=False,
            version=None,
            details=f"ZAP API endpoint at {settings.ZAP_API_URL} (Daemon not currently connected)"
        )

    @staticmethod
    def check_custom_web() -> ScannerHealth:
        return ScannerHealth(
            name="Custom Web Security Engine",
            available=True,
            version="1.0.0 (Native Python Async)",
            details="Native Python async HTTP security checks active (Headers, Cookies, CORS, Methods, Exposures)"
        )

    @staticmethod
    def check_recon() -> ScannerHealth:
        return ScannerHealth(
            name="Reconnaissance & OSINT Engine",
            available=True,
            version="1.0.0 (Native DNS/TLS/HTTP)",
            details="Native DNS resolver, TLS certificate inspection, and endpoint discovery active"
        )

    @classmethod
    def get_all_health(cls) -> List[ScannerHealth]:
        return [
            cls.check_recon(),
            cls.check_custom_web(),
            cls.check_nmap(),
            cls.check_nuclei(),
            cls.check_zap(),
        ]
