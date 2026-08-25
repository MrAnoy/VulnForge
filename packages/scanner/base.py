"""
VulnForge Abstract Base Scanner Adapter
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from packages.schemas.models import FindingBase, EvidenceItem
from packages.shared.constants import ScannerType


class BaseScannerAdapter(ABC):
    scanner_type: ScannerType
    name: str

    def __init__(self):
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if scanner dependencies/binaries/APIs are available."""
        pass

    @abstractmethod
    def get_version(self) -> Optional[str]:
        """Return scanner version string if available."""
        pass

    @abstractmethod
    async def validate(self, target: str, options: Dict[str, Any]) -> bool:
        """Validate target format and options before execution."""
        pass

    @abstractmethod
    async def prepare(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare scan context, config, or arguments."""
        pass

    @abstractmethod
    async def execute(self, target: str, options: Dict[str, Any]) -> Any:
        """Execute scan and return raw results."""
        pass

    @abstractmethod
    async def parse(self, raw_results: Any) -> List[Dict[str, Any]]:
        """Parse raw output into structured intermediate finding dicts."""
        pass

    @abstractmethod
    async def normalize(self, parsed_items: List[Dict[str, Any]], target: str) -> List[FindingBase]:
        """Convert parsed items into standardized FindingBase instances."""
        pass

    async def cleanup(self) -> None:
        """Perform any post-scan resource cleanup."""
        pass
