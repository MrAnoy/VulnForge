# Scanner Adapter Architecture

VulnForge implements a modular adapter pattern enabling pluggable security scanning tools.

## 1. Base Scanner Interface

Every scanner implements `packages/scanner/base.py`:

```python
class BaseScannerAdapter(ABC):
    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def get_version(self) -> Optional[str]: ...

    @abstractmethod
    async def validate(self, target: str, options: Dict[str, Any]) -> bool: ...

    @abstractmethod
    async def prepare(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]: ...

    @abstractmethod
    async def execute(self, target: str, options: Dict[str, Any]) -> Any: ...

    @abstractmethod
    async def parse(self, raw_results: Any) -> List[Dict[str, Any]]: ...

    @abstractmethod
    async def normalize(self, parsed_items: List[Dict[str, Any]], target: str) -> List[FindingBase]: ...
```

## 2. Integrated Scanners

### A. Reconnaissance Engine (`ReconAdapter`)
- **DNS Records**: A, AAAA, MX, TXT (SPF/DMARC), NS, CNAME.
- **TLS/SSL Certificates**: Issuer, Subject, Expiration date, Days left, SANs.
- **HTTP Availability & Headers**: Status code, Server banner, X-Powered-By.
- **Security Policy Files**: `/.well-known/security.txt`, `/robots.txt`.

### B. Custom Web Security Engine (`CustomWebAdapter`)
- **Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
- **Insecure Cookies**: Missing Secure flag, Missing HttpOnly flag.
- **CORS Policies**: Arbitrary Origin reflection, Wildcard with credentials.
- **Sensitive Endpoints**: `/.git/HEAD`, `/.env`, `/web.config`, `/.DS_Store`, `/actuator/env`, `/phpinfo.php`.
- **Risky HTTP Methods**: TRACE (XST), PUT, DELETE.

### C. Nmap Network Scanner (`NmapAdapter`)
- **Host Discovery & Port Scanning**: Pre-defined safe TCP Connect (`-sT`) scans.
- **Service Version Detection**: Banner identification (`-sV`).
- **Risky Port Warnings**: Telnet (23), FTP (21), RDP (3389), Redis (6379), MongoDB (27017).

### D. Nuclei Template Scanner (`NucleiAdapter`)
- **Vulnerability Checks**: Approved tags (`cve`, `misconfiguration`, `exposure`, `tech`).
- **Rate-limited**: Safe concurrency with JSONL streaming parser.

### E. OWASP ZAP Scanner (`ZapAdapter`)
- **Spider & Passive Scan**: Interfaces with OWASP ZAP API daemon.
- **Controlled Active Scan**: Disabled by default.
