# Scope & Target Authorization Engine

## 1. Scope Validation Pipeline

```
Input Target URL / IP
         ↓
Normalization (Host, Port, Protocol)
         ↓
DNS Resolution & SSRF Validation (Private IP Check)
         ↓
Denylist / Exclusion Evaluation
         ↓
Allowlist & Subnet/Wildcard Evaluation
         ↓
Mandatory Authorization Confirmation Gate
         ↓
Execution Authorization Issued
```

## 2. Supported Target Formats

- **Full URL**: `https://api.example.com/v1/`
- **Hostname / Domain**: `example.com`
- **Wildcard Subdomains**: `*.example.com` (covers `api.example.com`, `auth.example.com`)
- **Single IP Address**: `198.51.100.25`
- **CIDR Subnets**: `198.51.100.0/24` (requires explicit admin authorization)
