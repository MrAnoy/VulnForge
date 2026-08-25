# Troubleshooting Guide

## 1. Scanner Availability Standby
- **Issue**: Scanner Health diagnostics show Nmap or Nuclei on Standby.
- **Solution**: Native Custom Web and Recon checks run without any external binaries. To enable Nmap and Nuclei, install them on the host system or run VulnForge using the Docker worker containers where scanners are pre-installed.

## 2. SSRF Protection Block on Local Targets
- **Issue**: `SSRF Protection: Target resolves to restricted/private IP`.
- **Solution**: Enable `allow_local_lab: true` under your project scope settings when assessing authorized local docker/lab targets (e.g. `http://localhost:3001` or `127.0.0.1`).

## 3. Database Initialization
- **Issue**: Database schema tables missing on fresh install.
- **Solution**: Run `python scripts/seed_demo.py` or launch the FastAPI app, which automatically creates all tables during lifespan initialization.
