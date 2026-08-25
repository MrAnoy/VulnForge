# Production Deployment Guide

## 1. Production Architecture with Docker Compose

In production, VulnForge runs across isolated containers behind an Nginx reverse proxy:

```
Internet (Port 443 / 80)
         │
         ▼
     Nginx Proxy
     ├── /api/  ───────► FastAPI Backend (Port 8000)
     └── /      ───────► Next.js Web Frontend (Port 3000)
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
              PostgreSQL 16         Redis 7
```

### Steps:
1. Copy `.env.example` to `.env` and set a secure `SECRET_KEY`.
2. Configure PostgreSQL credentials in `.env`.
3. Run `docker-compose up -d --build`.
4. Run migrations/seed: `docker-compose exec api python scripts/seed_demo.py`.
