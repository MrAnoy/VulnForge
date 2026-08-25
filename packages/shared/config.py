"""
VulnForge Configuration Module
"""
import os
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Branding
    APP_NAME: str = "VulnForge"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Enterprise Automated VAPT & Security Assessment Platform"
    
    # Environment
    ENVIRONMENT: str = Field(default="development", description="development | staging | production")
    DEBUG: bool = True
    DEMO_MODE: bool = False
    
    # Security & Auth
    SECRET_KEY: str = "vulnforge-super-secret-production-change-me-32-chars-min"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./vulnforge.db"
    SYNC_DATABASE_URL: str = "sqlite:///./vulnforge.db"
    
    # Redis & Worker
    REDIS_URL: str = "redis://localhost:6379/0"
    USE_IN_PROCESS_WORKER: bool = True  # Fallback to AsyncIO background workers if Redis/Celery is down
    
    # Scanner Limits & Safety
    SCAN_TIMEOUT_SECONDS: int = 1800  # 30 mins
    MAX_CONCURRENT_SCANS: int = 5
    DEFAULT_RATE_LIMIT_RPS: int = 20
    ALLOW_LOCAL_TARGETS: bool = True  # Only allowed when explicit authorized local lab mode is active
    
    # AI Security Copilot
    AI_PROVIDER: str = "mock"  # "mock" | "openai" | "gemini" | "local"
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    AI_MODEL: str = "gpt-4o-mini"
    
    # Scanner binary paths (auto-detected if in PATH)
    NMAP_PATH: Optional[str] = "nmap"
    NUCLEI_PATH: Optional[str] = "nuclei"
    ZAP_API_URL: Optional[str] = "http://localhost:8080"
    ZAP_API_KEY: Optional[str] = None
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]


settings = Settings()
