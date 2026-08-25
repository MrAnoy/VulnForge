"""
VulnForge Main FastAPI Application Entrypoint
"""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from apps.api.core.database import init_db
from packages.shared.config import settings
from packages.shared.logging import logger

# Routers
from apps.api.routers import (
    auth,
    organizations,
    projects,
    assets,
    scope,
    assessments,
    findings,
    remediation,
    reports,
    copilot,
    system,
    api_keys,
    audit_logs,
    webhooks,
    schedules,
    prioritization,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables
    logger.info(f"Initializing {settings.APP_NAME} v{settings.APP_VERSION}...")
    await init_db()
    logger.info("Database schemas initialized.")
    yield
    # Shutdown
    logger.info(f"Shutting down {settings.APP_NAME}...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows Next.js frontend dev server and direct calls
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An internal server error occurred. Please consult system logs."
            }
        }
    )


# Include all routers
app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(projects.router)
app.include_router(assets.router)
app.include_router(scope.router)
app.include_router(assessments.router)
app.include_router(findings.router)
app.include_router(remediation.router)
app.include_router(reports.router)
app.include_router(copilot.router)
app.include_router(system.router)
app.include_router(api_keys.router)
app.include_router(audit_logs.router)
app.include_router(webhooks.router)
app.include_router(schedules.router)
app.include_router(prioritization.router)


@app.get("/")
async def root():
    return {
        "platform": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/docs",
        "health": "/api/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("apps.api.main:app", host="0.0.0.0", port=8000, reload=True)
