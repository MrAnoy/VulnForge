"""
VulnForge Rate Limiter Middleware and Utility
"""
import time
from collections import defaultdict
from fastapi import HTTPException, Request, status


class InMemoryRateLimiter:
    def __init__(self, requests_limit: int = 100, window_seconds: int = 60):
        self.requests_limit = requests_limit
        self.window_seconds = window_seconds
        self.history = defaultdict(list)

    def is_rate_limited(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old timestamps
        self.history[key] = [t for t in self.history[key] if t > window_start]
        
        if len(self.history[key]) >= self.requests_limit:
            return True
            
        self.history[key].append(now)
        return False


global_limiter = InMemoryRateLimiter(requests_limit=120, window_seconds=60)
auth_limiter = InMemoryRateLimiter(requests_limit=15, window_seconds=60)


async def check_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path

    limiter = auth_limiter if "/auth/" in path else global_limiter
    key = f"{client_ip}:{path}"

    if limiter.is_rate_limited(key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait a moment before trying again."
        )
