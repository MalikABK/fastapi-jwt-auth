# app/core/rate_limiter.py
# Enhanced rate limiting with Redis backend

import time
import asyncio
from typing import Optional
from app.core.cache import cache_service


class RedisRateLimiter:
    def __init__(self):
        self.cache = cache_service

    async def is_rate_limited(
        self, 
        identifier: str, 
        limit: int, 
        window: int,
        increase: bool = True
    ) -> tuple[bool, int, int]:
        """
        Check if a request is rate limited.
        
        Args:
            identifier: Unique identifier for the rate limit (e.g., IP address, user ID)
            limit: Maximum number of requests allowed
            window: Time window in seconds
            increase: Whether to increase the counter (default: True)
            
        Returns:
            Tuple of (is_limited, current_count, reset_time)
        """
        if not self.cache._connected:
            # If Redis is not connected, skip rate limiting
            return False, 0, int(time.time()) + window
        
        key = f"rate_limit:{identifier}"
        current_time = int(time.time())
        reset_time = ((current_time // window) + 1) * window
        
        # Use Redis transactions to atomically check and update the counter
        pipe = self.cache.redis_client.pipeline()
        
        # Check current count
        current_count = await self.cache.get(key)
        
        if current_count is None:
            # First request in this window, set counter and expiration
            if increase:
                pipe.setex(key, window, 1)
                pipe.execute()
            return False, 1, reset_time
        else:
            current_count = int(current_count)
            
            if current_count >= limit:
                # Rate limit exceeded
                return True, current_count, reset_time
            else:
                # Increment counter if allowed
                if increase:
                    pipe.incr(key)
                    pipe.expire(key, window)
                    await pipe.execute()
                
                return False, current_count + 1, reset_time

    async def get_remaining_requests(
        self, 
        identifier: str, 
        limit: int, 
        window: int
    ) -> tuple[int, int]:
        """
        Get remaining requests and reset time for an identifier.
        
        Args:
            identifier: Unique identifier for the rate limit
            limit: Maximum number of requests allowed
            window: Time window in seconds
            
        Returns:
            Tuple of (remaining_requests, reset_time)
        """
        if not self.cache._connected:
            return limit, int(time.time()) + window
        
        key = f"rate_limit:{identifier}"
        current_count = await self.cache.get(key)
        
        if current_count is None:
            current_count = 0
        else:
            current_count = int(current_count)
        
        remaining = max(0, limit - current_count)
        current_time = int(time.time())
        reset_time = ((current_time // window) + 1) * window
        
        return remaining, reset_time


# Global rate limiter instance
rate_limiter = RedisRateLimiter()


def get_rate_limit_headers(identifier: str, limit: int, window: int):
    """
    Helper function to get rate limit headers for HTTP responses
    """
    async def _get_headers():
        remaining, reset_time = await rate_limiter.get_remaining_requests(
            identifier, limit, window
        )
        return {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_time),
        }
    
    # This would normally be called within an async context
    # For now, returning a function that can be awaited
    return _get_headers


# Rate limiting middleware
async def rate_limit_middleware(request, call_next, limit: int, window: int):
    """
    Middleware function for rate limiting
    """
    # Use IP address as identifier (could be extended to use user ID for authenticated requests)
    identifier = request.client.host
    
    is_limited, current_count, reset_time = await rate_limiter.is_rate_limited(
        identifier, limit, window
    )
    
    if is_limited:
        from fastapi.responses import JSONResponse
        from fastapi import status
        
        response = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded"}
        )
        response.headers.update({
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(reset_time),
        })
        return response
    
    # Add rate limit headers to response
    remaining, _ = await rate_limiter.get_remaining_requests(identifier, limit, window)
    response = await call_next(request)
    response.headers.update({
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset_time),
    })
    
    return response