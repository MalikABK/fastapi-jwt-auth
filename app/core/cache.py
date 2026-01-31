# app/core/cache.py
# Redis cache integration for performance and scalability

import redis.asyncio as redis
from typing import Optional, Union
from app.core.config import settings
import json
import asyncio


class CacheService:
    def __init__(self):
        self.redis_client = None
        self._connected = False

    async def connect(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=settings.redis_host if hasattr(settings, 'redis_host') else 'localhost',
                port=settings.redis_port if hasattr(settings, 'redis_port') else 6379,
                db=0,
                password=settings.redis_password if hasattr(settings, 'redis_password') else None,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Test connection
            await self.redis_client.ping()
            self._connected = True
            print("Connected to Redis successfully")
        except Exception as e:
            print(f"Failed to connect to Redis: {e}")
            self._connected = False

    async def disconnect(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
            self._connected = False

    async def get(self, key: str) -> Optional[str]:
        """Get value from cache"""
        if not self._connected:
            return None
        
        try:
            value = await self.redis_client.get(key)
            return value
        except Exception:
            return None

    async def set(self, key: str, value: str, expire: int = 3600) -> bool:
        """Set value in cache with expiration"""
        if not self._connected:
            return False
        
        try:
            await self.redis_client.setex(key, expire, value)
            return True
        except Exception:
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if not self._connected:
            return False
        
        try:
            await self.redis_client.delete(key)
            return True
        except Exception:
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if not self._connected:
            return False
        
        try:
            result = await self.redis_client.exists(key)
            return result == 1
        except Exception:
            return False

    async def get_json(self, key: str) -> Optional[dict]:
        """Get JSON value from cache"""
        value = await self.get(key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None
        return None

    async def set_json(self, key: str, value: dict, expire: int = 3600) -> bool:
        """Set JSON value in cache"""
        try:
            json_value = json.dumps(value)
            return await self.set(key, json_value, expire)
        except Exception:
            return False


# Global cache instance
cache_service = CacheService()


# Initialize cache on startup
async def init_cache():
    await cache_service.connect()


# Close cache on shutdown
async def close_cache():
    await cache_service.disconnect()