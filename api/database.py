"""PostgreSQL (asyncpg) ve Redis bağlantı yönetimi."""

import os
import asyncpg
import redis.asyncio as aioredis

_pg_pool: asyncpg.Pool | None = None
_redis_client: aioredis.Redis | None = None


async def get_pg_pool() -> asyncpg.Pool:
    global _pg_pool
    if _pg_pool is None:
        _pg_pool = await asyncpg.create_pool(
            host=os.getenv("POSTGRES_HOST", "postgres"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            database=os.getenv("POSTGRES_DB", "nac_db"),
            user=os.getenv("POSTGRES_USER", "nac_admin"),
            password=os.getenv("POSTGRES_PASSWORD", ""),
            min_size=2,
            max_size=10,
        )
    return _pg_pool


async def close_pg_pool():
    global _pg_pool
    if _pg_pool:
        await _pg_pool.close()
        _pg_pool = None


def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.Redis(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            decode_responses=True,
        )
    return _redis_client


async def close_redis():
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None
