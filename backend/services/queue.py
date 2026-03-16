from __future__ import annotations

from typing import Optional

import redis

from backend import config


class RedisQueue:
    def __init__(self, url: str, key: str) -> None:
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._key = key

    def enqueue(self, job_id: int) -> None:
        self._client.lpush(self._key, str(job_id))

    def dequeue(self, timeout: int = 5) -> Optional[int]:
        item = self._client.brpop(self._key, timeout=timeout)
        if not item:
            return None
        _, value = item
        try:
            return int(value)
        except ValueError:
            return None


def get_queue() -> RedisQueue:
    return RedisQueue(config.get_redis_url(), config.get_queue_key())
