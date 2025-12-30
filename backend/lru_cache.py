"""
Simple LRU (Least Recently Used) cache implementation

Provides a bounded cache with automatic eviction of least recently used items.
"""

from collections import OrderedDict
from typing import Any, Optional


class LRUCache:
    """
    Thread-safe LRU cache with a maximum size.

    When the cache reaches max_size, the least recently used item is evicted.
    Uses OrderedDict to maintain insertion/access order.
    """

    def __init__(self, max_size: int = 1000):
        """
        Initialize LRU cache.

        Args:
            max_size: Maximum number of items to store (default: 1000)
        """
        if max_size <= 0:
            raise ValueError("max_size must be positive")

        self.max_size = max_size
        self._cache: OrderedDict[str, Any] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache, marking it as recently used.

        Args:
            key: Cache key

        Returns:
            Cached value if present, None otherwise
        """
        if key not in self._cache:
            return None

        # Move to end (mark as recently used)
        self._cache.move_to_end(key)
        return self._cache[key]

    def set(self, key: str, value: Any) -> None:
        """
        Set value in cache, evicting LRU item if at capacity.

        Args:
            key: Cache key
            value: Value to cache
        """
        if key in self._cache:
            # Update existing key and move to end
            self._cache.move_to_end(key)
        elif len(self._cache) >= self.max_size:
            # Evict least recently used (first item)
            self._cache.popitem(last=False)

        self._cache[key] = value

    def delete(self, key: str) -> bool:
        """
        Delete a key from the cache.

        Args:
            key: Cache key to delete

        Returns:
            True if key was present and deleted, False otherwise
        """
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def pop(self, key: str, default: Any = None) -> Any:
        """
        Remove and return value for key, or default if not present.

        Args:
            key: Cache key
            default: Default value if key not found

        Returns:
            Cached value or default
        """
        return self._cache.pop(key, default)

    def clear(self) -> None:
        """Clear all items from the cache."""
        self._cache.clear()

    def __len__(self) -> int:
        """Return number of items in cache."""
        return len(self._cache)

    def __contains__(self, key: str) -> bool:
        """Check if key is in cache."""
        return key in self._cache
