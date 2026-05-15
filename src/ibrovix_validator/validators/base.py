"""Base validator interface."""

from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseValidator(ABC):
    """Abstract validator for proxy config fields and connectivity."""

    @abstractmethod
    async def validate(self, config: dict) -> dict:
        """Validate a single config dict. Returns config with added validation fields.
        
        Added fields:
            valid: bool
            error: str | None
            latency_ms: float | None (for connectivity checks)
        """
        ...

    def name(self) -> str:
        return self.__class__.__name__
