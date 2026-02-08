"""Public interface for oro-crypto.

Define the abstract base classes that form this brick's public contract.
Implementations live in their own modules.

Example:

    from abc import ABC, abstractmethod

    class Store(ABC):
        '''Data storage contract.'''

        @abstractmethod
        async def get(self, key: str) -> dict | None: ...

        @abstractmethod
        async def put(self, key: str, value: dict) -> None: ...
"""
