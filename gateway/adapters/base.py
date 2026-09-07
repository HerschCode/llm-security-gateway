"""
Pluggability interface (confirmed architecture: thin Python adapter class,
not a config/YAML mapping layer -- see docs/decisions.md).

Any backend the gateway sits in front of implements this one method. "Dropping
the gateway in front of a different LLM app" means writing one small subclass,
not reconfiguring the gateway itself.
"""
from abc import ABC, abstractmethod
from typing import Iterator


class BackendAdapter(ABC):
    name: str = "unnamed_backend"

    @abstractmethod
    def send(self, prompt: str, session_id: str, role: str = "employee", user_id: str = "unknown") -> str:
        """Sends prompt to the backend, returns the backend's raw response text."""
        raise NotImplementedError

    def stream(self, prompt: str, session_id: str, role: str = "employee", user_id: str = "unknown") -> Iterator[str]:
        """Optional: streaming variant, yields response chunks as they'd arrive
        from a real streaming LLM API. Default implementation just chunks the
        non-streaming send() result -- a real streaming backend would override
        this with its actual token-by-token/SSE stream. Adapters that don't
        override this still work with the gateway's streaming endpoint, just
        without genuine incremental generation."""
        full_response = self.send(prompt, session_id, role, user_id)
        chunk_size = 20
        for i in range(0, len(full_response), chunk_size):
            yield full_response[i:i + chunk_size]
