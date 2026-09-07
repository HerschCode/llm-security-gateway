"""
Deliberately trivial second backend -- exists to prove the gateway is
actually pluggable, not just built around one hardcoded target. Structurally
nothing like stub_ops_agent.py (no roles, no tools, no domain data) on
purpose: if the gateway's pre-flight checks work identically in front of
both, that's the portability claim actually demonstrated rather than asserted.
"""
from gateway.adapters.base import BackendAdapter


class TrivialEchoAdapter(BackendAdapter):
    name = "trivial_echo_backend"

    def send(self, prompt: str, session_id: str, role: str = "employee", user_id: str = "unknown") -> str:
        return f"[echo] You said: {prompt[:200]}"
