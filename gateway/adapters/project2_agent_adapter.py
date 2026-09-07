"""
Adapter wrapping project2_agent (a best-effort reconstruction -- see
project2_agent/documents.py's module docstring). Unlike stub_ops_agent, this
backend has its own internal tool-authorization, so it's a more realistic
test of "does the gateway add value on top of a backend that already does
some defense," not just "does the gateway protect a completely undefended
backend."
"""
from gateway.adapters.base import BackendAdapter
from project2_agent.agent import handle, FAKE_SYSTEM_PROMPT


class Project2AgentAdapter(BackendAdapter):
    name = "project2_agent (best-effort reconstruction -- see project2_agent/ module docstrings)"

    def send(self, prompt: str, session_id: str, role: str = "employee", user_id: str = "unknown") -> str:
        return handle(prompt, role=role, session_id=session_id, user_id=user_id)

    def stream(self, prompt: str, session_id: str, role: str = "employee", user_id: str = "unknown"):
        full_response = self.send(prompt, session_id, role, user_id)
        words = full_response.split(" ")
        for i, word in enumerate(words):
            yield word + (" " if i < len(words) - 1 else "")
