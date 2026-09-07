"""
Logging schema (matches build doc's Tier-1 requirement exactly):
  timestamp, session_id, decision (allow/block), detection_layer_used,
  latency_ms, matched_pattern_id (if blocked)

Plus a few fields beyond the minimum spec (request_id, phase, category) that
make the log actually useful for the attack-simulation report and for
distinguishing pre-flight blocks from post-flight blocks -- noted here since
it's an intentional addition, not scope creep on the logging schema itself.
"""
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parents[1] / "logs" / "gateway.jsonl"


@dataclass
class LogRecord:
    timestamp: float
    session_id: str
    request_id: str
    phase: str                      # "pre_flight" | "post_flight"
    decision: str                   # "allow" | "block"
    detection_layer_used: str | None
    latency_ms: float
    matched_pattern_id: str | None
    extra: dict = field(default_factory=dict)


class GatewayLogger:
    def __init__(self, path: Path = LOG_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, record: LogRecord):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(record)) + "\n")

    def new_request_id(self) -> str:
        return str(uuid.uuid4())[:8]

    def now(self) -> float:
        return time.time()
