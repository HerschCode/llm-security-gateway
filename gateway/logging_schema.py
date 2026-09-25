"""
Logging schema (matches build doc's Tier-1 requirement exactly):
  timestamp, session_id, decision (allow/block), detection_layer_used,
  latency_ms, matched_pattern_id (if blocked)

Plus a few fields beyond the minimum spec (request_id, phase, category, user_id)
that make the log actually useful for the attack-simulation report and for
distinguishing pre-flight blocks from post-flight blocks -- noted here since
it's an intentional addition, not scope creep on the logging schema itself.

This JSONL file is this project's audit trail: every request gets an
append-only, per-phase record of who (user_id/session_id), what (decision,
matched_pattern_id), and when (timestamp) -- see the "Audit logging" section
in README.md for how it's used (compliance framing, dashboard queries).
"""
import json
import queue
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parents[1] / "logs" / "gateway.jsonl"

_SENTINEL = object()  # signals writer thread to drain and exit


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
    user_id: str = "unknown"        # caller identity, for audit attribution -- see module docstring


class GatewayLogger:
    """
    Thread-safe append logger backed by a queue + single writer thread.
    Hot path: queue.put() -- no file I/O, no lock contention under concurrency.

    The writer opens the file, appends one coalesced batch and closes it again; it never keeps a handle between batches. A long-lived
    handle made the log impossible to rotate or delete while the gateway ran on Windows (a file opened by Python cannot be renamed or
    removed by anyone else: WinError 32) and, on any platform, left the logger writing to a rotated-away file. With per-batch opens,
    an external rotator (or the dashboard's rotation handling) can rename the file between batches and the next batch starts a new one.
    A rotator that holds the file for an instant is retried; if the file stays locked the batch is dropped and counted in `dropped`
    rather than killing the writer thread.
    """

    WRITE_RETRIES = 4

    def __init__(self, path: Path = LOG_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._queue: queue.Queue = queue.Queue()
        self.dropped = 0
        self._thread = threading.Thread(
            target=self._writer, daemon=True, name="gateway-log-writer"
        )
        self._thread.start()

    def _write_batch(self, lines: list[str]):
        for attempt in range(self.WRITE_RETRIES):
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.writelines(lines)
                return
            except PermissionError:                 # another process holds the file for an instant (Windows)
                time.sleep(0.05 * (attempt + 1))
        self.dropped += len(lines)

    def _writer(self):
        """Drain the queue in batches; one open/write/close per batch keeps disk I/O low."""
        while True:
            item = self._queue.get()
            if item is _SENTINEL:
                break
            batch, stop = [item], False
            while True:                             # coalesce anything that arrived while we were writing
                try:
                    extra = self._queue.get_nowait()
                except queue.Empty:
                    break
                if extra is _SENTINEL:
                    stop = True
                    break
                batch.append(extra)
            self._write_batch(batch)
            if stop:
                return

    def log(self, record: LogRecord):
        line = json.dumps(asdict(record)) + "\n"
        self._queue.put(line)

    def close(self):
        """Write everything still queued and stop the writer thread."""
        self._queue.put(_SENTINEL)
        self._thread.join(timeout=5)

    def new_request_id(self) -> str:
        return str(uuid.uuid4())[:8]

    def now(self) -> float:
        return time.time()
