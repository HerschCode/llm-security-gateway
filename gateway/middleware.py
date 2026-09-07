"""
Core middleware orchestrator. Implements the request lifecycle from the build
doc:

  Pre-flight: PII redaction -> injection detection (ensemble of all 3 layers,
              since this is the *protecting* path, not the *comparing* path --
              scripts/evaluate.py is where each layer is measured individually)
              -> rate limit -> session anomaly check
  -> forward to backend adapter (if pre-flight clean)
  Post-flight: role-based exposure check -> jailbreak-compliance check ->
               system-prompt leak check
  -> log everything, return decision + response

"Ensemble" here means block if ANY layer blocks -- defense in depth, matching
the doc's request-lifecycle diagram which doesn't ask for a single-layer
production mode. Which layer actually fired is preserved in the log
(matched_pattern_id + detection_layer_used), so a block is always attributable
to a specific layer even in ensemble mode.
"""
import time
from dataclasses import dataclass, field

from gateway.adaptive_threshold import AdaptiveThresholdTracker
from gateway.adapters.base import BackendAdapter
from gateway.detectors import rule_based
from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector, SIMILARITY_THRESHOLD
from gateway.detectors.classifier import ScratchClassifierDetector, CLASSIFIER_THRESHOLD
from gateway.logging_schema import GatewayLogger, LogRecord
from gateway.pii import scan_and_redact
from gateway.response_checks import check_jailbreak_compliance, check_system_prompt_leak
from gateway.role_exposure import check as check_role_exposure
from gateway.session_checks import SessionTracker


@dataclass
class GatewayResponse:
    allowed: bool
    response_text: str | None
    block_reason: str | None
    trace: dict = field(default_factory=dict)


class GatewayMiddleware:
    def __init__(self):
        self.embedding_detector = EmbeddingSimilarityDetector()
        self.embedding_detector.load()
        self.classifier_detector = ScratchClassifierDetector()
        self.classifier_detector.load()
        self.session_tracker = SessionTracker()
        self.adaptive_tracker = AdaptiveThresholdTracker()
        self.logger = GatewayLogger()

    def _run_injection_ensemble(self, text: str, session_id: str) -> tuple[bool, str | None, str | None, dict]:
        """Runs all 3 detection layers, blocks if any fires. Returns
        (blocked, detection_layer_used, matched_pattern_id, per_layer_trace).

        Tier 3 adaptive thresholding: layers 2 and 3's thresholds are scaled
        down for sessions with an elevated risk score (prior blocks in this
        session), making them easier to trip for a session that's already
        looked suspicious -- rather than treating every request as
        independent of what this session did a moment ago."""
        per_layer = {}
        multiplier = self.adaptive_tracker.get_threshold_multiplier(session_id)

        rb_result = rule_based.detect(text)
        per_layer["rule_based"] = {"blocked": rb_result.blocked, "latency_ms": rb_result.latency_ms}
        if rb_result.blocked:
            self.adaptive_tracker.record_block(session_id)
            return True, "rule_based", rb_result.matched_pattern_id, per_layer

        emb_threshold = SIMILARITY_THRESHOLD * multiplier
        emb_result = self.embedding_detector.detect(text, threshold=emb_threshold)
        per_layer["embedding_similarity"] = {
            "blocked": emb_result.blocked, "latency_ms": emb_result.latency_ms,
            "effective_threshold": emb_threshold, "risk_multiplier": multiplier,
        }
        if emb_result.blocked:
            self.adaptive_tracker.record_block(session_id)
            return True, "embedding_similarity", emb_result.matched_pattern_id, per_layer

        clf_threshold = CLASSIFIER_THRESHOLD * multiplier
        clf_result = self.classifier_detector.detect(text, threshold=clf_threshold)
        per_layer["scratch_classifier"] = {
            "blocked": clf_result.blocked, "latency_ms": clf_result.latency_ms,
            "effective_threshold": clf_threshold, "risk_multiplier": multiplier,
        }
        if clf_result.blocked:
            self.adaptive_tracker.record_block(session_id)
            return True, "scratch_classifier", clf_result.matched_pattern_id, per_layer

        return False, None, None, per_layer

    def process(
        self,
        prompt: str,
        session_id: str,
        backend: BackendAdapter,
        role: str = "employee",
        system_prompt: str = "",
        user_id: str = "unknown",
    ) -> GatewayResponse:
        request_id = self.logger.new_request_id()
        overall_start = time.perf_counter()

        # ---------- PRE-FLIGHT ----------
        pre_start = time.perf_counter()

        pii_result = scan_and_redact(prompt)
        working_text = pii_result.redacted_text

        session_check = self.session_tracker.record_and_check(session_id)
        if not session_check.allowed:
            self.logger.log(LogRecord(
                timestamp=self.logger.now(), session_id=session_id, request_id=request_id,
                phase="pre_flight", decision="block", detection_layer_used="session_check",
                latency_ms=(time.perf_counter() - pre_start) * 1000,
                matched_pattern_id=session_check.reason,
                extra={"pii_found": pii_result.found, "session_details": session_check.details},
            ))
            return GatewayResponse(
                allowed=False, response_text=None, block_reason=session_check.reason,
                trace={"phase": "pre_flight", "session_check": session_check.details},
            )

        blocked, layer_used, pattern_id, per_layer_trace = self._run_injection_ensemble(working_text, session_id)
        pre_latency_ms = (time.perf_counter() - pre_start) * 1000

        self.logger.log(LogRecord(
            timestamp=self.logger.now(), session_id=session_id, request_id=request_id,
            phase="pre_flight", decision="block" if blocked else "allow",
            detection_layer_used=layer_used, latency_ms=pre_latency_ms,
            matched_pattern_id=pattern_id,
            extra={"pii_found": pii_result.found, "per_layer": per_layer_trace},
        ))

        if blocked:
            return GatewayResponse(
                allowed=False, response_text=None,
                block_reason=f"injection_detected:{layer_used}:{pattern_id}",
                trace={"phase": "pre_flight", "per_layer": per_layer_trace, "pii_found": pii_result.found},
            )

        # ---------- FORWARD TO BACKEND ----------
        backend_response = backend.send(working_text, session_id=session_id, role=role, user_id=user_id)

        # ---------- POST-FLIGHT ----------
        post_start = time.perf_counter()

        role_result = check_role_exposure(backend_response, role)
        compliance_result = check_jailbreak_compliance(backend_response)
        leak_result = check_system_prompt_leak(backend_response, system_prompt)

        post_blocked = role_result.exposed or compliance_result.flagged or leak_result.leaked
        post_latency_ms = (time.perf_counter() - post_start) * 1000

        post_reason = None
        if role_result.exposed:
            post_reason = f"role_exposure:{','.join(role_result.matched_tags)}"
        elif compliance_result.flagged:
            post_reason = "jailbreak_compliance"
        elif leak_result.leaked:
            post_reason = "system_prompt_leak"

        self.logger.log(LogRecord(
            timestamp=self.logger.now(), session_id=session_id, request_id=request_id,
            phase="post_flight", decision="block" if post_blocked else "allow",
            detection_layer_used="post_flight_checks", latency_ms=post_latency_ms,
            matched_pattern_id=post_reason,
            extra={
                "role_exposure_tags": role_result.matched_tags,
                "compliance_markers": compliance_result.matched_markers,
                "system_leak": leak_result.leaked,
            },
        ))

        if post_blocked:
            # A post-flight catch is a real signal too -- feeds the same
            # adaptive-risk mechanism as pre-flight blocks.
            self.adaptive_tracker.record_block(session_id)
            final_text = role_result.redacted_text if role_result.exposed else (
                "[RESPONSE BLOCKED: gateway post-flight check flagged this response -- "
                f"reason: {post_reason}]"
            )
            return GatewayResponse(
                allowed=False, response_text=final_text, block_reason=post_reason,
                trace={
                    "phase": "post_flight",
                    "role_exposure": role_result.matched_tags,
                    "compliance_markers": compliance_result.matched_markers,
                    "system_leak": leak_result.leaked,
                    "total_latency_ms": (time.perf_counter() - overall_start) * 1000,
                },
            )

        return GatewayResponse(
            allowed=True, response_text=backend_response, block_reason=None,
            trace={
                "per_layer": per_layer_trace,
                "total_latency_ms": (time.perf_counter() - overall_start) * 1000,
            },
        )

    def process_streaming(
        self,
        prompt: str,
        session_id: str,
        backend: BackendAdapter,
        role: str = "employee",
        system_prompt: str = "",
        user_id: str = "unknown",
    ):
        """
        Tier 3: streaming support. Pre-flight runs exactly as in process() --
        there's nothing to stream on the way in. The difference is on the way
        out: instead of waiting for the full response before running
        post-flight checks, this re-runs the post-flight checks against the
        GROWING buffer after every chunk, so a leak gets caught and the
        stream gets cut off as soon as enough of it has arrived to detect the
        violation -- not after the backend has already finished generating
        (and the caller has already seen) the entire leaked response.

        Yields dicts: {"chunk": str, "cut_off": bool}. If cut_off=True, no
        further chunks are sent and the caller should treat the response as
        blocked (same semantics as GatewayResponse.allowed=False).
        """
        request_id = self.logger.new_request_id()

        # ---------- PRE-FLIGHT (identical to process()) ----------
        pii_result = scan_and_redact(prompt)
        working_text = pii_result.redacted_text

        session_check = self.session_tracker.record_and_check(session_id)
        if not session_check.allowed:
            self.logger.log(LogRecord(
                timestamp=self.logger.now(), session_id=session_id, request_id=request_id,
                phase="pre_flight", decision="block", detection_layer_used="session_check",
                latency_ms=0.0, matched_pattern_id=session_check.reason, extra={},
            ))
            yield {"chunk": f"[BLOCKED pre-flight: {session_check.reason}]", "cut_off": True}
            return

        blocked, layer_used, pattern_id, _ = self._run_injection_ensemble(working_text, session_id)
        if blocked:
            self.logger.log(LogRecord(
                timestamp=self.logger.now(), session_id=session_id, request_id=request_id,
                phase="pre_flight", decision="block", detection_layer_used=layer_used,
                latency_ms=0.0, matched_pattern_id=pattern_id, extra={},
            ))
            yield {"chunk": f"[BLOCKED pre-flight: injection_detected:{layer_used}:{pattern_id}]", "cut_off": True}
            return

        # ---------- STREAM FROM BACKEND, CHECKING INCREMENTALLY ----------
        buffer = ""
        for chunk in backend.stream(working_text, session_id=session_id, role=role, user_id=user_id):
            buffer += chunk

            role_result = check_role_exposure(buffer, role)
            compliance_result = check_jailbreak_compliance(buffer)
            leak_result = check_system_prompt_leak(buffer, system_prompt)

            if role_result.exposed or compliance_result.flagged or leak_result.leaked:
                reason = (
                    f"role_exposure:{','.join(role_result.matched_tags)}" if role_result.exposed
                    else "jailbreak_compliance" if compliance_result.flagged
                    else "system_prompt_leak"
                )
                self.adaptive_tracker.record_block(session_id)
                self.logger.log(LogRecord(
                    timestamp=self.logger.now(), session_id=session_id, request_id=request_id,
                    phase="post_flight", decision="block", detection_layer_used="streaming_post_flight",
                    latency_ms=0.0, matched_pattern_id=reason,
                    extra={"chars_generated_before_cutoff": len(buffer), "buffer_snippet": buffer[-80:]},
                ))
                yield {"chunk": f"\n[STREAM CUT OFF -- post-flight check flagged: {reason}]", "cut_off": True}
                return

            yield {"chunk": chunk, "cut_off": False}

        self.logger.log(LogRecord(
            timestamp=self.logger.now(), session_id=session_id, request_id=request_id,
            phase="post_flight", decision="allow", detection_layer_used="streaming_post_flight",
            latency_ms=0.0, matched_pattern_id=None, extra={"total_chars": len(buffer)},
        ))
