"""No pre-flight step may scale worse than roughly linearly with the input (SEC-02, docs/security-scans.md).

The email pattern used to rescan a whole run of local-part characters from every start position when no "@" followed: 270 ms for 20,000
characters of plain "a", quadratic. The test measures the SCALING (doubling the input must not much more than double the time) rather than an
absolute time, so it does not depend on the speed of the machine."""
import time

import pytest

from gateway.actions.taint import TaintTracker
from gateway.detectors import rule_based
from gateway.pii import scan_and_redact
from gateway.pii_in import find_aadhaar, find_pan, find_phone
from gateway.text_normalizer import decoding_candidates, normalize, sanitize

N = 20_000
PATHOLOGICAL = {
    "one long run of letters": lambda n: "a" * n,
    "one long run of digits": lambda n: "0" * n,
    "local-part characters with dots": lambda n: "a." * (n // 2),
    "digits with dashes": lambda n: "1-" * (n // 2),
    "spaced digits": lambda n: "1 " * (n // 2),
    "plus and digits": lambda n: "+91 " * (n // 4),
    "at signs": lambda n: "a@" * (n // 2),
    "at sign then a long run": lambda n: "a@" + "b" * (n - 2),
    "repeated attack phrase": lambda n: "ignore all " * (n // 11),
    "stacked combining marks": lambda n: ("e" + "\u0301" * 3) * (n // 4),
    "upper-case run (PAN-like)": lambda n: "A" * n,
}
STEPS = {
    "pii": scan_and_redact,
    "pii_in": lambda t: (find_aadhaar(t), find_pan(t), find_phone(t)),
    "rules": rule_based.detect,
    "normalize": normalize,
    "sanitize": sanitize,
    "cipher readings": lambda t: [rule_based.detect(r) for _, r in decoding_candidates(t)],
    "taint index": lambda t: TaintTracker().add("doc", t, "untrusted"),
}


def best_of(fn, arg, repeats=3):
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn(arg)
        times.append(time.perf_counter() - t0)
    return min(times)


@pytest.mark.parametrize("step", STEPS)
@pytest.mark.parametrize("shape", PATHOLOGICAL)
def test_doubling_the_input_does_not_more_than_roughly_double_the_time(step, shape):
    fn, make = STEPS[step], PATHOLOGICAL[shape]
    small, large = best_of(fn, make(N)), best_of(fn, make(2 * N))
    if large < 0.02:                                   # both fast enough that timer noise dominates the ratio
        return
    assert large / max(small, 1e-6) < 3.3, f"{step} on {shape}: {small * 1000:.1f} ms -> {large * 1000:.1f} ms (a linear step gives about 2x, a quadratic one 4x)"


def test_the_pii_step_on_the_largest_allowed_prompt_is_fast_in_absolute_terms():
    """A backstop against a slow constant: the worst shape at the default prompt limit must stay far below a second."""
    assert max(best_of(scan_and_redact, make(N)) for make in PATHOLOGICAL.values()) < 0.5
