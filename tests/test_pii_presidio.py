"""The Presidio backend (gateway/pii_presidio.py). Skipped unless the optional extra is installed: pip install -e .[pii]
(the NER tests also need: python -m spacy download en_core_web_sm)."""
import pytest

pytest.importorskip("presidio_analyzer")
pytest.importorskip("presidio_anonymizer")

from gateway import pii  # noqa: E402
from gateway import pii_presidio as pp  # noqa: E402
from gateway.pii_in import verhoeff_check_digit  # noqa: E402


def aadhaar(seed_digits="23412341234"):
    return seed_digits + str(verhoeff_check_digit(seed_digits))


def grouped(d):
    return f"{d[:4]} {d[4:8]} {d[8:]}"


def spans(text, **kw):
    return [(s.type, text[s.start:s.end]) for s in pii.resolve_overlaps(pp.detect_spans_presidio(text, **kw))]


def test_the_backend_is_selected_by_the_environment_and_redacts(monkeypatch):
    monkeypatch.setenv("PII_BACKEND", "presidio")
    text = f"Mail olivia.anderson@company.co.in, PAN ABCPE1234F, Aadhaar {grouped(aadhaar())}"
    r = pii.scan_and_redact(text)
    assert set(r.found) == {"email", "pan", "aadhaar"}
    assert r.redacted_text == "Mail [REDACTED_EMAIL], PAN [REDACTED_PAN], Aadhaar [REDACTED_AADHAAR]"


def test_presidios_own_recognizers_still_do_their_part():
    assert ("credit_card", "4111 1111 1111 1111") in spans("card 4111 1111 1111 1111 declined")
    assert ("email", "a.b@example.com") in spans("mail a.b@example.com")


def test_the_custom_indian_recognizers_add_aadhaar_pan_and_mobile():
    d = aadhaar()
    s = spans(f"UID {d}; PAN ABCPE1234F; call +91 98765 43210")
    assert ("aadhaar", d) in s and ("pan", "ABCPE1234F") in s and ("phone", "+91 98765 43210") in s


def test_the_aadhaar_gating_is_the_same_as_the_dependency_free_path():
    d = aadhaar()
    assert ("aadhaar", d) not in spans(f"Tracking number {d} is in transit.")          # bare, no context: left alone
    assert ("aadhaar", d) in spans(f"My Aadhaar number is {d}.")
    assert any(t == "aadhaar" for t, _ in spans(f"reference {grouped(d)} noted"))       # grouped and checksum-valid


def test_presidios_default_phone_recognizer_flags_a_bare_ten_digit_order_number():
    """The reason the regex path gates bare numbers on context (RT-09): Presidio's own PhoneRecognizer reports an order number that
    looks like an Indian mobile at its lowest score, so the threshold decides whether it is redacted. Pinned as observed behaviour."""
    hits = pp.analyze("Order 9876543210 shipped on Monday.", custom_indian=False, threshold=0.0)
    assert any(r.entity_type == "PHONE_NUMBER" and r.score <= 0.5 for r in hits)


def test_threshold_removes_low_confidence_results(monkeypatch):
    monkeypatch.setenv("PII_PRESIDIO_THRESHOLD", "0.95")
    assert spans("Order 9876543210 shipped on Monday.") == []


def test_anonymizer_output_matches_the_shared_redaction():
    text = f"Mail a.b@example.com about PAN ABCPE1234F and Aadhaar {aadhaar()}"
    results = pp.analyze(text)
    assert pp.anonymize_with_presidio(text, results) == pii.redact(text, pii.resolve_overlaps(pp.detect_spans_presidio(text)))


def test_person_is_only_reported_in_ner_mode():
    assert all(t != "person" for t, _ in spans("Please escalate the case raised by Priya Sharma."))


def test_ner_mode_finds_a_person_name():
    spacy = pytest.importorskip("spacy")
    try:
        spacy.load("en_core_web_sm")
    except OSError:
        pytest.skip("en_core_web_sm is not installed")
    assert any(t == "person" and "Priya Sharma" in v for t, v in spans("Please escalate the case raised by Priya Sharma.", ner=True))
