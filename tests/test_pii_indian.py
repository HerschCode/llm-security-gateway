"""Indian identifiers in the dependency-free PII path (gateway/pii_in.py, backend `regex`), and the false-positive guards that keep order
numbers from being redacted (the RT-09 lesson, reports/redteam-2026-09.md)."""
import random

import pytest

from gateway import pii
from gateway.pii import PIISpan, detect_spans_regex, resolve_overlaps, scan_and_redact
from gateway.pii_in import verhoeff_check_digit, verhoeff_ok


def valid_aadhaar(seed=1, first="2"):
    payload = first + "".join(random.Random(seed).choice("0123456789") for _ in range(10))
    return payload + str(verhoeff_check_digit(payload))


def grouped(d, sep=" "):
    return sep.join([d[:4], d[4:8], d[8:]])


def types(text, **kw):
    return [(s.type, text[s.start:s.end]) for s in resolve_overlaps(detect_spans_regex(text, **kw))]


# ---- Verhoeff -----------------------------------------------------------------------------------------------------------------------

def test_verhoeff_textbook_example_and_round_trip():
    assert verhoeff_check_digit("236") == 3 and verhoeff_ok("2363") and not verhoeff_ok("2364")
    rng = random.Random(0)
    for _ in range(200):
        payload = "".join(rng.choice("0123456789") for _ in range(11))
        assert verhoeff_ok(payload + str(verhoeff_check_digit(payload)))


def test_verhoeff_detects_every_single_digit_error_and_adjacent_transposition():
    full = valid_aadhaar(7)
    for i in range(12):
        for d in range(1, 10):
            assert not verhoeff_ok(full[:i] + str((int(full[i]) + d) % 10) + full[i + 1:])
    for i in range(11):
        if full[i] != full[i + 1]:
            assert not verhoeff_ok(full[:i] + full[i + 1] + full[i] + full[i + 2:])


def test_verhoeff_rejects_non_digits():
    assert not verhoeff_ok("23a3") and not verhoeff_ok("")


# ---- Aadhaar ------------------------------------------------------------------------------------------------------------------------

def test_grouped_valid_aadhaar_is_redacted_without_any_context():
    a = grouped(valid_aadhaar())
    assert types(f"The number on the card reads {a}.") == [("aadhaar", a)]
    b = grouped(valid_aadhaar(2), "-")
    assert types(f"ID {b}") == [("aadhaar", b)]


def test_bare_valid_aadhaar_needs_a_context_word():
    d = valid_aadhaar(3)
    assert types(f"Tracking number {d} is in transit.") == []                      # 8% of random 12-digit numbers validate: leave it
    assert types(f"My Aadhaar number is {d}.") == [("aadhaar", d)]
    assert types(f"UID: {d}") == [("aadhaar", d)]


def test_context_makes_a_bad_checksum_acceptable_but_grouping_alone_does_not():
    bad = valid_aadhaar(4)[:-1] + str((int(valid_aadhaar(4)[-1]) + 1) % 10)
    assert types(f"aadhaar {grouped(bad)}") == [("aadhaar", grouped(bad))]
    assert types(f"reference {grouped(bad)} noted") == []


def test_aadhaar_never_starts_with_zero_or_one():
    for first in "01":
        d = first + valid_aadhaar(5)[1:]
        assert types(f"Aadhaar {grouped(d)}") == []


def test_aadhaar_context_word_variants_and_devanagari():
    d = valid_aadhaar(6)
    for phrase in ("Aadhar", "aadhaar card no", "UIDAI", "enrolment number", "\u0906\u0927\u093e\u0930"):
        assert types(f"{phrase} {d}") == [("aadhaar", d)], phrase


def test_a_16_digit_card_number_is_not_mistaken_for_an_aadhaar_and_vice_versa():
    card = "4111 1111 1111 1111"
    assert types(f"card {card}") == [("credit_card", card)]
    a = grouped(valid_aadhaar(8))
    assert [t for t, _ in types(f"aadhaar {a}")] == ["aadhaar"]


# ---- PAN ------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("pan", ["ABCPE1234F", "AAACC1234A", "BNZPK4567L", "ZZZHZ9999Z"])
def test_pan_in_upper_case_is_redacted_without_context(pan):
    assert types(f"Vendor tax registration {pan} verified.") == [("pan", pan)]


@pytest.mark.parametrize("not_pan", ["ABCXE1234F", "ABCDE12345", "ABCPE12345", "ABPE1234F", "ABCPE1234", "abcpe1234f"])
def test_pan_shaped_but_invalid_or_lower_case_needs_context_or_is_left_alone(not_pan):
    assert types(f"Catalogue code {not_pan} is discontinued.") == []


def test_lower_case_pan_needs_a_pan_context():
    assert types("my pan is abcpe1234f") == [("pan", "abcpe1234f")]
    assert types("the code abcpe1234f was mentioned") == []


def test_pan_inside_a_longer_alphanumeric_run_is_not_matched():
    assert types("SKUABCPE1234FX and XABCPE1234F") == []


# ---- phone ----------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("phone", ["+91 98765 43210", "+91-9876543210", "+919876543210", "+91 9876543210", "09876543210", "91 9876543210", "(+91) 98765 43210"])
def test_indian_mobile_with_a_prefix_is_redacted(phone):
    assert types(f"Call me on {phone} after lunch.") == [("phone", phone)]


@pytest.mark.parametrize("phone", ["98765 43210", "98765-43210"])
def test_five_five_grouping_is_redacted(phone):
    assert types(f"Reach {phone} tonight.") == [("phone", phone)]


def test_bare_ten_digit_mobile_needs_a_context_word():
    assert types("Mobile: 9876543210") == [("phone", "9876543210")]
    assert types("Order 9876543210 shipped on Monday.") == []                    # the RT-09 case: an order number that looks like a mobile
    assert types("Invoice number 8123456789 is overdue.") == []


def test_landline_needs_the_leading_zero_and_a_separator():
    assert types("Office line 011-26544422 until 6 pm.") == [("phone", "011-26544422")]
    assert types("Ref 26544422 today") == []


# ---- the RT-09 guard: identifiers that must never be redacted -------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "What is the status of purchase order 4500012345?", "Escalate CASE-4471 and supplier ID 3300987 please.", "The invoice total is $1,250.00 for PO 7700123.",
    "tracking 202609251200 shipped", "batch 1234 5678 9012 3456 archived", "ISO 9001:2015 and RFC 2119", "IP 10.0.0.1 is the gateway",
    "Deploy v2.3.1 on 2026-09-25", "order 6123456789 and order 7123456789", "part 000-12-3456",
])
def test_ordinary_identifiers_are_not_redacted(text):
    assert scan_and_redact(text).found == [] and scan_and_redact(text).redacted_text == text


# ---- integration with scan_and_redact ---------------------------------------------------------------------------------------------------------

def test_scan_and_redact_reports_types_spans_and_the_redacted_text():
    a = valid_aadhaar(9)
    text = f"Aadhaar {a}, PAN ABCPE1234F, mobile +91 98765 43210, mail a.b@example.com"
    r = scan_and_redact(text)
    assert set(r.found) == {"aadhaar", "pan", "phone", "email"}
    assert r.redacted_text == "Aadhaar [REDACTED_AADHAAR], PAN [REDACTED_PAN], mobile [REDACTED_PHONE], mail [REDACTED_EMAIL]"
    assert all(isinstance(s, PIISpan) for s in r.spans) and [s.start for s in r.spans] == sorted(s.start for s in r.spans)


def test_regex_us_backend_is_the_pre_phase_5_behaviour(monkeypatch):
    monkeypatch.setenv("PII_BACKEND", "regex_us")
    a = valid_aadhaar(9)
    r = scan_and_redact(f"Aadhaar {a} PAN ABCPE1234F mail a@b.co")
    assert r.found == ["email"]


def test_unknown_backend_is_rejected(monkeypatch):
    monkeypatch.setenv("PII_BACKEND", "nope")
    with pytest.raises(ValueError):
        scan_and_redact("x")


def test_overlap_resolution_prefers_the_more_specific_validator():
    spans = [PIISpan("phone", 0, 12), PIISpan("credit_card", 0, 19), PIISpan("email", 30, 40)]
    kept = resolve_overlaps(spans)
    assert [s.type for s in kept] == ["credit_card", "email"]


def test_the_pii_module_still_exports_the_names_older_code_used():
    assert pii.PII_PATTERNS is pii.US_PATTERNS and set(pii.US_PATTERNS) == {"email", "phone", "ssn", "credit_card"}


# ---- SSN validity (the SSA rules) --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("ssn", ["123-45-6789", "078-05-1120", "899-12-3456", "001-01-0001"])
def test_a_structurally_valid_ssn_is_redacted(ssn):
    assert types(f"SSN {ssn} on file.") == [("ssn", ssn)]


@pytest.mark.parametrize("ssn", ["000-12-3456", "666-12-3456", "900-12-3456", "987-65-4321", "123-00-4567", "123-45-0000"])
def test_an_ssn_that_cannot_be_real_is_left_alone(ssn):
    assert types(f"Part number {ssn} is back-ordered.") == []


def test_the_pre_phase_5_backend_did_redact_those(monkeypatch):
    monkeypatch.setenv("PII_BACKEND", "regex_us")
    assert scan_and_redact("Part number 000-12-3456 is back-ordered.").found == ["ssn"]


# ---- a 4-4-4 group inside a longer grouped number is not an Aadhaar (found by scripts/evaluate_pii.py: 10% of Luhn-failing 16-digit numbers) --------

def test_the_first_or_last_three_groups_of_a_card_style_number_are_not_an_aadhaar():
    rng = random.Random(11)
    hits = 0
    for _ in range(300):
        groups = [str(rng.randint(2, 9)) + "".join(rng.choice("0123456789") for _ in range(3)) for _ in range(4)]
        text = "Batch " + " ".join(groups) + " archived"
        hits += any(t == "aadhaar" for t, _ in types(text))
    assert hits == 0                                                            # ~10% of these validated by chance before the guard


def test_a_standalone_grouped_aadhaar_is_still_found_next_to_other_text():
    a = grouped(valid_aadhaar(12))
    for text in (f"{a}", f"ID: {a}.", f"({a})", f"{a}, next"):
        assert any(t == "aadhaar" for t, _ in types(text)), text
