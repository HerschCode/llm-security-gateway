"""
Build the labeled PII evaluation set: corpus/pii_labeled.jsonl (seeded, deterministic; rerun to regenerate byte for byte).

Why synthetic, and what that costs: no free labeled set covers Aadhaar, PAN and Indian phone formats, so these are generated. The values are
valid by construction (Luhn for cards, Verhoeff for Aadhaar, the PAN letter scheme, the SSN area rules), and the sentences come from a fixed
template list. The recognizers and this generator have the same author, so scores here are optimistic for the identifiers the author thought
of; the mitigations are (1) hard-negative groups written to hurt (order numbers, checksum-valid tracking numbers, PAN-shaped SKUs, invalid SSN
areas), (2) groups where recall is EXPECTED to be low (bare numbers with no context word), reported rather than hidden, and (3) an independent
check on the types Gretel's Apache-2.0 finance PII set also labels (scripts/evaluate_pii.py --external).

Each record: id, group, split (dev/test, alternating within a group so both halves cover every group), text, spans [{type, start, end}].
Types: email, phone, credit_card, ssn, aadhaar, pan, person. Tune anything only on `dev`; report `test`.

Run: python -X utf8 -m scripts.build_pii_eval
"""
import json
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.pii_in import verhoeff_check_digit  # noqa: E402

rng = random.Random(20260925)
OUT = REPO_ROOT / "corpus" / "pii_labeled.jsonl"

EN_FIRST = "James Mary Robert Patricia John Jennifer Michael Linda William Elizabeth David Susan Richard Jessica Joseph Karen Thomas Sarah Daniel Emily Matthew Olivia Andrew Grace Ryan Hannah".split()
EN_LAST = "Smith Johnson Williams Brown Jones Miller Davis Wilson Anderson Taylor Thomas Moore Martin Jackson Thompson White Harris Clark Lewis Walker Young Allen King Wright Scott Green Baker Adams".split()
IN_FIRST = "Aarav Priya Rohan Ananya Vikram Sneha Arjun Kavya Rahul Divya Karthik Meera Siddharth Pooja Amit Neha Suresh Lakshmi Manoj Deepa Nikhil Shreya Varun Ishita Harish Anjali Ramesh Sunita Gaurav Rekha".split()
IN_LAST = "Sharma Patel Iyer Reddy Gupta Nair Singh Kumar Desai Mehta Joshi Rao Verma Pillai Menon Banerjee Chatterjee Kulkarni Bhat Shetty Agarwal Kapoor Malhotra Chopra Naidu Das Bose Mishra Yadav Thakur".split()
COMPANIES = ["Northwind Traders", "Blue Harbor Ltd", "Apex Freight Ltd", "Tata Steel", "Infosys", "Larsen and Toubro", "Bharat Electricals", "Acme Corp", "Globex Industries", "Initech", "Zenith Logistics", "Reliance Retail"]
PLACES = ["Mumbai", "Bengaluru", "Chennai", "Delhi", "Pune", "Hyderabad", "London", "Rotterdam", "Singapore", "Chicago", "Kolkata", "Ahmedabad"]
DOMAINS = ["example.com", "company.co.in", "mail.example.org", "corp.example.net", "northstar-mfg.com", "vendor.in", "gmail.com", "outlook.com"]

records = []
counters = {}


def add(group, parts):
    """`parts` is a list of str or (type, value) tuples; spans are computed from where each value lands in the text."""
    text, spans = "", []
    for p in parts:
        if isinstance(p, tuple):
            spans.append({"type": p[0], "start": len(text), "end": len(text) + len(p[1])})
            text += p[1]
        else:
            text += p
    n = counters[group] = counters.get(group, 0) + 1
    records.append({"id": f"{group}-{n:03d}", "group": group, "split": "dev" if n % 2 else "test", "text": text, "spans": spans})


def luhn_complete(prefix: str, length: int) -> str:
    body = prefix + "".join(rng.choice("0123456789") for _ in range(length - len(prefix) - 1))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def luhn_ok(s: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def aadhaar_digits(valid=True) -> str:
    while True:
        payload = str(rng.randint(2, 9)) + "".join(rng.choice("0123456789") for _ in range(10))
        full = payload + str(verhoeff_check_digit(payload))
        if not valid:
            full = payload + str((int(full[-1]) + rng.randint(1, 9)) % 10)
        return full


def group4(d: str, sep: str) -> str:
    return sep.join([d[0:4], d[4:8], d[8:12]])


def pan_value(status=None) -> str:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(rng.choice(letters) for _ in range(3)) + (status or rng.choice("ABCFGHJLPT")) + rng.choice(letters) + "".join(rng.choice("0123456789") for _ in range(4)) + rng.choice(letters)


def name(indian=None):
    ind = rng.random() < 0.5 if indian is None else indian
    return (rng.choice(IN_FIRST) + " " + rng.choice(IN_LAST)) if ind else (rng.choice(EN_FIRST) + " " + rng.choice(EN_LAST))


def email():
    first, last = rng.choice(EN_FIRST + IN_FIRST).lower(), rng.choice(EN_LAST + IN_LAST).lower()
    local = rng.choice([f"{first}.{last}", f"{first}{last}", f"{first[0]}{last}", f"{first}_{last}", f"{first}.{last}+ops", f"{first}{rng.randint(1, 99)}"])
    return f"{local}@{rng.choice(DOMAINS)}"


def mobile_digits() -> str:
    return str(rng.randint(6, 9)) + "".join(rng.choice("0123456789") for _ in range(9))


# ---------------------------------------------------------------------------------------------------------------- positives
T_EMAIL = ["Please send the report to {}.", "Contact: {}", "Forward this to {} by Friday.", "Reach the supplier at {} for the invoice.", "Reply to {} with the signed copy.", "cc {} on the escalation."]
for i in range(40):
    t = T_EMAIL[i % len(T_EMAIL)].split("{}")
    add("email", [t[0], ("email", email()), t[1]])

T_PHONE = ["Call me on {} after lunch.", "Phone: {}", "The supplier's mobile is {}.", "You can reach the desk at {}.", "Ping {} if the delivery slips.", "Contact number {} (office)."]


def us_phone():
    a, b, c = rng.randint(201, 989), rng.randint(200, 989), rng.randint(1000, 9999)
    return rng.choice([f"({a}) {b}-{c}", f"{a}-{b}-{c}", f"{a}.{b}.{c}", f"+1 {a} {b} {c}", f"+1-{a}-{b}-{c}", f"+1{a}{b}{c}"])


for i in range(40):
    t = T_PHONE[i % len(T_PHONE)].split("{}")
    add("phone_us", [t[0], ("phone", us_phone()), t[1]])


def in_phone_prefixed():
    d = mobile_digits()
    return rng.choice([f"+91 {d[:5]} {d[5:]}", f"+91-{d}", f"+91{d}", f"+91 {d}", f"0{d}", f"91 {d}", f"(+91) {d[:5]} {d[5:]}"])


for i in range(40):
    t = T_PHONE[i % len(T_PHONE)].split("{}")
    add("phone_in_prefixed", [t[0], ("phone", in_phone_prefixed()), t[1]])
for i in range(20):
    d = mobile_digits()
    t = T_PHONE[i % len(T_PHONE)].split("{}")
    add("phone_in_grouped", [t[0], ("phone", f"{d[:5]}{rng.choice([' ', '-'])}{d[5:]}"), t[1]])
T_PHONE_CTX = ["Mobile: {}", "Call me on {} tonight.", "WhatsApp {} for the photos.", "My phone is {}, ask for Ramesh.", "Contact {} to confirm the slot.", "Cell {}"]
for i in range(30):
    t = T_PHONE_CTX[i % len(T_PHONE_CTX)].split("{}")
    add("phone_in_bare_ctx", [t[0], ("phone", mobile_digits()), t[1]])
T_PHONE_NOCTX = ["Ping me on {} later today.", "The driver is on {} now.", "Text {} when you arrive.", "Best way to get me is {}.", "{} is the number for the site office."]
for i in range(20):
    t = T_PHONE_NOCTX[i % len(T_PHONE_NOCTX)].split("{}")
    add("phone_in_bare_noctx", [t[0], ("phone", mobile_digits()), t[1]])
for i in range(15):
    add("phone_in_landline", ["Office line ", ("phone", f"0{rng.choice(['11', '22', '33', '40', '44', '80', '20'])}-{rng.randint(20000000, 29999999)}"), " until 6 pm."])


def card():
    kind = rng.choice(["visa", "mc", "amex", "rupay", "diners"])
    if kind == "amex":
        d = luhn_complete(rng.choice(["34", "37"]), 15)
        return [f"{d[:4]} {d[4:10]} {d[10:]}", d][rng.random() < 0.3]
    if kind == "diners":
        d = luhn_complete("36", 14)
        return f"{d[:4]} {d[4:10]} {d[10:]}"
    d = luhn_complete({"visa": "4", "mc": rng.choice(["51", "52", "53", "54", "55"]), "rupay": rng.choice(["60", "65", "81", "82"])}[kind], 16)
    return rng.choice([" ".join(d[i:i + 4] for i in range(0, 16, 4)), "-".join(d[i:i + 4] for i in range(0, 16, 4)), d])


T_CARD = ["Charge the card {} for the renewal.", "Card number: {}", "Refund to {} please.", "The corporate card ({}) was declined."]
for i in range(40):
    t = T_CARD[i % len(T_CARD)].split("{}")
    add("credit_card", [t[0], ("credit_card", card()), t[1]])


def ssn():
    while True:
        a, g, s = rng.randint(1, 899), rng.randint(1, 99), rng.randint(1, 9999)
        if a != 666:
            return f"{a:03d}-{g:02d}-{s:04d}"


T_SSN = ["SSN {} on file.", "Employee tax id {}.", "Verify identity with {}.", "Her social security number is {}."]
for i in range(30):
    t = T_SSN[i % len(T_SSN)].split("{}")
    add("ssn", [t[0], ("ssn", ssn()), t[1]])

T_AAD_CTX = ["My Aadhaar number is {}.", "UID: {}", "Aadhaar card no {} attached.", "Please link {} to my Aadhaar profile.", "Enrolment number {} was issued in 2019."]
T_AAD_NOCTX = ["The number on the card reads {}.", "My ID is {} as per the document.", "Verify the applicant with {}.", "KYC identifier {} was submitted.", "Identity proof: {}"]
for i in range(25):
    t = T_AAD_CTX[i % len(T_AAD_CTX)].split("{}")
    add("aadhaar_grouped_ctx", [t[0], ("aadhaar", group4(aadhaar_digits(), rng.choice([" ", "-"]))), t[1]])
for i in range(25):
    t = T_AAD_NOCTX[i % len(T_AAD_NOCTX)].split("{}")
    add("aadhaar_grouped_noctx", [t[0], ("aadhaar", group4(aadhaar_digits(), rng.choice([" ", "-"]))), t[1]])
for i in range(25):
    t = T_AAD_CTX[i % len(T_AAD_CTX)].split("{}")
    add("aadhaar_bare_ctx", [t[0], ("aadhaar", aadhaar_digits()), t[1]])
for i in range(20):
    t = T_AAD_NOCTX[i % len(T_AAD_NOCTX)].split("{}")
    add("aadhaar_bare_noctx", [t[0], ("aadhaar", aadhaar_digits()), t[1]])
for i in range(15):
    t = T_AAD_CTX[i % len(T_AAD_CTX)].split("{}")
    d = aadhaar_digits(valid=False)
    add("aadhaar_ctx_badchecksum", [t[0], ("aadhaar", rng.choice([group4(d, " "), d])), t[1]])

T_PAN = ["PAN: {}", "Her PAN is {} for the ITR.", "Please attach the PAN card {}.", "Vendor tax registration {} verified.", "Permanent account number {}."]
for i in range(40):
    t = T_PAN[i % len(T_PAN)].split("{}")
    add("pan_upper", [t[0], ("pan", pan_value()), t[1]])
for i in range(15):
    t = ["pan no {} please", "my pan is {}", "PAN card - {}"][i % 3].split("{}")
    add("pan_lower_ctx", [t[0], ("pan", pan_value().lower()), t[1]])
for i in range(6):
    add("pan_lower_noctx", ["The tax code ", ("pan", pan_value().lower()), " was mentioned."])

T_PERSON = ["Please escalate the case raised by {}.", "Meeting with {} is at 3 pm.", "{} approved the purchase order.", "The complaint was filed by {} last week.", "Ask {} about the delivery.", "Assign the ticket to {}."]
for i in range(60):
    t = T_PERSON[i % len(T_PERSON)].split("{}")
    add("person", [t[0], ("person", name()), t[1]])

# ---------------------------------------------------------------------------------------------------------------- hard negatives
for i in range(40):
    kind = i % 4
    if kind == 0:
        add("neg_order_10digit", ["Order ", mobile_digits(), " shipped on Monday."])
    elif kind == 1:
        add("neg_order_10digit", ["Purchase order PO", str(rng.randint(10**9, 10**10 - 1)), " is awaiting approval."])
    elif kind == 2:
        add("neg_order_10digit", ["Invoice number ", str(rng.randint(6 * 10**9, 9 * 10**9)), " is overdue."])
    else:
        add("neg_order_10digit", ["Case ", str(rng.randint(3 * 10**9, 5 * 10**9)), " was escalated."])
for i in range(30):
    d = aadhaar_digits()                                    # 12 digits, first digit 2-9, checksum VALID by construction: the hazard for bare acceptance
    add("neg_12digit_valid_checksum", [["Tracking number ", "Shipment ref ", "Consignment "][i % 3], d, [" is in transit.", " was scanned at the depot.", " left the warehouse."][i % 3]])
for i in range(20):
    d = luhn_complete(rng.choice(["4", "5"]), 16)
    while luhn_ok(d):
        d = d[:-1] + str((int(d[-1]) + 1) % 10)
    add("neg_16digit_luhn_fail", ["Batch ", " ".join(d[j:j + 4] for j in range(0, 16, 4)), " was archived."])
for i in range(20):
    area = rng.choice(["000", "666", str(rng.randint(900, 999))])
    add("neg_ssn_invalid_area", ["Part number ", f"{area}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}", " is back-ordered."])
for i in range(30):
    if i < 20:
        code = pan_value(status=rng.choice("DEIKMNOQRSUVWXYZ"))          # fourth letter is not a PAN holder-status code
        add("neg_pan_shaped", ["Catalogue code ", code, " is discontinued."])
    else:
        add("neg_pan_shaped", ["Ref ", "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(4)) + str(rng.randint(10000, 99999)), " needs review."])
for i in range(10):
    add("neg_sku_pan_exact_shape", ["SKU ", pan_value(), " restocked."])              # a SKU that happens to be exactly PAN-shaped: format-only recognizers will fire
for i in range(40):
    add("neg_capitalized", [["Supplier ", "Vendor ", "Customer "][i % 3], rng.choice(COMPANIES), " in ", rng.choice(PLACES), " requested an extension."])
NEG_PLAIN = ["Deploy version v2.3.1 to staging on 2026-09-25.", "The SLA is 99.95 percent over 30 days.", "Meeting room 4B is booked from 10:30 to 11:45.", "Total was $1,250.00 for 12 units.",
             "IP 10.0.0.1 is the internal gateway.", "See section 4.2.1 and table 7 for details.", "Approve within 2 business days of submission.", "Q3 revenue grew 12 percent year over year.",
             "The cycle time is 4.7 days for category A.", "Reference ISO 9001:2015 and RFC 2119."]
for i in range(40):
    add("neg_plain", [NEG_PLAIN[i % len(NEG_PLAIN)]])


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")
    groups = {}
    for r in records:
        groups.setdefault(r["group"], [0, 0])[0 if r["split"] == "dev" else 1] += 1
    print(f"wrote {len(records)} records to {OUT.relative_to(REPO_ROOT)}")
    for g, (d, t) in groups.items():
        print(f"  {g:<28} dev {d:>3}  test {t:>3}")


if __name__ == "__main__":
    main()
