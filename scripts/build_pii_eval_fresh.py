"""
A FRESH labeled PII set (corpus/pii_labeled_fresh.jsonl), written after the recognizers were frozen and after the dev/test results of
corpus/pii_labeled.jsonl had been seen (and one bug, an Aadhaar match inside a card-style number, fixed because of them). New random values
from a different seed AND new sentence templates: structured text, several identifiers in one record, Hinglish, all-caps forms and longer prose.
It reuses only the value generators of scripts/build_pii_eval.py (Luhn / Verhoeff / PAN / SSN validity), not its templates.

Use it once for the final numbers; do not tune against it.  Same group names as the main set so the per-group tables line up.

Run: python -X utf8 -m scripts.build_pii_eval_fresh
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts import build_pii_eval as base  # noqa: E402  (importing it builds the main records in memory; they are not written)

OUT = REPO_ROOT / "corpus" / "pii_labeled_fresh.jsonl"
rng = base.rng
rng.seed(20261001)
records = []
counters = {}


def add(group, parts):
    text, spans = "", []
    for p in parts:
        if isinstance(p, tuple):
            spans.append({"type": p[0], "start": len(text), "end": len(text) + len(p[1])})
            text += p[1]
        else:
            text += p
    n = counters[group] = counters.get(group, 0) + 1
    records.append({"id": f"{group}-fresh-{n:03d}", "group": group, "split": "fresh", "text": text, "spans": spans})


def cycle(templates, i):
    return templates[i % len(templates)].split("{}")


# ---- positives ------------------------------------------------------------------------------------------------------------------------
for i in range(30):
    t = cycle(['{"contact_email": "', "email = '", "From: ", "To: ", "Send the signed form to ", "Note - mailbox is "], i)
    end = {0: '", "status": "open"}', 1: "'", 2: "\nSubject: renewal", 3: "\n", 4: " by end of day.", 5: " (monitored)"}[i % 6]
    add("email", [t[0], ("email", base.email()), end])
for i in range(30):
    add("phone_us", [["tel: ", "Dial ", "Fax/phone ", "Emergency contact -> ", "Ring ", "Callback #"][i % 6], ("phone", base.us_phone()), ["\n", ", thanks", " (mobile)", ".", " tomorrow", " ext 4"][i % 6]])
for i in range(30):
    add("phone_in_prefixed", [["Contact: ", "Whatsapp/Call ", "Emergency: ", "Site engineer ", "Ph: ", "Reach me @ "][i % 6], ("phone", base.in_phone_prefixed()), ["", " (Rahul)", " - urgent", ".", "\nThanks", " pls"][i % 6]])
for i in range(15):
    d = base.mobile_digits()
    add("phone_in_grouped", [["Number ", "Mob ", "Phone "][i % 3], ("phone", f"{d[:5]}{[' ', '-'][i % 2]}{d[5:]}"), " for delivery."])
for i in range(20):
    add("phone_in_bare_ctx", [["mobile no: ", "Cell - ", "contact number is ", "call ", "phone: "][i % 5], ("phone", base.mobile_digits()), " pls confirm"])
for i in range(15):
    add("phone_in_bare_noctx", [["Driver: ", "Get back to me on ", "Hit me at ", "Ravi says "][i % 4], ("phone", base.mobile_digits()), " if late"])
for i in range(12):
    add("phone_in_landline", ["Reception: ", ("phone", f"0{rng.choice(['11', '22', '33', '40', '44', '80'])}-{rng.randint(20000000, 29999999)}"), " (till 6)"])
for i in range(30):
    add("credit_card", [["Payment method: ", "CC# ", "Card on file - ", "Please charge ", "PAN(card) "][i % 5], ("credit_card", base.card()), ["", " exp 09/28", " (corporate)", ".", " CVV withheld"][i % 5]])
for i in range(25):
    add("ssn", [["SSN: ", "Tax ID ", "Social: ", "applicant ssn "][i % 4], ("ssn", base.ssn()), ["\n", " verified", ".", " (W-9)"][i % 4]])
for i in range(20):
    add("aadhaar_grouped_ctx", [["Aadhaar: ", "UID - ", "aadhar number ", "AADHAAR NO. "][i % 4], ("aadhaar", base.group4(base.aadhaar_digits(), [" ", "-"][i % 2])), [" (masked in copy)", "\n", ".", " kyc done"][i % 4]])
for i in range(20):
    add("aadhaar_grouped_noctx", [["Identity: ", "Applicant number ", "as per card ", "Proof # "][i % 4], ("aadhaar", base.group4(base.aadhaar_digits(), " ")), [".", "\n", " ok", ""][i % 4]])
for i in range(20):
    add("aadhaar_bare_ctx", [["mera aadhaar number hai ", "aadhaar ", "UID no ", "Aadhar card: "][i % 4], ("aadhaar", base.aadhaar_digits()), [" bhej diya", "", ".", " (photocopy)"][i % 4]])
for i in range(15):
    add("aadhaar_bare_noctx", [["Card reads ", "Verify ", "Number: ", "ID "][i % 4], ("aadhaar", base.aadhaar_digits()), ["", " please", ".", " today"][i % 4]])
for i in range(12):
    d = base.aadhaar_digits(valid=False)
    add("aadhaar_ctx_badchecksum", [["aadhaar ", "UID: "][i % 2], ("aadhaar", [base.group4(d, " "), d][i % 2]), " (draft)"])
for i in range(30):
    add("pan_upper", [["PAN: ", "Permanent Account Number ", "Tax PAN - ", "GST/PAN "][i % 4], ("pan", base.pan_value()), ["\n", " verified", ".", " on record"][i % 4]])
for i in range(12):
    add("pan_lower_ctx", [["pan card ", "pan: ", "my pan "][i % 3], ("pan", base.pan_value().lower()), " ok"])
for i in range(5):
    add("pan_lower_noctx", ["code ", ("pan", base.pan_value().lower()), " noted"])
for i in range(40):
    add("person", [["Signed by ", "Regards, ", "Dear ", "Interviewed ", "Raised by ", "Customer: "][i % 6], ("person", base.name()), [" on 12 June.", "\nPlease revert.", ",", " yesterday.", " via portal.", ""][i % 6]])

# several identifiers in one record: what real prompts look like
for i in range(30):
    a, b, c = base.email(), base.in_phone_prefixed(), base.pan_value()
    add("mixed", ["Applicant ", ("person", base.name()), " (", ("email", a), ", ", ("phone", b), ") PAN ", ("pan", c), " Aadhaar ", ("aadhaar", base.group4(base.aadhaar_digits(), " ")), "."])

# ---- hard negatives -------------------------------------------------------------------------------------------------------------------
for i in range(30):
    add("neg_order_10digit", [["Ticket #", "AWB ", "Docket ", "Ref: "][i % 4], str(rng.randint(6 * 10**9, 9 * 10**9 + 999999999)), [" closed.", " delivered.", " pending.", ""][i % 4]])
for i in range(25):
    add("neg_12digit_valid_checksum", [["Container ", "Reference number ", "Job ", "Parcel "][i % 4], base.aadhaar_digits(), [" loaded.", " scanned.", " billed.", " arrived."][i % 4]])
for i in range(20):
    d = base.luhn_complete(rng.choice(["4", "5"]), 16)
    while base.luhn_ok(d):
        d = d[:-1] + str((int(d[-1]) + 1) % 10)
    add("neg_16digit_luhn_fail", [["Serial ", "Lot ", "Order key "][i % 3], "-".join(d[j:j + 4] for j in range(0, 16, 4)), " logged."])
for i in range(20):
    add("neg_ssn_invalid_area", [["Drawing ", "Model ", "Item "][i % 3], f"{rng.choice(['000', '666', str(rng.randint(900, 999))])}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}", " revised."])
for i in range(25):
    add("neg_pan_shaped", [["Model ", "Catalogue ", "Part "][i % 3], base.pan_value(status=rng.choice("DEIKMNOQRSUVWXYZ")), " superseded."])
for i in range(8):
    add("neg_sku_pan_exact_shape", ["SKU ", base.pan_value(), " in stock."])
for i in range(30):
    add("neg_capitalized", [["Meeting at ", "Shipment to ", "Contract with "][i % 3], rng.choice(base.COMPANIES), " (", rng.choice(base.PLACES), ") confirmed."])
NEG_PLAIN = ["Version 4.12.0 released on 2026-10-01.", "Budget is 4,500,000 INR for FY 2026-27.", "Room 12B, floor 3, gate 7.", "Throughput hit 2,400 requests per second at 14:05.",
             "Section 3.4.2 refers to clause 17(b).", "The ratio was 0.87 with a p-value of 0.031.", "Batch 20260925 completed in 41 minutes.", "See appendix C, figure 9 and table 12."]
for i in range(30):
    add("neg_plain", [NEG_PLAIN[i % len(NEG_PLAIN)]])


def main():
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")
    print(f"wrote {len(records)} records ({sum(len(r['spans']) for r in records)} gold spans, {sum(not r['spans'] for r in records)} negatives) to {OUT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
