"""
Presidio backend for gateway/pii.py (optional extra: `pip install -e .[pii]`, then `python -m spacy download en_core_web_sm` for the NER mode).

  presidio        Presidio's pattern recognizers (email, phone via the phonenumbers library, credit card with Luhn, US SSN with its
                  validity rules) plus three CUSTOM recognizers for Indian identifiers, on a blank spaCy pipeline (tokenizer only, no model).
  presidio_ner    the same on `en_core_web_sm`, which adds PERSON. A much larger dependency and resident set; not for the 512 MB tier.

The custom recognizers are Presidio `EntityRecognizer` subclasses that call the validated detectors in gateway/pii_in.py (Aadhaar with the
Verhoeff checksum and context, PAN, Indian mobile/landline), so Presidio's engine, registry, overlap handling and anonymizer are used, and
the Indian logic is written and tested once. Presidio's own India recognizers (InAadhaarRecognizer, InPanRecognizer) exist in the version
installed here; `make_analyzer(builtin_indian=True, custom_indian=False)` builds that variant so scripts/evaluate_pii.py can compare them.

The score threshold is a measured choice (docs/pii-evaluation.md): PII_PRESIDIO_THRESHOLD, default DEFAULT_THRESHOLD.
"""
import functools
import os
from pathlib import Path

from gateway import pii_in
from gateway.pii import PIISpan

try:
    from presidio_analyzer import AnalysisExplanation, AnalyzerEngine, EntityRecognizer, RecognizerRegistry, RecognizerResult
    from presidio_analyzer.nlp_engine import NlpEngineProvider
except ImportError as exc:                                                       # pragma: no cover - exercised only without the extra
    raise ImportError("PII_BACKEND=presidio needs the optional extra: pip install -e .[pii]") from exc

REPO_ROOT = Path(__file__).resolve().parents[1]
BLANK_MODEL_DIR = REPO_ROOT / "data" / "external" / "spacy_blank_en"
NER_MODEL = "en_core_web_sm"
DEFAULT_THRESHOLD = 0.4

ENTITY_TO_TYPE = {"EMAIL_ADDRESS": "email", "PHONE_NUMBER": "phone", "CREDIT_CARD": "credit_card", "US_SSN": "ssn",
                  "IN_AADHAAR": "aadhaar", "IN_PAN": "pan", "PERSON": "person"}


class _WrappedRecognizer(EntityRecognizer):
    """A Presidio recognizer whose logic is one of the pii_in detectors."""
    ENTITY = ""
    FINDER = staticmethod(lambda text: [])

    def __init__(self):
        super().__init__(supported_entities=[self.ENTITY], supported_language="en", name=type(self).__name__)

    def load(self):                                                              # nothing to load
        pass

    def analyze(self, text, entities, nlp_artifacts=None):
        if entities and self.ENTITY not in entities:
            return []
        return [RecognizerResult(self.ENTITY, start, end, score,
                                 analysis_explanation=AnalysisExplanation(recognizer=self.name, original_score=score, textual_explanation=detail))
                for start, end, score, detail in type(self).FINDER(text)]


class AadhaarRecognizer(_WrappedRecognizer):
    ENTITY = "IN_AADHAAR"
    FINDER = staticmethod(pii_in.find_aadhaar)


class PanRecognizer(_WrappedRecognizer):
    ENTITY = "IN_PAN"
    FINDER = staticmethod(pii_in.find_pan)


class IndianPhoneRecognizer(_WrappedRecognizer):
    ENTITY = "PHONE_NUMBER"
    FINDER = staticmethod(pii_in.find_phone)


def _blank_model_path() -> str:
    if not BLANK_MODEL_DIR.exists():
        import spacy
        BLANK_MODEL_DIR.parent.mkdir(parents=True, exist_ok=True)
        spacy.blank("en").to_disk(BLANK_MODEL_DIR)
    return str(BLANK_MODEL_DIR)


@functools.lru_cache(maxsize=8)
def make_analyzer(ner: bool = False, custom_indian: bool = True, builtin_indian: bool = False) -> "AnalyzerEngine":
    model = NER_MODEL if ner else _blank_model_path()
    nlp_engine = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": model}]}).create_engine()
    registry = RecognizerRegistry(supported_languages=["en"])
    registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=["en"])
    if not ner:                                                                   # a blank pipeline has no entities; drop the recognizer that reads them
        for r in list(registry.recognizers):
            if type(r).__name__ == "SpacyRecognizer":
                registry.remove_recognizer(r.name)
    if builtin_indian:
        from presidio_analyzer.predefined_recognizers import InAadhaarRecognizer, InPanRecognizer
        registry.add_recognizer(InAadhaarRecognizer())
        registry.add_recognizer(InPanRecognizer())
    if custom_indian:
        for cls in (AadhaarRecognizer, PanRecognizer, IndianPhoneRecognizer):
            registry.add_recognizer(cls())
    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=["en"])


def _threshold() -> float:
    return float(os.environ.get("PII_PRESIDIO_THRESHOLD", DEFAULT_THRESHOLD))


def analyze(text: str, ner: bool = False, custom_indian: bool = True, builtin_indian: bool = False, threshold: float | None = None):
    entities = [e for e in ENTITY_TO_TYPE if ner or e != "PERSON"]
    return make_analyzer(ner, custom_indian, builtin_indian).analyze(
        text=text, language="en", entities=entities, score_threshold=_threshold() if threshold is None else threshold)


def detect_spans_presidio(text: str, ner: bool = False, **kwargs) -> list[PIISpan]:
    return [PIISpan(ENTITY_TO_TYPE[r.entity_type], r.start, r.end, float(r.score), "presidio") for r in analyze(text, ner, **kwargs)
            if r.entity_type in ENTITY_TO_TYPE]


def anonymize_with_presidio(text: str, results=None, ner: bool = False) -> str:
    """Redaction through presidio-anonymizer (the same `[REDACTED_<TYPE>]` output as gateway.pii.redact; a test asserts they agree)."""
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    results = analyze(text, ner) if results is None else results
    operators = {e: OperatorConfig("replace", {"new_value": f"[REDACTED_{t.upper()}]"}) for e, t in ENTITY_TO_TYPE.items()}
    return AnonymizerEngine().anonymize(text=text, analyzer_results=results, operators=operators).text
