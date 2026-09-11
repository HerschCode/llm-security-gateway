"""
Tokenizer/vocab/encoding for the scratch classifier -- deliberately torch-free
so it can be imported by both the training path
(gateway/detectors/scratch_classifier_model.py, which needs torch for the
model itself) and the numpy serving path
(gateway/detectors/classifier_numpy.py, which must NOT import torch -- see
that module's docstring for why). Splitting this out is what makes the
torch-free import actually torch-free: encode()/PAD_IDX used to live in
scratch_classifier_model.py alongside `import torch`, so importing them at all
pulled torch in regardless of which detector used them.
"""
import re
from collections import Counter

MAX_VOCAB_SIZE = 8000
MAX_SEQ_LEN = 128
EMBED_DIM = 64
HIDDEN_DIM = 32
PAD_IDX = 0
UNK_IDX = 1


def tokenize(text: str) -> list[str]:
    """Simple whitespace + punctuation-aware tokenizer. Deliberately basic --
    this is a from-scratch baseline, not a production tokenizer."""
    text = text.lower()
    return re.findall(r"[a-z0-9]+", text)


def build_vocab(texts: list[str], max_vocab_size: int = MAX_VOCAB_SIZE) -> dict:
    counter = Counter()
    for text in texts:
        counter.update(tokenize(text))

    vocab = {"<pad>": PAD_IDX, "<unk>": UNK_IDX}
    for word, _ in counter.most_common(max_vocab_size - 2):
        vocab[word] = len(vocab)
    return vocab


def encode(text: str, vocab: dict, max_len: int = MAX_SEQ_LEN) -> list[int]:
    tokens = tokenize(text)[:max_len]
    ids = [vocab.get(tok, UNK_IDX) for tok in tokens]
    if len(ids) < max_len:
        ids = ids + [PAD_IDX] * (max_len - len(ids))
    return ids
