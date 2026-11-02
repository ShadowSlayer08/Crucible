"""slm.export — the tokenizer.model copy that GGUF conversion depends on.

Regression for the gap that blocked the live GGUF export: AutoTokenizer.save emits
tokenizer.json but not the raw SentencePiece tokenizer.model, so convert_hf_to_gguf.py
(Phi-3 etc.) failed with 'Missing tokenizer.model'. merge_adapter now backfills it.
Heavy train/merge deps aren't needed here — the helper is pure filesystem logic.
"""
import slm.export as export


def test_ensure_tokenizer_model_already_present(tmp_path):
    out = tmp_path / "merged"
    out.mkdir()
    (out / "tokenizer.model").write_bytes(b"spm")
    assert export._ensure_tokenizer_model(str(tmp_path / "base"), str(out)) is True


def test_ensure_tokenizer_model_copies_from_local_base(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    (base / "tokenizer.model").write_bytes(b"sentencepiece-model-bytes")
    out = tmp_path / "merged"
    out.mkdir()
    assert not (out / "tokenizer.model").exists()
    assert export._ensure_tokenizer_model(str(base), str(out)) is True
    assert (out / "tokenizer.model").read_bytes() == b"sentencepiece-model-bytes"


def test_ensure_tokenizer_model_missing_returns_false_no_raise(tmp_path):
    base = tmp_path / "base"   # no tokenizer.model, not a resolvable HF repo id
    base.mkdir()
    out = tmp_path / "merged"
    out.mkdir()
    assert export._ensure_tokenizer_model(str(base), str(out)) is False
    assert not (out / "tokenizer.model").exists()
