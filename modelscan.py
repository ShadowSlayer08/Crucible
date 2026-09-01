"""
modelscan.py — Model-artifact supply-chain scanner (static, no-execution).

The rest of CRUCIBLE red-teams a model's *behaviour* at runtime. This module covers
the layer nothing else touches: the model *artifact* itself — the weight file you
download from a hub and load with one line of code. Pickle-based formats
(``.pkl``, ``.pt``/``.pth``, ``.ckpt``, ``.bin``) run arbitrary Python on load via
``__reduce__``; a poisoned checkpoint is remote code execution the moment you call
``torch.load``. This is MITRE ATLAS AML.T0010 (ML Supply Chain Compromise) and the
"Data Poisoning / Supply Chain" surface named in the project's own taxonomy.

How it stays safe: it NEVER unpickles anything. It disassembles the pickle opcode
stream with the standard-library ``pickletools`` (pure inspection) and flags
dangerous ``GLOBAL`` / ``REDUCE`` references — the same technique Fickling and
ProtectAI's modelscan use. Config files are grepped for remote-code switches
(``trust_remote_code``, ``auto_map``). ``.safetensors`` is reported safe-by-format.

Public API
    scan_path(path)                 -> ScanReport   (file or directory)
    scan_file(path)                 -> list[Finding]
    scan_pickle_bytes(data, source) -> list[Finding]
    print_model_scan_report(report) -> None
    report_to_dict(report)          -> dict         (JSON export)

No third-party dependencies.
"""

from __future__ import annotations

import io
import json
import os
import pickletools
import zipfile
from dataclasses import dataclass, field

import colors as C

# ── Severity ordering ─────────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Extensions we treat as (possibly) pickle-backed model artifacts.
PICKLE_EXTS = {".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin",
               ".model", ".pdparams", ".dat", ".p", ".joblib"}
ZIP_EXTS = {".pt", ".pth", ".ckpt", ".zip"}         # torch saves a zip of pickles
CONFIG_EXTS = {".json", ".yaml", ".yml"}
SAFE_EXTS = {".safetensors", ".gguf", ".onnx", ".npz", ".npy", ".h5"}

# ── Opcodes that invoke code / build arbitrary objects on load ────────────────
_INVOKE_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}
_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
               "SHORT_BINSTRING", "BINSTRING", "STRING"}

# (module, name) pairs that are direct code-execution sinks → CRITICAL.
_CRITICAL_SINKS = {
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
    ("os", "execl"), ("os", "execlp"), ("os", "spawnl"), ("os", "spawnv"),
    ("posix", "system"), ("nt", "system"),
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "Popen"),
    ("subprocess", "check_output"), ("subprocess", "check_call"),
    ("subprocess", "getoutput"),
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "compile"),
    ("builtins", "__import__"), ("builtins", "getattr"),
    ("__builtin__", "eval"), ("__builtin__", "exec"), ("__builtin__", "compile"),
    ("__builtin__", "__import__"),
    ("pty", "spawn"), ("runpy", "_run_code"), ("runpy", "_run_module_code"),
    ("importlib", "import_module"), ("ctypes", "CDLL"), ("ctypes", "WinDLL"),
    ("socket", "socket"), ("webbrowser", "open"),
}
# Modules whose import inside a pickle is suspicious → at least HIGH.
_DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty",
    "runpy", "importlib", "ctypes", "multiprocessing", "webbrowser", "commands",
    "popen2", "pip", "setuptools", "requests", "urllib", "urllib2", "httplib",
    "ftplib", "telnetlib", "smtplib",
}
# Staging helpers — noteworthy but not alone conclusive → MEDIUM.
_STAGING_MODULES = {"base64", "codecs", "binascii", "zlib", "bz2", "lzma", "marshal"}


@dataclass
class Finding:
    source: str          # file (or file::member) the finding is in
    severity: str        # CRITICAL/HIGH/MEDIUM/LOW/INFO
    kind: str            # short slug e.g. "pickle-code-exec"
    detail: str          # human-readable explanation
    reference: str = ""  # e.g. "os.system" or "trust_remote_code"
    position: int = -1   # byte offset in the pickle stream, if known


@dataclass
class ScanReport:
    root: str
    findings: list = field(default_factory=list)
    scanned_files: list = field(default_factory=list)
    skipped_files: list = field(default_factory=list)   # (path, reason)

    @property
    def overall(self) -> str:
        if not self.findings:
            return "SAFE"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    @property
    def is_dangerous(self) -> bool:
        return any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["HIGH"]
                   for f in self.findings)


# ─────────────────────────────────────────────────────────────────────────────
# PICKLE OPCODE SCANNING  (inspection only — never unpickles)
# ─────────────────────────────────────────────────────────────────────────────
def _classify_global(module: str, name: str) -> tuple | None:
    """Return (severity, kind, detail) for a global reference, or None if benign."""
    if (module, name) in _CRITICAL_SINKS:
        return ("CRITICAL", "pickle-code-exec",
                f"references code-execution sink {module}.{name}() — loading this "
                f"artifact would run arbitrary code")
    if module in _DANGEROUS_MODULES:
        return ("HIGH", "pickle-dangerous-import",
                f"imports from dangerous module '{module}' ({module}.{name}) inside a "
                f"pickle — a known code-execution vector")
    if module in _STAGING_MODULES:
        return ("MEDIUM", "pickle-staging-import",
                f"imports {module}.{name} — often used to stage/obfuscate a payload")
    return None


def scan_pickle_bytes(data: bytes, source: str) -> list:
    """Disassemble a pickle stream and flag dangerous globals / reduce usage.

    Uses pickletools.genops (pure opcode inspection). Nothing is unpickled, so a
    malicious artifact is analysed without ever running its payload.
    """
    findings = []
    recent_strings: list = []
    globals_seen: list = []       # (module, name)
    invoke = False
    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            op = opcode.name
            if op in _STRING_OPS and isinstance(arg, str):
                recent_strings.append(arg)
                if len(recent_strings) > 8:
                    recent_strings.pop(0)
            elif op == "GLOBAL":
                parts = str(arg).replace("\n", " ").split()
                mod = parts[0] if parts else ""
                nm = parts[1] if len(parts) > 1 else ""
                globals_seen.append((mod, nm, pos))
            elif op == "STACK_GLOBAL":
                mod = recent_strings[-2] if len(recent_strings) >= 2 else ""
                nm = recent_strings[-1] if recent_strings else ""
                globals_seen.append((mod, nm, pos))
            elif op in _INVOKE_OPS:
                invoke = True
    except Exception as exc:  # malformed / truncated pickle — report, don't crash
        findings.append(Finding(source, "MEDIUM", "pickle-parse-error",
                                f"could not fully parse pickle stream: {exc}"))
        return findings

    flagged_dangerous = False
    for mod, nm, pos in globals_seen:
        verdict = _classify_global(mod, nm)
        if verdict:
            sev, kind, detail = verdict
            findings.append(Finding(source, sev, kind, detail,
                                    reference=f"{mod}.{nm}", position=pos))
            if SEVERITY_ORDER[sev] >= SEVERITY_ORDER["HIGH"]:
                flagged_dangerous = True

    # An executable pickle with only known-safe imports (typical ML checkpoint):
    # note it once as INFO so a clean scan still says *why* it's clean.
    if globals_seen and invoke and not flagged_dangerous and not findings:
        findings.append(Finding(
            source, "INFO", "pickle-executable-clean",
            f"constructs Python objects on load ({len(globals_seen)} import(s), "
            f"no dangerous references detected) — normal for a checkpoint"))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CONTAINER / CONFIG / FORMAT DISPATCH
# ─────────────────────────────────────────────────────────────────────────────
def _looks_like_pickle(data: bytes) -> bool:
    # Pickle protocol 2+ begins with b'\x80'; protocol 0/1 commonly start with
    # '(' , 'c', ']', '}' , ' ' etc. Be permissive — genops will reject non-pickle.
    return bool(data) and (data[:1] == b"\x80" or data[:1] in b"(c]}climL")


def scan_zip_container(path: str) -> list:
    """Torch .pt/.ckpt files are ZIP archives of pickle streams — scan each."""
    findings = []
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                low = info.filename.lower()
                if low.endswith((".pkl", ".pickle")) or low.endswith("data.pkl") \
                        or "/data.pkl" in low or low.endswith("/data"):
                    with zf.open(info) as fh:
                        blob = fh.read()
                    if _looks_like_pickle(blob):
                        findings += scan_pickle_bytes(
                            blob, f"{os.path.basename(path)}::{info.filename}")
    except zipfile.BadZipFile:
        return []   # not a zip container; caller falls back to raw pickle scan
    return findings


def scan_config(path: str) -> list:
    """Flag remote-code switches in a HF-style config/JSON."""
    findings = []
    src = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError as exc:
        return [Finding(src, "INFO", "unreadable", f"could not read: {exc}")]

    lowered = raw.lower()
    if '"trust_remote_code": true' in lowered.replace(" ", "") \
            or '"trust_remote_code":true' in lowered.replace(" ", ""):
        findings.append(Finding(src, "HIGH", "config-remote-code",
                                "trust_remote_code=true — loader will execute code "
                                "shipped with the model", reference="trust_remote_code"))
    try:
        obj = json.loads(raw)
    except Exception:
        obj = None
    if isinstance(obj, dict):
        if "auto_map" in obj:
            findings.append(Finding(src, "HIGH", "config-auto-map",
                                    "auto_map present — maps model classes to custom "
                                    "python modules loaded at import", reference="auto_map"))
        if "custom_pipeline" in obj:
            findings.append(Finding(src, "MEDIUM", "config-custom-pipeline",
                                    "custom_pipeline present — pulls a remote pipeline "
                                    "implementation", reference="custom_pipeline"))
    # script URLs anywhere in the file
    for token in lowered.split('"'):
        t = token.strip()
        if t.startswith(("http://", "https://")) and t.endswith((".py", ".sh")):
            findings.append(Finding(src, "MEDIUM", "config-script-url",
                                    f"references a remote script: {t}", reference=t))
    return findings


def scan_safetensors(path: str) -> list:
    """safetensors is a code-free format by design — report it as safe, but sanity
    check the header parses (a corrupt header can crash a loader)."""
    src = os.path.basename(path)
    try:
        with open(path, "rb") as f:
            n = int.from_bytes(f.read(8), "little")
            header = f.read(n)
        json.loads(header.decode("utf-8", errors="replace"))
    except Exception as exc:
        return [Finding(src, "LOW", "safetensors-header",
                        f"safetensors header did not parse cleanly: {exc}")]
    return [Finding(src, "INFO", "safetensors-safe",
                    "safetensors format — tensors only, no executable code")]


def scan_file(path: str) -> list:
    """Dispatch a single file to the right scanner based on its extension/content."""
    ext = os.path.splitext(path)[1].lower()
    src = os.path.basename(path)
    if ext == ".safetensors":
        return scan_safetensors(path)
    if ext in CONFIG_EXTS:
        return scan_config(path)
    if ext in SAFE_EXTS:
        return [Finding(src, "INFO", "safe-format",
                        f"{ext} is a non-executable format — no pickle payload")]

    # Pickle-family: try zip-container first (torch), then raw pickle.
    findings = []
    if ext in ZIP_EXTS:
        findings = scan_zip_container(path)
        if findings:
            return findings
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as exc:
        return [Finding(src, "INFO", "unreadable", f"could not read: {exc}")]
    if _looks_like_pickle(blob):
        return scan_pickle_bytes(blob, src)
    return [Finding(src, "INFO", "no-pickle",
                    "no pickle stream detected at file start")]


def _is_scannable(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in PICKLE_EXTS or ext in ZIP_EXTS or ext in CONFIG_EXTS \
        or ext in SAFE_EXTS


def scan_path(path: str) -> ScanReport:
    """Scan a single file or, for a directory, every model-artifact under it."""
    report = ScanReport(root=path)
    if os.path.isfile(path):
        targets = [path]
    elif os.path.isdir(path):
        targets = []
        for dirpath, _dirs, files in os.walk(path):
            for name in files:
                fp = os.path.join(dirpath, name)
                if _is_scannable(fp):
                    targets.append(fp)
    else:
        report.skipped_files.append((path, "not found"))
        return report

    for fp in sorted(targets):
        report.scanned_files.append(fp)
        report.findings.extend(scan_file(fp))
    return report


# ─────────────────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────────────────
_SEV_COLOR = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW,
              "LOW": C.YELLOW, "INFO": C.DIM}


def report_to_dict(report: ScanReport) -> dict:
    return {
        "root": report.root,
        "overall": report.overall,
        "is_dangerous": report.is_dangerous,
        "files_scanned": len(report.scanned_files),
        "findings": [
            {"source": f.source, "severity": f.severity, "kind": f.kind,
             "detail": f.detail, "reference": f.reference, "position": f.position}
            for f in report.findings
        ],
    }


def print_model_scan_report(report: ScanReport) -> None:
    width = 78
    print(f"\n{'═' * width}")
    print(C.BOLD("  MODEL SUPPLY-CHAIN SCAN  —  artifact deserialization risk (ATLAS AML.T0010)"))
    print(f"{'═' * width}\n")
    print(f"  Target        : {report.root}")
    print(f"  Files scanned : {len(report.scanned_files)}")

    dangerous = [f for f in report.findings if SEVERITY_ORDER[f.severity] >= 2]
    overall = report.overall
    ocol = _SEV_COLOR.get(overall, C.GREEN) if overall != "SAFE" else C.GREEN
    print(f"  Verdict       : {ocol(C.BOLD(overall))}\n")

    if not report.findings:
        print(f"  {C.GREEN('✓')} No model artifacts found to scan, or all clean.\n")
        return

    # Group findings by file for readability.
    by_src = {}
    for f in report.findings:
        by_src.setdefault(f.source, []).append(f)

    for src, items in by_src.items():
        worst = max(items, key=lambda f: SEVERITY_ORDER[f.severity]).severity
        mark = C.RED("✗") if SEVERITY_ORDER[worst] >= 3 else (
            C.YELLOW("!") if SEVERITY_ORDER[worst] >= 2 else C.DIM("·"))
        print(f"  {mark} {C.BOLD(src)}")
        for f in items:
            col = _SEV_COLOR.get(f.severity, C.DIM)
            tag = col(f"[{f.severity}]")
            ref = C.DIM(f"  ({f.reference})") if f.reference else ""
            print(f"      {tag} {f.detail}{ref}")
        print()

    if dangerous:
        print(f"  {C.RED('⚠ Do NOT load these artifacts')} until reviewed — "
              f"deserializing them may execute attacker code.\n")


if __name__ == "__main__":   # pragma: no cover - manual smoke test
    import sys
    rep = scan_path(sys.argv[1] if len(sys.argv) > 1 else ".")
    print_model_scan_report(rep)
