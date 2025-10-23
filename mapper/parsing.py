# parsing.py
# Deterministic string + IEC parsing utilities.

from __future__ import annotations
import re
from typing import List, Optional, Tuple

# ---------- Normalizers ----------

_CLEAN = re.compile(r"[^a-z0-9]+")
_CAND_PREFIX = re.compile(r"^\s*\{source\.Name\}\s+to\s+\{target\.Name\}\s*:\s*", re.IGNORECASE)
_REP_PREFIX  = re.compile(r"^\s*[^:]+?\s+to\s+[^:]+?\s*:\s*", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"\{[^}]+\}")

def _normalize_text(s: str) -> str:
    s = (s or "").lower().strip()
    s = _CLEAN.sub(" ", s)
    return " ".join(s.split())

# ---------- Keys (Description-only) ----------

def _desc_key_from_candidate(threat_description: str) -> str:
    t = _CAND_PREFIX.sub("", threat_description or "")
    t = _PLACEHOLDER.sub("", t)
    return _normalize_text(t)

def _desc_key_from_report(report_description: str) -> str:
    t = _REP_PREFIX.sub("", report_description or "")
    return _normalize_text(t)

# ---------- Optional Title keys (diagnostics only) ----------

_TITLE_LEAD = re.compile(r"^\s*(?:authenticated\s+|unauthenticated\s+)?", re.IGNORECASE)

def _title_key_from_report(title: str, source: str) -> str:
    t = title or ""
    if source:
        t = t.replace(source, "", 1)
    t = _TITLE_LEAD.sub("", t)
    return _normalize_text(t)

def _title_key_from_candidate(short_title: str) -> str:
    return _normalize_text(short_title)

# ---------- IEC IDs ----------

FAMILIES = ("CR", "SAR", "EDR", "HDR", "NDR")
_NUM     = r"\d+(?:\.\d+)?"
IEC_RE   = re.compile(
    rf"\b(?P<fam>{'|'.join(FAMILIES)})[\s\-_]*({_NUM})(?:\s*R[Ee][\s\-\(]*(\d+)[\s\)]*)?\b",
    flags=re.IGNORECASE,
)

def normalize_iec_id(s: str) -> Optional[str]:
    if s is None:
        return None
    m = IEC_RE.search(str(s))
    if not m:
        return None
    fam = m.group(1).upper()
    num = m.group(2)
    re_n = m.group(3)
    base = f"{fam} {num}"
    return f"{base} RE({re_n})" if re_n else base

def extract_all_iec_ids(text: str) -> List[str]:
    if text is None:
        return []
    s = str(text).replace("\xa0", " ")
    out: List[str] = []
    for m in IEC_RE.finditer(s):
        fam = m.group(1).upper()
        num = m.group(2)
        re_n = m.group(3)
        base = f"{fam} {num}"
        tok  = f"{base} RE({re_n})" if re_n else base
        out.append(tok)
    # Also split on common separators (and)
    for part in re.split(r"(?i)\band\b|[;,/]", s):
        m = IEC_RE.search(part.strip())
        if m:
            fam = m.group(1).upper()
            num = m.group(2)
            re_n = m.group(3)
            base = f"{fam} {num}"
            tok  = f"{base} RE({re_n})" if re_n else base
            out.append(tok)
    seen, uniq = set(), []
    for x in out:
        if x and x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

# ---------- Source/Target parsing from report Description ----------

_SRC_TGT = re.compile(r"^\s*(?P<src>[^:]+?)\s+to\s+(?P<tgt>[^:]+?)\s*:", re.IGNORECASE)

def parse_src_tgt_from_report_desc(desc: str) -> Tuple[Optional[str], Optional[str]]:
    m = _SRC_TGT.match(desc or "")
    if not m:
        return None, None
    return m.group("src").strip(), m.group("tgt").strip()
