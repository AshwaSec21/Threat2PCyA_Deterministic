import re
from .parsing import normalize_asset

def build_asset_regex(assets: list[str], synonyms: dict[str, list[str]] | None = None):
    canon = {}
    for a in assets:
        k = normalize_asset(a)
        if not k: continue
        canon.setdefault(k, set()).add(k)
    for k, syns in (synonyms or {}).items():
        ck = normalize_asset(k)
        canon.setdefault(ck, set()).update([normalize_asset(s) for s in syns])
    patt = {}
    for ck, terms in canon.items():
        parts = [r'\b' + re.escape(t) + r'\b' for t in terms if t]
        patt[ck] = re.compile('|'.join(parts), flags=re.IGNORECASE) if parts else None
    return patt

def text_asset_hits(text: str, patt_map: dict):
    hits = set()
    if not text or not patt_map: return hits
    for k, p in patt_map.items():
        if p and p.search(text):
            hits.add(k)
    return hits
