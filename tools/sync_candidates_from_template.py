#!/usr/bin/env python3
import argparse
import re
from pathlib import Path
import sys
import uuid
import time
import os
import pandas as pd

# make 'mapper' importable
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mapper.candidates_builder import build_canonical_candidates

# --- helpers ---
SRC_TGT_PREFIX_RE = re.compile(r"^\s*\{[^}]+\}\s+to\s+\{[^}]+\}\s*[:：]\s*", re.IGNORECASE)
LEADING_TO_COLON  = re.compile(r'^\s*to\s*[:：]\s*', re.IGNORECASE)
DROP_COLS = {"_title_key", "_desc_key", "Threat_Description_tpl"}  # always remove if present
CANON_ORDER = [
    "Threat_ShortTitle",
    "Threat_Category",
    "Threat_Description",
    "Candidate_62443_ID",
    "MappingBasis",
    "RuleClassesHit",
    "62443_ID",
    "IEC_Title",
    "IEC_Description",
]

def _s(x) -> str:
    try:
        if pd.isna(x): return ""
    except Exception:
        pass
    return "" if x is None else str(x)

def strip_src_tgt_prefix(desc_full) -> str:
    s = _s(desc_full)
    return SRC_TGT_PREFIX_RE.sub("", s)

def clean_degenerate_prefix(s: str) -> str:
    s = _s(s)
    return LEADING_TO_COLON.sub("", s).strip()

def atomic_save_csv(df: pd.DataFrame, out_path: Path, max_retries: int = 4, delay_sec: float = 2.0):
    out_path = Path(out_path)
    tmp_path = out_path.with_suffix(f".{uuid.uuid4().hex}.tmp.csv")
    df.to_csv(tmp_path, index=False, encoding="utf-8")
    last_err = None
    for i in range(max_retries):
        try:
            os.replace(tmp_path, out_path)
            print(f"Wrote: {out_path}")
            return
        except PermissionError as e:
            last_err = e
            if i < max_retries - 1:
                print("Target in use (Excel/Preview/OneDrive?). Retrying in 2s…")
                time.sleep(delay_sec)
            else:
                alt = out_path.with_name(out_path.stem + ".NEW.csv")
                os.replace(tmp_path, alt)
                print(f"Could not overwrite locked file. Wrote to: {alt}")
                raise last_err

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", default="resources/AlstomTemplate.tb7")
    ap.add_argument("--in", dest="in_csv", default="resources/threat_to_62443_candidates.csv")
    ap.add_argument("--out", dest="out_csv", default="resources/threat_to_62443_candidates.csv")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1]
    tpl_path  = (root / args.template).resolve()
    base_path = (root / args.in_csv).resolve()
    out_path  = (root / args.out_csv).resolve()

    base = pd.read_csv(base_path)
    if "Threat_ShortTitle" not in base.columns or "Threat_Description" not in base.columns:
        raise RuntimeError("Input CSV must contain 'Threat_ShortTitle' and 'Threat_Description'.")

    canon = build_canonical_candidates(tpl_path, base_path)
    if "Threat_ShortTitle" not in canon.columns or "Threat_Description" not in canon.columns:
        raise RuntimeError("Template builder must provide 'Threat_ShortTitle' and 'Threat_Description'.")

    # Merge template descriptions in
    canon_for_merge = canon[["Threat_ShortTitle", "Threat_Description"]].copy()
    merged = base.merge(canon_for_merge, on="Threat_ShortTitle", how="left")

    # Select template vs original description Series robustly
    tpl_desc_series = (
        merged["Threat_Description_y"] if "Threat_Description_y" in merged.columns
        else (merged["Threat_Description"] if "Threat_Description" in canon_for_merge.columns
              and "Threat_Description" not in base.columns else pd.Series([""] * len(merged), index=merged.index))
    )
    orig_desc_series = (
        merged["Threat_Description_x"] if "Threat_Description_x" in merged.columns
        else (merged["Threat_Description"] if "Threat_Description" in base.columns
              else pd.Series([""] * len(merged), index=merged.index))
    )

    tpl_hits = tpl_desc_series.astype(str).str.len().gt(0)

    # Compute updated descriptions
    updated = []
    for i in merged.index:
        tpl_val  = tpl_desc_series.iloc[i]
        orig_val = orig_desc_series.iloc[i]
        if _s(tpl_val):
            updated.append(clean_degenerate_prefix(strip_src_tgt_prefix(tpl_val)))
        else:
            updated.append(_s(orig_val))
    merged["Threat_Description"] = updated

    # Build output: start from merged, drop helper *_x/*_y and known helper columns
    out_df = merged.drop(columns=[c for c in merged.columns if c.endswith("_x") or c.endswith("_y")], errors="ignore")
    out_df = out_df.drop(columns=[c for c in out_df.columns if c in DROP_COLS], errors="ignore")

    # If we have all canonical columns, force that exact order; otherwise keep existing order minus helpers
    if all(col in out_df.columns for col in CANON_ORDER):
        out_df = out_df.reindex(columns=CANON_ORDER)

    # Save atomically (handles Windows locks)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_save_csv(out_df, out_path)

    # Console summary
    print(f"Rows: {len(out_df)} | Updated from template: {int(tpl_hits.sum())}")
    leading_stub_count = int(out_df["Threat_Description"].astype(str).str.match(
        r'^\s*to\s*[:：]\s*', case=False, na=False).sum())
    print(f"Leading 'to :' after cleanup: {leading_stub_count}")
    empties = int(out_df["Threat_Description"].astype(str).str.strip().eq("").sum())
    if empties:
        print(f"WARNING: Empty Threat_Description rows: {empties}")

if __name__ == "__main__":
    main()
