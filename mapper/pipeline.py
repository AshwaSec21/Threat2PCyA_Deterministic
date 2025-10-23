# pipeline.py
# Deterministic mapper (Description-only), with SL cascade, RE(n) preserved, asset gating.
# Output shows TraceableRIDs (from PCyA TIS Source), MappedRIDs (post asset gating), MissingIEC.

from __future__ import annotations
import re
from collections import defaultdict
from typing import Iterable, List, Optional, Union, IO, Dict, Set, Tuple

import pandas as pd

from .parsing import (
    _desc_key_from_report,
    _title_key_from_report,         # diagnostics only
    parse_src_tgt_from_report_desc,
    extract_all_iec_ids,
)
from .csv_rules import load_rules

# --------------------- Readers ---------------------

def _read_csv(obj: Union[str, IO, pd.DataFrame]) -> pd.DataFrame:
    if obj is None:
        raise ValueError("CSV reader received None")
    if isinstance(obj, pd.DataFrame):
        return obj.copy()
    return pd.read_csv(obj, dtype=str).fillna("")

def _read_excel(obj: Union[str, IO, pd.DataFrame]) -> pd.DataFrame:
    if obj is None:
        raise ValueError("Excel reader received None")
    if isinstance(obj, pd.DataFrame):
        return obj.copy()
    return pd.read_excel(obj, dtype=str).fillna("")

# --------------------- IEC helpers ---------------------

def _cascade_candidate_iec(cand_row: dict, target_sl: int, allowed_families: Set[str]) -> List[str]:
    out: List[str] = []
    for sl in range(1, target_sl + 1):
        col = None
        for k in cand_row.keys():
            ku = str(k).strip().upper()
            if ku.startswith(f"SL{sl}"):
                col = k
                break
        if not col:
            continue
        cell = str(cand_row.get(col, "")).strip()
        if not cell or cell.lower() in {"not applicable", "check manually"}:
            continue
        for tok in extract_all_iec_ids(cell):
            fam = tok.split()[0]
            if fam in allowed_families:
                out.append(tok)
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def _build_pcya_crosswalk(pcya_df: pd.DataFrame, rid_col: str, iec_col: str,
                          allowed_families: Set[str]) -> Dict[str, Set[str]]:
    xwalk: Dict[str, Set[str]] = defaultdict(set)
    for _, row in pcya_df.iterrows():
        rid = str(row.get(rid_col, "")).strip()
        if not rid:
            continue
        for tok in extract_all_iec_ids(str(row.get(iec_col, ""))):
            fam = tok.split()[0]
            if fam in allowed_families:
                xwalk[tok].add(rid)
    return xwalk

# --------------------- Asset helpers ---------------------

_ASSET_SPLIT = re.compile(r"[;,/|]")

def _canon_asset_set(s: str) -> Set[str]:
    parts = [p.strip() for p in _ASSET_SPLIT.split(s or "") if p.strip()]
    return set(map(str.casefold, parts))

def _resolve_candidate_allocation(s: str, src: Optional[str], tgt: Optional[str]) -> Set[str]:
    if not s:
        return set()
    if src:
        s = s.replace("{source.Name}", src)
    if tgt:
        s = s.replace("{target.Name}", tgt)
    return _canon_asset_set(s)

def _passes_asset_policy(threat_assets: Set[str], pcya_assets: Set[str], cand_alloc: Set[str]) -> bool:
    if threat_assets and pcya_assets and threat_assets.isdisjoint(pcya_assets):
        return False
    if cand_alloc and not cand_alloc.issubset(pcya_assets):
        return False
    return True

# --------------------- Main ---------------------

def run_pipeline(
    tmt_csv: Union[str, IO, pd.DataFrame] = None,
    pcya_xlsx: Union[str, IO, pd.DataFrame] = None,
    candidates_csv: Union[str, IO, pd.DataFrame] = None,
    iec_xlsx: Optional[Union[str, IO, pd.DataFrame]] = None,  # optional
    *,
    target_sl: int = 3,
    families: Iterable[str] = ("CR", "SAR", "EDR", "HDR", "NDR"),
    pcya_reqid_col: str = "Requirement ID",
    pcya_iec_col: str   = "TIS Source",
    pcya_assets_col: str = "Assets Allocated to",
    # accept app.py-style kwargs
    f_threats=None,
    f_pcya=None,
    f_rules=None,
    f_iec=None,
    **_ignored,
) -> Tuple[pd.DataFrame, Dict]:

    # Prefer app.py-style explicit handles if provided
    tmt_csv        = f_threats if f_threats is not None else tmt_csv
    pcya_xlsx      = f_pcya    if f_pcya    is not None else pcya_xlsx
    candidates_csv = f_rules   if f_rules   is not None else candidates_csv
    iec_xlsx       = f_iec     if f_iec     is not None else iec_xlsx

    # Validate presence
    missing = [n for n,v in [("tmt_csv (f_threats)",tmt_csv),("pcya_xlsx (f_pcya)",pcya_xlsx),("candidates_csv (f_rules)",candidates_csv)] if v is None]
    if missing:
        raise ValueError(f"Missing required input(s): {', '.join(missing)}")

    # Load
    threats = _read_csv(tmt_csv)
    pcya    = _read_excel(pcya_xlsx)
    rules   = load_rules(candidates_csv)
    allowed_families = set(x.upper() for x in families)

    # TMT column normalization
    if "Title" not in threats.columns:
        guesses = [c for c in threats.columns if c.lower() == "title"]
        if guesses: threats.rename(columns={guesses[0]: "Title"}, inplace=True)
        else: threats["Title"] = ""
    desc_col = next((c for c in threats.columns if "description" in c.lower()), None)
    if desc_col and desc_col != "Description":
        threats.rename(columns={desc_col: "Description"}, inplace=True)
    if "Description" not in threats.columns:
        raise ValueError("TMT CSV must include a 'Description' column.")
    if "Source" not in threats.columns:
        guesses = [c for c in threats.columns if c.lower() == "source"]
        if guesses: threats.rename(columns={guesses[0]: "Source"}, inplace=True)
        else: threats["Source"] = ""

    # Build keys & src/tgt
    threats["DescForKey"]  = threats["Description"]
    threats["_desc_key"]   = threats["DescForKey"].map(_desc_key_from_report)
    threats["_title_key"]  = threats.apply(lambda r: _title_key_from_report(r.get("Title",""), r.get("Source","")), axis=1)

    # Robust Src/Tgt extraction (always two columns)
    src_tgt_df = threats["Description"].apply(
        lambda s: pd.Series(parse_src_tgt_from_report_desc(s) or ("", ""))
    )
    src_tgt_df.columns = ["_Src", "_Tgt"]
    threats = pd.concat([threats, src_tgt_df], axis=1)

    # Threat assets (from src/tgt)
    threats["_ThreatAssets"] = threats.apply(
        lambda r: {str(r["_Src"]).casefold(), str(r["_Tgt"]).casefold()} - {""},
        axis=1
    )

    # Desc-only matching
    rules_by_desc: Dict[str, List[int]] = rules.groupby("_desc_key").indices
    no_key_match: List[Dict] = []
    match_idx_by_threat: Dict[int, List[int]] = {}
    for i, r in threats.iterrows():
        dk = r["_desc_key"]
        idxs = rules_by_desc.get(dk)
        if not idxs:
            no_key_match.append({"Id": r.get("Id", i), "Title": r.get("Title",""), "DescKey": dk})
            continue
        match_idx_by_threat[i] = list(idxs)

    # Ensure PCyA columns (rename case-insensitively if needed)
    for col, need in ((pcya_reqid_col, True), (pcya_iec_col, True), (pcya_assets_col, False)):
        if col not in pcya.columns:
            lc = {c.lower(): c for c in pcya.columns}
            key = col.lower()
            if key in lc:
                if lc[key] != col:
                    pcya.rename(columns={lc[key]: col}, inplace=True)
            elif need:
                raise ValueError(f"PCyA is missing required column: '{col}'")
            else:
                pcya[col] = ""

    # Build crosswalk IEC -> RIDs
    xwalk = _build_pcya_crosswalk(pcya, pcya_reqid_col, pcya_iec_col, allowed_families)

    # Build results
    candidate_iec_all: Set[str] = set()
    cross_iec_all: Set[str] = set(xwalk.keys())
    rows = []
    asset_filtered_rows = []

    for t_idx, cand_idxs in match_idx_by_threat.items():
        trow = threats.loc[t_idx]
        src, tgt = trow["_Src"], trow["_Tgt"]
        threat_assets = trow["_ThreatAssets"]

        required_iec: List[str] = []
        for ci in cand_idxs:
            crow = rules.loc[ci].to_dict()
            casc = _cascade_candidate_iec(crow, target_sl, allowed_families)
            required_iec.extend(casc)

        # stable unique
        seen, req_uni = set(), []
        for x in required_iec:
            if x not in seen:
                seen.add(x); req_uni.append(x)

        candidate_iec_all.update(req_uni)

        # TraceableRIDs (from TIS Source, pre-asset) + MappedRIDs (post-asset)
        traceable_rids_all: Set[str] = set()
        matched_rids: Set[str] = set()

        for iec_id in req_uni:
            rids_for_iec = xwalk.get(iec_id, set())
            if rids_for_iec:
                traceable_rids_all.update(rids_for_iec)
            for rid in rids_for_iec:
                pcya_assets = _canon_asset_set(str(
                    pcya.loc[pcya[pcya_reqid_col] == rid, pcya_assets_col].iloc[0]
                    if (pcya[pcya_reqid_col] == rid).any() else ""
                ))
                cand_alloc = _resolve_candidate_allocation(
                    str(rules.loc[cand_idxs[0]].get("PCyA allocated to","")), src, tgt
                )
                if _passes_asset_policy(threat_assets, pcya_assets, cand_alloc):
                    matched_rids.add(rid)
                else:
                    asset_filtered_rows.append({
                        "ThreatId": trow.get("Id", t_idx),
                        "ThreatTitle": trow.get("Title",""),
                        "IEC_ID": iec_id,
                        "RID": rid,
                        "ThreatAssets": sorted(threat_assets),
                        "PCyAAssets": sorted(pcya_assets),
                        "CandidateAlloc": sorted(cand_alloc),
                    })

        # Status + MissingIEC
        status = "Not mitigated"
        missing = []
        if matched_rids:
            status = "Mitigated"
        elif req_uni:
            status = "Partially satisfied"
            missing = [x for x in req_uni if not xwalk.get(x)]

        rows.append({
            "ThreatId": trow.get("Id", t_idx),
            "ThreatTitle": trow.get("Title",""),
            "Source": trow.get("Source",""),
            "Src": src, "Tgt": tgt,
            "TraceableRIDs": "; ".join(sorted(traceable_rids_all)),   # ← from PCyA TIS Source
            "MappedRIDs": "; ".join(sorted(matched_rids)),            # ← after asset policy
            "Status": status,
            "MissingIEC": "; ".join(missing),                         # IECs with zero RIDs in crosswalk
        })

    final_df = pd.DataFrame(rows)

    # Diagnostics
    only_cand  = sorted(candidate_iec_all - cross_iec_all)[:100]
    only_cross = sorted(cross_iec_all - candidate_iec_all)[:100]
    intersect  = sorted(candidate_iec_all & cross_iec_all)[:100]
    diag_iec_alignment = {
        "candidate_iec_count": len(candidate_iec_all),
        "crosswalk_iec_count": len(cross_iec_all),
        "intersection_count": len(candidate_iec_all & cross_iec_all),
        "only_in_candidates_sample": only_cand,
        "only_in_crosswalk_sample": only_cross,
        "intersection_sample": intersect,
    }

    threat_keys_preview = (
        threats[["Id","Title","Source","DescForKey","_title_key","_desc_key"]]
        .head(10).to_dict(orient="records")
    )
    candidate_keys_preview = (
        rules[["Threat_ShortTitle","Threat_Description","_title_key","_desc_key"]]
        .head(10).to_dict(orient="records")
    )

    th_descs = set(threats["_desc_key"].unique())
    cand_descs = set(rules["_desc_key"].unique())

    debug = {
        "stats": {
            "threats": int(len(threats)),
            "final_mappings": int(len(final_df)),
            "no_candidates": int(len([1 for _ in no_key_match])),
            "asset_filtered": int(len(asset_filtered_rows)),
            "rules_total": int(len(rules)),
        },
        "iec_id_alignment": diag_iec_alignment,
        "unmapped_threats": pd.DataFrame(no_key_match),
        "asset_filtered_examples": pd.DataFrame(asset_filtered_rows).head(200),
        "threat_keys_preview": threat_keys_preview,
        "candidate_keys_preview": candidate_keys_preview,
        "desc_intersection_sample": sorted(th_descs & cand_descs)[:20],
        "desc_only_in_threats_sample": sorted(th_descs - cand_descs)[:20],
        "desc_only_in_candidates_sample": sorted(cand_descs - th_descs)[:20],
    }

    return final_df, debug
