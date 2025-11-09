# pipeline.py
# Deterministic mapper (Description-only), with SL cascade, RE(n) preserved,
# and CORRECT mitigation-side asset gating (source/target/both).
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

def _rids_for_exact_iec(pcya_df: pd.DataFrame, rid_col: str, iec_col: str, exact_iec: str) -> Set[str]:
    """
    Return PCyA Requirement IDs for which the TIS Source explicitly contains the EXACT IEC token.
    Example exact_iec: 'CR 3.1 RE(1)' or 'HDR 3.2 RE(1)'
    """
    want = exact_iec.strip()
    out: Set[str] = set()
    for _, row in pcya_df[[rid_col, iec_col]].iterrows():
        rid = str(row[rid_col]).strip()
        if not rid:
            continue
        tokens = set(extract_all_iec_ids(str(row[iec_col])))
        if want in tokens:
            out.add(rid)
    return out

def _cascade_candidate_iec(cand_row: dict, target_sl: int, allowed_families: Set[str]) -> List[str]:
    """
    Expand SL1..SLN columns from candidates row to a list of IEC tokens (CR 3.1, CR 3.1 RE(1), ...),
    only keeping allowed families.
    """
    out: List[str] = []
    for sl in range(1, target_sl + 1):
        col = None
        for k in cand_row.keys():
            ku = str(k).strip().upper()
            if ku.startswith(f"SL{sl}"):
                col = k; break
        if not col:
            continue
        cell = str(cand_row.get(col, "")).strip()
        if not cell or cell.lower() in {"not applicable", "check manually"}:
            continue
        for tok in extract_all_iec_ids(cell):
            fam = tok.split()[0]
            if fam in allowed_families:
                out.append(tok)
    # stable unique
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def _collect_candidate_iec(cand_row: dict, target_sl: int, allowed_families: Set[str], mode: str = "cascade") -> List[str]:
    """
    mode = 'cascade' -> include SL1..SL(target_sl)
    mode = 'exact'   -> include only SL(target_sl)
    """
    out: List[str] = []
    sl_range = range(1, target_sl + 1) if mode == "cascade" else range(target_sl, target_sl + 1)

    for sl in sl_range:
        col = None
        for k in cand_row.keys():
            ku = str(k).strip().upper()
            if ku.startswith(f"SL{sl}"):
                col = k; break
        if not col:
            continue
        cell = str(cand_row.get(col, "")).strip()
        if not cell or cell.lower() in {"not applicable", "check manually"}:
            continue
        for tok in extract_all_iec_ids(cell):
            fam = tok.split()[0]
            if fam in allowed_families:
                out.append(tok)
    # stable unique
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def _build_pcya_crosswalk(pcya_df: pd.DataFrame, rid_col: str, iec_col: str,
                          allowed_families: Set[str]) -> Dict[str, Set[str]]:
    """
    Optional: diagnostic view of IEC -> RIDs present anywhere in PCyA.
    We STILL re-check exact per-IEC per-row at match time (using _rids_for_exact_iec).
    """
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
    """
    Substitute {source.Name}/{target.Name} then return a normalized asset set.
    """
    if not s:
        return set()
    if src:
        s = s.replace("{source.Name}", src)
    if tgt:
        s = s.replace("{target.Name}", tgt)
    return _canon_asset_set(s)

def _passes_asset_policy(threat_assets: Set[str], pcya_assets: Set[str], cand_alloc: Set[str]) -> bool:
    """
    1) There must be overlap between *required* threat assets and PCyA assets (if both provided).
    2) Candidate allocation (resolved) must be subset of PCyA assets (if provided).
    """
    if threat_assets and pcya_assets and threat_assets.isdisjoint(pcya_assets):
        return False
    if cand_alloc and not cand_alloc.issubset(pcya_assets):
        return False
    return True

# --------------------- NEW: mitigation side helpers ---------------------

def _mitigation_side_for_category(cat: str) -> str:
    """
    Deterministic fallback when the candidates row doesn't explicitly allocate to source/target.
    Returns one of: 'source', 'target', 'both'.
    """
    c = (cat or "").strip().lower()
    if "tamper" in c or c == "t":
        return "target"
    if "spoof" in c or c == "s":
        return "both"
    if "elevation" in c or "imperson" in c:
        return "both"
    if "information disclosure" in c or c == "i":
        return "target"
    if "denial of service" in c or "dos" in c or c == "d":
        return "target"
    if "repudiation" in c or c == "r":
        return "source"
    return "both"

def _required_assets_for_threat(
    src: str, tgt: str, threat_assets: Set[str], cand_row: pd.Series
) -> Set[str]:
    """
    Decide which side(s) are required for gating.
    Priority:
      1) Use the candidates row's "PCyA allocated to" (authoritative).
      2) If empty, fall back to category -> side policy.
    """
    src_c = (src or "").casefold()
    tgt_c = (tgt or "").casefold()

    # 1) Authoritative: explicit allocation in the candidate row
    cand_alloc = _resolve_candidate_allocation(str(cand_row.get("PCyA allocated to", "")), src, tgt)
    if cand_alloc:
        # Only keep assets that correspond to this threat’s src/tgt context
        # - if the allocation mentions src only -> source-only
        # - if it mentions tgt only -> target-only
        # - if both -> both
        sides = set()
        if src_c and src_c in cand_alloc:
            sides.add(src_c)
        if tgt_c and tgt_c in cand_alloc:
            sides.add(tgt_c)
        if sides:
            return sides
        # If allocation lists something else (rare), require overlap with the threat's assets
        inter = threat_assets & cand_alloc
        if inter:
            return inter
        # Fallback to both if nothing intersects (defensive)
        return threat_assets

    # 2) Fallback: category-based policy
    side = _mitigation_side_for_category(str(cand_row.get("Threat_Category", "")))
    if side == "target":
        return {tgt_c} - {""}
    if side == "source":
        return {src_c} - {""}
    return threat_assets

# --------------------- Main ---------------------

def run_pipeline(
    tmt_csv: Union[str, IO, pd.DataFrame] = None,
    pcya_xlsx: Union[str, IO, pd.DataFrame] = None,
    candidates_csv: Union[str, IO, pd.DataFrame] = None,
    iec_xlsx: Optional[Union[str, IO, pd.DataFrame]] = None,  # optional for future
    *,
    target_sl: int = 2,
    families: Iterable[str] = ("CR", "SAR", "EDR", "HDR", "NDR"),
    pcya_reqid_col: str = "Requirement ID",
    pcya_iec_col: str   = "TIS Source",
    pcya_assets_col: str = "Assets Allocated to",
    # app.py passthroughs
    f_threats=None, f_pcya=None, f_rules=None, f_iec=None,
    **_ignored,
) -> Tuple[pd.DataFrame, Dict]:

    # Prefer app.py handles if provided
    tmt_csv        = f_threats if f_threats is not None else tmt_csv
    pcya_xlsx      = f_pcya    if f_pcya    is not None else pcya_xlsx
    candidates_csv = f_rules   if f_rules   is not None else candidates_csv
    iec_xlsx       = f_iec     if f_iec     is not None else iec_xlsx

    # Validate presence
    missing = [n for n,v in [("tmt_csv (f_threats)",tmt_csv),("pcya_xlsx (f_pcya)",pcya_xlsx),("candidates_csv (f_rules)",candidates_csv)] if v is None]
    if missing:
        raise ValueError(f"Missing required input(s): {', '.join(missing)}")

    # Load inputs
    threats = _read_csv(tmt_csv)
    pcya    = _read_excel(pcya_xlsx)
    rules   = load_rules(candidates_csv)
    allowed_families = set(x.upper() for x in families)

    # TMT normalization
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

    # Build desc-only keys + src/tgt + threat assets

    # 1) Parse src/tgt first
    src_tgt_df = threats["Description"].apply(
        lambda s: pd.Series(parse_src_tgt_from_report_desc(s) or ("", ""))
    )
    src_tgt_df.columns = ["_Src", "_Tgt"]
    threats = pd.concat([threats, src_tgt_df], axis=1)

    # 2) Build description-only key using src/tgt-aware function
    from .parsing import _desc_key_from_report_with_assets, _title_key_from_report
    threats["DescForKey"] = threats["Description"]
    threats["_desc_key"] = threats.apply(
        lambda r: _desc_key_from_report_with_assets(r["DescForKey"], r["_Src"], r["_Tgt"]),
        axis=1
    )

    # (optional) title key unchanged; just re-run after we have Source
    threats["_title_key"] = threats.apply(
        lambda r: _title_key_from_report(r.get("Title", ""), r.get("Source", "")),
        axis=1
    )

    threats["_ThreatAssets"] = threats.apply(
        lambda r: {str(r["_Src"]).casefold(), str(r["_Tgt"]).casefold()} - {""},
        axis=1
    )

    # Build desc-only index for candidates
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

    # Optional diagnostic crosswalk
    xwalk = _build_pcya_crosswalk(pcya, pcya_reqid_col, pcya_iec_col, allowed_families)

    # ---------- Per-threat mapping ----------
    candidate_iec_all: Set[str] = set()
    cross_iec_all: Set[str] = set(xwalk.keys())
    rows = []
    asset_filtered_rows = []
    debug: Dict = {}

    for t_idx, cand_idxs in match_idx_by_threat.items():
        trow = threats.loc[t_idx]
        src, tgt = trow["_Src"], trow["_Tgt"]
        threat_assets = trow["_ThreatAssets"]

        # Collect required IECs via SL cascade from all matching candidate rows
        required_iec: List[str] = []
        for ci in cand_idxs:
            casc = _cascade_candidate_iec(rules.loc[ci].to_dict(), target_sl, allowed_families)
            required_iec.extend(casc)

        # stable unique
        seen, req_uni = set(), []
        for x in required_iec:
            if x not in seen:
                seen.add(x); req_uni.append(x)

        candidate_iec_all.update(req_uni)

        # --- Identify IECs that are missing in PCyA ---
        # (i.e., required by candidate but not traced by any PCyA requirement)
        missing_iec = []
        for iec in req_uni:
            match_rows = pcya[
                pcya[pcya_iec_col].astype(str).str.contains(iec, case=False, regex=False)
            ]
            if match_rows.empty:
                missing_iec.append(iec)


        # --- Debug probe for Threat 0 (optional) ---
        if str(trow.get("Id", t_idx)) == "0":
            debug["threat0_probe"] = {
                "RequiredIEC": sorted(req_uni),
                "TraceableRIDsByIEC": {
                    iec: sorted(_rids_for_exact_iec(pcya, pcya_reqid_col, pcya_iec_col, iec))
                    for iec in req_uni
                }
            }
        # -------------------------------------------

        # Determine REQUIRED threat assets (source-only / target-only / both)
        first_cand = rules.loc[cand_idxs[0]] if cand_idxs else pd.Series({})
        required_threat_assets = _required_assets_for_threat(src, tgt, threat_assets, first_cand)

        # Build TraceableRIDs (strictly from PCyA, per exact IEC) and MappedRIDs (asset-gated subset)
        traceable_rids_all: Set[str] = set()
        matched_rids: Set[str] = set()

        for iec_id in req_uni:
            rids_for_iec = _rids_for_exact_iec(pcya, pcya_reqid_col, pcya_iec_col, iec_id)
            if rids_for_iec:
                traceable_rids_all.update(rids_for_iec)

            # asset gating
            for rid in rids_for_iec:
                # fetch PCyA assets for that RID
                rid_mask = (pcya[pcya_reqid_col] == rid)
                pcya_assets = _canon_asset_set(str(
                    pcya.loc[rid_mask, pcya_assets_col].iloc[0] if rid_mask.any() else ""
                ))
                # candidate allocation (resolved placeholders) — still checked as subset rule
                cand_alloc_subset = _resolve_candidate_allocation(
                    str(first_cand.get("PCyA allocated to", "")), src, tgt
                )
                if _passes_asset_policy(required_threat_assets, pcya_assets, cand_alloc_subset):
                    matched_rids.add(rid)
                else:
                    asset_filtered_rows.append({
                        "ThreatId": trow.get("Id", t_idx),
                        "ThreatTitle": trow.get("Title",""),
                        "IEC_ID": iec_id,
                        "RID": rid,
                        "RequiredThreatAssets": sorted(required_threat_assets),
                        "PCyAAssets": sorted(pcya_assets),
                        "CandidateAlloc": sorted(cand_alloc_subset),
                    })

        # Status + MissingIEC (missing = IECs with zero traceable RIDs in PCyA)
        missing_iec = [x for x in req_uni if not _rids_for_exact_iec(pcya, pcya_reqid_col, pcya_iec_col, x)]
        if matched_rids:
            status = "Mitigated"
        elif traceable_rids_all:
            status = "Partially satisfied"
        elif req_uni:
            status = "Not mitigated"
        else:
            status = "Not applicable"

        # Any leakage sanity (should be empty)
        stray_rids = matched_rids - traceable_rids_all

        rows.append({
            "ThreatId": trow.get("Id", t_idx),
            "ThreatTitle": trow.get("Title", ""),
            "Threat_Description": trow.get("Description", ""),  # 🆕 new column (comes from TMT CSV)
            "Source": trow.get("Source", ""),
            "Src": src,
            "Tgt": tgt,
            "TraceableRIDs": "; ".join(sorted(traceable_rids_all)),
            "MappedRIDs": "; ".join(sorted(matched_rids)),
            "StrayRIDs": "; ".join(sorted(stray_rids)),
            "Status": status,
            "MissingIEC": "; ".join(sorted(set(missing_iec))),
        })


    final_df = pd.DataFrame(rows)

    # Diagnostics
    problem_df = final_df[final_df["StrayRIDs"].astype(str).str.len() > 0].copy()
    debug["threats_with_stray_rids"] = problem_df

    only_cand  = sorted(candidate_iec_all - set(_build_pcya_crosswalk(pcya, pcya_reqid_col, pcya_iec_col, allowed_families).keys()))[:100]
    only_cross = sorted(set(_build_pcya_crosswalk(pcya, pcya_reqid_col, pcya_iec_col, allowed_families).keys()) - candidate_iec_all)[:100]
    intersect  = sorted(candidate_iec_all & set(_build_pcya_crosswalk(pcya, pcya_reqid_col, pcya_iec_col, allowed_families).keys()))[:100]
    debug["iec_id_alignment"] = {
        "candidate_iec_count": len(candidate_iec_all),
        "crosswalk_iec_count": len(set(_build_pcya_crosswalk(pcya, pcya_reqid_col, pcya_iec_col, allowed_families).keys())),
        "intersection_count": len(candidate_iec_all & set(_build_pcya_crosswalk(pcya, pcya_reqid_col, pcya_iec_col, allowed_families).keys())),
        "only_in_candidates_sample": only_cand,
        "only_in_crosswalk_sample": only_cross,
        "intersection_sample": intersect,
    }

    # Key previews
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

    debug.update({
        "stats": {
            "threats": int(len(threats)),
            "final_mappings": int(len(final_df)),
            "no_candidates": int(len([1 for _ in no_key_match])),
            "asset_filtered": int(len(asset_filtered_rows)),
            "rules_total": int(len(rules)),
        },
        "unmapped_threats": pd.DataFrame(no_key_match),
        "asset_filtered_examples": pd.DataFrame(asset_filtered_rows).head(200),
        "threat_keys_preview": threat_keys_preview,
        "candidate_keys_preview": candidate_keys_preview,
        "desc_intersection_sample": sorted(th_descs & cand_descs)[:20],
        "desc_only_in_threats_sample": sorted(th_descs - cand_descs)[:20],
        "desc_only_in_candidates_sample": sorted(cand_descs - th_descs)[:20],
    })

    return final_df, debug
