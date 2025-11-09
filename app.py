# app.py
import os
import pandas as pd
import streamlit as st

from mapper.pipeline import run_pipeline

st.set_page_config(page_title="Threat → PCyA Mapper", layout="wide")
st.title("Threat → PCyA Deterministic Mapper (Description-only)")

if "do_run" not in st.session_state:
    st.session_state.do_run = False
if "last_error" not in st.session_state:
    st.session_state.last_error = ""

st.markdown(
    """
Upload:
1) **Threat Model CSV** (Microsoft TMT export)  
2) **PCyA Excel** (your requirement matrix)  

For **Candidates CSV** and **IEC 62443 Excel** you can either use the **bundled resources** or upload custom files.
Then select **PCyA columns**, choose **Target SL** and **Families**, and click **Run**.
"""
)

# -------------------- Uploaders (Threats + PCyA) --------------------
u1, u2 = st.columns(2)
with u1:
    f_threats = st.file_uploader(
        "1) Threat Model CSV (from Microsoft TMT)",
        type=["csv"],
        key="uploader_tmt",
        help="The TMT export where Description starts with 'Source to Target: ...'."
    )
with u2:
    f_pcya = st.file_uploader(
        "2) PCyA Excel (XLSX)",
        type=["xlsx", "xlsm", "xls"],
        key="uploader_pcya",
        help="Your requirement matrix including 'Requirement ID', 'TIS Source' and 'Assets Allocated to'."
    )

# -------------------- Bundled resources toggles + optional uploads --------------------
st.subheader("Rules & IEC resources")
left, right = st.columns(2)

with left:
    use_bundled_candidates = st.checkbox(
        "Use bundled Candidates CSV (resources/threat_to_62443_candidates.csv)",
        value=True,
        help="If checked, the bundled rules are used. Uncheck to upload your own."
    )
    f_rules_upload = None
    if not use_bundled_candidates:
        f_rules_upload = st.file_uploader(
            "Upload Candidates CSV (optional override)",
            type=["csv"],
            key="uploader_rules",
        )

with right:
    use_bundled_iec = st.checkbox(
        "Use bundled IEC 62443 Excel (resources/IEC-62443-4-2.xlsx)",
        value=True,
        help="If checked, the bundled IEC Excel is used. Uncheck to upload your own (optional)."
    )
    f_iec_upload = None
    if not use_bundled_iec:
        f_iec_upload = st.file_uploader(
            "Upload IEC 62443 Excel (optional)",
            type=["xlsx", "xlsm", "xls"],
            key="uploader_iec",
        )

# Resolve resource paths
RES_CANDIDATES = os.path.join("resources", "threat_to_62443_candidates.csv")
RES_IEC        = os.path.join("resources", "IEC-62443-4-2.xlsx")

# Decide effective inputs for rules + IEC
rules_source = RES_CANDIDATES if use_bundled_candidates else f_rules_upload
iec_source   = RES_IEC        if use_bundled_iec        else f_iec_upload  # may be None (optional)

# -------------------- PCyA column pickers --------------------
pcya_cols = []
if f_pcya is not None:
    try:
        f_pcya.seek(0)
        pcya_preview = pd.read_excel(f_pcya, engine="openpyxl", nrows=50)
        pcya_cols = list(pcya_preview.columns.astype(str))
    except Exception as e:
        st.warning(f"Could not read PCyA to discover columns: {e}")
        pcya_cols = []

def _pick(cols, candidates):
    low = {str(c).lower().strip(): str(c) for c in cols}
    for name in candidates:
        k = name.lower().strip()
        if k in low:
            return low[k]
    for name in candidates:
        k = name.lower().strip()
        for c in cols:
            if k in str(c).lower():
                return c
    return cols[0] if cols else ""

st.subheader("PCyA column mapping")
c1, c2, c3 = st.columns(3)
with c1:
    pcya_rid_col = st.selectbox(
        "Requirement ID column",
        options=pcya_cols if pcya_cols else [""],
        index=(pcya_cols.index(_pick(pcya_cols, ["Requirement ID", "Req ID"])) if pcya_cols else 0),
        disabled=(not pcya_cols),
    )
with c2:
    pcya_iec_col = st.selectbox(
        "IEC reference column (contains CR/SAR/EDR/HDR/NDR IDs)",
        options=pcya_cols if pcya_cols else [""],
        index=(pcya_cols.index(_pick(pcya_cols, ["TIS Source", "IEC Ref", "IEC reference"])) if pcya_cols else 0),
        disabled=(not pcya_cols),
    )
with c3:
    pcya_assets_col = st.selectbox(
        "Assets column (PCyA “Assets Allocated to”)",
        options=pcya_cols if pcya_cols else [""],
        index=(pcya_cols.index(_pick(pcya_cols, ["Assets Allocated to", "Assets"])) if pcya_cols else 0),
        disabled=(not pcya_cols),
    )

# -------------------- SL + Families --------------------
st.subheader("Target Security Level & Applicable Families")
lcol, rcol = st.columns([1, 2])
with lcol:
    target_sl = st.selectbox(
        "Target SL",
        options=[1, 2, 3, 4],
        index=2,  # default SL3
        help="SL1 only; SL1+SL2; SL1..SL3; SL1..SL4 (cascading)."
    )
with rcol:
    families_all = ["CR", "SAR", "EDR", "HDR", "NDR"]
    families = st.multiselect(
        "Applicable IEC 62443 families",
        options=families_all,
        default=families_all,
        help="Selected families will be considered in SL1..SL4 cells and PCyA crosswalk."
    )

# -------------------- Run --------------------
bcol, _ = st.columns([1,5])
with bcol:
    if st.button("Run"):
        st.session_state.do_run = True
        st.session_state.last_error = ""

if st.session_state.do_run:
    if f_threats is None or f_pcya is None or rules_source is None:
        st.error("Please upload Threat Model CSV, PCyA Excel, and ensure Candidates CSV is set (bundled or uploaded).")
        st.session_state.do_run = False
    elif not pcya_rid_col or not pcya_iec_col or not pcya_assets_col:
        st.error("Please select the three PCyA columns (Requirement ID, IEC reference, Assets).")
        st.session_state.do_run = False
    else:
        try:
            # Rewind uploads if present
            try: f_threats.seek(0)
            except Exception: pass
            try: f_pcya.seek(0)
            except Exception: pass
            if not use_bundled_candidates and rules_source is not None:
                try: rules_source.seek(0)
                except Exception: pass
            if (not use_bundled_iec) and iec_source is not None:
                try: iec_source.seek(0)
                except Exception: pass

            # Call the pipeline (accepts file-like objects OR paths)
            final_df, debug = run_pipeline(
                f_threats=f_threats,
                f_pcya=f_pcya,
                f_rules=rules_source,
                f_iec=iec_source,
                target_sl=target_sl,
                families=tuple(families),
                pcya_reqid_col=pcya_rid_col,
                pcya_iec_col=pcya_iec_col,
                pcya_assets_col=pcya_assets_col,
            )

            st.success(
                f"Mapping complete. Target SL = SL{target_sl}; Families = {', '.join(families) if families else '—'}."
            )

            # -------------------- Results --------------------
            st.subheader("Results")
            st.dataframe(final_df, use_container_width=True)
            if not final_df.empty:
                st.download_button(
                    "Download CSV",
                    data=final_df.to_csv(index=False).encode("utf-8"),
                    file_name="threat_to_pcya_mapping.csv",
                    mime="text/csv",
                )

            # -------------------- Diagnostics --------------------
            st.subheader("Diagnostics")

            st.markdown("**Stats**")
            st.json(debug.get("stats", {}), expanded=False)

            with st.expander("IEC ID alignment (candidates vs PCyA crosswalk)"):
                ia = debug.get("iec_id_alignment", {})
                if ia:
                    colA, colB, colC = st.columns(3)
                    with colA:
                        st.metric("Candidate IEC count", ia.get("candidate_iec_count", 0))
                        st.caption("Only in candidates (sample)")
                        st.write(ia.get("only_in_candidates_sample", []))
                    with colB:
                        st.metric("PCyA crosswalk IEC count", ia.get("crosswalk_iec_count", 0))
                        st.caption("Only in crosswalk (sample)")
                        st.write(ia.get("only_in_crosswalk_sample", []))
                    with colC:
                        st.metric("Intersection count", ia.get("intersection_count", 0))
                        st.caption("Intersection (sample)")
                        st.write(ia.get("intersection_sample", []))
                else:
                    st.write("—")

            with st.expander("Unmapped TMT threats (no candidate by description)"):
                df_um = debug.get("unmapped_threats")
                if isinstance(df_um, pd.DataFrame) and not df_um.empty:
                    st.dataframe(df_um, use_container_width=True)
                else:
                    st.write("—")

            with st.expander("Asset-filtered (failed allocation/overlap policy)"):
                df_af = debug.get("asset_filtered_examples")
                if isinstance(df_af, pd.DataFrame) and not df_af.empty:
                    st.dataframe(df_af, use_container_width=True)
                    st.caption(f"Rows: {len(df_af)}")
                else:
                    st.write("—")

            with st.expander("Key samples (threat vs candidates)"):
                tk = debug.get("threat_keys_preview")
                ck = debug.get("candidate_keys_preview")
                if tk:
                    st.caption("Threat keys (first 10)")
                    st.write(tk)
                if ck:
                    st.caption("Candidate keys (first 10)")
                    st.write(ck)

            with st.expander("Description key alignment (samples)"):
                st.write({
                    "intersection": debug.get("desc_intersection_sample"),
                    "only_in_threats": debug.get("desc_only_in_threats_sample"),
                    "only_in_candidates": debug.get("desc_only_in_candidates_sample"),
                })
            with st.expander("Threats with StrayRIDs (mapped but not traced via TIS Source)"):
                df_stray = debug.get("threats_with_stray_rids")
                if isinstance(df_stray, pd.DataFrame) and not df_stray.empty:
                    st.dataframe(df_stray, use_container_width=True)
                    st.caption(f"Count: {len(df_stray)}")
                else:
                    st.write("—")


        except Exception as e:
            st.session_state.last_error = str(e)
            st.error(f"Error: {e}")
            st.session_state.do_run = False

# Last error (if any)
if st.session_state.last_error:
    with st.expander("Last error"):
        st.code(st.session_state.last_error)
