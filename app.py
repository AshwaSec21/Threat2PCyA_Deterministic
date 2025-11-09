# app.py
import io
import os
import pandas as pd
import streamlit as st

from mapper.pipeline import run_pipeline

st.set_page_config(page_title="Threat → PCyA Deterministic Mapper", layout="wide")

st.title("Threat → PCyA Deterministic Mapper (No AI)")
st.caption("Maps TMT threats to IEC 62443 candidates and PCyA requirements deterministically.")

# ---------------- Sidebar: Inputs ----------------
with st.sidebar:
    st.header("Inputs")

    # TMT CSV (required)
    f_threats = st.file_uploader("TMT CSV (export)", type=["csv"], key="tmt_csv")

    # PCyA Excel (required)
    f_pcya = st.file_uploader("PCyA Excel", type=["xlsx", "xls"], key="pcya_xlsx")

    st.divider()

    st.subheader("Resources (Candidates & IEC)")
    use_bundled_rules = st.checkbox("Use bundled Candidates CSV", value=True,
                                    help="resources/threat_to_62443_candidates.csv")
    f_rules = None
    if not use_bundled_rules:
        f_rules = st.file_uploader("Candidates CSV", type=["csv"], key="rules_csv")

    use_bundled_iec = st.checkbox("Use bundled IEC 62443 Excel", value=True,
                                  help="resources/IEC-62443-4-2.xlsx")
    f_iec = None
    if not use_bundled_iec:
        f_iec = st.file_uploader("IEC 62443 Excel", type=["xlsx", "xls"], key="iec_xlsx")

    st.divider()

    st.subheader("Mapping Options")
    target_sl = st.selectbox("Target Security Level", options=[1, 2, 3, 4], index=1)
    sl_mode = st.radio(
        "SL selection mode",
        options=["cascade", "exact"],
        index=0,
        help="• cascade = include SL1..SLn\n• exact = include only selected SLn"
    )
    families = st.multiselect(
        "IEC families",
        options=["CR", "SAR", "EDR", "HDR", "NDR"],
        default=["CR", "SAR", "EDR", "HDR", "NDR"],
        help="Filter candidates/PCyA by 62443 family."
    )

    st.divider()
    st.subheader("PCyA Column Names")
    pcya_rid_col = st.text_input("Requirement ID column", value="Requirement ID")
    pcya_iec_col = st.text_input("IEC reference column (PCyA → TIS Source)", value="TIS Source")
    pcya_assets_col = st.text_input("Assets column (PCyA)", value="Assets Allocated to")

    st.divider()
    run_btn = st.button("Run Mapping", type="primary", use_container_width=True)

# --------------- Resolve bundled paths if chosen ---------------
def _maybe_open(path_str: str):
    """Return a file-like stream for Streamlit if the bundled path exists; else the path string itself."""
    if os.path.exists(path_str):
        return path_str  # run_pipeline can read path strings directly
    return path_str     # keep as string; pipeline will try to open it

rules_source = _maybe_open("resources/threat_to_62443_candidates.csv") if use_bundled_rules else f_rules
iec_source   = _maybe_open("resources/IEC-62443-4-2.xlsx") if use_bundled_iec else f_iec

# ------------------ Main run & output ------------------
if run_btn:
    # Basic guards
    if not f_threats or not f_pcya:
        st.error("Please provide both **TMT CSV** and **PCyA Excel** to run the mapping.")
        st.stop()
    if use_bundled_rules is False and rules_source is None:
        st.error("Please provide the **Candidates CSV** or enable **Use bundled Candidates CSV**.")
        st.stop()

    try:
        final_df, debug = run_pipeline(
            f_threats=f_threats,
            f_pcya=f_pcya,
            f_rules=rules_source,
            f_iec=iec_source,
            target_sl=target_sl,
            sl_mode=sl_mode,  # <-- new toggle
            families=tuple(families),
            pcya_reqid_col=pcya_rid_col,
            pcya_iec_col=pcya_iec_col,
            pcya_assets_col=pcya_assets_col,
        )
    except Exception as e:
        st.exception(e)
        st.stop()

    st.success("Mapping complete.", icon="✅")

    # Default column order (show new diagnostics columns too)
    preferred_cols = [
        "ThreatId", "ThreatTitle", "Threat_Description", "Source", "Src", "Tgt",
        "TraceableRIDs", "MappedRIDs", "FilteredRIDs", "StrayRIDs",
        "Status", "MissingIEC", "RequiredAssets", "CandidateAlloc",
    ]
    # Build the table with preferred columns first (keep any extras at the end)
    ordered_cols = [c for c in preferred_cols if c in final_df.columns] + \
                   [c for c in final_df.columns if c not in preferred_cols]

    st.subheader("Results")
    st.dataframe(final_df[ordered_cols], use_container_width=True, hide_index=True)

    # Download CSV
    csv_bytes = final_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download CSV",
        data=csv_bytes,
        file_name="threat_to_pcya_mappings.csv",
        mime="text/csv",
        use_container_width=True
    )

    # ---------------- Diagnostics ----------------
    with st.expander("Diagnostics", expanded=False):
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Threats (input)", debug.get("stats", {}).get("threats", 0))
        with col2:
            st.metric("Rows (final)", debug.get("stats", {}).get("final_rows", 0))
        with col3:
            st.metric("Rules (candidates)", debug.get("stats", {}).get("rules_total", 0))

        st.write("**Unmapped threats (no Description-key match):**")
        um = debug.get("unmapped_threats")
        if isinstance(um, pd.DataFrame) and not um.empty:
            st.dataframe(um, use_container_width=True, hide_index=True)
            st.caption("These threats did not match any candidate by normalized Description; shown in output as 'Manual review – no candidate'.")
        else:
            st.info("None")

        st.write("**Asset-filtered examples (first 200):**")
        af = debug.get("asset_filtered_examples")
        if isinstance(af, pd.DataFrame) and not af.empty:
            st.dataframe(af, use_container_width=True, hide_index=True)
        else:
            st.info("None")

        tokens = debug.get("iec_tokens_seen_in_candidates", [])
        if tokens:
            st.write("**IEC tokens seen in candidates (first 200):**")
            st.code(", ".join(tokens))

else:
    st.info("Upload TMT CSV and PCyA Excel, then click **Run Mapping** from the sidebar.")
