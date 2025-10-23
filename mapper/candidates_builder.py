# mapper/candidates_builder.py
from pathlib import Path
import re
import json
import xml.etree.ElementTree as ET
import pandas as pd

# Placeholders like {source.Name}, {target.Name}, etc.
PLACEHOLDER_RE = re.compile(r"\{[^}]+\}")

def _norm_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def _lower_collapse(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()

def _title_key_from_candidate(short_title: str) -> str:
    return _lower_collapse(short_title)

def _desc_key_from_template(desc: str) -> str:
    # remove placeholders THEN normalize — keys must be placeholder-agnostic
    return _lower_collapse(PLACEHOLDER_RE.sub(" ", desc or ""))

def normalize_iec_id(s: str) -> str:
    # Keep RE(n) if present; do NOT collapse variants
    return (s or "").upper().replace("\xa0", " ").strip()

# ----------------------------
# XML (.tb7) reader (preferred)
# ----------------------------
def _collect_props(elem) -> dict:
    props = {}
    for prop in elem.findall("./Properties/Property"):
        name = (prop.findtext("Name") or "").strip()
        if not name:
            continue
        val = prop.findtext("Value")
        if val is None:
            val = prop.findtext("Content")
        if val is None:
            val = "".join(prop.itertext()) or ""
        props[name] = _norm_space(val)
    return props

def read_threat_types_from_xml_tb7(tb7_xml_path: Path) -> pd.DataFrame:
    p = Path(tb7_xml_path)
    if not p.exists():
        raise FileNotFoundError(f"Template not found: {p}")

    try:
        tree = ET.parse(p)
        root = tree.getroot()
    except Exception as e:
        raise RuntimeError(f"Could not parse XML from {p}: {e}")

    rows, seen = [], set()

    for elem in root.iter():
        props = _collect_props(elem)
        title = props.get("Title") or elem.findtext("Title") or elem.findtext("ShortTitle")
        # IMPORTANT: keep placeholders in the stored description
        desc  = props.get("UserThreatDescription") or elem.findtext("Description")
        cat   = props.get("UserThreatCategory") or props.get("Category") or elem.findtext("Category") or ""

        if title and desc:
            t = _norm_space(title)
            d = _norm_space(desc)  # keep placeholders here
            key = (t.lower(), _lower_collapse(PLACEHOLDER_RE.sub(" ", d)))
            if key not in seen:
                seen.add(key)
                rows.append({
                    "Threat_ShortTitle": t,
                    "Threat_Category": _norm_space(str(cat)),
                    "Threat_Description": d,  # placeholders retained
                })

    if not rows:
        raise RuntimeError(
            f"No threat types found in XML template {p}. "
            f"Ensure the template stores threats as Properties with Title/UserThreatDescription."
        )

    df = pd.DataFrame(rows).drop_duplicates(subset=["Threat_ShortTitle", "Threat_Description"])
    return df

# ----------------------------
# JSON fallback (if a template is JSON)
# ----------------------------
def _maybe_add_threat_json(rows: list, obj: dict):
    if not isinstance(obj, dict):
        return
    title = obj.get("ShortTitle") or obj.get("Title") or obj.get("Name")
    desc  = obj.get("Description") or obj.get("Text") or obj.get("Summary")
    cat   = obj.get("Category") or obj.get("Group") or obj.get("Type") or ""
    if title and desc:
        rows.append({
            "Threat_ShortTitle": _norm_space(title),
            "Threat_Category": _norm_space(str(cat)),
            "Threat_Description": _norm_space(desc),  # keep placeholders if present
        })

def read_threat_types_from_json_tb7(tb7_json_path: Path) -> pd.DataFrame:
    encodings = ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"]
    text, last_err = None, None
    for enc in encodings:
        try:
            with open(tb7_json_path, "r", encoding=enc) as fh:
                text = fh.read()
            if text and text.strip():
                break
        except Exception as e:
            last_err = e
            text = None
    if text is None or not text.strip():
        raise RuntimeError(f"Could not read text from {tb7_json_path} with encodings {encodings}. Last error: {last_err}")

    try:
        data = json.loads(text)
    except Exception as e:
        raise RuntimeError(f"Could not parse JSON from {tb7_json_path}: {e}")

    rows = []
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                for it in v:
                    _maybe_add_threat_json(rows, it)
        _maybe_add_threat_json(rows, data)
    elif isinstance(data, list):
        for it in data:
            _maybe_add_threat_json(rows, it)

    if not rows:
        raise RuntimeError(f"No threat types found in JSON template {tb7_json_path}")
    return pd.DataFrame(rows).drop_duplicates(subset=["Threat_ShortTitle", "Threat_Description"])

# ----------------------------
# Base candidates (curated CSV)
# ----------------------------
def load_base_candidates(csv_path: Path) -> pd.DataFrame:
    q = Path(csv_path)
    if not q.exists():
        raise FileNotFoundError(f"Base candidates CSV not found: {q}")

    df = pd.read_csv(q, encoding="utf-8", engine="python")
    df.columns = [c.strip() for c in df.columns]

    def pick(*names, default=""):
        for n in names:
            if n in df.columns:
                return n
        df[names[0]] = default
        return names[0]

    c_title = pick("Threat_ShortTitle", "Threat ShortTitle", "Threat Short Title")
    c_desc  = pick("Threat_Description", "Threat Description", "Threat Desc")
    c_iecid = pick("62443_ID", "IEC_ID")

    for c in [c_title, c_desc, c_iecid]:
        df[c] = df[c].astype(str).fillna("")

    df = df.rename(columns={
        c_title: "Threat_ShortTitle",
        c_desc:  "Threat_Description",  # expect placeholders in the curated CSV now
        c_iecid: "62443_ID",
    })

    def norm_ids(cell: str) -> str:
        parts = [normalize_iec_id(x) for x in str(cell).split(";") if str(x).strip()]
        seen, out = set(), []
        for x in parts:
            if x and x not in seen:
                seen.add(x); out.append(x)
        return "; ".join(out)

    df["62443_ID"] = df["62443_ID"].apply(norm_ids)
    return df[["Threat_ShortTitle", "Threat_Description", "62443_ID"]]

# ----------------------------
# Canonical builder
# ----------------------------
def build_canonical_candidates(template_tb7_path: Path, base_csv: Path) -> pd.DataFrame:
    try:
        tpl = read_threat_types_from_xml_tb7(template_tb7_path)
    except Exception:
        tpl = read_threat_types_from_json_tb7(template_tb7_path)

    base = load_base_candidates(base_csv)

    tpl["_title_key"] = tpl["Threat_ShortTitle"].apply(_title_key_from_candidate)
    tpl["_desc_key"]  = tpl["Threat_Description"].apply(_desc_key_from_template)

    base["_title_key"] = base["Threat_ShortTitle"].apply(_title_key_from_candidate)
    base["_desc_key"]  = base["Threat_Description"].apply(_desc_key_from_template)

    canon = tpl.merge(
        base[["_title_key", "_desc_key", "62443_ID"]],
        on=["_title_key", "_desc_key"],
        how="left"
    )

    need = canon["62443_ID"].isna() | (canon["62443_ID"].astype(str).str.strip() == "")
    if need.any():
        base_by_title = (
            base[["_title_key", "62443_ID"]]
            .drop_duplicates("_title_key")
            .rename(columns={"62443_ID": "62443_ID_title"})
        )
        canon = canon.merge(base_by_title, on="_title_key", how="left")
        canon["62443_ID"] = canon["62443_ID"].where(~need, canon["62443_ID_title"])
        canon = canon.drop(columns=["62443_ID_title"])

    canon = canon.rename(columns={"62443_ID": "Candidate_62443_ID"})
    canon["Candidate_62443_ID"] = canon["Candidate_62443_ID"].fillna("").astype(str)

    return canon[[
        "Threat_ShortTitle", "Threat_Category", "Threat_Description",
        "_title_key", "_desc_key", "Candidate_62443_ID"
    ]]
