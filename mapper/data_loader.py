# mapper/data_loader.py
import pandas as pd
import re
from pathlib import Path

def load_threats(f) -> pd.DataFrame:
    df = pd.read_csv(f, encoding='utf-8', engine='python')
    df.columns = [c.strip() for c in df.columns]
    for col in ['Id','Title','Description','Category']:
        if col not in df.columns: df[col] = ''
        df[col] = df[col].astype(str).fillna('')
    return df

def normalize_iec_id(s: str) -> str:
    s = (s or "").replace("\xa0", " ")
    s = re.sub(r"\s+", " ", s).strip().upper()
    return s  # keep RE(n) variants distinct

def _sl_to_level(s: str):
    """Extract SL level 1..4 from a string like 'SL 3', 'SL-3', '3', etc."""
    if s is None: return None
    m = re.search(r'([1-4])', str(s))
    return int(m.group(1)) if m else None

def _finalize_iec_df(df: pd.DataFrame) -> pd.DataFrame:
    # Ensure core text fields exist
    for col in ['Id','Title','Detail']:
        if col not in df.columns: df[col] = ''
        df[col] = df[col].astype(str).fillna('')

    # IEC_ID
    df['IEC_ID'] = df['Id'].apply(normalize_iec_id)

    # Find SL-C column by common aliases
    lower_map = {c.lower(): c for c in df.columns}
    slc_alias = next((lower_map[k] for k in ('sl-c','sl c','slc','sl - c') if k in lower_map), None)
    df['SL-C'] = df[slc_alias].astype(str).fillna('') if slc_alias else ''

    # Prefer rows with non-empty SL-C when duplicates per IEC_ID exist
    df['_slc_nonempty'] = df['SL-C'].astype(str).str.strip().ne('')
    df = df.sort_values(['IEC_ID', '_slc_nonempty'], ascending=[True, False])
    df = df.drop_duplicates(subset=['IEC_ID'], keep='first').drop(columns=['_slc_nonempty'])

    # Parse numeric level (1..4) from SL-C
    df['SL_LEVEL'] = df['SL-C'].apply(_sl_to_level)

    return df[['IEC_ID', 'Title', 'Detail', 'SL-C', 'SL_LEVEL']].copy()

def load_iec(f) -> pd.DataFrame:
    df = pd.read_excel(f, sheet_name=0)
    df.columns = [str(c).strip() for c in df.columns]
    return _finalize_iec_df(df)

def load_iec_bundled() -> pd.DataFrame:
    root = Path(__file__).resolve().parents[1]
    p = root / "resources" / "IEC-62443-4-2.xlsx"
    if not p.exists():
        raise FileNotFoundError(f"Bundled IEC file not found: {p}")
    df = pd.read_excel(p, sheet_name=0)
    df.columns = [str(c).strip() for c in df.columns]
    return _finalize_iec_df(df)

def load_pcya(f) -> pd.DataFrame:
    df = pd.read_excel(f)
    df.columns = [c.strip() for c in df.columns]
    for col in ['Requirement ID','Description','Assets Allocated to']:
        if col not in df.columns: df[col] = ''
        df[col] = df[col].astype(str).fillna('')
    return df

def load_crosswalk(f) -> pd.DataFrame | None:
    if f is None:
        return None
    df = pd.read_csv(f, encoding='utf-8', engine='python')
    df.columns = [c.strip() for c in df.columns]
    needed = {'Requirement ID','IEC_ID'}
    if not needed.issubset(set(df.columns)):
        return None
    return df[['Requirement ID','IEC_ID']].copy()
