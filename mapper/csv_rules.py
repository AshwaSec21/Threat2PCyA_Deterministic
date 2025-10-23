# csv_rules.py
# Load and normalize candidates CSV (desc-only keying).

from __future__ import annotations
import pandas as pd
from typing import Union, IO
from .parsing import _desc_key_from_candidate, _title_key_from_candidate

def _read_csv_maybe(obj: Union[str, IO, pd.DataFrame]) -> pd.DataFrame:
    if isinstance(obj, pd.DataFrame):
        return obj.copy()
    return pd.read_csv(obj, dtype=str).fillna("")

def load_rules(candidates_csv: Union[str, IO, pd.DataFrame]) -> pd.DataFrame:
    df = _read_csv_maybe(candidates_csv)
    df.columns = [str(c) for c in df.columns]

    if "Threat_Description" not in df.columns:
        raise ValueError("Candidates CSV must have a 'Threat_Description' column.")

    df["_desc_key"]  = df["Threat_Description"].map(_desc_key_from_candidate)
    df["_title_key"] = df["Threat_ShortTitle"].map(_title_key_from_candidate) if "Threat_ShortTitle" in df.columns else ""
    return df
