"""app.py
======
Windows EVTX Forensic Log Converter & Interactive Inspector GUI.

Built with Streamlit and powered by fileconversion.py.
Features:
- Dual-Engine Support: Native evtx_dump binary + pure-Python fallback.
- Multi-Format Export: Convert EVTX to CSV, JSON, JSON Lines (JSONL), or standard Windows XML.
- Forensic Grid: Essential forensic columns (Record #, Time, Level, Event ID, Name, Provider, Channel, Computer, Action) with inline EVENT DATA drawer.
- Inline Row Expansion ("EVENT DATA" Drawer): Inspect key-values, Show raw XML, and Show raw JSON.
- Collapsible "▸ Advanced filters" Accordion: Filter by Event ID, Level, Provider, Channel, Computer, Time, and Keyword.
- 1-Click Export Toolbar: Download current filtered records as CSV, JSON, or XML.
"""

import glob
import html
import importlib
import inspect
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd
import plotly.express as px
import streamlit as st

import fileconversion

import duckdb
from log_templater import DuckDBTemplateManager, Drain3ChannelManager, get_event_family_label
from stage3_vectorizing import TemplateEmbedder, TemplateVectorIndex, construct_representative_text
from query_parser import ForensicQueryParser, QueryFilter, TimeRange
from query_executor import EventQueryExecutor

try:
    importlib.reload(fileconversion)
except Exception:
    pass

convert = getattr(fileconversion, "convert")
convert_and_load = getattr(fileconversion, "convert_and_load")
convert_from_path = getattr(fileconversion, "convert_from_path")
convert_from_upload = getattr(fileconversion, "convert_from_upload")
record_to_xml = getattr(fileconversion, "record_to_xml")
records_to_xml = getattr(fileconversion, "records_to_xml")
CSV_COLUMNS = getattr(fileconversion, "CSV_COLUMNS")


# Streamlit 1.40+ deprecation-free width parameter helper
def stretch_kw() -> Dict[str, Any]:
    """Returns width='stretch' if supported by current Streamlit, else use_container_width=True."""
    sig = inspect.signature(st.button)
    if "width" in sig.parameters:
        return {"width": "stretch"}
    return {"use_container_width": True}


def normalize_path(p: Optional[str]) -> str:
    if hasattr(fileconversion, "normalize_path"):
        return fileconversion.normalize_path(p)
    if not p:
        return ""
    return os.path.abspath(os.path.expandvars(os.path.expanduser(str(p).strip().strip("'\""))))


def find_source_files(src: str, selected_files: Optional[List[str]] = None, recursive: bool = False) -> List[str]:
    if hasattr(fileconversion, "find_source_files"):
        return fileconversion.find_source_files(src, selected_files=selected_files, recursive=recursive)
    norm = normalize_path(src)
    if os.path.isfile(norm):
        return [norm]
    if os.path.isdir(norm):
        return [os.path.join(norm, f) for f in os.listdir(norm) if f.lower().endswith(".evtx")]
    return glob.glob(norm, recursive=recursive)


# ------------------------------------------------------------------------------
# FORMATTING & EXTRACTION HELPERS
# ------------------------------------------------------------------------------

def format_time_utc(ts_str: Any) -> str:
    """Formats ISO-8601 timestamp string to standard 'M/D/YY, H:MM:SS AM/PM'."""
    if not ts_str:
        return "-"
    try:
        s = str(ts_str).rstrip("Z").replace("T", " ").strip()
        if "." in s:
            s_main, s_micro = s.split(".", 1)
            s = f"{s_main}.{s_micro[:6]}"
            dt = datetime.fromisoformat(s)
        else:
            dt = datetime.fromisoformat(s)
        hour = dt.hour % 12 or 12
        ampm = "AM" if dt.hour < 12 else "PM"
        return f"{dt.month}/{dt.day}/{dt.year % 100}, {hour}:{dt.minute:02d}:{dt.second:02d} {ampm}"
    except Exception:
        return str(ts_str)


def unpack_event_data_dict(ed_raw: Any) -> Dict[str, Any]:
    """Extracts structured key-values from raw EventData or UserData strings."""
    if not ed_raw or str(ed_raw).strip().lower() in ("", "none", "nan", "null", "{}"):
        return {}
    s = str(ed_raw).strip()
    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            clean = {}
            for idx, (k, v) in enumerate(parsed.items(), 1):
                if isinstance(v, dict) and "Value" in v:
                    clean[k] = v["Value"]
                else:
                    clean[k] = v
            return clean
        elif isinstance(parsed, list):
            return {f"Data{i+1}": x for i, x in enumerate(parsed)}
    except Exception:
        pass
    return {"Data1": s}


def compute_event_summary(row: Any) -> str:
    """Computes a concise, single-line summary string for the Forensic Grid (e.g. Data1=Category: ...)."""
    # 1. EventData parsing
    ed_raw = str(row.get("EventData", "")).strip()
    if ed_raw and ed_raw.lower() not in ("", "none", "nan", "null", "{}"):
        unpacked = unpack_event_data_dict(ed_raw)
        if unpacked:
            pairs = []
            for k, v in unpacked.items():
                val_s = str(v).strip().replace("\r", " ").replace("\n", " ")
                val_s = re.sub(r"\s+", " ", val_s)
                if val_s:
                    pairs.append(f"{k}={val_s}")
            if pairs:
                res = " ".join(pairs)
                return re.sub(r"\s+", " ", res).strip()

    # 2. Message fallback
    msg = str(row.get("Message", "")).strip()
    if msg and msg.lower() not in ("", "none", "nan", "null"):
        res = msg.replace("\r", " ").replace("\n", " ")
        return re.sub(r"\s+", " ", res).strip()

    # 3. UserData fallback
    ud_raw = str(row.get("UserData", "")).strip()
    if ud_raw and ud_raw.lower() not in ("", "none", "nan", "null", "{}"):
        unpacked_ud = unpack_event_data_dict(ud_raw)
        if unpacked_ud:
            pairs = [f"{k}={v}" for k, v in unpacked_ud.items() if str(v).strip()]
            if pairs:
                res = " ".join(pairs).replace("\r", " ").replace("\n", " ")
                return re.sub(r"\s+", " ", res).strip()
        return re.sub(r"\s+", " ", ud_raw.replace("\r", " ").replace("\n", " ")).strip()

    # 4. Task fallback
    task = str(row.get("Task", "")).strip()
    if task and task not in ("0", "", "none", "nan"):
        return f"Task: {task}"

    return "-"


def clean_event_id_scalar(val: Any) -> str:
    """Extracts clean numeric EventID if stored as a dictionary string (e.g. {'#text': 4624})."""
    s = str(val).strip()
    if "#text" in s:
        m = re.search(r"['\"]?#text['\"]?\s*:\s*['\"]?(\d+)['\"]?", s)
        if m:
            return m.group(1)
    return s


def analyze_forensic_query(
    query: str,
    df: pd.DataFrame,
    source_label: str,
) -> Tuple[str, Optional[pd.DataFrame]]:
    """Analyzes a natural language security query against an event log dataframe.

    Returns: (markdown_response, matched_dataframe_or_None)
    """
    if df.empty:
        return (
            f"⚠️ **No records found in active scope (`{source_label}`).** "
            "Please ensure you have converted `.evtx` logs in the **Converter** tab first.",
            None,
        )

    q = query.lower().strip()

    # Column mappings
    ev_col = "EventID" if "EventID" in df.columns else None
    msg_col = "Message" if "Message" in df.columns else None
    ed_col = "EventData" if "EventData" in df.columns else None
    comp_col = "Computer" if "Computer" in df.columns else None
    chan_col = "Channel" if "Channel" in df.columns else None
    time_col = "TimeCreated" if "TimeCreated" in df.columns else None
    lvl_col = "LevelName" if "LevelName" in df.columns else ("Level" if "Level" in df.columns else None)

    target_event_ids: List[str] = []
    mitre_tactics: List[str] = []
    technique_name = ""
    threat_level = "Informational"

    # Brute Force / Failed Logon
    if any(term in q for term in ["failed logon", "fail", "bad password", "brute force", "4625", "auth fail", "logon error"]):
        target_event_ids.extend(["4625", "4740", "4776"])
        mitre_tactics.append("Credential Access (TA0006) - T1110: Brute Force")
        technique_name = "Authentication Failure & Password Spray Analysis"
        threat_level = "High"

    # Privilege Escalation / Sensitive Privileges
    elif any(term in q for term in ["privilege", "escalation", "admin", "4672", "special privilege", "token", "seimpersonate"]):
        target_event_ids.extend(["4672", "4673", "4674"])
        mitre_tactics.append("Privilege Escalation (TA0004) - T1078.002: Domain/Local Admin Privileges")
        technique_name = "Special Privilege Assignment & Token Analysis"
        threat_level = "Medium"

    # Successful Logons
    elif any(term in q for term in ["successful logon", "valid logon", "logon type", "4624"]):
        target_event_ids.append("4624")
        mitre_tactics.append("Initial Access / Lateral Movement (TA0008) - T1078: Valid Accounts")
        technique_name = "Successful User Authentication Trace"
        threat_level = "Informational"

    # Process Creation / Execution
    elif any(term in q for term in ["process", "powershell", "cmd", "execution", "command", "4688", "4104"]):
        target_event_ids.extend(["4688", "4104", "4103", "1"])
        mitre_tactics.append("Execution (TA0002) - T1059: Command and Scripting Interpreter")
        technique_name = "Process Creation & Script Execution Audit"
        threat_level = "Medium"

    # Service Installation / Persistence
    elif any(term in q for term in ["service", "persistence", "7045", "4697", "installed"]):
        target_event_ids.extend(["7045", "4697"])
        mitre_tactics.append("Persistence (TA0003) - T1543.003: Windows Service Creation")
        technique_name = "New Service Creation / Persistence Artifacts"
        threat_level = "High"

    # Audit Log Cleared / Anti-Forensics
    elif any(term in q for term in ["clear", "cleared", "tamper", "audit log", "1102", "104", "evasion"]):
        target_event_ids.extend(["1102", "104"])
        mitre_tactics.append("Defense Evasion (TA0005) - T1070.001: Clear Windows Event Logs")
        technique_name = "Event Log Deletion & Defense Evasion"
        threat_level = "Critical"

    # Account Management
    elif any(term in q for term in ["user create", "account create", "password reset", "lockout", "4720", "4724", "4740", "group"]):
        target_event_ids.extend(["4720", "4722", "4724", "4728", "4738", "4740"])
        mitre_tactics.append("Persistence / Impact - T1136: Create Account")
        technique_name = "Account Management & Modification Tracking"
        threat_level = "Medium"

    # Explicit numeric Event ID detection from query
    explicit_ids = re.findall(r"\b\d{4}\b", q)
    if explicit_ids:
        target_event_ids.extend(explicit_ids)

    # Filter dataframe
    matched_df = pd.DataFrame()
    if target_event_ids and ev_col:
        matched_df = df[df[ev_col].isin(target_event_ids)]

    # If no event ID matches or user asked freeform query, search text across columns
    if matched_df.empty:
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", q)
        hex_codes = re.findall(r"0x[0-9a-fA-F]+", q)
        search_terms = ips + hex_codes

        if not search_terms:
            stop_words = {"show", "find", "were", "what", "when", "where", "from", "with", "have", "been", "that", "this", "events", "logs"}
            search_terms = [w for w in re.findall(r"\b[a-zA-Z0-9_\-\.]{4,}\b", q) if w.lower() not in stop_words]

        if search_terms:
            mask = pd.Series(False, index=df.index)
            for term in search_terms[:5]:
                for c in [msg_col, ed_col, comp_col, chan_col]:
                    if c and c in df.columns:
                        mask = mask | df[c].astype(str).str.contains(term, case=False, na=False, regex=False)
            matched_df = df[mask]
        else:
            if "error" in q and lvl_col:
                matched_df = df[df[lvl_col].astype(str).str.contains("Error|Critical", case=False, na=False)]
            elif "warning" in q and lvl_col:
                matched_df = df[df[lvl_col].astype(str).str.contains("Warning", case=False, na=False)]
            else:
                matched_df = df.head(50)

    match_count = len(matched_df)
    total_records = len(df)

    if match_count == 0:
        return (
            f"### 🔍 Investigation Query: *\"{query}\"*\n\n"
            f"**Scope Analyzed:** `{source_label}` ({total_records:,} total records)\n\n"
            f"❌ **No matching events found** for this query in the selected log scope.",
            None,
        )

    # Summary metrics
    time_min = matched_df[time_col].min() if time_col and not matched_df[time_col].empty else "N/A"
    time_max = matched_df[time_col].max() if time_col and not matched_df[time_col].empty else "N/A"
    hosts = [str(h) for h in matched_df[comp_col].dropna().unique() if str(h).strip()] if comp_col else []
    host_summary = ", ".join(hosts[:3]) + (f" (+{len(hosts)-3} more)" if len(hosts) > 3 else "") if hosts else "N/A"

    # Extract user mentions
    user_counts: Dict[str, int] = {}
    if ed_col:
        for val in matched_df[ed_col].dropna():
            if "UserName" in val or "User" in val:
                m_user = re.search(r'["\'](?:TargetUserName|SubjectUserName|UserName)["\']\s*:\s*["\']([^"\']+)["\']', str(val))
                if m_user:
                    u = m_user.group(1)
                    if u not in ("-", "SYSTEM"):
                        user_counts[u] = user_counts.get(u, 0) + 1

    top_users_str = ", ".join(f"`{u}` ({cnt})" for u, cnt in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:4]) if user_counts else "N/A"

    response = (
        f"### 🛡️ Forensic Investigation Analysis\n\n"
        f"**Query:** *\"{query}\"*\n\n"
        f"**Target Scope:** `{source_label}` | **Threat Level:** `{threat_level}`\n\n"
        f"---\n\n"
        f"#### 📊 Key Findings & Evidence Metrics\n"
        f"- **Matched Security Events:** **{match_count:,}** record(s) out of {total_records:,} ({(match_count/total_records)*100:.2f}% of log)\n"
        f"- **Timeline Range:** `{time_min}` $\\rightarrow$ `{time_max}`\n"
        f"- **Affected System(s):** `{host_summary}`\n"
        f"- **Primary Account(s) Identified:** {top_users_str}\n\n"
    )

    if mitre_tactics:
        response += (
            f"#### 🎯 MITRE ATT&CK Classification\n"
            f"- **Tactics & Techniques:** {', '.join(mitre_tactics)}\n"
            f"- **Analytical Pattern:** `{technique_name}`\n\n"
        )

    response += (
        f"#### 💡 Tactical Next Steps\n"
        f"1. **Lateral Movement Audit:** Review authentication logs on affected systems around `{time_min}`.\n"
        f"2. **Process Corroboration:** Correlate with Sysmon/Event ID 4688 to verify parent-child execution.\n"
        f"3. **Artifact Review:** Detailed matching records are provided below in the Evidence Artifacts inspector."
    )

    return response, matched_df


# ------------------------------------------------------------------------------
# STREAMLIT CONFIGURATION & STYLING (HIGH CONTRAST & PERFECT ALIGNMENT)
# ------------------------------------------------------------------------------

st.set_page_config(
    page_title="Windows EVTX Forensic Log Converter & Inspector",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    /* Metric Card Styling */
    div[data-testid="metric-container"] {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        padding: 12px 18px;
        border-radius: 10px;
        box-shadow: 0 1px 4px rgba(0, 0, 0, 0.04);
        transition: all 0.2s ease-in-out;
    }
    div[data-testid="metric-container"]:hover {
        border-color: #1E88E5;
        box-shadow: 0 4px 12px rgba(30, 136, 229, 0.12);
    }
    div[data-testid="metric-container"] label {
        color: #64748B !important;
        font-weight: 600 !important;
        font-size: 0.80rem !important;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #0F172A !important;
        font-weight: 800 !important;
    }

    /* Primary Buttons -> Blue */
    button[kind="primary"],
    div[data-testid="stButton"] > button[kind="primary"],
    .stButton > button[type="primary"],
    button[data-testid="baseButton-primary"] {
        background-color: #1E88E5 !important;
        border-color: #1976D2 !important;
        color: #FFFFFF !important;
        box-shadow: 0 2px 8px rgba(30, 136, 229, 0.25) !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
    }
    button[kind="primary"]:hover,
    div[data-testid="stButton"] > button[kind="primary"]:hover,
    .stButton > button[type="primary"]:hover {
        background-color: #1976D2 !important;
        border-color: #1565C0 !important;
        color: #FFFFFF !important;
        box-shadow: 0 4px 12px rgba(30, 136, 229, 0.35) !important;
    }

    /* Secondary / Action Buttons */
    .stButton > button {
        border-radius: 6px !important;
        font-size: 0.85rem !important;
        border-color: #CBD5E1 !important;
        color: #1E293B !important;
        background-color: #FFFFFF !important;
        transition: all 0.15s ease-in-out;
    }
    .stButton > button:hover {
        border-color: #1E88E5 !important;
        color: #1E88E5 !important;
        background-color: #F8FAFC !important;
    }

    /* Download Buttons */
    .stDownloadButton > button {
        border-color: #1E88E5 !important;
        color: #1E88E5 !important;
        background-color: #FFFFFF !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
    }
    .stDownloadButton > button:hover {
        background-color: rgba(30, 136, 229, 0.08) !important;
        border-color: #1565C0 !important;
        color: #1565C0 !important;
    }

    /* Inputs focus */
    input:focus, textarea:focus, div[data-baseweb="input"]:focus-within {
        border-color: #1E88E5 !important;
        box-shadow: 0 0 0 1px #1E88E5 !important;
    }

    /* ------------------------------------------------------------- */
    /* FORENSIC GRID ROW ALIGNMENT & FONT CONTRAST                   */
    /* ------------------------------------------------------------- */

    /* Ensure every horizontal block is vertically centered */
    div[data-testid="stHorizontalBlock"] {
        align-items: center !important;
        border-bottom: 1px solid #E2E8F0 !important;
        padding-top: 1px !important;
        padding-bottom: 1px !important;
    }

    /* Ensure each column has no top margin displacement */
    div[data-testid="stHorizontalBlock"] > div[data-testid="column"] {
        display: flex !important;
        align-items: center !important;
        justify-content: flex-start !important;
        min-height: 32px !important;
        padding: 0 4px !important;
    }

    /* Remove paragraph margins which caused vertical displacement */
    div[data-testid="stHorizontalBlock"] div[data-testid="stMarkdownContainer"] p {
        margin: 0 !important;
        padding: 0 !important;
        line-height: 28px !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
    }

    /* Action button column: exact centering and compact 26px height */
    div[data-testid="stHorizontalBlock"] > div[data-testid="column"]:last-child {
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
    }
    div[data-testid="stHorizontalBlock"] > div[data-testid="column"]:last-child div[data-testid="stButton"] {
        width: 100% !important;
        margin: 0 !important;
    }
    div[data-testid="stHorizontalBlock"] > div[data-testid="column"]:last-child div[data-testid="stButton"] button {
        height: 26px !important;
        min-height: 26px !important;
        max-height: 26px !important;
        line-height: 24px !important;
        padding: 0 6px !important;
        font-size: 0.76rem !important;
        font-weight: 600 !important;
        margin: 0 !important;
        border-radius: 4px !important;
        width: 100% !important;
    }

    /* HIGH-CONTRAST CELL TYPOGRAPHY ON LIGHT BACKGROUND */
    .cell-mono {
        font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace !important;
        font-size: 0.82rem !important;
        font-weight: 700 !important;
        color: #0F172A !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
        display: block !important;
    }
    .cell-time {
        font-family: 'JetBrains Mono', Consolas, monospace !important;
        font-size: 0.80rem !important;
        color: #1E293B !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
        display: block !important;
    }
    .cell-text {
        font-size: 0.82rem !important;
        color: #0F172A !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
        display: block !important;
    }

    /* SEVERITY PILL BADGES */
    .badge-error {
        background-color: #FEE2E2 !important;
        color: #DC2626 !important;
        border: 1px solid #FCA5A5 !important;
        border-radius: 10px !important;
        padding: 1px 7px !important;
        font-size: 0.76rem !important;
        font-weight: 700 !important;
        display: inline-block !important;
        line-height: 1.4 !important;
    }
    .badge-critical {
        background-color: #FEE2E2 !important;
        color: #991B1B !important;
        border: 1px solid #F87171 !important;
        border-radius: 10px !important;
        padding: 1px 7px !important;
        font-weight: 800 !important;
        font-size: 0.76rem !important;
        display: inline-block !important;
        line-height: 1.4 !important;
    }
    .badge-warning {
        background-color: #FEF3C7 !important;
        color: #B45309 !important;
        border: 1px solid #FCD34D !important;
        border-radius: 10px !important;
        padding: 1px 7px !important;
        font-size: 0.76rem !important;
        font-weight: 700 !important;
        display: inline-block !important;
        line-height: 1.4 !important;
    }
    .badge-info {
        background-color: #E0F2FE !important;
        color: #0369A1 !important;
        border: 1px solid #BAE6FD !important;
        border-radius: 10px !important;
        padding: 1px 7px !important;
        font-size: 0.76rem !important;
        font-weight: 600 !important;
        display: inline-block !important;
        line-height: 1.4 !important;
    }
    .badge-verbose {
        background-color: #F1F5F9 !important;
        color: #475569 !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 10px !important;
        padding: 1px 7px !important;
        font-size: 0.76rem !important;
        display: inline-block !important;
        line-height: 1.4 !important;
    }

    /* INLINE ROW EXPANSION: EVENT DATA DRAWER */
    .forensic-drawer {
        background-color: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-left: 4px solid #1E88E5;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 6px 0 14px 0;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.06);
    }
    .forensic-drawer-title {
        font-size: 0.78rem;
        font-weight: 800;
        letter-spacing: 0.08em;
        color: #0F172A;
        text-transform: uppercase;
        margin-bottom: 8px;
    }
    .forensic-payload-box {
        background-color: #0F172A !important;
        border: 1px solid #1E293B !important;
        border-radius: 6px !important;
        padding: 14px 18px !important;
        font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace !important;
        font-size: 0.80rem !important;
        color: #F8FAFC !important;
        line-height: 1.6 !important;
        margin-bottom: 12px !important;
        word-break: break-word !important;
        max-height: 280px !important;
        overflow-y: auto !important;
        white-space: pre-wrap !important;
    }
    .forensic-payload-key {
        color: #38BDF8 !important;
        font-weight: 700 !important;
        margin-right: 10px !important;
    }
    .forensic-payload-val {
        color: #F8FAFC !important;
    }

    /* Filter indicator pill */
    .filter-indicator-pill {
        background-color: rgba(30, 136, 229, 0.12);
        border: 1px solid rgba(30, 136, 229, 0.35);
        border-radius: 16px;
        padding: 3px 12px;
        font-size: 0.82rem;
        font-weight: 700;
        color: #1E88E5;
        display: inline-block;
    }

    /* Chatbot Message Styling */
    div[data-testid="stChatMessage"] {
        border-radius: 12px !important;
        padding: 14px 18px !important;
        margin-bottom: 12px !important;
        border: 1px solid rgba(30, 136, 229, 0.12) !important;
        transition: all 0.2s ease-in-out !important;
    }
    div[data-testid="stChatMessage"]:hover {
        border-color: rgba(30, 136, 229, 0.3) !important;
    }
    div[data-testid="stChatMessage"][data-testid*="user"] {
        background-color: rgba(30, 136, 229, 0.05) !important;
    }
    div[data-testid="stChatMessage"][data-testid*="assistant"] {
        background-color: #FFFFFF !important;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.03) !important;
    }
    div[data-testid="stChatInput"] {
        border-radius: 10px !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# ------------------------------------------------------------------------------

if "active_tab" not in st.session_state:
    st.session_state["active_tab"] = "converter"
if "last_converted_file" not in st.session_state:
    st.session_state["last_converted_file"] = None
if "viewer_folder" not in st.session_state:
    st.session_state["viewer_folder"] = "Converted files"
if "expanded_record_id" not in st.session_state:
    st.session_state["expanded_record_id"] = None
if "raw_view_mode" not in st.session_state:
    st.session_state["raw_view_mode"] = None
if "grid_page" not in st.session_state:
    st.session_state["grid_page"] = 1
if "grid_page_size" not in st.session_state:
    st.session_state["grid_page_size"] = 25
if "grid_sort_asc" not in st.session_state:
    st.session_state["grid_sort_asc"] = True
if "chatbot_messages" not in st.session_state:
    st.session_state["chatbot_messages"] = [
        {
            "role": "assistant",
            "content": "👋 **Forensic AI Assistant online.** Ask questions to correlate security events, hunt threats, or inspect specific event IDs across your converted logs.",
            "evidence": None,
        }
    ]


@st.cache_data(show_spinner=False)
def load_log_data(filepath: str) -> pd.DataFrame:
    """Loads and caches a CSV or JSON file as a pandas DataFrame."""
    if not os.path.isfile(filepath):
        return pd.DataFrame()
    try:
        lower_path = filepath.lower()
        if lower_path.endswith(".json"):
            df = pd.read_json(filepath, dtype=str)
        elif lower_path.endswith(".jsonl"):
            df = pd.read_json(filepath, lines=True, dtype=str)
        else:
            df = pd.read_csv(filepath, dtype=str, keep_default_na=False)

        df.fillna("", inplace=True)
        df.replace({"null": "", "None": "", "NULL": "", "NaN": "", "nan": ""}, inplace=True)
        if "EventID" in df.columns:
            df["EventID"] = df["EventID"].apply(clean_event_id_scalar)
        return df
    except Exception as e:
        st.error(f"Error loading log file: {e}")
        return pd.DataFrame()


# ------------------------------------------------------------------------------
# STAGE 3 FORENSIC CACHED ENGINES & DUCKDB SYNC
# ------------------------------------------------------------------------------

@st.cache_resource
def get_duckdb_conn() -> duckdb.DuckDBPyConnection:
    """Provides a shared, persistent DuckDB connection for canonical forensic storage."""
    conn = duckdb.connect("forensic_logs.duckdb")
    return conn


@st.cache_resource
def get_drain3_mgr() -> DuckDBTemplateManager:
    """Provides the multi-channel Drain3 clustering and template manager."""
    return DuckDBTemplateManager(state_dir=".drain3_state")


@st.cache_resource
def get_embedder() -> TemplateEmbedder:
    """Loads and caches the technical template embedding model (BAAI/bge-small-en-v1.5)."""
    return TemplateEmbedder(model_name="BAAI/bge-small-en-v1.5")


@st.cache_resource
def get_vector_index(_embedder: TemplateEmbedder) -> TemplateVectorIndex:
    """Initializes and caches the Qdrant vector index stored in ./qdrant_storage."""
    return TemplateVectorIndex(embedder=_embedder, storage_path="./qdrant_storage")


@st.cache_resource
def get_query_parser() -> ForensicQueryParser:
    """Provides the NLP forensic query parser and intent router."""
    return ForensicQueryParser()


@st.cache_resource
def get_query_executor() -> EventQueryExecutor:
    """Provides the unified DuckDB SQL and JSON query executor."""
    return EventQueryExecutor()


def sync_dataframe_to_duckdb(
    conn: duckdb.DuckDBPyConnection,
    df: pd.DataFrame,
    scope_key: str,
    force_resync: bool = False,
) -> Dict[str, Any]:
    """Syncs DataFrame into DuckDB canonical_logs, clusters with Drain3, and indexes templates in Qdrant."""
    if df.empty:
        return {"records": 0, "templates": 0, "vectors": 0, "drain_stats": {}, "vector_stats": {}}

    tables = [r[0] for r in conn.execute("SHOW TABLES").fetchall()]
    table_exists = "canonical_logs" in tables

    needs_full_reload = not table_exists or force_resync
    if table_exists and not needs_full_reload:
        current_count = conn.execute("SELECT COUNT(*) FROM canonical_logs").fetchone()[0]
        if current_count != len(df):
            needs_full_reload = True

    if needs_full_reload:
        conn.execute("DROP TABLE IF EXISTS template_instances")
        conn.execute("DROP TABLE IF EXISTS log_templates")
        conn.execute("DROP TABLE IF EXISTS canonical_logs")
        conn.register("df_temp_ingest", df)
        conn.execute("CREATE TABLE canonical_logs AS SELECT * FROM df_temp_ingest")
        conn.unregister("df_temp_ingest")

    # Run Drain3 clustering
    mgr = get_drain3_mgr()
    drain_stats = mgr.process_canonical_records(conn, canonical_table="canonical_logs")

    # Run Qdrant Vector Indexing
    embedder = get_embedder()
    v_idx = get_vector_index(embedder)
    v_stats = v_idx.index_from_duckdb(conn, templates_table="log_templates")

    rec_count = conn.execute("SELECT COUNT(*) FROM canonical_logs").fetchone()[0]
    tpl_count = conn.execute("SELECT COUNT(*) FROM log_templates").fetchone()[0]
    v_count = v_idx.client.count(v_idx.collection_name).count

    return {
        "records": rec_count,
        "templates": tpl_count,
        "vectors": v_count,
        "drain_stats": drain_stats,
        "vector_stats": v_stats,
    }


# ------------------------------------------------------------------------------
# SIDEBAR: NAVIGATION & CONTROLS
# ------------------------------------------------------------------------------

st.sidebar.title("Windows Event Logs")
st.sidebar.subheader("Navigation")

tab_keys = ["converter", "viewer", "assistant"]
tab_options = [
    "🔄 Convert EVTX (Multi-Format)",
    "📊 Forensic Grid & Inspector",
    "🤖 Forensic Assistant",
]
key_to_idx = {k: i for i, k in enumerate(tab_keys)}

curr_key = st.session_state.get("active_tab", "converter")
if curr_key in ("chatbot", "templates"):
    curr_key = "assistant"
    st.session_state["active_tab"] = "assistant"
curr_idx = key_to_idx.get(curr_key, 0)

page_selection = st.sidebar.radio(
    "Choose Mode:",
    options=tab_options,
    index=curr_idx,
)
sel_idx = tab_options.index(page_selection)
st.session_state["active_tab"] = tab_keys[sel_idx]

st.sidebar.markdown("---")
st.sidebar.caption("⚡ **Engine:** `evtx_dump` + `python-evtx` fallback")
st.sidebar.caption("📁 **Supported Formats:** CSV, JSON, JSONL, XML")


# ==============================================================================
# VIEW 1: CONVERTER (MULTI-FORMAT EXPORT)
# ==============================================================================

if st.session_state["active_tab"] == "converter":
    st.title("🔄 Windows EVTX Multi-Format Converter")
    st.markdown(
        "Convert Windows `.evtx` event logs to **CSV**, **JSON**, **JSON Lines (JSONL)**, or **XML** "
        "with complete forensic fidelity (all 23 attributes preserved)."
    )

    col_mode, col_fmt = st.columns([2, 1])
    with col_mode:
        convert_mode = st.radio(
            "Select Conversion Method:",
            options=["📂 Drag & Drop File Upload", "🖥️ File Path / Folder / Wildcard"],
            horizontal=True,
        )
    with col_fmt:
        export_fmt_label = st.selectbox(
            "Target Export Format:",
            options=["CSV (.csv)", "JSON (.json)", "JSON Lines (.jsonl)", "XML (.xml)"],
            index=0,
            help="Choose the file format to generate from the EVTX event logs.",
        )
        fmt_map = {
            "CSV (.csv)": ("csv", "text/csv", ".csv"),
            "JSON (.json)": ("json", "application/json", ".json"),
            "JSON Lines (.jsonl)": ("jsonl", "application/x-ndjson", ".jsonl"),
            "XML (.xml)": ("xml", "application/xml", ".xml"),
        }
        output_format, mime_type, ext_suffix = fmt_map[export_fmt_label]

    # --------------------------------------------------------------------------
    # OPTION A: BROWSER FILE UPLOAD
    # --------------------------------------------------------------------------
    if convert_mode == "📂 Drag & Drop File Upload":
        st.subheader("Upload .evtx File(s)")
        uploaded_files = st.file_uploader(
            "Upload one or more .evtx files directly from your browser:",
            type=["evtx"],
            accept_multiple_files=True,
            help="Select one or multiple .evtx files to convert.",
        )

        default_dest = st.session_state.get("viewer_folder") or "Converted files"

        if uploaded_files:
            total_upload_mb = sum(getattr(f, "size", 0) for f in uploaded_files) / (1024 * 1024)
            st.info(
                f"📋 Ready to convert **{len(uploaded_files)}** file(s) "
                f"({total_upload_mb:.2f} MB total) to **{output_format.upper()}**. "
                f"Output stored in: `{default_dest}/`",
                icon="ℹ️",
            )
            with st.expander(f"Inspect Uploaded Files ({len(uploaded_files)} files)", expanded=False):
                file_summary = []
                for uf in uploaded_files:
                    f_size_kb = getattr(uf, "size", 0) / 1024
                    base_target = os.path.splitext(uf.name)[0] + ext_suffix
                    file_summary.append({
                        "Uploaded File": uf.name,
                        "Size": f"{f_size_kb:.1f} KB" if f_size_kb < 1024 else f"{f_size_kb/1024:.2f} MB",
                        "Target File": base_target,
                        "Format": output_format.upper(),
                    })
                st.dataframe(pd.DataFrame(file_summary), **stretch_kw())

            with st.expander("⚙️ Destination Settings (Optional)", expanded=False):
                dest_folder_upload = st.text_input(
                    "Destination folder for converted files:",
                    value=default_dest,
                    key="custom_upload_dest",
                ).strip() or default_dest
        else:
            dest_folder_upload = default_dest

        col_btn, _ = st.columns([1, 3])
        with col_btn:
            start_upload_conv = st.button("🚀 Convert Uploaded Files", type="primary", **stretch_kw())

        if start_upload_conv:
            if not uploaded_files:
                st.warning("Please select at least one `.evtx` file to convert.")
            else:
                st.session_state["viewer_folder"] = dest_folder_upload
                st.cache_data.clear()
                progress_bar = st.progress(0.0)
                status_text = st.empty()

                results = []
                total = len(uploaded_files)
                start_time = time.time()

                for idx, up_file in enumerate(uploaded_files, 1):
                    status_text.markdown(f"Converting **{up_file.name}** ({idx}/{total}) to {output_format.upper()}...")
                    res = convert_from_upload(up_file, output_dir=dest_folder_upload, output_format=output_format)
                    results.append(res)
                    progress_bar.progress(idx / total)

                elapsed = time.time() - start_time
                status_text.empty()
                progress_bar.empty()

                successful = [r for r in results if r["success"]]
                total_records = sum(r["record_count"] for r in successful)

                st.success(
                    f"🎉 Successfully converted {len(successful)}/{total} file(s) "
                    f"({total_records:,} total records) to {output_format.upper()} in {elapsed:.2f}s!"
                )

                summary_data = [
                    {
                        "File": r["input_file"],
                        "Status": "✅ Success" if r["success"] else "❌ Failed",
                        "Records": f"{r['record_count']:,}",
                        "Output File": r["output_file"],
                        "Format": r.get("output_format", output_format).upper(),
                        "Error": r.get("error") or "",
                    }
                    for r in results
                ]
                st.dataframe(pd.DataFrame(summary_data), **stretch_kw())

                if successful:
                    target_file = successful[0]["output_file"]
                    st.session_state["last_converted_file"] = target_file
                    st.session_state["active_view_file"] = os.path.basename(target_file)
                    st.cache_data.clear()

                    col_view, col_dl = st.columns([1, 1])
                    with col_view:
                        if st.button(f"📊 Open {os.path.basename(target_file)} in Inspector", type="primary", **stretch_kw()):
                            st.session_state["active_tab"] = "viewer"
                            st.session_state["viewer_selected_file"] = target_file
                            st.rerun()
                    with col_dl:
                        try:
                            with open(target_file, "rb") as f_dl:
                                st.download_button(
                                    label=f"📥 Download {os.path.basename(target_file)}",
                                    data=f_dl.read(),
                                    file_name=os.path.basename(target_file),
                                    mime=mime_type,
                                    **stretch_kw(),
                                )
                        except Exception:
                            pass

    # --------------------------------------------------------------------------
    # OPTION B: SYSTEM PATH / FOLDER / WILDCARD
    # --------------------------------------------------------------------------
    else:
        st.subheader("Specify Source & Destination Paths")
        st.caption("Enter any file path, directory path, or wildcard pattern on your local filesystem.")

        col_src, col_dst = st.columns(2)
        with col_src:
            source_input = st.text_input(
                "Source Path (file, directory, or wildcard pattern):",
                value="Original Data/evtx" if os.path.isdir("Original Data/evtx") else "",
                placeholder="e.g. sample.evtx, Original Data/evtx, or logs/*.evtx",
            )
            recursive_check = st.checkbox(
                "Recursively scan subdirectories",
                value=False,
            )

        with col_dst:
            dest_input = st.text_input(
                "Destination Location (folder or explicit output file):",
                value=st.session_state["viewer_folder"],
                placeholder=f"e.g. Converted files or output{ext_suffix}",
            )

        col_scan, col_conv = st.columns([1, 2])
        with col_scan:
            scan_clicked = st.button("🔍 Scan & Preview Files", **stretch_kw())
        with col_conv:
            convert_clicked = st.button(f"🚀 Convert to {output_format.upper()}", type="primary", **stretch_kw())

        if scan_clicked and source_input:
            detected_files = find_source_files(source_input, recursive=recursive_check)
            if detected_files:
                st.info(f"Found **{len(detected_files)}** `.evtx` file(s) matching `{source_input}`:")
                st.code("\n".join(detected_files[:20]) + ("\n...and more" if len(detected_files) > 20 else ""))
            else:
                st.warning(f"No `.evtx` files found matching path: `{source_input}`")

        if convert_clicked:
            if not source_input:
                st.warning("Please provide a valid source path or pattern.")
            else:
                st.session_state["viewer_folder"] = dest_input
                progress_bar = st.progress(0.0)
                status_text = st.empty()

                start_time = time.time()
                try:
                    def update_progress(current, total, filename, count):
                        pct = current / total if total > 0 else 1.0
                        progress_bar.progress(pct)
                        status_text.markdown(f"Converting: **{filename}** ({current}/{total}) -> **{count:,}** records")

                    results = convert_from_path(
                        source_path=source_input,
                        output_dir=dest_input,
                        recursive=recursive_check,
                        output_format=output_format,
                        progress_callback=update_progress,
                    )

                    elapsed = time.time() - start_time
                    status_text.empty()
                    progress_bar.empty()

                    if not results:
                        st.warning(f"No `.evtx` files were found or converted for: `{source_input}`")
                    else:
                        successful = [r for r in results if r["success"]]
                        total_records = sum(r["record_count"] for r in successful)

                        st.success(
                            f"🎉 Converted {len(successful)}/{len(results)} file(s) "
                            f"({total_records:,} records total) to {output_format.upper()} in {elapsed:.2f}s!"
                        )

                        summary_data = [
                            {
                                "File": os.path.basename(r["input_file"]),
                                "Status": "✅ Success" if r["success"] else "❌ Failed",
                                "Records": f"{r['record_count']:,}",
                                "Output File": r["output_file"],
                                "Format": r.get("output_format", output_format).upper(),
                                "Error": r.get("error") or "",
                            }
                            for r in results
                        ]
                        st.dataframe(pd.DataFrame(summary_data), **stretch_kw())

                        if successful:
                            if st.button("📊 Open Converted Logs in Inspector", **stretch_kw()):
                                st.session_state["active_tab"] = "viewer"
                                st.session_state["viewer_selected_file"] = successful[0]["output_file"]
                                st.rerun()

                except Exception as exc:
                    status_text.empty()
                    progress_bar.empty()
                    st.error(f"Conversion failed: {exc}")


# ==============================================================================
# VIEW 2: LOG VIEWER & FORENSIC GRID INSPECTOR
# ==============================================================================

elif st.session_state["active_tab"] == "viewer":
    st.title("📊 Forensic Log Inspector & Grid")
    st.markdown("Interactive Windows Event Log viewer featuring the exact forensic grid, advanced filters, and inline event drawers.")

    log_dir = st.session_state.get("viewer_folder", "Converted files")
    norm_log_dir = normalize_path(log_dir)

    available_files = []
    if os.path.isdir(norm_log_dir):
        for ext in ("*.csv", "*.json", "*.jsonl"):
            available_files.extend(glob.glob(os.path.join(norm_log_dir, ext)))
        available_files = sorted(list(set(available_files)))

    # Handle file requested from converter tab
    requested_file = st.session_state.pop("viewer_selected_file", None)
    if requested_file and os.path.isfile(requested_file):
        norm_req = normalize_path(requested_file)
        if norm_req not in [normalize_path(p) for p in available_files]:
            available_files.insert(0, norm_req)

    if available_files:
        file_map = {os.path.basename(p): p for p in available_files}
        options = list(file_map.keys())

        default_index = 0
        if requested_file:
            req_base = os.path.basename(requested_file)
            if req_base in options:
                default_index = options.index(req_base)
                st.session_state["active_view_file"] = req_base
        elif "active_view_file" in st.session_state and st.session_state["active_view_file"] in options:
            default_index = options.index(st.session_state["active_view_file"])

        chosen_filename = st.selectbox(
            "Select Converted Log File to Inspect:",
            options=options,
            index=default_index,
            key="active_view_file",
            format_func=lambda fn: f"{fn} ({os.path.getsize(file_map[fn]) / 1024:.1f} KB)",
        )
        selected_log_path = file_map[chosen_filename]
    else:
        st.warning(f"No converted log files found inside `{log_dir}`. Convert an `.evtx` file in the Converter tab first.")
        selected_log_path = None

    if selected_log_path and os.path.isfile(selected_log_path):
        df = load_log_data(selected_log_path)

        if df.empty:
            st.info(f"The selected log `{os.path.basename(selected_log_path)}` contains 0 records.")
        else:
            # Precompute summary column for high-speed searching and grid display
            if "_summary_cached" not in df.columns:
                df["_summary_cached"] = df.apply(compute_event_summary, axis=1)

            # ------------------------------------------------------------------
            # 1. COLLAPSIBLE "▸ ADVANCED FILTERS" ACCORDION
            # ------------------------------------------------------------------
            with st.expander("▸ Advanced filters", expanded=False):
                st.caption("Filter records by Event ID, Level, Provider, Channel, Computer, or Keyword.")

                flt_r1c1, flt_r1c2, flt_r1c3 = st.columns([2, 1, 1])
                with flt_r1c1:
                    filter_keyword = st.text_input(
                        "Keyword Search:",
                        placeholder="Search across EventData, Message, Provider, Computer, UserID...",
                        key="flt_keyword",
                    )
                with flt_r1c2:
                    all_eids = sorted(df["EventID"].unique().tolist()) if "EventID" in df.columns else []
                    sel_eids = st.multiselect("Event ID:", options=all_eids, key="flt_eids")
                with flt_r1c3:
                    all_levels = sorted([lvl for lvl in df["LevelName"].unique().tolist() if lvl]) if "LevelName" in df.columns else []
                    sel_levels = st.multiselect("Severity Level:", options=all_levels, key="flt_levels")

                flt_r2c1, flt_r2c2, flt_r2c3 = st.columns(3)
                with flt_r2c1:
                    all_providers = sorted([pr for pr in df["Provider"].unique().tolist() if pr]) if "Provider" in df.columns else []
                    sel_providers = st.multiselect("Provider:", options=all_providers, key="flt_providers")
                with flt_r2c2:
                    all_channels = sorted([ch for ch in df["Channel"].unique().tolist() if ch]) if "Channel" in df.columns else []
                    sel_channels = st.multiselect("Channel:", options=all_channels, key="flt_channels")
                with flt_r2c3:
                    all_computers = sorted([comp for comp in df["Computer"].unique().tolist() if comp]) if "Computer" in df.columns else []
                    sel_computers = st.multiselect("Computer:", options=all_computers, key="flt_computers")

                col_reset, _ = st.columns([1, 4])
                with col_reset:
                    if st.button("↺ Reset All Filters", **stretch_kw()):
                        st.session_state["flt_keyword"] = ""
                        st.session_state["flt_eids"] = []
                        st.session_state["flt_levels"] = []
                        st.session_state["flt_providers"] = []
                        st.session_state["flt_channels"] = []
                        st.session_state["flt_computers"] = []
                        st.session_state["grid_page"] = 1
                        st.rerun()

            # Apply Filters
            filtered_df = df.copy()

            if filter_keyword:
                kw = filter_keyword.strip().lower()
                mask = pd.Series(False, index=filtered_df.index)
                search_columns = [
                    "_summary_cached",
                    "EventData",
                    "UserData",
                    "Message",
                    "Provider",
                    "Channel",
                    "Computer",
                    "UserID",
                    "EventID",
                    "Task",
                    "RecordID",
                ]
                for col in search_columns:
                    if col in filtered_df.columns:
                        mask = mask | filtered_df[col].astype(str).str.lower().str.contains(kw, regex=False, na=False)
                filtered_df = filtered_df[mask]

            if sel_eids:
                filtered_df = filtered_df[filtered_df["EventID"].isin(sel_eids)]

            if sel_levels:
                filtered_df = filtered_df[filtered_df["LevelName"].isin(sel_levels)]

            if sel_providers:
                filtered_df = filtered_df[filtered_df["Provider"].isin(sel_providers)]

            if sel_channels:
                filtered_df = filtered_df[filtered_df["Channel"].isin(sel_channels)]

            if sel_computers:
                filtered_df = filtered_df[filtered_df["Computer"].isin(sel_computers)]

            # ------------------------------------------------------------------
            # 2. TOP ACTION BAR (1-CLICK EXPORTS & LIVE COUNTER)
            # ------------------------------------------------------------------
            st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
            act_col_left, act_col_csv, act_col_json, act_col_xml = st.columns([3, 1, 1, 1])

            with act_col_left:
                base_name = os.path.basename(selected_log_path)
                if len(filtered_df) == len(df):
                    st.markdown(
                        f"<div style='line-height: 38px; color: #0F172A; font-weight: 600; font-size: 0.92rem;'>"
                        f"<b>{base_name}</b> &nbsp;•&nbsp; <span class='filter-indicator-pill'>{len(df):,} total records</span>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f"<div style='line-height: 38px; color: #0F172A; font-weight: 600; font-size: 0.92rem;'>"
                        f"<b>{base_name}</b> &nbsp;•&nbsp; <span class='filter-indicator-pill'>Showing {len(filtered_df):,} of {len(df):,} records (Filtered)</span>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

            # Export filtered records to CSV
            with act_col_csv:
                csv_payload = filtered_df[[c for c in CSV_COLUMNS if c in filtered_df.columns]].to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="📥 Export CSV",
                    data=csv_payload,
                    file_name=f"export_{base_name.rsplit('.', 1)[0]}.csv",
                    mime="text/csv",
                    **stretch_kw(),
                )

            # Export filtered records to JSON
            with act_col_json:
                json_payload = filtered_df[[c for c in CSV_COLUMNS if c in filtered_df.columns]].to_json(orient="records", indent=2).encode("utf-8")
                st.download_button(
                    label="📥 Export JSON",
                    data=json_payload,
                    file_name=f"export_{base_name.rsplit('.', 1)[0]}.json",
                    mime="application/json",
                    **stretch_kw(),
                )

            # Export filtered records to XML
            with act_col_xml:
                records_dict = filtered_df[[c for c in CSV_COLUMNS if c in filtered_df.columns]].to_dict(orient="records")
                xml_payload = records_to_xml(records_dict).encode("utf-8")
                st.download_button(
                    label="📥 Export XML",
                    data=xml_payload,
                    file_name=f"export_{base_name.rsplit('.', 1)[0]}.xml",
                    mime="application/xml",
                    **stretch_kw(),
                )

            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

            # ------------------------------------------------------------------
            # 3. FORENSIC GRID TABLE & CONTROLS
            # ------------------------------------------------------------------
            if filtered_df.empty:
                st.info("No event records match the current filter criteria.")
            else:
                sort_asc = st.session_state.get("grid_sort_asc", True)
                if "RecordID" in filtered_df.columns:
                    filtered_df["_rec_num"] = pd.to_numeric(filtered_df["RecordID"], errors="coerce").fillna(0)
                    filtered_df = filtered_df.sort_values(by="_rec_num", ascending=sort_asc)

                # Pagination controls
                total_filtered = len(filtered_df)
                page_size = st.session_state.get("grid_page_size", 25)
                total_pages = max(1, (total_filtered + page_size - 1) // page_size)

                current_page = min(max(1, st.session_state.get("grid_page", 1)), total_pages)
                st.session_state["grid_page"] = current_page

                # Pagination & Sorting Toolbar
                pg_c1, pg_sort, pg_c2, pg_c3, pg_c4, pg_c5, pg_c6 = st.columns([1.1, 1.6, 0.7, 0.7, 1.5, 0.7, 0.7])
                with pg_c1:
                    new_size = st.selectbox(
                        "Page size:",
                        options=[25, 50, 100],
                        index=[25, 50, 100].index(page_size) if page_size in [25, 50, 100] else 0,
                        key="sel_page_size",
                        label_visibility="collapsed",
                    )
                    if new_size != page_size:
                        st.session_state["grid_page_size"] = new_size
                        st.session_state["grid_page"] = 1
                        st.rerun()

                with pg_sort:
                    sort_lbl = f"⇅ Sort: Record # ({'Asc ↑' if sort_asc else 'Desc ↓'})"
                    if st.button(sort_lbl, key="btn_toggle_sort", **stretch_kw()):
                        st.session_state["grid_sort_asc"] = not sort_asc
                        st.rerun()

                with pg_c2:
                    if st.button("⏮ First", disabled=(current_page == 1), **stretch_kw()):
                        st.session_state["grid_page"] = 1
                        st.rerun()
                with pg_c3:
                    if st.button("◀ Prev", disabled=(current_page == 1), **stretch_kw()):
                        st.session_state["grid_page"] = current_page - 1
                        st.rerun()
                with pg_c4:
                    start_num = (current_page - 1) * page_size + 1
                    end_num = min(current_page * page_size, total_filtered)
                    st.markdown(
                        f"<div style='text-align: center; font-size: 0.82rem; line-height: 32px; color: #475569; font-weight: 600;'>"
                        f"Page <b>{current_page}</b> of <b>{total_pages}</b> &nbsp;({start_num:,} - {end_num:,} of {total_filtered:,})"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
                with pg_c5:
                    if st.button("Next ▶", disabled=(current_page == total_pages), **stretch_kw()):
                        st.session_state["grid_page"] = current_page + 1
                        st.rerun()
                with pg_c6:
                    if st.button("Last ⏭", disabled=(current_page == total_pages), **stretch_kw()):
                        st.session_state["grid_page"] = total_pages
                        st.rerun()

                # Slice records for current page
                start_idx = (current_page - 1) * page_size
                page_df = filtered_df.iloc[start_idx : start_idx + page_size]

                # --------------------------------------------------------------
                # TABLE HEADER ROW (FLEXBOX SINGLE CONTAINER)
                # Exact columns: Record # ↑ | Time (UTC) | Level | Event ID | Name | Provider | Channel | Computer | Action
                # --------------------------------------------------------------
                sort_symbol = "↑" if sort_asc else "↓"
                th_col_widths = [1.2, 1.8, 1.1, 1.1, 1.1, 2.2, 1.8, 1.8, 1.1]

                header_html = f"""
                <div style="display: flex; background-color: #0F172A; border-radius: 6px; padding: 10px 10px; margin-bottom: 4px; align-items: center; border-bottom: 2px solid #1E88E5;">
                    <div style="flex: 1.2; font-size: 0.78rem; font-weight: 800; color: #F59E0B; text-transform: uppercase; letter-spacing: 0.05em;">Record # {sort_symbol}</div>
                    <div style="flex: 1.8; font-size: 0.78rem; font-weight: 700; color: #F8FAFC; text-transform: uppercase; letter-spacing: 0.05em;">Time (UTC)</div>
                    <div style="flex: 1.1; font-size: 0.78rem; font-weight: 700; color: #F8FAFC; text-transform: uppercase; letter-spacing: 0.05em;">Level</div>
                    <div style="flex: 1.1; font-size: 0.78rem; font-weight: 700; color: #F8FAFC; text-transform: uppercase; letter-spacing: 0.05em;">Event ID</div>
                    <div style="flex: 1.1; font-size: 0.78rem; font-weight: 700; color: #F8FAFC; text-transform: uppercase; letter-spacing: 0.05em;">Name</div>
                    <div style="flex: 2.2; font-size: 0.78rem; font-weight: 700; color: #F8FAFC; text-transform: uppercase; letter-spacing: 0.05em;">Provider</div>
                    <div style="flex: 1.8; font-size: 0.78rem; font-weight: 700; color: #F8FAFC; text-transform: uppercase; letter-spacing: 0.05em;">Channel</div>
                    <div style="flex: 1.8; font-size: 0.78rem; font-weight: 700; color: #F8FAFC; text-transform: uppercase; letter-spacing: 0.05em;">Computer</div>
                    <div style="flex: 1.1; font-size: 0.78rem; font-weight: 700; color: #F8FAFC; text-transform: uppercase; letter-spacing: 0.05em; text-align: center;">Action</div>
                </div>
                """
                st.markdown(header_html, unsafe_allow_html=True)

                # --------------------------------------------------------------
                # TABLE ROWS & INLINE EVENT DATA DRAWER
                # --------------------------------------------------------------
                expanded_id = st.session_state.get("expanded_record_id")

                for _, row in page_df.iterrows():
                    rec_id = str(row.get("RecordID", "")).strip()
                    is_expanded = (expanded_id is not None and expanded_id == rec_id)

                    raw_time = row.get("TimeCreated", "")
                    time_display = format_time_utc(raw_time)

                    lvl_name = str(row.get("LevelName", "")).strip() or "Information"
                    lvl_lower = lvl_name.lower()
                    if "error" in lvl_lower:
                        lvl_badge_class = "badge-error"
                    elif "crit" in lvl_lower:
                        lvl_badge_class = "badge-critical"
                    elif "warn" in lvl_lower:
                        lvl_badge_class = "badge-warning"
                    elif "info" in lvl_lower:
                        lvl_badge_class = "badge-info"
                    else:
                        lvl_badge_class = "badge-verbose"

                    eid_val = str(row.get("EventID", "")).strip()
                    name_val = str(row.get("Task", "")).strip()
                    if not name_val or name_val in ("0", "none", "nan"):
                        name_val = "-"

                    prov_val = str(row.get("Provider", "")).strip() or "-"
                    chan_val = str(row.get("Channel", "")).strip() or "-"
                    comp_val = str(row.get("Computer", "")).strip() or "-"

                    c_rec, c_time, c_lvl, c_eid, c_name, c_prov, c_chan, c_comp, c_act = st.columns(th_col_widths)

                    with c_rec:
                        st.markdown(f"<span class='cell-mono'>{html.escape(rec_id)}</span>", unsafe_allow_html=True)
                    with c_time:
                        st.markdown(f"<span class='cell-time' title='{html.escape(str(raw_time))}'>{html.escape(time_display)}</span>", unsafe_allow_html=True)
                    with c_lvl:
                        st.markdown(f"<span class='{lvl_badge_class}'>{html.escape(lvl_name)}</span>", unsafe_allow_html=True)
                    with c_eid:
                        st.markdown(f"<span class='cell-mono'>{html.escape(eid_val)}</span>", unsafe_allow_html=True)
                    with c_name:
                        st.markdown(f"<span class='cell-text' title='{html.escape(name_val)}'>{html.escape(name_val)}</span>", unsafe_allow_html=True)
                    with c_prov:
                        st.markdown(f"<span class='cell-text' title='{html.escape(prov_val)}'>{html.escape(prov_val)}</span>", unsafe_allow_html=True)
                    with c_chan:
                        st.markdown(f"<span class='cell-text' title='{html.escape(chan_val)}'>{html.escape(chan_val)}</span>", unsafe_allow_html=True)
                    with c_comp:
                        st.markdown(f"<span class='cell-mono' title='{html.escape(comp_val)}'>{html.escape(comp_val)}</span>", unsafe_allow_html=True)

                    with c_act:
                        if is_expanded:
                            if st.button("Close", key=f"btn_close_row_{rec_id}", type="primary", **stretch_kw()):
                                st.session_state["expanded_record_id"] = None
                                st.session_state["raw_view_mode"] = None
                                st.rerun()
                        else:
                            if st.button("Details", key=f"btn_det_row_{rec_id}", **stretch_kw()):
                                st.session_state["expanded_record_id"] = rec_id
                                st.session_state["raw_view_mode"] = None
                                st.rerun()

                    # ----------------------------------------------------------
                    # INLINE EVENT DATA DRAWER (IF EXPANDED)
                    # ----------------------------------------------------------
                    if is_expanded:
                        ed_raw = str(row.get("EventData", "")).strip()
                        unpacked_ed = unpack_event_data_dict(ed_raw)

                        payload_lines = []
                        if unpacked_ed:
                            for pk, pv in unpacked_ed.items():
                                val_clean = str(pv).strip().replace("\r\n", "\n")
                                safe_pk = html.escape(str(pk)).replace("`", "&#96;")
                                # Escape markdown special chars so stack traces never parse as code blocks/lists
                                safe_pv = html.escape(val_clean).replace("`", "&#96;").replace("*", "&#42;").replace("_", "&#95;")
                                payload_lines.append(
                                    f"<div style='margin-bottom: 8px;'>"
                                    f"<span class='forensic-payload-key'>{safe_pk}</span> "
                                    f"<span class='forensic-payload-val' style='font-family: inherit; color: #F8FAFC;'>{safe_pv}</span>"
                                    f"</div>"
                                )
                        else:
                            msg_clean = str(row.get("Message", "")).strip()
                            if msg_clean:
                                safe_msg = html.escape(msg_clean).replace("`", "&#96;").replace("*", "&#42;").replace("_", "&#95;")
                                payload_lines.append(f"<span class='forensic-payload-val' style='color: #F8FAFC;'>{safe_msg}</span>")
                            else:
                                payload_lines.append("<span style='color: #94A3B8;'>No EventData or payload parameters attached to this record.</span>")

                        payload_html = "".join(payload_lines)

                        st.markdown(
                            f"""
                            <div class="forensic-drawer">
                                <div class="forensic-drawer-title">EVENT DATA</div>
                                <div class="forensic-payload-box">
                                    {payload_html}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        # Drawer Action Bar: Show raw XML | Show raw JSON | Close
                        d_c1, d_c2, d_c3, _ = st.columns([1.3, 1.3, 1.0, 4.0])
                        with d_c1:
                            xml_active = (st.session_state.get("raw_view_mode") == "xml")
                            btn_xml_label = "Hide raw XML" if xml_active else "Show raw XML"
                            if st.button(btn_xml_label, key=f"drawer_xml_{rec_id}", **stretch_kw()):
                                st.session_state["raw_view_mode"] = None if xml_active else "xml"
                                st.rerun()

                        with d_c2:
                            json_active = (st.session_state.get("raw_view_mode") == "json")
                            btn_json_label = "Hide raw JSON" if json_active else "Show raw JSON"
                            if st.button(btn_json_label, key=f"drawer_json_{rec_id}", **stretch_kw()):
                                st.session_state["raw_view_mode"] = None if json_active else "json"
                                st.rerun()

                        with d_c3:
                            if st.button("Close", key=f"drawer_close_{rec_id}", **stretch_kw()):
                                st.session_state["expanded_record_id"] = None
                                st.session_state["raw_view_mode"] = None
                                st.rerun()

                        # Raw XML display
                        if st.session_state.get("raw_view_mode") == "xml":
                            clean_rec = row.to_dict()
                            clean_rec = {k: v for k, v in clean_rec.items() if not k.startswith("_")}
                            raw_xml_text = record_to_xml(clean_rec)
                            st.caption("Standard Windows Event XML:")
                            st.code(raw_xml_text, language="xml")

                        # Raw JSON display
                        elif st.session_state.get("raw_view_mode") == "json":
                            clean_rec = row.to_dict()
                            clean_rec = {k: v for k, v in clean_rec.items() if not k.startswith("_")}
                            raw_json_text = json.dumps(clean_rec, indent=2)
                            st.caption("Standard Structured JSON Record:")
                            st.code(raw_json_text, language="json")

            # ------------------------------------------------------------------
            # 4. COLLAPSIBLE VISUAL ANALYTICS & METRICS
            # ------------------------------------------------------------------
            st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
            with st.expander("📊 Visual Analytics & Metrics", expanded=False):
                kpi1, kpi2, kpi3, kpi4 = st.columns(4)
                with kpi1:
                    st.metric("Total Filtered Events", f"{len(filtered_df):,}")
                with kpi2:
                    u_eids = filtered_df["EventID"].nunique() if "EventID" in filtered_df.columns else 0
                    st.metric("Unique Event IDs", f"{u_eids:,}")
                with kpi3:
                    u_prov = filtered_df["Provider"].nunique() if "Provider" in filtered_df.columns else 0
                    st.metric("Providers", f"{u_prov:,}")
                with kpi4:
                    u_chan = filtered_df["Channel"].nunique() if "Channel" in filtered_df.columns else 0
                    st.metric("Channels", f"{u_chan:,}")

                st.markdown("---")
                chart_col1, chart_col2 = st.columns(2)
                with chart_col1:
                    if "EventID" in filtered_df.columns and not filtered_df.empty:
                        top_e = filtered_df["EventID"].astype(str).value_counts().head(10).reset_index()
                        top_e.columns = ["EventID", "Count"]
                        fig_e = px.bar(
                            top_e,
                            x="EventID",
                            y="Count",
                            title=f"Top 10 Event IDs ({os.path.basename(selected_log_path)})",
                            text="Count",
                            color="Count",
                            color_continuous_scale="Blues",
                        )
                        fig_e.update_xaxes(type="category")
                        fig_e.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
                        st.plotly_chart(fig_e, **stretch_kw())

                with chart_col2:
                    if "Provider" in filtered_df.columns and not filtered_df.empty:
                        top_p = filtered_df["Provider"].astype(str).value_counts().head(8).reset_index()
                        top_p.columns = ["Provider", "Count"]
                        fig_p = px.pie(
                            top_p,
                            names="Provider",
                            values="Count",
                            title=f"Event Providers Distribution ({os.path.basename(selected_log_path)})",
                            hole=0.4,
                        )
                        fig_p.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
                        st.plotly_chart(fig_p, **stretch_kw())


# ==============================================================================
# VIEW 3: UNIFIED FORENSIC ASSISTANT (GEMINI-STYLE NLP CHAT & TEMPLATE DEDUP)
# ==============================================================================

elif st.session_state["active_tab"] == "assistant":
    # 1. Discover available logs
    csv_dir = st.session_state.get("viewer_folder", "Converted files")
    norm_csv_dir = normalize_path(csv_dir)
    available_files = []
    if os.path.isdir(norm_csv_dir):
        for ext in ("*.csv", "*.json", "*.jsonl"):
            available_files.extend(glob.glob(os.path.join(norm_csv_dir, ext)))
    available_files = sorted(available_files)

    if not available_files:
        st.title("🤖 Windows Forensic Assistant")
        st.warning(
            f"⚠️ No converted log files found in `{csv_dir}`. "
            "Please convert `.evtx` files in the **Converter** tab before starting an investigation."
        )
        if st.button("🔄 Go to EVTX Converter", type="primary", **stretch_kw()):
            st.session_state["active_tab"] = "converter"
            st.rerun()
    else:
        # Scope Selection
        file_options = {os.path.basename(f): f for f in available_files}
        log_names = list(file_options.keys())

        # Sidebar Assistant Controls
        st.sidebar.markdown("---")
        st.sidebar.subheader("Investigation Scope")
        selected_log_name = st.sidebar.selectbox(
            "Target Log File:",
            options=["All Converted Logs (Consolidated)"] + log_names,
            index=0 if len(log_names) > 1 else 1,
            help="Choose an individual log file or query across all converted logs simultaneously.",
        )

        force_resync = st.sidebar.button("🔄 Re-Index Scope in DuckDB & Qdrant", **stretch_kw())

        if st.sidebar.button("🗑️ Clear Chat History", **stretch_kw()):
            st.session_state["chatbot_messages"] = [
                {
                    "role": "assistant",
                    "content": "👋 **Hello! I'm your Forensic AI Assistant.** Ask any question about your event logs in plain English to investigate alerts, hunt threats, or inspect specific system behaviors.",
                    "filter_card": None,
                    "templates": None,
                    "evidence": None,
                }
            ]
            st.rerun()

        # Connect to DuckDB and sync records
        conn = get_duckdb_conn()

        with st.spinner("Synchronizing logs with DuckDB & Drain3 templater..."):
            if selected_log_name == "All Converted Logs (Consolidated)":
                dfs = []
                for fn, fp in file_options.items():
                    temp_df = load_log_data(fp)
                    if not temp_df.empty:
                        temp_df["SourceLog"] = fn
                        dfs.append(temp_df)
                active_df = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
                scope_label = f"All Logs ({len(dfs)} files)"
            else:
                active_df = load_log_data(file_options[selected_log_name])
                scope_label = selected_log_name

            # Ingest and cluster into DuckDB
            if not active_df.empty:
                last_synced = st.session_state.get("synced_scope")
                if last_synced != scope_label or force_resync:
                    sync_res = sync_dataframe_to_duckdb(conn, active_df, scope_label, force_resync=force_resync)
                    st.session_state["synced_scope"] = scope_label
                    st.session_state["sync_res"] = sync_res

        # Retrieve DB metrics
        total_rec_count = 0
        total_tpl_count = 0
        total_vec_count = 0
        try:
            total_rec_count = conn.execute("SELECT COUNT(*) FROM canonical_logs").fetchone()[0]
            total_tpl_count = conn.execute("SELECT COUNT(*) FROM log_templates").fetchone()[0]
            v_idx = get_vector_index(get_embedder())
            total_vec_count = v_idx.client.count(v_idx.collection_name).count
        except Exception:
            pass

        dedup_ratio = 0.0
        if total_rec_count > 0 and total_tpl_count > 0:
            dedup_ratio = max(0.0, (1.0 - (total_tpl_count / total_rec_count)) * 100.0)

        # Gemini Hero Header
        st.title("🤖 Windows Forensic Assistant")
        st.markdown(
            "Chat with your event logs using **natural language (NLP)**. "
            "Powered by **Drain3 log clustering**, **BGE technical embeddings**, and **DuckDB canonical verification**."
        )

        # KPI Metrics Cards Banner
        kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
        with kpi_col1:
            st.metric("Investigation Scope", scope_label[:20] + ("..." if len(scope_label) > 20 else ""))
        with kpi_col2:
            st.metric("Canonical Records", f"{total_rec_count:,}")
        with kpi_col3:
            st.metric("Drain3 Templates", f"{total_tpl_count:,}", delta=f"{dedup_ratio:.1f}% Dedup" if dedup_ratio > 0 else None)
        with kpi_col4:
            st.metric("Vector Index", f"🟢 {total_vec_count:,} Vectors")

        # ----------------------------------------------------------------------
        # INTEGRATED CLUSTERED TEMPLATES & DEDUP EXPLORER (EXPANDABLE PANEL)
        # ----------------------------------------------------------------------
        with st.expander("🧩 Drain3 Clustered Templates & Evidentiary Traceability Matrix", expanded=False):
            st.markdown(
                "Inspect how near-identical log records were deduplicated into structural templates while maintaining **100% evidentiary traceability** back to every original record."
            )

            # Template Search Filter
            tpl_search_col, tpl_btn_col = st.columns([3, 1])
            with tpl_search_col:
                tpl_kw = st.text_input("Search Mined Templates by Keyword or Event ID:", placeholder="e.g. 4625, logon, USB...", key="tpl_matrix_search")
            with tpl_btn_col:
                st.write("")
                st.write("")
                if st.button("🔄 Re-Mine Templates", **stretch_kw()):
                    with st.spinner("Re-mining templates with Drain3..."):
                        mgr = get_drain3_mgr()
                        mgr.process_canonical_records(conn, canonical_table="canonical_logs")
                        v_idx.index_from_duckdb(conn, templates_table="log_templates")
                        st.success("Templates and vectors refreshed!")
                        st.rerun()

            # Mined Templates Table
            query_tpl_sql = "SELECT template_id, source_type, provider, event_id, level, total_count, first_seen_utc, last_seen_utc, template_string FROM log_templates"
            tpl_params = []
            if tpl_kw and tpl_kw.strip():
                query_tpl_sql += " WHERE LOWER(template_string) LIKE ? OR event_id LIKE ?"
                kw_p = f"%{tpl_kw.strip().lower()}%"
                tpl_params = [kw_p, f"%{tpl_kw.strip()}%"]
            query_tpl_sql += " ORDER BY total_count DESC"

            try:
                matrix_tpl_df = conn.execute(query_tpl_sql, tpl_params).df()
                st.dataframe(matrix_tpl_df, **stretch_kw())

                # Traceability Inspector
                all_tids = matrix_tpl_df["template_id"].tolist()
                if all_tids:
                    st.markdown("##### 🔗 100% Evidentiary Traceability Drilldown")
                    sel_tid = st.selectbox("Select Template to Trace:", options=all_tids, key="sel_trace_tpl")
                    if sel_tid:
                        mgr = get_drain3_mgr()
                        full_inst_records = mgr.get_records_for_template(conn, sel_tid, canonical_table="canonical_logs")
                        
                        inst_m1, inst_m2 = st.columns(2)
                        with inst_m1:
                            st.metric("Total Represented Instances", f"{len(full_inst_records):,} records")
                        with inst_m2:
                            st.metric("Traceability Guarantee", "100% Exact (Zero Sampling)")

                        p_cols = [c for c in ["RecordID", "event_record_id", "TimeCreated", "time_created_utc", "LevelName", "Level", "EventID", "Channel", "Computer", "UserID", "Message"] if c in full_inst_records.columns]
                        st.dataframe(full_inst_records[p_cols if p_cols else full_inst_records.columns[:8]], **stretch_kw())

                        csv_dl = full_inst_records.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            label="📥 Download Template Records as CSV",
                            data=csv_dl,
                            file_name=f"{sel_tid}_instances.csv",
                            mime="text/csv",
                            key=f"dl_matrix_{sel_tid}",
                        )
            except Exception as e:
                st.info(f"No templates currently loaded: {e}")

        st.markdown("---")

        # ----------------------------------------------------------------------
        # GEMINI CHAT INTERFACE & CONVERSATION STREAM
        # ----------------------------------------------------------------------
        # Welcoming suggestions if chat is empty
        if not st.session_state.get("chatbot_messages") or len(st.session_state["chatbot_messages"]) <= 1:
            st.caption("✨ **Suggested prompts to get started:**")
            sug_col1, sug_col2 = st.columns(2)
            submitted_prompt = None
            with sug_col1:
                if st.button("🔍 Logon failures for process 1064", **stretch_kw()):
                    submitted_prompt = "Show me logon failure events for process 1064 yesterday"
                if st.button("🛡️ Critical errors in System log", **stretch_kw()):
                    submitted_prompt = "What critical errors occurred in System log?"
            with sug_col2:
                if st.button("🔌 USB reader disconnect events", **stretch_kw()):
                    submitted_prompt = "Find USB reader disconnect events"
                if st.button("⚡ Process creation and execution trace", **stretch_kw()):
                    submitted_prompt = "Show me process creation events"
        else:
            submitted_prompt = None

        # Render Chat History
        for idx, msg in enumerate(st.session_state["chatbot_messages"]):
            avatar_icon = "🧑‍💻" if msg["role"] == "user" else "✨"
            with st.chat_message(msg["role"], avatar=avatar_icon):
                st.markdown(msg["content"])

                # Render Filter Resolution Card
                f_card = msg.get("filter_card")
                if f_card:
                    with st.expander("⚙️ Structured NLP Filter Breakdown", expanded=False):
                        fc1, fc2, fc3 = st.columns(3)
                        with fc1:
                            st.markdown(f"**Intent:** `{f_card.get('intent', 'N/A')}`")
                            st.markdown(f"**Channel:** `{f_card.get('source_type') or 'All Channels'}`")
                        with fc2:
                            st.markdown(f"**Event ID:** `{f_card.get('event_id') or 'None'}`")
                            st.markdown(f"**Level:** `{f_card.get('level') or 'Any'}`")
                        with fc3:
                            st.markdown(f"**Time Range:** `{f_card.get('time_range') or 'Unbounded'}`")
                            st.markdown(f"**Entities:** `{f_card.get('entities') or 'None'}`")
                        st.markdown(f"**Residual Semantic Query:** *\"{f_card.get('semantic_query', '')}\"*")

                # Render Matched Templates Expander
                tpl_matches = msg.get("templates")
                if tpl_matches:
                    with st.expander(f"🧩 Matching Drain3 Templates ({len(tpl_matches)} clusters)", expanded=False):
                        tpl_display = []
                        for t in tpl_matches:
                            meta = t.get("metadata", {})
                            tpl_display.append({
                                "Score": round(float(t.get("score", 0.0)), 3),
                                "Template ID": t.get("template_id"),
                                "Channel": meta.get("source_type"),
                                "Event ID": meta.get("event_id"),
                                "Level": meta.get("level"),
                                "Count": meta.get("total_count"),
                                "Template String": meta.get("template_string"),
                            })
                        st.dataframe(pd.DataFrame(tpl_display), **stretch_kw())

                # Render Evidence Artifacts Grid
                ev_df = msg.get("evidence")
                if ev_df is not None and not ev_df.empty:
                    with st.expander(f"🔎 Evidence Artifacts ({len(ev_df):,} matching events)", expanded=True):
                        pref_cols = [
                            c for c in ["RecordID", "event_record_id", "TimeCreated", "time_created_utc", "LevelName", "Level", "level", "EventID", "event_id", "Channel", "source_type", "Computer", "computer", "ProcessID", "process_id", "UserID", "user_id", "Message", "message"]
                            if c in ev_df.columns
                        ]
                        display_cols = pref_cols if pref_cols else list(ev_df.columns[:8])
                        st.dataframe(ev_df[display_cols].head(250), **stretch_kw())

                        # Download matched evidence
                        ev_csv = ev_df.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            label="📥 Download Evidence as CSV",
                            data=ev_csv,
                            file_name=f"forensic_evidence_{idx}.csv",
                            mime="text/csv",
                            key=f"btn_dl_ev_{idx}",
                        )

        # Chat Input Bar
        user_input = st.chat_input("Ask a forensic question in plain English (e.g. 'Show me logon failures for process 1064 yesterday')...")
        active_query = submitted_prompt or user_input

        # Process query if submitted
        if active_query:
            st.session_state["chatbot_messages"].append(
                {"role": "user", "content": active_query, "evidence": None, "filter_card": None, "templates": None}
            )

            with st.spinner("Thinking... Parsing NLP query, searching vector index, and verifying DuckDB evidence..."):
                # Step 1: Parse NLP query
                parser = get_query_parser()
                qf = parser.parse_query(active_query)

                time_range_str = f"{qf.time_range.start_utc} to {qf.time_range.end_utc} (UTC)" if qf.time_range else "Unbounded"
                entities_str = ", ".join(f"{k}={v}" for k, v in qf.entity_filters.to_dict().items() if v) or "None"

                filter_card = {
                    "intent": qf.intent,
                    "source_type": qf.source_type,
                    "event_id": qf.event_id,
                    "level": qf.level,
                    "time_range": time_range_str,
                    "entities": entities_str,
                    "semantic_query": qf.semantic_query,
                }

                # Step 2: Pass 1 Vector Search on Templates with pre-filtering
                v_idx = get_vector_index(get_embedder())
                qdrant_filters: Dict[str, Any] = {}
                if qf.source_type:
                    qdrant_filters["source_type"] = qf.source_type
                if qf.level:
                    qdrant_filters["level"] = qf.level
                if qf.event_id:
                    qdrant_filters["event_id"] = qf.event_id
                if qf.time_range:
                    qdrant_filters["time_range"] = {"start_time": qf.time_range.start_utc, "end_time": qf.time_range.end_utc}

                template_matches = v_idx.search(
                    query_text=qf.semantic_query or active_query,
                    filters=qdrant_filters if qdrant_filters else None,
                    top_k=5,
                )

                candidate_rec_ids: List[str] = []
                if template_matches:
                    inst_map = v_idx.resolve_search_results_to_instances(conn, template_matches)
                    for ids in inst_map.values():
                        candidate_rec_ids.extend(ids)

                # Step 3: Pass 2 Evidentiary Record Execution via DuckDB
                executor = get_query_executor()
                matched_records = executor.execute_query(
                    conn=conn,
                    query_filter=qf,
                    candidate_record_ids=candidate_rec_ids if candidate_rec_ids else None,
                    canonical_table="canonical_logs",
                    limit=500,
                )

                # Fallback to direct structured filter if vector candidates yielded no intersection
                if matched_records.empty and (qf.entity_filters.has_any() or qf.event_id or qf.time_range or qf.level):
                    matched_records = executor.execute_query(
                        conn=conn,
                        query_filter=qf,
                        candidate_record_ids=None,
                        canonical_table="canonical_logs",
                        limit=500,
                    )

                # Build narrative response
                match_cnt = len(matched_records)
                resp_text = f"### 🔍 Forensic Findings\n\n"
                resp_text += f"**Question:** *\"{active_query}\"*\n\n"
                resp_text += f"**Identified Intent:** `{qf.intent.upper()}` | **Active Scope:** `{scope_label}`\n\n"

                if qf.intent == "ambiguous" and qf.clarifying_question:
                    resp_text += f"> 💡 **Clarification Needed:** {qf.clarifying_question}\n\n"

                if match_cnt > 0:
                    time_cols = [c for c in ["TimeCreated", "time_created_utc"] if c in matched_records.columns]
                    time_min = matched_records[time_cols[0]].min() if time_cols else "N/A"
                    time_max = matched_records[time_cols[0]].max() if time_cols else "N/A"

                    host_cols = [c for c in ["Computer", "computer"] if c in matched_records.columns]
                    hosts = [str(h) for h in matched_records[host_cols[0]].dropna().unique() if str(h).strip()] if host_cols else []
                    hosts_str = ", ".join(hosts[:3]) + (f" (+{len(hosts)-3} more)" if len(hosts) > 3 else "") if hosts else "N/A"

                    resp_text += f"#### 📊 Key Evidence Summary\n"
                    resp_text += f"- **Matched Records:** **{match_cnt:,}** canonical event(s)\n"
                    resp_text += f"- **Time Window:** `{time_min}` $\\rightarrow$ `{time_max}`\n"
                    resp_text += f"- **Affected System(s):** `{hosts_str}`\n"
                    resp_text += f"- **Clustered Templates:** `{len(template_matches)}` pattern(s)\n\n"
                    resp_text += "You can inspect the matched Drain3 templates and exact canonical evidence records below."
                else:
                    resp_text += f"❌ **No matching events found** for the parsed filters in `{scope_label}`.\n\n"
                    resp_text += "Try broadening the search query or selecting a different log file in the sidebar."

            st.session_state["chatbot_messages"].append(
                {
                    "role": "assistant",
                    "content": resp_text,
                    "filter_card": filter_card,
                    "templates": template_matches,
                    "evidence": matched_records,
                }
            )
            st.rerun()

