"""app.py
======
Windows EVTX Forensic Log Converter & Interactive Inspector GUI.

Built with Streamlit and powered by fileconversion.py.
Features:
- Dual-Engine Support: Native evtx_dump binary + pure-Python fallback.
- Multi-Format Export: Convert EVTX to CSV, JSON, JSON Lines (JSONL), or standard Windows XML.
- Forensic Grid: Identical columns to evtxparser (Record #, Time, Level, Event ID, Name, Provider, Channel, Computer, Summary).
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
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st

import fileconversion

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

    /* Read More Summary Popover */
    details.read-more-wrapper summary::-webkit-details-marker {
        display: none !important;
    }
    details.read-more-wrapper summary {
        list-style: none !important;
        outline: none !important;
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
# SIDEBAR: NAVIGATION & CONTROLS
# ------------------------------------------------------------------------------

st.sidebar.title("Windows Event Logs")
st.sidebar.subheader("Navigation")
page_selection = st.sidebar.radio(
    "Choose Mode:",
    options=["🔄 Convert EVTX (Multi-Format)", "📊 Forensic Grid & Inspector"],
    index=0 if st.session_state["active_tab"] == "converter" else 1,
)
if page_selection == "🔄 Convert EVTX (Multi-Format)":
    st.session_state["active_tab"] = "converter"
else:
    st.session_state["active_tab"] = "viewer"

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
                        placeholder="Search EventData, UserData, Message, or UserID...",
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
                for col in ["_summary_cached", "EventData", "UserData", "Message", "Computer", "UserID"]:
                    if col in filtered_df.columns:
                        mask = mask | filtered_df[col].astype(str).str.lower().str.contains(kw, na=False)
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
                # Exact columns: Record # ↑ | Time (UTC) | Level | Event ID | Name | Provider | Channel | Computer | Summary | Action
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
