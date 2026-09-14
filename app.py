"""app.py
======
Windows EVTX to CSV Converter & Interactive Log Viewer GUI.

Built with Streamlit and powered by fileconversion.py.
Features:
- Unrestricted Source: Upload files via browser, or enter any system path/wildcard.
- Unrestricted Destination: Save CSVs to any folder or explicit filename anywhere on disk.
- Dual-Engine Support: Native evtx_dump binary + pure-Python fallback.
- Interactive Log Viewer: Search, filter, inspect JSON payloads, and view charts.
"""

import glob
import json
import os
import re
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.express as px
import streamlit as st

import importlib
import fileconversion

try:
    importlib.reload(fileconversion)
except Exception:
    pass

convert = getattr(fileconversion, "convert")
convert_and_load = getattr(fileconversion, "convert_and_load")
convert_from_path = getattr(fileconversion, "convert_from_path")
convert_from_upload = getattr(fileconversion, "convert_from_upload")


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
# STREAMLIT CONFIGURATION & STYLING (BLUE THEME)
# ------------------------------------------------------------------------------

st.set_page_config(
    page_title="Windows EVTX Log Converter & Viewer",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for blue theme across all components
st.markdown(
    """
    <style>
    /* Metric card styling */
    div[data-testid="metric-container"] {
        background-color: rgba(30, 136, 229, 0.07);
        border: 1px solid rgba(30, 136, 229, 0.22);
        padding: 12px 18px;
        border-radius: 10px;
        transition: all 0.2s ease-in-out;
    }
    div[data-testid="metric-container"]:hover {
        border-color: rgba(30, 136, 229, 0.55);
        background-color: rgba(30, 136, 229, 0.12);
    }

    /* Table overflow */
    .stDataFrame {
        border-radius: 8px;
        overflow: hidden;
    }

    /* Primary Buttons -> Blue */
    button[kind="primary"],
    div[data-testid="stButton"] > button[kind="primary"],
    .stButton > button[type="primary"],
    button[data-testid="baseButton-primary"] {
        background-color: #1E88E5 !important;
        border-color: #1976D2 !important;
        color: #FFFFFF !important;
        box-shadow: 0 4px 14px rgba(30, 136, 229, 0.3) !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
    }
    button[kind="primary"]:hover,
    div[data-testid="stButton"] > button[kind="primary"]:hover,
    .stButton > button[type="primary"]:hover,
    button[data-testid="baseButton-primary"]:hover {
        background-color: #1976D2 !important;
        border-color: #1565C0 !important;
        color: #FFFFFF !important;
        box-shadow: 0 6px 18px rgba(30, 136, 229, 0.45) !important;
    }
    button[kind="primary"]:active,
    div[data-testid="stButton"] > button[kind="primary"]:active,
    button[data-testid="baseButton-primary"]:active {
        background-color: #1565C0 !important;
        border-color: #0D47A1 !important;
    }

    /* Radio Buttons -> Blue */
    div[data-testid="stRadio"] div[role="radiogroup"] label[data-checked="true"] div:first-child,
    div[data-testid="stRadio"] [role="radiogroup"] label[data-checked="true"] span:first-child {
        border-color: #1E88E5 !important;
        background-color: #1E88E5 !important;
    }
    div[data-testid="stRadio"] svg {
        fill: #1E88E5 !important;
    }
    div[data-testid="stRadio"] [role="radiogroup"] label[data-checked="true"] p {
        color: #1E88E5 !important;
        font-weight: 600 !important;
    }

    /* Progress bar -> Blue */
    div[data-testid="stProgress"] > div > div > div > div {
        background-color: #1E88E5 !important;
    }

    /* File Uploader -> Blue Accents */
    div[data-testid="stFileUploader"] section[data-testid="stFileUploadDropzone"] {
        border-color: rgba(30, 136, 229, 0.35) !important;
        background-color: rgba(30, 136, 229, 0.03) !important;
    }
    div[data-testid="stFileUploader"] section[data-testid="stFileUploadDropzone"]:hover {
        border-color: #1E88E5 !important;
        background-color: rgba(30, 136, 229, 0.07) !important;
    }
    div[data-testid="stFileUploader"] button {
        border-color: #1E88E5 !important;
        color: #1E88E5 !important;
    }
    div[data-testid="stFileUploader"] button:hover {
        background-color: rgba(30, 136, 229, 0.1) !important;
        border-color: #1976D2 !important;
        color: #1976D2 !important;
    }

    /* Download Buttons -> Blue Outline */
    .stDownloadButton > button {
        border-color: #1E88E5 !important;
        color: #1E88E5 !important;
    }
    .stDownloadButton > button:hover {
        background-color: rgba(30, 136, 229, 0.09) !important;
        border-color: #1976D2 !important;
        color: #1976D2 !important;
    }

    /* Inputs focus outline -> Blue */
    input:focus, textarea:focus, div[data-baseweb="input"]:focus-within {
        border-color: #1E88E5 !important;
        box-shadow: 0 0 0 1px #1E88E5 !important;
    }

    /* Checkboxes -> Blue */
    div[data-testid="stCheckbox"] input[type="checkbox"]:checked + span {
        background-color: #1E88E5 !important;
        border-color: #1E88E5 !important;
    }

    /* Multiselect / Tags */
    div[data-baseweb="select"] span[data-baseweb="tag"] {
        background-color: rgba(30, 136, 229, 0.15) !important;
    }

    /* Active Tab */
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #1E88E5 !important;
        border-bottom-color: #1E88E5 !important;
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
if "last_converted_csv" not in st.session_state:
    st.session_state["last_converted_csv"] = None
if "viewer_folder" not in st.session_state:
    st.session_state["viewer_folder"] = "Converted files"
if "conversion_history" not in st.session_state:
    st.session_state["conversion_history"] = []


def clean_event_id_scalar(val: Any) -> str:
    """Extracts clean numeric EventID if stored as a dictionary string (e.g. {'#text': 4624})."""
    s = str(val).strip()
    if "#text" in s:
        m = re.search(r"['\"]?#text['\"]?\s*:\s*['\"]?(\d+)['\"]?", s)
        if m:
            return m.group(1)
    return s


@st.cache_data(show_spinner=False)
def load_csv_data(filepath: str) -> pd.DataFrame:
    """Loads and caches a CSV file as a pandas DataFrame."""
    if not os.path.isfile(filepath):
        return pd.DataFrame()
    try:
        df = pd.read_csv(filepath, dtype=str, keep_default_na=False)
        df.fillna("", inplace=True)
        df.replace({"null": "", "None": "", "NULL": "", "NaN": "", "nan": ""}, inplace=True)
        if "EventID" in df.columns:
            df["EventID"] = df["EventID"].apply(clean_event_id_scalar)
        return df
    except Exception as e:
        st.error(f"Error loading CSV file: {e}")
        return pd.DataFrame()


# ------------------------------------------------------------------------------
# SIDEBAR: NAVIGATION & CONTROLS
# ------------------------------------------------------------------------------

st.sidebar.title("Windows Logs")
st.sidebar.subheader("Navigation")
page_selection = st.sidebar.radio(
    "Choose Mode:",
    options=["🔄 Convert EVTX to CSV", "📊 Log Viewer & Inspector"],
    index=0 if st.session_state["active_tab"] == "converter" else 1,
)
if page_selection == "🔄 Convert EVTX to CSV":
    st.session_state["active_tab"] = "converter"
else:
    st.session_state["active_tab"] = "viewer"


# ==============================================================================
# VIEW 1: CONVERTER (UPLOAD OR PATH)
# ==============================================================================

if st.session_state["active_tab"] == "converter":
    st.title("Windows EVTX to CSV Converter")
    st.markdown(
        "Convert any Windows `.evtx` event logs to structured `.csv` format. "
        "Supports browser uploads, local folders and recursive searches without path restrictions."
    )

    convert_mode = st.radio(
        "Select Conversion Method:",
        options=["📂 Drag & Drop File Upload", "🖥️ File Path / Folder"],
        horizontal=True,
    )

    # --------------------------------------------------------------------------
    # OPTION A: BROWSER FILE UPLOAD
    # --------------------------------------------------------------------------
    if convert_mode == "📂 Drag & Drop File Upload":
        st.subheader("Upload .evtx File(s)")
        uploaded_files = st.file_uploader(
            "Upload one or more .evtx files directly from your computer:",
            type=["evtx"],
            accept_multiple_files=True,
            help="Select one or multiple .evtx files to convert.",
        )

        default_dest = st.session_state.get("viewer_folder") or "Converted files"

        if uploaded_files:
            total_upload_mb = sum(getattr(f, "size", 0) for f in uploaded_files) / (1024 * 1024)
            st.info(
                f"📋 **Auto-detected Details:** Ready to convert **{len(uploaded_files)}** file(s) "
                f"({total_upload_mb:.2f} MB total). Converted `.csv` files will be automatically stored in: `{default_dest}/`",
                icon="ℹ️",
            )
            with st.expander(f"Inspect Uploaded Files ({len(uploaded_files)} files)", expanded=False):
                file_summary = []
                for uf in uploaded_files:
                    f_size_kb = getattr(uf, "size", 0) / 1024
                    base_csv = os.path.splitext(uf.name)[0] + ".csv"
                    file_summary.append({
                        "Uploaded File": uf.name,
                        "Size": f"{f_size_kb:.1f} KB" if f_size_kb < 1024 else f"{f_size_kb/1024:.2f} MB",
                        "Target CSV": base_csv,
                    })
                st.dataframe(pd.DataFrame(file_summary), use_container_width=True)

            with st.expander("⚙️ Destination Settings (Optional)", expanded=False):
                dest_folder_upload = st.text_input(
                    "Destination folder for converted files:",
                    value=default_dest,
                    help="Where converted files are saved. Automatically set to your Converted files folder.",
                    key="custom_upload_dest",
                ).strip() or default_dest
        else:
            dest_folder_upload = default_dest

        col_btn, _ = st.columns([1, 3])
        with col_btn:
            start_upload_conv = st.button("🚀 Convert Uploaded Files", type="primary", use_container_width=True)

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
                    status_text.markdown(f"Converting **{up_file.name}** ({idx}/{total})...")
                    res = convert_from_upload(up_file, output_dir=dest_folder_upload)
                    results.append(res)
                    progress_bar.progress(idx / total)

                elapsed = time.time() - start_time
                status_text.empty()
                progress_bar.empty()

                successful = [r for r in results if r["success"]]
                total_records = sum(r["record_count"] for r in successful)

                st.success(
                    f"🎉 Successfully converted {len(successful)}/{total} file(s) "
                    f"({total_records:,} total records) in {elapsed:.2f}s!"
                )

                summary_data = [
                    {
                        "File": r["input_file"],
                        "Status": "✅ Success" if r["success"] else "❌ Failed",
                        "Records": f"{r['record_count']:,}",
                        "Output CSV": r["output_file"],
                        "Error": r.get("error") or "",
                    }
                    for r in results
                ]
                st.dataframe(pd.DataFrame(summary_data), use_container_width=True)

                if successful:
                    target_file = successful[0]["output_file"]
                    st.session_state["last_converted_csv"] = target_file
                    st.session_state["selected_log_path"] = target_file
                    st.cache_data.clear()

                    col_view, col_dl = st.columns([1, 1])
                    with col_view:
                        if st.button(f"📊 Open {os.path.basename(target_file)} in Viewer", type="primary", use_container_width=True):
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
                                    mime="text/csv",
                                    use_container_width=True,
                                )
                        except Exception:
                            pass

    # --------------------------------------------------------------------------
    # OPTION B: SYSTEM PATH / FOLDER / WILDCARD
    # --------------------------------------------------------------------------
    else:
        st.subheader("1. Specify Source & Destination Paths")
        st.caption("Enter any file path, directory path, or wildcard pattern. No restrictions on source or destination.")

        col_src, col_dst = st.columns(2)
        with col_src:
            source_input = st.text_input(
                "Source Path (file, directory, or wildcard pattern):",
                value="Original Data/evtx" if os.path.isdir("Original Data/evtx") else "",
                placeholder="e.g. sample.evtx, Original Data/evtx, or logs/*.evtx",
                help="Accepts relative or absolute paths, home paths (~), and wildcards (*.evtx).",
            )
            recursive_check = st.checkbox(
                "Recursively scan subdirectories",
                value=False,
                help="If checked, searches all nested subfolders for .evtx files.",
            )

        with col_dst:
            dest_input = st.text_input(
                "Destination Location (folder or explicit .csv file):",
                value=st.session_state["viewer_folder"],
                placeholder="e.g. Converted files or custom_name.csv",
                help="Where converted files will be stored. Intermediate folders will be created automatically.",
            )

        col_scan, col_conv = st.columns([1, 2])
        with col_scan:
            scan_clicked = st.button("🔍 Scan & Preview Files", use_container_width=True)
        with col_conv:
            convert_clicked = st.button("🚀 Start Conversion", type="primary", use_container_width=True)

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
                            f"({total_records:,} records total) in {elapsed:.2f}s!"
                        )

                        summary_data = [
                            {
                                "File": os.path.basename(r["input_file"]),
                                "Status": "✅ Success" if r["success"] else "❌ Failed",
                                "Records": f"{r['record_count']:,}",
                                "Output CSV": r["output_file"],
                                "Error": r.get("error") or "",
                            }
                            for r in results
                        ]
                        st.dataframe(pd.DataFrame(summary_data), use_container_width=True)

                        if successful:
                            if st.button("📊 Open Converted Logs in Viewer", use_container_width=True):
                                st.session_state["active_tab"] = "viewer"
                                st.session_state["viewer_selected_file"] = successful[0]["output_file"]
                                st.rerun()

                except Exception as exc:
                    status_text.empty()
                    progress_bar.empty()
                    st.error(f"Conversion failed: {exc}")


# ==============================================================================
# VIEW 2: LOG VIEWER & INSPECTOR
# ==============================================================================

elif st.session_state["active_tab"] == "viewer":
    st.title("📊 Windows Event Log Viewer & Inspector")
    st.markdown("Search, filter, visualize, and inspect payloads of converted event log CSVs.")

    csv_dir = st.session_state.get("viewer_folder", "Converted files")
    norm_csv_dir = normalize_path(csv_dir)

    available_csvs = []
    if os.path.isdir(norm_csv_dir):
        available_csvs = sorted(glob.glob(os.path.join(norm_csv_dir, "*.csv")))

    # Check if a specific file was requested from the converter tab
    requested_file = st.session_state.pop("viewer_selected_file", None)
    if requested_file and os.path.isfile(requested_file):
        norm_req = normalize_path(requested_file)
        if norm_req not in [normalize_path(p) for p in available_csvs]:
            available_csvs.insert(0, norm_req)

    if available_csvs:
        csv_map = {os.path.basename(p): p for p in available_csvs}
        options = list(csv_map.keys())

        # Determine which index to show
        default_index = 0
        if requested_file:
            req_base = os.path.basename(requested_file)
            if req_base in options:
                default_index = options.index(req_base)
                st.session_state["active_view_file"] = req_base
        elif "active_view_file" in st.session_state and st.session_state["active_view_file"] in options:
            default_index = options.index(st.session_state["active_view_file"])

        chosen_filename = st.selectbox(
            "Select Converted CSV File to Inspect:",
            options=options,
            index=default_index,
            key="active_view_file",
            format_func=lambda fn: f"{fn} ({os.path.getsize(csv_map[fn]) / 1024:.1f} KB)",
        )
        selected_csv_path = csv_map[chosen_filename]
    else:
        st.warning(f"No `.csv` files found inside `{csv_dir}`. Convert `.evtx` files in the Converter tab first.")
        selected_csv_path = None

    if selected_csv_path and os.path.isfile(selected_csv_path):
        df = load_csv_data(selected_csv_path)

        if df.empty:
            st.info(f"The selected log `{os.path.basename(selected_csv_path)}` contains 0 records.")
        else:
            st.info(
                f"🪵 **Currently Inspecting:** `{os.path.basename(selected_csv_path)}` "
                f"({len(df):,} total event records loaded)",
                icon="📊",
            )

            # ------------------------------------------------------------------
            # KPI SUMMARY CARDS
            # ------------------------------------------------------------------
            st.markdown("---")
            kpi1, kpi2, kpi3, kpi4 = st.columns(4)
            with kpi1:
                st.metric("Total Events", f"{len(df):,}")
            with kpi2:
                unique_event_ids = df["EventID"].nunique() if "EventID" in df.columns else 0
                st.metric("Unique Event IDs", f"{unique_event_ids:,}")
            with kpi3:
                unique_providers = df["Provider"].nunique() if "Provider" in df.columns else 0
                st.metric("Providers", f"{unique_providers:,}")
            with kpi4:
                unique_channels = df["Channel"].nunique() if "Channel" in df.columns else 0
                st.metric("Channels", f"{unique_channels:,}")

            # ------------------------------------------------------------------
            # VISUAL ANALYTICS (PLOTLY)
            # ------------------------------------------------------------------
            st.markdown("---")
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                if "EventID" in df.columns and not df.empty:
                    top_events = (
                        df["EventID"]
                        .astype(str)
                        .value_counts()
                        .head(10)
                        .reset_index()
                    )
                    top_events.columns = ["EventID", "Count"]
                    fig_events = px.bar(
                        top_events,
                        x="EventID",
                        y="Count",
                        title=f"Top 10 Event IDs ({os.path.basename(selected_csv_path)})",
                        text="Count",
                        color="Count",
                        color_continuous_scale="Blues",
                    )
                    fig_events.update_xaxes(type="category")
                    fig_events.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
                    st.plotly_chart(fig_events, use_container_width=True)

            with chart_col2:
                if "Provider" in df.columns and not df.empty:
                    top_providers = (
                        df["Provider"]
                        .astype(str)
                        .value_counts()
                        .head(8)
                        .reset_index()
                    )
                    top_providers.columns = ["Provider", "Count"]
                    fig_prov = px.pie(
                        top_providers,
                        names="Provider",
                        values="Count",
                        title=f"Event Providers Distribution ({os.path.basename(selected_csv_path)})",
                        hole=0.4,
                    )
                    fig_prov.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
                    st.plotly_chart(fig_prov, use_container_width=True)

            # ------------------------------------------------------------------
            # FILTER CONTROLS
            # ------------------------------------------------------------------
            st.markdown("---")
            st.subheader("🔍 Search & Filter Records")

            f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns(5)

            with f_col1:
                search_text = st.text_input("Global Search (all fields):", placeholder="Type user, IP, keyword...")

            with f_col2:
                event_ids = sorted(df["EventID"].unique().tolist()) if "EventID" in df.columns else []
                sel_event_ids = st.multiselect("Event ID:", options=event_ids)

            with f_col3:
                levels = sorted([lvl for lvl in df["LevelName"].unique().tolist() if lvl]) if "LevelName" in df.columns else []
                sel_levels = st.multiselect("Severity Level:", options=levels)

            with f_col4:
                channels = sorted([ch for ch in df["Channel"].unique().tolist() if ch]) if "Channel" in df.columns else []
                sel_channels = st.multiselect("Channel:", options=channels)

            with f_col5:
                providers = sorted([pr for pr in df["Provider"].unique().tolist() if pr]) if "Provider" in df.columns else []
                sel_providers = st.multiselect("Provider:", options=providers)

            # Apply filters
            filtered_df = df.copy()

            if search_text:
                mask = pd.Series(False, index=filtered_df.index)
                for col in filtered_df.columns:
                    mask = mask | filtered_df[col].astype(str).str.contains(search_text, case=False, na=False)
                filtered_df = filtered_df[mask]

            if sel_event_ids:
                filtered_df = filtered_df[filtered_df["EventID"].isin(sel_event_ids)]

            if sel_levels:
                filtered_df = filtered_df[filtered_df["LevelName"].isin(sel_levels)]

            if sel_channels:
                filtered_df = filtered_df[filtered_df["Channel"].isin(sel_channels)]

            if sel_providers:
                filtered_df = filtered_df[filtered_df["Provider"].isin(sel_providers)]

            st.caption(f"Showing **{len(filtered_df):,}** of **{len(df):,}** records")

            # ------------------------------------------------------------------
            # DATA TABLE & EXPORT
            # ------------------------------------------------------------------
            core_cols = [
                "RecordID",
                "TimeCreated",
                "EventID",
                "LevelName",
                "Channel",
                "Provider",
                "Computer",
                "UserID",
                "ProcessID",
                "Task",
                "Keywords",
                "EventData",
                "UserData",
            ]
            display_cols = [c for c in core_cols if c in filtered_df.columns]
            # If any other columns exist, keep them accessible
            remaining_cols = [c for c in filtered_df.columns if c not in display_cols]
            table_cols = display_cols + remaining_cols

            st.dataframe(filtered_df[table_cols], use_container_width=True, height=380)

            csv_bytes = filtered_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label=f"📥 Download Filtered Data as CSV ({len(filtered_df):,} rows)",
                data=csv_bytes,
                file_name=f"filtered_{os.path.basename(selected_csv_path)}",
                mime="text/csv",
            )

            # ------------------------------------------------------------------
            # RECORD DETAIL & JSON PAYLOAD INSPECTOR
            # ------------------------------------------------------------------
            st.markdown("---")
            st.subheader("🔬 Record & EventData Payload Inspector")
            st.caption("Select an individual event RecordID to inspect its full 23 system attributes and structured JSON payloads.")

            if not filtered_df.empty and "RecordID" in filtered_df.columns:
                records_list = filtered_df["RecordID"].astype(str).tolist()
                rec_col, _ = st.columns([2, 2])
                with rec_col:
                    selected_rec_id = st.selectbox("Select RecordID to inspect:", options=records_list)

                chosen_row = filtered_df[filtered_df["RecordID"] == selected_rec_id].iloc[0]

                insp_left, insp_right = st.columns([1, 2])

                with insp_left:
                    st.markdown("##### Full System Metadata")
                    sys_keys = [
                        "RecordID", "TimeCreated", "EventID", "Qualifiers", "Level", "LevelName",
                        "Channel", "Provider", "ProviderGuid", "EventSourceName", "Task", "Opcode",
                        "Keywords", "Computer", "UserID", "ProcessID", "ThreadID", "Version",
                        "ActivityID", "RelatedActivityID", "Message"
                    ]
                    sys_metadata = {k: chosen_row[k] for k in sys_keys if k in chosen_row and str(chosen_row[k]).strip()}
                    st.json(sys_metadata)

                with insp_right:
                    st.markdown("##### Payload Data (EventData & UserData)")
                    raw_event_data = str(chosen_row.get("EventData", "")).strip()
                    raw_user_data = str(chosen_row.get("UserData", "")).strip()

                    payload_tabs = []
                    if raw_event_data:
                        payload_tabs.append("EventData")
                    if raw_user_data:
                        payload_tabs.append("UserData")

                    if payload_tabs:
                        rendered_tabs = st.tabs([f"📦 {t}" for t in payload_tabs])
                        for tab, tname in zip(rendered_tabs, payload_tabs):
                            with tab:
                                content = raw_event_data if tname == "EventData" else raw_user_data
                                try:
                                    parsed = json.loads(content)
                                    def _clean_json_nulls(o: Any) -> Any:
                                        if o is None:
                                            return ""
                                        if isinstance(o, str) and o.strip().lower() in ("null", "none", "nan"):
                                            return ""
                                        if isinstance(o, dict):
                                            return {k: _clean_json_nulls(v) for k, v in o.items()}
                                        if isinstance(o, list):
                                            return [_clean_json_nulls(x) for x in o]
                                        return o
                                    st.json(_clean_json_nulls(parsed))
                                except Exception:
                                    st.code(content, language="json" if content.startswith(("{", "[")) else "text")
                    else:
                        st.info("No EventData or UserData payload attached to this record.")
            else:
                st.info("No records match the current filter criteria.")
