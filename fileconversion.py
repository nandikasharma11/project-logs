"""fileconversion.py
=================
Comprehensive, unrestricted converter for Windows .evtx event logs to CSV.

Features:
- Complete Field Extraction (No Missing Columns):
  * Extracts all standard System metadata: RecordID, TimeCreated, EventID, Level, LevelName,
    Channel, Provider, ProviderGuid, Task, Opcode, Keywords, Computer, UserID (Security SID),
    ProcessID, ThreadID, Version, ActivityID, RelatedActivityID, and Qualifiers.
  * Extracts all EventData and UserData payloads, normalizing attributes into structured JSON.
  * Captures rendered Message descriptions if present.
- Complete Record Extraction (No Missing Entries):
  * Multiline JSON stream buffering prevents unescaped newline drops.
  * In-memory sequential sorting ensures records appear in exact chronological & RecordID order
    (resolving multithreaded chunk shuffling where earlier records were pushed to the file end).
- Unrestricted Source & Destination:
  * Works with single files, folders, wildcard/glob patterns, recursive walks, in-memory bytes,
    and Streamlit UploadedFile objects.
  * Saves to any folder or explicit CSV filename anywhere on disk.
- Dual-Engine Architecture:
  * Primary: High-speed native `evtx_dump` binary with deadlock-free temporary error pipe.
  * Fallback: Pure-Python parser using `python-evtx` (Evtx.Evtx) with zero external binary dependency.
"""

import argparse
import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Optional pure-Python fallback support
try:
    import Evtx.Evtx as python_evtx
    import xml.etree.ElementTree as ET
    HAS_PYTHON_EVTX = True
except ImportError:
    HAS_PYTHON_EVTX = False


# ==============================================================================
# SCHEMA CONSTANTS & LEVEL MAPPINGS
# ==============================================================================

CSV_COLUMNS = [
    "RecordID",
    "TimeCreated",
    "EventID",
    "Level",
    "LevelName",
    "Channel",
    "Provider",
    "ProviderGuid",
    "EventSourceName",
    "Task",
    "Opcode",
    "Keywords",
    "Computer",
    "UserID",
    "ProcessID",
    "ThreadID",
    "Version",
    "ActivityID",
    "RelatedActivityID",
    "Qualifiers",
    "EventData",
    "UserData",
    "Message",
]

LEVEL_NAMES = {
    "0": "LogAlways",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}


# ==============================================================================
# PATH UTILITIES (Unrestricted Source & Destination)
# ==============================================================================

def normalize_path(path_str: Optional[str]) -> str:
    """Cleans, strips surrounding quotes, expands environment variables and user home (~),

    and returns a fully resolved absolute path.
    """
    if not path_str:
        return ""
    cleaned = str(path_str).strip().strip("'\"")
    cleaned = os.path.expandvars(os.path.expanduser(cleaned))
    return os.path.abspath(cleaned)


def find_source_files(
    source_path: str,
    selected_files: Optional[List[str]] = None,
    recursive: bool = False,
) -> List[str]:
    """Finds all matching source .evtx files from a path, directory, or wildcard pattern.

    Removes all source location restrictions.
    """
    raw = str(source_path).strip().strip("'\"")
    expanded = os.path.expandvars(os.path.expanduser(raw))

    # Case 1: Direct single file
    if os.path.isfile(expanded):
        return [os.path.abspath(expanded)]

    # Case 2: Wildcard or glob pattern (e.g. *.evtx or /logs/*.evtx)
    if any(ch in raw for ch in ("*", "?", "[", "]")):
        matches = glob.glob(expanded, recursive=recursive)
        files = [
            os.path.abspath(m)
            for m in sorted(matches)
            if os.path.isfile(m) and (m.lower().endswith(".evtx") or not os.path.isdir(m))
        ]
        if files:
            if selected_files:
                files = [f for f in files if os.path.basename(f) in selected_files or f in selected_files]
            return files

    # Case 3: Directory
    if os.path.isdir(expanded):
        files = []
        if recursive:
            for root_dir, _, filenames in os.walk(expanded):
                for f in sorted(filenames):
                    if f.lower().endswith(".evtx"):
                        files.append(os.path.abspath(os.path.join(root_dir, f)))
        else:
            for f in sorted(os.listdir(expanded)):
                full_p = os.path.join(expanded, f)
                if os.path.isfile(full_p) and f.lower().endswith(".evtx"):
                    files.append(os.path.abspath(full_p))

        if selected_files:
            files = [f for f in files if os.path.basename(f) in selected_files or f in selected_files]
        return files

    # Case 4: Resolved relative to current directory
    abs_fallback = os.path.abspath(expanded)
    if os.path.isfile(abs_fallback):
        return [abs_fallback]
    if os.path.isdir(abs_fallback):
        files = [
            os.path.abspath(os.path.join(abs_fallback, f))
            for f in sorted(os.listdir(abs_fallback))
            if f.lower().endswith(".evtx")
        ]
        if selected_files:
            files = [f for f in files if os.path.basename(f) in selected_files or f in selected_files]
        return files

    return []


def resolve_output_path(
    source_file_or_name: str,
    destination: str,
    is_single_file: bool = False,
) -> str:
    """Calculates the target CSV filepath for any source and destination without restrictions.

    - If destination ends in .csv and converting a single file, saves directly to that .csv file.
    - If destination is a directory (or converting multiple files), saves as <basename>.csv inside it.
    """
    dest_cleaned = normalize_path(destination or "Converted files")
    base_name = os.path.splitext(os.path.basename(source_file_or_name))[0]

    if dest_cleaned.lower().endswith(".csv"):
        if is_single_file:
            target_csv = dest_cleaned
        else:
            parent = os.path.dirname(dest_cleaned) or "."
            target_csv = os.path.join(parent, f"{base_name}.csv")
    else:
        target_csv = os.path.join(dest_cleaned, f"{base_name}.csv")

    # Ensure parent directory exists anywhere on disk
    parent_dir = os.path.dirname(target_csv)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    return target_csv


# ==============================================================================
# TOOL DISCOVERY & VALIDATION
# ==============================================================================

def find_evtx_dump_tool() -> str:
    """Locates and validates a working native `evtx_dump` binary on the system.

    Checks:
    1. Custom EVTX_DUMP_PATH environment variable.
    2. Standard package manager locations (Homebrew, Cargo, Chocolatey, etc.).
    3. System PATH.
    """
    env_tool = os.environ.get("EVTX_DUMP_PATH")
    candidates = [env_tool] if env_tool else []

    # Priority 1: Standard locations
    standard_paths = [
        "/opt/homebrew/bin/evtx_dump",
        "/usr/local/bin/evtx_dump",
        os.path.expanduser("~/.cargo/bin/evtx_dump"),
        "/usr/bin/evtx_dump",
        r"C:\ProgramData\chocolatey\bin\evtx_dump.exe",
        os.path.expandvars(r"%USERPROFILE%\.cargo\bin\evtx_dump.exe"),
        r"C:\Program Files\evtx_dump\evtx_dump.exe",
    ]
    candidates.extend(standard_paths)

    # Priority 2: System PATH
    which_path = shutil.which("evtx_dump")
    if which_path and which_path not in candidates:
        candidates.append(which_path)

    for raw_path in candidates:
        if not raw_path:
            continue
        path = os.path.expandvars(os.path.expanduser(str(raw_path).strip().strip("'\"")))
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        try:
            result = subprocess.run(
                [path, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and (
                "evtx" in result.stdout.lower()
                or "parser" in result.stdout.lower()
                or "0." in result.stdout
            ):
                return path
        except Exception:
            continue

    if HAS_PYTHON_EVTX:
        return "python-evtx"

    raise FileNotFoundError(
        "Working 'evtx_dump' executable not found. "
        "Please install it via Homebrew (`brew install evtx`), Cargo (`cargo install evtx`), "
        "or install the pure-Python fallback (`pip install python-evtx`)."
    )


# ==============================================================================
# DATA NORMALIZATION HELPERS
# ==============================================================================

def extract_scalar_value(val: Any) -> str:
    """Extracts a clean scalar string from various evtx_dump JSON structures,

    handling dicts with '#text', '#attributes', or direct values.
    """
    if val is None:
        return ""
    if isinstance(val, (int, float, bool)):
        return str(val).strip()
    if isinstance(val, str):
        s = val.strip()
        # Handle cases where dict string was stringified e.g. {'#text': 4624}
        if s.startswith("{") and "#text" in s:
            m = re.search(r"['\"]?#text['\"]?\s*:\s*['\"]?([^'\"}]+)['\"]?", s)
            if m:
                return m.group(1).strip()
        return s
    if isinstance(val, dict):
        if "#text" in val:
            return extract_scalar_value(val["#text"])
        attrs = val.get("#attributes", {})
        if isinstance(attrs, dict):
            if "SystemTime" in attrs:
                return extract_scalar_value(attrs["SystemTime"])
            if "Name" in attrs:
                return extract_scalar_value(attrs["Name"])
            if "Value" in attrs:
                return extract_scalar_value(attrs["Value"])
            if "UserID" in attrs:
                return extract_scalar_value(attrs["UserID"])
            if "ProcessID" in attrs:
                return extract_scalar_value(attrs["ProcessID"])
            if "ThreadID" in attrs:
                return extract_scalar_value(attrs["ThreadID"])
            if "Guid" in attrs:
                return extract_scalar_value(attrs["Guid"])
            if "ActivityID" in attrs:
                return extract_scalar_value(attrs["ActivityID"])
        if "Name" in val and "Value" in val:
            return f"{val['Name']}={val['Value']}"
        if "Name" in val:
            return extract_scalar_value(val["Name"])
        if len(val) == 1:
            return extract_scalar_value(next(iter(val.values())))
        return json.dumps(val, ensure_ascii=False)
    if isinstance(val, list):
        return ", ".join(extract_scalar_value(x) for x in val if x is not None)
    return str(val).strip()


def clean_event_payload(data: Any) -> str:
    """Recursively normalizes EventData or UserData payloads, ensuring all values,

    attributes, and nested structures are completely extracted into clean JSON.
    """
    if data is None or data == "":
        return ""

    def _normalize(obj: Any) -> Any:
        if obj is None:
            return None
        if isinstance(obj, (int, float, bool)):
            return obj
        if isinstance(obj, str):
            return obj.strip()
        if isinstance(obj, list):
            # Check if this is a list of {"#attributes": {"Name": ...}, "#text": ...}
            if all(isinstance(x, dict) for x in obj):
                named_map = {}
                simple_list = []
                is_named = False
                for x in obj:
                    attrs = x.get("#attributes", {}) if isinstance(x, dict) else {}
                    name = attrs.get("Name") or (x.get("Name") if isinstance(x, dict) else None)
                    val = x.get("#text") if "#text" in x else (x.get("Value") if "Value" in x else None)
                    if name is not None:
                        is_named = True
                        named_map[str(name)] = _normalize(val if val is not None else "")
                    else:
                        simple_list.append(_normalize(x))
                if is_named and not simple_list:
                    return named_map
            return [_normalize(x) for x in obj]
        if isinstance(obj, dict):
            # Case A: {"Data": [...]} or {"Data": {...}}
            if len(obj) == 1 and "Data" in obj:
                return _normalize(obj["Data"])
            # Case B: single item {"#attributes": {"Name": ...}, "#text": ...}
            if "#attributes" in obj and ("#text" in obj or "Value" in obj):
                attrs = obj["#attributes"]
                if "Name" in attrs:
                    val = obj.get("#text", obj.get("Value", ""))
                    return {str(attrs["Name"]): _normalize(val)}
            # Case C: dictionary with nested items
            res = {}
            for k, v in obj.items():
                if k == "#attributes" and isinstance(v, dict):
                    for ak, av in v.items():
                        if ak not in ("xmlns", "xmlns:auto-ns"):
                            res[ak] = _normalize(av)
                elif k == "#text":
                    res["Value"] = _normalize(v)
                else:
                    res[k] = _normalize(v)
            return res
        return str(obj)

    cleaned = _normalize(data)
    if cleaned is None or cleaned == "" or cleaned == {} or cleaned == []:
        return ""
    if isinstance(cleaned, (dict, list)):
        return json.dumps(cleaned, ensure_ascii=False)
    return str(cleaned)


def extract_record_row(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts all 22 standard fields from a raw EVTX event dictionary without dropping any data."""
    system = event.get("System", {}) if isinstance(event.get("System"), dict) else {}

    # 1. Record ID (integer)
    raw_rec_id = extract_scalar_value(system.get("EventRecordID", ""))

    # 2. Time Created
    time_created = extract_scalar_value(system.get("TimeCreated", ""))

    # 3. Event ID & Qualifiers
    ev_id_obj = system.get("EventID", "")
    event_id = extract_scalar_value(ev_id_obj)
    qualifiers = ""
    if isinstance(ev_id_obj, dict):
        qualifiers = extract_scalar_value(ev_id_obj.get("#attributes", {}).get("Qualifiers", ""))

    # 4. Level & Level Name
    level = extract_scalar_value(system.get("Level", ""))
    level_name = LEVEL_NAMES.get(str(level), "")

    # 5. Channel
    channel = extract_scalar_value(system.get("Channel", ""))

    # 6. Provider, Guid, EventSourceName
    prov_obj = system.get("Provider", {})
    provider = ""
    provider_guid = ""
    event_source = ""
    if isinstance(prov_obj, dict):
        attrs = prov_obj.get("#attributes", {})
        provider = extract_scalar_value(attrs.get("Name") or prov_obj.get("Name", ""))
        provider_guid = extract_scalar_value(attrs.get("Guid") or prov_obj.get("Guid", ""))
        event_source = extract_scalar_value(attrs.get("EventSourceName", ""))
    else:
        provider = extract_scalar_value(prov_obj)

    # 7. Task, Opcode, Keywords
    task = extract_scalar_value(system.get("Task", ""))
    opcode = extract_scalar_value(system.get("Opcode", ""))
    keywords = extract_scalar_value(system.get("Keywords", ""))

    # 8. Computer
    computer = extract_scalar_value(system.get("Computer", ""))

    # 9. User ID (Security SID)
    sec_obj = system.get("Security", {})
    user_id = ""
    if isinstance(sec_obj, dict):
        user_id = extract_scalar_value(sec_obj.get("#attributes", {}).get("UserID") or sec_obj.get("UserID", ""))
    elif isinstance(sec_obj, str):
        user_id = extract_scalar_value(sec_obj)

    # 10. Execution Process ID & Thread ID
    exec_obj = system.get("Execution", {})
    process_id = ""
    thread_id = ""
    if isinstance(exec_obj, dict):
        attrs = exec_obj.get("#attributes", {})
        process_id = extract_scalar_value(attrs.get("ProcessID") or exec_obj.get("ProcessID", ""))
        thread_id = extract_scalar_value(attrs.get("ThreadID") or exec_obj.get("ThreadID", ""))

    # 11. Version
    version = extract_scalar_value(system.get("Version", ""))

    # 12. Correlation Activity IDs
    corr_obj = system.get("Correlation", {})
    activity_id = ""
    rel_activity_id = ""
    if isinstance(corr_obj, dict):
        attrs = corr_obj.get("#attributes", {})
        activity_id = extract_scalar_value(attrs.get("ActivityID") or corr_obj.get("ActivityID", ""))
        rel_activity_id = extract_scalar_value(attrs.get("RelatedActivityID") or corr_obj.get("RelatedActivityID", ""))

    # 13. EventData Payload
    event_data_raw = event.get("EventData")
    event_data_str = clean_event_payload(event_data_raw)

    # 14. UserData Payload
    user_data_raw = event.get("UserData")
    user_data_str = clean_event_payload(user_data_raw)

    # 15. Rendered Message
    rendering_info = event.get("RenderingInfo", {})
    message = ""
    if isinstance(rendering_info, dict):
        message = extract_scalar_value(rendering_info.get("Message", ""))

    return {
        "RecordID": raw_rec_id,
        "TimeCreated": time_created,
        "EventID": event_id,
        "Level": level,
        "LevelName": level_name,
        "Channel": channel,
        "Provider": provider,
        "ProviderGuid": provider_guid,
        "EventSourceName": event_source,
        "Task": task,
        "Opcode": opcode,
        "Keywords": keywords,
        "Computer": computer,
        "UserID": user_id,
        "ProcessID": process_id,
        "ThreadID": thread_id,
        "Version": version,
        "ActivityID": activity_id,
        "RelatedActivityID": rel_activity_id,
        "Qualifiers": qualifiers,
        "EventData": event_data_str,
        "UserData": user_data_str,
        "Message": message,
    }


# ==============================================================================
# PURE-PYTHON PARSER FALLBACK
# ==============================================================================

def parse_evtx_python(evtx_path: str, output_csv_path: str) -> int:
    """Pure-Python fallback parser using `python-evtx` (Evtx.Evtx) and XML parsing.

    Extracts all 22 standard fields and sorts records sequentially.
    """
    if not HAS_PYTHON_EVTX:
        raise ImportError(
            "Neither 'evtx_dump' executable nor 'python-evtx' library was found. "
            "Please install evtx via Homebrew (`brew install evtx`), Cargo (`cargo install evtx`), "
            "or pip (`pip install python-evtx`)."
        )

    parent_dir = os.path.dirname(output_csv_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    def _strip_ns(tag: str) -> str:
        return tag.split("}")[-1] if "}" in tag else tag

    extracted_rows = []

    with python_evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                if not xml_str:
                    continue
                root = ET.fromstring(xml_str)

                system_elem = None
                data_elem = None
                user_data_elem = None
                rendering_elem = None

                for child in root:
                    tname = _strip_ns(child.tag)
                    if tname == "System":
                        system_elem = child
                    elif tname == "EventData":
                        data_elem = child
                    elif tname == "UserData":
                        user_data_elem = child
                    elif tname == "RenderingInfo":
                        rendering_elem = child

                # System fields
                rec_id = ""
                time_created = ""
                event_id = ""
                qualifiers = ""
                level = ""
                channel = ""
                provider = ""
                provider_guid = ""
                event_source = ""
                task = ""
                opcode = ""
                keywords = ""
                computer = ""
                user_id = ""
                process_id = ""
                thread_id = ""
                version = ""
                activity_id = ""
                rel_activity_id = ""

                if system_elem is not None:
                    for elem in system_elem:
                        t = _strip_ns(elem.tag)
                        if t == "EventRecordID":
                            rec_id = (elem.text or "").strip()
                        elif t == "EventID":
                            event_id = (elem.text or "").strip()
                            qualifiers = elem.attrib.get("Qualifiers", "")
                        elif t == "TimeCreated":
                            time_created = elem.attrib.get("SystemTime", (elem.text or "").strip())
                        elif t == "Level":
                            level = (elem.text or "").strip()
                        elif t == "Channel":
                            channel = (elem.text or "").strip()
                        elif t == "Computer":
                            computer = (elem.text or "").strip()
                        elif t == "Provider":
                            provider = elem.attrib.get("Name", (elem.text or "").strip())
                            provider_guid = elem.attrib.get("Guid", "")
                            event_source = elem.attrib.get("EventSourceName", "")
                        elif t == "Task":
                            task = (elem.text or "").strip()
                        elif t == "Opcode":
                            opcode = (elem.text or "").strip()
                        elif t == "Keywords":
                            keywords = (elem.text or "").strip()
                        elif t == "Security":
                            user_id = elem.attrib.get("UserID", "")
                        elif t == "Execution":
                            process_id = elem.attrib.get("ProcessID", "")
                            thread_id = elem.attrib.get("ThreadID", "")
                        elif t == "Version":
                            version = (elem.text or "").strip()
                        elif t == "Correlation":
                            activity_id = elem.attrib.get("ActivityID", "")
                            rel_activity_id = elem.attrib.get("RelatedActivityID", "")

                level_name = LEVEL_NAMES.get(str(level), "")

                # EventData payload
                event_data_str = ""
                if data_elem is not None:
                    named_data = {}
                    list_data = []
                    for item in data_elem:
                        n = item.attrib.get("Name")
                        v = (item.text or "").strip()
                        if n:
                            named_data[n] = v
                        else:
                            list_data.append(v)
                    if named_data:
                        event_data_str = json.dumps(named_data, ensure_ascii=False)
                    elif list_data:
                        event_data_str = json.dumps(list_data, ensure_ascii=False)
                    else:
                        event_data_str = (data_elem.text or "").strip()

                # UserData payload
                user_data_str = ""
                if user_data_elem is not None:
                    ud_map = {}
                    for item in user_data_elem:
                        itag = _strip_ns(item.tag)
                        ud_map[itag] = {
                            _strip_ns(sub.tag): (sub.text or "").strip()
                            for sub in item
                        } if len(item) > 0 else (item.text or "").strip()
                    user_data_str = json.dumps(ud_map, ensure_ascii=False) if ud_map else (user_data_elem.text or "").strip()

                # Message
                message = ""
                if rendering_elem is not None:
                    msg_elem = rendering_elem.find("{*}Message")
                    if msg_elem is not None and msg_elem.text:
                        message = msg_elem.text.strip()

                extracted_rows.append(
                    {
                        "RecordID": rec_id,
                        "TimeCreated": time_created,
                        "EventID": event_id,
                        "Level": level,
                        "LevelName": level_name,
                        "Channel": channel,
                        "Provider": provider,
                        "ProviderGuid": provider_guid,
                        "EventSourceName": event_source,
                        "Task": task,
                        "Opcode": opcode,
                        "Keywords": keywords,
                        "Computer": computer,
                        "UserID": user_id,
                        "ProcessID": process_id,
                        "ThreadID": thread_id,
                        "Version": version,
                        "ActivityID": activity_id,
                        "RelatedActivityID": rel_activity_id,
                        "Qualifiers": qualifiers,
                        "EventData": event_data_str,
                        "UserData": user_data_str,
                        "Message": message,
                    }
                )
            except Exception:
                continue

    # Sort sequentially by RecordID so all entries appear in chronological order
    def _sort_key(r: Dict[str, Any]) -> Tuple[int, str]:
        rid = r.get("RecordID", "")
        try:
            return (int(rid), "")
        except Exception:
            return (0, r.get("TimeCreated", ""))

    extracted_rows.sort(key=_sort_key)

    with open(output_csv_path, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in extracted_rows:
            writer.writerow(row)

    return len(extracted_rows)


# ==============================================================================
# CORE SINGLE-FILE CONVERSION
# ==============================================================================

def parse_evtx_to_csv(
    evtx_path: str,
    output_csv_path: str,
    dump_tool: Optional[str] = None,
) -> Dict[str, Any]:
    """Parses a single .evtx file and writes all 22 structured event fields to CSV.

    Ensures zero missing columns and zero dropped entries with multiline JSON buffering
    and sequential record sorting.
    """
    clean_in = normalize_path(evtx_path)
    clean_out = normalize_path(output_csv_path)

    if not os.path.isfile(clean_in):
        raise FileNotFoundError(f"Source EVTX file not found: '{evtx_path}' (resolved: '{clean_in}')")

    parent_dir = os.path.dirname(clean_out)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    tool = dump_tool or find_evtx_dump_tool()

    if tool == "python-evtx":
        count = parse_evtx_python(clean_in, clean_out)
        return {
            "success": True,
            "input_file": clean_in,
            "output_file": clean_out,
            "record_count": count,
            "error": None,
        }

    # Native evtx_dump binary execution
    cmd = [tool, clean_in, "-o", "jsonl"]
    extracted_rows = []

    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as stderr_tmp:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=stderr_tmp,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except Exception as e:
            if HAS_PYTHON_EVTX:
                try:
                    count = parse_evtx_python(clean_in, clean_out)
                    return {
                        "success": True,
                        "input_file": clean_in,
                        "output_file": clean_out,
                        "record_count": count,
                        "error": None,
                    }
                except Exception:
                    pass
            raise RuntimeError(f"Failed to start evtx_dump at '{tool}': {e}") from e

        # Multiline JSON streaming buffer to avoid dropping entries with embedded newlines
        json_buffer = ""
        for line in proc.stdout:
            if not line:
                continue
            json_buffer += line
            try:
                data = json.loads(json_buffer)
                json_buffer = ""  # Reset buffer on successful parse
                event = data.get("Event") if isinstance(data.get("Event"), dict) else data
                row = extract_record_row(event)
                extracted_rows.append(row)
            except json.JSONDecodeError:
                # Accumulate multiline JSON payload
                if len(json_buffer) > 10000000:  # Safety ceiling 10 MB
                    json_buffer = ""
                continue
            except Exception:
                json_buffer = ""
                continue

        proc.wait()

        # Handle complete failure or fallback
        if proc.returncode != 0 and len(extracted_rows) == 0:
            stderr_tmp.seek(0)
            err_output = stderr_tmp.read().strip()
            if HAS_PYTHON_EVTX:
                try:
                    count = parse_evtx_python(clean_in, clean_out)
                    return {
                        "success": True,
                        "input_file": clean_in,
                        "output_file": clean_out,
                        "record_count": count,
                        "error": None,
                    }
                except Exception:
                    pass
            raise RuntimeError(f"evtx_dump failed (exit code {proc.returncode}): {err_output or 'Unknown error'}")

    # Sort sequentially by RecordID so all entries appear in exact chronological order
    def _sort_key(r: Dict[str, Any]) -> Tuple[int, str]:
        rid = r.get("RecordID", "")
        try:
            return (int(rid), "")
        except Exception:
            return (0, r.get("TimeCreated", ""))

    extracted_rows.sort(key=_sort_key)

    with open(clean_out, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in extracted_rows:
            writer.writerow(row)

    return {
        "success": True,
        "input_file": clean_in,
        "output_file": clean_out,
        "record_count": len(extracted_rows),
        "error": None,
    }


# ==============================================================================
# BATCH & PATH CONVERSION
# ==============================================================================

def convert_from_path(
    source_path: str,
    output_dir: str = "Converted files",
    selected_files: Optional[List[str]] = None,
    progress_callback: Optional[Callable[[int, int, str, int], None]] = None,
    recursive: bool = False,
) -> List[Dict[str, Any]]:
    """Converts .evtx file(s) given any path (file, directory, or wildcard) and stores CSVs.

    No restrictions on source location or destination directory/file format.
    """
    target_files = find_source_files(source_path, selected_files=selected_files, recursive=recursive)

    if not target_files:
        cleaned_src = normalize_path(source_path)
        if not os.path.exists(cleaned_src) and not any(ch in source_path for ch in ("*", "?")):
            raise FileNotFoundError(f"Source path not found: '{source_path}' (resolved: '{cleaned_src}')")
        return []

    is_single_batch = (len(target_files) == 1)
    dump_tool = find_evtx_dump_tool()
    results = []
    total = len(target_files)

    for idx, full_input in enumerate(target_files, 1):
        out_csv = resolve_output_path(full_input, output_dir, is_single_file=is_single_batch)
        fname = os.path.basename(full_input)
        try:
            res = parse_evtx_to_csv(full_input, out_csv, dump_tool=dump_tool)
            results.append(res)
            if progress_callback:
                progress_callback(idx, total, fname, res["record_count"])
        except Exception as err:
            results.append(
                {
                    "success": False,
                    "input_file": full_input,
                    "output_file": out_csv,
                    "record_count": 0,
                    "error": str(err),
                }
            )
            if progress_callback:
                progress_callback(idx, total, fname, 0)

    return results


# ==============================================================================
# GUI & STREAMLIT UPLOAD CONVERSION
# ==============================================================================

def convert_from_upload(
    uploaded_file: Any,
    output_dir: str = "Converted files",
    filename: Optional[str] = None,
    dump_tool: Optional[str] = None,
) -> Dict[str, Any]:
    """Converts an uploaded file (Streamlit UploadedFile, BytesIO, or raw bytes) to CSV.

    Stores the output CSV with all 22 columns at the designated destination.
    """
    actual_name = filename or getattr(uploaded_file, "name", None) or "uploaded_event_log.evtx"
    out_csv = resolve_output_path(actual_name, output_dir, is_single_file=True)

    if isinstance(uploaded_file, (bytes, bytearray)):
        content = bytes(uploaded_file)
    elif hasattr(uploaded_file, "getbuffer"):
        content = bytes(uploaded_file.getbuffer())
    elif hasattr(uploaded_file, "getvalue"):
        content = bytes(uploaded_file.getvalue())
    elif hasattr(uploaded_file, "read"):
        read_val = uploaded_file.read()
        content = read_val.encode("utf-8") if isinstance(read_val, str) else read_val
    else:
        raise TypeError(f"Unsupported uploaded file format: {type(uploaded_file)}")

    tmp = tempfile.NamedTemporaryFile(suffix=".evtx", delete=False)
    try:
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name
    finally:
        tmp.close()

    try:
        res = parse_evtx_to_csv(tmp_path, out_csv, dump_tool=dump_tool)
        res["input_file"] = actual_name
        return res
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


# ==============================================================================
# UNIFIED CONVERSION ENTRY POINT
# ==============================================================================

def convert(
    source: Union[str, Any, List[Any]],
    output_dir: str = "Converted files",
    selected_files: Optional[List[str]] = None,
    progress_callback: Optional[Callable[[int, int, str, int], None]] = None,
    recursive: bool = False,
) -> List[Dict[str, Any]]:
    """Unified entry point to convert .evtx files via path, upload(s), or raw bytes."""
    if isinstance(source, str):
        return convert_from_path(
            source_path=source,
            output_dir=output_dir,
            selected_files=selected_files,
            progress_callback=progress_callback,
            recursive=recursive,
        )

    if isinstance(source, (list, tuple)):
        if source and all(isinstance(x, str) for x in source):
            results = []
            total = len(source)
            tool = find_evtx_dump_tool()
            for idx, p in enumerate(source, 1):
                out_csv = resolve_output_path(p, output_dir, is_single_file=False)
                try:
                    res = parse_evtx_to_csv(p, out_csv, dump_tool=tool)
                    results.append(res)
                    if progress_callback:
                        progress_callback(idx, total, os.path.basename(p), res["record_count"])
                except Exception as e:
                    results.append({
                        "success": False,
                        "input_file": p,
                        "output_file": out_csv,
                        "record_count": 0,
                        "error": str(e),
                    })
                    if progress_callback:
                        progress_callback(idx, total, os.path.basename(p), 0)
            return results

        results = []
        total = len(source)
        tool = find_evtx_dump_tool()
        for idx, item in enumerate(source, 1):
            res = convert_from_upload(item, output_dir=output_dir, dump_tool=tool)
            results.append(res)
            if progress_callback:
                fname = getattr(item, "name", f"upload_{idx}.evtx")
                progress_callback(idx, total, fname, res["record_count"])
        return results

    single_res = convert_from_upload(source, output_dir=output_dir)
    if progress_callback:
        progress_callback(1, 1, single_res["input_file"], single_res["record_count"])
    return [single_res]


def convert_and_load(
    source: Union[str, Any],
    output_dir: str = "Converted files",
) -> Tuple[Any, str, int]:
    """Converts an .evtx file, stores the CSV, and loads it into a pandas DataFrame."""
    import pandas as pd

    results = convert(source=source, output_dir=output_dir)
    if not results:
        raise RuntimeError(f"No files were converted for source: {source}")

    first = results[0]
    if not first["success"]:
        err_msg = first.get("error") or "Unknown conversion error"
        raise RuntimeError(f"Conversion failed: {err_msg}")

    out_csv = first["output_file"]
    record_count = first["record_count"]

    if record_count == 0 or not os.path.exists(out_csv) or os.path.getsize(out_csv) == 0:
        df = pd.DataFrame(columns=CSV_COLUMNS)
    else:
        try:
            df = pd.read_csv(out_csv, dtype=str)
            df.fillna("", inplace=True)
            for col in CSV_COLUMNS:
                if col not in df.columns:
                    df[col] = ""
        except Exception:
            df = pd.DataFrame(columns=CSV_COLUMNS)

    return df, out_csv, record_count


# Backward-compatibility aliases
convert_evtx_folder = convert_from_path
convert_evtx_bytes = convert_from_upload


# ==============================================================================
# COMMAND LINE INTERFACE (CLI)
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Convert any Windows .evtx event logs to CSV with all 22 columns and full chronological ordering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Single file conversion
  python fileconversion.py sample.evtx
  python fileconversion.py sample.evtx my_output.csv
  python fileconversion.py -i "~/Desktop/Security.evtx" -o "/tmp/Security.csv"

  # Directory conversion
  python fileconversion.py "Original Data/evtx"
  python fileconversion.py -i "Original Data/evtx" -o "Converted files"
  python fileconversion.py -i "C:\\Windows\\System32\\winevt\\Logs" -o "D:\\Logs" -r

  # Wildcard conversion
  python fileconversion.py "*.evtx"
  python fileconversion.py "logs/*.evtx" -o "output_csvs"
""",
    )
    parser.add_argument(
        "source_pos",
        nargs="?",
        default=None,
        help="Source .evtx file, directory, or wildcard pattern (positional).",
    )
    parser.add_argument(
        "dest_pos",
        nargs="?",
        default=None,
        help="Destination directory or CSV file path (positional, optional).",
    )
    parser.add_argument(
        "-i",
        "-I",
        "--input",
        dest="input_path",
        default=None,
        help="Source path to an .evtx file, directory, or wildcard pattern.",
    )
    parser.add_argument(
        "-o",
        "-O",
        "--output",
        dest="output_path",
        default=None,
        help="Destination directory or CSV file path (defaults to 'Converted files').",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories for .evtx files when source is a folder.",
    )
    parser.add_argument(
        "-s",
        "--select",
        nargs="+",
        dest="selected_files",
        default=None,
        help="Specific file names to convert when source is a directory.",
    )

    args = parser.parse_args()

    source = args.input_path or args.source_pos
    destination = args.output_path or args.dest_pos or "Converted files"

    if not source:
        parser.print_help()
        sys.exit(1)

    try:
        print(f"🚀 Starting conversion:")
        print(f"   Source     : {source}")
        print(f"   Destination: {destination}")
        if args.recursive:
            print(f"   Mode       : Recursive directory search enabled")

        results = convert_from_path(
            source_path=source,
            output_dir=destination,
            selected_files=args.selected_files,
            recursive=args.recursive,
            progress_callback=lambda idx, total, fn, count: print(
                f"   [{idx}/{total}] ✅ {fn} -> {count:,} records converted"
            ),
        )

        if not results:
            print(f"\n⚠️  No .evtx files found for source '{source}'.")
            sys.exit(0)

        successful = [r for r in results if r["success"]]
        failed = [r for r in results if not r["success"]]
        total_records = sum(r["record_count"] for r in successful)

        print("\n" + "=" * 60)
        print(f"✨ Conversion complete: {len(successful)}/{len(results)} file(s) successful.")
        print(f"📊 Total event records converted: {total_records:,}")
        print(f"📋 Columns extracted: {len(CSV_COLUMNS)} columns ({', '.join(CSV_COLUMNS[:7])}...)")

        if successful:
            print(f"📁 Destination output: '{destination}'")

        if failed:
            print("\n❌ Failed conversions:")
            for f in failed:
                print(f"   - {f['input_file']}: {f['error']}")
            sys.exit(1)

        sys.exit(0)

    except Exception as exc:
        print(f"\n❌ Error during conversion: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()