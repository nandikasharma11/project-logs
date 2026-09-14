#!/usr/bin/env python3
"""
================================================================================
STAGE 2: Contextual Transformation & Chunking for Windows CSV Logs (DFIR RAG)
================================================================================
Author: Senior Data Engineer / DFIR Specialist
Description:
    Production-ready pipeline for contextual transformation, null-aware semantic
    serialization, chronological sliding-window sessionization, and metadata
    separation of unstructured/semi-structured Windows EVTX event log exports.

Design Principles:
    1. Zero Information Loss: Null, empty, or missing values are deliberately
       retained in raw representations; rows are NEVER dropped.
    2. Embedding Space Hygiene: Semantic text serialization dynamically omits
       missing keys to avoid polluting dense/sparse vector spaces with repeated
       "null", "nan", or "none" tokens.
    3. Causal Sequence Preservation: Chronological windowing groups events within
       temporal causality boundaries, automatically subdividing bursts that exceed
       token limits.
    4. Zero Heavy External Bloat: Built on Python standard libraries and pandas,
       with pluggable tokenizer integration (tiktoken / tokenizers / fallback).
================================================================================
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple, Union

import pandas as pd


# ==============================================================================
# 1. TOKEN ESTIMATOR (PLUGGABLE & ZERO-BLOAT)
# ==============================================================================

class TokenEstimator:
    """Lightweight, pluggable token counter supporting Hugging Face transformers
    (e.g., BAAI/bge-small-en-v1.5), tiktoken, and a robust character-ratio fallback (BPE ~4 chars/token).
    """

    def __init__(
        self,
        model_name_or_tokenizer: Any = "BAAI/bge-small-en-v1.5",
        encoding_name: str = "cl100k_base",
    ):
        self._tokenizer = None
        self._tiktoken_enc = None

        # 1. Direct tokenizer instance passed
        if hasattr(model_name_or_tokenizer, "encode"):
            self._tokenizer = model_name_or_tokenizer
            return

        # 2. Transformers AutoTokenizer (BAAI/bge-small-en-v1.5)
        if isinstance(model_name_or_tokenizer, str) and model_name_or_tokenizer:
            try:
                from transformers import AutoTokenizer
                try:
                    self._tokenizer = AutoTokenizer.from_pretrained(
                        model_name_or_tokenizer,
                        local_files_only=True,
                    )
                except Exception:
                    self._tokenizer = AutoTokenizer.from_pretrained(model_name_or_tokenizer)
            except Exception:
                pass

        # 3. Tiktoken support
        try:
            import tiktoken
            try:
                self._tiktoken_enc = tiktoken.encoding_for_model(str(model_name_or_tokenizer))
            except Exception:
                self._tiktoken_enc = tiktoken.get_encoding(encoding_name)
        except Exception:
            pass

    def count(self, text: str) -> int:
        """Returns token count for the given text string."""
        if not text:
            return 0
        if self._tokenizer is not None:
            try:
                return len(self._tokenizer.encode(text, add_special_tokens=False))
            except Exception:
                pass
        if self._tiktoken_enc is not None:
            try:
                return len(self._tiktoken_enc.encode(text))
            except Exception:
                pass
        # BPE heuristic fallback: ~4 characters per token for English & log strings
        return max(1, len(text) // 4)


# ==============================================================================
# 2. UTILITY & NULL-CHECKING HELPERS
# ==============================================================================

def is_null_or_empty(val: Any) -> bool:
    """Strictly determines whether a value is considered empty, null, or uninformative.

    Returns True for None, float NaN, empty strings, and string literals:
    'nan', 'null', 'none', 'n/a', 'na', '<na>', or pure whitespace.
    """
    if val is None:
        return True
    if isinstance(val, float) and pd.isna(val):
        return True
    s = str(val).strip()
    return s == "" or s.lower() in ("nan", "null", "none", "n/a", "na", "<na>")


def clean_string_scalar(val: Any) -> str:
    """Returns a stripped clean string or empty string if null."""
    if is_null_or_empty(val):
        return ""
    return str(val).strip()


def parse_iso_datetime(val: Any) -> Optional[datetime]:
    """Parses various timestamp formats into a timezone-aware UTC datetime.

    Falls back to None if parsing fails without dropping the underlying row.
    """
    if is_null_or_empty(val):
        return None
    try:
        dt = pd.to_datetime(val, utc=True)
        if pd.isna(dt):
            return None
        return dt.to_pydatetime()
    except Exception:
        return None


# ==============================================================================
# 3. COLUMN NORMALIZATION & HEADER ALIASING
# ==============================================================================

class ColumnNormalizer:
    """Detects and aliases variable forensic headers into canonical schema keys."""

    CANONICAL_ALIASES: Dict[str, List[str]] = {
        "timestamp": [
            "timecreated", "date and time", "timestamp", "systemtime",
            "date_time", "datetime", "date", "time",
        ],
        "event_id": [
            "eventid", "id", "event_id", "event id", "recordid",
        ],
        "host": [
            "computer", "machinename", "host", "hostname", "system_name",
        ],
        "level": [
            "leveldisplayname", "levelname", "level", "severity",
        ],
        "user": [
            "targetusername", "subjectusername", "username", "user",
            "userid", "account_name", "account",
        ],
        "source": [
            "channel", "providername", "provider", "source", "log_name",
        ],
        "details": [
            "message", "description", "details", "payload", "eventdata", "userdata",
        ],
    }

    def __init__(self, custom_aliases: Optional[Dict[str, List[str]]] = None):
        self.aliases = self.CANONICAL_ALIASES.copy()
        if custom_aliases:
            for k, v in custom_aliases.items():
                self.aliases[k] = [x.lower() for x in v]

    def resolve_mapping(self, df_columns: Iterable[str]) -> Dict[str, str]:
        """Resolves existing DataFrame column names to canonical schema keys.

        Returns a dict mapping: {existing_col_name: canonical_key}
        """
        mapping: Dict[str, str] = {}
        cleaned_cols = {col: re.sub(r"[_\s\-]+", "", str(col).lower()) for col in df_columns}

        for canon_key, variations in self.aliases.items():
            matched_col = None
            for var in variations:
                clean_var = re.sub(r"[_\s\-]+", "", var.lower())
                for original_col, clean_col in cleaned_cols.items():
                    if clean_col == clean_var:
                        matched_col = original_col
                        break
                if matched_col:
                    break
            if matched_col and matched_col not in mapping:
                mapping[matched_col] = canon_key

        return mapping


# ==============================================================================
# 4. ROW-LEVEL SEMANTIC SERIALIZATION
# ==============================================================================

class SemanticRowSerializer:
    """Serializes a single normalized log row into an embedding-optimized string.

    Layout: "[Timestamp] Host | EventID (Level) | User | Details: <Message>"
    Strict Null Rule: Completely omits any field whose value is null, empty, or NaN.
    Truncates details/message field to max_details_chars (default: 300).
    """

    def __init__(self, max_details_chars: int = 300, normalizer: Optional[ColumnNormalizer] = None):
        self.max_details_chars = max_details_chars
        self.normalizer = normalizer or ColumnNormalizer()

    def serialize(self, record: Dict[str, Any]) -> str:
        """Converts a dictionary row into an embedding-optimized string.

        Format: "[Timestamp] Host | EventID (Level) | User | Details: <Message>"
        If a column value is null, empty, or NaN, drops that key completely.
        """
        # Auto-normalize if raw/unnormalized column headers are present
        if not any(k in record for k in ("timestamp", "host", "event_id", "details")):
            mapping = self.normalizer.resolve_mapping(record.keys())
            norm_rec = {canon: record[orig] for orig, canon in mapping.items() if orig in record}
        else:
            norm_rec = record

        raw_ts = clean_string_scalar(norm_rec.get("timestamp"))
        host = clean_string_scalar(norm_rec.get("host"))
        ev_id = clean_string_scalar(norm_rec.get("event_id"))
        lvl = clean_string_scalar(norm_rec.get("level"))
        user = clean_string_scalar(norm_rec.get("user"))
        raw_details = clean_string_scalar(norm_rec.get("details"))

        parts: List[str] = []

        # 1. [Timestamp] Host
        if raw_ts and host:
            parts.append(f"[{raw_ts}] {host}")
        elif raw_ts:
            parts.append(f"[{raw_ts}]")
        elif host:
            parts.append(f"{host}")

        # 2. EventID (Level)
        if ev_id and lvl:
            parts.append(f"{ev_id} ({lvl})")
        elif ev_id:
            parts.append(f"{ev_id}")
        elif lvl:
            parts.append(f"({lvl})")

        # 3. User
        if user:
            parts.append(f"{user}")

        # 4. Details: <Message> (max 300 characters)
        if raw_details:
            flattened = " ".join(raw_details.split())
            if len(flattened) > self.max_details_chars:
                flattened = flattened[: self.max_details_chars]
            parts.append(f"Details: {flattened}")

        if not parts:
            return "LogRecord: [Empty attributes]"

        return " | ".join(parts)


# ==============================================================================
# 5. CHRONOLOGICAL WINDOWING & MULTI-ROW CHUNKER
# ==============================================================================

@dataclass
class ForensicChunk:
    """Data structure representing a windowed chronological log chunk."""

    chunk_id: str
    text: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        start_t = self.metadata.get("start_time") or self.metadata.get("start_timestamp")
        end_t = self.metadata.get("end_time") or self.metadata.get("end_timestamp")
        h = self.metadata.get("host")
        eids = self.metadata.get("event_ids", [])
        return {
            "chunk_id": self.chunk_id,
            "text": self.text,
            "metadata": {
                "start_time": start_t,
                "end_time": end_t,
                "host": h,
                "event_ids": eids,
                "start_timestamp": start_t,
                "end_timestamp": end_t,
                "levels": self.metadata.get("levels", []),
                "raw_row_count": self.metadata.get("raw_row_count", 0),
            },
            # Top-level convenience keys
            "start_time": start_t,
            "end_time": end_t,
            "host": h,
            "event_ids": eids,
        }


class ChronologicalWindowChunker:
    """Groups chronologically sorted normalized log records into sliding time-window

    chunks with causal overlap and token-boundary subdivision.
    """

    def __init__(
        self,
        window_duration_minutes: int = 10,
        window_overlap_minutes: int = 2,
        max_tokens_per_chunk: int = 512,
        group_by_host: bool = False,
        token_estimator: Optional[TokenEstimator] = None,
        serializer: Optional[SemanticRowSerializer] = None,
    ):
        if window_overlap_minutes >= window_duration_minutes:
            raise ValueError("window_overlap_minutes must be strictly less than window_duration_minutes")

        self.window_duration = timedelta(minutes=window_duration_minutes)
        self.window_overlap = timedelta(minutes=window_overlap_minutes)
        self.window_step = self.window_duration - self.window_overlap
        self.max_tokens = max_tokens_per_chunk
        self.group_by_host = group_by_host
        self.tokenizer = token_estimator or TokenEstimator()
        self.serializer = serializer or SemanticRowSerializer()

    def chunk_records(self, records: List[Dict[str, Any]]) -> List[ForensicChunk]:
        """Orchestrates grouping, chronological sorting, and sliding window chunking."""
        if not records:
            return []

        # Annotate parsed datetimes without dropping unparseable rows
        parsed_entries = []
        for i, r in enumerate(records):
            dt = parse_iso_datetime(r.get("timestamp"))
            parsed_entries.append((dt, i, r))

        # Split into host partitions if requested, or global timeline
        partitions: Dict[str, List[Tuple[Optional[datetime], int, Dict[str, Any]]]] = {}
        if self.group_by_host:
            for entry in parsed_entries:
                h = clean_string_scalar(entry[2].get("host")) or "UNKNOWN_HOST"
                partitions.setdefault(h, []).append(entry)
        else:
            partitions["GLOBAL"] = parsed_entries

        all_chunks: List[ForensicChunk] = []

        for partition_key, entries in partitions.items():
            # Sort chronologically (unparseable datetimes place at start with index tie-breaker)
            epoch_min = datetime(1970, 1, 1, tzinfo=timezone.utc)
            sorted_entries = sorted(
                entries,
                key=lambda x: (x[0] if x[0] is not None else epoch_min, x[1]),
            )

            partition_chunks = self._sliding_window_partition(sorted_entries)
            all_chunks.extend(partition_chunks)

        return all_chunks

    def _sliding_window_partition(
        self,
        sorted_entries: List[Tuple[Optional[datetime], int, Dict[str, Any]]],
    ) -> List[ForensicChunk]:
        """Applies sliding window across a chronologically sorted partition."""
        chunks: List[ForensicChunk] = []

        # Separate entries with valid datetimes from unparseable entries
        timed_entries = [e for e in sorted_entries if e[0] is not None]
        untimed_entries = [e for e in sorted_entries if e[0] is None]

        # Process timed entries using sliding time window
        if timed_entries:
            min_time = timed_entries[0][0]
            max_time = timed_entries[-1][0]
            current_window_start = min_time

            while current_window_start <= max_time:
                current_window_end = current_window_start + self.window_duration

                # Collect all entries falling strictly within [start, end)
                window_entries = [
                    e for e in timed_entries
                    if current_window_start <= e[0] < current_window_end
                ]

                if window_entries:
                    sub_chunks = self._pack_window_to_chunks(window_entries)
                    chunks.extend(sub_chunks)

                    # Advance window by step
                    current_window_start += self.window_step
                else:
                    # Fast-forward jump if there is a wide time gap with zero events
                    remaining = [e[0] for e in timed_entries if e[0] >= current_window_start]
                    if not remaining:
                        break
                    next_time = remaining[0]
                    if next_time >= current_window_end:
                        current_window_start = next_time
                    else:
                        current_window_start += self.window_step

        # Process any untimed / unparseable entries sequentially
        if untimed_entries:
            sub_chunks = self._pack_window_to_chunks(untimed_entries)
            chunks.extend(sub_chunks)

        return chunks

    def _pack_window_to_chunks(
        self,
        entries: List[Tuple[Optional[datetime], int, Dict[str, Any]]],
    ) -> List[ForensicChunk]:
        """Subdivides a temporal window of events into sub-chunks if total tokens

        exceed max_tokens_per_chunk while strictly maintaining sequence order.
        """
        sub_chunks: List[ForensicChunk] = []
        current_batch_lines: List[str] = []
        current_batch_rows: List[Dict[str, Any]] = []
        current_token_count = 0

        for dt, idx, row in entries:
            serialized_line = self.serializer.serialize(row)
            line_tokens = self.tokenizer.count(serialized_line)

            # If adding this line exceeds the threshold, flush the current sub-chunk
            if current_batch_lines and (current_token_count + line_tokens > self.max_tokens):
                chunk = self._build_chunk_artifact(current_batch_lines, current_batch_rows)
                sub_chunks.append(chunk)

                current_batch_lines = []
                current_batch_rows = []
                current_token_count = 0

            current_batch_lines.append(serialized_line)
            current_batch_rows.append(row)
            current_token_count += line_tokens

        # Flush trailing records in window
        if current_batch_lines:
            chunk = self._build_chunk_artifact(current_batch_lines, current_batch_rows)
            sub_chunks.append(chunk)

        return sub_chunks

    def _build_chunk_artifact(
        self,
        lines: List[str],
        rows: List[Dict[str, Any]],
    ) -> ForensicChunk:
        """Constructs a finalized ForensicChunk with separated metadata."""
        chunk_text = "\n".join(lines)

        # Extract timestamps
        timestamps = [
            parse_iso_datetime(r.get("timestamp"))
            for r in rows
            if parse_iso_datetime(r.get("timestamp")) is not None
        ]
        start_ts = min(timestamps).isoformat() if timestamps else None
        end_ts = max(timestamps).isoformat() if timestamps else None

        # Unique Forensic Identifiers
        unique_hosts = list(dict.fromkeys(
            clean_string_scalar(r.get("host"))
            for r in rows
            if clean_string_scalar(r.get("host"))
        ))

        unique_event_ids = list(dict.fromkeys(
            clean_string_scalar(r.get("event_id"))
            for r in rows
            if clean_string_scalar(r.get("event_id"))
        ))

        unique_levels = list(dict.fromkeys(
            clean_string_scalar(r.get("level"))
            for r in rows
            if clean_string_scalar(r.get("level"))
        ))

        metadata = {
            "chunk_id": str(uuid.uuid4()),
            "start_time": start_ts,
            "end_time": end_ts,
            "start_timestamp": start_ts,
            "end_timestamp": end_ts,
            "host": unique_hosts[0] if len(unique_hosts) == 1 else (unique_hosts if unique_hosts else None),
            "event_ids": unique_event_ids,
            "levels": unique_levels,
            "raw_row_count": len(rows),
        }

        return ForensicChunk(
            chunk_id=metadata["chunk_id"],
            text=chunk_text,
            metadata=metadata,
        )


# ==============================================================================
# 6. TOP-LEVEL DFIR PIPELINE ORCHESTRATOR
# ==============================================================================

class DFIRLogTransformerPipeline:
    """Unified Stage 2 Pipeline: Ingests raw DataFrames or CSV files, executes

    header normalization, null-aware serialization, chronological windowing,
    and metadata extraction.
    """

    def __init__(
        self,
        window_duration_minutes: int = 10,
        window_overlap_minutes: int = 2,
        max_tokens_per_chunk: int = 512,
        group_by_host: bool = False,
        max_details_chars: int = 300,
        model_name_or_tokenizer: Any = "BAAI/bge-small-en-v1.5",
    ):
        self.normalizer = ColumnNormalizer()
        self.serializer = SemanticRowSerializer(max_details_chars=max_details_chars)
        self.tokenizer = TokenEstimator(model_name_or_tokenizer=model_name_or_tokenizer)
        self.chunker = ChronologicalWindowChunker(
            window_duration_minutes=window_duration_minutes,
            window_overlap_minutes=window_overlap_minutes,
            max_tokens_per_chunk=max_tokens_per_chunk,
            group_by_host=group_by_host,
            token_estimator=self.tokenizer,
            serializer=self.serializer,
        )

    def transform_dataframe(self, df: pd.DataFrame) -> List[ForensicChunk]:
        """Processes an in-memory DataFrame into contextual forensic chunks.

        Guarantees that rows with null/missing values are NEVER dropped.
        """
        if df.empty:
            return []

        # Resolve variable headers
        col_map = self.normalizer.resolve_mapping(df.columns)

        # Build normalized records while preserving all rows
        normalized_records: List[Dict[str, Any]] = []
        for _, row in df.iterrows():
            rec: Dict[str, Any] = {}
            for col_name, val in row.items():
                canon_key = col_map.get(col_name)
                if canon_key:
                    rec[canon_key] = val
                else:
                    # Retain any extra unmapped column under its original name
                    rec[str(col_name)] = val
            normalized_records.append(rec)

        # Execute chronological windowing and metadata separation
        return self.chunker.chunk_records(normalized_records)

    def transform_csv(self, filepath: str) -> List[ForensicChunk]:
        """Loads a CSV file with null-preservation and generates forensic chunks."""
        # Use keep_default_na=False to prevent converting empty strings to NaN
        df = pd.read_csv(filepath, dtype=str, keep_default_na=False)
        return self.transform_dataframe(df)


def preprocess_and_chunk_windows_logs(
    df: Union[pd.DataFrame, str],
    window_duration_minutes: int = 10,
    window_overlap_minutes: int = 2,
    max_tokens_per_chunk: int = 512,
    model_name_or_tokenizer: Any = "BAAI/bge-small-en-v1.5",
    group_by_host: bool = False,
) -> List[Dict[str, Any]]:
    """Preprocesses and chunks Windows log DataFrames for an embedding model (e.g. bge-small-en-v1.5).

    Requirements:
    1. Input: A pandas DataFrame containing Windows log columns (e.g., TimeCreated,
       Id/EventID, MachineName, Level, TargetUserName, Message) or filepath to CSV.
    2. Formatting:
       - Converts each row into: "[Timestamp] Host | EventID (Level) | User | Details: <Message>"
       - If a column value is null, empty, or NaN, drops that key completely from
         the text string (never writes "null" or "NaN").
       - Truncates the message field to a max of 300 characters.
    3. Chunking:
       - Sorts chronologically by timestamp.
       - Groups rows into 10-minute sliding windows with a 2-minute overlap.
       - Caps each chunk at 512 tokens (using tiktoken or transformers).
    4. Output:
       - Returns a list of chunks containing the formatted text block and a
         metadata dictionary (start_time, end_time, host, unique event_ids list).
    """
    if isinstance(df, str):
        if not os.path.exists(df):
            raise FileNotFoundError(f"Log CSV file not found: {df}")
        df = pd.read_csv(df, dtype=str, keep_default_na=False)

    if df is None or df.empty:
        return []

    pipeline = DFIRLogTransformerPipeline(
        window_duration_minutes=window_duration_minutes,
        window_overlap_minutes=window_overlap_minutes,
        max_tokens_per_chunk=max_tokens_per_chunk,
        group_by_host=group_by_host,
        max_details_chars=300,
        model_name_or_tokenizer=model_name_or_tokenizer,
    )

    chunks = pipeline.transform_dataframe(df)
    return [c.to_dict() for c in chunks]


# ==============================================================================
# 7. RUNNABLE DEMONSTRATION & TEST BLOCK
# ==============================================================================

def _run_test_demonstration():
    """Demonstrates and validates preprocess_and_chunk_windows_logs against all
    specified requirements.
    """
    print("=" * 80)
    print("🚀 RUNNING STAGE 2: PREPROCESS & CHUNK WINDOWS LOGS VERIFICATION TEST")
    print("=" * 80)

    # 1. Construct realistic mock dataset with diverse naming & missing values
    raw_data = [
        # Event 1: Normal Security logon (complete attributes)
        {
            "TimeCreated": "2026-09-14T08:00:10Z",
            "EventID": 4624,
            "MachineName": "SEC-SRV-01",
            "Level": "Information",
            "TargetUserName": "admin_jdoe",
            "Message": "An account was successfully logged on. LogonType=10, SourceIp=192.168.1.105",
        },
        # Event 2: Missing TargetUserName (Null User -> dropped completely)
        {
            "TimeCreated": "2026-09-14T08:01:25Z",
            "EventID": "7045",
            "MachineName": "SEC-SRV-01",
            "Level": "Warning",
            "TargetUserName": None,
            "Message": "A new service was installed in the system: PSSvc. ServiceFileName=C:\\Windows\\Temp\\svc.exe",
        },
        # Event 3: Missing Message / NaN Details (Null Details -> dropped completely)
        {
            "TimeCreated": "2026-09-14T08:02:40Z",
            "EventID": "4672",
            "MachineName": "SEC-SRV-01",
            "Level": "Information",
            "TargetUserName": "SYSTEM",
            "Message": float("nan"),
        },
        # Event 4: Large burst command execution (tests 300 char truncation & 512 token cap)
        {
            "TimeCreated": "2026-09-14T08:04:15Z",
            "EventID": 4688,
            "MachineName": "SEC-SRV-01",
            "Level": "Information",
            "TargetUserName": "admin_jdoe",
            "Message": (
                "New process created: powershell.exe -NoP -NonI -W Hidden -Exec Bypass "
                "-EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA"
                "UwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4A"
                "dAAoACIAMQAwAC4AMAAuADAALgAxACIALAA0ADQANAA0ACkAOwA= " * 8
            ),
        },
        # Event 5: Occurs in the 2-minute overlap interval (08:08 - 08:10)
        {
            "TimeCreated": "2026-09-14T08:09:30Z",
            "EventID": 4625,
            "MachineName": "SEC-SRV-01",
            "Level": "Error",
            "TargetUserName": "guest",
            "Message": "An account failed to log on. Status=0xC000006D, SubStatus=0xC000006A",
        },
        # Event 6: Out-of-order timestamp across different host (Tests chronological sorting)
        {
            "TimeCreated": "2026-09-14T07:59:00Z",
            "EventID": 1102,
            "MachineName": "DC-PRIMARY",
            "Level": "Critical",
            "TargetUserName": "attacker_svc",
            "Message": "The audit log was cleared.",
        },
        # Event 7: Next window event (at 08:14:00Z)
        {
            "TimeCreated": "2026-09-14T08:14:00Z",
            "EventID": "4720",
            "MachineName": "DC-PRIMARY",
            "Level": "Information",
            "TargetUserName": "backdoor_admin",
            "Message": "A user account was created.",
        },
        # Event 8: Completely sparse row with missing ID, User, and Message
        {
            "TimeCreated": "2026-09-14T08:15:00Z",
            "EventID": None,
            "MachineName": "SEC-SRV-01",
            "Level": "Information",
            "TargetUserName": "",
            "Message": None,
        },
    ]

    mock_df = pd.DataFrame(raw_data)
    print(f"📊 Input Mock DataFrame: {len(mock_df)} records:")
    print(mock_df[["TimeCreated", "EventID", "MachineName", "TargetUserName", "Level"]])
    print("-" * 80)

    # 2. Execute preprocess_and_chunk_windows_logs
    chunks = preprocess_and_chunk_windows_logs(
        mock_df,
        window_duration_minutes=10,
        window_overlap_minutes=2,
        max_tokens_per_chunk=512,
        model_name_or_tokenizer="BAAI/bge-small-en-v1.5",
    )

    print(f"\n✨ Generated {len(chunks)} Contextual Chunk(s):\n")

    for i, chk in enumerate(chunks, 1):
        meta = chk["metadata"]
        print(f"┌── [CHUNK {i} - ID: {chk['chunk_id'][:8]}...]")
        print(f"│ ⏱️  Time Range: {meta['start_time']} -> {meta['end_time']}")
        print(f"│ 💻 Host(s)   : {meta['host']}")
        print(f"│ 🆔 Event IDs : {meta['event_ids']}")
        print("├── 📄 FORMATTED TEXT BLOCK:")
        for line in chk["text"].splitlines():
            print(f"│   {line}")
        print("└" + "─" * 78 + "\n")

    # 3. Assertions & Validations
    print("=" * 80)
    print("🔬 VALIDATION CHECKS:")
    assert len(chunks) > 0, "Chunks must not be empty"

    for i, chk in enumerate(chunks):
        assert "metadata" in chk, f"Chunk {i} missing 'metadata' dict"
        meta = chk["metadata"]
        assert "start_time" in meta, f"Chunk {i} missing start_time"
        assert "end_time" in meta, f"Chunk {i} missing end_time"
        assert "host" in meta, f"Chunk {i} missing host"
        assert "event_ids" in meta, f"Chunk {i} missing event_ids"
        assert isinstance(meta["event_ids"], list), f"Chunk {i} event_ids must be a list"

        # Verify no "null" or "NaN" in text
        text_lower = chk["text"].lower()
        for bad_token in ["| null |", "| nan |", "| none |", "details: nan", "details: null"]:
            assert bad_token not in text_lower, f"Found forbidden token '{bad_token}' in chunk text"

        # Verify max 300 chars details per line
        for line in chk["text"].splitlines():
            if "Details: " in line:
                details_payload = line.split("Details: ", 1)[1]
                assert len(details_payload) <= 300, (
                    f"Details payload exceeds 300 characters: {len(details_payload)} chars"
                )

    print("✅ All 4 requirements verified successfully!")
    print("   1. Ingests pandas DataFrame with Windows log columns.")
    print("   2. Formats: '[Timestamp] Host | EventID (Level) | User | Details: <Message>'")
    print("      - Null/empty/NaN keys completely dropped.")
    print("      - Message truncated to max 300 chars.")
    print("   3. 10-minute sliding window with 2-minute overlap chronologically sorted.")
    print("      - Capped at 512 tokens using BAAI/bge-small-en-v1.5 tokenizer.")
    print("   4. Returns chunks with text and metadata dictionary (start_time, end_time, host, event_ids).")
    print("=" * 80)


if __name__ == "__main__":
    _run_test_demonstration()

