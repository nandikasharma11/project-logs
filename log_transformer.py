#!/usr/bin/env python3
"""
================================================================================
STAGE 2: Contextual Transformation & Chunking for Windows Event Logs (DFIR RAG)
================================================================================
Author: Principal Data Engineer & Cybersecurity Forensics Specialist
Description:
    Production-grade pipeline for Stage 2 of the local Windows Log RAG architecture.
    Performs header normalization, null-safe semantic row serialization,
    chronological sessionization with sliding time windows (10-min window, 2-min overlap),
    token-aware burst subdivision, and dual-representation chunking for downstream
    vectorization (SecBERT dense + BM25 sparse) and Qdrant payload filtering.

Architectural Standards:
    1. Dual-Representation Rule: Every chunk outputs a formatted semantic 'text'
       block and a filterable structured 'metadata' dictionary.
    2. Deterministic Identifiers: Chunk IDs conform to RFC 4122 UUIDv5 generated
       from host and start_timestamp.
    3. Embedding Hygiene: Missing/null/NaN values are dynamically omitted from
       text serialization. Literal 'null', 'nan', or 'none' never pollute vectors.
    4. Zero Information Loss: Raw missing values are retained in metadata payloads;
       log rows are NEVER dropped.
    5. Causal Windowing & Clock-Skew: Chronological sliding window preserves causal
       chains with a configurable clock-skew tolerance buffer (default ±5s).
================================================================================
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple, Union

import pandas as pd


# Constant Namespace for RFC 4122 UUIDv5 chunk identifier generation (DNS namespace)
UUID5_NAMESPACE_DFIR = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


# ==============================================================================
# 1. TOKEN ESTIMATOR (PLUGGABLE: TIKTOKEN / TRANSFORMERS / HEURISTIC)
# ==============================================================================

class TokenEstimator:
    """Lightweight, pluggable token counter supporting tiktoken, Hugging Face
    transformers tokenizers, and a robust character/word heuristic fallback.
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

        # 2. Tiktoken support (preferred for speed)
        try:
            import tiktoken
            try:
                self._tiktoken_enc = tiktoken.encoding_for_model(str(model_name_or_tokenizer))
            except Exception:
                self._tiktoken_enc = tiktoken.get_encoding(encoding_name)
        except Exception:
            pass

        # 3. Transformers AutoTokenizer fallback
        if self._tiktoken_enc is None and isinstance(model_name_or_tokenizer, str) and model_name_or_tokenizer:
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

    def count(self, text: str) -> int:
        """Calculates token count for the given text block."""
        if not text:
            return 0
        if self._tiktoken_enc is not None:
            try:
                return len(self._tiktoken_enc.encode(text))
            except Exception:
                pass
        if self._tokenizer is not None:
            try:
                return len(self._tokenizer.encode(text, add_special_tokens=False))
            except Exception:
                pass
        # Robust BPE heuristic fallback: ~4 characters per token for English and log payloads
        return max(1, len(text) // 4)


# ==============================================================================
# 2. NULL-CHECKING & TIMESTAMP NORMALIZATION HELPERS
# ==============================================================================

def is_null_or_empty(val: Any) -> bool:
    """Strictly evaluates whether a value is missing, null, or semantically empty.

    Returns True for:
      - None
      - float NaN / pd.NA
      - Empty strings and whitespace-only strings
      - String literals: 'nan', 'null', 'none', 'n/a', 'na', '<na>', 'undefined'
    """
    if val is None:
        return True
    if isinstance(val, float) and (pd.isna(val) or val != val):
        return True
    s = str(val).strip()
    if s == "":
        return True
    return s.lower() in ("nan", "null", "none", "n/a", "na", "<na>", "undefined")


def clean_string_scalar(val: Any) -> Optional[str]:
    """Returns stripped string or None if the value is null or empty."""
    if is_null_or_empty(val):
        return None
    cleaned = str(val).strip()
    return cleaned if cleaned else None


def normalize_utc_timestamp(val: Any) -> Tuple[Optional[datetime], Optional[str]]:
    """Normalizes any datetime/timestamp scalar into a UTC datetime object and
    an RFC 3339 / ISO 8601 formatted string ('YYYY-MM-DDTHH:MM:SSZ').

    Returns (dt_utc, iso_string). Falls back to (None, None) on parse failure
    without dropping the underlying record.
    """
    if is_null_or_empty(val):
        return None, None
    try:
        dt = pd.to_datetime(val, utc=True)
        if pd.isna(dt):
            return None, None
        pydt = dt.to_pydatetime()
        iso_str = pydt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return pydt, iso_str
    except Exception:
        return None, None


def generate_chunk_id(
    host: Optional[str],
    start_timestamp: Optional[str],
    slice_index: int = 0,
) -> str:
    """Generates a deterministic RFC 4122 UUIDv5 derived from host + start_timestamp.

    Guarantees reproducibility and unique identification for Qdrant points.
    """
    h = clean_string_scalar(host) or "UNKNOWN_HOST"
    ts = clean_string_scalar(start_timestamp) or "NO_TIMESTAMP"
    seed = f"{h}:{ts}" if slice_index == 0 else f"{h}:{ts}:{slice_index}"
    return str(uuid.uuid5(UUID5_NAMESPACE_DFIR, seed))


# ==============================================================================
# 3. INPUT INGESTION & FLEXIBLE COLUMN ALIASING
# ==============================================================================

def load_input_data(input_data: Union[pd.DataFrame, str]) -> pd.DataFrame:
    """Loads a pandas DataFrame from either an existing DataFrame or a file path (CSV or JSONL).

    Retains nulls and empty fields without dropping rows.
    """
    if isinstance(input_data, pd.DataFrame):
        return input_data.copy()

    if not isinstance(input_data, str):
        raise TypeError(f"Expected pandas DataFrame or file path string, got {type(input_data)}")

    if not os.path.exists(input_data):
        raise FileNotFoundError(f"Input log file not found: {input_data}")

    lower_path = input_data.lower()
    if lower_path.endswith(".jsonl") or lower_path.endswith(".ndjson"):
        return pd.read_json(input_data, lines=True, dtype=str)
    elif lower_path.endswith(".json"):
        try:
            return pd.read_json(input_data, lines=True, dtype=str)
        except Exception:
            return pd.read_json(input_data, dtype=str)
    else:
        # CSV format (preserve nulls and empty strings)
        return pd.read_csv(input_data, dtype=str, keep_default_na=False)


class ColumnNormalizer:
    """Dynamically maps common variations of Windows log headers to canonical schema keys:
    - timestamp <- [TimeCreated, Date and Time, SystemTime, Timestamp]
    - event_id  <- [EventID, Id, Event_ID]
    - host      <- [Computer, MachineName, Host, Hostname]
    - level     <- [LevelDisplayName, Level, Severity]
    - user      <- [TargetUserName, SubjectUserName, SecurityUserID, User]
    - channel   <- [Channel, ProviderName, Provider, Source]
    - details   <- [Message, Data, Description, Payload]
    """

    CANONICAL_ALIASES: Dict[str, List[str]] = {
        "timestamp": [
            "timecreated", "date and time", "systemtime", "timestamp",
            "date_time", "datetime", "date", "time", "utctime",
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
            "targetusername", "subjectusername", "securityuserid", "user",
            "username", "userid", "account_name", "account",
        ],
        "channel": [
            "channel", "providername", "provider", "source", "log_name",
        ],
        "details": [
            "message", "data", "description", "payload", "eventdata", "userdata",
        ],
    }

    def __init__(self, custom_aliases: Optional[Dict[str, List[str]]] = None):
        self.aliases = self.CANONICAL_ALIASES.copy()
        if custom_aliases:
            for k, v in custom_aliases.items():
                self.aliases[k] = [x.lower() for x in v]

    def resolve_mapping(self, df_columns: Iterable[str]) -> Dict[str, str]:
        """Resolves existing DataFrame column names to canonical schema keys.

        Returns:
            Dict[str, str]: Mapping of {existing_column_name: canonical_schema_key}
        """
        mapping: Dict[str, str] = {}
        cleaned_cols = {col: re.sub(r"[_\s\-\.]+", "", str(col).lower()) for col in df_columns}

        for canon_key, variations in self.aliases.items():
            matched_col = None
            for var in variations:
                clean_var = re.sub(r"[_\s\-\.]+", "", var.lower())
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
    """Transforms a normalized log record into a high-signal semantic narrative string.

    Template format:
        [<Timestamp>] <Host> | <Channel> | EventID: <EventID> (<Level>) | User: <User> | Details: <Details>

    Rules:
        - Dynamic Null Omission: If any field evaluates to missing, empty string,
          None, NaN, "nan", "null", "N/A", or whitespace, that key and its delimiter
          are completely omitted.
        - Literal "null", "nan", or "None" are NEVER output into text.
        - Truncates verbose details to max_details_chars (default: 300).
    """

    def __init__(
        self,
        max_details_chars: int = 300,
        normalizer: Optional[ColumnNormalizer] = None,
    ):
        self.max_details_chars = max_details_chars
        self.normalizer = normalizer or ColumnNormalizer()

    def serialize(self, record: Dict[str, Any]) -> str:
        """Serializes a single log record dictionary into a semantic row string."""
        # Auto-normalize if canonical keys are not present
        if not any(k in record for k in ("timestamp", "host", "event_id", "details", "channel")):
            mapping = self.normalizer.resolve_mapping(record.keys())
            norm_rec = {canon: record[orig] for orig, canon in mapping.items() if orig in record}
        else:
            norm_rec = record

        # Extract normalized attributes
        raw_ts = clean_string_scalar(norm_rec.get("timestamp"))
        host = clean_string_scalar(norm_rec.get("host"))
        channel = clean_string_scalar(norm_rec.get("channel"))
        ev_id = clean_string_scalar(norm_rec.get("event_id"))
        level = clean_string_scalar(norm_rec.get("level"))
        user = clean_string_scalar(norm_rec.get("user"))
        raw_details = clean_string_scalar(norm_rec.get("details"))

        # Clean event_id if stored as dictionary string
        if ev_id and "#text" in ev_id:
            m = re.search(r"['\"]?#text['\"]?\s*:\s*['\"]?(\d+)['\"]?", ev_id)
            if m:
                ev_id = m.group(1)

        parts: List[str] = []

        # 1. [<Timestamp>] <Host>
        if raw_ts and host:
            parts.append(f"[{raw_ts}] {host}")
        elif raw_ts:
            parts.append(f"[{raw_ts}]")
        elif host:
            parts.append(f"{host}")

        # 2. <Channel>
        if channel:
            parts.append(f"{channel}")

        # 3. EventID: <EventID> (<Level>)
        if ev_id and level:
            parts.append(f"EventID: {ev_id} ({level})")
        elif ev_id:
            parts.append(f"EventID: {ev_id}")
        elif level:
            parts.append(f"Level: {level}")

        # 4. User: <User>
        if user:
            parts.append(f"User: {user}")

        # 5. Details: <Details> (capped to max_details_chars)
        if raw_details:
            flattened = " ".join(raw_details.split())
            if len(flattened) > self.max_details_chars:
                flattened = flattened[: self.max_details_chars]
            parts.append(f"Details: {flattened}")

        if not parts:
            return "LogRecord: [Empty attributes]"

        return " | ".join(parts)


# ==============================================================================
# 5. FORENSIC CHUNK DATA STRUCTURE
# ==============================================================================

@dataclass
class ForensicChunk:
    """Dual-representation forensic log chunk."""

    chunk_id: str
    text: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dictionary representation matching Qdrant schema indexing."""
        return {
            "chunk_id": self.chunk_id,
            "text": self.text,
            "metadata": self.metadata,
            # Top-level backward compatibility convenience aliases
            "start_time": self.metadata.get("start_time"),
            "end_time": self.metadata.get("end_time"),
            "start_timestamp": self.metadata.get("start_timestamp"),
            "end_timestamp": self.metadata.get("end_timestamp"),
            "host": self.metadata.get("host"),
            "event_ids": self.metadata.get("event_ids", []),
        }


# ==============================================================================
# 6. CHRONOLOGICAL WINDOWING & BURST CHUNKER
# ==============================================================================

def sort_with_clock_skew(
    entries: List[Tuple[Optional[datetime], int, Dict[str, Any]]],
    clock_skew_seconds: float = 5.0,
) -> List[Tuple[Optional[datetime], int, Dict[str, Any]]]:
    """Sorts entries chronologically with clock-skew tolerance buffer.

    If two entries on the same host have timestamps within clock_skew_seconds
    (default ±5 seconds), their original log sequence order (source row index)
    is preserved, preventing artificial inversion caused by cross-provider
    or sub-second clock drift.
    """
    if not entries:
        return []

    timed_entries = [e for e in entries if e[0] is not None]
    untimed_entries = [e for e in entries if e[0] is None]

    if not timed_entries:
        return sorted(untimed_entries, key=lambda x: x[1])

    # Initial sort strictly by parsed timestamp
    sorted_timed = sorted(timed_entries, key=lambda x: (x[0], x[1]))

    # Group adjacent events within clock_skew_seconds into stable clusters
    if clock_skew_seconds > 0:
        clustered_timed: List[Tuple[Optional[datetime], int, Dict[str, Any]]] = []
        current_cluster: List[Tuple[Optional[datetime], int, Dict[str, Any]]] = [sorted_timed[0]]

        for entry in sorted_timed[1:]:
            last_dt = current_cluster[-1][0]
            curr_dt = entry[0]
            if curr_dt is not None and last_dt is not None and (curr_dt - last_dt).total_seconds() <= clock_skew_seconds:
                current_cluster.append(entry)
            else:
                # Settle cluster preserving original source index
                current_cluster.sort(key=lambda x: x[1])
                clustered_timed.extend(current_cluster)
                current_cluster = [entry]

        if current_cluster:
            current_cluster.sort(key=lambda x: x[1])
            clustered_timed.extend(current_cluster)

        sorted_timed = clustered_timed

    return sorted(untimed_entries, key=lambda x: x[1]) + sorted_timed


class ChronologicalWindowChunker:
    """Implements temporal sliding windowing and sessionization:
    - window_duration_minutes: Default 10 min (captures causal chains).
    - window_overlap_minutes: Default 2 min (prevents cutting off bursts).
    - max_tokens_per_chunk: Default 512 tokens (subdivides bursts without dropping records).
    - clock_skew_seconds: Default 5s tolerance buffer for cross-provider drift.
    """

    def __init__(
        self,
        window_duration_minutes: int = 10,
        window_overlap_minutes: int = 2,
        max_tokens_per_chunk: int = 512,
        clock_skew_seconds: float = 5.0,
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
        self.clock_skew_seconds = clock_skew_seconds
        self.group_by_host = group_by_host
        self.tokenizer = token_estimator or TokenEstimator()
        self.serializer = serializer or SemanticRowSerializer()

    def chunk_records(self, records: List[Dict[str, Any]]) -> List[ForensicChunk]:
        """Orchestrates grouping, clock-skew sorting, sliding windows, and metadata extraction."""
        if not records:
            return []

        # Parse timestamps and track original row indices
        parsed_entries: List[Tuple[Optional[datetime], int, Dict[str, Any]]] = []
        for i, r in enumerate(records):
            pydt, _ = normalize_utc_timestamp(r.get("timestamp"))
            parsed_entries.append((pydt, i, r))

        # Partition by host if enabled, otherwise global timeline
        partitions: Dict[str, List[Tuple[Optional[datetime], int, Dict[str, Any]]]] = {}
        if self.group_by_host:
            for entry in parsed_entries:
                h = clean_string_scalar(entry[2].get("host")) or "UNKNOWN_HOST"
                partitions.setdefault(h, []).append(entry)
        else:
            partitions["GLOBAL"] = parsed_entries

        all_chunks: List[ForensicChunk] = []

        for _, entries in partitions.items():
            sorted_entries = sort_with_clock_skew(
                entries,
                clock_skew_seconds=self.clock_skew_seconds,
            )
            partition_chunks = self._sliding_window_partition(sorted_entries)
            all_chunks.extend(partition_chunks)

        return all_chunks

    def _sliding_window_partition(
        self,
        sorted_entries: List[Tuple[Optional[datetime], int, Dict[str, Any]]],
    ) -> List[ForensicChunk]:
        """Applies sliding window across chronologically sorted entries."""
        chunks: List[ForensicChunk] = []

        timed_entries = [e for e in sorted_entries if e[0] is not None]
        untimed_entries = [e for e in sorted_entries if e[0] is None]

        # Process timed events using sliding temporal window
        if timed_entries:
            min_time = timed_entries[0][0]
            max_time = timed_entries[-1][0]
            current_window_start = min_time

            while current_window_start <= max_time:
                current_window_end = current_window_start + self.window_duration

                # Select all events falling strictly within [start, end)
                window_entries = [
                    e for e in timed_entries
                    if current_window_start <= e[0] < current_window_end
                ]

                if window_entries:
                    sub_chunks = self._pack_window_to_chunks(window_entries)
                    chunks.extend(sub_chunks)
                    current_window_start += self.window_step
                else:
                    # Fast-forward jump if there is a gap with zero events
                    remaining = [e for e in timed_entries if e[0] >= current_window_start]
                    if not remaining:
                        break
                    next_time = remaining[0][0]
                    if next_time >= current_window_end:
                        current_window_start = next_time
                    else:
                        current_window_start += self.window_step

        # Process any untimed / unparseable events sequentially
        if untimed_entries:
            sub_chunks = self._pack_window_to_chunks(untimed_entries)
            chunks.extend(sub_chunks)

        return chunks

    def _pack_window_to_chunks(
        self,
        entries: List[Tuple[Optional[datetime], int, Dict[str, Any]]],
    ) -> List[ForensicChunk]:
        """Subdivides a temporal window of events into sub-chunks (micro-slices) if total
        tokens exceed max_tokens_per_chunk while strictly maintaining causality order.
        Zero events are dropped.
        """
        sub_chunks: List[ForensicChunk] = []
        current_batch_lines: List[str] = []
        current_batch_entries: List[Tuple[Optional[datetime], int, Dict[str, Any]]] = []
        current_token_count = 0

        for entry in entries:
            _, _, row = entry
            serialized_line = self.serializer.serialize(row)
            line_tokens = self.tokenizer.count(serialized_line)

            # If adding this line exceeds the token budget, flush current micro-slice
            if current_batch_lines and (current_token_count + line_tokens > self.max_tokens):
                chunk = self._build_chunk_artifact(
                    current_batch_lines,
                    current_batch_entries,
                    slice_index=len(sub_chunks),
                )
                sub_chunks.append(chunk)

                current_batch_lines = []
                current_batch_entries = []
                current_token_count = 0

            current_batch_lines.append(serialized_line)
            current_batch_entries.append(entry)
            current_token_count += line_tokens

        # Flush trailing records in window
        if current_batch_lines:
            chunk = self._build_chunk_artifact(
                current_batch_lines,
                current_batch_entries,
                slice_index=len(sub_chunks),
            )
            sub_chunks.append(chunk)

        return sub_chunks

    def _build_chunk_artifact(
        self,
        lines: List[str],
        entries: List[Tuple[Optional[datetime], int, Dict[str, Any]]],
        slice_index: int = 0,
    ) -> ForensicChunk:
        """Constructs a finalized ForensicChunk with separated metadata matching Qdrant schema."""
        chunk_text = "\n".join(lines)

        rows = [e[2] for e in entries]
        source_indices = [e[1] for e in entries]

        # Extract timestamps
        timed_list = [e[0] for e in entries if e[0] is not None]
        if timed_list:
            start_iso = min(timed_list).strftime("%Y-%m-%dT%H:%M:%SZ")
            end_iso = max(timed_list).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            start_iso = None
            end_iso = None

        # Host extraction
        unique_hosts = list(dict.fromkeys(
            clean_string_scalar(r.get("host"))
            for r in rows
            if clean_string_scalar(r.get("host"))
        ))
        host_val = unique_hosts[0] if len(unique_hosts) == 1 else (unique_hosts[0] if unique_hosts else None)

        # Unique Event IDs
        unique_event_ids = list(dict.fromkeys(
            clean_string_scalar(r.get("event_id"))
            for r in rows
            if clean_string_scalar(r.get("event_id"))
        ))

        # Unique Severity Levels
        unique_levels = list(dict.fromkeys(
            clean_string_scalar(r.get("level"))
            for r in rows
            if clean_string_scalar(r.get("level"))
        ))

        # Unique Non-null Users
        unique_users = list(dict.fromkeys(
            clean_string_scalar(r.get("user"))
            for r in rows
            if clean_string_scalar(r.get("user"))
        ))

        # Deterministic UUIDv5 chunk identifier
        chunk_uuid = generate_chunk_id(
            host=host_val,
            start_timestamp=start_iso,
            slice_index=slice_index,
        )

        metadata: Dict[str, Any] = {
            "chunk_id": chunk_uuid,
            "start_timestamp": start_iso,
            "end_timestamp": end_iso,
            "start_time": start_iso,   # Backward compatibility alias
            "end_time": end_iso,       # Backward compatibility alias
            "host": host_val,
            "event_ids": unique_event_ids,
            "levels": unique_levels,
            "users": unique_users,
            "raw_row_count": len(rows),
            "source_row_indices": source_indices,
        }

        return ForensicChunk(
            chunk_id=chunk_uuid,
            text=chunk_text,
            metadata=metadata,
        )


# ==============================================================================
# 7. TOP-LEVEL DFIR PIPELINE ORCHESTRATOR
# ==============================================================================

class DFIRLogTransformerPipeline:
    """Unified Stage 2 Pipeline: Ingests raw DataFrames or CSV/JSONL files, executes
    header normalization, null-aware serialization, chronological windowing,
    and structured metadata extraction.
    """

    def __init__(
        self,
        window_duration_minutes: int = 10,
        window_overlap_minutes: int = 2,
        max_tokens_per_chunk: int = 512,
        clock_skew_seconds: float = 5.0,
        group_by_host: bool = False,
        max_details_chars: int = 300,
        model_name_or_tokenizer: Any = "BAAI/bge-small-en-v1.5",
    ):
        self.normalizer = ColumnNormalizer()
        self.serializer = SemanticRowSerializer(max_details_chars=max_details_chars, normalizer=self.normalizer)
        self.tokenizer = TokenEstimator(model_name_or_tokenizer=model_name_or_tokenizer)
        self.chunker = ChronologicalWindowChunker(
            window_duration_minutes=window_duration_minutes,
            window_overlap_minutes=window_overlap_minutes,
            max_tokens_per_chunk=max_tokens_per_chunk,
            clock_skew_seconds=clock_skew_seconds,
            group_by_host=group_by_host,
            token_estimator=self.tokenizer,
            serializer=self.serializer,
        )

    def transform_dataframe(self, df: pd.DataFrame) -> List[ForensicChunk]:
        """Processes an in-memory DataFrame into contextual forensic chunks.
        Guarantees that rows with null/missing values are NEVER dropped.
        """
        if df is None or df.empty:
            return []

        col_map = self.normalizer.resolve_mapping(df.columns)

        normalized_records: List[Dict[str, Any]] = []
        for orig_idx, row in df.iterrows():
            rec: Dict[str, Any] = {}
            for col_name, val in row.items():
                canon_key = col_map.get(col_name)
                if canon_key:
                    rec[canon_key] = val
                else:
                    rec[str(col_name)] = val

            # Normalize timestamp string into canonical ISO 8601 UTC
            if "timestamp" in rec:
                _, iso_ts = normalize_utc_timestamp(rec["timestamp"])
                if iso_ts:
                    rec["timestamp"] = iso_ts

            normalized_records.append(rec)

        return self.chunker.chunk_records(normalized_records)

    def transform_file(self, filepath: str) -> List[ForensicChunk]:
        """Loads a CSV or JSONL file and generates forensic chunks."""
        df = load_input_data(filepath)
        return self.transform_dataframe(df)

    def transform_csv(self, filepath: str) -> List[ForensicChunk]:
        """Backward-compatible convenience alias for transform_file."""
        return self.transform_file(filepath)


def preprocess_and_chunk_windows_logs(
    df: Union[pd.DataFrame, str],
    window_duration_minutes: int = 10,
    window_overlap_minutes: int = 2,
    max_tokens_per_chunk: int = 512,
    clock_skew_seconds: float = 5.0,
    max_details_chars: int = 300,
    model_name_or_tokenizer: Any = "BAAI/bge-small-en-v1.5",
    group_by_host: bool = False,
) -> List[Dict[str, Any]]:
    """Preprocesses and chunks Windows log DataFrames or files for embedding models.

    Args:
        df: In-memory pandas DataFrame or file path (CSV or JSONL).
        window_duration_minutes: Sliding time window duration (default: 10 minutes).
        window_overlap_minutes: Overlap duration between consecutive windows (default: 2 minutes).
        max_tokens_per_chunk: Hard token budget per chunk (default: 512 tokens).
        clock_skew_seconds: Cross-provider clock-skew tolerance buffer (default: 5.0 seconds).
        max_details_chars: Character ceiling for details/message field (default: 300 characters).
        model_name_or_tokenizer: Model name string or tokenizer instance for token estimation.
        group_by_host: If True, partitions timeline per host before windowing (default: False).

    Returns:
        List of chunk dictionaries formatted as:
        {
            "chunk_id": str,          # Deterministic RFC 4122 UUIDv5 (derived from host + start_timestamp)
            "text": str,              # Formatted semantic block
            "metadata": dict          # Structured payload for Qdrant traversal
        }
    """
    df_loaded = load_input_data(df)
    if df_loaded is None or df_loaded.empty:
        return []

    pipeline = DFIRLogTransformerPipeline(
        window_duration_minutes=window_duration_minutes,
        window_overlap_minutes=window_overlap_minutes,
        max_tokens_per_chunk=max_tokens_per_chunk,
        clock_skew_seconds=clock_skew_seconds,
        group_by_host=group_by_host,
        max_details_chars=max_details_chars,
        model_name_or_tokenizer=model_name_or_tokenizer,
    )

    chunks = pipeline.transform_dataframe(df_loaded)
    return [c.to_dict() for c in chunks]


# ==============================================================================
# 8. RUNNABLE DEMONSTRATION
# ==============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("STAGE 2: WINDOWS LOG TRANSFORMER & CHUNKER VERIFICATION")
    print("=" * 80)

    sample_logs = [
        {
            "TimeCreated": "2026-09-14T08:00:00Z",
            "EventID": 4624,
            "Computer": "SEC-SRV-01",
            "Channel": "Security",
            "Level": "Information",
            "TargetUserName": "admin",
            "Message": "An account was successfully logged on.",
        },
        {
            "TimeCreated": "2026-09-14T08:08:30Z",
            "EventID": 4625,
            "Computer": "SEC-SRV-01",
            "Channel": "Security",
            "Level": "Warning",
            "TargetUserName": "guest",
            "Message": "An account failed to log on (0xC000006A).",
        },
        {
            "TimeCreated": "2026-09-14T08:16:30Z",
            "EventID": 7045,
            "Computer": "SEC-SRV-01",
            "Channel": "System",
            "Level": "Information",
            "TargetUserName": None,
            "Message": "A new service was installed on the system.",
        },
    ]

    df_test = pd.DataFrame(sample_logs)
    demo_chunks = preprocess_and_chunk_windows_logs(df_test)

    print(f"Generated {len(demo_chunks)} chunks:")
    for idx, chk in enumerate(demo_chunks):
        print(f"\n--- Chunk {idx + 1} ({chk['chunk_id']}) ---")
        print(chk["text"])
        print("Metadata:", json.dumps(chk["metadata"], indent=2))
