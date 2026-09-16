#!/usr/bin/env python3
"""
================================================================================
Unit & Integration Tests for STAGE 2: Windows Log Contextual Transformation
================================================================================
Author: Principal Data Engineer & Cybersecurity Forensics Specialist
Description:
    Comprehensive pytest/unittest suite verifying:
    1. Null stripping: Omission of null User/Channel, no literal 'null', 'nan', 'None'.
    2. Message capping: 300-char truncation on verbose details.
    3. Windowing & Overlap: Chronological sorting of out-of-order events spanning
       25 minutes, producing properly overlapped 10-minute windows (2-min overlap).
    4. Token limit & Burst: Subdividing token bursts exceeding 512 tokens without
       dropping records.
    5. Metadata integrity: Unique event_ids/levels, RFC 4122 UUIDv5 chunk_id,
       and ISO 8601 start_timestamp/end_timestamp.
    6. File Ingestion: Reading CSV and JSONL input files with null preservation.
    7. Clock-Skew Tolerance: Preserving order of cross-provider events within ±5s.
    8. Column Aliasing: Dynamically mapping diverse Windows log headers.
================================================================================
"""

import json
import os
import re
import sys
import tempfile
import unittest
import uuid
from datetime import datetime

import pandas as pd
import pytest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_transformer import (
    ColumnNormalizer,
    SemanticRowSerializer,
    RowDocumentSerializer,
    ChronologicalWindowChunker,
    TokenEstimator,
    preprocess_and_chunk_windows_logs,
    transform_rows_as_documents,
    InMemoryLogStore,
    format_llm_batch,
    load_input_data,
    generate_chunk_id,
    sort_with_clock_skew,
)


class TestLogTransformer(unittest.TestCase):
    """Test suite verifying all Stage 2 specification requirements."""

    def test_01_null_stripping(self):
        """1. Null stripping: Verify that an input row with null User and Channel
        outputs a text string without 'User:', 'None', or 'nan'.
        """
        serializer = SemanticRowSerializer(max_details_chars=300)
        row = {
            "TimeCreated": "2026-09-14T08:00:00Z",
            "EventID": 4688,
            "Computer": "SEC-SRV-01",
            "TargetUserName": None,         # Explicit None
            "Channel": float("nan"),        # NaN float
            "Level": "nan",                 # String literal 'nan'
            "Message": "Process created: powershell.exe",
        }
        serialized = serializer.serialize(row)

        self.assertIsNotNone(serialized)
        # Verify mandatory template structure
        self.assertIn("[2026-09-14T08:00:00Z] SEC-SRV-01", serialized)
        self.assertIn("EventID: 4688", serialized)
        self.assertIn("Details: Process created: powershell.exe", serialized)

        # CRITICAL: Dynamic null omission assertions
        self.assertNotIn("User:", serialized, "Null user key must be completely omitted")
        self.assertNotIn("Channel", serialized, "Null channel must be completely omitted")
        self.assertNotIn("none", serialized.lower(), "Literal 'None' must never appear")
        self.assertNotIn("nan", serialized.lower(), "Literal 'nan' must never appear")
        self.assertNotIn("null", serialized.lower(), "Literal 'null' must never appear")
        self.assertNotIn("||", serialized, "Delimiters must be cleanly formatted without empty blocks")

    def test_02_message_capping(self):
        """2. Message capping: Verify messages longer than 300 chars are truncated."""
        serializer = SemanticRowSerializer(max_details_chars=300)
        long_message = "powershell.exe -EncodedCommand " + ("A" * 500)
        row = {
            "TimeCreated": "2026-09-14T08:00:00Z",
            "EventID": 4688,
            "Computer": "SEC-SRV-01",
            "Channel": "Security",
            "Level": "Information",
            "TargetUserName": "admin",
            "Message": long_message,
        }
        serialized = serializer.serialize(row)

        self.assertIn("Details: ", serialized)
        details_part = serialized.split("Details: ")[1]
        self.assertLessEqual(
            len(details_part),
            300,
            f"Details length ({len(details_part)}) must not exceed 300 characters",
        )

    def test_03_windowing_and_overlap(self):
        """3. Windowing & Overlap: Feed out-of-order events spanning 25 minutes;
        verify they sort chronologically and produce properly overlapped 10-minute windows.
        """
        # Create events across 25 minutes:
        # e1: 08:00:00 (min 0)  -> Window 1 [08:00 - 08:10)
        # e2: 08:04:00 (min 4)  -> Window 1 [08:00 - 08:10)
        # e3: 08:09:00 (min 9)  -> In 2-min overlap [08:08 - 08:10) => in Window 1 and Window 2
        # e4: 08:16:30 (min 16.5) -> In 2-min overlap [08:16 - 08:18) => in Window 2 and Window 3
        # e5: 08:24:00 (min 24) -> Window 3 [08:16 - 08:26)
        raw_events = [
            {
                "TimeCreated": "2026-09-14T08:24:00Z",  # Provided out of order
                "EventID": "1102",
                "Computer": "HOST-ALPHA",
                "Channel": "Security",
                "Level": "Critical",
                "TargetUserName": "admin",
                "Message": "Audit log was cleared",
            },
            {
                "TimeCreated": "2026-09-14T08:00:00Z",
                "EventID": "4624",
                "Computer": "HOST-ALPHA",
                "Channel": "Security",
                "Level": "Information",
                "TargetUserName": "SYSTEM",
                "Message": "Successful logon",
            },
            {
                "TimeCreated": "2026-09-14T08:16:30Z",
                "EventID": "7045",
                "Computer": "HOST-ALPHA",
                "Channel": "System",
                "Level": "Information",
                "TargetUserName": "admin",
                "Message": "Service installed: PSSvc",
            },
            {
                "TimeCreated": "2026-09-14T08:04:00Z",
                "EventID": "4688",
                "Computer": "HOST-ALPHA",
                "Channel": "Security",
                "Level": "Information",
                "TargetUserName": "admin",
                "Message": "cmd.exe executed",
            },
            {
                "TimeCreated": "2026-09-14T08:09:00Z",
                "EventID": "4625",
                "Computer": "HOST-ALPHA",
                "Channel": "Security",
                "Level": "Warning",
                "TargetUserName": "guest",
                "Message": "Failed logon attempt 0xC000006A",
            },
        ]
        df = pd.DataFrame(raw_events)

        chunks = preprocess_and_chunk_windows_logs(
            df,
            window_duration_minutes=10,
            window_overlap_minutes=2,
            max_tokens_per_chunk=512,
        )

        # Must produce at least 3 chronological sliding windows
        self.assertGreaterEqual(len(chunks), 3, "Spanning 25 minutes with 8-min step must yield >= 3 chunks")

        # Verify chronological sorting across chunks
        timestamps = [c["metadata"]["start_timestamp"] for c in chunks]
        self.assertEqual(timestamps, sorted(timestamps), "Chunks must be chronologically ordered")

        # Verify that Event 4625 (at 08:09:00) falls in the 2-minute overlap of Window 1 and Window 2
        chunk1_event_ids = chunks[0]["metadata"]["event_ids"]
        chunk2_event_ids = chunks[1]["metadata"]["event_ids"]
        self.assertIn("4625", chunk1_event_ids, "Event 4625 must be in Window 1 (08:00 - 08:10)")
        self.assertIn("4625", chunk2_event_ids, "Event 4625 must also be in Window 2 (08:08 - 08:18)")

        # Verify that Event 7045 (at 08:16:30) falls in the 2-minute overlap of Window 2 and Window 3
        chunk3_event_ids = chunks[2]["metadata"]["event_ids"]
        self.assertIn("7045", chunk2_event_ids, "Event 7045 must be in Window 2 (08:08 - 08:18)")
        self.assertIn("7045", chunk3_event_ids, "Event 7045 must also be in Window 3 (08:16 - 08:26)")

        # Verify multi-row text assembly with newlines
        self.assertIn("\n", chunks[0]["text"], "Multi-row text must be joined by newlines")

    def test_04_token_limit_and_burst(self):
        """4. Token limit & Burst: Ensure bursts exceeding 512 tokens are
        subdivided without dropped records.
        """
        # Create 25 events within the exact same 1-minute interval
        # Each event has ~250 chars of details (~70 tokens), total ~1750 tokens >> 512 max
        burst_events = []
        for i in range(25):
            burst_events.append({
                "TimeCreated": "2026-09-14T08:01:00Z",
                "EventID": f"{4624 + (i % 3)}",
                "Computer": "BURST-SRV-01",
                "Channel": "Security",
                "Level": "Information",
                "TargetUserName": f"user_{i:02d}",
                "Message": f"Payload transaction {i}: " + ("X" * 200),
            })

        df_burst = pd.DataFrame(burst_events)
        chunks = preprocess_and_chunk_windows_logs(
            df_burst,
            window_duration_minutes=10,
            window_overlap_minutes=2,
            max_tokens_per_chunk=512,
        )

        # Must be subdivided into multiple sub-chunks
        self.assertGreater(
            len(chunks),
            1,
            "A burst of 25 events exceeding 512 tokens must be subdivided into micro-slices",
        )

        # ZERO DROPPED RECORDS: Verify that the sum of raw_row_count equals 25
        total_rows_accounted = sum(c["metadata"]["raw_row_count"] for c in chunks)
        self.assertEqual(
            total_rows_accounted,
            25,
            "Burst subdivision must never drop any log records",
        )

        # Verify all source row indices are accounted for
        all_source_indices = []
        for c in chunks:
            all_source_indices.extend(c["metadata"]["source_row_indices"])
        self.assertEqual(
            sorted(all_source_indices),
            list(range(25)),
            "All source row indices must be preserved across sub-chunks",
        )

        # Verify each sub-chunk has a unique deterministic chunk_id
        chunk_ids = [c["chunk_id"] for c in chunks]
        self.assertEqual(len(chunk_ids), len(set(chunk_ids)), "Sub-chunks must have unique UUIDs")

    def test_05_metadata_integrity(self):
        """5. Metadata integrity: Verify event_ids and levels contain correct
        unique lists, start_timestamp and end_timestamp conform to ISO 8601,
        and chunk_id conforms to RFC 4122 UUIDv5.
        """
        raw_events = [
            {
                "TimeCreated": "2026-09-14T08:00:10Z",
                "EventID": "4624",
                "Computer": "DC-PRIMARY",
                "Channel": "Security",
                "Level": "Information",
                "TargetUserName": "admin",
                "Message": "Logon 1",
            },
            {
                "TimeCreated": "2026-09-14T08:02:00Z",
                "EventID": "4625",
                "Computer": "DC-PRIMARY",
                "Channel": "Security",
                "Level": "Warning",
                "TargetUserName": "attacker",
                "Message": "Logon failed",
            },
            {
                "TimeCreated": "2026-09-14T08:05:00Z",
                "EventID": "4624",  # Duplicate EventID
                "Computer": "DC-PRIMARY",
                "Channel": "Security",
                "Level": "Information",  # Duplicate Level
                "TargetUserName": "admin",  # Duplicate User
                "Message": "Logon 2",
            },
        ]
        df = pd.DataFrame(raw_events)

        chunks = preprocess_and_chunk_windows_logs(df)
        self.assertEqual(len(chunks), 1)

        chunk = chunks[0]
        self.assertIn("chunk_id", chunk)
        self.assertIn("text", chunk)
        self.assertIn("metadata", chunk)

        meta = chunk["metadata"]

        # 1. Unique Event IDs (flat list without duplicates)
        self.assertEqual(meta["event_ids"], ["4624", "4625"])

        # 2. Unique Severity Levels (flat list without duplicates)
        self.assertEqual(meta["levels"], ["Information", "Warning"])

        # 3. Unique Users (flat list without duplicates)
        self.assertEqual(meta["users"], ["admin", "attacker"])

        # 4. ISO 8601 Timestamps
        iso_regex = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
        self.assertRegex(meta["start_timestamp"], iso_regex)
        self.assertRegex(meta["end_timestamp"], iso_regex)
        self.assertEqual(meta["start_timestamp"], "2026-09-14T08:00:10Z")
        self.assertEqual(meta["end_timestamp"], "2026-09-14T08:05:00Z")

        # 5. RFC 4122 UUIDv5 validation (deterministic)
        uuid_regex = r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        self.assertRegex(chunk["chunk_id"], uuid_regex)
        expected_uuid = generate_chunk_id(host="DC-PRIMARY", start_timestamp="2026-09-14T08:00:10Z")
        self.assertEqual(chunk["chunk_id"], expected_uuid)

        # 6. Backward-compatibility aliases
        self.assertEqual(meta["start_time"], meta["start_timestamp"])
        self.assertEqual(meta["end_time"], meta["end_timestamp"])
        self.assertEqual(meta["raw_row_count"], 3)
        self.assertEqual(meta["source_row_indices"], [0, 1, 2])

    def test_06_file_input_csv_and_jsonl(self):
        """Verify ingestion directly from CSV and JSONL file paths."""
        sample_records = [
            {
                "TimeCreated": "2026-09-14T08:00:00Z",
                "EventID": "4688",
                "Computer": "FILE-TEST-01",
                "Channel": "Security",
                "Level": "Information",
                "TargetUserName": "svc_agent",
                "Message": "Process launched: whoami.exe",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Test CSV file
            csv_path = os.path.join(tmpdir, "test.csv")
            pd.DataFrame(sample_records).to_csv(csv_path, index=False)
            csv_chunks = preprocess_and_chunk_windows_logs(csv_path)
            self.assertEqual(len(csv_chunks), 1)
            self.assertIn("whoami.exe", csv_chunks[0]["text"])

            # 2. Test JSONL file
            jsonl_path = os.path.join(tmpdir, "test.jsonl")
            with open(jsonl_path, "w", encoding="utf-8") as f:
                for rec in sample_records:
                    f.write(json.dumps(rec) + "\n")
            jsonl_chunks = preprocess_and_chunk_windows_logs(jsonl_path)
            self.assertEqual(len(jsonl_chunks), 1)
            self.assertIn("whoami.exe", jsonl_chunks[0]["text"])

    def test_07_clock_skew_tolerance(self):
        """Verify that events within ±5 seconds clock-skew buffer retain their
        original log order rather than being inverted by sub-second provider drift.
        """
        skew_events = [
            # Event 1: Security provider logged at 08:00:03Z
            (
                datetime.fromisoformat("2026-09-14T08:00:03+00:00"),
                0,
                {"timestamp": "2026-09-14T08:00:03Z", "details": "Action 1"},
            ),
            # Event 2: System provider logged at 08:00:01Z (drifted 2s behind)
            (
                datetime.fromisoformat("2026-09-14T08:00:01+00:00"),
                1,
                {"timestamp": "2026-09-14T08:00:01Z", "details": "Action 2"},
            ),
        ]

        # With default 5s tolerance buffer, Event 1 stays before Event 2
        sorted_events = sort_with_clock_skew(skew_events, clock_skew_seconds=5.0)
        self.assertEqual(
            [e[1] for e in sorted_events],
            [0, 1],
            "Cross-provider events within ±5s must preserve causal input sequence",
        )

        # With 0s tolerance buffer (strict sort), 08:00:01 sorts before 08:00:03
        strictly_sorted = sort_with_clock_skew(skew_events, clock_skew_seconds=0.0)
        self.assertEqual(
            [e[1] for e in strictly_sorted],
            [1, 0],
            "Strict sorting without buffer places 08:00:01 before 08:00:03",
        )

    def test_08_flexible_column_aliasing(self):
        """Verify dynamic header mapping from non-standard Windows log formats."""
        non_standard_row = {
            "SystemTime": "2026-09-14T10:00:00Z",
            "Id": "7045",
            "Hostname": "DC-BACKUP",
            "Severity": "Warning",
            "SecurityUserID": "NETWORK_SERVICE",
            "Source": "System",
            "Payload": "Service created successfully",
        }
        df = pd.DataFrame([non_standard_row])
        chunks = preprocess_and_chunk_windows_logs(df)

        self.assertEqual(len(chunks), 1)
        chunk = chunks[0]
        meta = chunk["metadata"]

        self.assertEqual(meta["host"], "DC-BACKUP")
        self.assertEqual(meta["event_ids"], ["7045"])
        self.assertEqual(meta["levels"], ["Warning"])
        self.assertEqual(meta["users"], ["NETWORK_SERVICE"])
        self.assertIn("EventID: 7045 (Warning)", chunk["text"])
        self.assertIn("User: NETWORK_SERVICE", chunk["text"])
        self.assertIn("Details: Service created successfully", chunk["text"])

    def test_09_row_level_self_contained_documents(self):
        """Blueprint Step 1: Transform each of N rows into an independent self-contained document
        chunk with full 23-column context without horizontal slicing.
        """
        rows = []
        for i in range(50):
            rows.append({
                "RecordID": f"{1000 + i}",
                "TimeCreated": f"2026-09-14T08:{i % 60:02d}:00Z",
                "EventID": "4625" if i % 2 == 0 else "4624",
                "Level": "2" if i % 2 == 0 else "4",
                "LevelName": "Error" if i % 2 == 0 else "Information",
                "Channel": "Security",
                "Provider": "Microsoft-Windows-Security-Auditing",
                "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                "EventSourceName": "",
                "Task": "Logon",
                "Opcode": "Info",
                "Keywords": "Audit Failure" if i % 2 == 0 else "Audit Success",
                "Computer": "SEC-SRV-01",
                "UserID": f"S-1-5-21-{i:04d}",
                "ProcessID": "672",
                "ThreadID": "1420",
                "Version": "2",
                "ActivityID": "{00000000-0000-0000-0000-000000000000}",
                "RelatedActivityID": "",
                "Qualifiers": "",
                "EventData": f'{{"TargetUserName": "user_{i}", "Status": "0xC000006A"}}',
                "UserData": "",
                "Message": f"Logon attempt for user_{i} was processed.",
            })

        df = pd.DataFrame(rows)

        # 1. Test transform_rows_as_documents directly
        docs = transform_rows_as_documents(df)
        self.assertEqual(len(docs), 50, "Every single row must become an independent document (50 in -> 50 out)")

        # Verify Document 0 structure
        doc0 = docs[0]
        self.assertEqual(doc0["row_id"], "1000")
        self.assertEqual(doc0["chunk_id"], "1000")

        # Verify structured key-value serialization
        text0 = doc0["text"]
        self.assertIn("TimeCreated: 2026-09-14T08:00:00Z", text0)
        self.assertIn("EventID: 4625", text0)
        self.assertIn("LevelName: Error", text0)
        self.assertIn("Computer: SEC-SRV-01", text0)
        self.assertIn("UserID: S-1-5-21-0000", text0)
        self.assertIn("Message: Logon attempt for user_0 was processed.", text0)
        self.assertIn("TargetUserName", text0)

        # Verify metadata retains all 23 columns
        meta0 = doc0["metadata"]
        self.assertEqual(meta0["row_id"], "1000")
        self.assertEqual(meta0["raw_row_count"], 1)
        self.assertEqual(meta0["Computer"], "SEC-SRV-01")
        self.assertEqual(meta0["EventID"], "4625")

        # 2. Test preprocess_and_chunk_windows_logs with chunk_mode="row"
        docs_via_entrypoint = preprocess_and_chunk_windows_logs(df, chunk_mode="row")
        self.assertEqual(len(docs_via_entrypoint), 50)
        self.assertEqual(docs_via_entrypoint[0]["row_id"], "1000")

    def test_10_duckdb_hybrid_storage_and_two_pass_fetch(self):
        """Blueprint Step 2 & 3: Hybrid in-memory storage and two-pass retrieval
        (Pass 1 vector candidates -> Pass 2 complete 23-column fetch).
        """
        rows = [
            {"RecordID": "2001", "EventID": "4625", "Computer": "HOST-A", "Message": "Brute force attempt 1"},
            {"RecordID": "2002", "EventID": "4624", "Computer": "HOST-A", "Message": "Admin logon"},
            {"RecordID": "2003", "EventID": "4625", "Computer": "HOST-B", "Message": "Brute force attempt 2"},
            {"RecordID": "2004", "EventID": "7045", "Computer": "HOST-A", "Message": "Service install"},
        ]
        df = pd.DataFrame(rows)

        # Ingest into in-memory structured engine (DuckDB / SQLite fallback)
        store = InMemoryLogStore(df)

        # Pass 1 simulated: Vector search returned candidate row_ids ['2001', '2003']
        candidate_ids = ["2001", "2003"]

        # Pass 2: Structured fetch by row_ids
        fetched_df = store.fetch_by_row_ids(candidate_ids)
        self.assertEqual(len(fetched_df), 2)
        fetched_record_ids = set(fetched_df["RecordID"].astype(str).tolist())
        self.assertEqual(fetched_record_ids, {"2001", "2003"})

        # SQL Filter test
        filtered_ids = store.filter_by_sql("EventID = '4625'")
        self.assertEqual(len(filtered_ids), 2)
        self.assertIn("2001", filtered_ids)
        self.assertIn("2003", filtered_ids)

    def test_11_llm_batch_formatting(self):
        """Blueprint Step 4: Batching fetched records for LLM analysis with prepended column headers."""
        rows = [{"RecordID": f"{i}", "EventID": "4624", "User": f"user_{i}"} for i in range(25)]
        df = pd.DataFrame(rows)

        batches = format_llm_batch(df, batch_size=10)
        # 25 rows with batch_size=10 -> 3 batches (10, 10, 5)
        self.assertEqual(len(batches), 3)

        # Verify header context and schema prepended
        self.assertIn("### LOG BATCH [1 to 10 of 25]", batches[0])
        self.assertIn("Columns: RecordID, EventID, User", batches[0])
        self.assertIn("| RecordID | EventID | User |", batches[0])

        self.assertIn("### LOG BATCH [21 to 25 of 25]", batches[2])


if __name__ == "__main__":
    unittest.main(verbosity=2)
