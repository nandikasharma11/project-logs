#!/usr/bin/env python3
"""
Unit Tests for STAGE 2: Windows Event Log Contextual Transformation & Chunking (log_transformer.py)
"""

import os
import sys
import unittest
import pandas as pd

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_transformer import (
    SemanticRowSerializer,
    ChronologicalWindowChunker,
    preprocess_and_chunk_windows_logs,
)


class TestLogTransformer(unittest.TestCase):
    """Test suite verifying all Stage 2 requirements."""

    def test_01_null_key_omission_and_300_char_truncation(self):
        """Verify null/NaN keys are dropped and message <= 300 chars."""
        serializer = SemanticRowSerializer()
        long_message = "powershell.exe -EncodedCommand " + ("A" * 500)
        row = {
            "TimeCreated": "2026-09-14T08:00:00Z",
            "EventID": 4688,
            "MachineName": "SEC-SRV-01",
            "TargetUserName": None,  # should be omitted
            "Level": float("nan"),   # should be omitted
            "Message": long_message,
        }
        serialized = serializer.serialize(row)
        self.assertIsNotNone(serialized)
        self.assertIn("[2026-09-14T08:00:00Z] SEC-SRV-01 | 4688", serialized)
        self.assertNotIn("TargetUserName", serialized)
        self.assertNotIn("nan", serialized.lower())
        self.assertNotIn("null", serialized.lower())

        # Check message <= 300
        details_part = serialized.split("Details: ")[1]
        self.assertLessEqual(len(details_part), 300)

    def test_02_chronological_sliding_window(self):
        """Verify sorting, 10-min window with 2-min overlap, and metadata."""
        raw_events = [
            {
                "TimeCreated": "2026-09-14T08:00:00Z",
                "EventID": 4624,
                "MachineName": "HOST-A",
                "TargetUserName": "SYSTEM",
                "Message": "Logon success",
            },
            {
                "TimeCreated": "2026-09-14T08:09:00Z",  # in 2-min overlap (08:08-08:10)
                "EventID": 4625,
                "MachineName": "HOST-A",
                "TargetUserName": "guest",
                "Message": "Logon failure 0xC000006A",
            },
            {
                "TimeCreated": "2026-09-14T08:12:00Z",  # in next window
                "EventID": 7045,
                "MachineName": "HOST-A",
                "TargetUserName": "admin",
                "Message": "Service installed",
            },
        ]
        df = pd.DataFrame(raw_events)
        chunks = preprocess_and_chunk_windows_logs(
            df,
            window_duration_minutes=10,
            window_overlap_minutes=2,
            max_tokens_per_chunk=512,
        )
        self.assertGreaterEqual(len(chunks), 2)
        for chk in chunks:
            self.assertIn("metadata", chk)
            meta = chk["metadata"]
            self.assertIn("start_time", meta)
            self.assertIn("end_time", meta)
            self.assertIn("host", meta)
            self.assertIn("event_ids", meta)


if __name__ == "__main__":
    unittest.main(verbosity=2)
