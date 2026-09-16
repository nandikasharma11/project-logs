#!/usr/bin/env python3
"""
================================================================================
TEST SUITE: Correlation Index Layer (correlation_indexer.py)
================================================================================
Validates all acceptance criteria:
  1. Every entity extracted produces a row in the correlation table with
     correct entity_type and denormalized metadata.
  2. A logon_id match spanning several hours is returned as high-confidence correlation.
  3. A bare process_id match spanning several hours is not returned (tight window).
  4. Process-start timestamps disambiguate reused PIDs.
  5. find_correlated returns results ranked by confidence weight then time proximity.
  6. Idempotency on rerun (no duplicate correlation rows).
  7. Traceability to real canonical DuckDB records.
================================================================================
"""

import json
import os
import sys
import unittest
import duckdb
import pandas as pd

# Add parent directory to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from correlation_indexer import (
    CorrelationConfig,
    CorrelationExtractor,
    CorrelationIndexManager,
    find_correlated,
)


class TestCorrelationIndexer(unittest.TestCase):
    """Test suite for CorrelationIndexManager and CorrelationExtractor."""

    def setUp(self):
        self.conn = duckdb.connect(":memory:")
        self.config = CorrelationConfig()
        self.mgr = CorrelationIndexManager(self.config)
        self._seed_database()

    def tearDown(self):
        self.conn.close()

    def _seed_database(self):
        """Creates a realistic canonical DuckDB table across Security, System, and Application."""
        rows = [
            # Row 1: Anchor Security Event 4624 (Logon session 0x35be7590 at 10:00:00)
            {
                "RecordID": "1001",
                "TimeCreated": "2026-09-15 10:00:00",
                "EventID": "4624",
                "LevelName": "LogAlways",
                "Channel": "Security",
                "Provider": "Microsoft-Windows-Security-Auditing",
                "Computer": "SEC-SRV01",
                "ProcessID": "672",
                "ThreadID": "1420",
                "UserID": "Admin",
                "ActivityID": "5D9F45AE-022D-0002-B046-9F5D2D02DD01",
                "EventData": json.dumps({
                    "TargetUserName": "Admin",
                    "TargetLogonId": "0x35be7590",
                    "IpAddress": "192.168.1.50",
                }),
                "Message": "An account was successfully logged on.",
            },
            # Row 2: Security Event 4672 (Special privileges assigned in same session 14 seconds later)
            {
                "RecordID": "1002",
                "TimeCreated": "2026-09-15 10:00:14",
                "EventID": "4672",
                "LevelName": "LogAlways",
                "Channel": "Security",
                "Provider": "Microsoft-Windows-Security-Auditing",
                "Computer": "SEC-SRV01",
                "ProcessID": "672",
                "ThreadID": "1424",
                "UserID": "Admin",
                "ActivityID": "5D9F45AE-022D-0002-B046-9F5D2D02DD01",
                "EventData": json.dumps({
                    "SubjectUserName": "Admin",
                    "SubjectLogonId": "0x35be7590",
                }),
                "Message": "Special privileges assigned to new logon.",
            },
            # Row 3: Security Event 4688 (Process Creation: cmd.exe in same session 3 HOURS later - wide window)
            {
                "RecordID": "1003",
                "TimeCreated": "2026-09-15 13:00:00",
                "EventID": "4688",
                "LevelName": "Information",
                "Channel": "Security",
                "Provider": "Microsoft-Windows-Security-Auditing",
                "Computer": "SEC-SRV01",
                "ProcessID": "4",
                "ThreadID": "80",
                "UserID": "Admin",
                "ActivityID": None,
                "EventData": json.dumps({
                    "SubjectLogonId": "0x35be7590",
                    "NewProcessId": "1064",
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                }),
                "Message": "A new process has been created.",
            },
            # Row 4: System Event 7036 (Service started by process 672 within tight window - 45s after anchor)
            {
                "RecordID": "2001",
                "TimeCreated": "2026-09-15 10:00:45",
                "EventID": "7036",
                "LevelName": "Information",
                "Channel": "System",
                "Provider": "Service Control Manager",
                "Computer": "SEC-SRV01",
                "ProcessID": "672",
                "ThreadID": "2100",
                "UserID": "SYSTEM",
                "ActivityID": None,
                "EventData": json.dumps({"param1": "W32Time", "param2": "running"}),
                "Message": "The Windows Time service entered the running state.",
            },
            # Row 5: System Event 7036 (Unrelated process 672 reused 4 HOURS LATER - should be REJECTED by tight PID window)
            {
                "RecordID": "2002",
                "TimeCreated": "2026-09-15 14:00:00",
                "EventID": "7036",
                "LevelName": "Information",
                "Channel": "System",
                "Provider": "Service Control Manager",
                "Computer": "SEC-SRV01",
                "ProcessID": "672",
                "ThreadID": "2200",
                "UserID": "SYSTEM",
                "ActivityID": None,
                "EventData": json.dumps({"param1": "BITS", "param2": "stopped"}),
                "Message": "The BITS service entered the stopped state.",
            },
            # Row 6: Sysmon Event 1 (Process Start: PID 18404 at 10:05:00)
            {
                "RecordID": "3001",
                "TimeCreated": "2026-09-15 10:05:00",
                "EventID": "1",
                "LevelName": "Information",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider": "Microsoft-Windows-Sysmon",
                "Computer": "SEC-SRV01",
                "ProcessID": "18404",
                "ThreadID": "300",
                "UserID": "Admin",
                "ActivityID": None,
                "EventData": json.dumps({
                    "UtcTime": "2026-09-15 10:05:00.000",
                    "ProcessId": "18404",
                    "Image": "C:\\Windows\\System32\\calc.exe",
                }),
                "Message": "Process Create: calc.exe",
            },
            # Row 7: Sysmon Event 1 (Different process reusing PID 18404 2 hours later at 12:05:00)
            {
                "RecordID": "3002",
                "TimeCreated": "2026-09-15 12:05:00",
                "EventID": "1",
                "LevelName": "Information",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider": "Microsoft-Windows-Sysmon",
                "Computer": "SEC-SRV01",
                "ProcessID": "18404",
                "ThreadID": "310",
                "UserID": "DevUser",
                "ActivityID": None,
                "EventData": json.dumps({
                    "UtcTime": "2026-09-15 12:05:00.000",
                    "ProcessId": "18404",
                    "Image": "C:\\Windows\\System32\\notepad.exe",
                }),
                "Message": "Process Create: notepad.exe",
            },
        ]

        df = pd.DataFrame(rows)
        self.conn.register("canonical_logs_seed", df)
        self.conn.execute("CREATE TABLE canonical_logs AS SELECT * FROM canonical_logs_seed")
        self.conn.unregister("canonical_logs_seed")

    def test_01_entity_extraction_and_denormalization(self):
        """Acceptance Criteria 1:
        Every entity extracted from a source event produces a row in the correlation
        table with the correct entity_type and denormalized metadata.
        """
        stats = self.mgr.build_correlation_index(self.conn, canonical_table="canonical_logs")
        self.assertEqual(stats["indexed_records"], 7)
        self.assertGreater(stats["total_correlations"], 15)

        # Inspect entities for Record 1001
        rows = self.conn.execute(
            """
            SELECT entity_type, entity_value, confidence, confidence_weight, source_type, event_id
            FROM entity_correlations
            WHERE event_record_id = '1001'
            """
        ).fetchall()

        etypes = {r[0]: r for r in rows}
        self.assertIn("logon_id", etypes)
        self.assertEqual(etypes["logon_id"][1], "0x35be7590")
        self.assertEqual(etypes["logon_id"][2], "High")
        self.assertEqual(etypes["logon_id"][3], 1.0)
        self.assertEqual(etypes["logon_id"][4], "Security")
        self.assertEqual(etypes["logon_id"][5], "4624")

        self.assertIn("activity_id", etypes)
        self.assertEqual(etypes["activity_id"][1], "5D9F45AE-022D-0002-B046-9F5D2D02DD01")

        self.assertIn("ip_address", etypes)
        self.assertEqual(etypes["ip_address"][1], "192.168.1.50")

        self.assertIn("process_id", etypes)
        self.assertEqual(etypes["process_id"][1], "672")

    def test_02_logon_id_wide_window_correlation(self):
        """Acceptance Criteria 2:
        A logon_id match spanning several hours (3 hours later) is still returned
        as high-confidence correlation.
        """
        self.mgr.build_correlation_index(self.conn, canonical_table="canonical_logs")

        # Find correlated events for Anchor Record 1001
        correlated = self.mgr.find_correlated(self.conn, anchor_event_record_id="1001")
        rec_ids = [c["event_record_id"] for c in correlated]

        # Record 1003 is 3 hours later, sharing logon_id 0x35be7590
        self.assertIn("1003", rec_ids)
        rec_1003 = next(c for c in correlated if c["event_record_id"] == "1003")
        self.assertEqual(rec_1003["entity_type"], "logon_id")
        self.assertEqual(rec_1003["confidence"], "High")
        self.assertEqual(rec_1003["confidence_weight"], 1.0)
        self.assertIn("+3h", rec_1003["time_delta_str"])

    def test_03_bare_pid_tight_window_rejection(self):
        """Acceptance Criteria 3:
        A bare process_id match spanning several hours (4 hours later) is not returned
        (strictly filtered out by the 300s tight window) to prevent PID reuse false positives.
        Meanwhile, a bare process_id match 45s later IS returned.
        """
        self.mgr.build_correlation_index(self.conn, canonical_table="canonical_logs")

        correlated = self.mgr.find_correlated(self.conn, anchor_event_record_id="1001")
        rec_ids = [c["event_record_id"] for c in correlated]

        # Record 2001 (45 seconds later, sharing PID 672) MUST be present
        self.assertIn("2001", rec_ids)

        # Record 2002 (4 hours later, sharing PID 672) MUST NOT be present
        self.assertNotIn("2002", rec_ids, "Bare PID match 4 hours later must be rejected by tight window")

    def test_04_process_start_time_disambiguation(self):
        """Acceptance Criteria 4:
        When process-start timestamps are available (Sysmon Event 1), process_id correlation
        uses (pid, start_time) and correctly distinguishes two different processes
        that reused the same PID at different times.
        """
        self.mgr.build_correlation_index(self.conn, canonical_table="canonical_logs")

        # Check entity values for Record 3001 and 3002
        rows_3001 = self.conn.execute(
            "SELECT entity_value FROM entity_correlations WHERE event_record_id = '3001' AND entity_type = 'process_id_disambiguated'"
        ).fetchall()
        rows_3002 = self.conn.execute(
            "SELECT entity_value FROM entity_correlations WHERE event_record_id = '3002' AND entity_type = 'process_id_disambiguated'"
        ).fetchall()

        self.assertTrue(len(rows_3001) > 0)
        self.assertTrue(len(rows_3002) > 0)

        val_3001 = rows_3001[0][0]
        val_3002 = rows_3002[0][0]

        # They share PID 18404 but have different start timestamps!
        self.assertIn("18404", val_3001)
        self.assertIn("18404", val_3002)
        self.assertNotEqual(val_3001, val_3002, "Different start times must produce different disambiguated entity values")

        # Correlating 3001 should NOT match 3002
        corr_3001 = self.mgr.find_correlated(self.conn, anchor_event_record_id="3001")
        corr_3001_ids = [c["event_record_id"] for c in corr_3001]
        self.assertNotIn("3002", corr_3001_ids, "Disambiguated process IDs must not falsely correlate across PID reuse")

    def test_05_multi_channel_correlation_ranking(self):
        """Acceptance Criteria 5:
        find_correlated returns results ranked by confidence weight DESC, then by time proximity ASC,
        and every result includes event_record_id, source_type, and time_delta.
        """
        self.mgr.build_correlation_index(self.conn, canonical_table="canonical_logs")

        correlated = self.mgr.find_correlated(self.conn, anchor_event_record_id="1001")
        self.assertGreaterEqual(len(correlated), 2)

        # High confidence (1.0) must come before Low confidence (0.3)
        for i in range(len(correlated) - 1):
            curr_wt = correlated[i]["confidence_weight"]
            next_wt = correlated[i + 1]["confidence_weight"]
            self.assertGreaterEqual(curr_wt, next_wt)

        # First item should be Record 1002 (High confidence, +14s)
        self.assertEqual(correlated[0]["event_record_id"], "1002")
        self.assertEqual(correlated[0]["confidence"], "High")
        self.assertIn("+14s", correlated[0]["time_delta_str"])
        self.assertIn("Shared", correlated[0]["relation_reason"])

    def test_06_idempotency_on_rerun(self):
        """Acceptance Criteria 6:
        Re-running index construction on the same source data is idempotent — zero duplicate rows.
        """
        stats_1 = self.mgr.build_correlation_index(self.conn, canonical_table="canonical_logs")
        count_1 = self.conn.execute("SELECT COUNT(*) FROM entity_correlations").fetchone()[0]

        # Re-run on same data
        stats_2 = self.mgr.build_correlation_index(self.conn, canonical_table="canonical_logs")
        count_2 = self.conn.execute("SELECT COUNT(*) FROM entity_correlations").fetchone()[0]

        self.assertEqual(stats_2["indexed_records"], 0, "Second run should process 0 new records")
        self.assertEqual(count_1, count_2, "Total rows in entity_correlations must remain unchanged")

    def test_07_traceability_to_canonical_logs(self):
        """Acceptance Criteria 7:
        Every returned event_record_id from find_correlated resolves directly to a real
        canonical record in DuckDB.
        """
        self.mgr.build_correlation_index(self.conn, canonical_table="canonical_logs")

        correlated = self.mgr.find_correlated(self.conn, anchor_event_record_id="1001")
        for c in correlated:
            rec_id = c["event_record_id"]
            db_row = self.conn.execute(
                "SELECT RecordID, Channel, EventID, Message FROM canonical_logs WHERE RecordID = ?",
                [rec_id],
            ).fetchone()
            self.assertIsNotNone(db_row, f"Record {rec_id} must resolve to canonical_logs")
            self.assertEqual(str(db_row[0]), rec_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
