#!/usr/bin/env python3
"""
================================================================================
Unit & Acceptance Tests for Query Execution Layer (query_executor.py)
================================================================================
Tests verify all non-negotiable acceptance criteria:
  1. Fixed Metadata Only: Filtering on fixed metadata (source_type, level) returns
     correct records without depending on event_data parsing.
  2. Event Details Inside JSON: Filtering on event-detail fields (IpAddress,
     TargetUserName) correctly matches against event_data JSON payload.
  3. Combined Metadata & Event Details: Single unified query combines fixed column
     and JSON event_data conditions simultaneously (no separate passes).
  4. Canonical Field Name Resolution: Resolves canonical names (ip_address) across
     heterogeneous Windows EventData keys (IpAddress vs SourceAddress).
  5. Vector Candidates Intersection: Intersects candidate event_record_ids from
     vector search with structured metadata filters in a single query.
  6. Evidence Preservation: Every returned row contains event_record_id, full
     event_data JSON, and raw_xml for forensic verification.
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

from query_executor import (
    EventQueryExecutor,
    execute_forensic_filter_query,
    query_event_data,
    resolve_json_keys_for_field,
)
from query_parser import EntityFilters, QueryFilter, TimeRange


class TestQueryExecutor(unittest.TestCase):
    """Acceptance test suite for EventQueryExecutor."""

    def setUp(self):
        self.conn = duckdb.connect(":memory:")
        self.executor = EventQueryExecutor()
        self._seed_database()

    def tearDown(self):
        self.conn.close()

    def _seed_database(self):
        """Creates a realistic canonical DuckDB table with fixed columns and heterogeneous event_data."""
        rows = [
            # Row 1: Security Event 4625 (Failed Logon from IP 192.168.1.50 for user admin)
            {
                "event_record_id": "REC_00001",
                "source_type": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": "4625",
                "level": "Error",
                "time_created_utc": "2026-09-14T08:15:00Z",
                "process_id": "672",
                "thread_id": "1420",
                "computer": "SEC-SRV-01",
                "user_id": "S-1-5-21-500",
                "event_data": json.dumps({
                    "TargetUserName": "admin",
                    "SubjectLogonId": "0x0",
                    "IpAddress": "192.168.1.50",
                    "IpPort": "54231",
                    "Status": "0xC000006D",
                    "SubStatus": "0xC000006A",
                }),
                "raw_xml": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID></System></Event>",
                "message": "An account failed to log on.",
            },
            # Row 2: Security Event 4624 (Successful Logon from IP 192.168.1.50 for user jdoe)
            {
                "event_record_id": "REC_00002",
                "source_type": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": "4624",
                "level": "Information",
                "time_created_utc": "2026-09-14T08:30:00Z",
                "process_id": "672",
                "thread_id": "1424",
                "computer": "SEC-SRV-01",
                "user_id": "S-1-5-21-1001",
                "event_data": json.dumps({
                    "TargetUserName": "jdoe",
                    "TargetLogonId": "0x3e7",
                    "IpAddress": "192.168.1.50",
                    "LogonType": "3",
                }),
                "raw_xml": "<Event><System><EventID>4624</EventID></System></Event>",
                "message": "An account was successfully logged on.",
            },
            # Row 3: Security Event 4625 (Failed Logon from IP 10.0.0.5 for user admin)
            {
                "event_record_id": "REC_00003",
                "source_type": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": "4625",
                "level": "Error",
                "time_created_utc": "2026-09-14T09:00:00Z",
                "process_id": "672",
                "thread_id": "1428",
                "computer": "SEC-SRV-01",
                "user_id": "S-1-5-21-500",
                "event_data": json.dumps({
                    "TargetUserName": "admin",
                    "SubjectLogonId": "0x0",
                    "IpAddress": "10.0.0.5",
                    "Status": "0xC000006D",
                }),
                "raw_xml": "<Event><System><EventID>4625</EventID></System></Event>",
                "message": "An account failed to log on from 10.0.0.5.",
            },
            # Row 4: System Event 7036 (Service Running State)
            {
                "event_record_id": "REC_00004",
                "source_type": "System",
                "provider": "Service Control Manager",
                "event_id": "7036",
                "level": "Information",
                "time_created_utc": "2026-09-14T09:30:00Z",
                "process_id": "1064",
                "thread_id": "2100",
                "computer": "SEC-SRV-01",
                "user_id": "S-1-5-18",
                "event_data": json.dumps({
                    "param1": "Windows Update",
                    "param2": "running",
                }),
                "raw_xml": "<Event><System><EventID>7036</EventID></System></Event>",
                "message": "The Windows Update service entered the running state.",
            },
            # Row 5: System Network Connection Event (using SourceAddress instead of IpAddress)
            {
                "event_record_id": "REC_00005",
                "source_type": "System",
                "provider": "Microsoft-Windows-TCPIP",
                "event_id": "4227",
                "level": "Warning",
                "time_created_utc": "2026-09-14T10:00:00Z",
                "process_id": "4",
                "thread_id": "80",
                "computer": "SEC-SRV-01",
                "user_id": "S-1-5-18",
                "event_data": json.dumps({
                    "SourceAddress": "10.0.0.5",
                    "DestAddress": "192.168.1.1",
                    "Protocol": "TCP",
                }),
                "raw_xml": "<Event><System><EventID>4227</EventID></System></Event>",
                "message": "TCP/IP failed to establish an outgoing connection.",
            },
            # Row 6: Application Event 1000 (Application Error with non-JSON event_data / malformed edge case)
            {
                "event_record_id": "REC_00006",
                "source_type": "Application",
                "provider": "Application Error",
                "event_id": "1000",
                "level": "Error",
                "time_created_utc": "2026-09-14T11:00:00Z",
                "process_id": "5520",
                "thread_id": "880",
                "computer": "SEC-SRV-01",
                "user_id": "S-1-5-21-1001",
                "event_data": "Plain text error description: faulting module ntdll.dll",
                "raw_xml": "<Event><System><EventID>1000</EventID></System></Event>",
                "message": "Faulting application test.exe, version 1.0.0.0.",
            },
        ]

        df = pd.DataFrame(rows)
        self.conn.register("canonical_logs_seed", df)
        self.conn.execute("CREATE TABLE canonical_logs AS SELECT * FROM canonical_logs_seed")
        self.conn.unregister("canonical_logs_seed")

    def test_01_fixed_metadata_only_query(self):
        """Acceptance Criteria 1:
        A query filtering only on a fixed metadata field (e.g., source_type=Security, level=Error)
        returns correct results with no dependency on event_data parsing.
        """
        q_filter = QueryFilter(
            time_range=None,
            source_type="Security",
            entity_filters=EntityFilters(),
            event_id=None,
            level="Error",
            semantic_query="",
            intent="pattern_or_aggregate",
            raw_query="Show security error events",
        )

        results = self.executor.execute_query(self.conn, q_filter, canonical_table="canonical_logs")

        # Expect REC_00001 and REC_00003 (both Security Error)
        self.assertEqual(len(results), 2)
        rec_ids = list(results["event_record_id"])
        self.assertIn("REC_00001", rec_ids)
        self.assertIn("REC_00003", rec_ids)
        for _, row in results.iterrows():
            self.assertEqual(row["source_type"], "Security")
            self.assertEqual(row["level"], "Error")

    def test_02_event_data_json_payload_query(self):
        """Acceptance Criteria 2:
        A query filtering on an event-detail field not present as a top-level column
        (e.g., a specific IpAddress or TargetUserName) correctly extracts and matches
        against the JSON payload, even though that field only exists for certain event types.
        """
        # Search specifically for IP address 192.168.1.50 inside event_data
        q_filter = QueryFilter(
            time_range=None,
            source_type=None,
            entity_filters=EntityFilters(ip_address="192.168.1.50"),
            event_id=None,
            level=None,
            semantic_query="",
            intent="specific_instance",
            raw_query="Find events from 192.168.1.50",
        )

        results = self.executor.execute_query(self.conn, q_filter, canonical_table="canonical_logs")

        # Expect REC_00001 and REC_00002 (both have IpAddress: 192.168.1.50 in event_data)
        self.assertEqual(len(results), 2)
        rec_ids = list(results["event_record_id"])
        self.assertIn("REC_00001", rec_ids)
        self.assertIn("REC_00002", rec_ids)

    def test_03_combined_metadata_and_event_data_query(self):
        """Acceptance Criteria 3:
        A query combining a metadata filter and an event-detail filter
        (e.g., source_type=Security AND ip_address=10.0.0.5) applies both conditions
        together in one query, not as separate unreconciled result sets.
        """
        q_filter = QueryFilter(
            time_range=None,
            source_type="Security",
            entity_filters=EntityFilters(ip_address="10.0.0.5"),
            event_id=None,
            level="Error",
            semantic_query="",
            intent="specific_instance",
            raw_query="Find security error from 10.0.0.5",
        )

        results = self.executor.execute_query(self.conn, q_filter, canonical_table="canonical_logs")

        # Must return exactly REC_00003 (Security, Error, and IP 10.0.0.5)
        # Note: REC_00005 also has 10.0.0.5, but its source_type is System, not Security!
        self.assertEqual(len(results), 1)
        self.assertEqual(results.iloc[0]["event_record_id"], "REC_00003")
        self.assertEqual(results.iloc[0]["source_type"], "Security")
        self.assertEqual(results.iloc[0]["level"], "Error")

    def test_04_canonical_field_name_resolution(self):
        """Acceptance Criteria 4:
        When a canonical field name maps to different actual JSON keys depending on event type,
        the resolution logic tries the right key(s) rather than requiring the user to know
        internal Windows field naming quirks.
        """
        # 1. Query for IP 10.0.0.5 without event_id hint -> matches both IpAddress (REC_00003) and SourceAddress (REC_00005)
        clause, params = query_event_data("ip_address", "10.0.0.5")
        self.assertIn("IpAddress", clause)
        self.assertIn("SourceAddress", clause)

        q_all_ips = QueryFilter(
            time_range=None,
            source_type=None,
            entity_filters=EntityFilters(ip_address="10.0.0.5"),
            event_id=None,
            level=None,
            semantic_query="",
            intent="specific_instance",
            raw_query="activity from 10.0.0.5",
        )
        res_all = self.executor.execute_query(self.conn, q_all_ips, canonical_table="canonical_logs")
        self.assertEqual(len(res_all), 2, "Should resolve across both IpAddress and SourceAddress keys")
        rec_ids = list(res_all["event_record_id"])
        self.assertIn("REC_00003", rec_ids)
        self.assertIn("REC_00005", rec_ids)

        # 2. Query with Event 4625 hint -> specializes to IpAddress
        hint_keys = resolve_json_keys_for_field("ip_address", event_id_hint="4625")
        self.assertEqual(hint_keys, ["IpAddress"])

    def test_05_vector_candidates_intersection(self):
        """Acceptance Criteria 5:
        If semantic_query / vector search was also run, intersect its resulting event_record_ids
        with this structured query's results in a single unified SQL query.
        """
        # Suppose vector search retrieved candidates: REC_00001, REC_00002, REC_00004
        candidates = ["REC_00001", "REC_00002", "REC_00004"]

        # Structured filter: level = Error
        q_filter = QueryFilter(
            time_range=None,
            source_type=None,
            entity_filters=EntityFilters(),
            event_id=None,
            level="Error",
            semantic_query="logon failure",
            intent="specific_instance",
            raw_query="logon failure error",
        )

        # Intersect vector candidates with structured filter
        results = self.executor.execute_query(
            self.conn,
            q_filter,
            candidate_record_ids=candidates,
            canonical_table="canonical_logs",
        )

        # Only REC_00001 is both in candidates AND level == Error
        # (REC_00002 and REC_00004 are in candidates but not Error; REC_00003 and REC_00006 are Error but not in candidates)
        self.assertEqual(len(results), 1)
        self.assertEqual(results.iloc[0]["event_record_id"], "REC_00001")

    def test_06_evidence_preservation_columns(self):
        """Acceptance Criteria 6:
        Every returned record includes its event_record_id and full event_data/raw_xml,
        so the answer step can cite and display the original evidence directly.
        """
        q_filter = QueryFilter(
            time_range=TimeRange(
                start_utc="2026-09-14T08:00:00Z",
                end_utc="2026-09-14T08:45:00Z",
            ),
            source_type="Security",
            entity_filters=EntityFilters(process_id="672"),
            event_id="4625",
            level="Error",
            semantic_query="",
            intent="specific_instance",
            raw_query="failed logon around 8:15",
        )

        results = self.executor.execute_query(self.conn, q_filter, canonical_table="canonical_logs")

        self.assertEqual(len(results), 1)
        row = results.iloc[0]

        # Assert full required columns are present and untouched
        self.assertEqual(row["event_record_id"], "REC_00001")
        self.assertEqual(row["source_type"], "Security")
        self.assertEqual(row["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(row["event_id"], "4625")
        self.assertEqual(row["time_created_utc"], "2026-09-14T08:15:00Z")
        self.assertEqual(row["process_id"], "672")
        self.assertEqual(row["thread_id"], "1420")
        self.assertEqual(row["computer"], "SEC-SRV-01")
        self.assertEqual(row["user_id"], "S-1-5-21-500")

        # Full evidence payload preserved
        self.assertIn("IpAddress", row["event_data"])
        self.assertIn("192.168.1.50", row["event_data"])
        self.assertIn("<EventID>4625</EventID>", row["raw_xml"])

    def test_07_sid_and_user_resolution(self):
        """Verify that querying for well-known account 'SYSTEM' resolves to S-1-5-18,
        matching rows stored with SID user_id.
        """
        q_filter = QueryFilter(
            time_range=None,
            source_type=None,
            entity_filters=EntityFilters(user_id="SYSTEM"),
            event_id=None,
            level=None,
            semantic_query="",
            intent="specific_instance",
            raw_query="events where user is SYSTEM",
        )

        results = self.executor.execute_query(self.conn, q_filter, canonical_table="canonical_logs")
        rec_ids = list(results["event_record_id"])
        # REC_00004 and REC_00005 both have user_id = S-1-5-18
        self.assertIn("REC_00004", rec_ids)
        self.assertIn("REC_00005", rec_ids)

    def test_08_hex_and_dec_process_id(self):
        """Verify that querying for hex process ID 0x428 matches decimal 1064 in DuckDB."""
        q_filter = QueryFilter(
            time_range=None,
            source_type=None,
            entity_filters=EntityFilters(process_id="0x428"),
            event_id=None,
            level=None,
            semantic_query="",
            intent="specific_instance",
            raw_query="events for process 0x428",
        )

        results = self.executor.execute_query(self.conn, q_filter, canonical_table="canonical_logs")
        self.assertEqual(len(results), 1)
        self.assertEqual(results.iloc[0]["event_record_id"], "REC_00004")
        self.assertEqual(str(results.iloc[0]["process_id"]), "1064")

    def test_09_process_name_and_provider_and_status_code(self):
        """Verify querying by process_name, provider, and status_code."""
        # 1. Provider
        q_prov = QueryFilter(
            time_range=None,
            source_type=None,
            entity_filters=EntityFilters(provider="Service Control Manager"),
            event_id=None,
            level=None,
            semantic_query="",
            intent="specific_instance",
            raw_query="provider Service Control Manager",
        )
        res_prov = self.executor.execute_query(self.conn, q_prov, canonical_table="canonical_logs")
        self.assertEqual(len(res_prov), 1)
        self.assertEqual(res_prov.iloc[0]["event_record_id"], "REC_00004")

        # 2. Status code inside event_data
        q_status = QueryFilter(
            time_range=None,
            source_type=None,
            entity_filters=EntityFilters(status_code="0xC000006D"),
            event_id=None,
            level=None,
            semantic_query="",
            intent="specific_instance",
            raw_query="logon failure status 0xC000006D",
        )
        res_status = self.executor.execute_query(self.conn, q_status, canonical_table="canonical_logs")
        # REC_00001 and REC_00003 have Status 0xC000006D in event_data
        self.assertEqual(len(res_status), 2)
        rec_ids = list(res_status["event_record_id"])
        self.assertIn("REC_00001", rec_ids)
        self.assertIn("REC_00003", rec_ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
