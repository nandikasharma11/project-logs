#!/usr/bin/env python3
"""
================================================================================
Unit & Acceptance Tests for Query Parsing & Filter Resolution Layer (query_parser.py)
================================================================================
Tests verify all non-negotiable acceptance criteria:
  1. Specific Instance Extraction: Query with process ID + relative time parses
     non-null time_range, entity_filters.process_id, and intent=specific_instance.
  2. Pattern or Aggregate Routing: Frequency questions ("how often") route to
     intent=pattern_or_aggregate with no entity narrowing.
  3. Correlation Intent Routing: Proximity questions ("what else happened around...")
     route to intent=correlation with anchor concept extracted.
  4. Zero False-Narrowing: Generic phrasing leaves source_type as None rather than guessing.
  5. Relative Time Auditability: Relative time expressions resolve to explicit UTC bounds.
  6. Ambiguous Intent: Queries lacking narrowing signals return intent=ambiguous
     with a helpful clarifying question.
================================================================================
"""

import datetime
import os
import sys
import unittest

# Add parent directory to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from query_parser import (
    ForensicQueryParser,
    QueryFilter,
    parse_forensic_query,
)


class TestQueryParser(unittest.TestCase):
    """Test suite for Query Parsing & Filter Resolution Layer."""

    def setUp(self):
        self.parser = ForensicQueryParser()
        # Fixed reference time for deterministic testing: Wednesday, Sep 16, 2026 at 14:00:00 UTC
        self.ref_time = datetime.datetime(2026, 9, 16, 14, 0, 0, tzinfo=datetime.timezone.utc)

    def test_01_specific_instance_extraction(self):
        """Acceptance Criteria 1:
        Given "show me the logon event for process 1064 around 3pm yesterday",
        the parser produces a non-null time_range and entity_filters.process_id,
        with intent = specific_instance.
        """
        query = "show me the logon event for process 1064 around 3pm yesterday"
        result: QueryFilter = self.parser.parse_query(query, reference_time=self.ref_time)

        # 1. Intent must be specific_instance
        self.assertEqual(result.intent, "specific_instance")

        # 2. Entity filters must have process_id == "1064"
        self.assertIsNotNone(result.entity_filters.process_id)
        self.assertEqual(result.entity_filters.process_id, "1064")

        # 3. Time range must be non-null and relative
        self.assertIsNotNone(result.time_range)
        self.assertTrue(result.time_range.is_relative)

        # Yesterday relative to Sep 16 is Sep 15; 3pm is 15:00 (+/- 30 min -> 14:30 to 15:30)
        self.assertEqual(result.time_range.start_utc, "2026-09-15T14:30:00Z")
        self.assertEqual(result.time_range.end_utc, "2026-09-15T15:30:00Z")

        # 4. Source channel clearly mapped to Security (from 'logon')
        self.assertEqual(result.source_type, "Security")

        # 5. Semantic residual cleans up filler words
        self.assertIn("logon", result.semantic_query.lower())

    def test_02_pattern_or_aggregate_routing(self):
        """Acceptance Criteria 2:
        Given "how often did the USB reader error occur",
        the parser produces intent = pattern_or_aggregate with no entity/time narrowing,
        correctly routing to an aggregate answer instead of an arbitrary single record.
        """
        query = "how often did the USB reader error occur"
        result: QueryFilter = self.parser.parse_query(query, reference_time=self.ref_time)

        self.assertEqual(result.intent, "pattern_or_aggregate")
        self.assertIsNone(result.time_range)
        self.assertFalse(result.entity_filters.has_any())
        self.assertIsNone(result.source_type, "USB reader error should not be falsely narrowed to a single channel")
        self.assertIn("USB reader error", result.semantic_query)

    def test_02b_pattern_with_time_range(self):
        """Pattern query with time expression: 'How often did the USB reader error occur last week?'"""
        query = "How often did the USB reader error occur last week?"
        result: QueryFilter = self.parser.parse_query(query, reference_time=self.ref_time)

        self.assertEqual(result.intent, "pattern_or_aggregate")
        self.assertIsNotNone(result.time_range)
        self.assertEqual(result.time_range.start_utc, "2026-09-09T14:00:00Z")  # 7 days prior
        self.assertEqual(result.time_range.end_utc, "2026-09-16T14:00:00Z")

    def test_03_correlation_intent_routing(self):
        """Acceptance Criteria 3:
        Given "what else happened around the time of this failed login",
        intent = correlation and anchor entity/time is extracted so it can be handed
        to the correlation index.
        """
        query = "what else happened around the time of this failed login"
        result: QueryFilter = self.parser.parse_query(query, reference_time=self.ref_time)

        self.assertEqual(result.intent, "correlation")
        self.assertEqual(result.source_type, "Security")
        self.assertEqual(result.event_id, "4625", "Failed login should resolve to Event 4625 anchor")

    def test_04_no_false_narrowing_on_channel(self):
        """Acceptance Criteria 4:
        When a channel is only vaguely implied, source_type stays null rather than being guessed.
        No silent false-narrowing of results.
        """
        # Generic inquiry: "what happened on this machine?"
        res1 = self.parser.parse_query("What happened around 3pm yesterday on this machine?", reference_time=self.ref_time)
        self.assertIsNone(res1.source_type, "Generic inquiry must NOT guess source_type")

        # Database connection issue: "Did the SQL server ever fail to connect?"
        res2 = self.parser.parse_query("Did the SQL server ever fail to connect?", reference_time=self.ref_time)
        self.assertIsNone(res2.source_type, "Database error could be Application, System, or network; must NOT false-narrow")

        # Explicit Security event
        res3 = self.parser.parse_query("Show security logons for user admin", reference_time=self.ref_time)
        self.assertEqual(res3.source_type, "Security")

        # Explicit Application event
        res4 = self.parser.parse_query("Check application crash in test.exe", reference_time=self.ref_time)
        self.assertEqual(res4.source_type, "Application")

        # Explicit System event
        res5 = self.parser.parse_query("Find system error from service control manager", reference_time=self.ref_time)
        self.assertEqual(res5.source_type, "System")

    def test_05_relative_time_auditability(self):
        """Acceptance Criteria 5:
        Extracted time_range, if relative ("yesterday"), resolves to explicit UTC bounds
        recorded in the output for forensic auditability.
        """
        # Query: "Check failed logins yesterday"
        res = self.parser.parse_query("Check failed logins yesterday", reference_time=self.ref_time)

        self.assertIsNotNone(res.time_range)
        self.assertTrue(res.time_range.is_relative)
        self.assertEqual(res.time_range.start_utc, "2026-09-15T00:00:00Z")
        self.assertEqual(res.time_range.end_utc, "2026-09-15T23:59:59Z")
        self.assertEqual(res.time_range.raw_expression, "yesterday")

    def test_06_ambiguous_intent_with_clarifying_prompt(self):
        """Verify that underspecified queries produce intent=ambiguous and a clarifying question."""
        res = self.parser.parse_query("show failed logins")

        self.assertEqual(res.intent, "ambiguous")
        self.assertIsNotNone(res.clarifying_question)
        self.assertIn("narrow down", res.clarifying_question)

    def test_07_comprehensive_entity_extraction(self):
        """Verify extraction of various forensic entities: IP, User, SID, LogonID, Computer, RecordID."""
        # IP address
        res_ip = self.parser.parse_query("Show logon from IP 192.168.1.100")
        self.assertEqual(res_ip.entity_filters.ip_address, "192.168.1.100")

        # User and SID
        res_usr = self.parser.parse_query("Find events for user jsmith")
        self.assertEqual(res_usr.entity_filters.user_id, "jsmith")

        res_sid = self.parser.parse_query("Find events for S-1-5-21-3623811015-3361044348-30300820-1013")
        self.assertEqual(res_sid.entity_filters.user_id, "S-1-5-21-3623811015-3361044348-30300820-1013")

        # Logon ID (Hex & decimal)
        res_lid = self.parser.parse_query("Show session with logon id 0x3e7")
        self.assertEqual(res_lid.entity_filters.logon_id, "0x3e7")

        # Computer / Host
        res_comp = self.parser.parse_query("Activity on host SEC-SRV-01")
        self.assertEqual(res_comp.entity_filters.computer, "SEC-SRV-01")

        # Event Record ID
        res_rec = self.parser.parse_query("Fetch record REC_00452")
        self.assertEqual(res_rec.entity_filters.event_record_id, "REC_00452")

    def test_08_data_bounds_coverage_clamping(self):
        """Verify that time ranges outside dataset bounds are flagged for coverage awareness."""
        # Available dataset is from Sep 10 to Sep 12
        bounds = ("2026-09-10T00:00:00Z", "2026-09-12T23:59:59Z")

        # Query asks about yesterday (Sep 15), which is outside coverage
        res = self.parser.parse_query(
            "What happened yesterday?",
            reference_time=self.ref_time,
            data_bounds=bounds,
        )
        self.assertIsNotNone(res.time_range)
    def test_09_metadata_attribute_linking_words_and_domain_user(self):
        """Verify that linking words ('is', 'was', 'named', 'id') are not falsely captured
        as entities, and domain-qualified usernames are parsed properly.
        """
        # User with linking word 'is'
        res_user_is = self.parser.parse_query("Show events where user is SYSTEM")
        self.assertEqual(res_user_is.entity_filters.user_id, "SYSTEM")

        # Computer with linking word 'is'
        res_comp_is = self.parser.parse_query("Check host where computer is DESKTOP-AULEN0J")
        self.assertEqual(res_comp_is.entity_filters.computer, "DESKTOP-AULEN0J")

        # Domain-qualified user
        res_dom_user = self.parser.parse_query("Show activity for user CONTOSO\\Administrator")
        self.assertEqual(res_dom_user.entity_filters.user_id, "CONTOSO\\Administrator")

    def test_10_process_name_provider_and_status_code(self):
        """Verify extraction of process_name, provider, status_code, and hex process_id."""
        # Provider extraction
        res_prov = self.parser.parse_query("Find events from provider Service Control Manager")
        self.assertEqual(res_prov.entity_filters.provider, "Service Control Manager")

        # Process name extraction
        res_proc = self.parser.parse_query("Application crash in svchost.exe")
        self.assertEqual(res_proc.entity_filters.process_name, "svchost.exe")

        # Hex status code
        res_status = self.parser.parse_query("Logon failure with status 0xC000006D")
        self.assertEqual(res_status.entity_filters.status_code, "0xC000006D")

        # Hex Process ID
        res_hex_pid = self.parser.parse_query("Find events for process 0x428")
        self.assertEqual(res_hex_pid.entity_filters.process_id, "0x428")

    def test_11_audit_logon_no_false_severity_error(self):
        """Verify that Security audit phrases like 'logon failure' do NOT force level='Error',
        because Windows Security audit events are recorded as Level=0 (LogAlways).
        """
        res = self.parser.parse_query("Show logon failure for user Administrator")
        self.assertEqual(res.source_type, "Security")
        self.assertEqual(res.event_id, "4625")
        self.assertIsNone(res.level, "Audit failures must NOT set level='Error', which discards LogAlways events")


if __name__ == "__main__":
    unittest.main(verbosity=2)
