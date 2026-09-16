#!/usr/bin/env python3
"""
================================================================================
Unit & Acceptance Tests for Deduplication & Templating Layer (log_templater.py)
================================================================================
Tests verify all non-negotiable acceptance criteria:
  1. Exact Instance Count: COUNT(template_instances) equals canonical log row count.
  2. Complete Traceability: Returns complete, exact list of event_record_ids for a template.
  3. High-Frequency Deduplication: 80%+ duplicate patterns collapse to 1 template with
     accurate total_count while preserving every individual occurrence in instances table.
  4. Idempotency: Re-running ingestion does not create duplicate templates or instances.
  5. Evidentiary Integrity: Canonical record store is NEVER modified, written to, or deleted.
  6. Multi-Channel Partitioning & Persistence: Independent miners per source_type
     with state persistence across incremental runs.
  7. Representative Document Generation: Emits one embeddable document per template.
================================================================================
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

import duckdb
import pandas as pd

# Add parent directory to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_templater import (
    Drain3ChannelManager,
    DuckDBTemplateManager,
    get_forensic_masking_instructions,
)


class TestLogTemplater(unittest.TestCase):
    """Test suite for the Deduplication/Templating Layer."""

    def setUp(self):
        self.temp_state_dir = tempfile.mkdtemp(prefix="drain3_test_")
        self.conn = duckdb.connect(":memory:")

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.temp_state_dir):
            shutil.rmtree(self.temp_state_dir, ignore_errors=True)

    def _create_synthetic_canonical_logs(self, count: int = 100) -> pd.DataFrame:
        """Helper to generate a rich canonical dataset matching the 23-column schema."""
        rows = []
        for i in range(count):
            channel = "Security" if i % 3 == 0 else ("System" if i % 3 == 1 else "Application")
            event_id = "4625" if i % 3 == 0 else ("7045" if i % 3 == 1 else "1000")
            msg = (
                f"An account failed to log on with status 0xC000006A from IP 192.168.1.{i % 20} for user user_{i % 5}"
                if channel == "Security"
                else (
                    f"Service Service_{i % 4} installed with binary C:\\Windows\\System32\\svc_{i % 4}.exe"
                    if channel == "System"
                    else f"Application error in module app_{i % 3}.exe at memory address 0x7FFE00{i:02x}"
                )
            )

            rows.append({
                "event_record_id": f"REC_{i:05d}",
                "source_type": channel,
                "provider": "Microsoft-Windows-Security-Auditing" if channel == "Security" else "Service Control Manager",
                "event_id": event_id,
                "level": "Error" if i % 2 == 0 else "Information",
                "time_created_utc": f"2026-09-14T08:{i % 60:02d}:{i % 60:02d}Z",
                "process_id": "672",
                "thread_id": "1420",
                "computer": "SEC-SRV-01",
                "user_id": f"S-1-5-21-{i % 10}",
                "event_data": f'{{"TargetUserName": "user_{i % 5}", "SubStatus": "0x0"}}',
                "message": msg,
            })

        df = pd.DataFrame(rows)
        self.conn.register("canonical_logs", df)
        self.conn.execute("CREATE TABLE canonical_logs_store AS SELECT * FROM canonical_logs")
        self.conn.unregister("canonical_logs")
        return df

    def test_01_exact_instance_count_matches_canonical(self):
        """Acceptance Criteria 1:
        SELECT COUNT(*) FROM template_instances equals total canonical row count.
        Every record is mapped to exactly one template, none dropped.
        """
        self._create_synthetic_canonical_logs(count=120)
        manager = DuckDBTemplateManager(state_dir=self.temp_state_dir)

        result = manager.process_canonical_records(self.conn, canonical_table="canonical_logs_store")

        self.assertEqual(result["new_records_processed"], 120)
        self.assertEqual(result["total_instances_mapped"], 120)

        # SQL Level Verification
        canonical_count = self.conn.execute("SELECT COUNT(*) FROM canonical_logs_store").fetchone()[0]
        instance_count = self.conn.execute("SELECT COUNT(*) FROM template_instances").fetchone()[0]
        template_sum = self.conn.execute("SELECT SUM(total_count) FROM log_templates").fetchone()[0]

        self.assertEqual(canonical_count, 120)
        self.assertEqual(instance_count, 120)
        self.assertEqual(template_sum, 120)

        integrity = manager.verify_evidentiary_integrity(self.conn, canonical_table="canonical_logs_store")
        self.assertTrue(integrity["integrity_valid"], "Evidentiary integrity check must pass with 100% equality")

    def test_02_traceability_returns_all_records(self):
        """Acceptance Criteria 2:
        Given a template_id, returns the complete, exact list of event_record_ids (no truncation).
        """
        self._create_synthetic_canonical_logs(count=60)
        manager = DuckDBTemplateManager(state_dir=self.temp_state_dir)
        manager.process_canonical_records(self.conn, canonical_table="canonical_logs_store")

        templates = self.conn.execute("SELECT template_id, total_count FROM log_templates ORDER BY total_count DESC").fetchall()
        self.assertGreater(len(templates), 0)

        for tid, expected_count in templates:
            # Query instances API
            record_ids = manager.get_instances_for_template(self.conn, tid)
            self.assertEqual(
                len(record_ids),
                expected_count,
                f"Traceability failed: template {tid} has total_count={expected_count} but returned {len(record_ids)} records",
            )
            self.assertEqual(len(set(record_ids)), expected_count, "Record IDs must be distinct")

            # Query joined full records API
            full_records_df = manager.get_records_for_template(self.conn, tid, canonical_table="canonical_logs_store")
            self.assertEqual(len(full_records_df), expected_count)
            self.assertIn("extracted_variables", full_records_df.columns)
            self.assertIn("event_record_id", full_records_df.columns)

    def test_03_high_frequency_deduplication(self):
        """Acceptance Criteria 3:
        High-frequency case: A single template covering 80%+ of a channel's records
        shows 1 row in the template table with accurate total_count, while template_instances
        still holds every individual occurrence.
        """
        rows = []
        # Generate 100 Security logs: 85 are logon failures (same template), 15 are unique logoffs
        for i in range(85):
            rows.append({
                "event_record_id": f"HIGH_FREQ_{i:04d}",
                "source_type": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": "4625",
                "level": "Error",
                "time_created_utc": f"2026-09-14T08:00:{i % 60:02d}Z",
                "message": f"An account failed to log on with status 0xC000006A from IP 10.0.0.{i} for user admin",
            })

        for i in range(15):
            rows.append({
                "event_record_id": f"UNIQUE_{i:04d}",
                "source_type": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": "4634",
                "level": "Information",
                "time_created_utc": f"2026-09-14T09:00:{i:02d}Z",
                "message": f"An account user_{i} was successfully logged off at terminal {i}",
            })

        df = pd.DataFrame(rows)
        self.conn.register("high_freq_raw", df)
        self.conn.execute("CREATE TABLE high_freq_store AS SELECT * FROM high_freq_raw")

        manager = DuckDBTemplateManager(state_dir=self.temp_state_dir)
        manager.process_canonical_records(self.conn, canonical_table="high_freq_store")

        # Query templates for event 4625
        t_4625 = self.conn.execute("SELECT template_id, total_count, template_string FROM log_templates WHERE event_id = '4625'").fetchall()
        self.assertEqual(len(t_4625), 1, "85 identical failed logon patterns must collapse into exactly 1 template")
        self.assertEqual(t_4625[0][1], 85, "The template total_count must accurately reflect all 85 occurrences")

        # Verify all 85 individual instances are preserved
        mapped_4625 = manager.get_instances_for_template(self.conn, t_4625[0][0])
        self.assertEqual(len(mapped_4625), 85)
        self.assertIn("HIGH_FREQ_0000", mapped_4625)
        self.assertIn("HIGH_FREQ_0084", mapped_4625)

        # Verify total database instances equals 100
        total_instances = self.conn.execute("SELECT COUNT(*) FROM template_instances").fetchone()[0]
        self.assertEqual(total_instances, 100)

    def test_04_idempotency_on_rerun(self):
        """Acceptance Criteria 4:
        Re-running ingestion on the same source records does not create duplicate
        templates or duplicate instance-mapping rows.
        """
        self._create_synthetic_canonical_logs(count=50)
        manager = DuckDBTemplateManager(state_dir=self.temp_state_dir)

        # First run
        run1 = manager.process_canonical_records(self.conn, canonical_table="canonical_logs_store")
        self.assertEqual(run1["new_records_processed"], 50)
        self.assertEqual(run1["total_instances_mapped"], 50)

        templates_after_run1 = self.conn.execute("SELECT COUNT(*) FROM log_templates").fetchone()[0]
        instances_after_run1 = self.conn.execute("SELECT COUNT(*) FROM template_instances").fetchone()[0]
        sum_after_run1 = self.conn.execute("SELECT SUM(total_count) FROM log_templates").fetchone()[0]

        # Second run on the identical table
        run2 = manager.process_canonical_records(self.conn, canonical_table="canonical_logs_store")
        self.assertEqual(run2["new_records_processed"], 0, "Idempotent re-run must process 0 new records")

        templates_after_run2 = self.conn.execute("SELECT COUNT(*) FROM log_templates").fetchone()[0]
        instances_after_run2 = self.conn.execute("SELECT COUNT(*) FROM template_instances").fetchone()[0]
        sum_after_run2 = self.conn.execute("SELECT SUM(total_count) FROM log_templates").fetchone()[0]

        self.assertEqual(templates_after_run1, templates_after_run2, "Template count must remain identical")
        self.assertEqual(instances_after_run1, instances_after_run2, "Instance count must remain identical")
        self.assertEqual(sum_after_run1, sum_after_run2, "Total count sum must not inflate")

    def test_05_canonical_table_never_modified(self):
        """Acceptance Criteria 5 (Hard Constraint):
        No operation writes to, modifies, or deletes rows in the original canonical
        DuckDB record table. Evidentiary integrity preserved.
        """
        df_original = self._create_synthetic_canonical_logs(count=50)

        # Compute hash of original canonical table
        orig_data = self.conn.execute("SELECT * FROM canonical_logs_store ORDER BY event_record_id").fetchall()
        orig_hash = hashlib.sha256(str(orig_data).encode("utf-8")).hexdigest()

        # Execute full template mining
        manager = DuckDBTemplateManager(state_dir=self.temp_state_dir)
        manager.process_canonical_records(self.conn, canonical_table="canonical_logs_store")

        # Re-compute hash of canonical table
        post_data = self.conn.execute("SELECT * FROM canonical_logs_store ORDER BY event_record_id").fetchall()
        post_hash = hashlib.sha256(str(post_data).encode("utf-8")).hexdigest()

        self.assertEqual(orig_hash, post_hash, "Canonical table data was mutated! Must be strictly read-only.")
        self.assertEqual(len(orig_data), len(post_data), "Canonical table row count changed!")

    def test_06_per_channel_partitioning_and_persistence(self):
        """Verify that miners are partitioned per source_type (Security, System, Application)
        and that state persists to disk across restarts.
        """
        chan_mgr1 = Drain3ChannelManager(state_dir=self.temp_state_dir)

        # Security log
        sec_cluster, sec_tpl, _ = chan_mgr1.mine_log("Security", "User admin failed logon from 10.0.0.1")
        # System log with identical text
        sys_cluster, sys_tpl, _ = chan_mgr1.mine_log("System", "User admin failed logon from 10.0.0.1")

        # Ensure different miners handled them
        self.assertIn("Security", chan_mgr1.miners)
        self.assertIn("System", chan_mgr1.miners)
        self.assertNotEqual(id(chan_mgr1.get_miner("Security")), id(chan_mgr1.get_miner("System")))

        # Save state
        chan_mgr1.save_all()

        # Restart manager from same state_dir
        chan_mgr2 = Drain3ChannelManager(state_dir=self.temp_state_dir)
        sec_miner2 = chan_mgr2.get_miner("Security")
        self.assertGreater(len(sec_miner2.drain.clusters), 0, "Persisted cluster state must load on restart")

    def test_07_representative_document_generation(self):
        """Verify representative document generation for downstream vector index:
        Produces 1 document per template containing template string and metadata.
        """
        self._create_synthetic_canonical_logs(count=100)
        manager = DuckDBTemplateManager(state_dir=self.temp_state_dir)
        manager.process_canonical_records(self.conn, canonical_table="canonical_logs_store")

        docs = manager.generate_representative_documents(self.conn)
        tpl_count = self.conn.execute("SELECT COUNT(*) FROM log_templates").fetchone()[0]

        self.assertEqual(len(docs), tpl_count, "Representative document count must equal template count")
        self.assertLess(len(docs), 100, "Template deduplication must reduce document count below raw log count")

        doc0 = docs[0]
        self.assertIn("template_id", doc0)
        self.assertIn("text", doc0)
        self.assertIn("[Source:", doc0["text"])
        self.assertIn("[EventID:", doc0["text"])
        self.assertIn("Template:", doc0["text"])
        self.assertTrue(doc0["metadata"]["is_template_document"])
        self.assertGreater(doc0["metadata"]["total_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
