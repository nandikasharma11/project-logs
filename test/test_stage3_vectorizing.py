#!/usr/bin/env python3
"""
================================================================================
Unit & Acceptance Tests for STAGE 3: Vector Indexing Layer (stage3_vectorizing.py)
================================================================================
Tests verify all non-negotiable acceptance criteria:
  1. Vector Count == Unique Templates: Vector count equals unique templates,
     not raw log count (e.g., 100 raw occurrences collapse to 1 vector).
  2. Pre-Filtered Search Isolation: Scoped filters (e.g. source_type=Security, level=Error)
     filter candidates BEFORE similarity search runs, strictly excluding non-matching items.
  3. Incremental Indexing: Re-running indexing after new logs arrive only embeds
     new templates and updates metadata in-place for existing templates (zero re-embedding).
  4. Forensic Audit Trail: Embedding model name, version, and dimension are recorded
     and retrievable from the index.
  5. Evidentiary Traceability: Every returned template_id resolves back to 100% of
     original raw records via the DuckDB instance-mapping table.
================================================================================
"""

import math
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

from log_templater import DuckDBTemplateManager
from stage3_vectorizing import (
    TemplateEmbedder,
    TemplateVectorIndex,
    construct_representative_text,
)


class TestStage3VectorIndexing(unittest.TestCase):
    """Acceptance test suite for Stage 3 Vector Indexing Layer."""

    @classmethod
    def setUpClass(cls):
        """Pre-load embedder once across tests for speed."""
        cls.shared_embedder = TemplateEmbedder(model_name="BAAI/bge-small-en-v1.5")

    def setUp(self):
        self.temp_state_dir = tempfile.mkdtemp(prefix="stage3_drain3_")
        self.conn = duckdb.connect(":memory:")
        self.template_mgr = DuckDBTemplateManager(state_dir=self.temp_state_dir)
        self.index = TemplateVectorIndex(
            collection_name=f"test_coll_{int(os.getpid())}",
            embedder=self.shared_embedder,
        )

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.temp_state_dir):
            shutil.rmtree(self.temp_state_dir, ignore_errors=True)

    def _seed_canonical_logs(self, security_error_count=80, security_info_count=15, system_info_count=10):
        """Helper generating synthetic canonical logs across distinct patterns."""
        rows = []
        rec_idx = 1

        # Pattern 1: Security Failed Logon (Error)
        for i in range(security_error_count):
            rows.append({
                "event_record_id": f"REC_{rec_idx:05d}",
                "source_type": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": "4625",
                "level": "Error",
                "time_created_utc": f"2026-09-14T08:{i % 60:02d}:00Z",
                "message": f"An account failed to log on with status 0xC000006A from IP 192.168.1.{i % 20} for user admin",
            })
            rec_idx += 1

        # Pattern 2: Security Successful Logon (Information)
        for i in range(security_info_count):
            rows.append({
                "event_record_id": f"REC_{rec_idx:05d}",
                "source_type": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": "4624",
                "level": "Information",
                "time_created_utc": f"2026-09-14T09:{i % 60:02d}:00Z",
                "message": f"An account was successfully logged on for user analyst_{i % 3}",
            })
            rec_idx += 1

        # Pattern 3: System Service State Change (Information)
        for i in range(system_info_count):
            rows.append({
                "event_record_id": f"REC_{rec_idx:05d}",
                "source_type": "System",
                "provider": "Service Control Manager",
                "event_id": "7036",
                "level": "Information",
                "time_created_utc": f"2026-09-14T10:{i % 60:02d}:00Z",
                "message": f"The Service svc_{i % 2} entered the running state.",
            })
            rec_idx += 1

        df = pd.DataFrame(rows)
        self.conn.register("canonical_logs_raw", df)
        self.conn.execute("CREATE TABLE canonical_logs AS SELECT * FROM canonical_logs_raw")
        self.conn.unregister("canonical_logs_raw")
        return df

    def test_01_vector_count_equals_unique_templates_not_raw_logs(self):
        """Acceptance Criteria 1:
        Number of vectors in index equals the number of unique templates,
        never the number of raw log rows.
        """
        # Ingest 105 raw logs across 3 distinct template patterns
        self._seed_canonical_logs(security_error_count=80, security_info_count=15, system_info_count=10)

        # 1. Run deduplication layer in DuckDB
        dedup_stats = self.template_mgr.process_canonical_records(self.conn, canonical_table="canonical_logs")
        self.assertEqual(dedup_stats["total_instances_mapped"], 105)
        self.assertEqual(dedup_stats["total_templates"], 3)

        # 2. Index templates into Qdrant
        idx_stats = self.index.index_from_duckdb(self.conn)

        # Assert vector count is 3, NOT 105
        self.assertEqual(idx_stats["new_indexed"], 3)
        self.assertEqual(idx_stats["total_vectors"], 3)

        qdrant_count = self.index.client.count(self.index.collection_name).count
        self.assertEqual(qdrant_count, 3, "Vector index must contain 1 vector per template, not 105 raw rows")

    def test_02_pre_filtered_search_strict_isolation(self):
        """Acceptance Criteria 2:
        A filtered query (e.g., source_type=Security, level=Error) only searches
        within that subset — results never include non-matching records even if semantically similar.
        """
        self._seed_canonical_logs(security_error_count=50, security_info_count=20, system_info_count=10)
        self.template_mgr.process_canonical_records(self.conn, canonical_table="canonical_logs")
        self.index.index_from_duckdb(self.conn)

        # Query that could conceptually match both 4624 (logon) and 4625 (logon failure),
        # but with strict pre-filters for Security + Error
        results = self.index.search(
            query_text="user logon activity",
            filters={"source_type": "Security", "level": "Error"},
            top_k=10,
        )

        self.assertGreater(len(results), 0, "Should match the Security Error template")
        for res in results:
            meta = res["metadata"]
            self.assertEqual(meta["source_type"], "Security")
            self.assertEqual(meta["level"], "Error")
            self.assertEqual(meta["event_id"], "4625")

        # Query for System channel only
        sys_results = self.index.search(
            query_text="service state change",
            filters={"source_type": "System"},
            top_k=10,
        )
        self.assertGreater(len(sys_results), 0)
        for res in sys_results:
            self.assertEqual(res["metadata"]["source_type"], "System")

    def test_03_incremental_indexing_no_duplicate_reembedding(self):
        """Acceptance Criteria 3:
        Re-running indexing after new logs arrive only adds/updates vectors for new
        or changed templates; unchanged templates are untouched (no wasted re-embedding).
        """
        # Batch 1: Initial 50 logs
        self._seed_canonical_logs(security_error_count=50, security_info_count=0, system_info_count=0)
        self.template_mgr.process_canonical_records(self.conn, canonical_table="canonical_logs")

        # Initial index run
        run1 = self.index.index_from_duckdb(self.conn)
        self.assertEqual(run1["new_indexed"], 1)
        self.assertEqual(run1["total_vectors"], 1)

        # Batch 2: Add 30 more failed logons (existing template) + 10 Application crash logs (new template)
        new_logs = []
        for i in range(30):
            new_logs.append({
                "event_record_id": f"REC_ADD_{i:04d}",
                "source_type": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": "4625",
                "level": "Error",
                "time_created_utc": f"2026-09-14T11:{i % 60:02d}:00Z",
                "message": f"An account failed to log on with status 0xC000006A from IP 10.0.0.{i} for user admin",
            })
        for i in range(10):
            new_logs.append({
                "event_record_id": f"REC_APP_{i:04d}",
                "source_type": "Application",
                "provider": "Application Error",
                "event_id": "1000",
                "level": "Error",
                "time_created_utc": f"2026-09-14T12:{i % 60:02d}:00Z",
                "message": f"Application crash in module test_{i % 2}.exe with fault offset 0x0001",
            })

        df_new = pd.DataFrame(new_logs)
        self.conn.register("df_new", df_new)
        self.conn.execute("INSERT INTO canonical_logs SELECT * FROM df_new")
        self.conn.unregister("df_new")

        # Run dedup layer again
        self.template_mgr.process_canonical_records(self.conn, canonical_table="canonical_logs")

        # Run incremental indexing
        run2 = self.index.index_from_duckdb(self.conn)

        # Assert: Exactly 1 new template embedded (Application 1000), 1 template metadata updated in-place (Event 4625)
        self.assertEqual(run2["new_indexed"], 1, "Only the 1 new Application template should be newly embedded")
        self.assertEqual(run2["metadata_updated"], 1, "The existing template should update payload in-place without re-embedding")
        self.assertEqual(run2["total_vectors"], 2)

        # Verify updated payload in Qdrant
        res_4625 = self.index.search("failed logon", filters={"event_id": "4625"})
        self.assertEqual(len(res_4625), 1)
        self.assertEqual(res_4625[0]["metadata"]["total_count"], 80)  # 50 initial + 30 added

    def test_04_embedding_model_audit_metadata_retrieval(self):
        """Acceptance Criteria 4:
        Embedding model name/version used is recorded and retrievable for forensic audit trail.
        """
        meta = self.index.get_model_metadata()

        self.assertIn("model_name", meta)
        self.assertIn("model_version", meta)
        self.assertIn("vector_dim", meta)
        self.assertIn("created_at_utc", meta)
        self.assertEqual(meta["model_name"], "BAAI/bge-small-en-v1.5")
        self.assertEqual(meta["vector_dim"], 384)

    def test_05_traceability_from_vector_result_to_raw_records(self):
        """Acceptance Criteria 5:
        Every returned template_id can be joined back to the instance-mapping table
        to recover the full, exact list of original event_record_ids from DuckDB.
        """
        self._seed_canonical_logs(security_error_count=40, security_info_count=10, system_info_count=0)
        self.template_mgr.process_canonical_records(self.conn, canonical_table="canonical_logs")
        self.index.index_from_duckdb(self.conn)

        # Perform search
        search_res = self.index.search("failed logon attempt", filters={"level": "Error"}, top_k=1)
        self.assertEqual(len(search_res), 1)

        matched_template_id = search_res[0]["template_id"]
        self.assertTrue(matched_template_id.startswith("TPL_SECURITY_4625"))

        # Recover full raw records from DuckDB
        raw_records_df = self.index.resolve_search_results_to_records(
            self.conn,
            search_res,
            canonical_table="canonical_logs",
        )

        # Assert: 100% of the 40 raw records recovered, with zero sampling
        self.assertEqual(len(raw_records_df), 40)
        self.assertEqual(len(raw_records_df["event_record_id"].unique()), 40)
        self.assertIn("extracted_variables", raw_records_df.columns)
        self.assertIn("message", raw_records_df.columns)

        # Also test instance ID dictionary resolver
        instances_map = self.index.resolve_search_results_to_instances(self.conn, search_res)
        self.assertIn(matched_template_id, instances_map)
        self.assertEqual(len(instances_map[matched_template_id]), 40)

    def test_06_embedder_unit_normalization(self):
        """Verify embedder outputs unit length vectors suitable for cosine distance."""
        embedder = self.shared_embedder
        vec = embedder.embed_single("Test forensic log message")
        l2_norm = math.sqrt(sum(x * x for x in vec))
        self.assertAlmostEqual(l2_norm, 1.0, places=4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
