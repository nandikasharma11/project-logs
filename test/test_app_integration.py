#!/usr/bin/env python3
"""
================================================================================
TEST SUITE: Streamlit App Integration (app.py)
================================================================================
Validates that app.py integrates with:
  - DuckDB canonical storage
  - Drain3 clustering
  - Qdrant vector index
  - Forensic NLP query parser
  - Evidentiary query executor
================================================================================
"""

import os
import duckdb
import pandas as pd
import pytest

import app


def test_app_resource_getters():
    """Validates that all Stage 3 cached resource getters return active instances."""
    conn = app.get_duckdb_conn()
    assert conn is not None

    mgr = app.get_drain3_mgr()
    assert mgr is not None

    embedder = app.get_embedder()
    assert embedder is not None
    assert embedder.vector_dim == 384

    v_idx = app.get_vector_index(embedder)
    assert v_idx is not None

    parser = app.get_query_parser()
    assert parser is not None

    executor = app.get_query_executor()
    assert executor is not None


def test_app_sync_dataframe_to_duckdb():
    """Validates that sync_dataframe_to_duckdb ingests rows, creates templates, and updates vector index."""
    test_conn = duckdb.connect(":memory:")
    
    sample_df = pd.DataFrame([
        {
            "RecordID": "1001",
            "TimeCreated": "2026-09-15 14:00:00",
            "EventID": "4625",
            "Level": "2",
            "LevelName": "Error",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "SEC-SRV01",
            "ProcessID": "2048",
            "ThreadID": "100",
            "UserID": "Admin",
            "Message": "An account failed to log on. Subject: Admin.",
            "EventData": '{"TargetUserName": "Admin", "IpAddress": "192.168.1.55"}',
            "RawXML": "<Event>1001</Event>",
        },
        {
            "RecordID": "1002",
            "TimeCreated": "2026-09-15 14:01:00",
            "EventID": "4625",
            "Level": "2",
            "LevelName": "Error",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "SEC-SRV01",
            "ProcessID": "2048",
            "ThreadID": "101",
            "UserID": "Admin",
            "Message": "An account failed to log on. Subject: Admin.",
            "EventData": '{"TargetUserName": "Admin", "IpAddress": "192.168.1.56"}',
            "RawXML": "<Event>1002</Event>",
        },
    ])

    res = app.sync_dataframe_to_duckdb(test_conn, sample_df, scope_key="test_scope", force_resync=True)
    assert res["records"] == 2
    assert res["templates"] >= 1
    assert "log_templates" in [r[0] for r in test_conn.execute("SHOW TABLES").fetchall()]
    assert "template_instances" in [r[0] for r in test_conn.execute("SHOW TABLES").fetchall()]

    # Validate query parser and executor on synced duckdb
    parser = app.get_query_parser()
    qf = parser.parse("Show me logon failure for process 2048")
    assert qf.event_id == "4625" or qf.entity_filters.process_id == "2048"

    executor = app.get_query_executor()
    matched = executor.execute_query(test_conn, qf, canonical_table="canonical_logs")
    assert len(matched) == 2
    assert matched["RecordID"].tolist() == ["1001", "1002"]
