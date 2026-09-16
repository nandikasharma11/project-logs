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


def test_app_sync_duplicate_record_ids_across_channels():
    """Validates that sync_dataframe_to_duckdb cleanly handles multiple files/channels
    sharing the same RecordID (e.g. RecordID 1 in Security, System, and Application)
    without triggering a PRIMARY KEY constraint violation.
    """
    test_conn = duckdb.connect(":memory:")

    multi_channel_df = pd.DataFrame([
        {
            "RecordID": "1",
            "TimeCreated": "2026-09-15 14:00:00",
            "EventID": "4625",
            "Level": "2",
            "LevelName": "Error",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "HOST-01",
            "ProcessID": "1000",
            "ThreadID": "10",
            "UserID": "Admin",
            "Message": "Security logon failure event",
            "EventData": "{}",
            "RawXML": "<Event>1</Event>",
        },
        {
            "RecordID": "1",
            "TimeCreated": "2026-09-15 14:00:01",
            "EventID": "7036",
            "Level": "4",
            "LevelName": "Information",
            "Channel": "System",
            "Provider": "Service Control Manager",
            "Computer": "HOST-01",
            "ProcessID": "500",
            "ThreadID": "11",
            "UserID": "SYSTEM",
            "Message": "Service started successfully",
            "EventData": "{}",
            "RawXML": "<Event>1</Event>",
        },
        {
            "RecordID": "1",
            "TimeCreated": "2026-09-15 14:00:02",
            "EventID": "1000",
            "Level": "2",
            "LevelName": "Error",
            "Channel": "Application",
            "Provider": "Application Error",
            "Computer": "HOST-01",
            "ProcessID": "1200",
            "ThreadID": "12",
            "UserID": "User1",
            "Message": "Application fault occurred",
            "EventData": "{}",
            "RawXML": "<Event>1</Event>",
        },
    ])

    # Ingest without constraint error
    res = app.sync_dataframe_to_duckdb(test_conn, multi_channel_df, scope_key="multi_channel_scope", force_resync=True)
    assert res["records"] == 3
    assert res["templates"] == 3
    assert res["vectors"] >= 3

    # Verify 100% evidentiary integrity
    mgr = app.get_drain3_mgr()
    integrity = mgr.verify_evidentiary_integrity(test_conn, canonical_table="canonical_logs")
    assert integrity["integrity_valid"] is True
    assert integrity["canonical_count"] == 3
    assert integrity["instance_count"] == 3


def test_generate_chatgpt_forensic_response():
    """Validates that generate_chatgpt_forensic_response produces a ChatGPT-style response
    centered on the user query, with direct answer, centered statistics card, and diagnostic guidance.
    """
    parser = app.get_query_parser()
    qf = parser.parse("Show logon failures for user Admin")

    sample_records = pd.DataFrame([
        {
            "RecordID": "101",
            "TimeCreated": "2026-09-15 14:00:00",
            "EventID": "4625",
            "LevelName": "LogAlways",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "SEC-SRV01",
            "ProcessID": "672",
            "UserID": "Admin",
            "Message": "An account failed to log on.",
            "EventData": '{"TargetUserName": "Admin", "IpAddress": "10.0.0.1", "Status": "0xC000006D"}',
        }
    ])

    sample_templates = [
        {
            "template_id": "tpl_001",
            "template_string": "An account failed to log on. Subject: <*>",
            "occurrence_count": 1,
        }
    ]

    # 1. Matched response test
    resp_matched = app.generate_chatgpt_forensic_response(
        query="Show logon failures for user Admin",
        qf=qf,
        records=sample_records,
        templates=sample_templates,
        scope_label="Security.csv",
        total_scope_records=100,
    )

    assert "### 🔍 Forensic Findings" in resp_matched
    assert "Forensic analysis for user **`Admin`**" in resp_matched
    assert "Forensic Evidence Statistics" in resp_matched
    assert "Matched Records" in resp_matched
    assert "Technical Details & Payload Highlights" in resp_matched
    assert "10.0.0.1" in resp_matched or "0xC000006D" in resp_matched

    # 2. Zero-match response test
    resp_zero = app.generate_chatgpt_forensic_response(
        query="Show logon failures for user Admin",
        qf=qf,
        records=pd.DataFrame(),
        templates=[],
        scope_label="System.csv",
        total_scope_records=50,
    )

    assert "No matching events found" in resp_zero
    assert "Query Resolution Diagnostic" in resp_zero
    assert "Why Did This Query Return No Results?" in resp_zero
    assert "Channel Mismatch" in resp_zero

