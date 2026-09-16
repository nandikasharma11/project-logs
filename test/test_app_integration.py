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


def test_app_correlation_resource_and_sync():
    """Validates that get_correlation_mgr is available and sync_dataframe_to_duckdb
    builds the entity_correlations table.
    """
    corr_mgr = app.get_correlation_mgr()
    assert corr_mgr is not None

    test_conn = duckdb.connect(":memory:")
    df = pd.DataFrame([
        {
            "RecordID": "501",
            "TimeCreated": "2026-09-15 12:00:00",
            "EventID": "4624",
            "Level": "0",
            "LevelName": "LogAlways",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "WORKSTATION-01",
            "ProcessID": "400",
            "ThreadID": "50",
            "UserID": "S-1-5-21-500",
            "Message": "Successful logon",
            "EventData": '{"TargetLogonId": "0x3e7", "TargetUserName": "SYSTEM"}',
            "RawXML": "<Event>501</Event>",
        },
        {
            "RecordID": "502",
            "TimeCreated": "2026-09-15 12:00:15",
            "EventID": "7036",
            "Level": "4",
            "LevelName": "Information",
            "Channel": "System",
            "Provider": "Service Control Manager",
            "Computer": "WORKSTATION-01",
            "ProcessID": "400",
            "ThreadID": "55",
            "UserID": "S-1-5-18",
            "Message": "Service entered the running state",
            "EventData": '{"ServiceName": "ForensicSvc"}',
            "RawXML": "<Event>502</Event>",
        },
    ])

    res = app.sync_dataframe_to_duckdb(test_conn, df, scope_key="test_corr_scope", force_resync=True)
    assert res["records"] == 2
    assert "correlations" in res
    assert "corr_stats" in res
    assert "entity_correlations" in [r[0] for r in test_conn.execute("SHOW TABLES").fetchall()]


def test_app_generate_chatgpt_correlation_response():
    """Validates that generate_chatgpt_forensic_response produces a dedicated
    Cross-Channel Correlation & Causal Sequence section when correlated events are supplied.
    """
    parser = app.get_query_parser()
    qf = parser.parse("What else happened around record 501?")
    assert qf.intent == "correlation"

    sample_records = pd.DataFrame([
        {
            "RecordID": "501",
            "TimeCreated": "2026-09-15 12:00:00",
            "EventID": "4624",
            "LevelName": "LogAlways",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "WORKSTATION-01",
            "ProcessID": "400",
            "UserID": "SYSTEM",
            "Message": "Successful logon",
            "EventData": "{}",
        },
        {
            "RecordID": "502",
            "TimeCreated": "2026-09-15 12:00:15",
            "EventID": "7036",
            "LevelName": "Information",
            "Channel": "System",
            "Provider": "Service Control Manager",
            "Computer": "WORKSTATION-01",
            "ProcessID": "400",
            "UserID": "SYSTEM",
            "Message": "Service started",
            "EventData": "{}",
        }
    ])

    correlated_events = [
        {
            "event_record_id": "502",
            "source_type": "System",
            "event_id": "7036",
            "provider": "Service Control Manager",
            "time_created_utc": "2026-09-15 12:00:15",
            "entity_type": "process_id",
            "entity_value": "400",
            "confidence": "Low",
            "confidence_weight": 0.3,
            "time_delta_seconds": 15,
            "time_delta_str": "+15s",
            "relation_reason": "Matching bare process_id within tight 300s window",
        }
    ]

    anchor_record = {
        "RecordID": "501",
        "EventID": "4624",
        "Channel": "Security",
        "TimeCreated": "2026-09-15 12:00:00",
    }

    resp = app.generate_chatgpt_forensic_response(
        query="What else happened around record 501?",
        qf=qf,
        records=sample_records,
        templates=[],
        scope_label="All Converted Logs",
        total_scope_records=100,
        correlated_events=correlated_events,
        anchor_record=anchor_record,
    )

    assert "### 🔍 Forensic Findings" in resp
    assert "Cross-channel correlation around **Anchor Record `#501`" in resp
    assert "Cross-Channel Correlation & Causal Sequence" in resp
    assert "⚓ **Anchor Event:** Record `#501`" in resp
    assert "+15s" in resp
    assert "System" in resp
    assert "7036" in resp
    assert "process_id: 400" in resp
    assert "Correlation Assessment" in resp


