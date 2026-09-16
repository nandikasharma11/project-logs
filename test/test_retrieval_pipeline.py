#!/usr/bin/env python3
"""
================================================================================
TEST SUITE: End-to-End Retrieval Pipeline (test_retrieval_pipeline.py)
================================================================================
Validates all 5 mandatory system prompt criteria and orchestration responsibilities:
  1. Specific Instance Citation: Cites exact matching records, not the whole population.
  2. Aggregate vs Instance Distinction: States counts accurately, no false claim of inspecting all.
  3. Chronological Correlation: Reasons across channels with high vs low confidence phrasing.
  4. Zero Hallucination: States "not found" when context is empty.
  5. Deduplication: Removes duplicates across filter execution and correlation expansion.
  6. Audit Trail Logging: Records execution metadata to DuckDB pipeline_audit_log.
  7. Swappable LLM Backends: Seamlessly swaps backend implementations.
================================================================================
"""

import os
import duckdb
import pandas as pd
import pytest

from retrieval_pipeline import (
    BaseLLMBackend,
    ForensicPromptBuilder,
    ForensicRetrievalPipeline,
    LLMResponse,
    MockLLMBackend,
    PipelineAuditLogger,
    PipelineConfig,
    get_llm_backend,
)
from query_parser import ForensicQueryParser
from query_executor import EventQueryExecutor
from correlation_indexer import CorrelationIndexManager
from stage3_vectorizing import TemplateEmbedder, TemplateVectorIndex


@pytest.fixture
def test_db_setup():
    """Sets up an in-memory DuckDB database with canonical records and templates."""
    conn = duckdb.connect(":memory:")

    # 1. Canonical logs with multiple channels
    df = pd.DataFrame([
        {
            "RecordID": "101",
            "TimeCreated": "2026-09-15 10:00:00",
            "EventID": "4624",
            "Level": "0",
            "LevelName": "LogAlways",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "HOST-01",
            "ProcessID": "400",
            "ThreadID": "20",
            "UserID": "SYSTEM",
            "Message": "Successful Logon. TargetUserName: SYSTEM.",
            "EventData": '{"TargetLogonId": "0x3E7", "TargetUserName": "SYSTEM"}',
            "RawXML": "<Event>101</Event>",
        },
        {
            "RecordID": "102",
            "TimeCreated": "2026-09-15 10:00:14",
            "EventID": "4688",
            "Level": "0",
            "LevelName": "LogAlways",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "HOST-01",
            "ProcessID": "1064",
            "ThreadID": "21",
            "UserID": "SYSTEM",
            "Message": "New Process Created: cmd.exe.",
            "EventData": '{"NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe", "ProcessId": "1064"}',
            "RawXML": "<Event>102</Event>",
        },
        {
            "RecordID": "103",
            "TimeCreated": "2026-09-15 10:00:45",
            "EventID": "7036",
            "Level": "4",
            "LevelName": "Information",
            "Channel": "System",
            "Provider": "Service Control Manager",
            "Computer": "HOST-01",
            "ProcessID": "1064",
            "ThreadID": "22",
            "UserID": "SYSTEM",
            "Message": "Service started successfully.",
            "EventData": '{"ServiceName": "TestService"}',
            "RawXML": "<Event>103</Event>",
        },
        {
            "RecordID": "104",
            "TimeCreated": "2026-09-15 10:05:00",
            "EventID": "1000",
            "Level": "2",
            "LevelName": "Error",
            "Channel": "Application",
            "Provider": "Application Error",
            "Computer": "HOST-01",
            "ProcessID": "9999",
            "ThreadID": "30",
            "UserID": "UserA",
            "Message": "Faulting application name: badapp.exe.",
            "EventData": '{"FaultingApplication": "badapp.exe"}',
            "RawXML": "<Event>104</Event>",
        },
    ])

    conn.execute("CREATE TABLE canonical_logs AS SELECT * FROM df")

    # 2. Build templates table
    conn.execute("""
        CREATE TABLE log_templates (
            template_id VARCHAR PRIMARY KEY,
            source_type VARCHAR,
            provider VARCHAR,
            event_id VARCHAR,
            level VARCHAR,
            template_string VARCHAR,
            first_seen_utc VARCHAR,
            last_seen_utc VARCHAR,
            total_count BIGINT
        )
    """)
    conn.execute("""
        INSERT INTO log_templates VALUES
        ('tpl_4624', 'Security', 'Microsoft-Windows-Security-Auditing', '4624', 'LogAlways', 'Successful Logon. TargetUserName: <*>.', '2026-09-15 10:00:00', '2026-09-15 10:00:00', 50256),
        ('tpl_4688', 'Security', 'Microsoft-Windows-Security-Auditing', '4688', 'LogAlways', 'New Process Created: <*>.', '2026-09-15 10:00:14', '2026-09-15 10:00:14', 120),
        ('tpl_7036', 'System', 'Service Control Manager', '7036', 'Information', 'Service started successfully.', '2026-09-15 10:00:45', '2026-09-15 10:00:45', 450),
        ('tpl_1000', 'Application', 'Application Error', '1000', 'Error', 'Faulting application name: <*>.', '2026-09-15 10:05:00', '2026-09-15 10:05:00', 12)
    """)

    # 3. Build correlation index
    corr_mgr = CorrelationIndexManager()
    corr_mgr.build_correlation_index(conn, canonical_table="canonical_logs")

    return conn


def test_01_pipeline_specific_instance_citation(test_db_setup):
    """AC 1: A specific_instance query returns an answer citing exactly the record(s)
    matching the narrowing filters, not the whole template population.
    """
    conn = test_db_setup
    config = PipelineConfig(backend_type="mock")
    pipeline = ForensicRetrievalPipeline(config=config)

    result = pipeline.execute(
        conn=conn,
        user_query="Show process creation event for process 1064",
    )

    assert result.intent == "specific_instance"
    assert not result.retrieved_records.empty
    # Must match Record 102
    assert "102" in result.retrieved_records["RecordID"].astype(str).tolist()
    # The answer must cite [Record #102, Channel: Security]
    assert "[Record #102, Channel: Security]" in result.answer or "[Record #102]" in str(result.citations)
    # Must NOT cite unrelated records
    assert "104" not in str(result.citations)


def test_02_pipeline_pattern_or_aggregate_distinction(test_db_setup):
    """AC 2: A pattern_or_aggregate query returns an answer stating counts/frequency
    accurately, without falsely implying every instance was individually reviewed.
    """
    conn = test_db_setup
    config = PipelineConfig(backend_type="mock")
    pipeline = ForensicRetrievalPipeline(config=config)

    result = pipeline.execute(
        conn=conn,
        user_query="How often did Event 4624 occur in Security?",
    )

    assert result.intent == "pattern_or_aggregate"
    # Verify aggregate count is referenced
    assert "aggregate" in result.answer.lower() or "occurred" in result.answer.lower()
    # Verify disclaimer/acknowledgment that not all occurrences were individually inspected
    assert "not all" in result.answer.lower() or "aggregate" in result.answer.lower()


def test_03_pipeline_correlation_chronological_reasoning(test_db_setup):
    """AC 3: A correlation query's answer reasons chronologically across channels
    and distinguishes high- vs. low-confidence links in its phrasing.
    """
    conn = test_db_setup
    config = PipelineConfig(backend_type="mock")
    pipeline = ForensicRetrievalPipeline(config=config)

    result = pipeline.execute(
        conn=conn,
        user_query="What else happened around record 102?",
    )

    assert result.intent == "correlation"
    assert len(result.correlated_records) >= 1

    # Record 103 (PID 1064 in System log at +31s) is linked
    corr_ids = [str(r["event_record_id"]) for r in result.correlated_records]
    assert "103" in corr_ids

    # The answer should cite both records and reason chronologically
    assert "chronological" in result.answer.lower() or "sequence" in result.answer.lower()
    assert "102" in str(result.citations) or "[Record #102" in result.answer
    assert "103" in str(result.citations) or "[Record #103" in result.answer


def test_04_pipeline_no_fabrication_beyond_context(test_db_setup):
    """AC 4: If the retrieved context doesn't contain the answer, the model must
    say so rather than inferring or guessing.
    """
    conn = test_db_setup
    config = PipelineConfig(backend_type="mock")
    pipeline = ForensicRetrievalPipeline(config=config)

    result = pipeline.execute(
        conn=conn,
        user_query="Show logon failure for user NonExistentUser999",
    )

    assert result.retrieved_records.empty
    # Must explicitly state not found in provided records
    assert "not found in the provided records" in result.answer.lower()
    assert len(result.citations) == 0


def test_05_pipeline_deduplication(test_db_setup):
    """AC 5: Deduplicates event_record_ids across direct filter matches and
    correlation expansion so records appear once, not twice.
    """
    conn = test_db_setup
    config = PipelineConfig(backend_type="mock", enable_correlation_expansion=True)
    pipeline = ForensicRetrievalPipeline(config=config)

    result = pipeline.execute(
        conn=conn,
        user_query="Show process 1064 in Security and what happened next",
    )

    # Directly matches 102 and 103, and correlation also links 102 and 103
    retrieved_ids = result.retrieved_records["RecordID"].astype(str).tolist()
    # Ensure no duplicates in final row set
    assert len(retrieved_ids) == len(set(retrieved_ids))


def test_06_pipeline_audit_trail_logging(test_db_setup):
    """AC 6: Full pipeline run is logged into DuckDB pipeline_audit_log with
    reproducibility metadata (query, filters, matched IDs, model version).
    """
    conn = test_db_setup
    config = PipelineConfig(backend_type="mock")
    pipeline = ForensicRetrievalPipeline(config=config)

    result = pipeline.execute(
        conn=conn,
        user_query="Show cmd process 1064",
    )

    # Verify DuckDB audit table exists and has row
    audit_rows = conn.execute("SELECT * FROM pipeline_audit_log WHERE query_id = ?", [result.query_id]).fetchall()
    assert len(audit_rows) == 1

    row = audit_rows[0]
    # query_id, timestamp_utc, user_query, intent, resolved_filter_json, matched_template_ids, retrieved_record_ids, correlated_record_ids, final_record_ids, model_name, model_backend, quantization, latency_ms, generated_answer, citations
    assert row[0] == result.query_id
    assert row[2] == "Show cmd process 1064"
    assert row[3] == result.intent
    assert "mock" in row[10]
    assert len(row[13]) > 0  # generated_answer


def test_07_pipeline_swappable_backends():
    """Validates that custom/alternative LLM backends can be swapped seamlessly."""
    class CustomEchoBackend(BaseLLMBackend):
        def generate(self, system_prompt, user_prompt, context_batches, config):
            return LLMResponse(
                text="Custom answer verifying [Record #999, Channel: Security].",
                model_name="CustomQwen",
                model_version="custom-v1",
                backend="custom",
                quantization="fp16",
                latency_ms=42.0,
                citations=["[Record #999, Channel: Security]"],
            )

    conn = duckdb.connect(":memory:")
    conn.execute("CREATE TABLE canonical_logs (RecordID VARCHAR, TimeCreated VARCHAR, Channel VARCHAR)")
    conn.execute("INSERT INTO canonical_logs VALUES ('999', '2026-09-15 12:00:00', 'Security')")

    custom_backend = CustomEchoBackend()
    pipeline = ForensicRetrievalPipeline(llm_backend=custom_backend)

    res = pipeline.execute(conn, "Test query")
    assert res.answer == "Custom answer verifying [Record #999, Channel: Security]."
    assert res.audit_metadata["backend"] == "custom"
    assert res.audit_metadata["model_name"] == "CustomQwen"
    assert "[Record #999, Channel: Security]" in res.citations
