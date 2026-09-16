#!/usr/bin/env python3
"""
================================================================================
METADATA + EVENT DETAIL QUERY EXECUTION LAYER
================================================================================
Author: Principal Forensics Specialist & Data Systems Architect
Description:
    Executes structured filters against canonical log records in DuckDB,
    combining:
      1. Fixed metadata columns (direct, indexed SQL on source_type, level,
         time_created_utc, process_id, thread_id, computer, user_id).
      2. Heterogeneous event-details inside 'event_data' (native DuckDB JSON
         evaluation using json_extract_string on TRY_CAST(event_data AS JSON)
         with canonical key resolution across event schemas).
      3. Semantic vector candidate intersection (intersecting vector search
         candidate event_record_ids in the same single SQL pass).
      4. Complete canonical evidence preservation (returns original rows with
         event_record_id, event_data, raw_xml for forensic citation).
================================================================================
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import duckdb
import pandas as pd

from query_parser import QueryFilter, TimeRange

logger = logging.getLogger("DFIR_QueryExecutor")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ==============================================================================
# 1. CANONICAL FIELD TO EVENT DATA JSON KEY MAPPINGS
# ==============================================================================

EVENT_DATA_KEY_MAPPINGS: Dict[str, Union[List[str], Dict[str, List[str]]]] = {
    "ip_address": {
        "4624": ["IpAddress"],
        "4625": ["IpAddress"],
        "default": ["IpAddress", "SourceAddress", "ClientAddress", "SourceIP", "ClientIP", "IPAddress"],
    },
    "logon_id": {
        "4624": ["TargetLogonId", "SubjectLogonId"],
        "4625": ["TargetLogonId", "SubjectLogonId"],
        "default": ["TargetLogonId", "SubjectLogonId", "LogonId"],
    },
    "user_id": {
        "4624": ["TargetUserName", "SubjectUserName", "TargetUserSid", "SubjectUserSid"],
        "4625": ["TargetUserName", "SubjectUserName", "TargetUserSid", "SubjectUserSid"],
        "default": ["TargetUserName", "SubjectUserName", "UserName", "AccountName", "TargetUser", "SubjectUserSid", "TargetUserSid", "UserSid"],
    },
    "user_name": {
        "4624": ["TargetUserName", "SubjectUserName"],
        "4625": ["TargetUserName", "SubjectUserName"],
        "default": ["TargetUserName", "SubjectUserName", "UserName", "AccountName"],
    },
    "process_name": {
        "4688": ["NewProcessName", "ParentProcessName"],
        "default": ["ProcessName", "NewProcessName", "Image", "Application"],
    },
    "process_id": {
        "4688": ["NewProcessId", "ProcessId"],
        "default": ["ProcessId", "NewProcessId", "ProcessID"],
    },
    "status_code": {
        "4625": ["Status", "SubStatus"],
        "default": ["Status", "SubStatus", "ErrorCode", "StatusCode"],
    },
    "computer": {
        "4624": ["WorkstationName", "TargetServerName"],
        "default": ["WorkstationName", "TargetServerName", "ComputerName"],
    },
}


def resolve_json_keys_for_field(
    field_name: str,
    event_id_hint: Optional[str] = None,
) -> List[str]:
    """Resolves a canonical field name (e.g. 'ip_address') to the actual JSON keys
    present in Windows EventData payloads, optionally specialized by event_id.
    """
    clean_field = field_name.lower().replace(" ", "_").replace("-", "_")
    mapping = EVENT_DATA_KEY_MAPPINGS.get(clean_field)
    if not mapping:
        # Direct key fallback
        return [field_name]

    if isinstance(mapping, dict):
        hint = str(event_id_hint).strip() if event_id_hint else None
        if hint and hint in mapping:
            return mapping[hint]
        return mapping.get("default", [field_name])

    return list(mapping)


def query_event_data(
    field_name: str,
    value: Any,
    event_id_hint: Optional[str] = None,
    json_col: str = "event_data",
) -> Tuple[str, List[Any]]:
    """Builds a parameterized DuckDB SQL clause to search inside event_data JSON.

    Uses TRY_CAST(event_data AS JSON) and json_extract_string to safely extract
    and compare values without failing on malformed JSON or NULLs.

    Returns:
        Tuple of (sql_clause, list_of_parameters)
    """
    keys = resolve_json_keys_for_field(field_name, event_id_hint)
    clauses: List[str] = []
    params: List[Any] = []

    clean_val = str(value).strip()
    for k in keys:
        clauses.append(
            f"LOWER(json_extract_string(TRY_CAST({json_col} AS JSON), '$.{k}')) = LOWER(?)"
        )
        params.append(clean_val)

    if len(clauses) == 1:
        return clauses[0], params

    return f"({' OR '.join(clauses)})", params


# ==============================================================================
# 2. QUERY EXECUTOR ENGINE
# ==============================================================================

class EventQueryExecutor:
    """Executes structured query filters against DuckDB canonical record tables.

    Seamlessly unifies:
      - Fixed metadata column filtering.
      - JSON event_data detail filtering.
      - Vector candidate intersection.
      - 100% evidentiary record preservation.
    """

    @staticmethod
    def resolve_canonical_columns(columns: Sequence[str]) -> Dict[str, str]:
        """Maps physical table column names to canonical schema keys."""
        cols_lower = {str(c).lower().replace("_", "").replace(" ", ""): str(c) for c in columns}

        def find_col(candidates: List[str]) -> Optional[str]:
            for cand in candidates:
                clean_cand = cand.lower().replace("_", "").replace(" ", "")
                if clean_cand in cols_lower:
                    return cols_lower[clean_cand]
            return None

        mapping = {
            "event_record_id": find_col(["event_record_id", "recordid", "row_id", "id"]),
            "source_type": find_col(["source_type", "channel", "source", "logname"]),
            "provider": find_col(["provider", "providername"]),
            "event_id": find_col(["event_id", "eventid", "id"]),
            "level": find_col(["levelname", "level", "severity"]),
            "time_created_utc": find_col(["time_created_utc", "timecreated", "timestamp", "systemtime"]),
            "process_id": find_col(["process_id", "processid", "pid"]),
            "thread_id": find_col(["thread_id", "threadid", "tid"]),
            "computer": find_col(["computer", "machinename", "host", "computername"]),
            "user_id": find_col(["user_id", "userid", "username", "targetusername", "account"]),
            "event_data": find_col(["event_data", "eventdata", "payload", "userdata"]),
            "raw_xml": find_col(["raw_xml", "rawxml", "xml", "original_xml"]),
            "message": find_col(["message", "details", "description"]),
        }
        return {k: v for k, v in mapping.items() if v is not None}

    def build_sql_query(
        self,
        query_filter: QueryFilter,
        candidate_record_ids: Optional[Sequence[str]] = None,
        canonical_table: str = "canonical_logs",
        available_columns: Optional[Sequence[str]] = None,
        limit: Optional[int] = None,
    ) -> Tuple[str, List[Any]]:
        """Compiles QueryFilter and candidate_record_ids into a single parameterized SQL query.

        Returns:
            Tuple of (sql_query_string, parameters_list)
        """
        col_map = self.resolve_canonical_columns(available_columns or [])
        rec_col = col_map.get("event_record_id") or "event_record_id"
        time_col = col_map.get("time_created_utc") or "time_created_utc"
        chan_col = col_map.get("source_type") or "source_type"
        prov_col = col_map.get("provider") or "provider"
        evid_col = col_map.get("event_id") or "event_id"
        lvl_col = col_map.get("level") or "level"
        pid_col = col_map.get("process_id")
        tid_col = col_map.get("thread_id")
        comp_col = col_map.get("computer")
        uid_col = col_map.get("user_id")
        ed_col = col_map.get("event_data") or "event_data"

        where_clauses: List[str] = []
        params: List[Any] = []

        # 1. Time Range Filter: BETWEEN ? AND ?
        if query_filter.time_range:
            where_clauses.append(f"{time_col} BETWEEN ? AND ?")
            params.extend([query_filter.time_range.start_utc, query_filter.time_range.end_utc])

        # 2. Source Channel Filter: source_type = ?
        if query_filter.source_type:
            where_clauses.append(f"LOWER(CAST({chan_col} AS VARCHAR)) = LOWER(?)")
            params.append(query_filter.source_type)

        # 3. Event ID Filter: event_id = ?
        if query_filter.event_id:
            val_eid = str(query_filter.event_id).strip()
            val_eid_int = int(val_eid) if val_eid.isdigit() else -1
            where_clauses.append(
                f"(TRY_CAST({evid_col} AS BIGINT) = ? OR REGEXP_REPLACE(CAST({evid_col} AS VARCHAR), '\\.0$', '') = ?)"
            )
            params.extend([val_eid_int, val_eid])

        # 4. Severity Level Filter: supports numeric codes and text labels
        if query_filter.level:
            lvl_clean = str(query_filter.level).strip().lower()
            lvl_map = {
                "critical": ["1", "critical"],
                "error": ["2", "error", "failure", "audit failure"],
                "warning": ["3", "warning"],
                "information": ["4", "0", "information", "informational", "info", "audit success", "logalways"],
                "verbose": ["5", "verbose"],
            }
            allowed = lvl_map.get(lvl_clean, [lvl_clean])
            placeholders = ", ".join(["?"] * len(allowed))
            where_clauses.append(f"LOWER(REGEXP_REPLACE(CAST({lvl_col} AS VARCHAR), '\\.0$', '')) IN ({placeholders})")
            params.extend(allowed)

        # 5. Entity Filters:
        entities = query_filter.entity_filters

        # Process ID (support both decimal and hex matching across top-level and EventData)
        if entities.process_id:
            val_raw = str(entities.process_id).strip()
            val_dec = str(int(val_raw, 16)) if val_raw.lower().startswith("0x") else val_raw
            val_dec_int = int(val_dec) if val_dec.isdigit() else -1
            try:
                val_hex = hex(int(val_dec))
            except Exception:
                val_hex = val_raw

            clause_dec, p_dec = query_event_data("process_id", val_dec, query_filter.event_id, json_col=ed_col)
            clause_hex, p_hex = query_event_data("process_id", val_hex, query_filter.event_id, json_col=ed_col)
            
            if pid_col:
                pid_clause = f"((TRY_CAST({pid_col} AS BIGINT) = ? OR REGEXP_REPLACE(CAST({pid_col} AS VARCHAR), '\\.0$', '') = ? OR LOWER(CAST({pid_col} AS VARCHAR)) = ?) OR {clause_dec} OR {clause_hex})"
                where_clauses.append(pid_clause)
                params.extend([val_dec_int, val_dec, val_raw.lower()])
                params.extend(p_dec)
                params.extend(p_hex)
            else:
                where_clauses.append(f"({clause_dec} OR {clause_hex})")
                params.extend(p_dec)
                params.extend(p_hex)

        # Process Name / Image (matches exact key and path substring)
        if getattr(entities, "process_name", None) and entities.process_name:
            pname = str(entities.process_name).strip()
            clause_pname, p_pname = query_event_data("process_name", pname, query_filter.event_id, json_col=ed_col)
            like_clause = f"(LOWER(json_extract_string(TRY_CAST({ed_col} AS JSON), '$.NewProcessName')) LIKE ? OR LOWER(json_extract_string(TRY_CAST({ed_col} AS JSON), '$.ProcessName')) LIKE ?)"
            where_clauses.append(f"({clause_pname} OR {like_clause})")
            params.extend(p_pname)
            params.extend([f"%{pname.lower()}%", f"%{pname.lower()}%"])

        # Provider
        if getattr(entities, "provider", None) and entities.provider:
            prov_val = str(entities.provider).strip()
            where_clauses.append(f"LOWER(CAST({prov_col} AS VARCHAR)) LIKE ?")
            params.append(f"%{prov_val.lower()}%")

        # Status Code (e.g. 0xC000006D)
        if getattr(entities, "status_code", None) and entities.status_code:
            code_val = str(entities.status_code).strip()
            clause_code, p_code = query_event_data("status_code", code_val, query_filter.event_id, json_col=ed_col)
            where_clauses.append(clause_code)
            params.extend(p_code)

        # Thread ID
        if entities.thread_id:
            val = str(entities.thread_id).strip()
            val_int = int(val) if val.isdigit() else -1
            if tid_col:
                where_clauses.append(f"(TRY_CAST({tid_col} AS BIGINT) = ? OR REGEXP_REPLACE(CAST({tid_col} AS VARCHAR), '\\.0$', '') = ?)")
                params.extend([val_int, val])

        # Computer / Hostname
        if entities.computer:
            val = str(entities.computer).strip()
            clause_comp, p_comp = query_event_data("computer", val, query_filter.event_id, json_col=ed_col)
            if comp_col:
                where_clauses.append(f"(LOWER(CAST({comp_col} AS VARCHAR)) = LOWER(?) OR LOWER(CAST({comp_col} AS VARCHAR)) LIKE ? OR {clause_comp})")
                params.extend([val, f"%{val.lower()}%"])
                params.extend(p_comp)
            else:
                where_clauses.append(clause_comp)
                params.extend(p_comp)

        # User ID / Username (check top-level column AND/OR event_data JSON with SID mapping)
        if entities.user_id:
            val = str(entities.user_id).strip()
            sid_equivalents = {
                "system": ["s-1-5-18", "system"],
                "local system": ["s-1-5-18", "system", "local system"],
                "local service": ["s-1-5-19", "local service"],
                "network service": ["s-1-5-20", "network service"],
                "s-1-5-18": ["s-1-5-18", "system"],
                "s-1-5-19": ["s-1-5-19", "local service"],
                "s-1-5-20": ["s-1-5-20", "network service"],
            }
            cand_users = sid_equivalents.get(val.lower(), [val])

            user_subclauses = []
            for u in cand_users:
                json_clause, json_params = query_event_data("user_id", u, query_filter.event_id, json_col=ed_col)
                if uid_col:
                    user_subclauses.append(f"(LOWER(CAST({uid_col} AS VARCHAR)) = LOWER(?) OR {json_clause})")
                    params.append(u)
                    params.extend(json_params)
                else:
                    user_subclauses.append(json_clause)
                    params.extend(json_params)

            if len(user_subclauses) == 1:
                where_clauses.append(user_subclauses[0])
            else:
                where_clauses.append(f"({' OR '.join(user_subclauses)})")

        # IP Address (located inside event_data JSON)
        if entities.ip_address:
            val = str(entities.ip_address).strip()
            clause, p = query_event_data("ip_address", val, query_filter.event_id, json_col=ed_col)
            where_clauses.append(clause)
            params.extend(p)

        # Logon ID (located inside event_data JSON)
        if entities.logon_id:
            val = str(entities.logon_id).strip()
            clause, p = query_event_data("logon_id", val, query_filter.event_id, json_col=ed_col)
            where_clauses.append(clause)
            params.extend(p)

        # Event Record ID
        if entities.event_record_id:
            val = str(entities.event_record_id).strip()
            where_clauses.append(f"REGEXP_REPLACE(CAST({rec_col} AS VARCHAR), '\\.0$', '') = ?")
            params.append(val)

        # 6. Candidate Record IDs Intersect (from Pass 1 vector search)
        if candidate_record_ids is not None:
            cands = [str(c).strip() for c in candidate_record_ids if str(c).strip()]
            if cands:
                placeholders = ", ".join(["?"] * len(cands))
                where_clauses.append(f"REGEXP_REPLACE(CAST({rec_col} AS VARCHAR), '\\.0$', '') IN ({placeholders})")
                params.extend(cands)
            else:
                # If vector search returned empty set, intersection must be empty
                where_clauses.append("1 = 0")

        # Compile final SQL query
        base_query = f"SELECT * FROM {canonical_table}"
        if where_clauses:
            base_query += " WHERE " + " AND ".join(where_clauses)

        base_query += f" ORDER BY {time_col} ASC, {rec_col} ASC"

        if limit and limit > 0:
            base_query += f" LIMIT {int(limit)}"

        return base_query, params

    def execute_query(
        self,
        conn: duckdb.DuckDBPyConnection,
        query_filter: QueryFilter,
        candidate_record_ids: Optional[Sequence[str]] = None,
        canonical_table: str = "canonical_logs",
        limit: Optional[int] = None,
    ) -> pd.DataFrame:
        """Executes the compiled query against DuckDB and returns matching canonical records.

        Guarantees:
          - Single unified SQL execution.
          - 100% full original rows with event_record_id, event_data, and raw_xml preserved.
        """
        # Discover table columns
        cols = [r[0] for r in conn.execute(f"DESCRIBE {canonical_table}").fetchall()]

        sql, params = self.build_sql_query(
            query_filter=query_filter,
            candidate_record_ids=candidate_record_ids,
            canonical_table=canonical_table,
            available_columns=cols,
            limit=limit,
        )

        logger.debug("Executing SQL: %s with params %s", sql, params)
        return conn.execute(sql, params).df()

    execute_filter = execute_query


# ==============================================================================
# 3. CONVENIENCE ENTRYPOINT
# ==============================================================================

_GLOBAL_EXECUTOR = EventQueryExecutor()


def execute_forensic_filter_query(
    conn: duckdb.DuckDBPyConnection,
    query_filter: QueryFilter,
    candidate_record_ids: Optional[Sequence[str]] = None,
    canonical_table: str = "canonical_logs",
    limit: Optional[int] = None,
) -> pd.DataFrame:
    """Convenience function to execute a QueryFilter against DuckDB."""
    return _GLOBAL_EXECUTOR.execute_query(
        conn=conn,
        query_filter=query_filter,
        candidate_record_ids=candidate_record_ids,
        canonical_table=canonical_table,
        limit=limit,
    )
