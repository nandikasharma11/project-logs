#!/usr/bin/env python3
"""
================================================================================
CORRELATION INDEX LAYER (correlation_indexer.py)
================================================================================
Author: Principal Forensics Specialist & Data Systems Architect
Description:
    Builds a derived, read-only correlation index in DuckDB that links events
    across the three Windows log channels (Application, System, Security, Sysmon)
    using shared entity identifiers and time-proximity windows.

Core Capabilities:
  1. Multi-Entity Extraction:
     - logon_id: High confidence (1.0), 12-hour session window.
     - activity_id: High confidence (1.0), 12-hour activity window.
     - user_id: Medium-high confidence (0.8), 4-hour window.
     - ip_address: Medium confidence (0.6), 1-hour window.
     - process_id:
         * (pid, start_time) when creation events exist: High confidence (1.0).
         * Bare pid: Low confidence (0.3), strict tight window (5 minutes / 300s).
     - thread_id: Low confidence (0.2), strict tight window (5 minutes / 300s).
     - computer: Trivial confidence (0.1), 24-hour host window.
  2. Idempotent Index Construction:
     - Populates 'entity_correlations' from 'canonical_logs' without duplicates.
  3. find_correlated(anchor_event_record_id, ...):
     - Returns cross-channel correlated events ranked by confidence weight and
       time proximity with human-readable time deltas.
================================================================================
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import duckdb
import pandas as pd
from dateutil import parser as date_parser

logger = logging.getLogger("DFIR_CorrelationIndexer")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ==============================================================================
# 1. CONFIGURATION & CONSTANTS
# ==============================================================================

@dataclass
class CorrelationConfig:
    """Configurable time windows and confidence weights per entity type."""

    # Maximum time distance (in seconds) between anchor and candidate event
    time_windows_seconds: Dict[str, int] = field(
        default_factory=lambda: {
            "logon_id": 43200,          # 12 hours (session lifetime)
            "activity_id": 43200,       # 12 hours (activity GUID trace)
            "user_id": 14400,           # 4 hours (user action burst)
            "ip_address": 3600,         # 1 hour (DHCP / network connection window)
            "process_id_disambiguated": 43200, # 12 hours (lifetime of exact process instance)
            "process_id": 300,          # 5 minutes (tight window to prevent PID reuse)
            "thread_id": 300,           # 5 minutes (tight window)
            "computer": 86400,          # 24 hours
        }
    )

    # Confidence weights and descriptive labels
    confidence_ratings: Dict[str, Tuple[str, float]] = field(
        default_factory=lambda: {
            "logon_id": ("High", 1.0),
            "activity_id": ("High", 1.0),
            "process_id_disambiguated": ("High", 1.0),
            "user_id": ("Medium-high", 0.8),
            "ip_address": ("Medium", 0.6),
            "process_id": ("Low", 0.3),
            "thread_id": ("Low", 0.2),
            "computer": ("Trivial", 0.1),
        }
    )

    def get_window(self, entity_type: str, overrides: Optional[Dict[str, int]] = None) -> int:
        if overrides and entity_type in overrides:
            return int(overrides[entity_type])
        return self.time_windows_seconds.get(entity_type, 3600)

    def get_confidence(self, entity_type: str) -> Tuple[str, float]:
        return self.confidence_ratings.get(entity_type, ("Medium", 0.5))


# ==============================================================================
# 2. ENTITY EXTRACTION & NORMALIZATION
# ==============================================================================

class CorrelationExtractor:
    """Extracts normalized correlation entities from canonical forensic records."""

    IGNORE_LOGON_IDS: Set[str] = {"0x0", "0x3e7", "0", "999", "0x0:0x0"}
    IGNORE_IPS: Set[str] = {"127.0.0.1", "::1", "-", "0.0.0.0", "localhost"}
    IGNORE_USERS: Set[str] = {"-", "none", "null", "nan"}

    @classmethod
    def extract_from_row(
        cls,
        row: Dict[str, Any],
        config: CorrelationConfig,
        process_start_map: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Extracts all correlation entities from a single canonical log row."""
        entities: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, str]] = set()

        def add_entity(etype: str, evalue: Any, custom_conf: Optional[Tuple[str, float]] = None):
            if evalue is None:
                return
            s_val = str(evalue).strip()
            if not s_val or s_val.lower() in ("nan", "none", "null", ""):
                return

            key = (etype, s_val.lower())
            if key in seen_keys:
                return
            seen_keys.add(key)

            conf_label, conf_wt = custom_conf if custom_conf else config.get_confidence(etype)
            entities.append({
                "entity_type": etype,
                "entity_value": s_val,
                "confidence": conf_label,
                "confidence_weight": conf_wt,
            })

        event_id = str(row.get("EventID") or row.get("event_id") or "").strip()
        time_created = str(row.get("TimeCreated") or row.get("time_created_utc") or "").strip()

        # Parse EventData JSON payload if present
        ed_obj: Dict[str, Any] = {}
        raw_ed = row.get("EventData") or row.get("event_data")
        if raw_ed:
            if isinstance(raw_ed, dict):
                ed_obj = raw_ed
            elif isinstance(raw_ed, str) and raw_ed.strip().startswith("{"):
                try:
                    ed_obj = json.loads(raw_ed)
                except Exception:
                    pass

        # 1. LOGON ID
        for k in ("TargetLogonId", "SubjectLogonId", "LogonId", "TargetLinkedLogonId"):
            v = ed_obj.get(k)
            if v and str(v).strip().lower() not in cls.IGNORE_LOGON_IDS:
                add_entity("logon_id", str(v).strip())

        # 2. ACTIVITY ID
        act_id = row.get("ActivityID") or row.get("activity_id") or ed_obj.get("ActivityID")
        if act_id:
            s_act = str(act_id).strip()
            if s_act and s_act.replace("-", "").replace("0", ""):
                add_entity("activity_id", s_act)

        rel_act_id = row.get("RelatedActivityID") or row.get("related_activity_id") or ed_obj.get("RelatedActivityID")
        if rel_act_id:
            s_rel = str(rel_act_id).strip()
            if s_rel and s_rel.replace("-", "").replace("0", ""):
                add_entity("activity_id", s_rel)

        # 3. USER ID
        raw_uid = row.get("UserID") or row.get("user_id")
        if raw_uid:
            s_uid = str(raw_uid).strip()
            if s_uid.lower() not in cls.IGNORE_USERS:
                add_entity("user_id", s_uid)

        for k in ("TargetUserName", "SubjectUserName", "UserName", "AccountName"):
            u_val = ed_obj.get(k)
            if u_val:
                s_u = str(u_val).strip()
                if s_u.lower() not in cls.IGNORE_USERS and not s_u.endswith("$"):
                    add_entity("user_id", s_u)

        for k in ("TargetUserSid", "SubjectUserSid", "UserSid"):
            sid_val = ed_obj.get(k)
            if sid_val and str(sid_val).startswith("S-1-"):
                add_entity("user_id", str(sid_val).strip())

        # 4. IP ADDRESS
        for k in ("IpAddress", "SourceAddress", "ClientAddress", "SourceIP", "ClientIP"):
            ip_val = ed_obj.get(k)
            if ip_val:
                s_ip = str(ip_val).strip()
                if s_ip not in cls.IGNORE_IPS:
                    add_entity("ip_address", s_ip)

        # 5. PROCESS ID (PID Reuse Handling)
        raw_pid = row.get("ProcessID") or row.get("process_id") or ed_obj.get("ProcessId") or ed_obj.get("NewProcessId")
        if raw_pid is not None:
            s_pid = str(raw_pid).strip()
            if s_pid.endswith(".0"):
                s_pid = s_pid[:-2]
            if s_pid and s_pid != "0":
                # Check for process creation disambiguation
                start_time = None
                if event_id in ("1", "4688"):
                    start_time = ed_obj.get("UtcTime") or time_created
                elif process_start_map and s_pid in process_start_map:
                    start_time = process_start_map[s_pid]

                if start_time:
                    disp_val = f"PID:{s_pid}@{start_time}"
                    add_entity("process_id_disambiguated", disp_val, custom_conf=("High", 1.0))
                else:
                    add_entity("process_id", s_pid, custom_conf=("Low", 0.3))

        # 6. THREAD ID
        raw_tid = row.get("ThreadID") or row.get("thread_id")
        if raw_tid is not None:
            s_tid = str(raw_tid).strip()
            if s_tid.endswith(".0"):
                s_tid = s_tid[:-2]
            if s_tid and s_tid != "0":
                add_entity("thread_id", s_tid, custom_conf=("Low", 0.2))

        # 7. COMPUTER / HOSTNAME
        raw_comp = row.get("Computer") or row.get("computer") or ed_obj.get("WorkstationName") or ed_obj.get("ComputerName")
        if raw_comp:
            s_comp = str(raw_comp).strip()
            if s_comp and s_comp not in ("-", "None", "null"):
                add_entity("computer", s_comp, custom_conf=("Trivial", 0.1))

        return entities


# ==============================================================================
# 3. CORRELATION INDEX MANAGER
# ==============================================================================

class CorrelationIndexManager:
    """Manages the derived DuckDB 'entity_correlations' table and executes
    sub-millisecond cross-channel correlation queries.
    """

    TABLE_CORRELATIONS = "entity_correlations"

    def __init__(self, config: Optional[CorrelationConfig] = None):
        self.config = config or CorrelationConfig()

    def init_schema(self, conn: duckdb.DuckDBPyConnection):
        """Initializes the entity_correlations table schema if not existing."""
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_CORRELATIONS} (
                correlation_id BIGINT,
                entity_type VARCHAR NOT NULL,
                entity_value VARCHAR NOT NULL,
                event_record_id VARCHAR NOT NULL,
                source_type VARCHAR,
                event_id VARCHAR,
                provider VARCHAR,
                time_created_utc VARCHAR NOT NULL,
                confidence VARCHAR NOT NULL,
                confidence_weight DOUBLE NOT NULL
            );
        """)

    def build_correlation_index(
        self,
        conn: duckdb.DuckDBPyConnection,
        canonical_table: str = "canonical_logs",
        force_rebuild: bool = False,
    ) -> Dict[str, Any]:
        """Extracts correlation entities from canonical_logs and updates the index.

        Idempotency: Only processes records that have not yet been indexed,
        guaranteeing zero duplicate rows on re-runs.
        """
        self.init_schema(conn)

        if force_rebuild:
            conn.execute(f"DELETE FROM {self.TABLE_CORRELATIONS}")

        # Check existing indexed record IDs for idempotency
        indexed_recs = set()
        try:
            res = conn.execute(f"SELECT DISTINCT event_record_id FROM {self.TABLE_CORRELATIONS}").fetchall()
            indexed_recs = {str(r[0]) for r in res}
        except Exception:
            pass

        # Identify unmapped rows from canonical_logs
        rec_col = "RecordID" if "RecordID" in [c[0] for c in conn.execute(f"DESCRIBE {canonical_table}").fetchall()] else "event_record_id"
        
        all_cols = [c[0] for c in conn.execute(f"DESCRIBE {canonical_table}").fetchall()]
        cols_sql = ", ".join(all_cols)

        unmapped_df = conn.execute(f"SELECT {cols_sql} FROM {canonical_table}").df()
        if unmapped_df.empty:
            return {"indexed_records": 0, "total_correlations": 0}

        # Convert once to list of dicts for ultra-fast iteration
        unmapped_records = unmapped_df.to_dict("records")

        # Step 1: Pre-build Process Start Time Map (from Sysmon Event 1 & Security Event 4688)
        process_start_map: Dict[str, str] = {}
        for r in unmapped_records:
            eid = str(r.get("EventID") or r.get("event_id") or "")
            if eid in ("1", "4688"):
                pid_val = str(r.get("ProcessID") or r.get("process_id") or "")
                t_val = str(r.get("TimeCreated") or r.get("time_created_utc") or "")
                if pid_val and t_val:
                    if pid_val.endswith(".0"):
                        pid_val = pid_val[:-2]
                    process_start_map[pid_val] = t_val

        # Step 2: Extract entities for unindexed rows
        entries_to_insert: List[Dict[str, Any]] = []
        next_id = 1
        try:
            max_id = conn.execute(f"SELECT COALESCE(MAX(correlation_id), 0) FROM {self.TABLE_CORRELATIONS}").fetchone()[0]
            next_id = int(max_id) + 1
        except Exception:
            pass

        new_recs_count = 0
        for row_dict in unmapped_records:
            rec_id = str(row_dict.get(rec_col) or "")
            if rec_id.endswith(".0"):
                rec_id = rec_id[:-2]
            if not rec_id or rec_id in indexed_recs:
                continue

            extracted = CorrelationExtractor.extract_from_row(row_dict, self.config, process_start_map)
            
            source_type = str(row_dict.get("Channel") or row_dict.get("source_type") or "")
            event_id = str(row_dict.get("EventID") or row_dict.get("event_id") or "")
            if event_id.endswith(".0"):
                event_id = event_id[:-2]
            provider = str(row_dict.get("Provider") or row_dict.get("provider") or "")
            time_created = str(row_dict.get("TimeCreated") or row_dict.get("time_created_utc") or "")

            for ent in extracted:
                entries_to_insert.append({
                    "correlation_id": next_id,
                    "entity_type": ent["entity_type"],
                    "entity_value": ent["entity_value"],
                    "event_record_id": rec_id,
                    "source_type": source_type,
                    "event_id": event_id,
                    "provider": provider,
                    "time_created_utc": time_created,
                    "confidence": ent["confidence"],
                    "confidence_weight": ent["confidence_weight"],
                })
                next_id += 1

            new_recs_count += 1
            indexed_recs.add(rec_id)

        # Step 3: Bulk insert into DuckDB
        if entries_to_insert:
            ins_df = pd.DataFrame(entries_to_insert)
            conn.register("df_corr_insert", ins_df)
            conn.execute(f"INSERT INTO {self.TABLE_CORRELATIONS} SELECT * FROM df_corr_insert")
            conn.unregister("df_corr_insert")

        total_corrs = conn.execute(f"SELECT COUNT(*) FROM {self.TABLE_CORRELATIONS}").fetchone()[0]
        logger.info(
            f"Correlation index built: {new_recs_count:,} new records processed, "
            f"{len(entries_to_insert):,} entities inserted (Total: {total_corrs:,})."
        )
        return {"indexed_records": new_recs_count, "total_correlations": total_corrs}

    def find_correlated(
        self,
        conn: duckdb.DuckDBPyConnection,
        anchor_event_record_id: str,
        window_overrides: Optional[Dict[str, int]] = None,
        allowed_entity_types: Optional[Sequence[str]] = None,
        min_confidence_weight: float = 0.2,
        include_trivial: bool = False,
        limit: int = 100,
        canonical_table: str = "canonical_logs",
    ) -> List[Dict[str, Any]]:
        """Finds all events correlated to an anchor event record across all channels."""
        anchor_id = str(anchor_event_record_id).strip()
        if anchor_id.endswith(".0"):
            anchor_id = anchor_id[:-2]

        self.init_schema(conn)

        # 1. Fetch anchor entities
        anchor_rows = conn.execute(
            f"""
            SELECT entity_type, entity_value, time_created_utc, source_type, event_id
            FROM {self.TABLE_CORRELATIONS}
            WHERE event_record_id = ?
            """,
            [anchor_id],
        ).fetchall()

        if not anchor_rows:
            return []

        anchor_time_str = anchor_rows[0][2]
        try:
            anchor_dt = date_parser.parse(anchor_time_str)
            if anchor_dt.tzinfo is None:
                anchor_dt = anchor_dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            anchor_dt = datetime.datetime.now(datetime.timezone.utc)

        # 2. Query correlated records per entity
        correlated_results: Dict[str, Dict[str, Any]] = {}

        for etype, evalue, _, _, _ in anchor_rows:
            if allowed_entity_types and etype not in allowed_entity_types:
                continue

            _, conf_wt_def = self.config.get_confidence(etype)
            if not include_trivial and conf_wt_def < min_confidence_weight:
                continue

            max_window = self.config.get_window(etype, window_overrides)

            # Query matches for this entity excluding the anchor record itself
            matches = conn.execute(
                f"""
                SELECT 
                    event_record_id,
                    source_type,
                    event_id,
                    provider,
                    time_created_utc,
                    confidence,
                    confidence_weight
                FROM {self.TABLE_CORRELATIONS}
                WHERE entity_type = ? 
                  AND entity_value = ?
                  AND event_record_id != ?
                """,
                [etype, evalue, anchor_id],
            ).fetchall()

            for rec_id, src, eid, prov, t_str, conf_lbl, conf_wt in matches:
                # Calculate time delta in seconds
                try:
                    ev_dt = date_parser.parse(t_str)
                    if ev_dt.tzinfo is None:
                        ev_dt = ev_dt.replace(tzinfo=datetime.timezone.utc)
                    delta_sec = (ev_dt - anchor_dt).total_seconds()
                except Exception:
                    delta_sec = 0.0

                # Strict Time-Window Enforcement
                if abs(delta_sec) > max_window:
                    continue

                # Human-readable time offset string
                sign = "+" if delta_sec >= 0 else "-"
                abs_sec = abs(int(delta_sec))
                if abs_sec < 60:
                    delta_str = f"{sign}{abs_sec}s"
                elif abs_sec < 3600:
                    delta_str = f"{sign}{abs_sec // 60}m {abs_sec % 60}s"
                else:
                    delta_str = f"{sign}{abs_sec // 3600}h {(abs_sec % 3600) // 60}m"

                # Construct relation description
                reason = f"Shared {etype.replace('_', ' ').title()}: `{evalue}` ({delta_str} in {src})"

                # If record already matched by another entity, keep higher confidence
                if rec_id in correlated_results:
                    existing = correlated_results[rec_id]
                    if conf_wt > existing["confidence_weight"]:
                        existing["entity_type"] = etype
                        existing["entity_value"] = evalue
                        existing["confidence"] = conf_lbl
                        existing["confidence_weight"] = conf_wt
                        existing["relation_reason"] = reason
                else:
                    correlated_results[rec_id] = {
                        "event_record_id": rec_id,
                        "source_type": src,
                        "event_id": eid,
                        "provider": prov,
                        "time_created_utc": t_str,
                        "entity_type": etype,
                        "entity_value": evalue,
                        "confidence": conf_lbl,
                        "confidence_weight": conf_wt,
                        "time_delta_seconds": delta_sec,
                        "time_delta_str": delta_str,
                        "relation_reason": reason,
                    }

        # 3. Sort: 1st by confidence_weight DESC, 2nd by abs(time_delta_seconds) ASC
        sorted_results = sorted(
            correlated_results.values(),
            key=lambda x: (-x["confidence_weight"], abs(x["time_delta_seconds"])),
        )

        return sorted_results[:limit]


# Convenience functional interface
def find_correlated(
    conn: duckdb.DuckDBPyConnection,
    anchor_event_record_id: str,
    window_overrides: Optional[Dict[str, int]] = None,
    allowed_entity_types: Optional[Sequence[str]] = None,
    min_confidence_weight: float = 0.2,
    include_trivial: bool = False,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Global functional interface for finding correlated events."""
    mgr = CorrelationIndexManager()
    return mgr.find_correlated(
        conn,
        anchor_event_record_id,
        window_overrides=window_overrides,
        allowed_entity_types=allowed_entity_types,
        min_confidence_weight=min_confidence_weight,
        include_trivial=include_trivial,
        limit=limit,
    )
