#!/usr/bin/env python3
"""
================================================================================
DEDUPLICATION & TEMPLATING LAYER (Drain3 + DuckDB Traceability)
================================================================================
Author: Principal Forensics Specialist & Data Systems Architect

ARCHITECTURE OVERVIEW:
This layer sits between the raw canonical log records (preserved in DuckDB) and
the downstream vector/semantic search and embedding pipeline. It addresses the
fundamental challenge of forensic log analysis: 80-95% of enterprise Windows
event logs are high-frequency, near-identical repetitive events (e.g., Event 4624
logon bursts, Event 4625 brute-force attempts, or Event 7036 service heartbeats).
Embedding every single log instance floods vector stores with redundant vectors
and blows out token budgets.

This module clusters redundant records into standardized templates using Drain3
streaming parse trees, while strictly upholding non-negotiable EVIDENTIARY INTEGRITY:
  - Canonical Store is Strictly Read-Only (SELECT queries only). Zero deletes/edits.
  - 100% Traceability: Every single event_record_id is mapped to a template.
    COUNT(template_instances) == COUNT(canonical_logs).
  - No Sampling or Silent Truncation: Querying a template returns 100% of the
    underlying raw records.

DERIVED DUCKDB TABLES CREATED:
--------------------------------------------------------------------------------
1. 'log_templates' (Derived Template Summary):
   - template_id        VARCHAR PRIMARY KEY (Deterministic cluster key: TPL_{CHANNEL}_{EVENTID}_{CLUSTER})
   - source_type        VARCHAR NOT NULL    (Security | System | Application)
   - provider           VARCHAR             (e.g., Microsoft-Windows-Security-Auditing)
   - event_id           VARCHAR             (e.g., 4625)
   - template_string    VARCHAR NOT NULL    (e.g., 'An account failed to log on with status <HEX> from IP <IP> for user <*>' )
   - first_seen_utc     VARCHAR NOT NULL    (Timestamp of earliest occurrence)
   - last_seen_utc      VARCHAR NOT NULL    (Timestamp of latest occurrence)
   - total_count        BIGINT NOT NULL     (Exact count of log records matching this template)

2. 'template_instances' (100% Evidentiary Traceability Mapping):
   - event_record_id    VARCHAR PRIMARY KEY (Foreign key back to canonical record store)
   - template_id        VARCHAR NOT NULL    (Foreign key to log_templates)
   - time_created_utc   VARCHAR             (Denormalized for zero-join time range queries)
   - extracted_variables VARCHAR            (JSON string of abstracted parameter values, e.g. {"0": "admin", "1": "10.0.0.1"})

DOWNSTREAM CONSUMPTION GUIDE:
--------------------------------------------------------------------------------
How Downstream Stages MUST Consume This Layer:

1. Stage 3 (Embedding Generation - SecBERT / BGE):
   - Call `generate_representative_documents(conn)` to retrieve the list of
     distinct template documents.
   - Embed ONLY these representative documents (1 vector per template), rather
     than 100,000 raw individual logs.
   - Each document contains: Source channel, EventID, synthesized Event Family
     label, Provider, and the standardized template string.

2. Stage 4 (Vector Indexing - Qdrant):
   - Upsert the template embeddings into Qdrant collection using `template_id`
     as the point ID.
   - Attach metadata payload (`source_type`, `event_id`, `provider`, `total_count`,
     `first_seen_utc`, `last_seen_utc`).

3. Stage 5 & 6 (Two-Pass Forensic Retrieval & RAG):
   - PASS 1 (Semantic Candidate Discovery):
     Perform dense/hybrid vector search against Qdrant to retrieve the top-k
     most relevant `template_id`s for an investigator's natural language query.
   - PASS 2 (Evidentiary Traceability & Full Record Fetch):
     Given the top `template_id`s, query DuckDB via:
       - `get_instances_for_template(conn, template_id)` -> Returns 100% of record IDs.
       - `get_records_for_template(conn, template_id)`   -> Returns full 23-column raw records.
     Pass the aggregated template context + exemplar records into the LLM for forensic synthesis.
================================================================================
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import duckdb
import pandas as pd
from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

logger = logging.getLogger(__name__)


# ==============================================================================
# 0. WINDOWS EVENT FAMILIES TAXONOMY
# ==============================================================================

WINDOWS_EVENT_FAMILIES: Dict[str, str] = {
    # Security Channel - Authentication & Logon
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4634": "Account Logoff",
    "4647": "User-Initiated Logoff",
    "4648": "Logon with Explicit Credentials",
    "4672": "Special Privileges Assigned to New Logon",
    "4776": "Domain Controller Validated Credentials (NTLM)",
    "4768": "Kerberos Authentication Ticket (TGT) Requested",
    "4769": "Kerberos Service Ticket Requested",
    "4771": "Kerberos Pre-Authentication Failed",
    # Security Channel - Process & Execution Tracking
    "4688": "A New Process Was Created",
    "4689": "A Process Has Exited",
    "4697": "A Service Was Installed in the System",
    "4698": "A Scheduled Task Was Created",
    "4699": "A Scheduled Task Was Deleted",
    "4700": "A Scheduled Task Was Enabled",
    "4702": "A Scheduled Task Was Updated",
    # Security Channel - Account & Group Management
    "4720": "A User Account Was Created",
    "4722": "A User Account Was Enabled",
    "4724": "An Attempt Was Made to Reset an Account Password",
    "4726": "A User Account Was Deleted",
    "4738": "A User Account Was Modified",
    "4740": "A User Account Was Locked Out",
    "4728": "A Member Was Added to a Security-Enabled Global Group",
    "4732": "A Member Was Added to a Security-Enabled Local Group",
    "4756": "A Member Was Added to a Security-Enabled Universal Group",
    # Security Channel - Policy & Audit
    "1102": "The Audit Log Was Cleared",
    "4719": "System Audit Policy Was Changed",
    # System Channel - Service & Lifecycle
    "7036": "Service State Changed",
    "7040": "Service Start Type Changed",
    "7045": "A New Service Was Installed on the System",
    "1074": "System Shutdown or Restart Initiated",
    "6005": "Event Log Service Started",
    "6006": "Event Log Service Stopped",
    "6008": "The Previous System Shutdown Was Unexpected",
    # Application Channel - Errors & Diagnostics
    "1000": "Application Error (Crash)",
    "1001": "Windows Error Reporting (WER)",
    "1002": "Application Hang",
}


def get_event_family_label(event_id: str, source_type: str = "") -> str:
    """Returns a short synthesized sentence or label describing the event family
    (e.g., 'Event 4625: Failed Logon') derivable from the Windows Event ID.
    """
    clean_id = str(event_id).strip()
    if clean_id in WINDOWS_EVENT_FAMILIES:
        return f"Event {clean_id}: {WINDOWS_EVENT_FAMILIES[clean_id]}"
    if source_type:
        return f"{source_type} Event {clean_id}"
    return f"Event {clean_id}"


# ==============================================================================
# 1. WINDOWS FORENSIC REGEX MASKING INSTRUCTIONS
# ==============================================================================

def get_forensic_masking_instructions() -> List[MaskingInstruction]:
    """Returns tuned regex masking instructions to mask variable parameters
    (IPs, hex error codes, SIDs, GUIDs, paths, timestamps) into standard tokens
    before Drain3 tree clustering.
    """
    return [
        # Hex Status & Memory Codes (e.g. 0xC000006A, 0x0, 0x7FFE)
        MaskingInstruction(r"\b0x[0-9a-fA-F]+\b", "<HEX>"),
        # IPv4 Addresses with optional port (e.g. 192.168.1.50, 10.0.0.1:443)
        MaskingInstruction(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b", "<IP>"),
        # Windows Security Identifiers - SIDs (e.g. S-1-5-21-123456789-...)
        MaskingInstruction(r"\bS-1-[0-59]-\d+(?:-\d+)+\b", "<SID>"),
        # Windows GUIDs / UUIDs (e.g. {54849625-5478-4994-A5BA-3E3B0328C30D})
        MaskingInstruction(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?", "<GUID>"),
        # Windows File Paths (e.g. C:\Windows\System32\cmd.exe)
        MaskingInstruction(r"[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*", "<PATH>"),
        # ISO 8601 & UTC Timestamps
        MaskingInstruction(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b", "<TIME>"),
    ]


# ==============================================================================
# 2. PER-CHANNEL DRAIN3 MINER MANAGER
# ==============================================================================

class Drain3ChannelManager:
    """Manages independent Drain3 TemplateMiner instances partitioned per source_type
    (e.g., Security, System, Application). Persists cluster state to disk.
    """

    def __init__(
        self,
        state_dir: str = ".drain3_state",
        config_file: Optional[str] = "drain3.ini",
        sim_th: float = 0.4,
        depth: int = 4,
    ):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = config_file
        self.sim_th = sim_th
        self.depth = depth
        self.miners: Dict[str, TemplateMiner] = {}
        self.masking_instructions = get_forensic_masking_instructions()

    def _get_config(self) -> TemplateMinerConfig:
        """Constructs a Drain3 configuration. Loads from config_file if present,
        otherwise uses programmatic defaults and domain masking rules.
        """
        config = TemplateMinerConfig()
        if self.config_file and os.path.isfile(self.config_file):
            try:
                config.load(self.config_file)
                if not config.masking_instructions:
                    config.masking_instructions = self.masking_instructions
                return config
            except Exception as e:
                logger.warning("Could not load config from %s: %s. Using defaults.", self.config_file, e)

        config.drain_sim_th = self.sim_th
        config.drain_depth = self.depth
        config.parametrize_numeric_tokens = True
        config.masking_instructions = self.masking_instructions
        return config

    def get_miner(self, source_type: str) -> TemplateMiner:
        """Retrieves or loads the persistent TemplateMiner for a specific source_type."""
        normalized_channel = (source_type or "unknown").strip().capitalize()
        if normalized_channel not in self.miners:
            safe_filename = re.sub(r"[^A-Za-z0-9_-]", "_", normalized_channel.lower())
            persistence_file = self.state_dir / f"{safe_filename}_miner.bin"
            self.state_dir.mkdir(parents=True, exist_ok=True)
            persistence = FilePersistence(str(persistence_file))
            config = self._get_config()
            miner = TemplateMiner(persistence_handler=persistence, config=config)
            self.miners[normalized_channel] = miner
        return self.miners[normalized_channel]

    def mine_log(
        self,
        source_type: str,
        log_message: str,
    ) -> Tuple[int, str, Dict[str, str]]:
        """Mines a log message using the channel's dedicated Drain3 miner.

        Returns:
            Tuple of (cluster_id, template_string, extracted_variables_dict)
        """
        miner = self.get_miner(source_type)
        cleaned_msg = " ".join((log_message or "").split())
        if not cleaned_msg:
            cleaned_msg = "[Empty Message]"

        result = miner.add_log_message(cleaned_msg)
        cluster_id = result.get("cluster_id") or 0
        template_str = result.get("template_mined") or cleaned_msg

        # Extract parameters against the template
        extracted_vars: Dict[str, str] = {}
        try:
            params = miner.extract_parameters(template_str, cleaned_msg)
            if params:
                for idx, p in enumerate(params):
                    val = getattr(p, "value", str(p))
                    extracted_vars[str(idx)] = str(val)
        except Exception:
            pass

        return cluster_id, template_str, extracted_vars

    def save_all(self) -> None:
        """Explicitly flushes state for all active channel miners to disk."""
        for miner in self.miners.values():
            if miner.persistence_handler:
                miner.save_state("incremental_batch")


# ==============================================================================
# 3. DUCKDB TEMPLATE & TRACEABILITY STORAGE ENGINE
# ==============================================================================

class DuckDBTemplateManager:
    """Manages the derived search index tables in DuckDB:
      - 'log_templates': Summary of mined templates, counts, and observation range.
      - 'template_instances': Traceability table linking every record_id to its template.

    Hard constraint:
      - NEVER writes to, modifies, or deletes rows in the canonical log table.
    """

    TABLE_TEMPLATES = "log_templates"
    TABLE_INSTANCES = "template_instances"

    def __init__(
        self,
        channel_manager: Optional[Drain3ChannelManager] = None,
        state_dir: str = ".drain3_state",
    ):
        self.channel_manager = channel_manager or Drain3ChannelManager(state_dir=state_dir)

    def init_tables(self, conn: duckdb.DuckDBPyConnection) -> None:
        """Creates the derived template and instance mapping tables if they do not exist."""
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_TEMPLATES} (
                template_id VARCHAR PRIMARY KEY,
                source_type VARCHAR NOT NULL,
                provider VARCHAR,
                event_id VARCHAR,
                level VARCHAR DEFAULT 'Information',
                template_string VARCHAR NOT NULL,
                first_seen_utc VARCHAR NOT NULL,
                last_seen_utc VARCHAR NOT NULL,
                total_count BIGINT NOT NULL DEFAULT 1
            );
        """)

        # Ensure level column exists if table was previously created without it
        try:
            cols = [r[0].lower() for r in conn.execute(f"DESCRIBE {self.TABLE_TEMPLATES}").fetchall()]
            if "level" not in cols:
                conn.execute(f"ALTER TABLE {self.TABLE_TEMPLATES} ADD COLUMN level VARCHAR DEFAULT 'Information'")
        except Exception:
            pass

        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_INSTANCES} (
                event_record_id VARCHAR PRIMARY KEY,
                template_id VARCHAR NOT NULL REFERENCES {self.TABLE_TEMPLATES}(template_id),
                time_created_utc VARCHAR,
                extracted_variables VARCHAR
            );
        """)

    @staticmethod
    def _resolve_canonical_columns(columns: Sequence[str]) -> Dict[str, str]:
        """Resolves existing DataFrame or DuckDB table column names to canonical keys:
        - event_record_id <- [event_record_id, RecordID, row_id, id]
        - source_type     <- [source_type, Channel, Source, LogName]
        - provider        <- [provider, Provider, ProviderName]
        - event_id        <- [event_id, EventID, Id]
        - level           <- [level, LevelName, Level, Severity]
        - time_created_utc<- [time_created_utc, TimeCreated, Timestamp, SystemTime]
        - message_text    <- [event_data, Message, EventData, Details, Payload]
        """
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
            "level": find_col(["level", "levelname", "severity"]),
            "time_created_utc": find_col(["time_created_utc", "timecreated", "timestamp", "systemtime"]),
            "message": find_col(["message", "details", "description"]),
            "event_data": find_col(["event_data", "eventdata", "payload", "userdata"]),
        }
        return {k: v for k, v in mapping.items() if v is not None}

    def process_canonical_records(
        self,
        conn: duckdb.DuckDBPyConnection,
        canonical_table: str = "canonical_logs",
    ) -> Dict[str, Any]:
        """Reads unmapped records from canonical_table, clusters them with Drain3,
        updates log_templates, and maps every record in template_instances.

        Hard constraint:
          - Reads canonical_table exclusively using SELECT.
          - Guaranteed idempotent: Re-running on existing records does not duplicate entries.
        """
        self.init_tables(conn)

        # Inspect canonical columns
        table_cols = [r[0] for r in conn.execute(f"DESCRIBE {canonical_table}").fetchall()]
        col_map = self._resolve_canonical_columns(table_cols)

        rec_col = col_map.get("event_record_id") or "event_record_id"
        chan_col = col_map.get("source_type") or "source_type"
        prov_col = col_map.get("provider") or "provider"
        evid_col = col_map.get("event_id") or "event_id"
        lvl_col = col_map.get("level")
        time_col = col_map.get("time_created_utc") or "time_created_utc"
        msg_col = col_map.get("message")
        ed_col = col_map.get("event_data")

        # Select only unmapped records (Idempotency Guard)
        unmapped_query = f"""
            SELECT * FROM {canonical_table}
            WHERE CAST({rec_col} AS VARCHAR) NOT IN (
                SELECT event_record_id FROM {self.TABLE_INSTANCES}
            )
            ORDER BY {time_col if time_col in table_cols else rec_col} ASC
        """
        unmapped_df = conn.execute(unmapped_query).df()

        if unmapped_df.empty:
            stats = self.verify_evidentiary_integrity(conn, canonical_table)
            return {
                "new_records_processed": 0,
                "new_templates_created": 0,
                "total_instances_mapped": stats["instance_count"],
                "total_templates": stats["template_count"],
            }

        new_records_count = len(unmapped_df)
        new_instances: List[Dict[str, Any]] = []
        template_updates: Dict[str, Dict[str, Any]] = {}

        # Fetch existing templates for fast cache lookups
        existing_tpls = conn.execute(f"SELECT template_id, template_string, level, first_seen_utc, last_seen_utc, total_count FROM {self.TABLE_TEMPLATES}").df()
        existing_tpl_map = {row["template_id"]: row.to_dict() for _, row in existing_tpls.iterrows()}

        sev_rank = {"Critical": 4, "Error": 3, "Warning": 2, "Information": 1, "Verbose": 0}

        for _, row in unmapped_df.iterrows():
            rec_id = str(row[rec_col]).strip()
            source_type = str(row.get(chan_col) or "Unknown").strip().capitalize()
            provider = str(row.get(prov_col) or "Unknown").strip() if prov_col else "Unknown"
            event_id = str(row.get(evid_col) or "0").strip() if evid_col else "0"
            raw_level = str(row.get(lvl_col) or "Information").strip().capitalize() if lvl_col else "Information"
            if not raw_level or raw_level.lower() in ("none", "nan", "null"):
                raw_level = "Information"
            time_created = str(row.get(time_col) or "").strip()

            # Format log text: prioritize Message, then EventData
            msg_val = str(row.get(msg_col) or "").strip() if msg_col else ""
            ed_val = str(row.get(ed_col) or "").strip() if ed_col else ""
            if msg_val and ed_val and msg_val != ed_val:
                log_text = f"{msg_val} | Payload: {ed_val}"
            elif msg_val:
                log_text = msg_val
            elif ed_val:
                log_text = ed_val
            else:
                log_text = f"EventID {event_id} from {provider}"

            # Drain3 mining
            cluster_id, template_str, extracted_vars = self.channel_manager.mine_log(
                source_type=source_type,
                log_message=log_text,
            )

            # Unique deterministic template identifier per channel & event
            safe_chan = re.sub(r"[^A-Za-z0-9]", "", source_type).upper()
            safe_evid = re.sub(r"[^A-Za-z0-9]", "", event_id) or "0"
            template_id = f"TPL_{safe_chan}_{safe_evid}_{cluster_id:04d}"

            # Track template aggregates
            if template_id in template_updates:
                t_entry = template_updates[template_id]
                t_entry["total_count"] += 1
                if sev_rank.get(raw_level, 1) > sev_rank.get(t_entry.get("level", "Information"), 1):
                    t_entry["level"] = raw_level
                if time_created:
                    if not t_entry["first_seen_utc"] or time_created < t_entry["first_seen_utc"]:
                        t_entry["first_seen_utc"] = time_created
                    if not t_entry["last_seen_utc"] or time_created > t_entry["last_seen_utc"]:
                        t_entry["last_seen_utc"] = time_created
                t_entry["template_string"] = template_str
            elif template_id in existing_tpl_map:
                e_entry = existing_tpl_map[template_id]
                first_seen = e_entry["first_seen_utc"]
                last_seen = e_entry["last_seen_utc"]
                curr_level = e_entry.get("level") or "Information"
                if sev_rank.get(raw_level, 1) > sev_rank.get(curr_level, 1):
                    curr_level = raw_level
                if time_created:
                    if not first_seen or time_created < first_seen:
                        first_seen = time_created
                    if not last_seen or time_created > last_seen:
                        last_seen = time_created
                template_updates[template_id] = {
                    "template_id": template_id,
                    "source_type": source_type,
                    "provider": provider,
                    "event_id": event_id,
                    "level": curr_level,
                    "template_string": template_str,
                    "first_seen_utc": first_seen or time_created,
                    "last_seen_utc": last_seen or time_created,
                    "total_count": int(e_entry["total_count"]) + 1,
                    "is_new": False,
                }
            else:
                template_updates[template_id] = {
                    "template_id": template_id,
                    "source_type": source_type,
                    "provider": provider,
                    "event_id": event_id,
                    "level": raw_level,
                    "template_string": template_str,
                    "first_seen_utc": time_created,
                    "last_seen_utc": time_created,
                    "total_count": 1,
                    "is_new": True,
                }

            # Prepare instance mapping row
            new_instances.append({
                "event_record_id": rec_id,
                "template_id": template_id,
                "time_created_utc": time_created,
                "extracted_variables": json.dumps(extracted_vars, ensure_ascii=False),
            })

        # Batch upsert templates in DuckDB
        new_templates_created = 0
        for tid, tinfo in template_updates.items():
            if tinfo.get("is_new", False) and tid not in existing_tpl_map:
                conn.execute(
                    f"""
                    INSERT INTO {self.TABLE_TEMPLATES} (
                        template_id, source_type, provider, event_id, level,
                        template_string, first_seen_utc, last_seen_utc, total_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        tinfo["template_id"],
                        tinfo["source_type"],
                        tinfo["provider"],
                        tinfo["event_id"],
                        tinfo["level"],
                        tinfo["template_string"],
                        tinfo["first_seen_utc"],
                        tinfo["last_seen_utc"],
                        tinfo["total_count"],
                    ],
                )
                new_templates_created += 1
            else:
                conn.execute(
                    f"""
                    UPDATE {self.TABLE_TEMPLATES}
                    SET template_string = ?,
                        level = ?,
                        first_seen_utc = LEAST(first_seen_utc, ?),
                        last_seen_utc = GREATEST(last_seen_utc, ?),
                        total_count = ?
                    WHERE template_id = ?
                    """,
                    [
                        tinfo["template_string"],
                        tinfo["level"],
                        tinfo["first_seen_utc"],
                        tinfo["last_seen_utc"],
                        tinfo["total_count"],
                        tid,
                    ],
                )

        # Batch insert instances in DuckDB
        if new_instances:
            inst_df = pd.DataFrame(new_instances)
            conn.register("_temp_new_instances", inst_df)
            conn.execute(
                f"""
                INSERT INTO {self.TABLE_INSTANCES}
                SELECT event_record_id, template_id, time_created_utc, extracted_variables
                FROM _temp_new_instances
                """
            )
            conn.unregister("_temp_new_instances")

        # Persist miner states to disk
        self.channel_manager.save_all()

        stats = self.verify_evidentiary_integrity(conn, canonical_table)
        return {
            "new_records_processed": new_records_count,
            "new_templates_created": new_templates_created,
            "total_instances_mapped": stats["instance_count"],
            "total_templates": stats["template_count"],
        }

    def get_instances_for_template(
        self,
        conn: duckdb.DuckDBPyConnection,
        template_id: str,
    ) -> List[str]:
        """Traceability API: Given a template_id, returns the complete, exact list
        of event_record_ids it represents without any sampling or truncation.
        """
        rows = conn.execute(
            f"""
            SELECT event_record_id
            FROM {self.TABLE_INSTANCES}
            WHERE template_id = ?
            ORDER BY time_created_utc ASC, event_record_id ASC
            """,
            [template_id],
        ).fetchall()
        return [str(r[0]) for r in rows]

    def get_records_for_template(
        self,
        conn: duckdb.DuckDBPyConnection,
        template_id: str,
        canonical_table: str = "canonical_logs",
    ) -> pd.DataFrame:
        """Traceability API: Given a template_id, joins with the canonical record store
        to return all complete 23-column raw records.
        """
        table_cols = [r[0] for r in conn.execute(f"DESCRIBE {canonical_table}").fetchall()]
        col_map = self._resolve_canonical_columns(table_cols)
        rec_col = col_map.get("event_record_id") or "event_record_id"

        query = f"""
            SELECT c.*, i.extracted_variables, i.template_id
            FROM {canonical_table} c
            INNER JOIN {self.TABLE_INSTANCES} i
                ON CAST(c.{rec_col} AS VARCHAR) = i.event_record_id
            WHERE i.template_id = ?
            ORDER BY i.time_created_utc ASC, i.event_record_id ASC
        """
        return conn.execute(query, [template_id]).df()

    def generate_representative_documents(
        self,
        conn: duckdb.DuckDBPyConnection,
    ) -> List[Dict[str, Any]]:
        """Representative Document Generation:
        Generates one embeddable text block per template_id with representative
        context (channel, event_id, provider, template string).
        Only these distinct templates are vectorized downstream (SecBERT/Qdrant),
        achieving high compression while retaining full traceability.
        """
        self.init_tables(conn)
        templates_df = conn.execute(
            f"""
            SELECT 
                template_id, 
                source_type, 
                provider, 
                event_id, 
                level,
                template_string, 
                first_seen_utc, 
                last_seen_utc, 
                total_count
            FROM {self.TABLE_TEMPLATES}
            ORDER BY total_count DESC, template_id ASC
            """
        ).df()

        documents: List[Dict[str, Any]] = []
        for _, row in templates_df.iterrows():
            tid = str(row["template_id"])
            stype = str(row["source_type"])
            eid = str(row["event_id"])
            prov = str(row["provider"])
            lvl = str(row.get("level") or "Information").strip().capitalize()
            tstr = str(row["template_string"])
            count = int(row["total_count"])
            family_label = get_event_family_label(eid, stype)

            embed_text = (
                f"[Source: {stype}] [Level: {lvl}] [EventID: {eid}] [Family: {family_label}] "
                f"[Provider: {prov}] Template: {tstr}"
            )

            meta = {
                "template_id": tid,
                "source_type": stype,
                "provider": prov,
                "event_id": eid,
                "level": lvl,
                "event_family": family_label,
                "template_string": tstr,
                "total_count": count,
                "first_seen_utc": str(row["first_seen_utc"]),
                "last_seen_utc": str(row["last_seen_utc"]),
                "is_template_document": True,
            }

            documents.append({
                "template_id": tid,
                "chunk_id": tid,
                "text": embed_text,
                "metadata": meta,
            })

        return documents

    def verify_evidentiary_integrity(
        self,
        conn: duckdb.DuckDBPyConnection,
        canonical_table: str = "canonical_logs",
    ) -> Dict[str, Any]:
        """Validates the non-negotiable acceptance criteria:
          1. COUNT(template_instances) == COUNT(canonical_logs)
          2. SUM(log_templates.total_count) == COUNT(canonical_logs)
          3. Zero records dropped or unmapped.
        """
        canonical_count = conn.execute(f"SELECT COUNT(*) FROM {canonical_table}").fetchone()[0]
        instance_count = conn.execute(f"SELECT COUNT(*) FROM {self.TABLE_INSTANCES}").fetchone()[0]
        tpl_sum_res = conn.execute(f"SELECT COALESCE(SUM(total_count), 0) FROM {self.TABLE_TEMPLATES}").fetchone()[0]
        template_count = conn.execute(f"SELECT COUNT(*) FROM {self.TABLE_TEMPLATES}").fetchone()[0]

        is_valid = (canonical_count == instance_count == tpl_sum_res)
        return {
            "canonical_count": canonical_count,
            "instance_count": instance_count,
            "template_sum_count": tpl_sum_res,
            "template_count": template_count,
            "integrity_valid": is_valid,
        }
