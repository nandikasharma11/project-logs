#!/usr/bin/env python3
"""
================================================================================
DEDUPLICATION & TEMPLATING LAYER (Drain3 + DuckDB Traceability)
================================================================================
Author: Principal Forensics Specialist & Data Systems Architect
Description:
    Derived search indexing layer between raw canonical DuckDB log records and
    downstream vector/semantic search. Clusters high-volume near-identical log
    entries into standardized templates using Drain3 streaming template mining
    while guaranteeing non-negotiable evidentiary integrity:

    1. Read-Only Canonical Store: Never writes to, modifies, or deletes records
       in the canonical DuckDB table.
    2. 100% Traceability: Every single event_record_id is mapped to exactly one
       template in 'template_instances'. COUNT(template_instances) == COUNT(canonical).
    3. Per-Channel Mining: Independent Drain3 miners partitioned by source_type
       (Security, System, Application) with domain-specific regex maskers.
    4. State Persistence: Miner state is persisted per channel across incremental
       ingestion runs (no re-clustering from scratch).
    5. Representative Document Generation: Emits one embeddable document per
       template for downstream SecBERT/Qdrant vector indexing.
    6. Idempotency: Re-running ingestion on existing records produces zero
       duplicate templates or instances.
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
        sim_th: float = 0.4,
        depth: int = 4,
    ):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.sim_th = sim_th
        self.depth = depth
        self.miners: Dict[str, TemplateMiner] = {}
        self.masking_instructions = get_forensic_masking_instructions()

    def _get_config(self) -> TemplateMinerConfig:
        """Constructs a Drain3 configuration with domain masking and numeric parametrization."""
        config = TemplateMinerConfig()
        config.drain_sim_th = self.sim_th
        config.drain_depth = self.depth
        config.parametrize_numeric_tokens = True
        config.masking_instructions = self.masking_instructions
        return config

    def get_miner(self, source_type: str) -> TemplateMiner:
        """Retrieves or loads the persistent TemplateMiner for a specific source_type."""
        normalized_channel = (source_type or "unknown").strip().capitalize()
        if normalized_channel not in self.miners:
            persistence_file = self.state_dir / f"{normalized_channel.lower()}_miner.bin"
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
                template_string VARCHAR NOT NULL,
                first_seen_utc VARCHAR NOT NULL,
                last_seen_utc VARCHAR NOT NULL,
                total_count BIGINT NOT NULL DEFAULT 1
            );
        """)

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
        existing_tpls = conn.execute(f"SELECT template_id, template_string, first_seen_utc, last_seen_utc, total_count FROM {self.TABLE_TEMPLATES}").df()
        existing_tpl_map = {row["template_id"]: row.to_dict() for _, row in existing_tpls.iterrows()}

        for _, row in unmapped_df.iterrows():
            rec_id = str(row[rec_col]).strip()
            source_type = str(row.get(chan_col) or "Unknown").strip().capitalize()
            provider = str(row.get(prov_col) or "Unknown").strip() if prov_col else "Unknown"
            event_id = str(row.get(evid_col) or "0").strip() if evid_col else "0"
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
                        template_id, source_type, provider, event_id,
                        template_string, first_seen_utc, last_seen_utc, total_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        tinfo["template_id"],
                        tinfo["source_type"],
                        tinfo["provider"],
                        tinfo["event_id"],
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
                        first_seen_utc = LEAST(first_seen_utc, ?),
                        last_seen_utc = GREATEST(last_seen_utc, ?),
                        total_count = ?
                    WHERE template_id = ?
                    """,
                    [
                        tinfo["template_string"],
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
            tstr = str(row["template_string"])
            count = int(row["total_count"])

            embed_text = (
                f"[Source: {stype}] [EventID: {eid}] [Provider: {prov}] "
                f"Template: {tstr}"
            )

            meta = {
                "template_id": tid,
                "source_type": stype,
                "event_id": eid,
                "provider": prov,
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
