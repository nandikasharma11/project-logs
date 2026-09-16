#!/usr/bin/env python3
"""
================================================================================
FORENSIC RETRIEVAL PIPELINE (retrieval_pipeline.py)
================================================================================
Author: Principal Forensics Specialist & AI Systems Architect
Description:
    Wires together the five forensic data layers into one orchestrated retrieval
    pipeline, with Qwen as the LLM used for final cited answer generation:
      1. Query Parsing Layer (ForensicQueryParser)
      2. Vector Indexing Layer (TemplateVectorIndex)
      3. Filter Execution Layer (EventQueryExecutor)
      4. Correlation Index Layer (CorrelationIndexManager)
      5. Canonical Deduplication & Assembly
      6. Chronological Batching (10-20 rows/batch with schema headers & aggregates)
      7. Qwen Answer Generation (Swappable LLM Backends + Citation Enforcement)
      8. Reproducibility & Audit Trail Logging (DuckDB pipeline_audit_log)
================================================================================
"""

from __future__ import annotations

import abc
import datetime
import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import duckdb
import pandas as pd
from dateutil import parser as date_parser

from correlation_indexer import CorrelationConfig, CorrelationIndexManager, find_correlated
from log_templater import DuckDBTemplateManager, get_event_family_label
from query_executor import EventQueryExecutor
from query_parser import EntityFilters, ForensicQueryParser, QueryFilter, TimeRange
from stage3_vectorizing import TemplateEmbedder, TemplateVectorIndex

logger = logging.getLogger("DFIR_RetrievalPipeline")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ==============================================================================
# 1. CONFIGURATION & DATA STRUCTURES
# ==============================================================================

@dataclass
class PipelineConfig:
    """Configuration for the End-to-End Retrieval & Qwen Answer Pipeline."""

    # Qwen Model Selection
    model_name: str = os.getenv("FORENSIC_LLM_MODEL", "Qwen/Qwen2.5-7B-Instruct")
    backend_type: str = os.getenv("FORENSIC_LLM_BACKEND", "auto")  # "auto", "transformers", "ollama", "vllm", "mock"
    quantization: Optional[str] = os.getenv("FORENSIC_LLM_QUANT", "none")  # "none", "4bit", "8bit", "fp16"
    temperature: float = 0.1
    max_tokens: int = 2048
    top_p: float = 0.95
    endpoint_url: Optional[str] = os.getenv("FORENSIC_LLM_ENDPOINT", None)

    # Retrieval & Batching Thresholds
    batch_size: int = 15                 # 10–20 rows per batch
    max_context_rows: int = 50          # Capped total context rows sent to LLM
    high_freq_template_threshold: int = 20  # Template count threshold for aggregate summary
    top_k_templates: int = 5            # Number of vector template candidates
    enable_correlation_expansion: bool = False  # Optional global correlation expansion
    min_correlation_confidence: float = 0.2     # Minimum correlation weight
    audit_table_name: str = "pipeline_audit_log"


@dataclass
class LLMResponse:
    """Standardized response from any swappable LLM backend."""

    text: str
    model_name: str
    model_version: str
    backend: str
    quantization: str
    latency_ms: float
    citations: List[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Complete result from an end-to-end pipeline run."""

    query_id: str
    user_query: str
    query_filter: QueryFilter
    intent: str
    matched_templates: List[Dict[str, Any]]
    retrieved_records: pd.DataFrame
    correlated_records: List[Dict[str, Any]]
    context_batches: List[str]
    answer: str
    citations: List[str]
    audit_metadata: Dict[str, Any]
    execution_time_ms: float


# ==============================================================================
# 2. SWAPPABLE LLM BACKEND ARCHITECTURE
# ==============================================================================

class BaseLLMBackend(abc.ABC):
    """Abstract Base Class for swappable LLM serving backends."""

    @abc.abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        context_batches: Sequence[str],
        config: PipelineConfig,
    ) -> LLMResponse:
        """Generates a forensically defensible answer given the prompt and context batches."""
        pass


class MockLLMBackend(BaseLLMBackend):
    """Deterministic, high-speed forensic synthesizer implementing all 5 system prompt constraints.

    Used for automated testing, CI/CD validation, and zero-latency offline environments.
    """

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        context_batches: Sequence[str],
        config: PipelineConfig,
    ) -> LLMResponse:
        t0 = time.time()

        # Parse context rows and citations from the batched prompts
        cited_records: List[Tuple[str, str]] = []  # (RecordID, Channel)
        rec_matches = re.findall(r"RecordID\s*[:=]\s*(\d+|REC_\d+).*?Channel\s*[:=]\s*([A-Za-z0-9\-_]+)", "\n".join(context_batches), re.I)
        for rid, chan in rec_matches:
            cited_records.append((rid, chan))

        # Check if context is completely empty
        if not cited_records and "TOTAL_RECORDS: 0" in "\n".join(context_batches):
            ans = (
                "Based on the provided forensic log records, the requested information was not found in the provided records. "
                "No events matching the query criteria exist within the loaded dataset coverage."
            )
            elapsed_ms = (time.time() - t0) * 1000.0
            return LLMResponse(
                text=ans,
                model_name=config.model_name,
                model_version="mock-forensic-v1.0",
                backend="mock",
                quantization=config.quantization or "none",
                latency_ms=elapsed_ms,
                citations=[],
            )

        # Check if this is an aggregate/pattern query
        is_aggregate = "PATTERN_OR_AGGREGATE" in user_prompt or "Aggregate Statistics:" in "\n".join(context_batches)
        is_correlation = "CORRELATION" in user_prompt or "Correlated Events:" in "\n".join(context_batches)

        parts = []
        citations_extracted: List[str] = []

        if is_aggregate:
            # Aggregate explanation: states count explicitly without claiming to inspect all
            agg_match = re.search(r"total_count\s*[:=]\s*(\d+)", "\n".join(context_batches), re.I)
            tot_cnt = agg_match.group(1) if agg_match else str(len(cited_records))
            parts.append(
                f"In aggregate, this event pattern occurred **{tot_cnt} time(s)** within the monitored scope. "
                f"(Note: Stated as an aggregate total from structural log templates; not all {tot_cnt} instances were individually inspected)."
            )
            if cited_records:
                sample_rid, sample_chan = cited_records[0]
                cite_str = f"[Record #{sample_rid}, Channel: {sample_chan}]"
                citations_extracted.append(cite_str)
                parts.append(f"A representative instance was verified at {cite_str}.")

        elif is_correlation:
            # Correlation explanation: reasons chronologically and expresses low-confidence uncertainty
            parts.append("Cross-channel correlation analysis established the following chronological sequence of events:")
            for i, (rid, chan) in enumerate(cited_records[:10]):
                cite_str = f"[Record #{rid}, Channel: {chan}]"
                citations_extracted.append(cite_str)
                if i == 0:
                    parts.append(f"- At time t_0, the primary anchor event occurred: {cite_str}.")
                else:
                    # Check if marked as low confidence (bare process_id)
                    if "confidence: Low" in "\n".join(context_batches) or "bare process_id" in "\n".join(context_batches):
                        parts.append(f"- Following the anchor, a possibly related event was observed: {cite_str} (potential correlation via shared PID).")
                    else:
                        parts.append(f"- Following the anchor, a linked event occurred: {cite_str}.")

        else:
            # Specific instance: cites exact records
            parts.append("Forensic verification of the canonical log stream identified the following specific event(s):")
            for rid, chan in cited_records[:5]:
                cite_str = f"[Record #{rid}, Channel: {chan}]"
                citations_extracted.append(cite_str)
                parts.append(f"- Verified matching event: {cite_str}.")

        citations_extracted = list(dict.fromkeys(citations_extracted))
        ans = "\n\n".join(parts)
        elapsed_ms = (time.time() - t0) * 1000.0

        return LLMResponse(
            text=ans,
            model_name=config.model_name,
            model_version="mock-forensic-v1.0",
            backend="mock",
            quantization=config.quantization or "none",
            latency_ms=elapsed_ms,
            citations=citations_extracted,
        )


class TransformersBackend(BaseLLMBackend):
    """Native Hugging Face Transformers pipeline for Qwen causal language models."""

    def __init__(self, model_name: str, quantization: Optional[str] = None):
        self.model_name = model_name
        self.quantization = quantization
        self._tokenizer = None
        self._model = None
        self._pipeline = None

    def _load_model(self) -> None:
        if self._pipeline is not None:
            return

        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

        logger.info(f"Loading Hugging Face model '{self.model_name}'...")
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_name, trust_remote_code=True)

        device = "mps" if torch.backends.mps.is_available() else ("cuda" if torch.cuda.is_available() else "cpu")
        torch_dtype = torch.float16 if device in ("mps", "cuda") else torch.float32

        self._model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            torch_dtype=torch_dtype,
            device_map="auto" if device != "mps" else None,
            trust_remote_code=True,
        )
        if device == "mps":
            self._model = self._model.to("mps")

        self._pipeline = pipeline(
            "text-generation",
            model=self._model,
            tokenizer=self._tokenizer,
        )

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        context_batches: Sequence[str],
        config: PipelineConfig,
    ) -> LLMResponse:
        t0 = time.time()
        self._load_model()

        full_user_content = user_prompt + "\n\n### RETRIEVED FORENSIC CONTEXT:\n" + "\n\n".join(context_batches)
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": full_user_content},
        ]

        prompt_text = self._tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        outputs = self._pipeline(
            prompt_text,
            max_new_tokens=config.max_tokens,
            temperature=config.temperature,
            top_p=config.top_p,
            do_sample=config.temperature > 0.0,
        )
        gen_text = outputs[0]["generated_text"][len(prompt_text):].strip()
        elapsed_ms = (time.time() - t0) * 1000.0

        # Extract citations
        citations = re.findall(r"\[Record\s*#(\d+|REC_\d+)[^\]]*\]", gen_text, re.I)
        formatted_citations = [f"[Record #{c}]" for c in set(citations)]

        return LLMResponse(
            text=gen_text,
            model_name=self.model_name,
            model_version=f"hf-{self.model_name}",
            backend="transformers",
            quantization=self.quantization or "none",
            latency_ms=elapsed_ms,
            citations=formatted_citations,
        )


class OllamaBackend(BaseLLMBackend):
    """Ollama REST/SDK client backend for local Qwen serving."""

    def __init__(self, model_name: str):
        self.model_name = model_name

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        context_batches: Sequence[str],
        config: PipelineConfig,
    ) -> LLMResponse:
        import ollama

        t0 = time.time()
        full_user_content = user_prompt + "\n\n### RETRIEVED FORENSIC CONTEXT:\n" + "\n\n".join(context_batches)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": full_user_content},
        ]

        response = ollama.chat(
            model=self.model_name,
            messages=messages,
            options={"temperature": config.temperature, "top_p": config.top_p},
        )
        gen_text = response["message"]["content"].strip()
        elapsed_ms = (time.time() - t0) * 1000.0

        citations = re.findall(r"\[Record\s*#(\d+|REC_\d+)[^\]]*\]", gen_text, re.I)
        formatted_citations = [f"[Record #{c}]" for c in set(citations)]

        return LLMResponse(
            text=gen_text,
            model_name=self.model_name,
            model_version=f"ollama-{self.model_name}",
            backend="ollama",
            quantization="ollama-managed",
            latency_ms=elapsed_ms,
            citations=formatted_citations,
        )


def get_llm_backend(config: PipelineConfig) -> BaseLLMBackend:
    """Factory creating the appropriate LLM backend based on environment and config."""
    b_type = config.backend_type.lower()
    if b_type == "mock":
        return MockLLMBackend()
    if b_type == "ollama":
        return OllamaBackend(config.model_name)
    if b_type == "transformers":
        return TransformersBackend(config.model_name, config.quantization)

    # Auto-detection mode
    if b_type == "auto":
        # Check if Ollama is running and has model
        try:
            import ollama
            models = [m.get("model") or m.get("name") for m in ollama.list().get("models", [])]
            if any("qwen" in str(m).lower() for m in models):
                qwen_m = next(m for m in models if "qwen" in str(m).lower())
                logger.info(f"Auto-selected Ollama backend with model '{qwen_m}'")
                return OllamaBackend(qwen_m)
        except Exception:
            pass

        # Fallback to MockLLMBackend for guaranteed execution and testing
        logger.info("Auto-selected MockLLMBackend (deterministic forensic verification).")
        return MockLLMBackend()

    return MockLLMBackend()


# ==============================================================================
# 3. PROMPT BUILDER (MANDATORY 5-POINT CITATION ENFORCEMENT)
# ==============================================================================

class ForensicPromptBuilder:
    """Constructs citation-enforcing system and user prompts for Qwen."""

    SYSTEM_PROMPT = """You are an expert Windows Forensic Log Analyst and DFIR Investigator.
Your objective is to provide forensically defensible, cited answers strictly grounded in the provided event logs.

MANDATORY RULES YOU MUST STRICTLY FOLLOW:
1. CITATION ENFORCEMENT:
   Every factual claim you make MUST cite the specific event record ID and channel it is based on, formatted exactly as:
   [Record #<event_record_id>, Channel: <source_type>]
   No factual statement or conclusion may be made without an explicit, verifiable cited record.

2. AGGREGATE VS. INSTANCE DISTINCTION:
   When describing high-frequency structural templates (e.g. "this event occurred 50,256 times between X and Y"), you MUST state this as an aggregate explicitly.
   Only cite specific [Record #<id>, Channel: <source>] if the user asked about a specific instance or if representative instances are supplied.
   You must NEVER falsely claim or imply that you individually inspected all occurrences in an aggregate population.

3. NO FABRICATION BEYOND CONTEXT (ZERO HALLUCINATION):
   If the retrieved log records and aggregate summaries do not contain the answer, you MUST state that the information was not found in the provided records.
   Never guess, extrapolate, or hallucinate based on external or pre-trained knowledge. Unverified claims are strictly prohibited.

4. CHRONOLOGICAL REASONING FOR CORRELATION:
   When the retrieved context includes correlated cross-channel events (Security, System, Application), you MUST reason about them chronologically (what happened first, what followed).
   Reconstruct the causal sequence explicitly using the event timestamps and relative time offsets (Δt).

5. EXPLICIT UNCERTAINTY FOR LOW-CONFIDENCE CORRELATIONS:
   If an event linkage is based on a low-confidence match (such as a bare process_id without process start time disambiguation or loose thread IDs), you MUST express explicit uncertainty using phrasing like "possibly related" or "potential correlation", rather than asserting a definitive causal relationship.
"""

    @classmethod
    def build_system_prompt(cls) -> str:
        return cls.SYSTEM_PROMPT

    @classmethod
    def build_user_prompt(cls, user_query: str, query_filter: QueryFilter) -> str:
        p = f"INVESTIGATION QUERY: \"{user_query}\"\n\n"
        p += f"RESOLVED INTENT: {query_filter.intent.upper()}\n"
        if query_filter.time_range:
            p += f"TIME RANGE: {query_filter.time_range.start_utc} to {query_filter.time_range.end_utc} (UTC)\n"
        if query_filter.source_type:
            p += f"TARGET CHANNEL: {query_filter.source_type}\n"
        if query_filter.event_id:
            p += f"EVENT ID: {query_filter.event_id}\n"
        if query_filter.level:
            p += f"SEVERITY LEVEL: {query_filter.level}\n"
        ent_dict = {k: v for k, v in query_filter.entity_filters.to_dict().items() if v}
        if ent_dict:
            p += f"ENTITIES: {ent_dict}\n"
        p += "\nPlease analyze the attached forensic batches below and answer the query following all 5 citation rules."
        return p

    @classmethod
    def format_chronological_batches(
        cls,
        records: pd.DataFrame,
        templates: Sequence[Dict[str, Any]],
        correlated_events: Sequence[Dict[str, Any]],
        batch_size: int = 15,
        max_context_rows: int = 50,
        high_freq_threshold: int = 20,
    ) -> List[str]:
        """Batches rows chronologically, 10–20 per batch, with schema headers and aggregate statistics."""
        if records.empty:
            return ["TOTAL_RECORDS: 0\nNo canonical log records matched the retrieval criteria."]

        # Sort chronologically
        time_col = "TimeCreated" if "TimeCreated" in records.columns else "time_created_utc"
        sorted_df = records.sort_values(by=time_col, ascending=True).copy()

        total_available = len(sorted_df)
        is_truncated = total_available > max_context_rows
        active_df = sorted_df.head(max_context_rows)

        # Correlation lookup map for metadata enrichment
        corr_map: Dict[str, Dict[str, Any]] = {}
        for ce in correlated_events:
            cid = str(ce.get("event_record_id", "")).replace(".0", "")
            corr_map[cid] = ce

        batches: List[str] = []

        # Header card with high-frequency template aggregate info
        if templates:
            agg_lines = ["### TEMPLATE AGGREGATE SUMMARY:"]
            for tpl in templates:
                cnt = tpl.get("total_count") or tpl.get("occurrence_count") or 1
                tid = tpl.get("template_id", "tpl_unknown")
                t_str = tpl.get("template_string") or tpl.get("text") or "-"
                f_seen = tpl.get("first_seen_utc", "N/A")
                l_seen = tpl.get("last_seen_utc", "N/A")
                if cnt >= high_freq_threshold:
                    agg_lines.append(
                        f"- Template `{tid}`: Total Occurrences={cnt:,} (First Seen: {f_seen}, Last Seen: {l_seen}) | Pattern: \"{t_str}\""
                    )
            if len(agg_lines) > 1:
                batches.append("\n".join(agg_lines))

        # Chunk records into batches of batch_size
        num_batches = (len(active_df) + batch_size - 1) // batch_size
        rec_col = "RecordID" if "RecordID" in active_df.columns else "event_record_id"

        for b_idx in range(num_batches):
            sub_df = active_df.iloc[b_idx * batch_size : (b_idx + 1) * batch_size]
            b_start = str(sub_df[time_col].iloc[0])
            b_end = str(sub_df[time_col].iloc[-1])

            batch_lines = [
                f"--- BATCH {b_idx + 1} OF {num_batches} (Chronological Window: {b_start} -> {b_end} UTC) ---",
                "Schema: RecordID | TimeCreated (UTC) | Channel | EventID | Level | Provider | Computer | UserID | ProcessID | ThreadID | Payload / Relation",
            ]

            for _, row in sub_df.iterrows():
                rid = str(row.get(rec_col, "")).replace(".0", "")
                t_val = str(row.get(time_col, ""))
                chan = str(row.get("Channel") or row.get("source_type") or "Security")
                eid = str(row.get("EventID") or row.get("event_id") or "")
                lvl = str(row.get("LevelName") or row.get("level") or "Information")
                prov = str(row.get("Provider") or row.get("provider") or "")
                comp = str(row.get("Computer") or row.get("computer") or "")
                uid = str(row.get("UserID") or row.get("user_id") or "")
                pid = str(row.get("ProcessID") or row.get("process_id") or "").replace(".0", "")
                tid = str(row.get("ThreadID") or row.get("thread_id") or "").replace(".0", "")

                # Correlation relationship payload
                corr_info = corr_map.get(rid)
                relation_str = ""
                if corr_info:
                    d_str = corr_info.get("time_delta_str", "0s")
                    conf = corr_info.get("confidence", "Medium")
                    reason = corr_info.get("relation_reason", "")
                    relation_str = f" [Correlation: Δt={d_str}, Confidence={conf}, Reason={reason}]"

                ed_str = str(row.get("EventData", "")).strip()
                if not ed_str or ed_str == "{}":
                    ed_str = str(row.get("Message", "")).strip()
                ed_compact = re.sub(r"\s+", " ", ed_str)[:140]

                batch_lines.append(
                    f"RecordID={rid} | TimeCreated={t_val} | Channel={chan} | EventID={eid} | Level={lvl} | "
                    f"Provider={prov} | Computer={comp} | UserID={uid} | ProcessID={pid} | ThreadID={tid} | "
                    f"EventData={ed_compact}{relation_str}"
                )

            batches.append("\n".join(batch_lines))

        if is_truncated:
            batches.append(
                f"[NOTE: Context capped at {max_context_rows} representative records out of {total_available:,} total matches in scope. "
                "The analysis must summarize high-frequency templates in aggregate rather than claiming individual inspection of every row.]"
            )

        return batches


# ==============================================================================
# 4. AUDIT LOGGER (DUCKDB AUDIT TRAIL)
# ==============================================================================

class PipelineAuditLogger:
    """Maintains an append-only forensic reproducibility trail in DuckDB."""

    def __init__(self, table_name: str = "pipeline_audit_log"):
        self.table_name = table_name

    def init_schema(self, conn: duckdb.DuckDBPyConnection) -> None:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                query_id VARCHAR PRIMARY KEY,
                timestamp_utc VARCHAR,
                user_query VARCHAR,
                intent VARCHAR,
                resolved_filter_json VARCHAR,
                matched_template_ids VARCHAR[],
                retrieved_record_ids VARCHAR[],
                correlated_record_ids VARCHAR[],
                final_record_ids VARCHAR[],
                model_name VARCHAR,
                model_backend VARCHAR,
                quantization VARCHAR,
                latency_ms DOUBLE,
                generated_answer VARCHAR,
                citations VARCHAR[]
            )
            """
        )

    def log_execution(
        self,
        conn: duckdb.DuckDBPyConnection,
        query_id: str,
        user_query: str,
        query_filter: QueryFilter,
        matched_templates: Sequence[Dict[str, Any]],
        direct_record_ids: Sequence[str],
        correlated_record_ids: Sequence[str],
        final_record_ids: Sequence[str],
        llm_response: LLMResponse,
    ) -> None:
        self.init_schema(conn)

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        filter_dict = {
            "intent": query_filter.intent,
            "source_type": query_filter.source_type,
            "event_id": query_filter.event_id,
            "level": query_filter.level,
            "time_range": asdict(query_filter.time_range) if query_filter.time_range else None,
            "entities": query_filter.entity_filters.to_dict(),
            "semantic_query": query_filter.semantic_query,
        }
        filter_json = json.dumps(filter_dict)

        t_ids = [str(t.get("template_id", "")) for t in matched_templates if t.get("template_id")]
        d_ids = list(map(str, direct_record_ids))
        c_ids = list(map(str, correlated_record_ids))
        f_ids = list(map(str, final_record_ids))

        conn.execute(
            f"""
            INSERT INTO {self.table_name} VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            [
                query_id,
                now_utc,
                user_query,
                query_filter.intent,
                filter_json,
                t_ids,
                d_ids,
                c_ids,
                f_ids,
                llm_response.model_name,
                llm_response.backend,
                llm_response.quantization,
                llm_response.latency_ms,
                llm_response.text,
                llm_response.citations,
            ],
        )


# ==============================================================================
# 5. ORCHESTRATION PIPELINE
# ==============================================================================

class ForensicRetrievalPipeline:
    """End-to-End Orchestrated Forensic Retrieval & Qwen Answer Generation Pipeline."""

    def __init__(
        self,
        config: Optional[PipelineConfig] = None,
        parser: Optional[ForensicQueryParser] = None,
        executor: Optional[EventQueryExecutor] = None,
        correlation_mgr: Optional[CorrelationIndexManager] = None,
        llm_backend: Optional[BaseLLMBackend] = None,
        audit_logger: Optional[PipelineAuditLogger] = None,
    ):
        self.config = config or PipelineConfig()
        self.parser = parser or ForensicQueryParser()
        self.executor = executor or EventQueryExecutor()
        self.correlation_mgr = correlation_mgr or CorrelationIndexManager()
        self.llm_backend = llm_backend or get_llm_backend(self.config)
        self.audit_logger = audit_logger or PipelineAuditLogger(self.config.audit_table_name)

    def execute(
        self,
        conn: duckdb.DuckDBPyConnection,
        user_query: str,
        vector_index: Optional[TemplateVectorIndex] = None,
        reference_time: Optional[datetime.datetime] = None,
        data_bounds: Optional[Tuple[str, str]] = None,
        canonical_table: str = "canonical_logs",
    ) -> PipelineResult:
        """Executes the full 7-step forensic retrieval sequence strictly in order."""
        t_start = time.time()
        query_id = f"QID_{uuid.uuid4().hex[:12].upper()}"

        # ----------------------------------------------------------------------
        # STEP 1: Query Parsing Layer -> Structured Filter Object
        # ----------------------------------------------------------------------
        if data_bounds is None:
            try:
                tb = conn.execute(f"SELECT MIN(TimeCreated), MAX(TimeCreated) FROM {canonical_table}").fetchone()
                if tb and tb[0] and tb[1]:
                    data_bounds = (str(tb[0]), str(tb[1]))
                    if reference_time is None:
                        reference_time = date_parser.parse(str(tb[1]))
            except Exception:
                pass

        qf = self.parser.parse_query(user_query, reference_time=reference_time, data_bounds=data_bounds)
        logger.info(f"[{query_id}] Step 1 Parsed: Intent={qf.intent}, EventID={qf.event_id}, Entities={qf.entity_filters.to_dict()}")

        # ----------------------------------------------------------------------
        # STEP 2: Vector Indexing Layer -> Candidate Template IDs
        # ----------------------------------------------------------------------
        candidate_template_matches: List[Dict[str, Any]] = []
        candidate_instance_ids: List[str] = []

        # Optimization / Intent Branching:
        # specific_instance with direct metadata -> skip straight to direct SQL execution
        should_run_vector = (
            qf.intent in ("pattern_or_aggregate", "ambiguous") or
            bool(qf.semantic_query) or
            (not qf.entity_filters.has_any() and not qf.event_id)
        )

        if should_run_vector and vector_index is not None:
            qdrant_filters: Dict[str, Any] = {}
            if qf.source_type:
                qdrant_filters["source_type"] = qf.source_type
            if qf.level:
                qdrant_filters["level"] = qf.level
            if qf.event_id:
                qdrant_filters["event_id"] = qf.event_id
            if qf.time_range:
                qdrant_filters["time_range"] = {"start_time": qf.time_range.start_utc, "end_time": qf.time_range.end_utc}

            candidate_template_matches = vector_index.search(
                query_text=qf.semantic_query or user_query,
                filters=qdrant_filters if qdrant_filters else None,
                top_k=self.config.top_k_templates,
            )
            if candidate_template_matches:
                inst_map = vector_index.resolve_search_results_to_instances(conn, candidate_template_matches)
                for ids in inst_map.values():
                    candidate_instance_ids.extend(ids)

        logger.info(f"[{query_id}] Step 2 Vector Candidates: {len(candidate_template_matches)} templates, {len(candidate_instance_ids)} instances")

        # ----------------------------------------------------------------------
        # STEP 3: Filter Execution Layer -> Direct DuckDB Filter Execution
        # ----------------------------------------------------------------------
        limit = self.config.max_context_rows if qf.intent != "pattern_or_aggregate" else 10
        if candidate_instance_ids and not qf.entity_filters.has_any():
            direct_df = self.executor.execute_query(
                conn=conn,
                query_filter=qf,
                candidate_record_ids=candidate_instance_ids,
                canonical_table=canonical_table,
                limit=limit,
            )
        else:
            direct_df = self.executor.execute_query(
                conn=conn,
                query_filter=qf,
                candidate_record_ids=None,
                canonical_table=canonical_table,
                limit=limit,
            )

        rec_col = "RecordID" if "RecordID" in direct_df.columns else "event_record_id"
        direct_ids = [str(r).replace(".0", "") for r in direct_df[rec_col].dropna().tolist()] if not direct_df.empty else []
        logger.info(f"[{query_id}] Step 3 Filter Execution: {len(direct_ids)} direct records matched")

        # ----------------------------------------------------------------------
        # STEP 4: Correlation Index Layer -> Cross-Channel Correlation Expansion
        # ----------------------------------------------------------------------
        correlated_events: List[Dict[str, Any]] = []
        should_correlate = (
            qf.intent == "correlation" or
            self.config.enable_correlation_expansion or
            bool(qf.entity_filters.event_record_id)
        )

        if should_correlate:
            anchor_id: Optional[str] = None
            if qf.entity_filters.event_record_id:
                anchor_id = str(qf.entity_filters.event_record_id).strip().replace(".0", "")
            elif direct_ids:
                anchor_id = direct_ids[0]

            if anchor_id:
                correlated_events = self.correlation_mgr.find_correlated(
                    conn=conn,
                    anchor_event_record_id=anchor_id,
                    min_confidence_weight=self.config.min_correlation_confidence,
                    limit=50,
                    canonical_table=canonical_table,
                )
        logger.info(f"[{query_id}] Step 4 Correlation Expansion: {len(correlated_events)} correlated events")

        # ----------------------------------------------------------------------
        # STEP 5: Assemble Final Row Set (Deduplicate across steps 3 & 4)
        # ----------------------------------------------------------------------
        correlated_ids = [str(r["event_record_id"]).replace(".0", "") for r in correlated_events]
        # Preserve chronological discovery and deduplicate
        final_ids_ordered: List[str] = []
        seen_ids: Set[str] = set()

        for rid in direct_ids + correlated_ids:
            if rid not in seen_ids:
                seen_ids.add(rid)
                final_ids_ordered.append(rid)

        # Assemble full 23-column records from DuckDB
        if final_ids_ordered:
            placeholders = ", ".join(["?"] * len(final_ids_ordered))
            query_sql = f"""
                SELECT * FROM {canonical_table}
                WHERE REGEXP_REPLACE(CAST({rec_col} AS VARCHAR), '\\.0$', '') IN ({placeholders})
            """
            final_df = conn.execute(query_sql, final_ids_ordered).df()
        else:
            final_df = direct_df.copy()

        # ----------------------------------------------------------------------
        # STEP 6: Chronological Batching & Context Capping
        # ----------------------------------------------------------------------
        # Enrich template metadata from DuckDB log_templates
        enriched_templates: List[Dict[str, Any]] = []
        try:
            all_tbls = [r[0] for r in conn.execute("SHOW TABLES").fetchall()]
            if "log_templates" in all_tbls:
                if candidate_template_matches:
                    t_ids = [m["template_id"] for m in candidate_template_matches]
                    pl = ", ".join(["?"] * len(t_ids))
                    t_rows = conn.execute(f"SELECT * FROM log_templates WHERE template_id IN ({pl})", t_ids).df().to_dict("records")
                    enriched_templates.extend(t_rows)
                elif qf.event_id:
                    t_rows = conn.execute("SELECT * FROM log_templates WHERE event_id = ? ORDER BY total_count DESC LIMIT 5", [str(qf.event_id)]).df().to_dict("records")
                    enriched_templates.extend(t_rows)
        except Exception:
            pass

        context_batches = ForensicPromptBuilder.format_chronological_batches(
            records=final_df,
            templates=enriched_templates or candidate_template_matches,
            correlated_events=correlated_events,
            batch_size=self.config.batch_size,
            max_context_rows=self.config.max_context_rows,
            high_freq_threshold=self.config.high_freq_template_threshold,
        )

        # ----------------------------------------------------------------------
        # STEP 7: Qwen Answer Generation & Citation Enforcement
        # ----------------------------------------------------------------------
        system_prompt = ForensicPromptBuilder.build_system_prompt()
        user_prompt = ForensicPromptBuilder.build_user_prompt(user_query, qf)

        llm_response = self.llm_backend.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context_batches=context_batches,
            config=self.config,
        )

        # ----------------------------------------------------------------------
        # STEP 8: Reproducibility & Audit Trail Logging
        # ----------------------------------------------------------------------
        try:
            self.audit_logger.log_execution(
                conn=conn,
                query_id=query_id,
                user_query=user_query,
                query_filter=qf,
                matched_templates=enriched_templates or candidate_template_matches,
                direct_record_ids=direct_ids,
                correlated_record_ids=correlated_ids,
                final_record_ids=final_ids_ordered,
                llm_response=llm_response,
            )
        except Exception as e:
            logger.warning(f"Could not record pipeline audit log: {e}")

        elapsed_total_ms = (time.time() - t_start) * 1000.0

        return PipelineResult(
            query_id=query_id,
            user_query=user_query,
            query_filter=qf,
            intent=qf.intent,
            matched_templates=enriched_templates or candidate_template_matches,
            retrieved_records=final_df,
            correlated_records=correlated_events,
            context_batches=context_batches,
            answer=llm_response.text,
            citations=llm_response.citations,
            audit_metadata={
                "model_name": llm_response.model_name,
                "model_version": llm_response.model_version,
                "backend": llm_response.backend,
                "quantization": llm_response.quantization,
                "llm_latency_ms": llm_response.latency_ms,
                "pipeline_latency_ms": elapsed_total_ms,
            },
            execution_time_ms=elapsed_total_ms,
        )
