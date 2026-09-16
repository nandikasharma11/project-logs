#!/usr/bin/env python3
"""
================================================================================
STAGE 3: Vector Indexing Layer (Template Embedding + Pre-Filtered Qdrant Index)
================================================================================
Author: Principal Forensics Specialist & Data Systems Architect
Description:
    Vector embedding and search acceleration layer sitting directly on top of
    the DuckDB deduplication/templating layer (log_templates & template_instances).

    Core Architectural Principles:
    1. 1 Vector per Template: A pattern occurring 50,000 times produces 1 vector,
       never 50,000 vectors. Reduces vector space overhead by up to 99.9%.
    2. Filter First, Then Search: Strict pre-filtering on metadata (source_type,
       provider, event_id, level, time_range) prunes search space BEFORE computing
       semantic vector similarity.
    3. Incremental Indexing: New templates get embedded and inserted; existing
       templates with changed total_count/last_seen_utc update metadata in-place
       with zero re-embedding.
    4. Forensic Audit Trail: Embedding model name, version, dimension, and creation
       timestamp are recorded and retrievable for full reproducibility.
    5. Pure Pointer / Evidentiary Integrity: The vector store is only a pointer.
       Returned template_ids resolve back to 100% of the raw, untouched records
       in DuckDB.
================================================================================
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import duckdb
import pandas as pd
import torch
from transformers import AutoModel, AutoTokenizer

from qdrant_client import QdrantClient
from qdrant_client.models import (
    DatetimeRange,
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)

from log_templater import get_event_family_label

logger = logging.getLogger("DFIR_Stage3_Vectorizing")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ==============================================================================
# 1. TEMPLATE EMBEDDER (SWAPPABLE EMBEDDING ENGINE)
# ==============================================================================

class TemplateEmbedder:
    """Modular dense embedding engine tailored for short, technical log templates.

    Defaults to 'BAAI/bge-small-en-v1.5' (384 dimensions, compact, ultra-fast),
    and supports swappable models such as 'jackaduma/SecBERT' (768 dimensions).
    """

    def __init__(
        self,
        model_name: str = "BAAI/bge-small-en-v1.5",
        device: Optional[str] = None,
        max_length: int = 512,
    ):
        self.model_name = model_name
        self.max_length = max_length
        self.device = self._resolve_device(device)

        logger.info("Initializing TemplateEmbedder: '%s' on %s", model_name, self.device)
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.to(self.device)
        self.model.eval()

        self.vector_dim: int = int(self.model.config.hidden_size)
        self.is_bge: bool = "bge" in model_name.lower()
        self.model_version: str = getattr(self.model.config, "_name_or_path", model_name)

    @staticmethod
    def _resolve_device(device: Optional[str] = None) -> torch.device:
        if device:
            return torch.device(device)
        if torch.cuda.is_available():
            return torch.device("cuda")
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return torch.device("mps")
        return torch.device("cpu")

    def _pool(self, model_output: Any, attention_mask: torch.Tensor) -> torch.Tensor:
        """Applies model-appropriate pooling and L2 normalization."""
        if self.is_bge:
            # BGE models use [CLS] token representation (index 0)
            embeddings = model_output.last_hidden_state[:, 0]
        else:
            # Standard mean pooling with attention mask coverage
            token_embeddings = model_output.last_hidden_state
            input_mask_expanded = (
                attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
            )
            sum_embeddings = torch.sum(token_embeddings * input_mask_expanded, dim=1)
            sum_mask = torch.clamp(input_mask_expanded.sum(dim=1), min=1e-9)
            embeddings = sum_embeddings / sum_mask

        # Unit-length L2 normalization for exact cosine similarity
        return torch.nn.functional.normalize(embeddings, p=2, dim=1)

    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """Generates unit-length normalized embeddings for a list of texts."""
        if not texts:
            return []

        all_embeddings: List[List[float]] = []

        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i : i + batch_size]
            encoded = self.tokenizer(
                batch_texts,
                padding=True,
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt",
            ).to(self.device)

            with torch.no_grad():
                outputs = self.model(**encoded)
                normalized = self._pool(outputs, encoded["attention_mask"])
                all_embeddings.extend(normalized.cpu().tolist())

        return all_embeddings

    def embed_single(self, text: str) -> List[float]:
        """Generates embedding for a single text string."""
        return self.embed_batch([text])[0]

    def embed_query(self, query_text: str) -> List[float]:
        """Embeds a search query. Appends BGE instruction prefix if applicable."""
        cleaned_query = query_text.strip()
        if self.is_bge:
            # Recommended prefix for BGE query embeddings
            prompt_query = f"Represent this sentence for searching relevant passages: {cleaned_query}"
        else:
            prompt_query = cleaned_query
        return self.embed_single(prompt_query)

    def get_model_audit_metadata(self) -> Dict[str, Any]:
        """Returns metadata for forensic auditability and reproducibility."""
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "vector_dim": self.vector_dim,
            "device": str(self.device),
            "normalization": "L2",
        }


# ==============================================================================
# 2. REPRESENTATIVE DOCUMENT CONSTRUCTION
# ==============================================================================

def construct_representative_text(template: Dict[str, Any]) -> str:
    """Builds a concise, structured search key for vector embedding from template metadata.

    Combines:
      - Source type (Channel)
      - Level (Severity label: Critical/Error/Warning/Information)
      - Event ID with readable event family description (e.g., 4625 - Failed Logon)
      - Provider
      - Masked template string (structural pattern without transient variable values)
    """
    source_type = str(template.get("source_type") or "Unknown").strip().capitalize()
    event_id = str(template.get("event_id") or "0").strip()
    provider = str(template.get("provider") or "Unknown").strip()
    level = str(template.get("level") or "Information").strip().capitalize()
    template_str = str(template.get("template_string") or template.get("text") or "").strip()

    family_label = get_event_family_label(event_id, source_type)

    return (
        f"[Source: {source_type}] [Level: {level}] [EventID: {event_id} - {family_label}] "
        f"[Provider: {provider}] Template: {template_str}"
    )


# ==============================================================================
# 3. VECTOR INDEX LAYER (PRE-FILTERED QDRANT INDEX)
# ==============================================================================

class TemplateVectorIndex:
    """Vector search index for log templates powered by Qdrant.

    Implements:
      - 1 Vector per template_id.
      - Pre-filtering (filter first, then semantic search).
      - Incremental indexing with in-place metadata updates (zero re-embedding).
      - Model audit trail recording.
      - Evidentiary traceability resolution to DuckDB.
    """

    COLLECTION_NAME = "log_templates_index"

    def __init__(
        self,
        collection_name: str = COLLECTION_NAME,
        embedder: Optional[TemplateEmbedder] = None,
        client: Optional[QdrantClient] = None,
        storage_path: Optional[str] = None,
    ):
        self.collection_name = collection_name
        self.embedder = embedder or TemplateEmbedder()
        self.storage_path = storage_path

        if client is not None:
            self.client = client
        elif storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self.client = QdrantClient(path=storage_path)
        else:
            self.client = QdrantClient(":memory:")

        self._init_collection()

        # Audit metadata
        self.index_metadata: Dict[str, Any] = {
            "collection_name": self.collection_name,
            "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **self.embedder.get_model_audit_metadata(),
        }

    def _init_collection(self) -> None:
        """Initializes Qdrant collection if not already existing."""
        collections = [c.name for c in self.client.get_collections().collections]
        if self.collection_name not in collections:
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(
                    size=self.embedder.vector_dim,
                    distance=Distance.COSINE,
                ),
            )
            logger.info(
                "Created Qdrant collection '%s' (dim=%d, distance=COSINE).",
                self.collection_name,
                self.embedder.vector_dim,
            )

    @staticmethod
    def _template_id_to_point_id(template_id: str) -> str:
        """Converts template_id into a deterministic UUID string for Qdrant point ID."""
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(template_id).strip()))

    def get_model_metadata(self) -> Dict[str, Any]:
        """Returns recorded embedding model audit trail information."""
        info = dict(self.index_metadata)
        try:
            info["total_vectors"] = self.client.count(self.collection_name).count
        except Exception:
            info["total_vectors"] = 0
        return info

    def index_templates(
        self,
        templates: List[Dict[str, Any]],
        batch_size: int = 32,
    ) -> Dict[str, int]:
        """Indexes templates incrementally:
          - New templates: Embedded and inserted with full payload.
          - Existing templates with updated stats (count/time/level): Payload updated in-place (no re-embedding).
          - Unchanged templates: Skipped.

        Args:
            templates: List of template dicts with:
                       template_id, source_type, provider, event_id, level,
                       template_string, first_seen_utc, last_seen_utc, total_count

        Returns:
            Dictionary of ingestion statistics.
        """
        if not templates:
            return {
                "new_indexed": 0,
                "metadata_updated": 0,
                "unchanged_skipped": 0,
                "total_vectors": self.client.count(self.collection_name).count,
            }

        new_to_embed: List[Dict[str, Any]] = []
        metadata_updated_count = 0
        unchanged_skipped_count = 0

        for t in templates:
            tid = str(t["template_id"]).strip()
            point_id = self._template_id_to_point_id(tid)

            # Check if point already exists in index
            existing = self.client.retrieve(self.collection_name, ids=[point_id], with_payload=True)

            payload = {
                "template_id": tid,
                "source_type": str(t.get("source_type") or "Unknown").strip().capitalize(),
                "provider": str(t.get("provider") or "Unknown").strip(),
                "event_id": str(t.get("event_id") or "0").strip(),
                "level": str(t.get("level") or "Information").strip().capitalize(),
                "template_string": str(t.get("template_string") or t.get("text") or "").strip(),
                "first_seen_utc": str(t.get("first_seen_utc") or ""),
                "last_seen_utc": str(t.get("last_seen_utc") or ""),
                "total_count": int(t.get("total_count") or 1),
            }

            if not existing:
                # New template -> needs vector embedding
                text_to_embed = t.get("text") or construct_representative_text(payload)
                new_to_embed.append({
                    "point_id": point_id,
                    "text": text_to_embed,
                    "payload": payload,
                })
            else:
                # Existing template -> check if metadata changed
                curr_payload = existing[0].payload or {}
                count_changed = curr_payload.get("total_count") != payload["total_count"]
                last_seen_changed = curr_payload.get("last_seen_utc") != payload["last_seen_utc"]
                level_changed = curr_payload.get("level") != payload["level"]

                if count_changed or last_seen_changed or level_changed:
                    # In-place metadata update without re-embedding!
                    self.client.set_payload(
                        collection_name=self.collection_name,
                        payload=payload,
                        points=[point_id],
                    )
                    metadata_updated_count += 1
                else:
                    unchanged_skipped_count += 1

        # Embed and insert new templates in batches
        if new_to_embed:
            texts = [item["text"] for item in new_to_embed]
            embeddings = self.embedder.embed_batch(texts, batch_size=batch_size)

            points = []
            for i, item in enumerate(new_to_embed):
                points.append(
                    PointStruct(
                        id=item["point_id"],
                        vector=embeddings[i],
                        payload=item["payload"],
                    )
                )

            self.client.upsert(collection_name=self.collection_name, points=points)

        total_vectors = self.client.count(self.collection_name).count
        return {
            "new_indexed": len(new_to_embed),
            "metadata_updated": metadata_updated_count,
            "unchanged_skipped": unchanged_skipped_count,
            "total_vectors": total_vectors,
        }

    def index_from_duckdb(
        self,
        conn: duckdb.DuckDBPyConnection,
        templates_table: str = "log_templates",
    ) -> Dict[str, int]:
        """Convenience method: Reads log_templates directly from DuckDB and indexes them."""
        query = f"""
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
            FROM {templates_table}
            ORDER BY total_count DESC
        """
        df = conn.execute(query).df()
        templates = df.to_dict(orient="records")
        return self.index_templates(templates)

    def search(
        self,
        query_text: str,
        filters: Optional[Dict[str, Any]] = None,
        top_k: int = 10,
    ) -> List[Dict[str, Any]]:
        """Pre-filtered semantic search over log templates.

        Filter Pattern: FILTER FIRST, THEN SEARCH.
        Narrows the candidate set via payload conditions before similarity ranking.

        Args:
            query_text: Natural language search query or forensic concept.
            filters: Optional dict with filter keys:
                     - 'source_type': str (e.g. 'Security')
                     - 'provider': str (e.g. 'Microsoft-Windows-Security-Auditing')
                     - 'event_id': str or int (e.g. '4625')
                     - 'level': str (e.g. 'Error')
                     - 'time_range': dict with optional 'start_time' and 'end_time'
            top_k: Number of top template matches to return.

        Returns:
            List of dicts: [{'template_id': str, 'score': float, 'metadata': dict}]
        """
        # 1. Build strict Qdrant pre-filters
        must_conditions: List[FieldCondition] = []

        if filters:
            if filters.get("source_type"):
                must_conditions.append(
                    FieldCondition(
                        key="source_type",
                        match=MatchValue(value=str(filters["source_type"]).strip().capitalize()),
                    )
                )
            if filters.get("provider"):
                must_conditions.append(
                    FieldCondition(
                        key="provider",
                        match=MatchValue(value=str(filters["provider"]).strip()),
                    )
                )
            if filters.get("event_id"):
                must_conditions.append(
                    FieldCondition(
                        key="event_id",
                        match=MatchValue(value=str(filters["event_id"]).strip()),
                    )
                )
            if filters.get("level"):
                must_conditions.append(
                    FieldCondition(
                        key="level",
                        match=MatchValue(value=str(filters["level"]).strip().capitalize()),
                    )
                )
            if filters.get("time_range"):
                tr = filters["time_range"]
                if isinstance(tr, dict):
                    start_str = tr.get("start_time")
                    end_str = tr.get("end_time")
                    if start_str:
                        start_dt = datetime.datetime.fromisoformat(str(start_str).replace("Z", "+00:00"))
                        must_conditions.append(
                            FieldCondition(key="last_seen_utc", range=DatetimeRange(gte=start_dt))
                        )
                    if end_str:
                        end_dt = datetime.datetime.fromisoformat(str(end_str).replace("Z", "+00:00"))
                        must_conditions.append(
                            FieldCondition(key="first_seen_utc", range=DatetimeRange(lte=end_dt))
                        )

        query_filter = Filter(must=must_conditions) if must_conditions else None

        # 2. Embed query
        query_vector = self.embedder.embed_query(query_text)

        # 3. Execute pre-filtered vector similarity search
        res = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vector,
            query_filter=query_filter,
            limit=top_k,
        )

        results: List[Dict[str, Any]] = []
        for point in res.points:
            payload = point.payload or {}
            results.append({
                "template_id": payload.get("template_id"),
                "score": float(point.score),
                "metadata": payload,
            })

        return results

    def resolve_search_results_to_records(
        self,
        conn: duckdb.DuckDBPyConnection,
        search_results: List[Dict[str, Any]],
        canonical_table: str = "canonical_logs",
    ) -> pd.DataFrame:
        """Traceability API: Joins search result template_ids with DuckDB template_instances
        and canonical_table to return 100% of underlying raw forensic records.
        """
        template_ids = [r["template_id"] for r in search_results if r.get("template_id")]
        if not template_ids:
            return pd.DataFrame()

        # Inspect canonical columns to find primary key
        cols = [r[0] for r in conn.execute(f"DESCRIBE {canonical_table}").fetchall()]
        cols_lower = {c.lower().replace("_", ""): c for c in cols}
        rec_col = cols_lower.get("eventrecordid") or cols_lower.get("recordid") or cols_lower.get("rowid") or "event_record_id"

        placeholders = ", ".join(["?"] * len(template_ids))
        query = f"""
            SELECT c.*, i.extracted_variables, i.template_id
            FROM {canonical_table} c
            INNER JOIN template_instances i
                ON CAST(c.{rec_col} AS VARCHAR) = i.event_record_id
            WHERE i.template_id IN ({placeholders})
            ORDER BY i.template_id, i.time_created_utc ASC
        """
        return conn.execute(query, template_ids).df()

    def resolve_search_results_to_instances(
        self,
        conn: duckdb.DuckDBPyConnection,
        search_results: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:
        """Returns mapping of template_id -> list of event_record_ids with zero sampling."""
        template_ids = [r["template_id"] for r in search_results if r.get("template_id")]
        if not template_ids:
            return {}

        placeholders = ", ".join(["?"] * len(template_ids))
        rows = conn.execute(
            f"""
            SELECT template_id, event_record_id
            FROM template_instances
            WHERE template_id IN ({placeholders})
            ORDER BY template_id, time_created_utc ASC
            """,
            template_ids,
        ).fetchall()

        mapping: Dict[str, List[str]] = {tid: [] for tid in template_ids}
        for tid, rec_id in rows:
            mapping[tid].append(str(rec_id))

        return mapping


# ==============================================================================
# 4. BACKWARD COMPATIBILITY & DUAL-VECTOR WRAPPERS
# ==============================================================================

class SecBERTDenseEmbedder:
    """Wrapper maintaining backward compatibility for direct SecBERT usage."""

    def __init__(self, model_name: str = "jackaduma/SecBERT", device: Optional[str] = None, max_length: int = 512):
        self.embedder = TemplateEmbedder(model_name=model_name, device=device, max_length=max_length)
        self.model_name = self.embedder.model_name
        self.vector_dim = self.embedder.vector_dim

    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        return self.embedder.embed_batch(texts, batch_size=batch_size)

    def embed_single(self, text: str) -> List[float]:
        return self.embedder.embed_single(text)


try:
    from fastembed import SparseTextEmbedding
except ImportError:
    SparseTextEmbedding = None


class BM25SparseEmbedder:
    """Wrapper maintaining backward compatibility for FastEmbed BM25 usage."""

    def __init__(self, model_name: str = "Qdrant/bm25"):
        if SparseTextEmbedding is None:
            raise ImportError("FastEmbed is required for sparse BM25 vectorization.")
        self.model_name = model_name
        self.model = SparseTextEmbedding(model_name=model_name)

    def embed_batch(self, texts: List[str], batch_size: int = 64) -> List[Tuple[List[int], List[float]]]:
        if not texts:
            return []
        generator = self.model.embed(texts, batch_size=batch_size)
        return [([int(idx) for idx in item.indices], [float(val) for val in item.values]) for item in generator]

    def embed_single(self, text: str) -> Tuple[List[int], List[float]]:
        return self.embed_batch([text])[0]


class ForensicChunkVectorizer:
    """Legacy chunk vectorizer maintaining backward compatibility for Stage 2 chunks."""

    def __init__(self, dense_model_name: str = "jackaduma/SecBERT", sparse_model_name: str = "Qdrant/bm25", device: Optional[str] = None):
        self.dense_embedder = SecBERTDenseEmbedder(model_name=dense_model_name, device=device)
        self.sparse_embedder = BM25SparseEmbedder(model_name=sparse_model_name)

    def vectorize_chunks(self, chunks: List[Dict[str, Any]], dense_batch_size: int = 16, sparse_batch_size: int = 64) -> List[Dict[str, Any]]:
        if not chunks:
            return []
        texts = [c["text"] for c in chunks]
        dense_vecs = self.dense_embedder.embed_batch(texts, batch_size=dense_batch_size)
        sparse_res = self.sparse_embedder.embed_batch(texts, batch_size=sparse_batch_size)
        enriched = []
        for i, c in enumerate(chunks):
            indices, values = sparse_res[i]
            enriched.append({
                "chunk_id": c.get("chunk_id", f"chunk-{i}"),
                "text": c["text"],
                "dense_vector": dense_vecs[i],
                "sparse_indices": indices,
                "sparse_values": values,
                "metadata": c.get("metadata", {}),
            })
        return enriched

    def vectorize_query(self, query_text: str) -> Dict[str, Any]:
        dense_vec = self.dense_embedder.embed_single(query_text)
        indices, values = self.sparse_embedder.embed_single(query_text)
        return {
            "text": query_text,
            "dense_vector": dense_vec,
            "sparse_indices": indices,
            "sparse_values": values,
        }


def vectorize_stage2_chunks(chunks: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
    vectorizer = ForensicChunkVectorizer()
    return vectorizer.vectorize_chunks(chunks)
