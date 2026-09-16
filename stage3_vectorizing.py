#!/usr/bin/env python3
"""
================================================================================
STAGE 3: Vectorization (Dense SecBERT + Sparse FastEmbed BM25) for DFIR RAG
================================================================================
Author: Principal Software Engineer / DFIR Specialist
Description:
    Dual-vector representation pipeline for contextualized Windows Event Log
    chunks generated in Stage 2. Computes:
      1. Dense Semantic Vectors: 768-dimensional normalized embeddings via
         domain-specific SecBERT (e.g., 'jackaduma/SecBERT') for semantic,
         conceptual, and attack-tactic similarity.
      2. Sparse Lexical Vectors: Token indices and BM25 weights via FastEmbed
         ('Qdrant/bm25') for exact-match forensic tokens (Event IDs like 4625,
         hex error codes like 0xC000006A, IP addresses, usernames, and hosts).

Input Format:
    List of chunk dictionaries from Stage 2:
    [
        {
            "chunk_id": "<uuid-or-hash>",
            "text": "[2026-09-14 08:00:00Z] SEC-SRV-01 | 4625 (Error) | guest ...",
            "metadata": {
                "start_time": "2026-09-14T08:00:00Z",
                "end_time": "2026-09-14T08:10:00Z",
                "host": "SEC-SRV-01",
                "event_ids": [4625, 4688]
            }
        }
    ]

Output Format:
    Enriched chunk dictionaries ready for Stage 4 Qdrant ingestion:
    [
        {
            "chunk_id": "<uuid-or-hash>",
            "text": "[2026-09-14 08:00:00Z] SEC-SRV-01 | 4625 (Error) ...",
            "dense_vector": [0.0123, -0.0456, ...],  # 768-dim float list
            "sparse_indices": [1866414088, 1737061407, ...],  # uint32/int list
            "sparse_values": [1.6652, 1.4210, ...],   # float list
            "metadata": { ... }
        }
    ]
================================================================================
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import torch
from transformers import AutoModel, AutoTokenizer

# Optional FastEmbed import with clear diagnostics
try:
    from fastembed import SparseTextEmbedding
except ImportError:
    SparseTextEmbedding = None  # Handled gracefully in BM25SparseEmbedder

logger = logging.getLogger("DFIR_Stage3_Vectorizing")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ==============================================================================
# 1. DENSE VECTOR EMBEDDER (SecBERT)
# ==============================================================================

class SecBERTDenseEmbedder:
    """Computes dense forensic embeddings using SecBERT.
    
    Performs mean pooling with attention mask coverage and L2 normalization
    to produce unit-length vectors optimized for Cosine similarity in Qdrant.
    """

    def __init__(
        self,
        model_name: str = "jackaduma/SecBERT",
        device: Optional[str] = None,
        max_length: int = 512,
    ):
        self.model_name = model_name
        self.max_length = max_length
        self.device = self._resolve_device(device)

        logger.info("Initializing SecBERT dense embedder with model: '%s' on %s", model_name, self.device)
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.to(self.device)
        self.model.eval()

        self.vector_dim = self.model.config.hidden_size

    @staticmethod
    def _resolve_device(device: Optional[str] = None) -> torch.device:
        if device:
            return torch.device(device)
        if torch.cuda.is_available():
            return torch.device("cuda")
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            # Apple Silicon acceleration
            return torch.device("mps")
        return torch.device("cpu")

    def _mean_pooling(
        self, model_output: Any, attention_mask: torch.Tensor
    ) -> torch.Tensor:
        """Mean pooling with attention mask to discard padding token artifacts."""
        token_embeddings = model_output.last_hidden_state  # (batch_size, seq_len, hidden_size)
        input_mask_expanded = (
            attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
        )
        sum_embeddings = torch.sum(token_embeddings * input_mask_expanded, dim=1)
        sum_mask = torch.clamp(input_mask_expanded.sum(dim=1), min=1e-9)
        return sum_embeddings / sum_mask

    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """Generates L2-normalized dense embeddings for a batch of text chunks."""
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
                pooled = self._mean_pooling(outputs, encoded["attention_mask"])
                # L2 normalize for exact cosine similarity
                normalized = torch.nn.functional.normalize(pooled, p=2, dim=1)
                all_embeddings.extend(normalized.cpu().tolist())

        return all_embeddings

    def embed_single(self, text: str) -> List[float]:
        """Generates embedding for a single string."""
        return self.embed_batch([text])[0]


# ==============================================================================
# 2. SPARSE VECTOR EMBEDDER (FastEmbed BM25)
# ==============================================================================

class BM25SparseEmbedder:
    """Generates sparse lexical vectors (token indices & BM25 weights) via FastEmbed.
    
    Preserves exact forensic tokens including Event IDs (e.g. 4625, 4688, 7045),
    NTSTATUS / Win32 hex error codes (e.g. 0xC000006A, 0x00000000), IP addresses,
    and process names.
    """

    def __init__(self, model_name: str = "Qdrant/bm25"):
        if SparseTextEmbedding is None:
            raise ImportError(
                "FastEmbed is required for sparse BM25 vectorization. "
                "Please install it with: pip install fastembed"
            )
        self.model_name = model_name
        logger.info("Initializing FastEmbed sparse embedder with model: '%s'", model_name)
        self.model = SparseTextEmbedding(model_name=model_name)

    def embed_batch(
        self, texts: List[str], batch_size: int = 64
    ) -> List[Tuple[List[int], List[float]]]:
        """Computes sparse representations (indices, values) for each text."""
        if not texts:
            return []

        results: List[Tuple[List[int], List[float]]] = []
        # FastEmbed model.embed handles batching and returns a generator
        generator = self.model.embed(texts, batch_size=batch_size)

        for item in generator:
            indices = [int(idx) for idx in item.indices]
            values = [float(val) for val in item.values]
            results.append((indices, values))

        return results

    def embed_single(self, text: str) -> Tuple[List[int], List[float]]:
        """Computes sparse representation for a single text string."""
        res = self.embed_batch([text])[0]
        return res


# ==============================================================================
# 3. FORENSIC CHUNK VECTORIZER (ORCHESTRATOR)
# ==============================================================================

class ForensicChunkVectorizer:
    """End-to-End vectorizer executing Stage 3 Vectorization.
    
    Transforms Stage 2 chunks into dual dense + sparse representations.
    """

    def __init__(
        self,
        dense_model_name: str = "jackaduma/SecBERT",
        sparse_model_name: str = "Qdrant/bm25",
        device: Optional[str] = None,
        max_length: int = 512,
    ):
        self.dense_embedder = SecBERTDenseEmbedder(
            model_name=dense_model_name,
            device=device,
            max_length=max_length,
        )
        self.sparse_embedder = BM25SparseEmbedder(model_name=sparse_model_name)

    def vectorize_chunks(
        self,
        chunks: List[Dict[str, Any]],
        dense_batch_size: int = 16,
        sparse_batch_size: int = 64,
    ) -> List[Dict[str, Any]]:
        """Enriches Stage 2 chunks with dense and sparse vector spaces.
        
        Args:
            chunks: List of dictionaries with keys: 'chunk_id', 'text', 'metadata'.
            dense_batch_size: Batch size for SecBERT inference.
            sparse_batch_size: Batch size for FastEmbed BM25 inference.
            
        Returns:
            List of enriched dictionaries with:
              'chunk_id', 'text', 'dense_vector', 'sparse_indices', 'sparse_values', 'metadata'
        """
        if not chunks:
            return []

        texts = [chunk["text"] for chunk in chunks]

        logger.info(
            "Vectorizing %d chunks (Dense SecBERT + Sparse BM25)...",
            len(texts),
        )
        t0 = time.time()

        # 1. Compute Dense Vectors
        dense_vectors = self.dense_embedder.embed_batch(texts, batch_size=dense_batch_size)

        # 2. Compute Sparse Vectors
        sparse_results = self.sparse_embedder.embed_batch(texts, batch_size=sparse_batch_size)

        elapsed = time.time() - t0
        logger.info(
            "Successfully vectorized %d chunks in %.2f seconds (%.2f chunks/sec).",
            len(chunks),
            elapsed,
            len(chunks) / max(elapsed, 0.001),
        )

        # 3. Assemble Enriched Chunks
        enriched_chunks: List[Dict[str, Any]] = []
        for i, chunk in enumerate(chunks):
            sparse_indices, sparse_values = sparse_results[i]
            enriched = {
                "chunk_id": chunk.get("chunk_id", f"chunk-{i}"),
                "text": chunk["text"],
                "dense_vector": dense_vectors[i],
                "sparse_indices": sparse_indices,
                "sparse_values": sparse_values,
                "metadata": chunk.get("metadata", {}),
            }
            enriched_chunks.append(enriched)

        return enriched_chunks

    def vectorize_query(self, query_text: str) -> Dict[str, Any]:
        """Vectorizes a single search query into dense and sparse representations.
        
        Essential for Stage 5 Hybrid Search execution.
        """
        dense_vector = self.dense_embedder.embed_single(query_text)
        sparse_indices, sparse_values = self.sparse_embedder.embed_single(query_text)
        return {
            "text": query_text,
            "dense_vector": dense_vector,
            "sparse_indices": sparse_indices,
            "sparse_values": sparse_values,
        }


# ==============================================================================
# 4. FUNCTIONAL INTERFACE
# ==============================================================================

def vectorize_stage2_chunks(
    chunks: List[Dict[str, Any]],
    dense_model: str = "jackaduma/SecBERT",
    sparse_model: str = "Qdrant/bm25",
    batch_size: int = 16,
    device: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Functional convenience entrypoint for Stage 3 Vectorization."""
    vectorizer = ForensicChunkVectorizer(
        dense_model_name=dense_model,
        sparse_model_name=sparse_model,
        device=device,
    )
    return vectorizer.vectorize_chunks(chunks, dense_batch_size=batch_size)


# ==============================================================================
# 5. SELF-CONTAINED VERIFICATION & DEMONSTRATION
# ==============================================================================

def _run_stage3_demonstration():
    """Runs a standalone demonstration and validation of Stage 3 vectorization."""
    print("=" * 80)
    print("🚀 STAGE 3: VECTORIZATION (SecBERT + FastEmbed BM25) DEMONSTRATION")
    print("=" * 80)

    # Mock Stage 2 chunks with real-world forensic tokens
    sample_chunks = [
        {
            "chunk_id": "chunk-sec-001",
            "text": (
                "[2026-09-14T08:09:30Z] SEC-SRV-01 | 4625 (Error) | guest | "
                "Details: An account failed to log on. Status=0xC000006D, SubStatus=0xC000006A"
            ),
            "metadata": {
                "start_time": "2026-09-14T08:00:00Z",
                "end_time": "2026-09-14T08:10:00Z",
                "host": "SEC-SRV-01",
                "event_ids": [4625],
            },
        },
        {
            "chunk_id": "chunk-sec-002",
            "text": (
                "[2026-09-14T08:04:15Z] SEC-SRV-01 | 4688 (Information) | admin_jdoe | "
                "Details: New process created: powershell.exe -NoP -NonI -W Hidden -Exec Bypass"
            ),
            "metadata": {
                "start_time": "2026-09-14T08:00:00Z",
                "end_time": "2026-09-14T08:10:00Z",
                "host": "SEC-SRV-01",
                "event_ids": [4688],
            },
        },
        {
            "chunk_id": "chunk-sec-003",
            "text": (
                "[2026-09-14T07:59:00Z] DC-PRIMARY | 1102 (Critical) | attacker_svc | "
                "Details: The audit log was cleared."
            ),
            "metadata": {
                "start_time": "2026-09-14T07:50:00Z",
                "end_time": "2026-09-14T08:00:00Z",
                "host": "DC-PRIMARY",
                "event_ids": [1102],
            },
        },
    ]

    print(f"\n📦 Processing {len(sample_chunks)} sample Stage 2 chunk(s)...")

    vectorizer = ForensicChunkVectorizer()
    enriched = vectorizer.vectorize_chunks(sample_chunks, dense_batch_size=2)

    print("\n🔍 VECTORIZATION RESULTS:")
    for i, chk in enumerate(enriched, 1):
        print(f"\n--- Chunk {i} [{chk['chunk_id']}] ---")
        print(f"📄 Text snippet: {chk['text'][:70]}...")
        print(f"🧠 Dense Vector Dimension: {len(chk['dense_vector'])} (Expected: 768)")
        print(f"   First 5 dense components: {[round(x, 4) for x in chk['dense_vector'][:5]]}")
        print(f"⚡ Sparse Tokens Count: {len(chk['sparse_indices'])}")
        print(f"   Sample Sparse (Index, BM25 weight): {list(zip(chk['sparse_indices'][:3], [round(v, 4) for v in chk['sparse_values'][:3]]))}")
        print(f"🏷️ Metadata preserved: {chk['metadata']}")

    # Validation Checks
    print("\n" + "=" * 80)
    print("🔬 VALIDATION CHECKS:")
    assert len(enriched) == len(sample_chunks), "Output chunk count mismatch"

    for i, chk in enumerate(enriched):
        assert "dense_vector" in chk, f"Chunk {i} missing dense_vector"
        assert "sparse_indices" in chk, f"Chunk {i} missing sparse_indices"
        assert "sparse_values" in chk, f"Chunk {i} missing sparse_values"
        assert len(chk["dense_vector"]) == 768, f"Dense vector must be 768 dimensions, got {len(chk['dense_vector'])}"
        assert len(chk["sparse_indices"]) == len(chk["sparse_values"]), "Sparse indices and values length mismatch"
        assert len(chk["sparse_indices"]) > 0, f"Sparse tokens should not be empty for chunk {i}"

    # Test Query Vectorization
    print("\n🎯 Testing Query Vectorization (for Stage 5 Hybrid Search)...")
    query_res = vectorizer.vectorize_query("0xC000006A Event 4625 brute force logon failure")
    assert len(query_res["dense_vector"]) == 768
    assert len(query_res["sparse_indices"]) > 0
    print("✅ Query vectorization confirmed (dense 768-d + sparse BM25 representation ready).")

    print("\n🎉 STAGE 3 VALIDATION PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    _run_stage3_demonstration()
