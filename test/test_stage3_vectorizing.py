#!/usr/bin/env python3
"""
================================================================================
Unit Tests for STAGE 3: Vectorization (Dense SecBERT + Sparse FastEmbed BM25)
================================================================================
Tests verify:
  1. Dense SecBERT produces 768-dimensional normalized vectors.
  2. Sparse FastEmbed produces valid BM25 indices and positive weights.
  3. Integration with Stage 2 chunking pipeline (log_transformer.py).
  4. Exact preservation of forensic metadata and chunk IDs.
  5. Correct query vectorization behavior for Stage 5 Hybrid Search.
================================================================================
"""

import math
import os
import sys
import unittest
import pandas as pd

# Add parent directory to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from stage3_vectorizing import (
    SecBERTDenseEmbedder,
    BM25SparseEmbedder,
    ForensicChunkVectorizer,
    vectorize_stage2_chunks,
)
from log_transformer import preprocess_and_chunk_windows_logs


class TestStage3Vectorization(unittest.TestCase):
    """Test suite for Stage 3 Vectorization pipeline."""

    @classmethod
    def setUpClass(cls):
        """Initialize vectorizer once for efficiency across tests."""
        cls.vectorizer = ForensicChunkVectorizer(
            dense_model_name="jackaduma/SecBERT",
            sparse_model_name="Qdrant/bm25",
        )

    def test_01_dense_embedder_dimensions_and_norm(self):
        """Verify SecBERT produces 768-dim L2-normalized vectors."""
        embedder = self.vectorizer.dense_embedder
        text = "EventID 4625 failed logon for user guest with substatus 0xC000006A"
        dense_vec = embedder.embed_single(text)

        self.assertEqual(len(dense_vec), 768, "Dense vector must be 768 dimensions")
        # Check L2 norm is approximately 1.0 (normalized for cosine distance)
        l2_norm = math.sqrt(sum(x * x for x in dense_vec))
        self.assertAlmostEqual(l2_norm, 1.0, places=3, msg="Dense vector should be L2-normalized")

    def test_02_sparse_embedder_tokens(self):
        """Verify FastEmbed BM25 produces indices and positive weights."""
        embedder = self.vectorizer.sparse_embedder
        text = "EventID 4688 new process powershell.exe -NoP -NonI"
        indices, values = embedder.embed_single(text)

        self.assertIsInstance(indices, list)
        self.assertIsInstance(values, list)
        self.assertEqual(len(indices), len(values), "Indices and values count must match")
        self.assertGreater(len(indices), 0, "Sparse indices should not be empty")
        for val in values:
            self.assertGreater(val, 0.0, "BM25 values should be positive")

    def test_03_stage2_to_stage3_integration(self):
        """Verify end-to-end integration: Stage 2 chunks -> Stage 3 vectorization."""
        # 1. Create realistic mock Windows logs DataFrame
        mock_data = [
            {
                "TimeCreated": "2026-09-14T08:00:00Z",
                "EventID": 4624,
                "MachineName": "SEC-SRV-01",
                "Level": "Information",
                "TargetUserName": "SYSTEM",
                "Message": "An account was successfully logged on.",
            },
            {
                "TimeCreated": "2026-09-14T08:03:00Z",
                "EventID": 4625,
                "MachineName": "SEC-SRV-01",
                "Level": "Error",
                "TargetUserName": "admin",
                "Message": "An account failed to log on. Status=0xC000006D, SubStatus=0xC000006A",
            },
            {
                "TimeCreated": "2026-09-14T08:05:00Z",
                "EventID": 4688,
                "MachineName": "SEC-SRV-01",
                "Level": "Information",
                "TargetUserName": "admin",
                "Message": "New process created: cmd.exe /c whoami",
            },
        ]
        df = pd.DataFrame(mock_data)

        # 2. Generate Stage 2 chunks
        stage2_chunks = preprocess_and_chunk_windows_logs(
            df,
            window_duration_minutes=10,
            window_overlap_minutes=2,
            max_tokens_per_chunk=512,
        )
        self.assertGreater(len(stage2_chunks), 0, "Stage 2 should yield at least one chunk")

        # 3. Vectorize via Stage 3
        enriched_chunks = self.vectorizer.vectorize_chunks(stage2_chunks, dense_batch_size=2)
        self.assertEqual(len(enriched_chunks), len(stage2_chunks))

        for chk in enriched_chunks:
            # Check required keys
            self.assertIn("chunk_id", chk)
            self.assertIn("text", chk)
            self.assertIn("dense_vector", chk)
            self.assertIn("sparse_indices", chk)
            self.assertIn("sparse_values", chk)
            self.assertIn("metadata", chk)

            # Check vector properties
            self.assertEqual(len(chk["dense_vector"]), 768)
            self.assertEqual(len(chk["sparse_indices"]), len(chk["sparse_values"]))
            self.assertGreater(len(chk["sparse_indices"]), 0)

            # Check metadata preservation
            meta = chk["metadata"]
            self.assertIn("start_time", meta)
            self.assertIn("end_time", meta)
            self.assertIn("host", meta)
            self.assertIn("event_ids", meta)

    def test_04_query_vectorization(self):
        """Verify single query vectorization generates both vector formats."""
        query = "Show failed logons with status 0xC000006A"
        q_vec = self.vectorizer.vectorize_query(query)

        self.assertEqual(q_vec["text"], query)
        self.assertEqual(len(q_vec["dense_vector"]), 768)
        self.assertIsInstance(q_vec["sparse_indices"], list)
        self.assertIsInstance(q_vec["sparse_values"], list)
        self.assertGreater(len(q_vec["sparse_indices"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
