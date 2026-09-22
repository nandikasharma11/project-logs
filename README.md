# Windows EVTX Forensic Analysis, RAG Pipeline & AI Assistant

> **Branch: `approach1`** — *Template-Deduplicated Semantic RAG with DuckDB, Qdrant & Qwen*

A high-performance, forensic-grade Windows Event Log (`.evtx`) processing, retrieval-augmented generation (RAG), and investigation platform. 

This branch implements the complete **Approach 1 Architecture**: an end-to-end multi-layer pipeline that solves the enterprise log volume problem (80–95% event redundancy) via **Drain3 template clustering**, **DuckDB evidentiary storage**, **1-vector-per-template Qdrant indexing**, **cross-channel entity correlation**, and **Qwen-powered cited reasoning**.

---

## Key Highlights of `approach1`

- **100% Evidentiary Integrity**: Raw forensic logs in DuckDB are strictly immutable and read-only (`COUNT(template_instances) == COUNT(canonical_logs)`). No log record is ever dropped or silently sampled.
- **Up to 99.9% Vector Store Efficiency**: Instead of embedding 50,000 identical logon failure events, Approach 1 generates **1 vector per template cluster**, drastically slashing embedding time, Qdrant storage, and token costs.
- **Cross-Channel Entity Correlation**: Automatically traces pivot entities (Logon IDs, SIDs, Process IDs, IP addresses, Computer names) across `Security`, `System`, `Application`, and `Sysmon` channels with time-proximity weighting and PID reuse safeguards.
- **Auditable & Cited AI Reasoning**: The forensic assistant synthesizes investigative conclusions with strict event record citations (`[EventRecordID #...]`) and logs every query and intermediate result to a DuckDB audit trail (`pipeline_audit_log`).
- **Interactive High-Contrast Dashboard**: Built with Streamlit, featuring a high-contrast forensic data grid, inline "EVENT DATA" drawers with raw JSON/XML inspection, real-time EVTX conversion, timeline analytics, and an integrated AI Forensic Chat Assistant.

---

## Architecture & Pipeline Layers

The `approach1` architecture is structured into modular, decoupled layers:

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                           RAW WINDOWS EVTX FILES                              │
└──────────────────────────────────────┬────────────────────────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ STAGE 1: INGESTION & CONVERSION (fileconversion.py)                           │
│  • Dual engine: Rust evtx_dump (ultra-fast) + python-evtx fallback            │
│  • 23-column normalized forensic schema + JSON extraction                     │
│  • Streaming export: CSV, JSON, JSONL, XML (zero pipe buffer deadlock)        │
└──────────────────────────────────────┬────────────────────────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ STAGE 2: CONTEXTUAL TRANSFORMATION & CHUNKING (log_transformer.py)            │
│  • Causal chronological sliding window (10-min window, 2-min overlap)         │
│  • Clock-skew tolerance buffer (±5s) & deterministic RFC 4122 UUIDv5 IDs      │
│  • Dual-representation chunks: semantic text narrative + filterable metadata  │
└──────────────────────────────────────┬────────────────────────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ TEMPLATING & DEDUPLICATION LAYER (log_templater.py, drain3.ini)               │
│  • Drain3 streaming parse tree clustering with regex parameter masking        │
│  • Derived DuckDB tables: log_templates & template_instances                  │
│  • 100% evidentiary mapping back to raw records; event family taxonomy        │
└──────────────────┬────────────────────────────────────────┬───────────────────┘
                   │                                        │
                   ▼                                        ▼
┌──────────────────────────────────────┐ ┌──────────────────────────────────────┐
│ STAGE 3: VECTOR INDEXING             │ │ CROSS-CHANNEL CORRELATION INDEXER    │
│ (stage3_vectorizing.py)              │ │ (correlation_indexer.py)             │
│  • 1 vector per unique template      │ │  • Graph linking across channels     │
│  • Qdrant dense/sparse collection    │ │  • Pivot on LogonID, SID, PID, IP    │
│  • Metadata payload pre-filtering    │ │  • Confidence weights & time windows │
└──────────────────┬───────────────────┘ └──────────────────┬───────────────────┘
                   │                                        │
                   └───────────────────┬────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ QUERY PARSING & FILTER RESOLUTION (query_parser.py)                           │
│  • Zero-false-narrowing natural language query parsing                        │
│  • Entity extraction (User, Host, PID, IP) + ISO 8601 UTC time bounding       │
│  • Routing intent resolution (search, correlation, summary, count)            │
└──────────────────────────────────────┬────────────────────────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ HYBRID FILTER EXECUTION (query_executor.py)                                   │
│  • DuckDB SQL execution on indexed metadata columns                           │
│  • Native JSON extraction (json_extract_string) on event_data payloads        │
│  • Single-pass intersection of vector candidate IDs and SQL criteria          │
└──────────────────────────────────────┬────────────────────────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ FORENSIC RETRIEVAL PIPELINE & LLM (retrieval_pipeline.py)                     │
│  • Chronological batching with schema headers & aggregate summaries           │
│  • Qwen / local / API LLM backend with strict forensic citation enforcement   │
│  • Full reproducibility audit logging into DuckDB pipeline_audit_log          │
└──────────────────────────────────────┬────────────────────────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ STREAMLIT FORENSIC WEB DASHBOARD & ASSISTANT (app.py)                         │
│  • EVTX converter GUI + high-contrast forensic table view                     │
│  • Inline event data drawer (raw JSON & XML viewer)                           │
│  • Gemini/Qwen-style Forensic Chat Assistant with citations and causal graphs  │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Branch File Contents & Module Breakdown

| File | Role & Functionality |
| :--- | :--- |
| **`fileconversion.py`** | **Stage 1 Core Converter**: High-throughput EVTX extraction using dual engines (native Rust `evtx_dump` with multiline JSON streaming or pure-Python `python-evtx` fallback). Normalizes 23 forensic columns (RecordID, TimeCreated, EventID, Channel, Provider, UserID/SID, ProcessID, EventData, UserData, Message). Supports recursive directory conversions and exports to CSV, JSON, JSONL, and XML. |
| **`log_transformer.py`** | **Stage 2 Contextual Transformer**: Normalizes headers, handles null-safe semantic serialization, and groups logs into chronological sliding sessions (10-minute window, 2-minute overlap, ±5s clock-skew tolerance). Generates RFC 4122 UUIDv5 deterministic chunk IDs and dual representations (semantic narrative text + structured metadata). |
| **`log_templater.py`** | **Drain3 Deduplication Layer**: Implements online parse-tree clustering of high-frequency repetitive events. Creates derived DuckDB tables (`log_templates` and `template_instances`), extracts runtime variable mappings, assigns event family taxonomy (Authentication, Process, Network, Policy), and enforces 100% evidentiary traceability without data loss. |
| **`drain3.ini`** | **Drain3 Configuration**: Tuned clustering parameters (similarity threshold `0.4`, depth `4`, max clusters `10000`) and regex masking rules for IP addresses, hex codes, SIDs, GUIDs, file paths, and timestamps. |
| **`stage3_vectorizing.py`** | **Stage 3 Vector Indexing**: Bridges DuckDB templates with Qdrant. Implements a **1-vector-per-template** strategy using Transformer/SecBERT dense embeddings. Supports metadata payload pre-filtering, incremental template indexing, and maintains a cryptographic audit trail. |
| **`query_parser.py`** | **Query Parsing Layer**: Parses natural language investigative prompts into structured `QueryFilter` objects. Resolves fuzzy relative time expressions ("yesterday", "last week", "around 3pm") to absolute ISO 8601 UTC intervals and extracts entities (User, PID, IP, Host) with zero false-narrowing. |
| **`query_executor.py`** | **Hybrid Query Execution Engine**: Executes structured queries against DuckDB canonical logs. Combines indexed column filtering with native DuckDB JSON queries (`json_extract_string` on `event_data`) and intersects vector search candidate IDs in a single SQL pass. |
| **`correlation_indexer.py`** | **Cross-Channel Entity Correlation**: Builds an idempotent correlation index in DuckDB connecting events across `Security`, `System`, `Application`, and `Sysmon`. Supports confidence-weighted traversal on Logon ID (1.0), Activity ID (1.0), User ID (0.8), IP (0.6), Process ID (0.3–1.0 with 5m temporal window), and Computer (0.1). |
| **`retrieval_pipeline.py`** | **End-to-End Orchestrator**: Coordinates parser, vector search, DuckDB execution, and cross-channel correlation. Formats chronological batches with schema headers and invokes Qwen (or swappable LLMs) with mandatory evidentiary citation enforcement (`[EventRecordID #...]`) and audit logging (`pipeline_audit_log`). |
| **`app.py`** | **Streamlit Forensic GUI**: Interactive web dashboard with custom high-contrast styling. Features real-time EVTX conversion, forensic log grid with sort/filter, inline event data drawer (raw JSON/XML), analytics charts, and the integrated AI Forensic Assistant. |
| **`test/`** | **Unit & Integration Test Suite**: 9 comprehensive test modules covering conversion, transformation, templating, vectorization, query parsing, execution, correlation, retrieval pipeline, and GUI integration. |

---

## Project Structure

```
.
├── README.md                        # Documentation for approach1
├── requirements.txt                 # Project dependencies
├── drain3.ini                       # Drain3 clustering and regex masking configuration
├── fileconversion.py                # Stage 1: EVTX parser and multi-format converter
├── log_transformer.py               # Stage 2: Contextual transformation and chunking
├── log_templater.py                 # Drain3 deduplication & DuckDB template manager
├── stage3_vectorizing.py            # Stage 3: Qdrant vector indexing layer
├── query_parser.py                  # Forensic query parser and time/entity resolver
├── query_executor.py                # DuckDB SQL and native JSON execution layer
├── correlation_indexer.py           # Cross-channel entity correlation indexer
├── retrieval_pipeline.py            # End-to-end RAG orchestrator with Qwen LLM
├── app.py                           # Streamlit Forensic Assistant & Log Viewer GUI
├── .streamlit/
│   └── config.toml                  # Streamlit high-contrast UI theme configuration
└── test/
    ├── test_fileconversion.py       # Tests for EVTX conversion engine
    ├── test_log_transformer.py      # Tests for Stage 2 chunking & serialization
    ├── test_log_templater.py        # Tests for Drain3 deduplication & DuckDB tables
    ├── test_stage3_vectorizing.py   # Tests for Qdrant template vectorization
    ├── test_query_parser.py         # Tests for natural language filter extraction
    ├── test_query_executor.py       # Tests for DuckDB SQL/JSON execution
    ├── test_correlation_indexer.py  # Tests for cross-channel entity correlation
    ├── test_retrieval_pipeline.py   # Tests for end-to-end RAG pipeline & LLM backend
    └── test_app_integration.py      # Tests for Streamlit GUI and state management
```

---

## Installation & Setup

### 1. Prerequisites
- Python 3.10+ (macOS, Linux, or Windows)
- *(Recommended)* Native `evtx_dump` binary for high-speed conversion:
  - **macOS**: `brew install evtx` or `cargo install evtx`
  - **Linux**: Download binary from [omerbenamram/evtx](https://github.com/omerbenamram/evtx)
  - **Windows**: Place `evtx_dump.exe` in system `PATH`

### 2. Environment Setup

```bash
# Clone the repository and switch to approach1 branch
git checkout approach1

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage Guide

### 1. Interactive Forensic Dashboard (Streamlit)

Launch the complete web interface:
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`:
- **Convert Logs**: Upload `.evtx` files or point to local directories.
- **Forensic Table**: View normalized records with fast sorting, filtering by Level, Channel, Event ID, Computer, or Keyword.
- **Inspect Event Data**: Click "EVENT DATA" to inspect parsed payload fields, view raw XML/JSON, or pivot to correlated cross-channel events.
- **AI Forensic Assistant**: Ask natural language investigative questions (e.g., *"Show failed logon attempts for Administrator between 2:00 PM and 4:00 PM and find correlated process activity"*). View answers with direct record citations, query execution audit logs, and causal entity graphs.

### 2. Command-Line EVTX Conversion (`fileconversion.py`)

Convert a single file:
```bash
python3 fileconversion.py -i /path/to/Security.evtx -o /path/to/Security.csv
```

Convert all logs in a directory to JSON:
```bash
python3 fileconversion.py -i /path/to/logs/ -o /path/to/output/ --format json
```

Force pure-Python fallback mode:
```bash
python3 fileconversion.py -i Security.evtx -o Security.csv --engine python
```

### 3. End-to-End Forensic RAG Pipeline CLI (`retrieval_pipeline.py`)

Run queries directly through the terminal against an indexed DuckDB database:
```bash
python3 retrieval_pipeline.py --db forensic_logs.duckdb --query "Find all lateral movement or remote desktop connections yesterday"
```

### 4. Running the Test Suite

Run all unit and integration tests:
```bash
PYTHONPATH=. pytest test/ -v
```

Run specific stage tests:
```bash
PYTHONPATH=. pytest test/test_log_templater.py test/test_query_parser.py -v
```

---

## License

This project is licensed under the MIT License.

