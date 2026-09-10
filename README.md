# Windows EVTX to CSV Converter & Streamlit Log Viewer

A high-performance, unrestricted converter and interactive dashboard for Windows Event Log (`.evtx`) files.

---

## Key Features

- **Full Field Extraction (23 Columns)**:
  - Standard System Metadata: `RecordID`, `TimeCreated`, `EventID`, `Level`, `LevelName`, `Channel`, `Provider`, `ProviderGuid`, `EventSourceName`, `Task`, `Opcode`, `Keywords`, `Computer`, `UserID` (Security SID), `ProcessID`, `ThreadID`, `Version`, `ActivityID`, `RelatedActivityID`, `Qualifiers`.
  - Normalized Payload Data: Structured `EventData` and `UserData` JSON objects.
  - Message Text: Rendered event descriptions when available.
- **Zero Missing Entries & Sequential Ordering**:
  - Multiline JSON streaming avoids pipe buffer deadlock and unescaped newline drops.
  - Sorts by integer `RecordID` chronologically, resolving multithreaded chunk shuffling.
- **Unrestricted Source & Destination**:
  - Accepts single files, directories, glob patterns (`*.evtx`), or recursive directory walks.
  - Custom target directory or explicit output file names.
- **Dual-Engine Architecture**:
  - **Native Engine**: Ultra-fast processing via `evtx_dump` with streaming execution.
  - **Pure-Python Fallback**: `python-evtx` (`Evtx.Evtx`) engine requiring zero binary dependencies.
- **Interactive Streamlit Web Dashboard**:
  - Upload `.evtx` files or select local paths to convert in real time.
  - Inspect converted CSV files with search, filtering (by Level, Channel, Event ID), and JSON payload tree views.
  - Built-in analytics charts powered by Plotly (Event levels, top Event IDs, timeline activity).
- **Scalable Architecture**:
  - Stream-to-disk architecture capable of processing multi-gigabyte log files without exhausting memory.

---

## Project Structure

```
├── app.py                  # Streamlit web GUI application
├── fileconversion.py       # Core EVTX to CSV conversion engine & CLI
├── requirements.txt        # Python dependencies
├── .streamlit/
│   └── config.toml         # Theme configuration (custom blue palette)
├── .gitignore              # Git ignore rules for logs, binaries, and virtual environments
└── README.md               # Project documentation
```

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone <REPO_URL>
   cd <REPO_FOLDER>
   ```

2. **Set up a virtual environment (optional but recommended)**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. *(Optional)* **Install native `evtx_dump`** for maximum extraction speed:
   - On macOS: `brew install evtx` or compile via `cargo install evtx`
   - Linux: Download release binary from [omerbenamram/evtx](https://github.com/omerbenamram/evtx)
   - Windows: Place `evtx_dump.exe` in your system `PATH`

---

## Usage

### 1. Interactive Web Dashboard (Streamlit)

Launch the web GUI:
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`. From the dashboard, you can:
- Convert single or multiple EVTX files.
- Monitor real-time conversion progress and statistics.
- Switch between converted CSV files and filter log records.
- Inspect raw EventData and UserData JSON structures.

### 2. Command-Line Interface (CLI)

Convert a single file:
```bash
python3 fileconversion.py -i /path/to/Security.evtx -o /path/to/output.csv
```

Convert all `.evtx` files in a folder:
```bash
python3 fileconversion.py -i /path/to/logs/ -o /path/to/output_folder/
```

Force pure-Python fallback mode:
```bash
python3 fileconversion.py -i Security.evtx -o Security.csv --engine python
```

---

## License

This project is licensed under the MIT License.
