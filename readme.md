# BlueBox

AI Assisted Tamper-Proof Flight Recorder for Connected Aircrafts

## Directory Map

```text
BlueBox/
|-- backend/                 # Ingestion, detection, explainability, and shared schema/path constants
|-- logger_layer/            # Cryptographic integrity logger source code
|-- UI_layer/                # Frontend dashboard and visual interface
|-- data/
|   |-- raw/                 # Immutable synthetic traffic inputs
|   `-- derived/             # Generated normalized, scored, and explanation outputs
|       |-- normalized/
|       |-- scored/
|       `-- explanations/
|-- demo/                    # Demo scripts and attack scenarios
|-- docs_md/                 # Reference markdown docs
|-- models/                  # Current model artifacts and stats
`-- runtime/
    |-- config/keys/         # Local development keys, ignored by git
    `-- evidence/            # SQLite stores, recovery ledgers, and demo output
```

## Directory Use

- `backend/`: parsing, normalization, anomaly detection, explanations, and shared constants.
- `logger_layer/`: hash chaining, signing, encrypted SQLite logging, and the logger demo API.
- `UI_layer/`: local logger dashboard.
- `demo/`: synthetic traffic generator and attack scenarios.
- `docs_md/`: supporting technical and regulatory notes.
- `data/raw/`: immutable source traffic samples.
- `data/derived/`: generated normalized CSVs, scored CSVs, and explanation JSON.
- `models/`: current per-domain PCAP model artifacts, ARINC model artifacts, and model stats.
- `runtime/`: operational state such as keys, SQLite evidence stores, recovery ledgers, and generated demo traffic.
