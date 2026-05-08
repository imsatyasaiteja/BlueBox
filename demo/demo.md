# BlueBox Demo Folder

This folder generates synthetic traffic for the combined BlueBox demo: AI anomaly
detection first, then tamper-evident logger ingestion.

## Keep

```text
demo/
|-- traffic_simulator.py      # Generates CSV/PCAP demo traffic and optional AI scores
|-- demo.md                   # This note
`-- attack_scenarios/         # YAML scenario inputs
```

## Usage

Generate a short traffic sample:

```powershell
.\bluebox-env\Scripts\python.exe .\demo\traffic_simulator.py --scenario normal --duration 3 --output-dir .\runtime\evidence\demo_output\normal --test
```

Generate an attack sample:

```powershell
.\bluebox-env\Scripts\python.exe .\demo\traffic_simulator.py --scenario lateral_movement --duration 3 --output-dir .\runtime\evidence\demo_output\lateral_movement --test
```

The generated files are runtime artifacts under `runtime/evidence/demo_output/` and are ignored by git. Each PCAP domain writes a `.pcap`, a readable event CSV, and a backend-style `_labels.csv`; `--test` also writes model `_scores.csv` files.

For the combined AI + logger showcase, use the web dashboard:

```powershell
.\bluebox-env\Scripts\python.exe .\logger_layer\api_server.py --host 127.0.0.1 --port 8080
```

Then open:

```text
http://127.0.0.1:8080
```

The dashboard's `Generate + Ingest` action generates scenario traffic, scores the generated event CSVs with `backend.detection.anomaly_model.score_event()`, writes score CSVs, and appends a signed demo manifest to the hash-chain logger. The manifest records the AI metrics and artifact paths without slowing the live demo by logging every packet row.
