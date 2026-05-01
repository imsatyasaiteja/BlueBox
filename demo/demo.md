# BlueBox Demo Folder

This folder is only for generating synthetic traffic used by the crypto logger demo.

## Keep

```text
demo/
|-- traffic_simulator.py      # Generates CSV and PCAP demo traffic
|-- demo.md                   # This note
`-- attack_scenarios/         # YAML scenario inputs
```

## Usage

Generate a short traffic sample:

```powershell
.\bluebox-env\Scripts\python.exe .\demo\traffic_simulator.py --scenario normal --duration 3 --output-dir .\data\generated\normal
```

Generate an attack sample:

```powershell
.\bluebox-env\Scripts\python.exe .\demo\traffic_simulator.py --scenario lateral_movement --duration 3 --output-dir .\data\generated\lateral_movement
```

The generated files are runtime artifacts under `data/generated/` and are ignored by git.

For crypto-layer testing, prefer the web dashboard:

```powershell
.\bluebox-env\Scripts\python.exe .\logger_layer\api_server.py --host 127.0.0.1 --port 8080
```

Then open:

```text
http://127.0.0.1:8080
```
