# BlueBox

AI Assisted Tamper-Proof Flight Recorder for Connected Aircrafts

## Directory Map

```text
BlueBox/
├── backend/                          # Anomaly flagging and explainable AI outputs and advisories
├── logger_layer/                     # Cryptographic integrity and tamper-proof logging
├── UI_layer/                         # Frontend dashboard and visual interface
├── data/ 
|   ├── explanations/
│   ├── normalized/
│   └── raw/                          # Synthetic traffic for testing
├── demo/                             # Demo scripts and scenarios
│   ├── demo.md
│   ├── traffic_simulator.py
│   └── attack_scenarios/*yaml        # Normal and attack traffic scenarios
├── docs_md/                          # Reference markdown docs
│   ├── architecture.md
|   ├── compliance.md
│   ├── protocols.md
|   ├── regulations.md
│   └── schema.md
└── models/    
```                         

## Directory Use

- `logger_layer/`: hash chaining, signing, encrypted SQLite logging, and the logger demo API
- `backend/`: anomaly explanation and natural-language advisories complying with EU Part-IS
- `UI_layer/`: local logger dashboard
- `demo/`: synthetic traffic generator and attack scenarios
- `docs_md/`: supporting technical and regulatory notes
- `data/`: synthetic raw network log data inputs by domain
