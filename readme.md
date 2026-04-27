# BlueBox

AI Assisted Tamper-Proof Flight Recorder for Connected Aircrafts

## Directory Map

```text
BlueBox/
├── backend/                          # Anomaly flagging and explainable AI outputs and advisories
├── crypto_layer/                     # Cryptographic integrity and tamper-proof logging
├── UI_layer/                         # Frontend dashboard and visual interface
├── demo/                             # Demo scripts and scenarios
│   ├── demo.md
│   ├── live_dashboard.py
│   ├── traffic_generator.py
│   └── scenarios/                    # Normal and attack traffic scenarios
├── docs_md/                          # Reference markdown docs
│   ├── architecture.md
|   ├── compliance.md
│   ├── protocols.md
│   └── regulations.md
├── data/                             # Synthetic traffic
│   ├── raw/
└── 
```

## Directory Use

- `crypto_layer/`: hash chaining, signing, and integrity checks
- `backend/`: anomaly explanation and natural-language advisories complying with EU Part-IS
- `UI_layer/`: dashboard and replay views
- `demo/`: runnable demo logic and attack scenarios
- `docs_md/`: supporting technical and regulatory notes
- `data/`: training, testing, and replay inputs by domain
- `bluebox-env/`: local development environment
