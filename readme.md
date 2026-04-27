# BlueBox

AI Assisted Tamper-Proof Flight Recorder for Connected Aircrafts

## Directory Map

```text
BlueBox/
├── crypto_layer/                     # Cryptographic integrity and tamper-proof logging
├── explainability_layer/             # Anomaly flagging and explainable AI outputs and advisories
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
├── input_traffic/                    # Synthetic traffic inputs
│   ├── avionics/
│   ├── cabin/
│   └── maintenance/
└── bluebox-env/                      # Local Python virtual environment
```

## Directory Use

- `crypto_layer/`: hash chaining, signing, and integrity checks
- `explainability_layer/`: anomaly explanation and natural-language advisories complying with EU Part-IS
- `UI_layer/`: dashboard and replay views
- `demo/`: runnable demo logic and attack scenarios
- `docs_md/`: supporting technical and regulatory notes
- `input_traffic/`: training, testing, and replay inputs by domain
- `bluebox-env/`: local development environment
