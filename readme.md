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
│   ├── bluebox_dashboard.py
│   ├── traffic_simulator.py
│   └── attack_scenarios/                    # Normal and attack traffic scenarios
├── docs_md/                          # Reference markdown docs
│   ├── architecture.md
|   ├── compliance.md
│   ├── protocols.md
│   └── regulations.md
└── data/                             # Synthetic traffic for testing
    ├── raw/ 
```

## Directory Use

- `crypto_layer/`: hash chaining, signing, and integrity checks
- `backend/`: anomaly explanation and natural-language advisories complying with EU Part-IS
- `UI_layer/`: dashboard and replay views
- `demo/`: runnable demo logic and attack scenarios
- `docs_md/`: supporting technical and regulatory notes
- `data/`: sythentic raw network log data inputs by domain
