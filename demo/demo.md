# BlueBox Demo

We're showcasing a **forensic investigation tool** that proves BlueBox is fundamentally different from existing aviation security tools.

### What Makes This Different?

| Tool Type | What It Does | Problem |
|-----------|------------|---------|
| Traditional Anomaly Detection (existing) | Detects attacks, sends alerts | Evidence can be deleted by attackers |
| **BlueBox** | **Detects attacks + proves deletion/ modification impossible** | **Evidence survives even system-level access** |

---

## Demo

### **Phase 1: Green Dashboard - Everything Normal**
```
What we do:
- Start live monitoring dashboard
- Send baseline network traffic (cabin, maintenance, avionics all operating normally)

What judges see:
- Green background
- Events flowing in real-time
- Live hash chain status: INTEGRITY VERIFIED
- No anomalies

Your line:
"Every event is cryptographically signed and linked into an immutable chain."
```

---

### **Phase 2: Red Dashboard - Attack Detected**
```
What we do:
- Inject lateral_movement attack scenario (attacker moving from maintenance to avionics)

What judges see:
- Dashboard turns
- Alert: "LATERAL MOVEMENT DETECTED - 94% Confidence"
- Timestamp: exact moment of breach
- Attacker IP source/destination visible
- Hash chain still intact (all events logged)

Your line:
"The system detected a lateral movement attack in real-time."

Then you ask the AI chatbot:
"What just happened? Which Part-IS regulations were violated?"

AI Chatbot explains:
- Description of the lateral movement
- EU Part-IS Article 4 violation (security vulnerability not contained)
- Immediate mitigation steps (isolate systems, capture evidence)
- Why this is critical (access to flight-critical systems)
```

---

### **Phase 3: Multiple Attacks - System Overwhelmed?**
```
What we do:
- Inject injection_attack scenario (while lateral movement still happening)
- Show the system handling multiple attack vectors simultaneously

What judges see:
- Dashboard shows TWO anomalies now:
  LATERAL MOVEMENT (94%)
  INJECTION ATTACK (87%)
- System doesn't break, it categorizes both attacks
- Timestamps show coordinated nature

Your line:
"Not just one attack, coordinated multi-vector attack detected."

Then you ask the AI:
"Is this a sophisticated threat? What does Part-IS say about coordinated attacks?"

AI explains:
- This is an Advanced Persistent Threat (APT)
- Multiple Part-IS violations
- Regulatory consequences (potential aircraft grounding)
- Timeline for EASA notification (24 hours)
```

---

### **Phase 4: Attacker Tries to Cover Tracks - INSTANT DETECTION**
```
What we do:
- YOU manually delete the log file (in front of judges)
- delete demo/logs/bluebox_chain.log

What judges see (IMMEDIATELY):
- Dashboard flashes: CRITICAL RED
- Giant alert: "FORENSIC INTEGRITY VIOLATION"
- Message: "Tampering detected in hash chain <100ms after deletion"
- Shows: "Evidence Status: COMPROMISED BUT DETECTED"
- Recovery: Backup hash chain available

THIS IS THE MONEY SHOT - Judges realize:
"Wait... even though someone deleted the log, the system CAUGHT IT."
"No other tool does this."
"This is the actual innovation."

Your line:
"The attacker just tried to erase all evidence. But BlueBox detected the tampering 
in less than 100 milliseconds. Even system-level access can't hide crimes."

Then you ask the AI:
"What does evidence tampering mean legally and for Part-IS compliance?"

AI explains:
- Evidence tampering = additional crime (obstruction of justice)
- Demonstrates intent to conceal (not accidental)
- Automatic law enforcement referral
- Part-IS investigation status updated
- All events (including tampering attempt) now logged as evidence
```

---

### **Phase 5: Generate Forensic Report**
```
What we do:
- Run: python demo/generate_forensic_report.py --incident-id latest

What judges see:
- PDF file generated: forensic_report_20260428_incident_001.pdf
- Report shows:
  • Executive summary
  • Timeline of all events (attacks + tampering)
  • Network diagrams showing attack path
  • Forensic evidence (cryptographically signed)
  • Part-IS compliance checklist
  • Regulatory recommendations
  • Digital chain of custody verified ✓

Your line:
"This is the evidence report that maintenance engineers hand to safety investigators 
and regulators. It's forensically sound, tamper-proof, and automatically generated.
This is why EU Part-IS requires tools like BlueBox."

Final statement:
"BlueBox solves a critical gap in aviation cybersecurity: forensic evidence that 
survives attacker attempts at concealment. This changes how airlines investigate 
cyberattacks and how regulators enforce safety."
```

---

## Why This Demo Is Brilliant

**Shows 3 core innovations simultaneously:**
1. Real-time anomaly detection (AI capability)
2. Tamper-proof evidence preservation (cryptography)
3. Explainable forensics + regulatory compliance (XAI + Part-IS)

**Tells a complete story:**
- Normal => Attacked => Covered Up => Recovered
- Judges see progression, not disconnected features

**Ends with regulatory proof:**
- Downloadable report
- Part-IS compliance statements
- Automatic mitigation recommendations

**Competitive advantage:**
- Existing tools: detect attacks, but evidence deletable
- BlueBox: detects attacks + proves deletion impossible

---

## Demo Script

**"BlueBox is a forensic flight recorder for aviation cybersecurity.**

**Unlike traditional security tools that just detect attacks, BlueBox proves that attackers can't hide crimes. Even if they delete evidence, BlueBox detects the tampering in <100ms.**

**In our demo, we show:**
1. **Normal operations** (everything green)
2. **AI detects lateral movement attack** (94% confidence)
3. **Multi-vector attack** (injection attack detected simultaneously)
4. **Attacker deletes logs to cover tracks** (CAUGHT in 100ms)
5. **Generate forensic report** (PDF suitable for regulators)

**This is why EU Part-IS regulations will require tools like BlueBox. Airlines can't investigate cyberattacks without forensic evidence. BlueBox makes evidence deletion impossible.**

**It's a completely different category from existing security tools.**"

---

## Technical Components You'll Build

| Component | Purpose |
|-----------|---------|
| `hash_chain.py` | Cryptographic logging (SHA256 + HMAC) |
| `live_monitor.py` | Real-time dashboard (green/red status) |
| `traffic_generator.py` | Inject attack scenarios (baseline, lateral_movement, injection, replay) |
| `chatbot_integration.py` | AI explains what happened + Part-IS implications |
| `forensic_report_generator.py` | Generate PDF with evidence + recommendations |
| `scenarios/` | Config files for each attack (normal.yaml, lateral_movement.yaml, etc.) |

---

## Demo Checklist (Before Presentation)

- [ ] Both terminals work together (monitor + generator)
- [ ] Hash chain file location confirmed (demo/logs/bluebox_chain.log)
- [ ] File deletion commands work on your OS
- [ ] Timing test: run demo end-to-end 5 times, verify exactly 2 minutes
- [ ] AI chatbot responses ready (rules-based or LLM integrated)
- [ ] PDF report generation tested
- [ ] Backup video recorded (as insurance)

---

## Questions You'll Get Ready For

**Q:** "What if the attacker deletes the machine?"
**A:** "We store evidence on external servers too (timestamp authority). Physical destruction leaves traces. Plus, we're monitoring the network-destruction of one machine doesn't silence the network."

**Q:** "Isn't this just a file backup system?"
**A:** "No. We're detecting attacks in real-time (94% confidence), proving tampering in <100ms, and generating regulatory evidence. Backup systems don't detect attacks or explain Part-IS violations."

**Q:** "Will EASA require this?"
**A:** "EU Part-IS already legally requires cybersecurity incident investigation. BlueBox makes that investigation possible. Regulators will likely mandate forensic-grade logging within 2-3 years."

**Q:** "How much would airlines pay for this?"
**A:** "Major airlines spend $2-5M annually on cybersecurity. BlueBox solves the hardest problem: forensic evidence. Conservative estimate: $50k-200k per deployment, or licensing model."

---

## Your Pitch (One Paragraph)

**"BlueBox is an AI-powered flight recorder for cybersecurity. Unlike traditional security tools that just detect attacks, BlueBox ensures attackers can't hide crimes. Every network event is cryptographically signed. Even if an attacker gains system-level access and deletes evidence, BlueBox detects the tampering in less than 100 milliseconds. Our demo shows this: normal operations, detection of lateral movement + injection attack, and then while the dashboard is live we delete the log file and it instantly shows CRITICAL ALERT. This is why EU Part-IS regulations will require tools like BlueBox: forensic evidence that survives attacker attempts at concealment. It changes how airlines investigate cybersecurity incidents."**

---

*Document created: April 28, 2026*  
