# Regulations

BlueBox uses EU Part-IS language as demo guidance for aviation cyber incident response. This page is not legal advice. It explains how the demo maps evidence to practical response steps.

## Why Part-IS Matters Here

EU Part-IS focuses on information security risks that can affect aviation safety and operations. BlueBox supports that workflow by preserving evidence, showing impact, and helping analysts prepare internal reporting and escalation.

## Common Demo Mapping

| BlueBox evidence | What it means | Part-IS aligned response |
|---|---|---|
| High-severity anomaly | Suspicious aircraft network or avionics behavior | Assess risk and operational impact |
| Cross-domain movement | A source appears to move across aircraft domains | Contain, investigate, and review access control |
| Command injection pattern | Traffic resembles unauthorized control behavior | Preserve evidence and isolate affected source |
| Replay behavior | Repeated or duplicated command pattern | Check system state and prevent repeated execution |
| DB mutation attempt | Attempt to alter evidence storage | Preserve tamper event and verify evidence integrity |
| Chain verification failure | Evidence trust is broken | Stop relying on protected views until restored |
| Recovery ledger restore | Trusted copy rebuilds the evidence DB | Record recovery action and verify post-restore trust |

## Response Clauses Used in BB Chat

BB Chat uses these clause labels as practical anchors:

| Clause | Demo meaning |
|---|---|
| `IS.I.OR.200` | Information security management expectations |
| `IS.I.OR.205` | Risk assessment and treatment |
| `IS.I.OR.210` | Risk treatment measures and controls |
| `IS.I.OR.215` | Internal reporting and evidence preservation |
| `IS.I.OR.230` | External notification or escalation when required |

## Simple Incident Response Flow

1. Identify the affected sequence, source, and target.
2. Preserve the signed evidence and AI explanation.
3. Verify the hash chain, recovery ledger, and AI evidence ledger.
4. Contain the source if it is unauthorized or unsafe.
5. Assess operational and safety impact.
6. Record internal findings under the local Part-IS process.
7. Escalate externally only if the organization process and severity require it.
8. Restore from recovery ledger if evidence trust was damaged.
9. Re-verify and export the report.

## BB Chat RAG Documents

Upload regulation PDFs or text files in:

```text
Forensic Replay -> RAG Knowledge Base
```

BB Chat will use:

- Uploaded text snippets when extractable.
- Stored document metadata when text extraction is unavailable.
- Built-in Part-IS response templates as fallback context.

## Good Demo Prompts

```text
Suggest incident response measures for sequence 356.
What Part-IS steps apply to a blocked DB mutation attempt?
What evidence should be preserved for internal reporting?
Does this attack path require escalation?
```
