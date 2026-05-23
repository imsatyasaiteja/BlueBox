# BlueBox Security Policy

BlueBox is a private Airbus-focused project. Do not report security issues through public GitHub issues, public discussions, or external disclosure channels.

## Reporting a Security Issue

Report suspected vulnerabilities, leaked secrets, unsafe evidence handling, or tamper/recovery failures through the approved internal Airbus project security channel.

If you are unsure who owns the channel, contact the BlueBox project owner and mark the message as security-sensitive.

Include:

- short description of the issue;
- affected branch, commit, or release package;
- affected component, such as API server, logger, BB Chat, React UI, model pipeline, or demo scripts;
- reproduction steps;
- screenshots or logs only when they do not expose sensitive data;
- suggested severity and impact;
- whether runtime evidence, keys, generated reports, or uploaded RAG documents are affected.

## Do Not Disclose Publicly

Do not publish:

- source code excerpts;
- runtime evidence databases;
- recovery ledgers;
- AI evidence ledgers;
- private keys or generated local keys;
- uploaded regulation documents;
- BB Chat transcripts;
- vulnerability details;
- screenshots containing sensitive evidence or Airbus-specific data.

## Supported Scope

Security review should cover:

| Area | Examples |
|---|---|
| Logger trust | Hash chain, RSA signatures, anchors, recovery ledger, AI evidence ledger |
| Evidence storage | SQLite integrity, encryption, tamper detection, restore workflow |
| API server | Protected read gates, request validation, local network exposure |
| React dashboard | Evidence display, upload/delete flows, report export |
| BB Chat and RAG | Uploaded documents, prompts, transcripts, Ollama usage, fallback behavior |
| Demo scripts | Traffic generation, forced corruption commands, local runtime cleanup |
| Secrets | Local demo keys, environment files, ignored runtime artifacts |

## Handling Secrets and Evidence

- Keep runtime keys under `runtime/config/keys/`.
- Do not commit local keys, generated databases, uploaded documents, or evidence exports.
- Treat `runtime/evidence/` and `runtime/trust_boundary/` as sensitive demo outputs.
- Do not upload evidence, source code, or RAG documents to external AI tools.
- Use local Ollama for BB Chat when possible.
- Delete temporary RAG uploads from the dashboard when they are no longer needed.

## Local Network Assumption

The default demo server binds to:

```text
127.0.0.1:8080
```

Keep it on localhost unless an authorised security review approves a wider network binding. If exposing the dashboard beyond localhost, add authentication, TLS, access control, and logging first.

## Vulnerability Response

For confirmed issues:

1. Preserve enough evidence to reproduce the issue.
2. Stop external sharing of affected builds or demo packages.
3. Rotate any exposed keys or credentials.
4. Patch the issue in a private branch.
5. Re-run logger verification, recovery tests, BB Chat tests, and dashboard build checks.
6. Document the fix and residual risk for the project owner.

## Security Caveat

BlueBox is a demonstration and evaluation project. It is not certified aviation software and must not be used in operational aircraft environments without formal security, safety, legal, and certification review.
