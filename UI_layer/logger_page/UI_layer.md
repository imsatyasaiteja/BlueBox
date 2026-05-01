# Logger Page

This page is a local dashboard for testing the BlueBox logger layer.

Run it with:

```powershell
.\bluebox-env\Scripts\python.exe .\logger_layer\api_server.py --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

## What It Tests

- Append a JSON event into the encrypted hash chain.
- Ingest CSV/PCAP files from a path.
- Generate demo traffic and ingest it.
- Verify hashes, RSA signatures, encrypted payload authentication, and anchors.
- Simulate blocked SQLite delete/update attempts.
- Inspect decrypted payloads for selected entries.

## Tamper Attempt Buttons

`Attempt Delete` and `Attempt Update` run direct SQLite operations against `log_entries`.
The append-only triggers should reject the operation. When rejected, the logger appends
a signed `SECURITY_EVENT` entry to the same hash chain.

If verification fails because the DB was modified out of band, preserve the database
and anchor file as evidence. Do not append recovery records to a chain that is already
untrusted.

## Related Docs

See:

```text
logger_layer/logger_layer.md
```
