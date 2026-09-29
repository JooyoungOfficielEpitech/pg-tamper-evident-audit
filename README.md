# pg-tamper-evident-audit

A tamper-evident audit log in plain PostgreSQL. No extra services, no blockchain.

Regulated software has to prove who changed what, and when. That includes medical devices (GxP / ALCOA+), finance, and anything under GDPR Art. 32. It also has to prove that **nobody quietly rewrote that history afterwards**. This repo shows the pattern I use in production, reduced to ~150 lines of SQL.

```
 app role ──EXECUTE──▶ audit.append() ──advisory lock──▶ audit.event (append-only)
                              │                              │
                              └─ hash = sha256(prev_hash ‖ canonical(row))
                                                             │
 anyone ─────────────────────────────────────▶ audit.verify() ── first broken link / modified row
```

## Four layers

| Layer | What it stops | How |
|---|---|---|
| **Least privilege** | the application editing history | App role has only `SELECT` + `EXECUTE audit.append()`. No `INSERT/UPDATE/DELETE` on the table. |
| **WORM triggers** | owners and migrations mutating rows | `BEFORE UPDATE/DELETE/TRUNCATE` triggers always raise. |
| **SHA-256 hash chain** | a superuser disabling triggers and editing rows | Each row hashes its canonical content plus the previous row's hash. Any edit, deletion or reorder breaks the chain. |
| **Serialized appends** | concurrent writers forking the chain | `pg_advisory_xact_lock` inside `append()`. Ids and chain order are gap-free under concurrency. |

Changes to business tables are captured by an `AFTER` row trigger (`audit.capture()`). It records the actor (`SET app.actor = '…'`), the operation, and before/after state as `jsonb`.

## Run the demo

Requires Docker.

```bash
./scripts/demo.sh
```

```
✔ schema installed
✔ 400 audit events written by 8 concurrent sessions
✔ verify() after concurrent writes: chain intact
✔ app role: DELETE on audit.event rejected
✔ owner: UPDATE on audit.event blocked by WORM trigger
✔ superuser silently edited row 42 -> verify(): 42 / content does not match its hash (row modified)
```

## Design notes

- **Why hash `jsonb::text`?** `jsonb` stores keys in a normalised order, so the canonical text is stable across reads and dumps. Timestamps are hashed in UTC with microseconds so time-zone settings cannot change the hash.
- **Why an advisory lock instead of `SERIALIZABLE`?** Appends are tiny, and one global lock gives a strict total order that is cheap to reason about. For very high write rates, shard the chain (e.g. one chain per tenant or per day) and anchor each shard.
- **Why `SECURITY DEFINER`?** The app can write audit rows only through `append()`. That function computes the hash itself, so callers cannot forge `prev_hash` / `hash`.

## Limits (what this does *not* do on its own)

- **A superuser can rebuild the whole chain from the edit onwards.** Tamper-*evidence* needs an anchor outside the database. Periodically export the latest hash to somewhere the DBA can't write: object storage with retention lock / WORM bucket, a signed timestamp, or a separate system. `verify()` then checks the chain up to the anchored hash.
- **This doesn't audit reads or DDL by itself.** Pair it with [pgAudit](https://www.pgaudit.org/) for database-level session logging, and ship those logs to the same retention-locked storage.
- **Coverage is only as good as the capture.** In the application, a startup guard that refuses to boot if any write path is unaudited keeps new endpoints from silently skipping the log.

## Files

- `sql/01_audit.sql`: table, `append()`, WORM triggers, `verify()`
- `sql/02_roles_and_capture.sql`: least-privilege role, example table with automatic change capture
- `scripts/demo.sh`: end-to-end demo against `postgres:17`

MIT License
