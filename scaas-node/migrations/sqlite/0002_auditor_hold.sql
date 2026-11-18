-- Node store v3 (set-auditor closing review C2b, store.md §4): a bit-32 confirm the node requeued as AUDITOR_NOT_READY is
-- held here, by chain and job id, with the proposal it was held for (token, pending, proposer; byte-exact BLOBs). Read
-- before every resend; kept across restarts and every requeue; deleted only at the job's final verdict.
CREATE TABLE auditor_hold (chain_key TEXT NOT NULL, job_id INTEGER NOT NULL, token BLOB NOT NULL, pending BLOB NOT NULL,
  proposer BLOB NOT NULL, held_at INTEGER NOT NULL, PRIMARY KEY (chain_key, job_id)) STRICT;
UPDATE meta SET value = '3' WHERE name = 'schema_version';
