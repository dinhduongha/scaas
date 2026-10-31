#!/usr/bin/env python3
"""blockscout-code-backfill.py <rpc> | --prune-coin-balances <rpc> <backup.csv> | --self-test: one-off for Blockscout on the pruned 7622 node: the ContractCode fetcher asks eth_getCode at the creation block,
which a pruned node no longer has ("No state available"), and retries forever. Contract code is immutable here
(no SELFDESTRUCT after EIP-6780 outside the creation tx), so take it at latest and mark the rows done.
Only the transactions selected by this run are marked; empty code (failed creation, or a create that self-destructed
in its own transaction) leaves addresses.contract_code NULL. The RPC code is checked to be 0x-hex before it reaches SQL.
--prune-coin-balances: the coin-balance catch-up fetcher retries forever the balances recorded at blocks the pruned node
no longer serves; delete the unfetched address_coin_balances rows (value_fetched_at IS NULL, the 9.0.2
unfetched_balances index) more than PRUNE_WINDOW blocks behind the node's tip, after a CSV backup of exactly those rows.
Restart explorer-backend afterwards (the fetcher keeps its queue in memory)."""
import json, re, subprocess, sys, urllib.request

HEX = re.compile(r"[0-9a-f]*")
PRUNE_WINDOW = 64  # Nethermind keeps about the last 64-128 states (Pruning.Mode Hybrid); older ones: "No state available"
PRUNE_WHERE = "value_fetched_at is null and block_number < :cutoff"

def prune_sql():
    """(backup, delete) psql scripts; values come in as psql variables -v cutoff=<int> -v expected=<int>."""
    backup = f"copy (select * from address_coin_balances where {PRUNE_WHERE} order by block_number, address_hash) to stdout with (format csv, header);"
    delete = (f"begin;\nwith d as (delete from address_coin_balances where {PRUNE_WHERE} returning 1) "
              "select count(*) as n, count(*) = :expected as ok from d \\gset\n"
              "\\if :ok\ncommit;\n\\echo deleted :n\n\\else\nrollback;\n\\echo rolled back: :n rows matched, backup has :expected\n\\endif\n")
    return backup, delete

def build_sql(rows):
    """rows: [(tx_hash_hex, address_hex, code_hex)] without 0x, lower case; returns one transaction."""
    for r in rows:
        if not all(HEX.fullmatch(x) for x in r):
            raise ValueError(f"not hex: {r!r}")
    sql = ["begin;"]
    for _, a, code in rows:
        if code:  # empty code: leave contract_code NULL, so Blockscout does not show a contract
            sql.append(f"insert into addresses (hash, contract_code, inserted_at, updated_at) values (decode('{a}','hex'), decode('{code}','hex'), now(), now()) "
                       f"on conflict (hash) do update set contract_code = excluded.contract_code, updated_at = now();")
    txs = ",".join(f"decode('{t}','hex')" for t, _, _ in rows)
    sql.append(f"update transactions set created_contract_code_indexed_at = now() where hash = any(array[{txs}]::bytea[]) and created_contract_code_indexed_at is null;")
    sql.append("commit;")
    return "\n".join(sql)

def self_test():
    s = build_sql([("aa", "0b", "6000"), ("cc", "0d", "")])
    assert "decode('6000','hex')" in s and "decode('0d'" not in s, s           # empty code: no upsert
    assert "hash = any(array[decode('aa','hex'),decode('cc','hex')]::bytea[])" in s, s  # only this run's rows
    for bad in [("aa", "0b", "60');drop table x;--"), ("aa", "0b", "0x60")]:
        try: build_sql([bad]); raise AssertionError(bad)
        except ValueError: pass
    b, d = prune_sql()
    assert "value_fetched_at is null and block_number < :cutoff" in b and b.startswith("copy (select"), b
    assert d.count(PRUNE_WHERE) == 1 and "\\if :ok\ncommit;" in d and "rollback;" in d, d
    print("self-test ok")

def psql(q, *var):
    return subprocess.run(["docker", "exec", "-i", "mba_explorer_db", "psql", "-U", "postgres", "-d", "blockscout", "-tA", "-v", "ON_ERROR_STOP=1",
                           *(a for v in var for a in ("-v", v))], input=q, capture_output=True, text=True, check=True).stdout

def prune(rpc, backup_path):
    r = json.loads(urllib.request.urlopen(urllib.request.Request(rpc, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode(), {"content-type": "application/json"})).read())
    tip = int(r["result"], 16)
    cutoff = tip - PRUNE_WINDOW
    backup, delete = prune_sql()
    csv = psql(backup, f"cutoff={cutoff}")
    with open(backup_path, "x") as f:  # never overwrite an earlier backup
        f.write(csv)
    rows = max(len(csv.splitlines()) - 1, 0)
    print(f"tip {tip}, cutoff {cutoff}: {rows} unfetched rows backed up to {backup_path}")
    print(psql(delete, f"cutoff={cutoff}", f"expected={rows}").strip())

def main(rpc):
    sel = psql("select encode(hash,'hex') || ' ' || encode(created_contract_address_hash,'hex') from transactions "
               "where created_contract_address_hash is not null and created_contract_code_indexed_at is null;")
    rows = []
    for t, a in (l.split() for l in sel.splitlines() if l.strip()):
        r = json.loads(urllib.request.urlopen(urllib.request.Request(rpc, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": ["0x" + a, "latest"]}).encode(), {"content-type": "application/json"})).read())
        code = r["result"]
        if not re.fullmatch(r"0x[0-9a-fA-F]*", code):
            raise ValueError(f"eth_getCode 0x{a}: not 0x-hex: {code[:40]!r}")
        rows.append((t, a, code[2:].lower()))
        print(a, len(code[2:]) // 2, "B")
    if not rows:
        print("nothing to backfill"); return
    print(psql(build_sql(rows)).strip().replace("\n", " "))

if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]: self_test()
    elif sys.argv[1] == "--prune-coin-balances": prune(sys.argv[2], sys.argv[3])
    else: main(sys.argv[1])
