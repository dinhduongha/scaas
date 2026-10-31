#!/usr/bin/env python3
"""blockscout-code-backfill.py <rpc> | --self-test: one-off for Blockscout on the pruned 7622 node: the ContractCode fetcher asks eth_getCode at the creation block,
which a pruned node no longer has ("No state available"), and retries forever. Contract code is immutable here
(no SELFDESTRUCT after EIP-6780 outside the creation tx), so take it at latest and mark the rows done.
Only the transactions selected by this run are marked; empty code (failed creation, or a create that self-destructed
in its own transaction) leaves addresses.contract_code NULL. The RPC code is checked to be 0x-hex before it reaches SQL."""
import json, re, subprocess, sys, urllib.request

HEX = re.compile(r"[0-9a-f]*")

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
    print("self-test ok")

def psql(q):
    return subprocess.run(["docker", "exec", "-i", "mba_explorer_db", "psql", "-U", "postgres", "-d", "blockscout", "-tA", "-v", "ON_ERROR_STOP=1"],
                          input=q, capture_output=True, text=True, check=True).stdout

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
    self_test() if sys.argv[1:] == ["--self-test"] else main(sys.argv[1])
