#!/usr/bin/env python3
"""blockscout-code-backfill.py <rpc>: one-off for Blockscout on the pruned 7622 node: the ContractCode fetcher asks eth_getCode at the creation block,
which a pruned node no longer has ("No state available"), and retries forever. Contract code is immutable here
(no SELFDESTRUCT after EIP-6780 outside the creation tx), so take it at latest and mark the rows done."""
import json, subprocess, sys, urllib.request
RPC = sys.argv[1]
def psql(q):
    return subprocess.run(["docker", "exec", "-i", "mba_explorer_db", "psql", "-U", "postgres", "-d", "blockscout", "-tA", "-v", "ON_ERROR_STOP=1"],
                          input=q, capture_output=True, text=True, check=True).stdout
rows = [l for l in psql("select encode(created_contract_address_hash,'hex') from transactions where created_contract_address_hash is not null and created_contract_code_indexed_at is null;").split() if l]
sql = ["begin;"]
for a in rows:
    r = json.loads(urllib.request.urlopen(urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": ["0x" + a, "latest"]}).encode(), {"content-type": "application/json"})).read())
    code = r["result"][2:]
    sql.append(f"insert into addresses (hash, contract_code, inserted_at, updated_at) values (decode('{a}','hex'), decode('{code}','hex'), now(), now()) "
               f"on conflict (hash) do update set contract_code = excluded.contract_code, updated_at = now();")
    print(a, len(code) // 2, "B")
sql.append("update transactions set created_contract_code_indexed_at = now() where created_contract_address_hash is not null and created_contract_code_indexed_at is null;")
sql.append("commit;")
print(psql("\n".join(sql)).strip().replace("\n", " "))
