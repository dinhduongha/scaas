# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-liquidity L2 (spec 2026-11-10-dex-liquidity.md §5): add `mtxLiquidityPull` to module T of every kind in
`entries.json`, and its event and errors to each face's ABI-only interface (`face_abi.json`), sorted as the generator
writes them. Idempotent. usage (from smartcontracts/evm): python3 script/modules/add_liquidity.py; then gen_faces.py."""
import json

ORDER = ('(bytes32,(address,uint256)[],(address,uint256)[],address,address,uint256,bytes32,int24,int24,uint128,bytes32,'
         'uint256,address,uint8,uint256,uint256,uint256)')
ROW = {"sel": "85fdfd38",
       "sig": f"mtxLiquidityPull({ORDER},(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]),uint256,address)",
       "name": "mtxLiquidityPull", "decl": "ERC20MetaTx", "kept": False, "mut": "nonpayable", "guard": "nonReentrant",
       "params": ["ITradeToken.LiquidityOrder calldata o", "IUARegistry.UASig calldata auth", "uint256 amount",
                  "address submitter"],
       "names": ["o", "auth", "amount", "submitter"], "returns": "", "ifaces": ["ILiquidityPullToken"], "vis": "external",
       "domain": "trade", "group": "T"}
B32 = lambda n: {"internalType": "bytes32", "name": n, "type": "bytes32"}  # noqa: E731
EVENT = {"anonymous": False, "inputs": [dict(B32("orderHash"), indexed=True), dict(B32("from"), indexed=True),
                                        {"indexed": True, "internalType": "address", "name": "dex", "type": "address"},
                                        {"indexed": False, "internalType": "uint256", "name": "amount", "type": "uint256"}],
         "name": "LiquidityPulled", "type": "event"}
ERRORS = [{"inputs": [{"internalType": "uint8", "name": "code", "type": "uint8"}], "name": "LiquidityShape", "type": "error"},
          {"inputs": [{"internalType": "address", "name": "caller", "type": "address"}], "name": "NotLiquidityDex",
           "type": "error"},
          {"inputs": [B32("orderHash")], "name": "ZeroFill", "type": "error"}]


def put(rows, row, key):
    if all(r[key] != row[key] for r in rows):
        rows.append(row)
        rows.sort(key=lambda r: r[key])


E = json.load(open('script/modules/entries.json'))
for k, rows in E['kinds'].items():
    put(rows, dict(ROW), 'name')
E['imports'].setdefault('ILiquidityPullToken', 'src/trade/ITradeToken.sol')
E['imports'] = dict(sorted(E['imports'].items()))
open('script/modules/entries.json', 'w').write(json.dumps(E, indent=1))
A = json.load(open('script/modules/face_abi.json'))
for k, abi in A['kinds'].items():
    put(abi['event'], dict(EVENT), 'name')
    for e in ERRORS:
        put(abi['error'], dict(e), 'name')
open('script/modules/face_abi.json', 'w').write(json.dumps(A, indent=1))
