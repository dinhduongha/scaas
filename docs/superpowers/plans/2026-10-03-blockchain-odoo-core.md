# Odoo Control Plane + Payment Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two optional addons — `dms_blockchain` (chains, tokens, signed meta-tx, relay outbox, finalized chain events, payment requests, service RPC for `bamboo-node`) and `dms_blockchain_payment` (`payment.provider` code `chain` wired to the payment gate).

**Architecture:** Odoo is the control plane: it never holds key material and never calls a chain. It writes one outbox row (`blockchain.relay.job`) in the same transaction as the business change; `bamboo-node` drains it over `/json/2` and reports back; only finalized events (`chain_event_ingest`) can move a payment to `done`.

**Tech Stack:** Odoo 19 Community, Python 3.12, no third-party Python dependency (keccak-256 and secp256k1 are pure Python in `dms_blockchain/lib`).

**Spec:** `docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` §3.5, §4, §5, §7–§10, rulings R6–R13, R17–R20.

## Global Constraints

- Model prefix `blockchain.`; uint256 = `Char` + CHECK `'^(0|[1-9][0-9]{0,77})$'`, suffix `_base`; addresses `Char` lowercase + CHECK `'^0x[0-9a-f]{40}$'`; hashes `_hash` (`'^0x[0-9a-f]{64}$'`); never `fields.Char(size=…)`; never `default=` on a stored compute; no field named after an Odoo field type.
- Constraints via `models.Constraint` / `models.UniqueIndex` (Odoo 19 ignores `_sql_constraints`, TRAPS §2) and verified in `pg_constraint`/`pg_indexes` by tests.
- `res.groups` uses `privilege_id`, never `category_id` (TRAPS §9).
- Cron XML calls exactly one model method (`model._cron_…()`) (CLAUDE.md §5.4).
- Public RPC methods: name without `_`, no `@api.private`, explicit group check first; logic in a `_private` method; never accept `company_id`/`allowed_company_ids` from a client (CLAUDE.md §6).
- `dms_blockchain` depends only on `base`, `mail`; `dms_blockchain_payment` on `dms_blockchain`, `payment`. Neither is a dependency of `bamboo_dms` or `dms_portal`.
- `MODE_KNOWN_MASK = 0xF3`, `MODE_RESTRICT_RELAYER = 0x01`, `MODE_RESTRICT_FEE_RECIPIENT = 0x02`, fee nibble `0x00/0x10/0x20` — copied from `MetaTxLib.sol`.
- `OP_PAY = keccak256("pay(bytes32)")[:4]`; lane `batch = int(keccak256(b"bamboo.pay.lane" + entry_ref))`; nonce always 0; EIP-712 domain name `"Bamboo MetaToken"` version `"1"`.
- Tests run on DB `dms_test_chain`, HTTP port 8920, worktree addons path first (see "Running the Odoo tests" below). Never `dms_test`/`odoo19`, never port 8899, never two runs at once.

## Running the Odoo tests

The container mounts the repo at `/mnt/custom-addons/bamboo-dms`; this worktree is visible at
`/mnt/custom-addons/bamboo-dms/.claude/worktrees/agent-a3bf35411cfe793e9`. Put it **first** in the
addons path so every DMS module comes from this branch:

```bash
WT=/mnt/custom-addons/bamboo-dms/.claude/worktrees/agent-a3bf35411cfe793e9
AP=$(docker exec odoo19-server-1 sh -c "grep '^addons_path' /etc/odoo/odoo.conf | cut -d= -f2 | tr -d ' '")
source /home/dockers/odoo19/.env
docker exec -i -e PGPASSWORD="$DB_PASSWORD" odoo19-db-1 psql -U odoo -d postgres -c 'DROP DATABASE IF EXISTS "dms_test_chain" WITH (FORCE);'
docker exec odoo19-server-1 odoo -c /etc/odoo/odoo.conf --logfile=/dev/stdout --db_host=db --db_port=5432 \
  --addons-path="$WT,$AP" --http-port=8920 --gevent-port=8921 -d dms_test_chain \
  -i dms_blockchain --without-demo --test-enable --test-tags /dms_blockchain --stop-after-init
```

Wrapped as `scripts/chain-odoo-test.sh <modules> [test-tags]` in Task 1 (it does exactly the above
and greps the summary line `odoo.tests.result: N failed, M error(s) of K tests`).

## Review Focus

- A signature whose `s > n/2` (malleable twin) must be rejected by the Python verifier, as OZ does on-chain — pinned in Task 1.
- `chain_event_ingest` called twice with the same range (node crashed after Odoo committed) must be a no-op returning the cursor, not a gap error — pinned in Task 4.
- A business exception inside `_on_paid` must not roll back the ingest batch — pinned in Task 5.
- An event from a contract that is not a registered token must never reach a payment request — pinned in Task 4.
- `relay_report` must refuse a transition not in the table (e.g. `queued → final`) — pinned in Task 3.

## File Structure

| File | Responsibility |
|---|---|
| `scripts/chain-odoo-test.sh` | run Odoo tests for these addons on the scratch DB/port |
| `dms_blockchain/__init__.py`, `__manifest__.py` | addon |
| `dms_blockchain/lib/keccak.py` | pure keccak-256 |
| `dms_blockchain/lib/secp256k1.py` | `ecrecover(digest, sig) -> address|None` (low-s only) |
| `dms_blockchain/lib/eip712.py` | constants, address/uint helpers, `struct_hash`, `domain_separator`, `digest`, `typed_data`, `pay_data`, `lane_batch` |
| `dms_blockchain/models/blockchain_chain.py` | `blockchain.chain`, `check_service()`, `node_config` |
| `dms_blockchain/models/blockchain_token.py` | `blockchain.token` |
| `dms_blockchain/models/blockchain_metatx.py` | `blockchain.metatx` (immutable signed envelope) |
| `dms_blockchain/models/blockchain_relay_job.py` | outbox + `relay_poll/claim/report`, `_cron_expire` |
| `dms_blockchain/models/blockchain_chain_event.py` | `blockchain.chain.event`, `chain_event_ingest` |
| `dms_blockchain/models/blockchain_payment_request.py` | request, settlement sum, gate, hooks, `_accept_signature`, `_cron_expire` |
| `dms_blockchain/security/blockchain_security.xml`, `ir.model.access.csv` | groups, rules, ACL |
| `dms_blockchain/data/blockchain_chain_data.xml`, `data/ir_cron.xml` | seeds, crons |
| `dms_blockchain/views/blockchain_views.xml` | list/form/menu |
| `dms_blockchain/tests/*` | tests |
| `dms_blockchain_payment/**` | provider, method, tx link, gate hooks, tests |

---

### Task 1: Pure crypto lib + KAT parity

**Files:**
- Create: `dms_blockchain/__init__.py`, `dms_blockchain/__manifest__.py` (minimal, `data: []`), `dms_blockchain/lib/__init__.py`, `lib/keccak.py`, `lib/secp256k1.py`, `lib/eip712.py`, `dms_blockchain/models/__init__.py` (empty), `dms_blockchain/tests/__init__.py`, `tests/test_eip712.py`, `scripts/chain-odoo-test.sh`

**Interfaces:**
- Produces: `keccak256(bytes)->bytes`; `ecrecover(digest: bytes, sig: bytes) -> str|None`; `eip712.norm_address(str)->str`, `eip712.MetaTx` field dict keys `from,to,value,data,batch,nonce,valid_until,mode,relayer,fee,fee_recipient` (ints for uint, `bytes` for data, lowercase str addresses); `struct_hash(m)->bytes`; `domain_separator(name, version, chain_id, contract)->bytes`; `digest(domain: dict, m)->bytes`; `typed_data(domain, m)->dict`; `pay_data(entry_ref: bytes)->bytes`; `lane_batch(entry_ref)->int`; constants `MODE_*`, `OP_PAY`.

- [ ] **Step 1: Failing test** — `dms_blockchain/tests/test_eip712.py`:

```python
"""Bản sao thứ ba của digest (Solidity, Rust, Python) — khoá bằng vector KAT do forge
sinh ở `smartcontracts/test/vectors/metatx_kat.json` (spec §6)."""
import json
import os

from odoo.tests.common import BaseCase, tagged

from ..lib import eip712
from ..lib.keccak import keccak256
from ..lib.secp256k1 import N, ecrecover

KAT = os.path.join(os.path.dirname(__file__), '..', '..', 'smartcontracts', 'test', 'vectors',
                   'metatx_kat.json')


def _kat():
    with open(KAT) as fh:
        return json.load(fh)


@tagged('post_install', '-at_install')
class TestEip712(BaseCase):

    def test_keccak_known_answers(self):
        self.assertEqual(keccak256(b'').hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(keccak256(b'abc').hex(),
                         '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        # one byte short of the 136-byte rate: pad byte becomes 0x81
        self.assertEqual(len(keccak256(b'a' * 135)), 32)
        self.assertNotEqual(keccak256(b'a' * 135), keccak256(b'a' * 136))

    def test_typehash_is_pinned(self):
        self.assertEqual(
            eip712.METATX_TYPEHASH,
            keccak256(b'MetaTransaction(address from,address to,uint256 value,bytes data,'
                      b'uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,'
                      b'address relayer,uint256 fee,address feeRecipient)'))

    def _kat_message(self, k):
        return {
            'from': k['from'], 'to': k['to'], 'value': int(k['value']),
            'data': bytes.fromhex(k['data'][2:]), 'batch': int(k['batch']),
            'nonce': int(k['nonce']), 'valid_until': int(k['valid_until']),
            'mode': int(k['mode']), 'relayer': k['relayer'], 'fee': int(k['fee']),
            'fee_recipient': k['fee_recipient'],
        }

    def test_struct_hash_and_digest_match_solidity(self):
        k = _kat()
        m = self._kat_message(k)
        self.assertEqual('0x' + eip712.struct_hash(m).hex(), k['struct_hash'].lower())
        domain = {'name': k['domain_name'], 'version': k['domain_version'],
                  'chain_id': int(k['chain_id']), 'verifying_contract': k['verifying_contract']}
        self.assertEqual('0x' + eip712.digest(domain, m).hex(), k['digest'].lower())

    def test_canonical_zeroing_ignores_unflagged_fee_recipient(self):
        m = self._kat_message(_kat())
        other = dict(m, fee_recipient='0x' + '11' * 20)
        self.assertEqual(eip712.struct_hash(m), eip712.struct_hash(other))
        flagged = dict(m, mode=m['mode'] | eip712.MODE_RESTRICT_FEE_RECIPIENT)
        self.assertNotEqual(eip712.struct_hash(flagged),
                            eip712.struct_hash(dict(flagged, fee_recipient='0x' + '11' * 20)))

    def test_ecrecover_matches_forge_signature(self):
        k = _kat()
        sig = bytes.fromhex(k['signature'][2:])
        self.assertEqual(ecrecover(bytes.fromhex(k['digest'][2:]), sig), k['signer'].lower())

    def test_high_s_twin_is_rejected(self):
        k = _kat()
        sig = bytes.fromhex(k['signature'][2:])
        r, s, v = sig[:32], int.from_bytes(sig[32:64], 'big'), sig[64]
        twin = r + (N - s).to_bytes(32, 'big') + bytes([55 - v if v >= 27 else 1 - v])
        self.assertIsNone(ecrecover(bytes.fromhex(k['digest'][2:]), twin))

    def test_garbage_signature_recovers_nothing(self):
        self.assertIsNone(ecrecover(b'\x00' * 32, b'\x00' * 65))
        self.assertIsNone(ecrecover(b'\x00' * 32, b'\x01' * 64))

    def test_typed_data_is_what_the_wallet_hashes(self):
        """Ví băm đúng JSON này; nó phải trùng digest Solidity, kể cả zeroing."""
        k = _kat()
        m = self._kat_message(k)
        domain = {'name': k['domain_name'], 'version': k['domain_version'],
                  'chain_id': int(k['chain_id']), 'verifying_contract': k['verifying_contract']}
        td = eip712.typed_data(domain, m)
        self.assertEqual(td['primaryType'], 'MetaTransaction')
        self.assertEqual(td['message']['feeRecipient'], '0x' + '00' * 20)
        self.assertEqual(td['domain']['chainId'], 9000)

    def test_pay_data_and_lane(self):
        ref = b'\x42' * 32
        self.assertEqual(eip712.pay_data(ref), eip712.OP_PAY + ref)
        self.assertEqual(eip712.OP_PAY, keccak256(b'pay(bytes32)')[:4])
        self.assertEqual(eip712.lane_batch(ref),
                         int.from_bytes(keccak256(b'bamboo.pay.lane' + ref), 'big'))

    def test_address_normalisation(self):
        self.assertEqual(eip712.norm_address('0xABCDEF0000000000000000000000000000000001'),
                         '0xabcdef0000000000000000000000000000000001')
        for bad in ('0x12', 'abcdef0000000000000000000000000000000001', '0x' + 'g' * 40, None):
            with self.assertRaises(ValueError):
                eip712.norm_address(bad)
```

`scripts/chain-odoo-test.sh`:

```bash
#!/usr/bin/env bash
# Odoo tests for the blockchain addons on their OWN scratch database and port.
# usage: scripts/chain-odoo-test.sh <modules,comma,separated> [test-tags]
set -euo pipefail
MODULES="${1:?modules}"
TAGS="${2:-}"
DB="${CHAIN_TEST_DB:-dms_test_chain}"
PORT="${CHAIN_TEST_PORT:-8920}"
[ "$DB" = odoo19 ] || [ "$DB" = dms_test ] && { echo "refusing $DB"; exit 1; }
[ "$PORT" = 8899 ] && { echo "refusing port 8899"; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WT="/mnt/custom-addons/bamboo-dms/${HERE#/home/dockers/odoo19/custom-addons/bamboo-dms/}"
[ "$HERE" = /home/dockers/odoo19/custom-addons/bamboo-dms ] && WT=/mnt/custom-addons/bamboo-dms
AP="$(docker exec odoo19-server-1 sh -c "grep '^addons_path' /etc/odoo/odoo.conf | cut -d= -f2 | tr -d ' '")"
: "${DB_PASSWORD:?source /home/dockers/odoo19/.env}"
if [ -z "$TAGS" ]; then for m in ${MODULES//,/ }; do TAGS="${TAGS:+$TAGS,}/$m"; done; fi
docker exec -i -e PGPASSWORD="$DB_PASSWORD" odoo19-db-1 psql -q -U odoo -d postgres \
  -c "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE);"
LOG="$(mktemp -t chain-odoo.XXXXXX)"
set +e
docker exec odoo19-server-1 odoo -c /etc/odoo/odoo.conf --logfile=/dev/stdout \
  --db_host=db --db_port=5432 --addons-path="$WT,$AP" \
  --http-port="$PORT" --gevent-port=$((PORT + 1)) --max-cron-threads=0 \
  -d "$DB" -i "$MODULES" --without-demo --test-enable --test-tags "$TAGS" \
  --stop-after-init 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e
grep -E 'odoo.tests.result|Initiating shutdown|ERROR|FAIL' "$LOG" | tail -40 || true
exit "$rc"
```

- [ ] **Step 2: Run to verify it fails**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: `ImportError`/`ModuleNotFoundError` for `..lib.eip712` (or 'dms_blockchain' not installable).

- [ ] **Step 3: Implement**

`dms_blockchain/__manifest__.py`:

```python
{
    'name': 'Bamboo Blockchain - Control Plane',
    'version': '19.0.1.0.0',
    'license': 'LGPL-3',
    'category': 'Accounting/Payment',
    'summary': 'Chains, tokens, signed meta-transactions, relay outbox, finalized chain events',
    'description': """
        Odoo is the control plane of bamboo-node: it decides, writes an outbox
        row, and reads finalized results. It holds no key and calls no chain.
        Optional: bamboo_dms installs and runs without it.
    """,
    'author': 'dinhduongha@gmail.com',
    'depends': ['base', 'mail'],
    'data': [],
    'installable': True,
    'application': False,
    'auto_install': False,
}
```

`dms_blockchain/__init__.py`: `from . import lib` / `from . import models`.

`dms_blockchain/lib/keccak.py`:

```python
"""Keccak-256 (bản gốc Ethereum, KHÔNG phải SHA3-256 của FIPS 202 — khác byte đệm).

Thuần Python để addon không kéo thư viện ngoài (ruling R13). Chậm (~µs/khối), đủ cho
vài chữ ký mỗi request.
"""
_MASK = (1 << 64) - 1
_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# _ROT[x][y]
_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_RATE = 136


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _permute(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
             for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    buf = bytearray(data)
    buf.append(0x01)
    while len(buf) % _RATE:
        buf.append(0)
    buf[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(buf), _RATE):
        for i in range(_RATE // 8):
            a[i % 5][i // 5] ^= int.from_bytes(buf[off + 8 * i: off + 8 * i + 8], 'little')
        a = _permute(a)
    return b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))
```

`dms_blockchain/lib/secp256k1.py`:

```python
"""`ecrecover` trên secp256k1, thuần Python. Chỉ nhận low-s (EIP-2), như OZ `ECDSA`."""
from .keccak import keccak256

P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, point):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, point)
        point = _add(point, point)
        k >>= 1
    return acc


def ecrecover(digest, sig):
    """Địa chỉ (0x… chữ thường) đã ký `digest`, hoặc None nếu chữ ký không hợp lệ."""
    if len(digest) != 32 or len(sig) != 65:
        return None
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:64], 'big')
    v = sig[64] - 27 if sig[64] >= 27 else sig[64]
    if v not in (0, 1) or not 0 < r < N or not 0 < s <= N // 2:
        return None
    y2 = (pow(r, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if y % 2 != v:
        y = P - y
    e = int.from_bytes(digest, 'big')
    rinv = pow(r, -1, N)
    q = _add(_mul(s * rinv % N, (r, y)), _mul(-e * rinv % N, G))
    if q is None:
        return None
    pub = q[0].to_bytes(32, 'big') + q[1].to_bytes(32, 'big')
    return '0x' + keccak256(pub)[-20:].hex()
```

`dms_blockchain/lib/eip712.py`:

```python
"""EIP-712 cho `MetaTransaction` — bản Python của `MetaTxLib.hashStruct`.

Quy tắc canonical-zeroing PHẢI giống hệt Solidity và Rust (spec §6). Đổi một dòng ở đây
mà không đổi `MetaTxLib.sol` là mọi chữ ký portal fail — fail-closed, nhưng là sự cố.
"""
import re

from .keccak import keccak256

MODE_RESTRICT_RELAYER = 0x01
MODE_RESTRICT_FEE_RECIPIENT = 0x02
MODE_FEE_MASK = 0xF0
MODE_KNOWN_MASK = 0xF3

METATX_TYPE = ('MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,'
               'uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,'
               'address feeRecipient)')
DOMAIN_TYPE = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
METATX_TYPEHASH = keccak256(METATX_TYPE.encode())
DOMAIN_TYPEHASH = keccak256(DOMAIN_TYPE.encode())
OP_PAY = keccak256(b'pay(bytes32)')[:4]
ZERO_ADDRESS = '0x' + '00' * 20
UINT256_MAX = 2 ** 256 - 1
_ADDRESS = re.compile(r'^0x[0-9a-fA-F]{40}$')


def norm_address(value):
    if not isinstance(value, str) or not _ADDRESS.match(value):
        raise ValueError(f'not an EVM address: {value!r}')
    return value.lower()


def _word_uint(v):
    v = int(v)
    if not 0 <= v <= UINT256_MAX:
        raise ValueError(f'uint256 out of range: {v}')
    return v.to_bytes(32, 'big')


def _word_address(a):
    return bytes(12) + bytes.fromhex(norm_address(a)[2:])


def mode_is_valid(mode):
    return 0 <= mode <= 0xFFFFFFFF and not (mode & ~MODE_KNOWN_MASK) and (mode & MODE_FEE_MASK) >> 4 <= 2


def canon(m):
    """(relayer, feeRecipient) như được băm: 0 khi cờ tương ứng tắt."""
    relayer = m['relayer'] if m['mode'] & MODE_RESTRICT_RELAYER else ZERO_ADDRESS
    fee_recipient = m['fee_recipient'] if m['mode'] & MODE_RESTRICT_FEE_RECIPIENT else ZERO_ADDRESS
    return relayer, fee_recipient


def struct_hash(m):
    relayer, fee_recipient = canon(m)
    return keccak256(b''.join((
        METATX_TYPEHASH,
        _word_address(m['from']), _word_address(m['to']), _word_uint(m['value']),
        keccak256(m['data']), _word_uint(m['batch']), _word_uint(m['nonce']),
        _word_uint(m['valid_until']), _word_uint(m['mode']),
        _word_address(relayer), _word_uint(m['fee']), _word_address(fee_recipient),
    )))


def domain_separator(name, version, chain_id, verifying_contract):
    return keccak256(b''.join((
        DOMAIN_TYPEHASH, keccak256(name.encode()), keccak256(version.encode()),
        _word_uint(chain_id), _word_address(verifying_contract),
    )))


def digest(domain, m):
    sep = domain_separator(domain['name'], domain['version'], domain['chain_id'],
                           domain['verifying_contract'])
    return keccak256(b'\x19\x01' + sep + struct_hash(m))


def typed_data(domain, m):
    """JSON cho `eth_signTypedData_v4`. Đã canonical-zero sẵn: ví băm đúng cái nó thấy."""
    relayer, fee_recipient = canon(m)
    return {
        'types': {
            'EIP712Domain': [
                {'name': 'name', 'type': 'string'}, {'name': 'version', 'type': 'string'},
                {'name': 'chainId', 'type': 'uint256'},
                {'name': 'verifyingContract', 'type': 'address'}],
            'MetaTransaction': [
                {'name': 'from', 'type': 'address'}, {'name': 'to', 'type': 'address'},
                {'name': 'value', 'type': 'uint256'}, {'name': 'data', 'type': 'bytes'},
                {'name': 'batch', 'type': 'uint256'}, {'name': 'nonce', 'type': 'uint256'},
                {'name': 'validUntil', 'type': 'uint256'}, {'name': 'mode', 'type': 'uint32'},
                {'name': 'relayer', 'type': 'address'}, {'name': 'fee', 'type': 'uint256'},
                {'name': 'feeRecipient', 'type': 'address'}],
        },
        'primaryType': 'MetaTransaction',
        'domain': {'name': domain['name'], 'version': domain['version'],
                   'chainId': int(domain['chain_id']),
                   'verifyingContract': norm_address(domain['verifying_contract'])},
        'message': {
            'from': norm_address(m['from']), 'to': norm_address(m['to']),
            'value': str(int(m['value'])), 'data': '0x' + m['data'].hex(),
            'batch': str(int(m['batch'])), 'nonce': str(int(m['nonce'])),
            'validUntil': str(int(m['valid_until'])), 'mode': int(m['mode']),
            'relayer': relayer, 'fee': str(int(m['fee'])), 'feeRecipient': fee_recipient,
        },
    }


def pay_data(entry_ref):
    if len(entry_ref) != 32:
        raise ValueError('entryRef must be 32 bytes')
    return OP_PAY + entry_ref


def lane_batch(entry_ref):
    return int.from_bytes(keccak256(b'bamboo.pay.lane' + entry_ref), 'big')
```

`dms_blockchain/lib/__init__.py`: empty docstring only. `dms_blockchain/tests/__init__.py`: `from . import test_eip712`.

- [ ] **Step 4: Run to verify it passes**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: `odoo.tests.result: 0 failed, 0 error(s) of 10 tests`.

- [ ] **Step 5: Commit**

```bash
git add dms_blockchain scripts/chain-odoo-test.sh
git commit -m "feat(blockchain): pure-Python keccak, ecrecover and EIP-712 locked to the forge KAT"
```

---

### Task 2: Chain, token, metatx models + security

**Files:**
- Create: `dms_blockchain/models/blockchain_chain.py`, `blockchain_token.py`, `blockchain_metatx.py`, `dms_blockchain/security/blockchain_security.xml`, `security/ir.model.access.csv`, `dms_blockchain/data/blockchain_chain_data.xml`, `dms_blockchain/views/blockchain_views.xml`, `dms_blockchain/tests/test_models.py`
- Modify: `dms_blockchain/__manifest__.py` (`data`), `models/__init__.py`, `tests/__init__.py`

**Interfaces:**
- Produces: `check_service(env, *roles)` (roles `'relay_worker'`, `'indexer'`); `blockchain.chain._active(evm_chain_number)`; `blockchain.chain.node_config(evm_chain_number, relayer_address=None)`; `blockchain.token` fields `chain_id address name symbol decimals domain_name domain_version currency_id active`, method `_domain()` → dict for `eip712.digest`; `blockchain.metatx` fields per spec §4.2 with `_message()` → dict for `eip712`, immutable except `metatx_state`, `executed_tx_hash`, `last_error`.

- [ ] **Step 1: Failing tests** — `dms_blockchain/tests/test_models.py`:

```python
from psycopg2 import IntegrityError

from odoo.exceptions import AccessError, UserError, ValidationError
from odoo.tests.common import TransactionCase, tagged
from odoo.tools import mute_logger

from ..lib import eip712

ADDR = '0x' + 'ab' * 20


class ChainCase(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.chain = cls.env['blockchain.chain'].create({
            'name': 'Test 9001', 'evm_chain_number': 9001, 'state': 'active'})
        cls.usd = cls.env.ref('base.USD')
        cls.token = cls.env['blockchain.token'].create({
            'chain_id': cls.chain.id, 'address': '0x' + 'CD' * 20, 'name': 'Bamboo USD',
            'symbol': 'bUSD', 'decimals': 6, 'currency_id': cls.usd.id})
        Users = cls.env['res.users'].with_context(no_reset_password=True)
        cls.relay_user = Users.create({
            'name': 'relay', 'login': 'relay@chain.test',
            'group_ids': [(6, 0, [cls.env.ref('base.group_user').id,
                                  cls.env.ref('dms_blockchain.group_blockchain_relay_worker').id])]})
        cls.indexer_user = Users.create({
            'name': 'indexer', 'login': 'indexer@chain.test',
            'group_ids': [(6, 0, [cls.env.ref('base.group_user').id,
                                  cls.env.ref('dms_blockchain.group_blockchain_indexer').id])]})
        cls.plain_user = Users.create({
            'name': 'plain', 'login': 'plain@chain.test',
            'group_ids': [(6, 0, [cls.env.ref('base.group_user').id])]})

    def _metatx_vals(self, **kw):
        vals = {
            'company_id': self.env.company.id, 'chain_id': self.chain.id,
            'token_id': self.token.id, 'from_address': ADDR, 'to_address': '0x' + '01' * 20,
            'value_base': '100', 'data_hex': '0x', 'batch_hex': '0x' + '00' * 31 + '07',
            'nonce_base': '0', 'valid_until_ts': 1_800_000_300, 'mode_flags': 1,
            'relayer_address': '0x' + '02' * 20, 'fee_base': '0',
            'fee_recipient_address': eip712.ZERO_ADDRESS,
            'digest_hash': '0x' + '33' * 32, 'signature_hex': '0x' + '44' * 65,
        }
        vals.update(kw)
        return vals


@tagged('post_install', '-at_install')
class TestModels(ChainCase):

    def test_constraints_exist_in_postgres(self):
        self.env.cr.execute("""SELECT conname FROM pg_constraint
                               WHERE conrelid IN ('blockchain_chain'::regclass,
                                                  'blockchain_token'::regclass,
                                                  'blockchain_metatx'::regclass)""")
        names = {r[0] for r in self.env.cr.fetchall()}
        for expected in ('blockchain_chain_evm_chain_number_uniq',
                         'blockchain_token_chain_address_uniq',
                         'blockchain_token_address_format',
                         'blockchain_metatx_chain_digest_uniq',
                         'blockchain_metatx_value_base_uint'):
            self.assertIn(expected, names)

    def test_token_address_is_stored_lowercase(self):
        self.assertEqual(self.token.address, '0x' + 'cd' * 20)

    def test_bad_address_refused(self):
        with self.assertRaises(ValidationError):
            self.env['blockchain.token'].create({
                'chain_id': self.chain.id, 'address': '0x12', 'name': 'x', 'symbol': 'x',
                'decimals': 0, 'currency_id': self.usd.id})

    def test_uint_column_refuses_leading_zero(self):
        with mute_logger('odoo.sql_db'), self.assertRaises(IntegrityError), self.cr.savepoint():
            self.env['blockchain.metatx'].create(self._metatx_vals(value_base='0100'))
            self.env.flush_all()

    def test_mode_with_unknown_bits_refused(self):
        with self.assertRaises(ValidationError):
            self.env['blockchain.metatx'].create(self._metatx_vals(mode_flags=0x04))

    def test_signed_envelope_is_immutable(self):
        mtx = self.env['blockchain.metatx'].create(self._metatx_vals())
        with self.assertRaises(UserError):
            mtx.write({'value_base': '1'})
        mtx.write({'metatx_state': 'failed', 'last_error': 'x'})
        self.assertEqual(mtx.metatx_state, 'failed')

    def test_message_round_trips_to_digest_inputs(self):
        mtx = self.env['blockchain.metatx'].create(self._metatx_vals())
        m = mtx._message()
        self.assertEqual(m['batch'], 7)
        self.assertEqual(m['data'], b'')
        self.assertEqual(m['valid_until'], 1_800_000_300)

    def test_node_config_is_service_only(self):
        with self.assertRaises(AccessError):
            self.env['blockchain.chain'].with_user(self.plain_user).node_config(9001)
        cfg = self.env['blockchain.chain'].with_user(self.relay_user).node_config(9001)
        self.assertEqual(cfg['evm_chain_number'], 9001)
        self.assertEqual(cfg['tokens'], [{'address': '0x' + 'cd' * 20, 'decimals': 6}])
        self.assertIsNone(cfg['journal_max_nonce'])
        self.env['blockchain.chain'].with_user(self.indexer_user).node_config(9001)

    def test_node_config_refuses_inactive_chain(self):
        self.chain.state = 'paused'
        with self.assertRaises(UserError):
            self.env['blockchain.chain'].with_user(self.relay_user).node_config(9001)

    def test_seed_chains_are_draft(self):
        c9000 = self.env.ref('dms_blockchain.data_chain_private9000')
        self.assertEqual(c9000.evm_chain_number, 9000)
        self.assertEqual(c9000.state, 'draft')
        self.assertEqual(self.env.ref('dms_blockchain.data_chain_gnosis').finality_quorum, 2)
```

- [ ] **Step 2: Run to verify it fails**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: errors — `blockchain.chain` unknown model / `group_blockchain_relay_worker` external id not found.

- [ ] **Step 3: Implement**

`dms_blockchain/models/blockchain_chain.py`:

```python
from odoo import api, fields, models
from odoo.exceptions import AccessError, UserError

SERVICE_GROUPS = {
    'relay_worker': 'dms_blockchain.group_blockchain_relay_worker',
    'indexer': 'dms_blockchain.group_blockchain_indexer',
}


def check_service(env, *roles):
    """Method dịch vụ PHẢI public (RPC gọi được) — nên nhóm quyền là cổng duy nhất.

    Hai nhóm, hai user, hai API key (canon §C14.1): chiếm key indexer không ghi được job.
    """
    if not any(env.user.has_group(SERVICE_GROUPS[r]) for r in roles):
        raise AccessError(env._("Reserved to the blockchain service accounts: %s", ', '.join(roles)))


class BlockchainChain(models.Model):
    _name = 'blockchain.chain'
    _description = 'Blockchain Network'
    _inherit = ['mail.thread']
    _order = 'evm_chain_number'

    name = fields.Char(required=True, tracking=True)
    evm_chain_number = fields.Integer(required=True, tracking=True, help='EIP-155 chain id.')
    caip2 = fields.Char(compute='_compute_caip2', store=True)
    native_currency = fields.Char()
    state = fields.Selection(
        [('draft', 'Draft'), ('active', 'Active'), ('paused', 'Paused')],
        default='draft', required=True, tracking=True)
    finality_mode = fields.Selection(
        [('depth', 'Confirmation depth'), ('tag', "'finalized' block tag")],
        default='depth', required=True, tracking=True)
    finality_depth = fields.Integer(default=1, tracking=True)
    finality_quorum = fields.Integer(
        default=1, tracking=True,
        help='Independent RPC endpoints (configured on the node) that must agree on a block hash.')
    indexed_block = fields.Integer(default=0, readonly=True, copy=False)
    public_rpc_url = fields.Char(help='Public RPC offered to wallets (wallet_addEthereumChain). Never a keyed URL.')
    token_ids = fields.One2many('blockchain.token', 'chain_id')

    _evm_chain_number_uniq = models.Constraint(
        'UNIQUE(evm_chain_number)', 'A chain id can be registered once.')
    _finality_quorum_positive = models.Constraint(
        'CHECK(finality_quorum >= 1)', 'Finality quorum is at least one endpoint.')
    _finality_depth_nonneg = models.Constraint(
        'CHECK(finality_depth >= 0)', 'Finality depth cannot be negative.')

    @api.depends('evm_chain_number')
    def _compute_caip2(self):
        for chain in self:
            chain.caip2 = f'eip155:{chain.evm_chain_number}'

    @api.model
    def _active(self, evm_chain_number):
        chain = self.sudo().search([('evm_chain_number', '=', int(evm_chain_number))], limit=1)
        if not chain or chain.state != 'active':
            raise UserError(self.env._('Chain %s is not active.', evm_chain_number))
        return chain

    @api.model
    def node_config(self, evm_chain_number, relayer_address=None):
        """POST /json/2/blockchain.chain/node_config
        Service accounts only. Không nhận company: chain và token là cấu hình chung."""
        check_service(self.env, 'relay_worker', 'indexer')
        return self._active(evm_chain_number)._node_config(relayer_address)

    def _node_config(self, relayer_address=None):
        self.ensure_one()
        from ..lib.eip712 import norm_address
        journal_max = None
        if relayer_address:
            self.env.cr.execute(
                'SELECT max(outer_nonce) FROM blockchain_relay_job WHERE chain_id = %s AND signer_address = %s',
                (self.id, norm_address(relayer_address)))
            journal_max = self.env.cr.fetchone()[0]
        return {
            'evm_chain_number': self.evm_chain_number,
            'finality_mode': self.finality_mode,
            'finality_depth': self.finality_depth,
            'finality_quorum': self.finality_quorum,
            'indexed_block': self.indexed_block,
            'tokens': [{'address': t.address, 'decimals': t.decimals}
                       for t in self.token_ids.filtered('active').sorted('id')],
            'journal_max_nonce': journal_max,
        }
```

Note: `_node_config` reads `blockchain_relay_job` which Task 3 creates. In Task 2 create `blockchain.relay.job` as a stub model in `blockchain_relay_job.py` with only `chain_id`, `signer_address`, `outer_nonce` so the SQL is valid; Task 3 completes it.

`dms_blockchain/models/blockchain_token.py`:

```python
from odoo import api, fields, models
from odoo.exceptions import ValidationError

from ..lib.eip712 import norm_address


class BlockchainToken(models.Model):
    _name = 'blockchain.token'
    _description = 'Blockchain Token'
    _inherit = ['mail.thread']
    _order = 'chain_id, symbol'

    chain_id = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    address = fields.Char(required=True, tracking=True)
    name = fields.Char(required=True)
    symbol = fields.Char(required=True)
    decimals = fields.Integer(required=True)
    domain_name = fields.Char(required=True, default='Bamboo MetaToken')
    domain_version = fields.Char(required=True, default='1')
    currency_id = fields.Many2one(
        'res.currency', required=True,
        help='Fiat currency this token is pegged to 1:1. Orders in another currency cannot use it (no FX).')
    is_confidential = fields.Boolean(default=False, readonly=True)
    active = fields.Boolean(default=True)

    _chain_address_uniq = models.Constraint(
        'UNIQUE(chain_id, address)', 'A token address is registered once per chain.')
    _address_format = models.Constraint(
        "CHECK(address ~ '^0x[0-9a-f]{40}$')", 'Token address must be a lowercase 0x address.')
    _decimals_range = models.Constraint(
        'CHECK(decimals >= 0 AND decimals <= 36)', 'Decimals out of range.')

    @api.model_create_multi
    def create(self, vals_list):
        return super().create([self._normalize(v) for v in vals_list])

    def write(self, vals):
        return super().write(self._normalize(vals))

    @api.model
    def _normalize(self, vals):
        if vals.get('address'):
            try:
                vals = dict(vals, address=norm_address(vals['address']))
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
        return vals

    def _domain(self):
        self.ensure_one()
        return {'name': self.domain_name, 'version': self.domain_version,
                'chain_id': self.chain_id.evm_chain_number, 'verifying_contract': self.address}
```

`dms_blockchain/models/blockchain_metatx.py`:

```python
from odoo import api, fields, models
from odoo.exceptions import UserError, ValidationError

from ..lib import eip712

UINT = "'^(0|[1-9][0-9]{0,77})$'"
ADDRESS = "'^0x[0-9a-f]{40}$'"
HASH32 = "'^0x[0-9a-f]{64}$'"

_MUTABLE = {'metatx_state', 'executed_tx_hash', 'last_error'}


class BlockchainMetatx(models.Model):
    """Phong bì EIP-1776 đã ký — bất biến sau khi ký (canon §C10.5)."""
    _name = 'blockchain.metatx'
    _description = 'Signed Meta-Transaction'
    _order = 'id desc'
    _rec_name = 'digest_hash'

    company_id = fields.Many2one('res.company', required=True, index=True)
    chain_id = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    token_id = fields.Many2one('blockchain.token', required=True, index=True, ondelete='restrict')
    from_address = fields.Char(required=True, index=True)
    to_address = fields.Char(required=True)
    value_base = fields.Char(required=True)
    data_hex = fields.Char(required=True, default='0x')
    batch_hex = fields.Char(required=True)
    nonce_base = fields.Char(required=True, default='0')
    valid_until_ts = fields.Integer(required=True, help='validUntil, unix seconds.')
    mode_flags = fields.Integer(required=True, default=0)
    relayer_address = fields.Char(required=True, default=eip712.ZERO_ADDRESS)
    fee_base = fields.Char(required=True, default='0')
    fee_recipient_address = fields.Char(required=True, default=eip712.ZERO_ADDRESS)
    digest_hash = fields.Char(required=True)
    signature_hex = fields.Char(required=True)
    signature_verified = fields.Boolean(default=False, readonly=True)
    metatx_state = fields.Selection(
        [('signed', 'Signed'), ('final', 'Executed (final)'), ('failed', 'Failed'),
         ('expired', 'Expired')], default='signed', required=True, index=True)
    executed_tx_hash = fields.Char()
    last_error = fields.Char()
    payment_request_id = fields.Many2one('blockchain.payment.request', index=True)

    _chain_digest_uniq = models.Constraint(
        'UNIQUE(chain_id, digest_hash)', 'One envelope per digest per chain.')
    _value_base_uint = models.Constraint(f'CHECK(value_base ~ {UINT})', 'value_base is a uint256.')
    _nonce_base_uint = models.Constraint(f'CHECK(nonce_base ~ {UINT})', 'nonce_base is a uint256.')
    _fee_base_uint = models.Constraint(f'CHECK(fee_base ~ {UINT})', 'fee_base is a uint256.')
    _addresses_format = models.Constraint(
        f'CHECK(from_address ~ {ADDRESS} AND to_address ~ {ADDRESS} AND relayer_address ~ {ADDRESS}'
        f' AND fee_recipient_address ~ {ADDRESS})', 'Addresses must be lowercase 0x addresses.')
    _hashes_format = models.Constraint(
        f'CHECK(digest_hash ~ {HASH32} AND batch_hex ~ {HASH32})', 'digest/batch are 32-byte hex.')
    _mode_range = models.Constraint(
        'CHECK(mode_flags >= 0 AND mode_flags <= 2147483647)', 'mode_flags is a non-negative int31.')

    @api.constrains('mode_flags')
    def _check_mode(self):
        for mtx in self:
            if not eip712.mode_is_valid(mtx.mode_flags):
                raise ValidationError(self.env._('Unknown mode bits: %s', hex(mtx.mode_flags)))

    def write(self, vals):
        if set(vals) - _MUTABLE:
            raise UserError(self.env._('A signed meta-transaction cannot be edited.'))
        return super().write(vals)

    def _message(self):
        self.ensure_one()
        return {
            'from': self.from_address, 'to': self.to_address, 'value': int(self.value_base),
            'data': bytes.fromhex(self.data_hex[2:]), 'batch': int(self.batch_hex, 16),
            'nonce': int(self.nonce_base), 'valid_until': self.valid_until_ts,
            'mode': self.mode_flags, 'relayer': self.relayer_address,
            'fee': int(self.fee_base), 'fee_recipient': self.fee_recipient_address,
        }
```

`dms_blockchain/models/blockchain_relay_job.py` (stub for this task):

```python
from odoo import fields, models


class BlockchainRelayJob(models.Model):
    _name = 'blockchain.relay.job'
    _description = 'Relay Job (outbox)'

    chain_id = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    signer_address = fields.Char(index=True)
    outer_nonce = fields.Integer()
```

`dms_blockchain/models/blockchain_payment_request.py` (stub so `blockchain.metatx.payment_request_id` resolves; Task 5 completes):

```python
from odoo import fields, models


class BlockchainPaymentRequest(models.Model):
    _name = 'blockchain.payment.request'
    _description = 'On-chain Payment Request'

    company_id = fields.Many2one('res.company', required=True, index=True)
```

`models/__init__.py`:

```python
from . import blockchain_chain
from . import blockchain_token
from . import blockchain_payment_request
from . import blockchain_metatx
from . import blockchain_relay_job
```

`dms_blockchain/security/blockchain_security.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <record id="module_category_blockchain" model="ir.module.category">
        <field name="name">Blockchain</field>
        <field name="sequence">60</field>
    </record>
    <!-- Odoo 19: groups hang off a privilege, not a category (TRAPS §9). -->
    <record id="res_groups_privilege_blockchain" model="res.groups.privilege">
        <field name="name">Blockchain</field>
        <field name="category_id" ref="module_category_blockchain"/>
    </record>

    <record id="group_blockchain_viewer" model="res.groups">
        <field name="name">Blockchain Viewer</field>
        <field name="privilege_id" ref="res_groups_privilege_blockchain"/>
        <field name="implied_ids" eval="[(4, ref('base.group_user'))]"/>
    </record>
    <record id="group_blockchain_operator" model="res.groups">
        <field name="name">Blockchain Operator</field>
        <field name="privilege_id" ref="res_groups_privilege_blockchain"/>
        <field name="implied_ids" eval="[(4, ref('group_blockchain_viewer'))]"/>
    </record>
    <record id="group_blockchain_manager" model="res.groups">
        <field name="name">Blockchain Manager</field>
        <field name="privilege_id" ref="res_groups_privilege_blockchain"/>
        <field name="implied_ids" eval="[(4, ref('group_blockchain_operator'))]"/>
    </record>
    <!-- Service accounts. Two groups, two users, two keys (canon §C14.1). -->
    <record id="group_blockchain_relay_worker" model="res.groups">
        <field name="name">Blockchain Relay Worker (service)</field>
        <field name="privilege_id" ref="res_groups_privilege_blockchain"/>
    </record>
    <record id="group_blockchain_indexer" model="res.groups">
        <field name="name">Blockchain Indexer (service)</field>
        <field name="privilege_id" ref="res_groups_privilege_blockchain"/>
    </record>

    <record id="rule_metatx_company" model="ir.rule">
        <field name="name">Meta-tx: own companies</field>
        <field name="model_id" ref="model_blockchain_metatx"/>
        <field name="domain_force">[('company_id', 'in', company_ids)]</field>
    </record>
</odoo>
```

(Task 3–5 append the rules for `relay.job`, `chain.event`, `payment.request`.)

`dms_blockchain/security/ir.model.access.csv`:

```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_chain_viewer,chain viewer,model_blockchain_chain,group_blockchain_viewer,1,0,0,0
access_chain_manager,chain manager,model_blockchain_chain,group_blockchain_manager,1,1,1,1
access_token_viewer,token viewer,model_blockchain_token,group_blockchain_viewer,1,0,0,0
access_token_manager,token manager,model_blockchain_token,group_blockchain_manager,1,1,1,1
access_metatx_operator,metatx operator,model_blockchain_metatx,group_blockchain_operator,1,0,0,0
access_relay_job_operator,relay job operator,model_blockchain_relay_job,group_blockchain_operator,1,0,0,0
access_payment_request_viewer,payment request viewer,model_blockchain_payment_request,group_blockchain_viewer,1,0,0,0
```

Service users get **no** ACL rows: their methods `check_service` then `sudo()`.

`dms_blockchain/data/blockchain_chain_data.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo noupdate="1">
    <record id="data_chain_private9000" model="blockchain.chain">
        <field name="name">Private EVM 9000</field>
        <field name="evm_chain_number">9000</field>
        <field name="native_currency">TOKEN9000</field>
        <field name="finality_mode">depth</field>
        <field name="finality_depth">1</field>
        <field name="finality_quorum">1</field>
    </record>
    <record id="data_chain_gnosis" model="blockchain.chain">
        <field name="name">Gnosis Chain</field>
        <field name="evm_chain_number">100</field>
        <field name="native_currency">xDAI</field>
        <field name="finality_mode">tag</field>
        <field name="finality_depth">0</field>
        <field name="finality_quorum">2</field>
        <field name="public_rpc_url">https://rpc.gnosischain.com</field>
    </record>
    <record id="data_chain_celo" model="blockchain.chain">
        <field name="name">Celo</field>
        <field name="evm_chain_number">42220</field>
        <field name="native_currency">CELO</field>
        <field name="finality_mode">tag</field>
        <field name="finality_depth">0</field>
        <field name="finality_quorum">2</field>
    </record>
</odoo>
```

`dms_blockchain/views/blockchain_views.xml` — list + form for chain, token, metatx (read-only), and a top menu (relay job, event, request views added in their tasks):

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <record id="view_chain_list" model="ir.ui.view">
        <field name="name">blockchain.chain.list</field>
        <field name="model">blockchain.chain</field>
        <field name="arch" type="xml">
            <list>
                <field name="evm_chain_number"/>
                <field name="name"/>
                <field name="state"/>
                <field name="finality_mode"/>
                <field name="finality_depth"/>
                <field name="finality_quorum"/>
                <field name="indexed_block"/>
            </list>
        </field>
    </record>
    <record id="view_chain_form" model="ir.ui.view">
        <field name="name">blockchain.chain.form</field>
        <field name="model">blockchain.chain</field>
        <field name="arch" type="xml">
            <form>
                <header><field name="state" widget="statusbar" options="{'clickable': '1'}"/></header>
                <sheet>
                    <group>
                        <group>
                            <field name="name"/>
                            <field name="evm_chain_number"/>
                            <field name="caip2"/>
                            <field name="native_currency"/>
                            <field name="public_rpc_url"/>
                        </group>
                        <group>
                            <field name="finality_mode"/>
                            <field name="finality_depth"/>
                            <field name="finality_quorum"/>
                            <field name="indexed_block"/>
                        </group>
                    </group>
                    <field name="token_ids">
                        <list><field name="symbol"/><field name="address"/><field name="decimals"/><field name="currency_id"/></list>
                    </field>
                </sheet>
                <chatter/>
            </form>
        </field>
    </record>
    <record id="view_token_list" model="ir.ui.view">
        <field name="name">blockchain.token.list</field>
        <field name="model">blockchain.token</field>
        <field name="arch" type="xml">
            <list>
                <field name="chain_id"/>
                <field name="symbol"/>
                <field name="name"/>
                <field name="address"/>
                <field name="decimals"/>
                <field name="currency_id"/>
                <field name="active" column_invisible="1"/>
            </list>
        </field>
    </record>
    <record id="view_token_form" model="ir.ui.view">
        <field name="name">blockchain.token.form</field>
        <field name="model">blockchain.token</field>
        <field name="arch" type="xml">
            <form>
                <sheet>
                    <group>
                        <group>
                            <field name="chain_id"/>
                            <field name="address"/>
                            <field name="name"/>
                            <field name="symbol"/>
                            <field name="decimals"/>
                        </group>
                        <group>
                            <field name="currency_id"/>
                            <field name="domain_name"/>
                            <field name="domain_version"/>
                            <field name="active"/>
                        </group>
                    </group>
                </sheet>
                <chatter/>
            </form>
        </field>
    </record>
    <record id="view_metatx_list" model="ir.ui.view">
        <field name="name">blockchain.metatx.list</field>
        <field name="model">blockchain.metatx</field>
        <field name="arch" type="xml">
            <list create="0" edit="0" delete="0">
                <field name="create_date"/>
                <field name="token_id"/>
                <field name="from_address"/>
                <field name="to_address"/>
                <field name="value_base"/>
                <field name="metatx_state"/>
                <field name="signature_verified"/>
                <field name="executed_tx_hash"/>
            </list>
        </field>
    </record>

    <record id="action_chain" model="ir.actions.act_window">
        <field name="name">Chains</field>
        <field name="res_model">blockchain.chain</field>
        <field name="view_mode">list,form</field>
    </record>
    <record id="action_token" model="ir.actions.act_window">
        <field name="name">Tokens</field>
        <field name="res_model">blockchain.token</field>
        <field name="view_mode">list,form</field>
    </record>
    <record id="action_metatx" model="ir.actions.act_window">
        <field name="name">Signed Meta-Transactions</field>
        <field name="res_model">blockchain.metatx</field>
        <field name="view_mode">list,form</field>
    </record>

    <menuitem id="menu_blockchain_root" name="Blockchain" sequence="80"
              groups="group_blockchain_viewer"/>
    <menuitem id="menu_blockchain_operations" name="Operations" parent="menu_blockchain_root" sequence="10"/>
    <menuitem id="menu_blockchain_config" name="Configuration" parent="menu_blockchain_root" sequence="90"
              groups="group_blockchain_manager"/>
    <menuitem id="menu_blockchain_metatx" action="action_metatx" parent="menu_blockchain_operations"
              sequence="30" groups="group_blockchain_operator"/>
    <menuitem id="menu_blockchain_chain" action="action_chain" parent="menu_blockchain_config" sequence="10"/>
    <menuitem id="menu_blockchain_token" action="action_token" parent="menu_blockchain_config" sequence="20"/>
</odoo>
```

Manifest `data`: `['security/blockchain_security.xml', 'security/ir.model.access.csv', 'data/blockchain_chain_data.xml', 'views/blockchain_views.xml']`. `tests/__init__.py` adds `test_models`.

- [ ] **Step 4: Run to verify it passes**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: `0 failed, 0 error(s)`.

- [ ] **Step 5: Commit**

```bash
git add dms_blockchain
git commit -m "feat(blockchain): chain, token and immutable signed meta-tx models with service gate"
```

---

### Task 3: Relay outbox — `relay_poll`, `relay_claim`, `relay_report`, expiry cron

**Files:**
- Modify: `dms_blockchain/models/blockchain_relay_job.py` (replace stub), `security/blockchain_security.xml` (rule), `security/ir.model.access.csv`, `views/blockchain_views.xml`, `__manifest__.py` (`data/ir_cron.xml`)
- Create: `dms_blockchain/data/ir_cron.xml`, `dms_blockchain/tests/test_relay_job.py`

**Interfaces:**
- Consumes: `check_service`, `blockchain.chain._active`, `blockchain.metatx._message()`.
- Produces: `blockchain.relay.job` fields `company_id chain_id metatx_id origin_producer origin_key chain_state business_state claimed_by claimed_datetime signer_address tx_hash outer_nonce attempt_count last_error`; `relay_poll(evm_chain_number, limit=10) -> list[dict]` with keys `id, token, metatx{from,to,value,data,batch,nonce,validUntil,mode,relayer,fee,feeRecipient}, signature, digest`; `relay_claim(job_ids, worker) -> list[int]`; `relay_report(job_id, chain_state, tx_hash=None, outer_nonce=None, signer_address=None, error=None) -> dict`; `_mark_executed(tx_hash)` (used by ingest); `_cron_expire()`; `TRANSITIONS` dict.

- [ ] **Step 1: Failing tests** — `dms_blockchain/tests/test_relay_job.py`:

```python
from odoo.exceptions import AccessError, UserError
from odoo.tests.common import tagged

from .test_models import ChainCase


@tagged('post_install', '-at_install')
class TestRelayJob(ChainCase):

    def setUp(self):
        super().setUp()
        self.mtx = self.env['blockchain.metatx'].create(self._metatx_vals())
        self.job = self.env['blockchain.relay.job'].create({
            'company_id': self.env.company.id, 'chain_id': self.chain.id,
            'metatx_id': self.mtx.id, 'origin_producer': 'test', 'origin_key': 'k1'})
        self.Job = self.env['blockchain.relay.job'].with_user(self.relay_user)

    def test_poll_returns_the_struct_as_strings(self):
        [row] = self.Job.relay_poll(9001)
        self.assertEqual(row['id'], self.job.id)
        self.assertEqual(row['token'], self.token.address)
        self.assertEqual(row['metatx']['value'], '100')
        self.assertEqual(row['metatx']['batch'], str(7))
        self.assertEqual(row['metatx']['validUntil'], '1800000300')
        self.assertEqual(row['signature'], '0x' + '44' * 65)

    def test_poll_and_report_are_service_only(self):
        with self.assertRaises(AccessError):
            self.env['blockchain.relay.job'].with_user(self.plain_user).relay_poll(9001)
        with self.assertRaises(AccessError):
            self.env['blockchain.relay.job'].with_user(self.indexer_user).relay_claim([self.job.id], 'n')

    def test_claim_is_compare_and_set(self):
        self.assertEqual(self.Job.relay_claim([self.job.id], 'node-a'), [self.job.id])
        self.assertEqual(self.Job.relay_claim([self.job.id], 'node-b'), [])
        self.assertEqual(self.job.chain_state, 'nonce_leased')
        self.assertEqual(self.job.claimed_by, 'node-a')
        self.assertEqual(self.Job.relay_poll(9001), [])

    def test_signed_then_broadcast_records_the_journal(self):
        self.Job.relay_claim([self.job.id], 'node-a')
        self.Job.relay_report(self.job.id, 'signed', tx_hash='0x' + 'aa' * 32,
                              outer_nonce=5, signer_address='0x' + 'BB' * 20)
        self.Job.relay_report(self.job.id, 'broadcast')
        self.assertEqual(self.job.outer_nonce, 5)
        self.assertEqual(self.job.signer_address, '0x' + 'bb' * 20)
        cfg = self.env['blockchain.chain'].with_user(self.relay_user).node_config(9001, '0x' + 'bb' * 20)
        self.assertEqual(cfg['journal_max_nonce'], 5)

    def test_transition_outside_the_table_is_refused(self):
        with self.assertRaises(UserError):
            self.Job.relay_report(self.job.id, 'final')
        with self.assertRaises(UserError):
            self.Job.relay_report(self.job.id, 'broadcast')

    def test_dead_fails_the_business_side(self):
        self.Job.relay_claim([self.job.id], 'node-a')
        self.Job.relay_report(self.job.id, 'dead', error='MetaTxInsufficientForFee(10, 1)')
        self.assertEqual(self.job.business_state, 'failed')
        self.assertEqual(self.mtx.metatx_state, 'failed')
        self.assertIn('Insufficient', self.mtx.last_error)

    def test_execution_overrides_dead(self):
        self.Job.relay_claim([self.job.id], 'node-a')
        self.Job.relay_report(self.job.id, 'dead', error='x')
        self.mtx._mark_executed('0x' + 'cc' * 32)
        self.assertEqual(self.job.chain_state, 'final')
        self.assertEqual(self.job.business_state, 'success')
        self.assertEqual(self.mtx.metatx_state, 'final')

    def test_final_is_absorbing(self):
        self.mtx._mark_executed('0x' + 'cc' * 32)
        with self.assertRaises(UserError):
            self.Job.relay_report(self.job.id, 'queued')

    def test_origin_key_is_unique(self):
        from psycopg2 import IntegrityError
        from odoo.tools import mute_logger
        with mute_logger('odoo.sql_db'), self.assertRaises(IntegrityError), self.cr.savepoint():
            self.env['blockchain.relay.job'].create({
                'company_id': self.env.company.id, 'chain_id': self.chain.id,
                'metatx_id': self.mtx.id, 'origin_producer': 'test', 'origin_key': 'k1'})
            self.env.flush_all()

    def test_cron_kills_expired_unclaimed_jobs(self):
        self.env['blockchain.relay.job']._cron_expire(now_ts=1_800_000_300 + 601)
        self.assertEqual(self.job.chain_state, 'dead')
        self.assertEqual(self.mtx.metatx_state, 'expired')

    def test_cron_leaves_broadcast_jobs_alone(self):
        self.Job.relay_claim([self.job.id], 'node-a')
        self.Job.relay_report(self.job.id, 'signed', tx_hash='0x' + 'aa' * 32, outer_nonce=1,
                              signer_address='0x' + 'bb' * 20)
        self.Job.relay_report(self.job.id, 'broadcast')
        self.env['blockchain.relay.job']._cron_expire(now_ts=1_800_000_300 + 601)
        self.assertEqual(self.job.chain_state, 'broadcast')
```

- [ ] **Step 2: Run to verify it fails**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: errors — `relay_poll` / `_mark_executed` missing.

- [ ] **Step 3: Implement** — replace `blockchain_relay_job.py`:

```python
import time

from odoo import api, fields, models
from odoo.exceptions import UserError

from ..lib.eip712 import norm_address
from .blockchain_chain import check_service

CHAIN_STATES = [
    ('queued', 'Queued'), ('nonce_leased', 'Claimed'), ('signed', 'Signed'),
    ('broadcast', 'Broadcast'), ('mined', 'Mined'), ('final', 'Final'),
    ('reverted', 'Reverted'), ('dead', 'Dead'),
]
# Bảng chuyển trạng thái do node báo (spec §4.3). `final` KHÔNG có ở đây: chỉ indexer.
TRANSITIONS = {
    'nonce_leased': {'queued', 'signed', 'dead'},
    'signed': {'broadcast', 'queued'},
    'broadcast': {'mined', 'reverted', 'broadcast', 'queued'},
    'mined': {'reverted'},
}
_EXPIRY_GRACE = 600


class BlockchainRelayJob(models.Model):
    """Outbox (canon §C10.8): dòng `queued` CHÍNH LÀ bản ghi outbox, ghi cùng transaction
    với nghiệp vụ. Hai vòng đời: `chain_state` và `business_state` — không có `state` trần."""
    _name = 'blockchain.relay.job'
    _description = 'Relay Job (outbox)'
    _order = 'id desc'

    company_id = fields.Many2one('res.company', required=True, index=True)
    chain_id = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    metatx_id = fields.Many2one('blockchain.metatx', required=True, index=True, ondelete='restrict')
    origin_producer = fields.Char(required=True)
    origin_key = fields.Char(required=True)
    chain_state = fields.Selection(CHAIN_STATES, default='queued', required=True, index=True)
    business_state = fields.Selection(
        [('pending', 'Pending'), ('success', 'Success'), ('failed', 'Failed')],
        default='pending', required=True, index=True)
    claimed_by = fields.Char()
    claimed_datetime = fields.Datetime()
    signer_address = fields.Char(index=True, help='Outer-transaction signer (the relayer wallet).')
    tx_hash = fields.Char(index=True)
    outer_nonce = fields.Integer()
    attempt_count = fields.Integer(default=0)
    last_error = fields.Char()

    _unique_origin = models.Constraint(
        'UNIQUE(company_id, origin_producer, origin_key)',
        'origin_key is the idempotency key within (company, producer).')

    # ------------------------------------------------------------------ RPC (node)

    @api.model
    def relay_poll(self, evm_chain_number, limit=10):
        """POST /json/2/blockchain.relay.job/relay_poll"""
        check_service(self.env, 'relay_worker')
        chain = self.env['blockchain.chain']._active(evm_chain_number)
        jobs = self.sudo().search([('chain_id', '=', chain.id), ('chain_state', '=', 'queued')],
                                  order='id', limit=max(1, min(int(limit), 50)))
        return [job._payload() for job in jobs]

    @api.model
    def relay_claim(self, job_ids, worker):
        """POST /json/2/blockchain.relay.job/relay_claim — compare-and-set queued→nonce_leased.

        Row lock SKIP LOCKED + ghi qua ORM trong cùng transaction RPC: không giữ lock qua
        một lời gọi HTTP nào (ruling R6)."""
        check_service(self.env, 'relay_worker')
        ids = [int(i) for i in job_ids]
        self.env.cr.execute(
            "SELECT id FROM blockchain_relay_job WHERE id = ANY(%s) AND chain_state = 'queued' "
            'FOR UPDATE SKIP LOCKED', (ids,))
        claimable = self.sudo().browse([r[0] for r in self.env.cr.fetchall()])
        claimable.write({'chain_state': 'nonce_leased', 'claimed_by': str(worker)[:64],
                         'claimed_datetime': fields.Datetime.now()})
        for job in claimable:
            job.attempt_count += 1
        return claimable.ids

    @api.model
    def relay_report(self, job_id, chain_state, tx_hash=None, outer_nonce=None,
                     signer_address=None, error=None):
        """POST /json/2/blockchain.relay.job/relay_report"""
        check_service(self.env, 'relay_worker')
        job = self.sudo().browse(int(job_id)).exists()
        if not job:
            raise UserError(self.env._('Unknown relay job %s.', job_id))
        return job._apply_report(chain_state, tx_hash, outer_nonce, signer_address, error)

    # ------------------------------------------------------------------ private

    def _payload(self):
        self.ensure_one()
        m = self.metatx_id._message()
        return {
            'id': self.id,
            'token': self.metatx_id.token_id.address,
            'digest': self.metatx_id.digest_hash,
            'signature': self.metatx_id.signature_hex,
            'metatx': {
                'from': m['from'], 'to': m['to'], 'value': str(m['value']),
                'data': '0x' + m['data'].hex(), 'batch': str(m['batch']),
                'nonce': str(m['nonce']), 'validUntil': str(m['valid_until']),
                'mode': m['mode'], 'relayer': m['relayer'], 'fee': str(m['fee']),
                'feeRecipient': m['fee_recipient'],
            },
        }

    def _apply_report(self, chain_state, tx_hash, outer_nonce, signer_address, error):
        self.ensure_one()
        allowed = TRANSITIONS.get(self.chain_state, set())
        if chain_state not in allowed:
            raise UserError(self.env._('Transition %(a)s -> %(b)s is not allowed.',
                                       a=self.chain_state, b=chain_state))
        vals = {'chain_state': chain_state}
        if tx_hash:
            vals['tx_hash'] = tx_hash.lower()
        if outer_nonce is not None:
            vals['outer_nonce'] = int(outer_nonce)
        if signer_address:
            vals['signer_address'] = norm_address(signer_address)
        if error:
            vals['last_error'] = str(error)[:500]
        if chain_state == 'queued':
            vals.update(claimed_by=False, claimed_datetime=False, tx_hash=False)
        if chain_state == 'dead':
            vals['business_state'] = 'failed'
            self.metatx_id.write({'metatx_state': 'failed', 'last_error': vals.get('last_error')})
        self.write(vals)
        return {'id': self.id, 'chain_state': self.chain_state}

    @api.model
    def _cron_expire(self, now_ts=None):
        """Job chưa ai ký vỏ mà chữ ký đã hết hạn + ân hạn ⇒ `dead`. Job đã ký/broadcast
        để nguyên: node vẫn đang theo dõi nonce của nó (không bỏ nonce, R18)."""
        now_ts = now_ts or int(time.time())
        jobs = self.sudo().search([
            ('chain_state', 'in', ('queued', 'nonce_leased')),
            ('metatx_id.valid_until_ts', '<', now_ts - _EXPIRY_GRACE),
        ])
        jobs.write({'chain_state': 'dead', 'business_state': 'failed',
                    'last_error': 'signature expired before relay'})
        jobs.metatx_id.filtered(lambda m: m.metatx_state == 'signed').write(
            {'metatx_state': 'expired'})
```

Add to `blockchain_metatx.py` (class body):

```python
    relay_job_ids = fields.One2many('blockchain.relay.job', 'metatx_id')

    def _mark_executed(self, tx_hash):
        """Duy nhất từ indexer: meta-tx đã thực thi và đã final. Hút mọi trạng thái job."""
        for mtx in self:
            mtx.write({'metatx_state': 'final', 'executed_tx_hash': tx_hash.lower()})
            mtx.relay_job_ids.write({'chain_state': 'final', 'business_state': 'success'})
```

`dms_blockchain/data/ir_cron.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo noupdate="1">
    <record id="cron_expire_relay_job" model="ir.cron">
        <field name="name">Blockchain: expire unrelayed jobs</field>
        <field name="model_id" ref="model_blockchain_relay_job"/>
        <field name="state">code</field>
        <field name="code">model._cron_expire()</field>
        <field name="interval_number">5</field>
        <field name="interval_type">minutes</field>
    </record>
</odoo>
```

Rule (append to security XML):

```xml
    <record id="rule_relay_job_company" model="ir.rule">
        <field name="name">Relay job: own companies</field>
        <field name="model_id" ref="model_blockchain_relay_job"/>
        <field name="domain_force">[('company_id', 'in', company_ids)]</field>
    </record>
```

Views (append): list `view_relay_job_list` (`create_date, chain_id, chain_state, business_state, tx_hash, outer_nonce, attempt_count, last_error`), action `action_relay_job`, menu under Operations sequence 20, groups operator; plus a server action button-free `action_requeue` method:

```python
    def action_requeue(self):
        """Operator: đưa job `dead`/`reverted` về hàng đợi nếu chữ ký còn hạn."""
        for job in self:
            if job.chain_state not in ('dead', 'reverted'):
                raise UserError(self.env._('Only dead or reverted jobs can be requeued.'))
            if job.metatx_id.valid_until_ts <= int(time.time()):
                raise UserError(self.env._('The signature has expired; ask the payer to sign again.'))
            job.write({'chain_state': 'queued', 'business_state': 'pending',
                       'claimed_by': False, 'tx_hash': False})
            job.metatx_id.write({'metatx_state': 'signed'})
```

with `<button name="action_requeue" type="object" string="Requeue" groups="dms_blockchain.group_blockchain_operator"/>` in the list header. Operator needs write on the job for the button: add CSV row `access_relay_job_operator` perms `1,1,0,0`.

- [ ] **Step 4: Run to verify it passes**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: `0 failed, 0 error(s)`.

- [ ] **Step 5: Commit**

```bash
git add dms_blockchain
git commit -m "feat(blockchain): relay outbox with CAS claim, transition table and expiry cron"
```

---

### Task 4: Chain events — `chain_event_ingest`

**Files:**
- Create: `dms_blockchain/models/blockchain_chain_event.py`, `dms_blockchain/tests/test_ingest.py`
- Modify: `models/__init__.py`, security XML/CSV (rule + viewer read), views (list + menu)

**Interfaces:**
- Consumes: `blockchain.metatx._mark_executed`, `blockchain.payment.request._apply_events(events)` (Task 5; in this task a no-op stub method on the request stub).
- Produces: `blockchain.chain.event` fields `chain_id company_id contract_address event_name block_number block_hash tx_hash log_index from_address to_address value_base fee_base fee_recipient_address entry_ref_hex digest_hash payment_request_id`; `chain_event_ingest(evm_chain_number, from_block, to_block, to_block_hash, events) -> {'indexed_block': int, 'created': int}`. Event dict keys from the node: `event` (`MetaTransactionExecuted`|`PaymentSettled`), `contract`, `block_number`, `block_hash`, `tx_hash`, `log_index`, and per event: `from, relayer, batch, nonce, digest, fee_recipient, fee` (executed) or `from, to, amount, fee, fee_recipient, entry_ref` (payment).

- [ ] **Step 1: Failing tests** — `dms_blockchain/tests/test_ingest.py`:

```python
from odoo.exceptions import AccessError, UserError
from odoo.tests.common import tagged

from .test_models import ChainCase


@tagged('post_install', '-at_install')
class TestIngest(ChainCase):

    def _executed(self, digest, log_index=0, contract=None, block=5):
        return {'event': 'MetaTransactionExecuted', 'contract': contract or self.token.address,
                'block_number': block, 'block_hash': '0x' + '0b' * 32, 'tx_hash': '0x' + 'e1' * 32,
                'log_index': log_index, 'from': '0x' + 'ab' * 20, 'relayer': '0x' + '02' * 20,
                'batch': '7', 'nonce': '0', 'digest': digest, 'fee_recipient': '0x' + '02' * 20,
                'fee': '0'}

    def _ingest(self, frm, to, events, user=None):
        return self.env['blockchain.chain.event'].with_user(user or self.indexer_user) \
            .chain_event_ingest(9001, frm, to, '0x' + '0b' * 32, events)

    def test_ingest_is_indexer_only(self):
        with self.assertRaises(AccessError):
            self._ingest(1, 5, [], user=self.relay_user)

    def test_cursor_must_be_contiguous(self):
        with self.assertRaises(UserError):
            self._ingest(2, 5, [])
        self.assertEqual(self._ingest(1, 5, [])['indexed_block'], 5)
        self.assertEqual(self.chain.indexed_block, 5)

    def test_replayed_range_is_a_noop_not_a_gap(self):
        self._ingest(1, 5, [self._executed('0x' + '33' * 32)])
        again = self._ingest(1, 5, [self._executed('0x' + '33' * 32)])
        self.assertEqual(again, {'indexed_block': 5, 'created': 0})
        self.assertEqual(self.env['blockchain.chain.event'].search_count([]), 1)

    def test_execution_finalizes_metatx_and_job(self):
        mtx = self.env['blockchain.metatx'].create(self._metatx_vals())
        job = self.env['blockchain.relay.job'].create({
            'company_id': self.env.company.id, 'chain_id': self.chain.id, 'metatx_id': mtx.id,
            'origin_producer': 't', 'origin_key': 'k'})
        self._ingest(1, 5, [self._executed(mtx.digest_hash)])
        self.assertEqual(mtx.metatx_state, 'final')
        self.assertEqual(mtx.executed_tx_hash, '0x' + 'e1' * 32)
        self.assertEqual(job.chain_state, 'final')

    def test_event_from_unregistered_contract_is_refused(self):
        with self.assertRaises(UserError):
            self._ingest(1, 5, [self._executed('0x' + '33' * 32, contract='0x' + '99' * 20)])
        self.assertEqual(self.chain.indexed_block, 0)

    def test_event_outside_the_range_is_refused(self):
        with self.assertRaises(UserError):
            self._ingest(1, 5, [self._executed('0x' + '33' * 32, block=6)])

    def test_unknown_event_name_is_refused(self):
        bad = dict(self._executed('0x' + '33' * 32), event='Transfer')
        with self.assertRaises(UserError):
            self._ingest(1, 5, [bad])

    def test_unique_key_exists(self):
        self.env.cr.execute("SELECT conname FROM pg_constraint WHERE conrelid = 'blockchain_chain_event'::regclass")
        self.assertIn('blockchain_chain_event_chain_tx_log_uniq', {r[0] for r in self.env.cr.fetchall()})
```

- [ ] **Step 2: Run to verify it fails**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: `KeyError: 'blockchain.chain.event'`.

- [ ] **Step 3: Implement** — `blockchain_chain_event.py`:

```python
from odoo import api, fields, models
from odoo.exceptions import UserError

from ..lib.eip712 import norm_address
from .blockchain_chain import check_service

EVENTS = ('MetaTransactionExecuted', 'PaymentSettled')


def _hex32(v, what):
    v = (v or '').lower()
    if len(v) != 66 or not v.startswith('0x') or any(c not in '0123456789abcdef' for c in v[2:]):
        raise UserError(f'{what} is not 32-byte hex: {v!r}')
    return v


def _uint(v, what):
    s = str(v)
    if not s.isdigit() or (len(s) > 1 and s[0] == '0') or len(s) > 78:
        raise UserError(f'{what} is not a uint256: {v!r}')
    return s


class BlockchainChainEvent(models.Model):
    """Log đã FINAL, đã giải mã. Chỉ indexer ghi, chỉ qua `chain_event_ingest` (spec §3.3)."""
    _name = 'blockchain.chain.event'
    _description = 'Finalized Chain Event'
    _order = 'block_number desc, log_index desc'
    _rec_name = 'tx_hash'

    chain_id = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    company_id = fields.Many2one('res.company', index=True)
    contract_address = fields.Char(required=True, index=True)
    event_name = fields.Selection([(e, e) for e in EVENTS], required=True, index=True)
    block_number = fields.Integer(required=True, index=True)
    block_hash = fields.Char(required=True)
    tx_hash = fields.Char(required=True, index=True)
    log_index = fields.Integer(required=True)
    from_address = fields.Char(index=True)
    to_address = fields.Char(index=True)
    value_base = fields.Char()
    fee_base = fields.Char()
    fee_recipient_address = fields.Char()
    entry_ref_hex = fields.Char(index=True)
    digest_hash = fields.Char(index=True)
    payment_request_id = fields.Many2one('blockchain.payment.request', index=True)

    _chain_tx_log_uniq = models.Constraint(
        'UNIQUE(chain_id, tx_hash, log_index)', 'One row per log.')

    @api.model
    def chain_event_ingest(self, evm_chain_number, from_block, to_block, to_block_hash, events):
        """POST /json/2/blockchain.chain.event/chain_event_ingest — indexer only.

        Một transaction: ghi event, áp tác dụng, tiến cursor. Lô đã ingest rồi (node crash
        sau khi Odoo commit) trả về cursor hiện tại, không lỗi."""
        check_service(self.env, 'indexer')
        chain = self.env['blockchain.chain']._active(evm_chain_number)
        self.env.cr.execute('SELECT indexed_block FROM blockchain_chain WHERE id = %s FOR UPDATE',
                            (chain.id,))
        indexed = self.env.cr.fetchone()[0]
        from_block, to_block = int(from_block), int(to_block)
        if to_block <= indexed:
            return {'indexed_block': indexed, 'created': 0}
        if from_block != indexed + 1 or to_block < from_block:
            raise UserError(self.env._('Cursor gap: expected block %(e)s, got %(g)s.',
                                       e=indexed + 1, g=from_block))
        _hex32(to_block_hash, 'to_block_hash')
        tokens = {t.address: t for t in chain.token_ids}
        rows = [self._decode(chain, tokens, ev, from_block, to_block) for ev in events]
        created = self.sudo().create(rows) if rows else self.sudo()
        created._apply()
        chain.sudo().write({'indexed_block': to_block})
        return {'indexed_block': to_block, 'created': len(created)}

    @api.model
    def _decode(self, chain, tokens, ev, from_block, to_block):
        name = ev.get('event')
        if name not in EVENTS:
            raise UserError(self.env._('Unknown event %s.', name))
        contract = norm_address(ev.get('contract'))
        if contract not in tokens:
            raise UserError(self.env._('Event from an unregistered contract %s.', contract))
        block = int(ev['block_number'])
        if not from_block <= block <= to_block:
            raise UserError(self.env._('Event block %s outside the ingested range.', block))
        vals = {
            'chain_id': chain.id, 'contract_address': contract, 'event_name': name,
            'block_number': block, 'block_hash': _hex32(ev['block_hash'], 'block_hash'),
            'tx_hash': _hex32(ev['tx_hash'], 'tx_hash'), 'log_index': int(ev['log_index']),
            'from_address': norm_address(ev['from']),
            'fee_base': _uint(ev.get('fee', '0'), 'fee'),
            'fee_recipient_address': norm_address(ev['fee_recipient']),
        }
        if name == 'MetaTransactionExecuted':
            vals['digest_hash'] = _hex32(ev['digest'], 'digest')
        else:
            vals.update(to_address=norm_address(ev['to']),
                        value_base=_uint(ev['amount'], 'amount'),
                        entry_ref_hex=_hex32(ev['entry_ref'], 'entry_ref'))
        return vals

    def _apply(self):
        executed = self.filtered(lambda e: e.event_name == 'MetaTransactionExecuted')
        for ev in executed:
            mtx = self.env['blockchain.metatx'].sudo().search(
                [('chain_id', '=', ev.chain_id.id), ('digest_hash', '=', ev.digest_hash)], limit=1)
            if mtx:
                ev.company_id = mtx.company_id
                mtx._mark_executed(ev.tx_hash)
        payments = self - executed
        if payments:
            self.env['blockchain.payment.request'].sudo()._apply_events(payments)
```

Uniqueness vs replay: a replayed range returns early before `create`, so the UNIQUE never fires on the happy path; it is the backstop for a buggy indexer that sends overlapping ranges.

Stub in `blockchain_payment_request.py` (until Task 5):

```python
    def _apply_events(self, events):
        return
```

Security: rule `rule_chain_event_company` with domain `['|', ('company_id', '=', False), ('company_id', 'in', company_ids)]`; CSV `access_chain_event_viewer,chain event viewer,model_blockchain_chain_event,group_blockchain_viewer,1,0,0,0`. View: list (`block_number, event_name, contract_address, from_address, to_address, value_base, entry_ref_hex, tx_hash, payment_request_id`), action, menu (Operations, sequence 40).

- [ ] **Step 4: Run to verify it passes**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: `0 failed, 0 error(s)`.

- [ ] **Step 5: Commit**

```bash
git add dms_blockchain
git commit -m "feat(blockchain): finalized event ingest with contiguous, idempotent cursor"
```

---

### Task 5: Payment request — settlement sum, gate, hooks, signature acceptance, expiry

**Files:**
- Modify (replace stub): `dms_blockchain/models/blockchain_payment_request.py`; security/CSV/views; `data/ir_cron.xml`
- Create: `dms_blockchain/tests/test_payment_request.py`

**Interfaces:**
- Consumes: `eip712.*`, `ecrecover`, `blockchain.token._domain()`, relay job model.
- Produces: `blockchain.payment.request` fields per spec §4.2 (`request_uuid company_id chain_id token_id receiving_address relayer_address payer_address amount_base amount_settled_base entry_ref_hex batch_hex issued_valid_until expiry_datetime request_state needs_attention attention_note res_model res_id metatx_ids event_ids`); `_open_request(token, receiving_address, relayer_address, payer_address, amount_base, company, res_model, res_id, validity_hours=24)`; `_issue(validity_seconds) -> typed_data dict` (sets `issued_valid_until`); `_message(valid_until) -> dict`; `_accept_signature(valid_until, signature_hex) -> blockchain.metatx`; `_live_job()`; hooks `_on_paid()`, `_on_expired()`; `_apply_events(events)`; `_cron_expire(now=None)`.

- [ ] **Step 1: Failing tests** — `dms_blockchain/tests/test_payment_request.py`:

```python
import time
from unittest.mock import patch

from odoo.exceptions import UserError
from odoo.tests.common import tagged

from ..lib import eip712
from ..lib.secp256k1 import G, N, _mul
from ..lib.keccak import keccak256
from .test_models import ChainCase

PK = 0xA11CE


def _addr(pk):
    q = _mul(pk, G)
    return '0x' + keccak256(q[0].to_bytes(32, 'big') + q[1].to_bytes(32, 'big'))[-20:].hex()


def _sign(pk, digest):
    """RFC6979 không cần cho test: k cố định khác nhau theo digest là đủ (không bao giờ dùng ở prod)."""
    z = int.from_bytes(digest, 'big')
    k = int.from_bytes(keccak256(pk.to_bytes(32, 'big') + digest), 'big') % N
    rp = _mul(k, G)
    r = rp[0] % N
    s = pow(k, -1, N) * (z + r * pk) % N
    v = rp[1] & 1
    if s > N // 2:
        s, v = N - s, v ^ 1
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + v])


@tagged('post_install', '-at_install')
class TestPaymentRequest(ChainCase):

    def setUp(self):
        super().setUp()
        self.payer = _addr(PK)
        self.req = self.env['blockchain.payment.request']._open_request(
            token=self.token, receiving_address='0x' + '5e' * 20,
            relayer_address='0x' + '02' * 20, payer_address=self.payer,
            amount_base=250_000_000, company=self.env.company,
            res_model='res.partner', res_id=self.env.user.partner_id.id)

    def _settle(self, amount, to=None, ref=None, log_index=0, frm=None, block=None):
        block = block or self.chain.indexed_block + 1
        ev = {'event': 'PaymentSettled', 'contract': self.token.address, 'block_number': block,
              'block_hash': '0x' + '0b' * 32, 'tx_hash': '0x' + f'{log_index + 1:02x}' * 32,
              'log_index': log_index, 'from': frm or self.payer, 'to': to or self.req.receiving_address,
              'amount': str(amount), 'fee': '0', 'fee_recipient': '0x' + '02' * 20,
              'entry_ref': ref or self.req.entry_ref_hex}
        return self.env['blockchain.chain.event'].with_user(self.indexer_user).chain_event_ingest(
            9001, block, block, '0x' + '0b' * 32, [ev])

    def test_entry_ref_is_random_and_lane_derived(self):
        other = self.env['blockchain.payment.request']._open_request(
            token=self.token, receiving_address='0x' + '5e' * 20, relayer_address='0x' + '02' * 20,
            payer_address=self.payer, amount_base=1, company=self.env.company,
            res_model='res.partner', res_id=1)
        self.assertNotEqual(self.req.entry_ref_hex, other.entry_ref_hex)
        ref = bytes.fromhex(self.req.entry_ref_hex[2:])
        self.assertEqual(int(self.req.batch_hex, 16), eip712.lane_batch(ref))

    def test_issue_builds_the_pay_message(self):
        td = self.req._issue(300)
        msg = td['message']
        self.assertEqual(msg['value'], '250000000')
        self.assertEqual(msg['nonce'], '0')
        self.assertEqual(msg['mode'], eip712.MODE_RESTRICT_RELAYER)
        self.assertEqual(msg['relayer'], '0x' + '02' * 20)
        self.assertEqual(msg['data'], '0x' + (eip712.OP_PAY + bytes.fromhex(self.req.entry_ref_hex[2:])).hex())
        self.assertEqual(int(msg['validUntil']), self.req.issued_valid_until)

    def test_accept_signature_writes_metatx_and_outbox_together(self):
        self.req._issue(300)
        vu = self.req.issued_valid_until
        dg = eip712.digest(self.token._domain(), self.req._message(vu))
        mtx = self.req._accept_signature(vu, '0x' + _sign(PK, dg).hex())
        self.assertTrue(mtx.signature_verified)
        self.assertEqual(mtx.digest_hash, '0x' + dg.hex())
        self.assertEqual(mtx.relay_job_ids.chain_state, 'queued')

    def test_valid_until_must_be_the_issued_one(self):
        self.req._issue(300)
        with self.assertRaises(UserError):
            self.req._accept_signature(self.req.issued_valid_until + 60, '0x' + '00' * 65)

    def test_wrong_signer_is_refused(self):
        self.req._issue(300)
        vu = self.req.issued_valid_until
        dg = eip712.digest(self.token._domain(), self.req._message(vu))
        with self.assertRaises(UserError):
            self.req._accept_signature(vu, '0x' + _sign(PK + 1, dg).hex())

    def test_non_recoverable_signature_is_kept_unverified(self):
        self.req._issue(300)
        mtx = self.req._accept_signature(self.req.issued_valid_until, '0x' + 'ab' * 100)
        self.assertFalse(mtx.signature_verified)

    def test_only_one_live_job_per_request(self):
        self.req._issue(300)
        self.req._accept_signature(self.req.issued_valid_until, '0x' + 'ab' * 100)
        self.req._issue(300)
        with self.assertRaises(UserError):
            self.req._accept_signature(self.req.issued_valid_until, '0x' + 'cd' * 100)

    def test_partial_then_final_and_gate_runs_once(self):
        calls = []
        with patch.object(type(self.req), '_on_paid', lambda rec: calls.append(rec.id)):
            self._settle(100_000_000)
            self.assertEqual(self.req.request_state, 'partial')
            self._settle(150_000_000, log_index=1)
            self.assertEqual(self.req.request_state, 'final')
            self._settle(1, log_index=2)
        self.assertEqual(calls, [self.req.id])
        self.assertTrue(self.req.needs_attention)          # overpaid by 1

    def test_payment_to_another_address_does_not_count(self):
        self._settle(250_000_000, to='0x' + '77' * 20)
        self.assertEqual(self.req.amount_settled_base, '0')
        self.assertEqual(self.req.request_state, 'open')

    def test_unknown_entry_ref_is_recorded_unmatched(self):
        self._settle(5, ref='0x' + '99' * 32)
        ev = self.env['blockchain.chain.event'].search([('entry_ref_hex', '=', '0x' + '99' * 32)])
        self.assertTrue(ev)
        self.assertFalse(ev.payment_request_id)

    def test_a_failing_hook_does_not_roll_back_ingest(self):
        def boom(rec):
            raise UserError('period closed')
        with patch.object(type(self.req), '_on_paid', boom):
            self._settle(250_000_000)
        self.assertEqual(self.req.request_state, 'final')
        self.assertTrue(self.req.needs_attention)
        self.assertIn('period closed', self.req.attention_note)
        self.assertEqual(self.chain.indexed_block, 1)

    def test_cron_expires_only_without_live_signature(self):
        """expiry = create + 24 h; chữ ký sống tới create + 26 h (+1 h ân hạn finality)."""
        self.req._issue(26 * 3600)
        self.req._accept_signature(self.req.issued_valid_until, '0x' + 'ab' * 100)
        at_expiry = self.req.expiry_datetime + timedelta(minutes=1)
        self.env['blockchain.payment.request']._cron_expire(now=at_expiry)
        self.assertEqual(self.req.request_state, 'open')
        later = self.req.expiry_datetime + timedelta(hours=4)
        self.env['blockchain.relay.job']._cron_expire(now_ts=calendar.timegm(later.timetuple()))
        self.env['blockchain.payment.request']._cron_expire(now=later)
        self.assertEqual(self.req.request_state, 'expired')
```

(Imports at the top of the test file: `import calendar` and `from datetime import timedelta`.)

- [ ] **Step 2: Run to verify it fails**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: `AttributeError: _open_request`.

- [ ] **Step 3: Implement** — replace `blockchain_payment_request.py`:

```python
import calendar
import logging
import secrets
import time
import uuid
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import UserError

from ..lib import eip712
from ..lib.secp256k1 import ecrecover

_logger = logging.getLogger(__name__)

UINT = "'^(0|[1-9][0-9]{0,77})$'"
LIVE_JOB_STATES = ('queued', 'nonce_leased', 'signed', 'broadcast', 'mined')
_FINALITY_GRACE = 3600


class BlockchainPaymentRequest(models.Model):
    """Một khoản phải thu on-chain (canon §C10.9, thu gọn). Lane `(payer, batch)` nonce 0:
    mọi chữ ký của request dùng chung lane ⇒ chain thực thi tối đa một (spec §5)."""
    _name = 'blockchain.payment.request'
    _description = 'On-chain Payment Request'
    _order = 'id desc'
    _rec_name = 'request_uuid'

    request_uuid = fields.Char(required=True, readonly=True, default=lambda s: str(uuid.uuid4()))
    company_id = fields.Many2one('res.company', required=True, index=True)
    chain_id = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    token_id = fields.Many2one('blockchain.token', required=True, index=True, ondelete='restrict')
    receiving_address = fields.Char(required=True)
    relayer_address = fields.Char(required=True, default=eip712.ZERO_ADDRESS)
    payer_address = fields.Char(required=True, index=True)
    amount_base = fields.Char(required=True)
    amount_settled_base = fields.Char(compute='_compute_amount_settled', store=True)
    entry_ref_hex = fields.Char(required=True, readonly=True)
    batch_hex = fields.Char(required=True, readonly=True)
    issued_valid_until = fields.Integer(readonly=True)
    expiry_datetime = fields.Datetime(required=True)
    request_state = fields.Selection(
        [('open', 'Open'), ('partial', 'Partially paid'), ('final', 'Paid (final)'),
         ('expired', 'Expired')], default='open', required=True, index=True)
    needs_attention = fields.Boolean(index=True)
    attention_note = fields.Char()
    res_model = fields.Char(index=True)
    res_id = fields.Integer(index=True)
    metatx_ids = fields.One2many('blockchain.metatx', 'payment_request_id')
    event_ids = fields.One2many('blockchain.chain.event', 'payment_request_id')

    _entry_ref_uniq = models.Constraint('UNIQUE(entry_ref_hex)', 'entryRef is unique.')
    _amount_base_uint = models.Constraint(f'CHECK(amount_base ~ {UINT})', 'amount_base is a uint256.')

    @api.depends('event_ids.value_base', 'event_ids.to_address', 'event_ids.contract_address')
    def _compute_amount_settled(self):
        for req in self:
            total = sum(int(ev.value_base) for ev in req.event_ids
                        if ev.event_name == 'PaymentSettled'
                        and ev.contract_address == req.token_id.address
                        and ev.to_address == req.receiving_address)
            req.amount_settled_base = str(total)

    # ------------------------------------------------------------------ building

    @api.model
    def _open_request(self, *, token, receiving_address, relayer_address, payer_address,
                      amount_base, company, res_model, res_id, validity_hours=24):
        if int(amount_base) <= 0:
            raise UserError(self.env._('Nothing to pay.'))
        ref = secrets.token_bytes(32)
        return self.sudo().create({
            'company_id': company.id, 'chain_id': token.chain_id.id, 'token_id': token.id,
            'receiving_address': eip712.norm_address(receiving_address),
            'relayer_address': eip712.norm_address(relayer_address or eip712.ZERO_ADDRESS),
            'payer_address': eip712.norm_address(payer_address),
            'amount_base': str(int(amount_base)),
            'entry_ref_hex': '0x' + ref.hex(),
            'batch_hex': '0x' + eip712.lane_batch(ref).to_bytes(32, 'big').hex(),
            'expiry_datetime': fields.Datetime.now() + timedelta(hours=validity_hours),
            'res_model': res_model, 'res_id': res_id,
        })

    def _message(self, valid_until):
        self.ensure_one()
        restricted = self.relayer_address != eip712.ZERO_ADDRESS
        return {
            'from': self.payer_address, 'to': self.receiving_address,
            'value': int(self.amount_base),
            'data': eip712.pay_data(bytes.fromhex(self.entry_ref_hex[2:])),
            'batch': int(self.batch_hex, 16), 'nonce': 0, 'valid_until': int(valid_until),
            'mode': eip712.MODE_RESTRICT_RELAYER if restricted else 0,
            'relayer': self.relayer_address, 'fee': 0, 'fee_recipient': eip712.ZERO_ADDRESS,
        }

    def _issue(self, validity_seconds):
        """Server chọn hạn; client chỉ trả lại đúng con số này (spec §4.5, review F20)."""
        self.ensure_one()
        if self.request_state not in ('open', 'partial'):
            raise UserError(self.env._('This payment request is %s.', self.request_state))
        valid_until = int(time.time()) + int(validity_seconds)
        self.sudo().issued_valid_until = valid_until
        return eip712.typed_data(self.token_id._domain(), self._message(valid_until))

    def _live_job(self):
        return self.metatx_ids.relay_job_ids.filtered(lambda j: j.chain_state in LIVE_JOB_STATES)

    def _accept_signature(self, valid_until, signature_hex):
        """Kiểm, rồi ghi metatx + job outbox trong CÙNG transaction (canon §C13)."""
        self.ensure_one()
        valid_until = int(valid_until)
        if not self.issued_valid_until or valid_until != self.issued_valid_until:
            raise UserError(self.env._('This signature was not made over the terms we issued.'))
        if valid_until <= int(time.time()):
            raise UserError(self.env._('The signing window has closed; start again.'))
        if self._live_job():
            raise UserError(self.env._('A payment for this request is already on its way.'))
        try:
            sig = bytes.fromhex(signature_hex[2:] if signature_hex.startswith('0x') else signature_hex)
        except ValueError as exc:
            raise UserError(self.env._('Malformed signature.')) from exc
        if not 65 <= len(sig) <= 2048:
            raise UserError(self.env._('Malformed signature.'))
        m = self._message(valid_until)
        dg = eip712.digest(self.token_id._domain(), m)
        signer = ecrecover(dg, sig) if len(sig) == 65 else None
        verified = signer == self.payer_address
        if signer is not None and not verified:
            raise UserError(self.env._('The signature is not from the wallet that started this payment.'))
        mtx = self.env['blockchain.metatx'].sudo().create({
            'company_id': self.company_id.id, 'chain_id': self.chain_id.id,
            'token_id': self.token_id.id, 'payment_request_id': self.id,
            'from_address': m['from'], 'to_address': m['to'], 'value_base': str(m['value']),
            'data_hex': '0x' + m['data'].hex(), 'batch_hex': self.batch_hex, 'nonce_base': '0',
            'valid_until_ts': valid_until, 'mode_flags': m['mode'],
            'relayer_address': m['relayer'], 'fee_base': '0',
            'fee_recipient_address': eip712.ZERO_ADDRESS, 'digest_hash': '0x' + dg.hex(),
            'signature_hex': '0x' + sig.hex(), 'signature_verified': verified,
        })
        self.env['blockchain.relay.job'].sudo().create({
            'company_id': self.company_id.id, 'chain_id': self.chain_id.id,
            'metatx_id': mtx.id, 'origin_producer': 'blockchain.payment.request',
            'origin_key': mtx.digest_hash,
        })
        return mtx

    # ------------------------------------------------------------------ settlement

    @api.model
    def _apply_events(self, events):
        """Gọi từ ingest (đã sudo). Khớp `entryRef`; event không khớp vẫn được giữ."""
        for ev in events:
            req = self.search([('entry_ref_hex', '=', ev.entry_ref_hex),
                               ('chain_id', '=', ev.chain_id.id)], limit=1)
            if req:
                ev.write({'payment_request_id': req.id, 'company_id': req.company_id.id})
        reqs = events.payment_request_id
        reqs.flush_recordset()
        reqs._payment_gate()

    def _payment_gate(self):
        for req in self:
            if req.request_state == 'final':
                if int(req.amount_settled_base) > int(req.amount_base):
                    req._attention('overpaid')
                continue
            settled, due = int(req.amount_settled_base or 0), int(req.amount_base)
            if settled < due:
                if settled:
                    req.request_state = 'partial'
                continue
            req.request_state = 'final'
            if settled > due:
                req._attention('overpaid')
            try:
                with self.env.cr.savepoint():
                    req._on_paid()
            except Exception as exc:  # noqa: BLE001 — một lỗi nghiệp vụ không được kẹt cursor
                _logger.exception('payment request %s: _on_paid failed', req.request_uuid)
                req._attention(str(exc))

    def _attention(self, note):
        self.write({'needs_attention': True, 'attention_note': (note or '')[:250]})

    def _on_paid(self):
        """Hook: request vừa đủ tiền (final). `dms_blockchain_payment` override."""

    def _on_expired(self):
        """Hook: request hết hạn mà không có tiền. `dms_blockchain_payment` override."""

    @api.model
    def _cron_expire(self, now=None):
        now = now or fields.Datetime.now()
        now_ts = calendar.timegm(now.timetuple())    # Odoo datetimes are naive UTC
        for req in self.sudo().search([('request_state', '=', 'open'),
                                       ('expiry_datetime', '<', now)]):
            if any(m.valid_until_ts + _FINALITY_GRACE > now_ts for m in req.metatx_ids):
                continue
            if req.metatx_ids.relay_job_ids.filtered(lambda j: j.chain_state in ('broadcast', 'mined')):
                continue
            req.request_state = 'expired'
            req._on_expired()
```

Cron (append to `ir_cron.xml`): `cron_expire_payment_request`, model `blockchain.payment.request`, `model._cron_expire()`, every 10 minutes. Security: rule `rule_payment_request_company`; CSV already has viewer read; operator write for `needs_attention` clearing: `access_payment_request_operator,...,1,1,0,0`. Views: list + form (readonly fields, `needs_attention` filter), action, menu Operations sequence 10.

- [ ] **Step 4: Run to verify it passes**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: `0 failed, 0 error(s)`.

- [ ] **Step 5: Commit**

```bash
git add dms_blockchain
git commit -m "feat(blockchain): payment request lane, signature acceptance and savepointed payment gate"
```

---

### Task 6: `/json/2` with API keys (HttpCase) + install boundary

**Files:**
- Create: `dms_blockchain/tests/test_json2.py`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Test** — `dms_blockchain/tests/test_json2.py`:

```python
import json

from odoo.tests.common import HttpCase, tagged


@tagged('post_install', '-at_install')
class TestJson2(HttpCase):
    """CLAUDE.md §6: node nói với Odoo qua /json/2 + bearer. Đây là đường thật, không mock."""

    def setUp(self):
        super().setUp()
        self.chain = self.env['blockchain.chain'].create({
            'name': 'J2', 'evm_chain_number': 9101, 'state': 'active'})
        self.env['blockchain.token'].create({
            'chain_id': self.chain.id, 'address': '0x' + 'cd' * 20, 'name': 'b', 'symbol': 'b',
            'decimals': 6, 'currency_id': self.env.ref('base.USD').id})
        self.relay = self.env['res.users'].create({
            'name': 'relay', 'login': 'relay-j2@chain.test',
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id,
                                  self.env.ref('dms_blockchain.group_blockchain_relay_worker').id])]})
        self.indexer = self.env['res.users'].create({
            'name': 'indexer', 'login': 'indexer-j2@chain.test',
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id,
                                  self.env.ref('dms_blockchain.group_blockchain_indexer').id])]})
        self.relay_key = self.env['res.users.apikeys'].with_user(self.relay).sudo()._generate(
            None, 'node', None)
        self.indexer_key = self.env['res.users.apikeys'].with_user(self.indexer).sudo()._generate(
            None, 'node', None)
        self.env.flush_all()

    def _json2(self, key, model, method, **kwargs):
        return self.url_open(
            f'/json/2/{model}/{method}', data=json.dumps(kwargs),
            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json',
                     'X-Odoo-Database': self.env.cr.dbname})

    def test_node_config_over_json2(self):
        res = self._json2(self.relay_key, 'blockchain.chain', 'node_config', evm_chain_number=9101)
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['tokens'][0]['decimals'], 6)

    def test_relay_poll_over_json2(self):
        res = self._json2(self.relay_key, 'blockchain.relay.job', 'relay_poll', evm_chain_number=9101)
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json(), [])

    def test_indexer_key_cannot_poll_jobs(self):
        res = self._json2(self.indexer_key, 'blockchain.relay.job', 'relay_poll', evm_chain_number=9101)
        self.assertEqual(res.status_code, 403, res.text)

    def test_ingest_over_json2(self):
        res = self._json2(self.indexer_key, 'blockchain.chain.event', 'chain_event_ingest',
                          evm_chain_number=9101, from_block=1, to_block=3,
                          to_block_hash='0x' + '0b' * 32, events=[])
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['indexed_block'], 3)

    def test_relay_key_cannot_ingest(self):
        res = self._json2(self.relay_key, 'blockchain.chain.event', 'chain_event_ingest',
                          evm_chain_number=9101, from_block=1, to_block=3,
                          to_block_hash='0x' + '0b' * 32, events=[])
        self.assertEqual(res.status_code, 403, res.text)
```

- [ ] **Step 2: Run** — `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain`
Expected: PASS (if `res.users.apikeys._generate` needs an expiration for non-admins, pass `fields.Datetime.now() + timedelta(days=1)`; if json2 returns 401/422 the test text says why — fix the call shape, not the assertion).

- [ ] **Step 3: Commit**

```bash
git add dms_blockchain/tests/test_json2.py dms_blockchain/tests/__init__.py
git commit -m "test(blockchain): service RPC over /json/2 with per-role API keys"
```

---

### Task 7: `dms_blockchain_payment` — provider `chain`

**Files:**
- Create: `dms_blockchain_payment/__init__.py`, `__manifest__.py`, `models/__init__.py`, `models/payment_provider.py`, `models/payment_transaction.py`, `models/blockchain_payment_request.py`, `data/payment_method_data.xml`, `data/payment_provider_data.xml`, `views/payment_provider_views.xml`, `security/ir.model.access.csv` (empty header only if needed), `tests/__init__.py`, `tests/test_chain_provider.py`

**Interfaces:**
- Consumes: `blockchain.payment.request._open_request/_issue/_accept_signature`, hooks.
- Produces: `payment.provider` fields `chain_token_id chain_receiving_address chain_relayer_address chain_validity_seconds`; `payment.transaction.chain_request_id`; private `payment.transaction._chain_amount_base() -> int`, `_chain_start(payer_address) -> dict typed_data`, `_chain_submit(valid_until, signature_hex) -> blockchain.metatx`, `_chain_status() -> dict`.

- [ ] **Step 1: Failing tests** — `dms_blockchain_payment/tests/test_chain_provider.py`:

```python
from odoo.exceptions import UserError
from odoo.tests.common import tagged

from odoo.addons.dms_blockchain.lib import eip712
from odoo.addons.dms_blockchain.tests.test_payment_request import PK, _addr, _sign
from odoo.addons.dms_blockchain.tests.test_models import ChainCase


@tagged('post_install', '-at_install')
class TestChainProvider(ChainCase):

    def setUp(self):
        super().setUp()
        self.provider = self.env.ref('dms_blockchain_payment.payment_provider_chain')
        self.provider.write({
            'state': 'test', 'chain_token_id': self.token.id,
            'chain_receiving_address': '0x' + '5E' * 20,
            'chain_relayer_address': '0x' + '02' * 20})
        self.partner = self.env['res.partner'].create({'name': 'Payer'})
        self.tx = self.env['payment.transaction'].create({
            'provider_id': self.provider.id,
            'payment_method_id': self.env.ref('dms_blockchain_payment.payment_method_chain').id,
            'partner_id': self.partner.id, 'amount': 12.345678,
            'currency_id': self.usd.id, 'reference': 'CHAIN-T1'})
        self.payer = _addr(PK)

    def test_amount_is_converted_exactly(self):
        self.assertEqual(self.tx._chain_amount_base(), 12_345_678)

    def test_currency_mismatch_is_refused_up_front(self):
        self.tx.currency_id = self.env.ref('base.EUR')
        with self.assertRaises(UserError):
            self.tx._chain_start(self.payer)

    def test_start_then_submit_queues_the_outbox(self):
        td = self.tx._chain_start(self.payer)
        self.assertEqual(td['message']['to'], '0x' + '5e' * 20)
        req = self.tx.chain_request_id
        dg = eip712.digest(self.token._domain(), req._message(req.issued_valid_until))
        self.tx._chain_submit(req.issued_valid_until, '0x' + _sign(PK, dg).hex())
        self.assertEqual(self.tx.state, 'pending')
        self.assertEqual(req.metatx_ids.relay_job_ids.chain_state, 'queued')

    def test_restart_with_same_wallet_reuses_the_lane(self):
        self.tx._chain_start(self.payer)
        req = self.tx.chain_request_id
        self.tx._chain_start(self.payer)
        self.assertEqual(self.tx.chain_request_id, req)

    def test_final_settlement_sets_the_transaction_done(self):
        self.tx._chain_start(self.payer)
        req = self.tx.chain_request_id
        self.env['blockchain.chain.event'].with_user(self.indexer_user).chain_event_ingest(
            9001, 1, 1, '0x' + '0b' * 32, [{
                'event': 'PaymentSettled', 'contract': self.token.address, 'block_number': 1,
                'block_hash': '0x' + '0b' * 32, 'tx_hash': '0x' + '01' * 32, 'log_index': 0,
                'from': self.payer, 'to': req.receiving_address, 'amount': req.amount_base,
                'fee': '0', 'fee_recipient': '0x' + '02' * 20, 'entry_ref': req.entry_ref_hex}])
        self.assertEqual(self.tx.state, 'done')

    def test_expired_request_cancels_the_transaction(self):
        self.tx._chain_start(self.payer)
        self.tx._set_pending()
        self.tx.chain_request_id._on_expired()
        self.assertEqual(self.tx.state, 'cancel')

    def test_done_transaction_is_not_set_done_twice(self):
        self.tx._chain_start(self.payer)
        self.tx._set_done()
        self.tx.chain_request_id._on_paid()      # no exception, no state change
        self.assertEqual(self.tx.state, 'done')
```

- [ ] **Step 2: Run to verify it fails**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain,dms_blockchain_payment /dms_blockchain_payment`
Expected: error — module `dms_blockchain_payment` not found.

- [ ] **Step 3: Implement**

`__manifest__.py`:

```python
{
    'name': 'Bamboo Blockchain - Payment Provider',
    'version': '19.0.1.0.0',
    'license': 'LGPL-3',
    'category': 'Accounting/Payment Providers',
    'summary': 'Pay with a signed meta-transaction; settled only by finalized chain events',
    'author': 'dinhduongha@gmail.com',
    'depends': ['dms_blockchain', 'payment'],
    'data': [
        'views/payment_provider_views.xml',
        'data/payment_method_data.xml',
        'data/payment_provider_data.xml',
    ],
    'post_init_hook': 'post_init_hook',
    'uninstall_hook': 'uninstall_hook',
    'installable': True,
    'application': False,
    'auto_install': False,
}
```

`__init__.py`:

```python
from . import models

from odoo.addons.payment import reset_payment_provider, setup_provider


def post_init_hook(env):
    setup_provider(env, 'chain')


def uninstall_hook(env):
    reset_payment_provider(env, 'chain')
```

`models/payment_provider.py`:

```python
from odoo import api, fields, models
from odoo.exceptions import ValidationError

from odoo.addons.dms_blockchain.lib.eip712 import norm_address


class PaymentProvider(models.Model):
    _inherit = 'payment.provider'

    code = fields.Selection(selection_add=[('chain', 'On-chain (meta-transaction)')],
                            ondelete={'chain': 'set default'})
    chain_token_id = fields.Many2one('blockchain.token', string='Token')
    chain_receiving_address = fields.Char(string='Receiving address')
    chain_relayer_address = fields.Char(
        string='Relayer address',
        help='Signed into every payment (MODE_RESTRICT_RELAYER): only this wallet may submit it.')
    chain_validity_seconds = fields.Integer(default=300, string='Signature validity (s)')

    @api.constrains('chain_receiving_address', 'chain_relayer_address')
    def _check_chain_addresses(self):
        for p in self.filtered(lambda p: p.code == 'chain'):
            for value in (p.chain_receiving_address, p.chain_relayer_address):
                if value:
                    try:
                        norm_address(value)
                    except ValueError as exc:
                        raise ValidationError(str(exc)) from exc

    def _get_default_payment_method_codes(self):
        self.ensure_one()
        if self.code != 'chain':
            return super()._get_default_payment_method_codes()
        return {'chain'}
```

`models/payment_transaction.py`:

```python
from decimal import ROUND_HALF_UP, Decimal

from odoo import fields, models
from odoo.exceptions import UserError

from odoo.addons.dms_blockchain.lib.eip712 import norm_address


class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    chain_request_id = fields.Many2one('blockchain.payment.request', readonly=True, index=True,
                                       copy=False)

    def _chain_amount_base(self):
        self.ensure_one()
        token = self.provider_id.chain_token_id
        if not token:
            raise UserError(self.env._('%s has no token configured.', self.provider_id.name))
        if token.currency_id != self.currency_id:
            raise UserError(self.env._(
                '%(t)s settles in %(c)s; this payment is in %(p)s. No conversion is offered.',
                t=token.symbol, c=token.currency_id.name, p=self.currency_id.name))
        exact = Decimal(str(self.currency_id.round(self.amount))) * (Decimal(10) ** token.decimals)
        return int(exact.quantize(Decimal(1), rounding=ROUND_HALF_UP))

    def _chain_start(self, payer_address):
        """Tạo hoặc tái dùng request (cùng ví ⇒ cùng lane), rồi phát typed data mới."""
        self.ensure_one()
        if self.provider_code != 'chain':
            raise UserError(self.env._('Not an on-chain transaction.'))
        payer = norm_address(payer_address)
        amount = self._chain_amount_base()
        req = self.chain_request_id
        if req and req.payer_address != payer:
            raise UserError(self.env._('This payment was started from another wallet.'))
        if not req:
            p = self.provider_id
            req = self.env['blockchain.payment.request']._open_request(
                token=p.chain_token_id, receiving_address=p.chain_receiving_address,
                relayer_address=p.chain_relayer_address, payer_address=payer,
                amount_base=amount, company=self.company_id,
                res_model=self._name, res_id=self.id)
            self.sudo().chain_request_id = req
        return req._issue(self.provider_id.chain_validity_seconds)

    def _chain_submit(self, valid_until, signature_hex):
        self.ensure_one()
        if not self.chain_request_id:
            raise UserError(self.env._('Start the payment first.'))
        mtx = self.chain_request_id._accept_signature(valid_until, signature_hex)
        if self.state == 'draft':
            self._set_pending()
        return mtx

    def _chain_status(self):
        self.ensure_one()
        req = self.chain_request_id
        job = req.metatx_ids[:1].relay_job_ids[:1] if req else self.env['blockchain.relay.job']
        return {
            'reference': self.reference, 'tx_state': self.state,
            'request_state': req.request_state if req else False,
            'job_state': job.chain_state if job else False,
            'tx_hash': (req.metatx_ids[:1].executed_tx_hash or job.tx_hash) if req else False,
        }
```

`models/blockchain_payment_request.py`:

```python
from odoo import models


class BlockchainPaymentRequest(models.Model):
    _inherit = 'blockchain.payment.request'

    def _transactions(self):
        return self.env['payment.transaction'].sudo().search([('chain_request_id', 'in', self.ids)])

    def _on_paid(self):
        super()._on_paid()
        for tx in self._transactions():
            if tx.state == 'done':
                continue
            if tx.state not in ('draft', 'pending', 'authorized', 'error'):
                self._attention(f'money arrived on a {tx.state} transaction {tx.reference}')
                continue
            tx._set_done()

    def _on_expired(self):
        super()._on_expired()
        self._transactions().filtered(lambda t: t.state in ('draft', 'pending'))._set_canceled()
```

`data/payment_method_data.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo noupdate="1">
    <record id="payment_method_chain" model="payment.method">
        <field name="name">On-chain token</field>
        <field name="code">chain</field>
        <field name="sequence">50</field>
        <field name="image" type="base64" file="dms_blockchain_payment/static/img/chain.png"/>
        <field name="support_tokenization">False</field>
        <field name="support_express_checkout">False</field>
        <field name="support_refund">none</field>
    </record>
</odoo>
```

(`static/img/chain.png`: any 64×64 PNG; generate with `python3 -c` writing a 1-colour PNG via `zlib`/`struct` — or copy `payment/static/img/` placeholder if one exists.)

`data/payment_provider_data.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo noupdate="1">
    <record id="payment_provider_chain" model="payment.provider">
        <field name="name">On-chain (meta-transaction)</field>
        <field name="code">chain</field>
        <field name="state">disabled</field>
        <field name="payment_method_ids" eval="[Command.set([ref('payment_method_chain')])]"/>
    </record>
</odoo>
```

`views/payment_provider_views.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <record id="payment_provider_form" model="ir.ui.view">
        <field name="name">payment.provider.form.chain</field>
        <field name="model">payment.provider</field>
        <field name="inherit_id" ref="payment.payment_provider_form"/>
        <field name="arch" type="xml">
            <group name="provider_credentials" position="inside">
                <group invisible="code != 'chain'">
                    <field name="chain_token_id" required="code == 'chain' and state != 'disabled'"/>
                    <field name="chain_receiving_address" required="code == 'chain' and state != 'disabled'"/>
                    <field name="chain_relayer_address"/>
                    <field name="chain_validity_seconds"/>
                </group>
            </group>
        </field>
    </record>
</odoo>
```

- [ ] **Step 4: Run to verify it passes**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain,dms_blockchain_payment`
Expected: both suites `0 failed, 0 error(s)`.

- [ ] **Step 5: Commit**

```bash
git add dms_blockchain_payment
git commit -m "feat(blockchain): payment provider 'chain' driven by the finality-gated request"
```

---

## Self-review

| Spec item | Task |
|---|---|
| §4.1 boundaries, no third-party Python | 1, 7 manifests |
| §4.2 chain/token/metatx/job/event/request fields + constraints | 2–5 |
| §4.3 transition table, `final` absorbing, `dead ⇒ failed` | 3 |
| §3.3/§3.5 ingest contiguous + idempotent + registered-contract only | 4 |
| §3.5 service RPC + group gate + `/json/2` | 2–4, 6 |
| §4.2 gate idempotent, savepoint hook, overpaid attention | 5 |
| §4.4 provider, amount conversion, FX refusal, `_set_done` / cancel hooks | 7 |
| §4.5 `issued_valid_until` equality, payer lock, one live job | 5, 7 |
| §5 guarantee 1 (no done before final) | 7 `test_final_settlement_sets_the_transaction_done` (only path to done) |
| §6 KAT parity | 1 |
| §9 T3, T4, T8, T16 | 4, 5, 6, 1 |

Ruling R20 (RPC endpoints live only in the node config; `blockchain.rpc.endpoint` dropped) is recorded in the spec in the same commit as Task 2.
