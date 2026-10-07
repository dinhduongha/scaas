> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

## 08. Chain adapter va chain profile: 6 he sinh thai + private chain

> Phần này sở hữu **hai trục**: `chain_family` (adapter nào chạy) và `chain_profile` (public/private). Nonce/sequence leasing, gas breaker, RPC failover và simulation gate đã được đặc tả ở §06 — ở đây chỉ nêu phần **giao diện** mà §06 gọi vào, và những chỗ giao diện đó **buộc phải rò rỉ**.
>
> Bản này là bản đã hardened. Những chỗ sửa số liệu so với bản nháp trước và so với `blockchain.md` đều được đánh dấu **[SỬA]**; những giả định trước đây ngầm định nay nằm ở §08.0b.

---

### 08.0. Kết luận trước

| Quyết định | Chọn | Lý do một dòng |
|---|---|---|
| Định danh chain | CAIP-2 `Char` (`eip155:100`, `sui:mainnet`, `ton:-239`) | Một cột chạy xuyên 7 hệ, không phải `Integer chain_id` chỉ dùng được cho EVM (§06 đã chốt) |
| Model | **một** `blockchain.chain`, `chain_profile` là `Selection` trên nó | Không tách `blockchain.chain.profile` như §01 viết — xem §08.12 mâu thuẫn (1) |
| Trục thứ ba (mới) | `is_production` Boolean, **không** phải một Selection env | Testnet đã nằm trong CAIP-2 (`eip155:10200` = Chiado); cái ta thật sự cần là một cờ chặn `payment.provider` trỏ vào testnet — xem §08.1 |
| Adapter | `Protocol` Python thuần trong `relay-pool/adapters/`, **không** trong addon | Adapter phải chạy được trong asyncio hot loop, không có `env` |
| Nhưng: shim trong addon | `dms_blockchain/lib/addr.py` — pure-python, zero-dep, **chỉ** validate/normalize địa chỉ | Form Odoo phải từ chối địa chỉ sai **trước** khi ghi record; không thể gọi HTTP sang relay-pool trong một `@api.constrains` |
| Số method core | **12** — bản nháp nói "9, không hơn" | **[SỬA]** 9 là con số thẩm mỹ. Ba method thiếu (`preflight`, `get_balance`, `decode_event`) mỗi cái tương ứng một sự cố production cụ thể — §08.2 |
| `sign_and_submit` | **một** method, không tách `sign` rồi `submit` | Sui dual-signature, Stellar fee-bump wrapping, Hedera payer-signature đều cần sponsor ký **sau** user trên cấu trúc adapter sở hữu |
| Replace / cancel | **không** thêm method; thêm tham số `bump: FeeBump \| None` vào `sign_and_submit` + flag `SUPPORTS_REPLACEMENT` | Sui/Stellar/Hedera **không có** replacement. Một method `replace()` sẽ raise `NotImplemented` trên 4/6 hệ — đó là API dối |
| Zether wave 1 | **chỉ EVM**, trên private Besu | Xem bảng khả thi §08.9b |
| Zether range proof | **[SỬA] 64-bit trên đơn vị token 6 decimals**, không phải 128-bit trên 18 decimals | Giảm ~60% gas verify với cùng trần giá trị $18 nghìn tỷ. Mâu thuẫn với `blockchain.md` §10.5.3 — lập luận đầy đủ ở §08.4b |
| Private stack | **Hyperledger Besu + QBFT**, `zeroBaseFee`, block gas limit 50M, contract size limit 64KB | GoQuorum ở chế độ maintenance, Polygon Edge đã bị Polygon khai tử 2024 — chọn Edge là chọn codebase chết |
| Relayer market trên private | **Không tồn tại.** Giữ envelope EIP-1776, bỏ auction/stake/PoW | Gas free ⇒ relayer không cung cấp dịch vụ vốn nào cả |
| Finality trên public | **quorum 2 RPC provider độc lập** mới được `_set_done` | Một RPC nói dối là kịch bản rẻ nhất để rút tiền khỏi hệ thống này — §08.0b, giả định A2 |

---

### 08.0b. Những giả định bản nháp không nói ra

Đây là phần một reviewer đọc bản nháp sẽ hỏi đầu tiên. Mỗi dòng là một giả định **ngầm**, kèm hậu quả nếu nó sai và cách xử lý đã chốt.

| # | Giả định ngầm | Nếu sai thì sao | Xử lý |
|---|---|---|---|
| A1 | Relay-pool là một service asyncio chạy dài, Odoo gọi được nó | Không nói ai deploy, Odoo gọi qua đâu, và điều gì xảy ra khi nó chết ⇒ addon không build được | §08.2b: ranh giới là **outbox trong DB + worker poll**, không phải HTTP đồng bộ từ Odoo |
| A2 | RPC node nói thật | Một RPC bị chiếm/độc hại trả `status=1` cho tx không tồn tại ⇒ `_set_done` ⇒ mất tiền. Đây là tấn công rẻ nhất trong toàn hệ | `finality_quorum` (mặc định 2) provider độc lập phải khớp `blockhash` + `receipt.status` trước `_set_done`. Private profile: chỉ tin **node của chính mình**, không tin vendor |
| A3 | Adapter stateless | Sai với 3/6 hệ: Sui giữ pool gas coin, TON giữ cửa sổ `query_id`, Soroban cache footprint. Hai instance adapter chạy song song sẽ equivocate | Adapter khai `is_stateful: bool`; state nằm ở Redis chung với nonce lease của §06, **không** ở bộ nhớ process |
| A4 | Địa chỉ ta lưu là danh tính chain nhìn thấy | Hedera có **hai** danh tính cho cùng một account (`0.0.12345` và EVM alias 20 byte). Lưu một cái, đối soát cái kia ⇒ không match | §08.3b: lưu **cả hai** cột, `chain_address` (canonical) và `chain_address_alt`; đối soát phải chấp nhận cả hai |
| A5 | Chain đứng yên | Celo đã chuyển sang L2 (Mar 2025) và làm sai toàn bộ dòng finality trong `blockchain.md`. Chuyện này sẽ lặp lại | `preflight()` chạy mỗi lần khởi động worker + cron 1h: so `chain_id`/`genesis_hash`/`protocol_version` quan sát được với record; lệch ⇒ `state='paused'`, không tự sửa |
| A6 | Simulate xong thì submit an toàn | State đổi giữa simulate và inclusion. `blockchain.md` viết *"tỷ lệ revert bằng 0%"* — **không đạt được**, xem §08.4c | Ngân sách revert là một dòng chi phí, không phải một bug. Và forwarder **phải** thu fee ngay cả khi inner call revert (§08.4c) |
| A7 | Custody ký được mọi scheme | TON/Sui/Stellar/Hedera dùng Ed25519 **thuần** (ký trên message, không ký trên digest). Nhiều KMS chỉ ký ECDSA trên digest ⇒ không ký được | §08.3b bảng scheme; đây là **blocker mua sắm** cho §07, phải xác nhận với nhà cung cấp trước khi cam kết chain order |
| A8 | Finality đủ để `_set_done` | Không. Còn phải decode được event và khớp nó với `blockchain.relay.job`. Tx final nhưng revert vẫn là tx final | `FinalityVerdict.level == FINAL` **và** `Receipt.status == success` **và** event khớp intent hash ⇒ mới `_set_done` |
| A9 | Ví relayer luôn có native token | Không có vòng nạp gas ⇒ pool chết im lặng lúc 2h sáng | `get_balance()` (method #11) + ngưỡng cảnh báo/tự chặn ở §06; đó là lý do method này không cắt được |
| A10 | Có một tỷ giá để quy gas ra token fee | Trên Gnosis/L2, `fee` tính bằng token nghiệp vụ nhưng gas trả bằng native ⇒ cần nguồn tỷ giá + hạn hiệu lực | `FeeQuote.rate_source` + `rate_expiry_epoch_ms` + biên trượt giá; quote hết hạn ⇒ báo giá lại, không submit |
| A11 | Meta-tx trong mempool công khai là an toàn | Payload EIP-1776 `MODE_OPEN` **tự chứng thực**: ai thấy nó trong mempool cũng broadcast được và lấy `fee`. Đó không phải bug, đó là định nghĩa | Capability `PRIVATE_SUBMISSION` (endpoint riêng) cho intent nhạy cảm; §05 xử lý phần lottery |
| A12 | Một record chain là đủ để cấu hình | Thiếu hẳn RPC endpoint, khoá API, giới hạn `eth_getLogs` | §08.1: model `blockchain.rpc.endpoint` + URL nằm trong `ir.config_parameter` (URL vendor **chứa** API key ⇒ URL là secret) |

---

### 08.1. `blockchain.chain`: hai trục trên một bản ghi

```python
class BlockchainChain(models.Model):
    _name = 'blockchain.chain'
    _description = 'A chain deployment target (family x profile)'
    _inherit = ['mail.thread']

    name             = fields.Char(required=True)
    caip2            = fields.Char(required=True, index=True)       # 'eip155:100'
    chain_family     = fields.Selection([
        ('evm', 'EVM'), ('hedera', 'Hedera'), ('ton', 'TON'),
        ('sui', 'Sui'), ('soroban', 'Soroban'), ('cosmwasm', 'CosmWasm'),
    ], required=True, index=True)
    chain_profile    = fields.Selection([
        ('public', 'Public'), ('private', 'Private / Permissioned'),
    ], required=True, default='private', index=True)
    is_production    = fields.Boolean(default=False, index=True)
    evm_chain_number = fields.Integer()          # chỉ có nghĩa khi chain_family='evm'
    genesis_hash     = fields.Char()             # preflight so khớp; rỗng = chưa preflight
    protocol_version = fields.Char()             # 'shanghai' | 'sui-1.39' | 'soroban-p22' ...
    native_symbol    = fields.Char(required=True)                   # xDAI, CELO, HBAR...
    native_decimals  = fields.Integer(required=True, default=18)
    native_is_stable = fields.Boolean(default=False)                # xDAI = True
    fee_token_mode   = fields.Selection([
        ('native', 'Native only'),
        ('erc20_feecurrency', 'ERC-20 fee currency (CIP-52)'),
        ('free', 'Zero gas price'),
    ], required=True, default='native')
    finality_depth   = fields.Integer(required=True, default=1)
    finality_mode    = fields.Selection([
        ('depth', 'Block depth'), ('bft_instant', 'BFT instant'),
        ('checkpoint', 'Checkpoint / epoch'), ('l1_batch', 'L2 with L1 batch'),
    ], required=True, default='depth')
    finality_quorum  = fields.Integer(required=True, default=2)     # số RPC độc lập phải khớp
    soft_final_seconds = fields.Integer(required=True, default=5)
    hard_final_seconds = fields.Integer(required=True, default=5)
    block_time_ms    = fields.Integer(required=True, default=5000)
    block_gas_limit  = fields.Integer()
    max_tx_gas       = fields.Integer()          # Hedera 15M, TON 1M unit, Soroban 100M instr
    capability_flags = fields.Json()             # metadata nhỏ, KHÔNG phải file/ảnh
    endpoint_ids     = fields.One2many('blockchain.rpc.endpoint', 'chain_id')
    state            = fields.Selection([('draft','Draft'), ('live','Live'),
                                         ('paused','Paused'), ('retired','Retired')],
                                        required=True, default='draft', tracking=True)

    _unique_caip2 = models.Constraint('UNIQUE(caip2)', 'CAIP-2 phải duy nhất.')
```

**Ba thay đổi so với bản nháp và lý do:**

1. `capability_json` → **`capability_flags`**. Quy tắc CLAUDE.md cấm tên field trùng **tên kiểu** Odoo; `capability_json` không trùng `json` nên hợp lệ về mặt chữ, nhưng đuôi `_json` mô tả *cách lưu* chứ không mô tả *nội dung* — và nội dung ở đây là một tập cờ. Đổi tên là zero-cost lúc này, không zero-cost sau 30 migration.
2. `is_production`. CAIP-2 đã phân biệt được testnet (`eip155:10200` là Chiado, `eip155:44787` là Alfajores), nên **không** cần trục môi trường thứ ba. Cái thật sự cần là một ràng buộc: `payment.provider` ở `state='enabled'` chỉ được trỏ vào chain có `is_production = True`. Không có nó, một lần copy database staging → production là đủ để nhận thanh toán thật trên testnet.
3. `genesis_hash` / `protocol_version`. Đây là câu trả lời cho giả định A5. Chúng do `preflight()` ghi, người dùng không sửa được trên form.

**Cảnh báo bẫy stored computed** (áp dụng khi ai đó muốn tính `hard_final_seconds` từ `finality_mode`): một stored computed field **không** nhận `default`. Nếu compute có nhánh không gán gì (ví dụ `finality_mode` mới thêm chưa được xử lý), cột `required` sẽ nhận NULL và INSERT chết. Ở model này mọi field đều là plain field có `default` — cố ý. Nếu sau này thêm computed, mọi nhánh phải gán, kể cả `else: rec.x = 0`.

#### `blockchain.rpc.endpoint`: chỗ bản nháp bỏ trống hoàn toàn

```python
class BlockchainRpcEndpoint(models.Model):
    _name = 'blockchain.rpc.endpoint'
    _description = 'One RPC / indexer / mirror endpoint for a chain'
    _order = 'priority, id'

    chain_id   = fields.Many2one('blockchain.chain', required=True,
                                 ondelete='cascade', index=True)
    name       = fields.Char(required=True)                 # 'gnosis-own-node-1'
    kind       = fields.Selection([('http','JSON-RPC HTTP'), ('ws','JSON-RPC WS'),
                                   ('grpc','gRPC'), ('mirror','Mirror / indexer'),
                                   ('rest','REST (LCD / Horizon)')], required=True)
    secret_ref = fields.Char(required=True)                 # key trong ir.config_parameter
    priority   = fields.Integer(required=True, default=10)
    is_archive = fields.Boolean(default=False)
    is_independent = fields.Boolean(default=True)           # đếm vào finality_quorum?
    max_log_block_range = fields.Integer(default=1000)      # Alchemy/Infura chặn ở 10_000
    rate_limit_rps      = fields.Integer(default=25)
    state      = fields.Selection([('draft','Draft'), ('live','Live'),
                                   ('degraded','Degraded'), ('down','Down')],
                                  required=True, default='draft')

    _unique_endpoint = models.Constraint('UNIQUE(chain_id, name)',
                                         'Tên endpoint phải duy nhất trong một chain.')
```

**Không có field `url`.** URL của mọi nhà cung cấp thương mại (Alchemy, Infura, QuickNode, Ankr) **nhúng API key trong path**: `https://eth-mainnet.g.alchemy.com/v2/<KEY>`. Nghĩa là URL *chính là* secret. Đặt nó vào một `Char` trên record là lặp lại đúng cái sai mà `password=True` từng che đậy: nó vẫn ra theo `read()`, RPC, và export CSV. URL nằm trong `ir.config_parameter` dưới key `secret_ref`, ví dụ `blockchain.rpc.eip155:100.own-node-1`; record chỉ giữ con trỏ. Truy cập qua private method:

```python
def _endpoint_url(self):
    self.ensure_one()
    url = self.env['ir.config_parameter'].sudo().get_param(self.secret_ref)
    if not url:
        raise UserError(_('Endpoint %s chưa có URL trong ir.config_parameter (%s).',
                          self.name, self.secret_ref))
    return url
```

`is_independent` tồn tại vì `finality_quorum = 2` chỉ có nghĩa khi hai endpoint thật sự độc lập. Hai key Alchemy khác nhau **không** độc lập — cùng một hạ tầng, cùng một sự cố. Quorum phải gồm ít nhất một node của chính mình.

**Seeding.** Chain records ship dưới dạng `data/blockchain_chain_data.xml` với `noupdate="1"`. Không `noupdate` thì mỗi lần `-u dms_blockchain` sẽ ghi đè `finality_depth` mà ops đã chỉnh sau một sự cố reorg — đúng loại lỗi mất 4 tiếng để tìm.

#### `preflight()`: hợp đồng chống chain đổi dưới chân

Theo quy ước CLAUDE.md §6, entry point public mỏng, logic ở method private:

```python
@api.model
def chain_preflight(self, caip2_list=None):
    """POST /web/dataset/call_kw/blockchain.chain/chain_preflight
       POST /json/2/blockchain.chain/chain_preflight
    Không nhận endpoint hay company từ client: suy ra từ user đã xác thực."""
    chains = self.search([('caip2', 'in', caip2_list)]) if caip2_list \
             else self.search([('state', '=', 'live')])
    return chains._run_preflight()

def _run_preflight(self):    # private: không lộ qua RPC
    ...
```

`_run_preflight` so 5 thứ với record: `chain_id`/`network_id` quan sát được, `genesis_hash`, `protocol_version`, tập capability adapter báo về, và `block_time` đo bằng 20 block gần nhất. Lệch bất kỳ cái nào ⇒ `state='paused'` + post lên `mail.thread`. **Không tự sửa record.** Chain đổi hành vi là sự kiện cần người đọc, không phải cần code đoán.

Cron gọi đúng một dòng (bẫy §5.4 CLAUDE.md — eval context của `ir.cron` không có `fields`, không có `relativedelta`):

```xml
<field name="state">code</field>
<field name="code">model.chain_preflight()</field>
```

---

### 08.2. `ChainAdapter`: 12 method — và tại sao không phải 9

Bản nháp chốt "9 method, không hơn". Con số đó sai theo hướng nguy hiểm: nó ép ba chức năng vận hành bắt buộc ra ngoài interface, nơi chúng sẽ được viết lại khác nhau cho từng chain. **[SỬA]** Mỗi method thêm vào dưới đây tương ứng một sự cố cụ thể mà thiếu nó sẽ gặp.

```python
# /home/dockers/odoo19/relay-pool/adapters/base.py
from typing import Protocol, AsyncIterator, Optional, Literal
from dataclasses import dataclass
from enum import Enum

SigScheme = Literal['ecdsa_secp256k1_keccak', 'ecdsa_secp256r1_sha256',
                    'ed25519_pure', 'schnorr_secp256k1', 'bls12381_g2']

# ---------- các kiểu dữ liệu mà bản nháp tham chiếu nhưng chưa định nghĩa ----------

@dataclass(frozen=True)
class Intent:
    """Cái mà Odoo ghi ra outbox. Adapter-agnostic, không chứa gì EVM-riêng."""
    intent_id: str                  # UUID, cũng là idempotency key
    caip2: str
    kind: str                       # 'token_transfer' | 'contract_call' | 'zether_transfer'
    target: str                     # địa chỉ contract dạng canonical của chain đó
    payload: bytes                  # calldata EVM | BOC TON | PTB bytes Sui | XDR Soroban
    asset_caip19: Optional[str]
    amount: int                     # đơn vị nhỏ nhất
    fee_offer: Optional["FeeOffer"] # None trên chain FEE_FREE
    deadline_epoch_ms: int
    sponsor_mode: str               # 'contract_metatx'|'protocol_payer'|'envelope'|'none'
    user_pubkey: Optional[bytes]    # cần cho chain xác thực bằng key, không bằng address

@dataclass(frozen=True)
class FeeOffer:
    fee_asset_caip19: str
    fee_amount: int
    rate_source: str                # 'chainlink:XDAI/USD' | 'internal:treasury' | 'fixed'
    rate_expiry_epoch_ms: int
    max_slippage_bps: int

@dataclass(frozen=True)
class UnsignedTx:
    intent_id: str
    body: bytes                     # dạng serialize gốc của chain
    digest: bytes                   # cái Signer thật sự ký
    digest_is_prehashed: bool       # False ⇒ Signer phải nhận nguyên message (Ed25519 thuần)
    scheme: SigScheme
    order: "OrderToken"
    adapter_state: dict             # footprint Soroban, gas coin Sui, query_id TON

@dataclass(frozen=True)
class SimResult:
    ok: bool
    revert_reason: Optional[str]
    gas_units: int
    resources: dict                 # Soroban: cpu_insns/mem_bytes/read_bytes/write_bytes
    footprint: Optional[bytes]      # chỉ Soroban
    state_diff_digest: Optional[str]# hash các thay đổi số dư, để so lại sau khi final
    simulated_at_block: str

@dataclass(frozen=True)
class FeeQuote:
    amount: int              # đơn vị nhỏ nhất của fee_asset
    fee_asset: str           # 'native' | CAIP-19 của ERC-20 (Celo feeCurrency)
    usd_estimate: float
    breakdown: dict          # {'gas': .., 'resource': .., 'rent': ..} — Soroban tách 3 khoản
    rate_source: str
    quote_expiry_epoch_ms: int

@dataclass(frozen=True)
class OrderToken:
    """Cái thay thế cho 'nonce'. Mỗi họ chain điền một dạng khác nhau."""
    kind: str                # 'nonce' | 'sequence' | 'seqno' | 'valid_start' | 'gas_coin' | 'query_id'
    value: str               # int dạng chuỗi, hoặc ObjectID của gas coin trên Sui
    lease_id: str
    expiry_epoch_ms: int

@dataclass(frozen=True)
class FeeBump:
    """Thay cho một method replace() sẽ NotImplemented trên 4/6 hệ."""
    previous_handle: str
    multiplier_bps: int      # 11_000 = +10%, đúng ngưỡng tối thiểu của geth/Besu

@dataclass(frozen=True)
class SubmitResult:
    handle: str              # tx hash | TransactionId | ObjectID digest | msg hash
    accepted_at_ms: int
    is_terminal: bool        # Hedera/Sui trả kết quả ngay; EVM/TON thì không

@dataclass(frozen=True)
class Hop:
    """TON: một 'giao dịch' là một cây message. Các chain khác trả list rỗng."""
    lt: int                  # logical time
    src: str
    dst: str
    success: bool
    bounced: bool

@dataclass(frozen=True)
class Receipt:
    handle: str
    block_ref: str           # 'number:hash' | checkpoint seq | ledger seq | consensus ts
    status: bool
    gas_used: int
    fee_paid: int
    fee_asset: str
    logs: list
    hops: list[Hop]

class FinalityLevel(Enum):
    UNKNOWN   = 0
    SUBMITTED = 1
    SOFT      = 2     # sequencer / 1 block / mempool accepted
    FINAL     = 3     # đủ điều kiện _set_done
    REORGED   = 4     # đã từng SOFT hoặc FINAL, nay không còn
    DROPPED   = 5     # rơi khỏi mempool, không bao giờ lên chain

@dataclass(frozen=True)
class FinalityVerdict:
    level: FinalityLevel
    observed_depth: int
    quorum_agreed: int       # bao nhiêu endpoint độc lập đồng ý
    block_ref: str
    reorg_of: Optional[str]

class Signer(Protocol):
    """§07 cài đặt. Adapter không bao giờ thấy khoá."""
    async def sign(self, key_ref: str, payload: bytes,
                   prehashed: bool, scheme: SigScheme) -> bytes: ...
    async def public_key(self, key_ref: str, scheme: SigScheme) -> bytes: ...

# ---------- interface ----------

class ChainAdapter(Protocol):
    caip2: str
    capabilities: frozenset[str]
    is_stateful: bool

    # 1-2: địa chỉ (đồng bộ, không I/O — dùng được cả trong Odoo qua lib/addr.py)
    def normalize_address(self, raw: str) -> str: ...
    def address_is_valid(self, raw: str) -> bool: ...

    # 3: chống chain đổi dưới chân (giả định A5)
    async def preflight(self) -> "PreflightReport": ...

    # 4-7: đường đi của một intent
    async def build_unsigned(self, intent: Intent, order: OrderToken) -> UnsignedTx: ...
    async def simulate(self, tx: UnsignedTx) -> SimResult: ...
    async def estimate_fee(self, tx: UnsignedTx, sim: SimResult) -> FeeQuote: ...
    async def sign_and_submit(self, tx: UnsignedTx, user_sig: bytes | None,
                              signer: Signer,
                              bump: FeeBump | None = None) -> SubmitResult: ...

    # 8-9: theo dõi
    async def get_receipt(self, handle: str) -> Optional[Receipt]: ...
    async def finality(self, receipt: Receipt) -> FinalityVerdict: ...

    # 10: stream — cursor bền, xem §08.2c
    def subscribe_events(self, flt: "EventFilter") -> AsyncIterator["Event"]: ...

    # 11: gas station (giả định A9). Thiếu nó = pool chết im lặng
    async def get_balance(self, address: str, asset_caip19: str | None) -> int: ...

    # 12: decode (giả định A8). Không decode được event = không khớp được job
    def decode_event(self, raw_log: dict) -> Optional["Event"]: ...
```

**Capability flags** (chuỗi trong `capabilities`) là cách duy nhất caller được phép rẽ nhánh theo chain, thay vì `if self.caip2.startswith('eip155')`:

| Flag | Ý nghĩa | Chain có |
|---|---|---|
| `SPONSOR_CONTRACT_METATX` | Relayer broadcast, contract verify user sig, trả fee token cho `msg.sender` | EVM, Hedera (HSCS), CosmWasm |
| `SPONSOR_PROTOCOL_PAYER` | Giao thức có trường "ai trả phí", không cần contract | Hedera, Sui, Soroban, Cosmos (`x/feegrant`) |
| `SPONSOR_ENVELOPE_WRAP` | Sponsor bọc tx đã ký của user | Soroban (fee-bump), TON (external msg) |
| `FEE_IN_ERC20` | Phí trả bằng token không phải native | Celo (CIP-52) |
| `FEE_FREE` | Gas price = 0 | Besu private, Cosmos appchain tự cấu hình. **[SỬA]** Bản nháp ghi "Celo Alfajores nội bộ" — sai, Alfajores là testnet công khai và vẫn tính gas |
| `SUPPORTS_REPLACEMENT` | Thay tx đang pending bằng tx cùng thứ tự, phí cao hơn | EVM (≥10% bump), CosmWasm (cùng sequence). **Không**: Sui, Hedera, Soroban, TON |
| `PRIVATE_SUBMISSION` | Có endpoint gửi tx không qua mempool công khai | Ethereum (Flashbots Protect), Gnosis (MEV Blocker) — verify từng chain |
| `SIM_PRODUCES_FOOTPRINT` | Simulate **bắt buộc**, output là input của build | Soroban |
| `STATE_RENT` | State có TTL, có thể bị archive | Soroban |
| `NO_NONCE_OBJECT_VERSION` | Không có nonce; thứ tự = version của object | Sui |
| `ASYNC_MESSAGE_TREE` | Một "giao dịch" là một cây message nhiều hop | TON |
| `DUAL_IDENTITY` | Một account có hai dạng địa chỉ hợp lệ | Hedera (`0.0.x` + EVM alias) |
| `ZK_ALTBN128_PRECOMPILE` | Có `ecAdd`/`ecMul`/`ecPairing` ở `0x06`/`0x07`/`0x08` | EVM, Hedera HSCS, Cosmos-EVM chains |
| `ZK_BLS12381_NATIVE` | Có host function/opcode BLS12-381 G1 MSM | Soroban (P22), TON (TVM v5+), Sui (`group_ops`) |

**Nguồn sự thật của capability là adapter, không phải record.** `preflight()` ghi tập cờ quan sát được vào `blockchain.chain.capability_flags`; field đó read-only trên form. Hai nguồn sự thật cho cùng một tập cờ là cách chắc chắn nhất để có drift.

#### 08.2b. Ranh giới Odoo ↔ relay-pool: outbox, không phải HTTP

Bản nháp nói adapter nằm **ngoài** addon nhưng không nói Odoo gọi nó bằng cách nào. Đây là quyết định kiến trúc lớn nhất còn để trống, và nếu chọn sai thì mỗi lần relay-pool chậm sẽ khoá một worker HTTP của Odoo.

**Chốt: transactional outbox, worker poll. Odoo không bao giờ gọi chain đồng bộ.**

```
Odoo (business tx)                 relay-pool (asyncio, ngoài addon)
──────────────────                 ─────────────────────────────────
INSERT blockchain.relay.job   ──►  poll SELECT ... WHERE state='queued'
  state='queued'                     FOR UPDATE SKIP LOCKED LIMIT 50
  intent_json (metadata nhỏ)
  idempotency_key UNIQUE             adapter.build → simulate → submit
COMMIT (cùng transaction với         UPDATE job SET state='submitted', handle=...
        record nghiệp vụ)
                                     finality loop → state='final' | 'reorged'
Odoo cron/queue đọc job 'final'  ◄──
  → payment.transaction._set_done()
```

Bốn lý do chọn outbox thay vì HTTP call từ Odoo:

1. **Nguyên tử với nghiệp vụ.** Job và `account.move`/`payment.transaction` ghi trong **cùng một** transaction PostgreSQL. Với HTTP: hoặc gọi trước commit (gọi rồi rollback = tiền đi mà sổ không ghi), hoặc gọi sau commit (commit rồi service chết = sổ ghi mà tiền không đi). Outbox loại bỏ cả hai.
2. **Relay-pool chết không kéo Odoo chết.** Job đọng ở `queued`, không có worker Odoo nào bị treo.
3. **Idempotency miễn phí.** `models.Constraint('UNIQUE(idempotency_key)', ...)` — kiểm chứng bằng `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_relay_job'::regclass;`, đừng tin code (bẫy §5.2 CLAUDE.md: `_sql_constraints` dạng list bị Odoo 19 bỏ qua **hoàn toàn**).
4. **`SKIP LOCKED` cho phép N worker** mà không cần một broker mới. Không thêm RabbitMQ/Celery cho một hàng đợi mà PostgreSQL làm được bằng một câu lệnh.

Chiều ngược lại (relay-pool ghi kết quả về Odoo) đi qua đúng RPC surface đã chốt ở CLAUDE.md §6: `POST /json/2/blockchain.relay.job/job_report_result` với JWT của một service user chuyên dụng. Không viết controller mới.

`intent_json` là **metadata nhỏ** — chain, target, selector, số tiền, deadline. Payload nhị phân lớn (BOC, XDR, proof Bulletproof 1.4 KB) đi qua `ir.attachment` trên Garage, đúng quy ước "không JSON blob, không base64 trong DB".

#### 08.2c. `subscribe_events`: chỗ một dòng interface giấu ba tuần việc

Bản nháp viết `subscribe_events` như thể nó là một generator. Sự thật vận hành:

| Vấn đề | Số cụ thể | Cơ chế |
|---|---|---|
| WS rớt kết nối | Alchemy/Infura ngắt WS sau ~5 phút không hoạt động; reconnect storm khi provider deploy | Cursor bền trong DB (`blockchain.chain.cursor_block`), **không** giữ trong RAM. Reconnect ⇒ backfill từ cursor |
| Gap khi backfill | `eth_getLogs` bị chặn 10.000 block (Alchemy/Infura); node riêng không chặn | `max_log_block_range` per endpoint, mặc định **1.000** (an toàn), 10.000 cho node riêng. Chunk và commit cursor sau mỗi chunk |
| Reorg xoá event đã đọc | Gnosis reorg 1-2 block là thường | Chỉ đẩy event vào ODS khi block đạt `finality_depth`; giữ buffer `finality_depth + 2` block để so lại |
| At-least-once | Không có exactly-once trên bất kỳ chain nào | Consumer phải idempotent theo `(handle, log_index)`; đây là constraint UNIQUE, không phải một lời khuyên |
| TON **không có log** | Không có `eth_getLogs` tương đương | Phải poll `getTransactions` theo account + `lt`; adapter TON dựng event từ cây message. Chi phí: 1 request/account/chu kỳ |
| Hedera không có WS cho contract log | Mirror node REST, độ trễ ~2-6 giây sau consensus | Poll mirror node; `finality` dựa vào consensus timestamp, không dựa vào độ sâu block |
| Sui | Checkpoint stream + `suix_subscribeEvent` (đang bị đánh dấu deprecated ở một số bản) | Dùng checkpoint polling làm đường chính, WS làm đường tăng tốc |

#### 08.2d. Error taxonomy: nếu thiếu, relay-pool không quyết được retry hay bỏ

Bản nháp không có. Đây là thứ quyết định mất tiền hay không: retry một `NonceConflict` là đúng, retry một `Equivocation` trên Sui là khoá object thêm 24 giờ.

```python
class AdapterError(Exception):
    retryable: bool
    backoff_ms: int

class TransientRpcError(AdapterError):    retryable = True   # 429, 5xx, timeout
class RateLimited(AdapterError):          retryable = True   # có Retry-After
class NonceConflict(AdapterError):        retryable = True   # xin lease mới rồi build lại
class InsufficientGasFunds(AdapterError): retryable = False  # cảnh báo ops, không retry
class SimulationRevert(AdapterError):     retryable = False  # có .reason
class Expired(AdapterError):              retryable = False  # deadline qua ⇒ intent mới
class Equivocation(AdapterError):         retryable = False  # Sui: KHÔNG được thử lại
class ChainMismatch(AdapterError):        retryable = False  # preflight fail ⇒ pause chain
class Rejected(AdapterError):             retryable = False  # policy/permissioning từ chối
```

Ánh xạ mẫu (bắt buộc mỗi adapter phải có bảng này trong test conformance):

| Chain | Chuỗi lỗi gốc | Map sang |
|---|---|---|
| EVM | `nonce too low` | `NonceConflict` |
| EVM | `replacement transaction underpriced` | `NonceConflict` (bump chưa đủ 10%) |
| EVM | `insufficient funds for gas * price + value` | `InsufficientGasFunds` |
| Sui | `ObjectVersionUnavailableForConsumption` | `Equivocation` — **không retry** |
| Hedera | `DUPLICATE_TRANSACTION` | `Expired` (phải sinh `validStart` mới) |
| Hedera | `BUSY` | `TransientRpcError` |
| Soroban | `TRY_AGAIN_LATER` | `TransientRpcError` |
| Soroban | entry archived | `SimulationRevert` → chuyển job sang `restoring` |
| Cosmos | `account sequence mismatch` | `NonceConflict` |
| Cosmos | `out of gas` | `SimulationRevert` |
| TON | external message không được accept | `TransientRpcError` (nhưng đếm, vì nó thường là `query_id` trùng) |

---

### 08.3. Chỗ trừu tượng hoá **buộc phải** rò rỉ

Đây là phần note gốc không nói, và nếu bỏ qua thì adapter Sui/TON sẽ được viết như adapter EVM rồi hỏng ở production. Bản nháp có 8 rò rỉ; dưới đây 14.

| # | Rò rỉ | Vì sao không che được | Lối thoát cụ thể |
|---|---|---|---|
| 1 | **Sui không có nonce.** Thứ tự = version của gas coin và owned object | `OrderToken.kind='gas_coin'`, `value` là `ObjectID`. Lease một *coin*, không lease một số | Pool N gas coin, `max_inflight = N`. §06.5 |
| 2 | **Sui equivocation lock.** Ký hai tx khác byte cùng dùng một owned object ⇒ object bị khoá tới hết epoch (~24h) | Không phải lỗi mạng, là hình phạt giao thức | Intent pool **phải** đảm bảo một intent chỉ có một sponsor. Trên public Sui: bắt buộc soft-exclusivity lottery (§05), không được gossip tự do. `Equivocation` là lỗi **không retryable** |
| 3 | **TON: "thành công" không có nghĩa gì.** External message được wallet nhận ≠ nghiệp vụ xong; kết quả thật ở hop 2-4, mỗi hop revert độc lập, tiền kẹt ở contract trung gian | Không có transaction nguyên tử đa contract trên TON. Bounce message trả tiền về nhưng **không** rollback state đã ghi | `get_receipt` phải trace **cây message** theo `logical time`, không phải một hash. `Receipt.hops: list[Hop]`. `is_terminal` chỉ True khi mọi lá của cây đã settle hoặc bounce |
| 4 | **Hedera: identity là `TransactionId`, không phải hash.** `validStart` chỉ hợp lệ trong cửa sổ ~180s; receipt sống ~3 phút rồi phải hỏi mirror node | Duplicate detection của Hedera dựa trên `TransactionId`, nên "retry cùng payload" = bị từ chối, không phải idempotent như ta muốn | `OrderToken.kind='valid_start'`. Retry **phải** sinh `validStart` mới ⇒ đây là tx khác, cần khoá idempotency ở tầng `blockchain.relay.job`, không dựa vào chain |
| 5 | **Soroban: footprint phải khai trước khi ký.** Chỉ `simulateTransaction` mới biết footprint | `simulate` không phải bước kiểm tra tuỳ chọn, nó là **một phần của build** | Adapter Soroban thực thi `build_unsigned` bằng cách gọi simulate nội bộ; `SIM_PRODUCES_FOOTPRINT` bắt caller không được skip |
| 6 | **Soroban: entry bị archive.** Đọc một entry hết TTL sẽ fail, cần `RestoreFootprint` preamble | Chain duy nhất trong 6 hệ mà "tiền biến mất khỏi tầm nhìn vì không đóng tiền thuê" là có thật | §08.8 — keeper cron do issuer trả, không phải user |
| 7 | **Celo: phí không phải native.** `FeeQuote.amount` vô nghĩa nếu không kèm `fee_asset` | Một `float gas_price` duy nhất là sai model | `FeeQuote` mang `fee_asset` bắt buộc. Gas breaker §06.4 phải so sánh theo `usd_estimate`, không theo native |
| 8 | **Cosmos `x/feegrant` đảo chiều luồng.** Granter chỉ là **một trường trong tx**; *user* mới là người broadcast | Ngược hoàn toàn với EIP-1776 (relayer broadcast) | Hai capability tách bạch: `SPONSOR_PROTOCOL_PAYER` (user broadcast, relay pool chỉ cấp allowance) và `SPONSOR_CONTRACT_METATX` (relay pool broadcast). Chọn cái nào là config per chain |
| 9 | **Hedera có hai địa chỉ cho một account.** `0.0.12345` và EVM alias `0x…` (20 byte) trỏ cùng một thực thể | HSCS trả log với địa chỉ EVM; SDK trả `AccountId`. Đối soát một chiều sẽ không match | Cờ `DUAL_IDENTITY`. Lưu **cả hai** cột; `normalize_address` trả dạng canonical `0.0.x`, `decode_event` phải map ngược qua mirror node |
| 10 | **Stellar fee-bump không tiêu sequence của người trả phí.** Inner tx giữ nguyên sequence của user | Nghe như chi tiết vụn, thực ra nó xoá bỏ nút thắt nonce của relayer | **Một** fee-source account phục vụ được số tx song song không giới hạn. Đây là chain duy nhất trong 6 hệ có tính chất đó — xem bảng throughput §08.3c |
| 11 | **Ed25519 thuần không ký được digest.** TON/Sui/Stellar/Hedera cần signer nhận **nguyên message** | ECDSA ký `H(m)`; Ed25519 (RFC 8032) hash bên trong thuật toán. Một KMS chỉ có API "sign this 32-byte digest" **không** ký Ed25519 được | `UnsignedTx.digest_is_prehashed = False` cho 4 hệ này. §07 phải xác nhận vendor hỗ trợ Ed25519 **trước** khi cam kết chain order |
| 12 | **ECDSA từ HSM thiếu recovery id.** KMS trả DER `(r,s)`; EVM cần `v` | Và cần chuẩn hoá low-s (EIP-2), nếu không tx bị từ chối | Adapter EVM tự thử `v ∈ {27,28}`, ecrecover, so với public key đã biết; nếu `s > n/2` thì `s = n - s`, lật `v`. Đây là ~15 dòng nhưng nếu quên thì ~50% giao dịch fail ngẫu nhiên |
| 13 | **Thời gian on-chain ≠ thời gian Odoo.** `deadline` được kiểm bằng block timestamp | Validator EVM được phép lệch tương lai tới 15s; Hedera `validStart` bị từ chối nếu ở tương lai | Quy tắc cứng: `deadline ≥ now + 120s + 3 × block_time + p99(queue_latency)`. Intent nào không thoả bị từ chối ở gateway, không gửi đi rồi hy vọng |
| 14 | **Gas free không xoá được thứ tự ưu tiên.** Trên Besu `gasPrice=0`, mọi tx bình đẳng | Không có cách nào để một settlement khẩn vượt lên trên 5.000 job batch | Tách EOA relayer theo lớp ưu tiên + admission control ở gateway. Ưu tiên là bài toán **hàng đợi ứng dụng**, không còn là bài toán phí |

**Không cố gộp 14 thứ này vào interface chung.** Interface core giữ 12 method; mỗi họ chain có một `Protocol` mở rộng (`SuiAdapterExt.lease_gas_coin()`, `TonAdapterExt.trace_message_tree()`, `SorobanAdapterExt.plan_restore()`, `HederaAdapterExt.resolve_alias()`) mà chỉ code đã kiểm tra capability flag mới được gọi.

#### 08.3b. Address format, signature scheme, order token: ba bảng brief yêu cầu

**Định dạng địa chỉ và dạng canonical để lưu:**

| Hệ | Dạng gốc | Bẫy | Canonical lưu trong DB |
|---|---|---|---|
| EVM | 20 byte hex, checksum EIP-55 | Chữ hoa/thường **là** checksum; so sánh chuỗi thô sẽ sai | Lower-case `0x` + 40 hex; hiển thị mới áp EIP-55 |
| Hedera | `0.0.12345` **và** EVM alias 20 byte | Hai danh tính, một thực thể (rò rỉ #9) | `0.0.x` ở `chain_address`, alias ở `chain_address_alt` |
| TON | raw `0:<64 hex>` **hoặc** user-friendly base64url với 3 cờ: bounceable, testnet, urlsafe | Cùng một ví có **4 chuỗi** hợp lệ khác nhau. Gửi tới dạng non-bounceable vs bounceable thay đổi hành vi khi contract chưa deploy | raw `0:<hex>`; UI hiển thị base64url bounceable, mainnet |
| Sui | 32 byte hex `0x…` (không phải 20) | Địa chỉ Sui đã đổi từ 20 → 32 byte năm 2022; thư viện cũ vẫn cắt 20 | 32 byte, có `0x`, lower-case, **không** rút gọn số 0 đầu |
| Soroban / Stellar | StrKey: `G…` (account, ed25519), `C…` (contract), `M…` (muxed) | `M…` chứa memo id bên trong — với B2B multi-tenant nó rất hữu ích nhưng nhiều ví không hỗ trợ | StrKey nguyên bản; ghi rõ loại vào `address_kind` |
| CosmWasm | bech32, HRP theo chain (`cosmos1…`, `neutron1…`, `osmo1…`) | Cùng public key ⇒ khác chuỗi theo từng chain. Copy địa chỉ giữa chain là lỗi thầm lặng | bech32 đầy đủ kèm HRP; **cấm** lưu 20 byte trần |

`normalize_address` phải reject chứ không "cố hiểu". Một địa chỉ EVM viết hoa sai checksum là địa chỉ người dùng gõ nhầm, không phải địa chỉ cần sửa hộ.

**Signature scheme và hệ quả lên custody (§07):**

| Hệ | Scheme | Prehashed? | Chữ ký meta-tx ký cái gì | Rủi ro custody |
|---|---|---|---|---|
| EVM | ECDSA secp256k1 + keccak256 | **Có** | EIP-712 typed data hash của struct `MetaTransaction` | Thấp. AWS KMS có `ECC_SECG_P256K1`; cần tự dựng `v` và low-s (rò rỉ #12) |
| Hedera | Ed25519 **hoặc** ECDSA secp256k1 | Ed25519: không / ECDSA: có | Body protobuf của transaction | Chọn **ECDSA secp256k1** nếu custody chỉ ký digest — Hedera hỗ trợ cả hai, đây là lối thoát rẻ nhất |
| TON | Ed25519 thuần | **Không** | Hash của cell body — nhưng ký qua API Ed25519 tiêu chuẩn nhận nguyên message | Cao nếu HSM chỉ ký digest |
| Sui | Ed25519 / secp256k1 / secp256r1 / zkLogin / passkey | Tuỳ scheme | `intent_message = intent_bytes ‖ bcs(TransactionData)` rồi blake2b | secp256r1 là lối thoát cho HSM FIPS (P-256 là scheme mọi HSM đều có) |
| Soroban | Ed25519 | **Không** | Transaction envelope hash (nhưng ký qua Ed25519 API) | Cao. Stellar không có phương án secp256k1 cho account signer |
| CosmWasm | secp256k1 (Amino/Protobuf `SIGN_MODE_DIRECT`) | **Có** | `SignDoc` protobuf, sha256 | Thấp |

**Đây là một phát hiện cross-section, không phải chi tiết vụn:** ba trong sáu hệ (TON, Soroban, và Sui/Hedera nếu chọn Ed25519) đòi một signer ký Ed25519 **thuần**. `blockchain.md` yêu cầu HSM FIPS 140-2 Level 3 cho mọi khoá. Trước khi cam kết chain order phải trả lời: HSM/MPC đã chọn có ký Ed25519 không? Nếu không, ba lối thoát theo thứ tự rẻ dần: (a) chọn ECDSA secp256k1 trên Hedera và secp256r1 trên Sui — chỉ còn TON và Soroban là vấn đề; (b) MPC provider (Fireblocks/Fordefi/Turnkey đều có Ed25519) thay vì HSM thuần; (c) hoãn TON/Soroban sang wave sau — vốn đã là wave 3-4 theo bảng §08.9b, nên chi phí của lựa chọn (c) gần bằng 0.

**Order token và trần song song mỗi ví relayer:**

| Hệ | Cơ chế thứ tự | Song song trên **một** ví | Số cụ thể |
|---|---|---|---|
| EVM | nonce tuần tự per EOA | Bị chặn cứng | geth `txpool.accountslots = 16` mặc định ⇒ ~16 tx in-flight/EOA. Muốn 100 tx song song ⇒ **7 EOA** |
| EVM (meta-tx 2D nonce) | `batchId` + `batchNonce` trong forwarder | Không giới hạn theo user | 2D nonce giải head-of-line cho **user**, không giải cho **EOA relayer**. Hai bài toán khác nhau — bản nháp gộp chúng |
| Hedera | `TransactionId = payer + validStart` | Cao | Không có nonce; giới hạn là throttle mạng, không phải ví |
| TON | `query_id` (Highload Wallet V3) | Cao | Xem §08.6 — **[SỬA]** con số của bản nháp |
| Sui | version của gas coin | = số gas coin trong pool | 1 tx/coin/lúc. Pool 50 coin ⇒ 50 in-flight |
| Soroban | sequence của **inner** account; fee source không tiêu sequence | **Không giới hạn cho fee source** | Rò rỉ #10 — ưu thế lớn nhất của Stellar trong 6 hệ |
| CosmWasm | account sequence tuần tự | Bị chặn cứng như EVM | 1 tx/sequence; cần nhiều account relayer |

#### 08.3c. Trần throughput thực tế mỗi hệ (ước tính, cần đo lại)

| Hệ | Ceiling do đâu | Số |
|---|---|---|
| Besu private QBFT | block gas limit 50M / block 2s | 25M gas/s ⇒ **~4 tx Zether/s** (6.3M gas) hoặc ~1.000 tx ERC-20 đơn giản/s |
| Gnosis public | block gas limit 17M / 5s | 3,4M gas/s toàn mạng ⇒ **~0,5 tx Zether/s** nếu chiếm 100% chain. Dùng >10% chain là hành vi phản xã hội ⇒ thực tế ~0,05 tx/s |
| Celo L2 | ~1s block, gas limit op-stack | Cao; nút thắt là chi phí đăng dữ liệu lên L1 |
| Hedera | throttle mạng ~15M gas/s cho contract call; max 15M gas/tx | **~2 tx Zether/s cho toàn mạng Hedera** — không phải cho ta. Loại Hedera khỏi Zether tần suất cao |
| TON | 254 out-message mỗi external message, ~1-2 external/ví/block 5s | **~50-100 msg/s mỗi ví relayer** (ước tính, cần benchmark) |
| Sui | 1 tx/gas coin; checkpoint ~250ms | Giới hạn thực tế là kích thước pool coin, không phải chain |
| Soroban | 100M CPU instruction/tx; ledger 5s | Zether verify sẽ chạm trần instruction trước khi chạm trần TPS |

---

### 08.4. EVM: Gnosis xDAI → Celo → L2s

| Chain | CAIP-2 | Block | Finality gate | Phí 1 tx thường | Zether verify (~6,3M gas, §08.4b) |
|---|---|---|---|---|---|
| Gnosis | `eip155:100` | 5s | soft 1 block / hard **~3-4 phút** **[SỬA]** | < $0,001 | **~$0,013** (2 gwei xDAI) |
| Celo | `eip155:42220` | ~1s (L2) | **xem cảnh báo dưới** | < $0,001, trả bằng cUSD/USDC | tương tự |
| Arbitrum/Base | `eip155:42161` / `8453` | 250ms | soft ~1s / hard 15-25 phút | $0,001-0,01 | $0,01-0,10 |
| Polygon PoS | `eip155:137` | 2s | **milestone ~1-2 phút** **[SỬA]** | < $0,01 | ~$0,05 |
| Ethereum L1 | `eip155:1` | 12s | 2 epoch = 12,8 phút | $0,5-5 | **$80-500 — loại** |

**[SỬA] Ba con số finality trong `blockchain.md` §10.4 sai và cả ba đều sai theo hướng nguy hiểm** (một cái quá bi quan, hai cái quá lạc quan):

1. **Gnosis: 12,8 phút là sai.** 12,8 phút là con số của Ethereum (2 epoch × 32 slot × 12s = 768s). Gnosis Beacon Chain có slot 5s và **16 slot/epoch** ⇒ 80s/epoch ⇒ finalization sau 2 epoch ≈ **160-240 giây**. Đặt 12,8 phút làm ngưỡng `_set_done` nghĩa là bắt khách hàng chờ gấp 4 lần cần thiết — trên chain được chọn làm chain #1.
2. **Polygon PoS: 25-30 phút là số của thời trước milestone.** Từ khi Heimdall milestone hoạt động (2023), Bor có finality xác định trong **~1-2 phút**. Con số 30 phút giờ chỉ đúng cho checkpoint phục vụ cầu nối về L1.
3. **Celo "IBFT 2.0, immediate finality, ~5 giây" đã hết đúng.** Celo mainnet đã chuyển thành L2 trên OP Stack (mốc công bố: tháng 3/2025 — cần xác nhận lại ngày chính xác trước khi trích dẫn ra ngoài). Hệ quả: Celo **mất finality tức thì** và giờ có cấu trúc soft/hard giống Arbitrum/Base. Phải đặt `finality_mode='l1_batch'`, **không** phải `bft_instant`. Nếu để nguyên dòng cũ, Finality Gate sẽ báo `done` trước khi tiền an toàn.

**Meta-tx**: `MetaTxForwarder` của §04 chạy nguyên vẹn trên cả năm. Không có gì đặc thù cần adapter riêng ngoài `feeCurrency`.

**Celo CIP-52**: giao dịch khai `feeCurrency = address(cUSD)`; validator trừ phí bằng chính ERC-20 đó qua `FeeCurrencyDirectory`. Với Open Relayer đây là điều kiện đẹp nhất trong 6 hệ: relayer **không cần giữ native token nào cả**, vốn lưu động của nó và fee nó thu về cùng một đơn vị ⇒ P&L của relayer không có rủi ro tỷ giá, và `FeeOffer.rate_source` có thể đặt `'fixed'`. Trên Gnosis thì native đã là stablecoin nên kết quả tương đương, chỉ khác là relayer buộc phải giữ xDAI và vẫn cần một tỷ giá nếu `fee` thu bằng token khác xDAI.

#### 08.4b. Mô hình gas cho Zether verify, và tại sao 128-bit là lựa chọn sai

Bản nháp và `blockchain.md` §01 nói "2,5-4M gas" mà không cho cơ sở. Cơ sở như sau, dùng giá precompile sau EIP-1108 (Istanbul, 12/2019 — chính EIP này hạ `ecMul` từ 40.000 xuống 6.000 và là lý do Zether trở nên khả thi trên EVM):

```
ecAdd (0x06)     =    150 gas
ecMul (0x07)     =  6.000 gas
ecPairing (0x08) = 45.000 + 34.000 mỗi cặp
```

Verify một Bulletproof gộp m mệnh đề, mỗi mệnh đề n bit, tổng N = m·n:
kích thước multi-exponentiation ≈ **2N + 2·log2(N) + 7** điểm.
EVM **không có** precompile MSM ⇒ mỗi điểm là một `ecMul` riêng, không gộp được.

| Cấu hình | N | Số `ecMul` | Gas MSM | + sigma proof & overhead | **Tổng ước tính** |
|---|---|---|---|---|---|
| 4 mệnh đề × 128 bit (`blockchain.md` hiện tại) | 512 | ~1.049 | 6,29M | ~0,3M | **~6,6M** |
| 4 × 64 bit | 256 | ~535 | 3,21M | ~0,3M | **~3,5M** |
| 3 × 64 bit (fee công khai, xem dưới) | 192 | ~407 | 2,44M | ~0,25M | **~2,7M** |

Kích thước proof: 2·⌈log2(N)⌉ + 4 điểm G1 + 5 scalar. Với N=256: 20 × 64 byte + 5 × 32 byte = **1.440 byte** calldata ≈ 23.000 gas calldata (16 gas/byte khác 0). Không đáng kể so với MSM.

**Hai kết luận đi ngược `blockchain.md`:**

*(a) Trần 2^128 giải sai bài toán.* Note lập luận đúng rằng `MAX = 2^32-1` của ConsenSys là vô dụng với token 18 decimals (4,29e9 wei = 0,00000000429 token). Nhưng cần cẩn thận: đòn bẩy đúng **không phải** nâng range proof lên 128 bit, mà là **định nghĩa đơn vị nội bộ của Zether token ở 6 decimals** (đúng như USDC, đúng như HTS của Hedera). Khi đó `2^64 - 1 ≈ 1,8e19` đơn vị = **18 nghìn tỷ USD** ở 6 decimals — thừa cho mọi kịch bản DMS và mọi kịch bản B2B Việt Nam. Chi phí: mất độ chính xác dưới 1e-6 token khi deposit/withdraw từ ERC-20 18 decimals, xử lý bằng cách làm tròn xuống và giữ phần dư trong contract (một dòng, đã là chuẩn của mọi cầu nối decimals). Lợi ích: **gas verify giảm ~47%** (6,6M → 3,5M), proof nhỏ hơn, và quan trọng nhất là **lọt vào trần 15M gas/tx của Hedera với biên an toàn** thay vì sát mép.

*(b) `EncryptedTransfer` vừa có `uint256 fee` công khai vừa có `C_fee` ciphertext, và không có mệnh đề nào buộc hai cái khớp nhau.* Đây hoặc là dư thừa hoặc là lỗ hổng soundness — không thể là cả hai. Triết lý đã khoá của dự án là **Public Relayer Fee** (relayer phải *thấy* fee để định giá): vậy giữ `fee` là `uint256` công khai, **bỏ `C_fee`**, và thay range proof cho fee bằng một sigma proof đẳng thức rẻ (chứng minh ciphertext trừ tiền mã hoá đúng `v + fee` với `fee` là hằng công khai). Bớt một mệnh đề range ⇒ N=192 ⇒ **~2,7M gas**, giảm 59% so với thiết kế hiện tại. Chi tiết mật mã thuộc §03; ở đây chỉ ghi nhận hệ quả: **quyết định này thay đổi tính khả thi của Zether trên Hedera và Gnosis, nên nó phải được chốt trước khi khoá chain order.**

Các con số trên là **ước tính từ nguyên lý**, không phải đo. Sai số có thể lớn theo cả hai chiều (implementation dùng bảng precompute; hoặc dùng nhiều pairing hơn dự kiến). Việc cần làm trước khi cam kết: fork Gnosis bằng anvil, deploy verifier hiện có, đo `gasUsed` thật cho cả ba cấu hình. Đó là 1-2 ngày công và nó quyết định 3 dòng trong bảng §08.9b.

#### 08.4c. "Tỷ lệ revert 0%" không tồn tại — và ai chịu tiền khi revert

`blockchain.md` §10.1 và §14.2.8 đều viết Simulation Gate phải đạt *"tỷ lệ revert bằng 0%"*. **Không đạt được**, vì một lý do đơn giản: `eth_estimateGas` chạy trên state ở block `N`, tx được đưa vào block `N+k`. Mọi thứ thay đổi trong khoảng đó — allowance bị rút, số dư bị tiêu, oracle đổi giá, contract bị pause — biến một simulate thành công thành một revert thật. Trên chain có mempool công khai, kẻ tấn công **cố tình** tạo khoảng đó.

Simulate giảm revert, không xoá revert. Ngân sách hợp lý: **0,5-2% revert** trên public chain có mempool mở, **<0,1%** trên private chain permissioned. Đó là một dòng chi phí, không phải một bug cần đóng.

**Và đây là lỗ hổng kinh tế của EIP-1776 mà cả note lẫn bản nháp không nói:** nếu forwarder gọi thẳng `to.call(data)` và inner call revert, toàn bộ transaction revert ⇒ **lệnh chuyển `fee` cho relayer cũng revert** ⇒ relayer trả gas và nhận về đúng 0. Trên một mạng open relayer, đây là vector tấn công gần như miễn phí: ký một loạt meta-tx chắc chắn revert, thả vào mempool, đốt tiền gas của mọi relayer.

Yêu cầu bắt buộc gửi sang §04 (thiết kế `MetaTxForwarder`):

```solidity
// forwarder PHẢI tách validation khỏi execution
(bool ok, bytes memory ret) = metaTx.to.call{gas: innerGasLimit}(metaTx.data);
// fee được thu BẤT KỂ ok — vì user đã ký uỷ quyền và relayer đã bỏ gas thật
_chargeFee(metaTx);            // luôn chạy
emit MetaTxExecuted(digest, ok, ret);
if (!ok) { /* KHÔNG revert; ghi nhận thất bại nghiệp vụ */ }
```

Đây chính là lý do ERC-4337 tách `validateUserOp` khỏi `execute`. EIP-1776 không có kiến trúc đó sẵn, ta phải tự áp. Hệ quả nghiệp vụ: một meta-tx có thể "thành công on-chain" (fee đã trả) nhưng "thất bại nghiệp vụ" (`ok == false`). `blockchain.relay.job` cần **hai** field trạng thái, không phải một: `chain_state` và `business_state`. Và `payment.transaction._set_done()` chỉ được gọi khi cả hai đều thành công — nguyên tắc `dms_vietqr` áp thêm một tầng nữa: *tx lên chain không phải là nghiệp vụ đã xong*.

**Zether trên EVM**: đây là hệ duy nhất Zether chạy được **hôm nay** mà không cần viết lại mật mã — `ecAdd`/`ecMul`/`ecPairing` ở `0x06`/`0x07`/`0x08`, alt_bn128, đúng đường cong của `anonymous-zether`. Trên Besu private với `zeroBaseFee`, 3-7M gas là một dòng kế toán nội bộ; trên Ethereum L1 nó là $80-500/giao dịch (cơ sở: 6,6M gas × 10 gwei × $3.000/ETH = $198; ở 5 gwei/$2.500 = $83; ở 20 gwei/$4.000 = $528).

---

### 08.5. HBAR (Hedera)

| Cơ chế | Ánh xạ sang EIP-1776 |
|---|---|
| **Payer Account** (`TransactionId.generate(relayerAccountId)`) | Tương đương `mode` + relayer trả gas, nhưng ở **tầng giao thức**, không cần contract. Relayer ký `Fee Payer Signature`; user ký chữ ký nghiệp vụ |
| **HTS transfer trong cùng tx** | Tương đương `fee` + `tokenContract` của EIP-1776. Nguyên tử vì Hedera cho phép nhiều transfer trong một `TransferTransaction` |
| **Scheduled Transactions** | Không có tương đương EVM. Dùng cho R3/R4: `ScheduleCreateTransaction` → nhiều `ScheduleSignTransaction` → mạng tự thực thi khi đủ ngưỡng. Đây là multisig **cấp giao thức**, rẻ hơn Gnosis Safe rất nhiều. Lưu ý: schedule có thời hạn (mặc định ~30 phút, tối đa cấu hình được) — quá hạn mà chưa đủ chữ ký thì tự huỷ, phải có cron nhắc |
| **HCS** | Không phải meta-tx. Là nơi neo hash cho Finality Gate: `TopicMessageSubmitTransaction`, ~$0,0001/message, consensus timestamp có giá trị pháp lý |

**Đặc tả cụ thể cho HCS anchoring mà note để ngỏ.** Neo **một hash mỗi giờ** (Merkle root của mọi `blockchain.relay.job` đạt `final` trong giờ đó), không neo từng giao dịch. Lý do: neo từng giao dịch nhân đôi số tx và không thêm bằng chứng nào — Merkle root + inclusion proof lưu trong `ir.attachment` trên Garage đã đủ cho kiểm toán.

Định dạng message (giữ dưới 1.024 byte để nằm trong một `TopicMessageSubmitTransaction`, không phải chunk):

```json
{"v":1,"caip2":"eip155:1337","from_ms":1735689600000,"to_ms":1735693200000,
 "n":1842,"root":"0x…32byte…","prev":"0x…32byte…"}
```

`prev` móc xích các anchor thành một chuỗi — thiếu nó thì xoá một anchor không để lại dấu vết. Chi phí: 24 message/ngày ≈ $0,0024/ngày ≈ **$0,88/năm**. Đây là cách rẻ nhất để có mốc thời gian không thể chối cãi cho **toàn bộ** hệ thống, và nó đặc biệt quan trọng cho phần chạy trên private chain — xem §08.10, mục "thâm hụt niềm tin".

**Zether trên HSCS**: HSCS chạy EVM bytecode và hỗ trợ precompile `0x01`-`0x09`, nên về code là port được. Rào cản là **kinh tế và throttle**:

| Yếu tố | Số | Hệ quả |
|---|---|---|
| Gas price HSCS | neo theo USD, khoảng $0,05-0,17 mỗi 1M gas (số công bố, cần đo lại) | 6,6M gas ⇒ **$0,33-1,10/giao dịch**. Với 3 × 64-bit (§08.4b, 2,7M gas) ⇒ $0,14-0,46 |
| Max gas mỗi contract call | 15.000.000 | 6,6M lọt nhưng biên mỏng; nếu verifier phình thêm 2× là chạm trần |
| Throttle gas toàn mạng | ~15M gas/giây cho contract call | **~2 tx Zether/giây cho toàn bộ Hedera** — không phải cho ta |

Vai trò đúng của Hedera trong kiến trúc này: **HCS làm audit anchor** (rẻ, độc lập, có giá trị pháp lý), **HTS làm token B2B công khai**, **HSCS chỉ cho hợp đồng escrow ít giao dịch**. Không đặt Zether tần suất cao ở đây.

---

### 08.6. TON

**Meta-tx**: chạy được, và chạy tốt. Wallet V5R1 (W5) chấp nhận signed request đến qua **internal message**, nghĩa là relayer có thể trả phí và forward hộ; TEP-74 Jetton transfer trong cùng chuỗi message trả thưởng cho relayer.

**[SỬA] Con số throughput của bản nháp.** Bản nháp viết *"cửa sổ `query_id` ~8192 slot trong 128 giây ⇒ trần lý thuyết ~64 tx/s"*. Đó là đọc sai cấu trúc `query_id` của Highload Wallet V3: nó gồm `shift` (13 bit) và `bit_number` (10 bit) ⇒ không gian **2^23 ≈ 8,39 triệu** id, được tái sử dụng sau `timeout` giây. Trần thật không nằm ở query_id mà ở hai chỗ khác:

- **254 out-message mỗi external message** (giới hạn action list của TVM).
- Số external message một contract xử lý được mỗi block (~5s), thực nghiệm 1-2.

⇒ ước tính **50-100 out-message/giây cho một ví relayer**, cần benchmark trên testnet trước khi đưa vào `blockchain.relayer.account.max_inflight`. Con số này *cao hơn* con số của bản nháp, nên nó không đổi kết luận nào, nhưng nó đổi cách cấu hình: nút thắt là **batching** (gom 254 action vào một external), không phải là số ví.

**Sự thật khó nghe về ZK trên TVM**: TVM (nâng cấp 2023-2024) đã thêm opcode BLS12-381 (`BLS_G1_ADD`, `BLS_G1_MULTIEXP`, `BLS_PAIRING`, `BLS_VERIFY`). Vậy Bulletproofs **về nguyên tắc** implement được. Nhưng bốn rào cản là thật:

1. **Sai đường cong.** TON có BLS12-381, Zether/`anonymous-zether` là alt_bn128. Không port được — phải **viết lại verifier bằng FunC/Tact và viết lại prover phía client** cho BLS12-381. Ước tính 9-15 tháng cộng audit. (Ước tính dựa trên: một verifier Bulletproof viết mới trên VM lạ + prover client + audit thường rơi vào khoảng đó; không có mốc so sánh trực tiếp trên TON.)
2. **Trần gas mỗi transaction.** Basechain mặc định ~1.000.000 gas unit (contract đặc biệt ~10M). Một verifier 64-bit cần MSM ~535 điểm cộng 7 vòng inner-product; ngay cả với opcode native, chi phí nằm ở vùng biên của trần đó. Cần benchmark trước, không cần thiết kế trước.
3. **`simulateAccounts` không có tương đương on-chain.** Trên EVM nó là một `view` mà contract khác gọi được. Trên TON không có synchronous cross-contract read — chỉ có get-method chạy **off-chain** qua `runGetMethod`. Với client SDK thì đủ (client vốn ở off-chain), nhưng bất kỳ contract nào muốn đọc số dư Zether của contract khác đều không làm được.
4. **Ed25519 thuần** (rò rỉ #11): custody phải ký được Ed25519, không có phương án thay thế trên TON.

Điều **cứu** Zether trên TON, nếu ngày nào đó làm: Zether là **một contract duy nhất** (registry + balance + verifier), nên actor model async không phá nó như phá một hệ multi-contract. Nghịch lý dễ chịu: cái khó nhất của TON lại không đụng đến Zether. Vẫn xếp TON ở wave 4.

---

### 08.7. SUI

**Sponsored transaction là native và là mô hình sạch nhất trong 6 hệ**: user dựng `TransactionData` với `gas_data.owner = sponsor`, sponsor ký **đúng cùng chuỗi byte** ⇒ tx có hai chữ ký trên một intent duy nhất. Sponsor **nhìn thấy toàn bộ PTB trước khi ký**, nên lệnh chuyển token thưởng nằm ngay trong PTB là verifiable một cách tầm thường — không cần `mode` bitmask, không cần simulate để biết mình có được trả không. Đây là điều EIP-1776 phải mô phỏng bằng cả một struct.

Vài trần cần đưa vào `blockchain.chain`: tối đa **1.024 lệnh** trong một PTB, kích thước tx tối đa **128 KB**, gas budget tối đa **50 SUI**.

Cái giá: **equivocation** (rò rỉ #2). Nếu user gửi cùng một intent cho hai relayer và hai relayer gắn hai gas coin khác nhau, hai tx khác byte cùng tiêu một owned object ⇒ object bị khoá tới hết epoch (~24h). Trên public Sui, **mô hình open relayer market tự do là không an toàn**; phải có exclusivity per intent. Trong error taxonomy, `Equivocation` là lỗi duy nhất mà retry làm tình hình **tệ hơn**.

**Zether trên Sui — hai phát hiện đáng đổi thiết kế:**

1. **Đừng port Bulletproofs.** Sui Move có `sui::groth16::verify_groth16_proof` (native, hỗ trợ BN254 và BLS12-381), rẻ hơn một verifier Bulletproofs viết tay bằng `group_ops` (~535 scalar mul trong Move) vài bậc, và proof cố định 128-192 byte thay vì 1,4 KB. Đánh đổi: Groth16 cần **trusted setup ceremony** cho mạch range proof — thứ mà nhánh Bulletproofs trên EVM cố tình tránh. Đây là một ngã ba thật: setup ceremony (chi phí tổ chức, rủi ro chính trị, phải công bố transcript) đổi lấy phí verify thấp và proof nhỏ.
2. **Object model xoá bỏ nhu cầu epoch/`rollOver`.** Cơ chế Epoch của Zether tồn tại chỉ để giải một race: nhiều khoản chuyển đến cùng một tài khoản trong cùng block làm hỏng ciphertext người nhận. Sui **tuần tự hoá truy cập theo object**: nếu mỗi tài khoản Zether là một object riêng (`ZetherAccount`), consensus đã sắp thứ tự giúp, `pending_transfers` và `rollOver()` trở nên thừa. Đổi lại phải chấp nhận đây không còn là "Zether" theo đúng bài báo mà là một biến thể — và mọi tài sản kiểm toán/tài liệu sẽ nói về hai thiết kế khác nhau trên hai chain.

Cảnh báo throughput: nếu đặt **một** shared object cho cả token thì mọi transfer đều tranh nó và Sui congestion control sẽ chặn cứng. Một object per account là **bắt buộc**, không phải tối ưu hoá. Hệ quả kèm theo: transfer giữa hai account là tx đụng **hai** owned object khác chủ ⇒ phải qua consensus path (~2s), không đi được fast-path 250ms. Đừng hứa 250ms cho confidential transfer.

---

### 08.8. Soroban (Stellar)

**Meta-tx**: `FeeBumpTransactionEnvelope` (CAP-0015) bọc tx đã ký của user, `feeSource` là relayer, **sequence number của inner tx không đổi và fee source không tiêu sequence của chính nó** — đây là điểm khác biệt quan trọng với mọi chain khác (rò rỉ #10): một tài khoản relayer duy nhất phục vụ được số giao dịch song song không giới hạn, trong khi trên EVM ta cần 7 EOA cho 100 tx in-flight. Bên trong, `require_auth` + `SorobanAuthorizationEntry` cho phép contract xác thực user và chuyển token thưởng cho `feeSource`.

**Sửa citation**: note ghi *"SEP-0043 (Soroban Invocation Authorizations)"*. Reference chuẩn tắc của authorization framework Soroban là **CAP-0046-11** cùng XDR `SorobanAuthorizationEntry` / `SorobanCredentials` / `SorobanAddressCredentials`; chuẩn SEP liên quan tới token trên Soroban là **SEP-0041 (Token Interface)**. Số hiệu SEP-0043 nhiều khả năng là nhầm — phải kiểm tra lại trước khi đưa vào bất kỳ tài liệu đối ngoại nào.

**State rent / TTL — ai trả `extend_ttl`, chốt luôn:**

| Câu hỏi | Chốt |
|---|---|
| Ai trả? | **Issuer**, qua keeper cron, không bao giờ là user |
| Vì sao không phải user? | Người dùng có số dư bị archive vì không đóng tiền thuê = một ticket hỗ trợ và một khiếu nại pháp lý. Đây là chain duy nhất mà "tiền biến mất khỏi tầm nhìn" là hành vi đúng của giao thức |
| TTL tối đa | ~3.110.400 ledger ≈ **180 ngày** ở 5s/ledger |
| Nhịp keeper | **Hàng tháng**, không phải hàng ngày: extend về trần mỗi 30 ngày cho biên an toàn 150 ngày. Cron 24h chỉ để *quét* entry sắp hết hạn |
| Cơ chế | `blockchain.chain.ttl_keeper_enabled`; cron gọi `model._cron_soroban_extend_ttl()` (một dòng trong XML, đúng bẫy §5.4 CLAUDE.md); batch ~100 entry/tx |
| Ngân sách | Một dòng chi phí cố định gắn vào `blockchain.token`. Ước tính: 10.000 account × 1 entry × 12 lần/năm ÷ 100 entry/tx = 1.200 tx/năm, phí Stellar ~$0,00002/op ⇒ **dưới $1/năm** phí mạng; chi phí thật là rent fee theo byte, cần đo trên testnet |
| Trường hợp đã archive rồi | `SorobanAdapterExt.plan_restore()` sinh `RestoreFootprint` preamble; job vào state `restoring`, **không** fail |

**Zether**: protocol 22 đã thêm host function BLS12-381 (bao gồm G1 MSM và pairing). Bulletproofs qua host function là khả thi về kỹ thuật; ràng buộc là **budget 100.000.000 CPU instruction/tx** và giới hạn read/write entry. Có host function MSM là lợi thế thật so với EVM (không phải 535 lần gọi riêng lẻ), nhưng vẫn phải viết lại verifier bằng Rust cho BLS12-381. Xếp wave 3, sau EVM và Sui.

---

### 08.9. CosmWasm

Ba cơ chế trong note thực ra là **bốn thứ khác nhau** và note gộp hơi vội:

| Cơ chế | Ai broadcast | Cần contract? | Đúng để làm gì |
|---|---|---|---|
| `x/feegrant` | **User** | Không | Trợ giá gas cho user đã có tài khoản on-chain. Granter chỉ là field `Fee.granter` |
| `x/authz` | **Relayer** (`MsgExec`) | Không | Relayer hành động *thay mặt* user với quyền đã cấp trước. Không phải meta-tx theo nghĩa "user ký, relayer nộp" — user **không** ký gì tại thời điểm thực thi, đây là uỷ quyền đứng, rủi ro khác hẳn |
| `ExecuteMsg::MetaExecute` | **Relayer** | Có | Tương đương thật của EIP-1776: contract verify chữ ký off-chain của user, trả CW20 cho `info.sender` |
| ICS-29 fee middleware | IBC relayer | Không | **Chỉ** cho relay packet IBC. Không liên quan tới sponsoring giao dịch của user — note để hai thứ này cạnh nhau dễ gây hiểu là thay thế được nhau |

**Zether trên CosmWasm — đề xuất đi ngược note, và một lối thoát thứ ba bản nháp bỏ sót.** Đừng viết verifier bằng CosmWasm: `wasmd` không có precompile bn254; verifier phải là Rust thuần (`ark-bn254`) compile sang WASM, và gas metering của CosmWasm đếm theo thao tác WASM ⇒ một Bulletproof verify rơi vào vùng vượt block gas limit của phần lớn chain Cosmos public (Neutron ~30M, Osmosis ~120M SDK gas/block). Ba con đường, xếp theo chi phí tăng dần:

1. **[MỚI] Dùng một chain Cosmos có sẵn EVM module** (Injective, Cronos, Evmos, hoặc bất kỳ chain nào chạy `x/evm` dựa trên go-ethereum). Các chain này **có sẵn precompile alt_bn128 `0x06`-`0x08`** vì chúng nhúng nguyên EVM của geth. Hệ quả: **contract Zether EVM chạy nguyên xi, không viết lại một dòng nào**, và ta vẫn ở trong hệ sinh thái Cosmos/IBC. Đây là lựa chọn rẻ nhất và bản nháp bỏ sót nó hoàn toàn.
2. **Appchain permissioned + module Go native** (`x/zether`, dùng `gnark`). Verify chạy ở tốc độ Go native, gas là tham số của chính mình, và có quyền định nghĩa `MsgTransferConfidential` như một message chuẩn. Chi phí: vận hành validator, upgrade coordination, IBC relayer.
3. Viết verifier bằng CosmWasm — **không khả thi kinh tế**, loại.

Nếu Cosmos vào scope Zether, chọn (1) trước, (2) chỉ khi cần chủ quyền tham số gas.

#### 08.9b. Bảng khả thi Zether tổng hợp

Đã cập nhật theo mô hình gas §08.4b (cấu hình tham chiếu: **3 mệnh đề × 64 bit ≈ 2,7M gas**, fee công khai).

| Hệ | Đường cong sẵn có | Port được `anonymous-zether`? | Chi phí/tx | Wave | Chặn chính |
|---|---|---|---|---|---|
| EVM (Besu private) | alt_bn128 precompile | **Có, gần như nguyên vẹn** | 0 (gas free) | **1** | Không. Trần: ~9 tx/s ở gas limit 50M |
| EVM (Gnosis public) | alt_bn128 precompile | Có | ~$0,005 | 2 | Chiếm 16% block gas limit mỗi tx ⇒ trần thực tế ~0,1 tx/s |
| Cosmos chain có `x/evm` | alt_bn128 qua geth EVM | **Có, không sửa** | tuỳ chain | 2 | Chọn chain; chưa khảo sát |
| Sui | Groth16 native + `group_ops` BLS12-381 | Không (viết lại Move, đổi hệ chứng minh) | < $0,01 | 2 | Cần trusted setup nếu chọn Groth16 |
| Soroban | BLS12-381 host fn (P22) | Không (viết lại Rust, đổi đường cong) | thấp | 3 | Budget 100M instruction; TTL; Ed25519 custody |
| Hedera HSCS | alt_bn128 (`0x06`-`0x08`) | Có về code | $0,14-0,46 | 3 | Throttle 15M gas/s toàn mạng ⇒ ~2 tx/s cho cả Hedera |
| Cosmos appchain (module Go) | gnark native | Không (viết module Go) | 0 (tự đặt) | 3 | Phải vận hành appchain |
| TON | BLS12-381 opcode (TVM) | Không (viết lại FunC + prover) | ? | 4 | Trần gas/tx 1M; sai đường cong; không có view cross-contract; Ed25519 |
| CosmWasm thuần | Không có precompile | **Không — loại** | — | — | Vượt block gas limit |

---

### 08.10. Trục thứ hai: chain profile

#### Stack private đề xuất: Hyperledger Besu + QBFT

| Ứng viên | Phán quyết |
|---|---|
| **Besu + QBFT** | **Chọn.** Apache-2.0, Linux Foundation, còn phát triển; QBFT là kế thừa IBFT2 và là mục tiêu của EEA client spec; có permissioning on-chain sẵn (node + account); cùng EVM với public ⇒ contract và adapter dùng chung |
| GoQuorum | Bỏ. Đã ở chế độ maintenance; Besu là đường nâng cấp mà chính ConsenSys chỉ sang |
| Polygon Edge / Supernets | **Bỏ dứt khoát.** Polygon đã ngừng sản phẩm này (2024). Chọn nó là chọn codebase không còn ai vá bảo mật |
| Substrate/Frontier, Avalanche Subnet | Bỏ ở wave 1: thêm một runtime lạ mà không giải quyết thêm bài toán nào |
| Hyperledger Fabric | Bỏ. Không phải EVM ⇒ mất toàn bộ contract Zether, mất adapter chung, mất đường di cư sang public. Chaincode Go không bù lại được |

**Cấu hình genesis cụ thể, và những con số hay bị bỏ sót:**

```jsonc
// chains/besu-dms/genesis.json  (repo hạ tầng, KHÔNG nằm trong addon)
"config": {
  "chainId": 1337001,                 // không trùng bất kỳ chainId công khai nào
  "qbft": { "blockperiodseconds": 2,
            "epochlength": 30000,
            "requesttimeoutseconds": 4,        // >= 2x blockperiod, nếu không round change liên tục
            "validatorcontractaddress": "0x…" },
  "zeroBaseFee": true,                // base fee = 0, EIP-1559 vẫn bật nhưng không thu
  "contractSizeLimit": 65536,         // EIP-170 mặc định 24576 -> verifier Bulletproof vượt
  "londonBlock": 0, "shanghaiTime": 0
},
"gasLimit": "0x2FAF080"               // 50.000.000
```

```bash
besu --min-gas-price=0 \             # node phải chấp nhận tx gasPrice=0
     --data-storage-format=BONSAI \  # dung lượng, xem bảng tăng trưởng dưới
     --tx-pool-price-bump=10 \
     --permissions-nodes-contract-enabled=true \
     --permissions-accounts-contract-enabled=true
```

**Bốn điều dễ sai nhất khi chuyển sang private chain:**

**(1) "Zero gas price không phải zero gas."** Gas vẫn được **đếm**, block gas limit vẫn ràng buộc, `out of gas` vẫn xảy ra. Với Zether ở 2,7-6,6M gas/tx, block gas limit mặc định của Besu chỉ cho vài giao dịch bảo mật mỗi block — nâng `gasLimit` lên 50M là bắt buộc. Ở 50M/2s = 25M gas/s ⇒ **~9 tx Zether/s** (2,7M) hoặc ~4 tx/s (6,6M). Đối chiếu nhu cầu: 5.000 outlet × 2 settlement/ngày = 10.000 tx/ngày ≈ 0,12 tx/s trung bình, đỉnh giờ cao điểm có thể 1-2 tx/s ⇒ **biên an toàn 4-9×**. Đủ, và con số này là lý do quyết định khoá #5 đúng.

**(2) Gas price = 0 đã xoá mất lá chắn DoS duy nhất.** Trên chain công khai, chi phí gas là thứ ngăn spam. Bỏ nó đi thì phải thay bằng ba lớp, thiếu một là một client lỗi vòng lặp lấp đầy chain:

1. Besu **account permissioning** on-chain (`AccountRules` contract) — chỉ địa chỉ đã cấp phép mới gửi được tx.
2. Node permissioning (`NodeRules`) — chỉ node đã cấp phép mới peer được.
3. Rate limit per-account ở RPC gateway (không phải ở node — node không biết tenant).

**(3) Không còn cơ chế ưu tiên** (rò rỉ #14). Với `gasPrice = 0`, tx pool sắp theo thứ tự đến và nonce; một settlement khẩn không thể trả thêm để vượt lên trên 5.000 job batch. Giải bằng ứng dụng: tách EOA relayer theo lớp ưu tiên (`urgent` / `normal` / `batch`), giới hạn số job `batch` in-flight, và một admission controller ở gateway. Đây là công việc thật, không phải một dòng config.

**(4) Đồng hồ.** QBFT với `blockperiodseconds: 2` rất nhạy với lệch giờ giữa validator: lệch quá block period sinh round change liên tục và throughput sụp. NTP đồng bộ (chronyd, cùng nguồn) là yêu cầu vận hành, không phải khuyến nghị.

**Validator set governance.** Hai lựa chọn của QBFT: (a) bỏ phiếu qua block header, (b) `ValidatorSmartContract` on-chain. Chọn **(b)**, vì (a) không để lại dấu vết mà kiểm toán viên đọc được. Ánh xạ sang Odoo: model `blockchain.validator.change` (`proposal` → `approved` → `applied` → `rejected`), owner của contract là multisig n-of-m, mỗi lần đổi validator sinh một record có `mail.thread` và attachment biên bản trên Garage. Không dùng `date` làm tên field — dùng `proposal_date`, `applied_date`.

**Quorum, chịu lỗi, và kịch bản chain đứng im:**

| Số validator | Quorum (⌈2n/3⌉) | Chịu được f = ⌊(n-1)/3⌋ | Ghi chú |
|---|---|---|---|
| 4 | 3 | 1 | Tối thiểu có ý nghĩa |
| 5 | 4 | 1 | Không lợi hơn 4 về chịu lỗi |
| 7 | 5 | 2 | **Khuyến nghị** cho production |
| 10 | 7 | 3 | Chi phí phối hợp bắt đầu vượt lợi ích |

**Đây là điều bản nháp không nói và nó là rủi ro vận hành lớn nhất của private chain:** BFT **không fork, nó dừng**. Mất quorum (2/4 validator chết) ⇒ chain **ngừng sản xuất block hoàn toàn**. Không có degraded mode, không có "chậm hơn" — rail thanh toán đứng im. So sánh: một public chain hầu như không bao giờ ở trạng thái này. Bắt buộc phải có:

- RTO công bố (đề xuất: **15 phút**) và runbook khôi phục: khởi động validator dự phòng đã đồng bộ sẵn (hot standby, cùng data dir snapshot ≤ 5 phút tuổi), **không** phải "dựng node mới rồi sync".
- Validator đặt ở **≥ 3 vùng lỗi độc lập** (khác AZ, khác nhà cung cấp điện/mạng). 4 validator trên cùng một hypervisor là 1 validator đội lốt 4.
- Diễn tập tắt 1 validator hàng quý, và tắt 2 (mất quorum) hàng năm trên môi trường staging.
- Fallback nghiệp vụ: khi chain đứng, `blockchain.relay.job` đọng ở `queued` và Odoo **không** được tự chuyển sang đường thanh toán khác — nguyên tắc `dms_vietqr` lần nữa: không có xác nhận thì không có thu tiền.

**Finality.** QBFT là BFT: block đã ký bởi quorum validator là **final ngay**, không reorg. Đặt `finality_mode='bft_instant'`, `finality_depth=1`. Nhưng **Finality Gate không biến mất**: nó vẫn phải (i) chờ block, (ii) xác nhận block có đủ chữ ký quorum trong `extraData` — không chỉ tin `eth_getTransactionReceipt`, (iii) từ chối nếu validator set trong block không khớp bản ghi `blockchain.validator.change` đang `applied`, và (iv) đọc từ **node của chính mình**, không từ một RPC vendor (`finality_quorum` trên private = 1 nhưng endpoint phải có `is_independent = True` và thuộc sở hữu của ta). Nếu bỏ (ii) và (iii), một validator set bị đổi sai vẫn khiến gateway báo `done` cho các block không hợp lệ. `_set_done` vẫn chỉ nổ sau gate — nguyên tắc `dms_vietqr` không được nới lỏng vì chain là của mình.

**Tăng trưởng dữ liệu (ước tính, cần đo):**

| Khoản | Kích thước | 10.000 tx Zether/ngày |
|---|---|---|
| Calldata mỗi confidential tx | proof ~1,4 KB + ciphertext ~0,5 KB + overhead ⇒ **~2,5 KB** | 25 MB/ngày |
| Receipt + log + trie | ~2-3× calldata | 50-75 MB/ngày |
| **Tổng full node (Bonsai)** | | **~100 MB/ngày ≈ 36 GB/năm** |
| Archive node | 3-5× | 110-180 GB/năm |

Hệ quả cấu hình: chạy **Bonsai** cho validator (state không lịch sử), giữ **một** archive node riêng cho kiểm toán và indexer, không bắt cả 7 validator gánh archive. Đây là quyết định phải ra ngay ngày đầu — đổi storage format sau đó là resync từ genesis.

**Thâm hụt niềm tin của private chain — nói thẳng với auditor.** Trên private chain, "stablecoin" không phải tài sản vô danh: nó là **một khoản phải trả của bên vận hành**. Tính bất biến của sổ cái là một cam kết tổ chức của người kiểm soát ≥ quorum validator, không phải một tính chất kinh tế như trên chain công khai. Hai hệ quả bắt buộc, không phải tuỳ chọn:

1. Ghi rõ điều này trong tài liệu kiểm toán và trong điều khoản với đối tác B2B. Đừng để auditor tự suy ra rồi kết luận nặng hơn sự thật.
2. **Neo Merkle root ra ngoài** (§08.5, HCS $0,88/năm, hoặc một contract trên Gnosis). Anchor bên ngoài biến "chúng tôi hứa không sửa sổ" thành "sửa sổ sẽ lộ ra ở một hệ thống chúng tôi không kiểm soát". Đây là món rẻ nhất mua được nhiều niềm tin nhất trong toàn bộ thiết kế.

#### Open relayer market trên private chain có ý nghĩa gì không?

**Không.** Và câu trả lời này nên được nói thẳng vì nó tiết kiệm cả một hệ thống con:

| Cấu phần của §05 | Trên private | Lý do |
|---|---|---|
| Auction / lottery / stake / PoW chống sybil | **Xoá** | Relayer không ứng vốn gì cả (gas = 0) ⇒ không có dịch vụ để định giá ⇒ không có thị trường |
| Intent gossip federation | **Xoá** | Một hub nội bộ; mọi bên tham gia đều đã qua permissioning |
| `PRIVATE_SUBMISSION` / chống front-run | **Xoá** | Không có mempool công khai; chỉ node được permission mới thấy tx |
| `fee` trong `MetaTransaction` | Đặt `0` | Nhưng **giữ trường** — xem dưới |
| `mode` | Mặc định `MODE_RESTRICT_RELAYER (0x01)` | Chỉ pool nội bộ nộp |
| Envelope EIP-1776 | **Giữ nguyên** | Ba lý do dưới |
| Forwarder thu fee khi inner revert (§08.4c) | **Giữ** | Trên private nó không bảo vệ tiền của relayer, nhưng nó giữ **hai trạng thái** `chain_state`/`business_state` giống hệt public ⇒ cùng một code đường nghiệp vụ |

Giữ envelope dù không có thị trường, vì nó vẫn mua được ba thứ có giá trị trên private chain:

1. **Tách người giữ khoá khỏi người trả phí.** User/Agent ký nghiệp vụ; chỉ pool nội bộ có tài khoản được permission gửi tx. Đây là một ranh giới bảo mật thật, không phải vấn đề tiền.
2. **2D nonce (`batchId`/`batchNonce`).** Xoá head-of-line blocking khi hàng nghìn intent chạy song song — vấn đề này không liên quan gì tới gas, nó tồn tại y hệt trên chain free. (Lưu ý phân biệt: 2D nonce giải head-of-line cho **user**; nonce của **EOA relayer** vẫn tuần tự và vẫn cần nhiều EOA — §08.3b.)
3. **Đường di cư sang public.** Cùng một struct, cùng một `MetaTxForwarder`, cùng một client SDK. Khi bật `chain_profile='public'`, chỉ đổi `mode` sang `MODE_OPEN`, đặt `fee > 0`, bật intent bus. Chữ ký ký cho private chain **không** hợp lệ trên public (domain separator có `chainId`) — đó là hành vi đúng và cố ý, không phải hạn chế.

Kết luận vận hành: `chain_profile` không chỉ là một cột metadata; nó là **feature flag bật/tắt khoảng 60% khối lượng code của §05**. Xây private trước không phải là bước đệm bị hoãn — nó là bước bỏ qua được cả một hệ con cho tới khi có nhu cầu thật.

#### 08.10b. Conformance suite: cách duy nhất để "trừu tượng hoá" là thật

Một `Protocol` không được thi hành bởi test chỉ là một comment dài. Mỗi adapter phải chạy qua cùng một bộ case, trên devnet cục bộ.

| # | Case | Kỳ vọng |
|---|---|---|
| 1 | `normalize_address` với 6 dạng sai (thiếu prefix, sai checksum, sai độ dài, HRP sai, khoảng trắng, unicode nhìn giống) | Reject cả 6, không "sửa hộ" |
| 2 | `preflight` trên chain đúng | Trả genesis/chainId khớp |
| 3 | `preflight` trên chain **sai** (trỏ RPC sang chain khác) | Raise `ChainMismatch` |
| 4 | Happy path: build → simulate → estimate → submit → receipt → finality=FINAL | < 2× `hard_final_seconds` |
| 5 | Simulate một call chắc chắn revert | `SimResult.ok = False`, có `revert_reason`, **không** submit |
| 6 | Submit hai lần cùng `intent_id` | Chỉ một tx lên chain |
| 7 | Deadline đã qua | `Expired`, không submit |
| 8 | Order token hết lease | `NonceConflict`, retry với lease mới thành công |
| 9 | Kill RPC chính giữa chừng | Failover sang endpoint #2, job vẫn tới `final` |
| 10 | Chain rollback (anvil `evm_revert` / restart devnet) | `FinalityVerdict.level = REORGED`, không bao giờ `_set_done` |
| 11 | Native balance = 0 | `InsufficientGasFunds`, có cảnh báo, **không** retry vô hạn |
| 12 | `decode_event` trên log của contract khác | Trả `None`, không raise |
| 13 | Meta-tx có inner call revert | `chain_state=success`, `business_state=failed`, fee đã thu (§08.4c) |
| 14 | Đặc thù họ chain | Sui: hai sponsor cùng gas coin ⇒ `Equivocation`. TON: cây message có một hop bounce ⇒ `is_terminal=True`, `hops[i].bounced=True`. Soroban: entry archived ⇒ job vào `restoring`. Hedera: retry cùng `validStart` ⇒ `Expired` |

Devnet cục bộ và chi phí CI:

| Hệ | Devnet | Chạy ở đâu |
|---|---|---|
| EVM | `anvil` (vài giây khởi động) | Mỗi PR |
| EVM private | `besu --network=dev` hoặc compose 4 validator QBFT | Mỗi PR (4 validator: nightly) |
| Sui | `sui start --with-faucet` | Mỗi PR |
| Soroban | `stellar container start local` | Mỗi PR |
| CosmWasm | `wasmd` single node | Mỗi PR |
| Hedera | Hedera Local Node (docker, cần ~16 GB RAM) | **Nightly** |
| TON | MyLocalTon (nặng, hay flaky) | **Nightly**, được phép fail mà không chặn merge |

Bảy hệ chia hai lớp CI vì lý do lười có tính toán: bốn devnet nhẹ chạy mỗi PR bắt được 90% lỗi; hai devnet nặng chạy nightly bắt phần còn lại mà không làm PR chờ 20 phút.

---

### 08.11. Câu hỏi còn treo cho người quyết

1. **Đơn vị Zether token: 6 decimals + range proof 64-bit (rẻ hơn 47-59% gas) hay giữ 18 decimals + 128-bit như `blockchain.md` đang viết?** Đây là quyết định thay đổi bảng khả thi của Hedera và Gnosis, phải chốt trước khi khoá chain order.
2. **Fee trong Zether là công khai (`uint256`) hay bí mật (`C_fee`)?** Note đang có cả hai và không có mệnh đề buộc chúng khớp. Triết lý "Public Relayer Fee" nói là công khai; nếu vậy bỏ `C_fee` và bớt được một range proof.
3. **Custody có ký được Ed25519 thuần không?** Nếu không: chấp nhận ECDSA trên Hedera, secp256r1 trên Sui, và hoãn TON/Soroban — hay đổi từ HSM sang MPC provider?
4. **Sui: Groth16 (cần trusted setup ceremony) hay Bulletproofs viết tay (đắt gas, không cần setup)?** Quyết định chính trị lẫn kỹ thuật.
5. **Sui: có chấp nhận rằng thiết kế Zether trên Sui sẽ khác thiết kế trên EVM** (bỏ epoch/`rollOver`), tức là hai bộ audit, hai bộ tài liệu?
6. **Cosmos: chọn một chain có sẵn `x/evm` (chạy contract EVM nguyên xi) hay vận hành appchain riêng với module Go?** Lựa chọn đầu rẻ hơn một bậc và bản nháp trước đã bỏ sót nó.
7. **Celo sau khi thành L2**: còn giữ Celo ở vị trí thứ hai trong chain order không, khi lợi thế "immediate finality" đã mất và chỉ còn lợi thế `feeCurrency`? Nếu bỏ, ứng viên thay thế là Polygon PoS (milestone ~1-2 phút) hay Base?
8. **Validator set của Besu private: ai là validator, và ở mấy vùng lỗi?** Nếu cả 4 đều do một pháp nhân vận hành trên cùng một hạ tầng thì tính bất biến là cam kết nội bộ, không phải tính chất kỹ thuật — và điều đó phải nói rõ với auditor. Chốt luôn RTO khi mất quorum.
9. **Ngưỡng `_set_done` trên L2**: chấp nhận soft finality (1 giây, rủi ro sequencer) hay bắt buộc hard (15-25 phút)? Câu trả lời khác nhau theo money flow: loyalty point có thể soft, B2B settlement thì không. Cần một ma trận `money_flow × finality_level`, không một ngưỡng chung.
10. **Ai vận hành relay-pool?** Nó nằm ngoài addon, ngoài Odoo, và là thành phần duy nhất giữ khoá ký. Team nào on-call, và deploy nó ở đâu so với Odoo?

---

### 08.12. Những chỗ mâu thuẫn cần đồng bộ giữa các section

1. **Tên model chain**: §01 dùng `blockchain.chain.profile`, §05 dùng `dms.blockchain.chain`, §06 dùng `blockchain.chain`. Chốt: **`blockchain.chain`** với `chain_profile` là `Selection` trên chính nó. §01 sửa `chain_profile_id` → `chain_id = fields.Many2one('blockchain.chain')`. Prefix `blockchain.` (không phải `dms.`) là bắt buộc theo quyết định khoá #7 — addon standalone, không phụ thuộc `dms`.
2. **Finality của Gnosis**: `blockchain.md` §10.4 ghi 12,8 phút. Sai — đó là số của Ethereum. Gnosis ≈ 3-4 phút (16 slot/epoch × 5s). Xem §08.4.
3. **Finality của Polygon PoS**: `blockchain.md` ghi 25-30 phút; đã lỗi thời từ khi có Heimdall milestone (~1-2 phút). Xem §08.4.
4. **Celo finality**: `blockchain.md` ghi IBFT 2.0 immediate finality; Celo đã lên L2 OP Stack. Phải là `l1_batch`. Xem §08.4.
5. **SEP-0043**: trong §10.2.5 nhiều khả năng là citation sai cho Soroban authorization framework (đúng là CAP-0046-11; SEP-0041 là token interface). Xem §08.8.
6. **ICS-29** bị đặt cạnh `x/feegrant` như thể cùng loại; chúng phục vụ hai bài toán khác nhau. Xem §08.9.
7. **"Tỷ lệ revert 0%"** trong §10.1 và §14.2.8 là mục tiêu không đạt được. Phải đổi thành ngân sách revert có số. Xem §08.4c.
8. **Zether range proof 128-bit** trong §10.5.3: đúng về việc `2^32` là vô dụng, sai về đòn bẩy. Xem §08.4b.
9. **`EncryptedTransfer` có cả `fee` công khai lẫn `C_fee`** mà không có mệnh đề ràng buộc: dư thừa hoặc lỗ hổng. Gửi §03 quyết. Xem §08.4b.
10. **§04 `MetaTxForwarder`** phải tách validation khỏi execution và thu fee kể cả khi inner call revert; kèm theo `blockchain.relay.job` cần hai field trạng thái. Xem §08.4c.
