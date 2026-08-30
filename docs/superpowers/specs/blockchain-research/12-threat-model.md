## 12. Mo hinh de doa va bao mat

### 12.0. Bien tin cay, doi thu, va nguyen tac chu dao

Nguyen tac VietQR ap dung o day o dang manh nhat: **broadcast khong phai la thanh toan, va `receipt.status == 1` cung khong phai**. Mot tx thanh cong tren chuoi voi `innerSuccess = false` van la tx thanh cong. Vi vay moi bien phap trong section nay deu quy ve mot cau hoi duy nhat: *dieu gi co the lam cho `blockchain.metatx.state` chuyen sang `done` trong khi tien khong thuc su di chuyen, hoac lam cho tien di chuyen ma khong co ban ghi nao trong Odoo?*

#### 12.0.1. Muoi gia dinh an cua ban nhap truoc — noi ra de con kiem chung duoc

Ban nhap truoc dung ca muoi gia dinh nay ma khong phat bieu cai nao. Mot mo hinh de doa khong liet ke gia dinh cua no thi khong kiem chung duoc, va moi gia dinh sai o day deu la mot lo hong khong ai tim.

| # | Gia dinh an | Co dung khong | Hau qua neu sai | Xu ly |
|---|---|---|---|---|
| G1 | Chi co mot tenant / mot phap nhan | **Sai** — §10.9 la multi-company | Operator cong ty A ky duoc bang khoa cong ty B | Them A9; §07.11 `resolve(tenant_uuid, signer_ref)` la bien that |
| G2 | `dms_blockchain` la mot process | **Sai** — co it nhat 4 process: Odoo, `relay-pool`, `confidential-signer`, indexer | Moi ranh gioi process la mot ranh gioi tin cay khong duoc mo ta | Bang 12.0.2 |
| G3 | Indexer chi doc | **Sai** — indexer la thu **ghi** `finalized`/`done` | Chiem indexer = tao tien trong so ke toan ma khong cham chuoi | Them A11 |
| G4 | `chain_profile = private` giam rui ro | **Chi doi rui ro** | Validator set la chinh ta ⇒ rewind duoc, precompile la code Go chua audit | 12.1.1, A12 |
| G5 | Prover client la tin cay va RNG cua no tot | **Chua kiem chung** | Lap `s` hoac `k` mot lan = **lo `x`** = mat sach tai khoan | 12.3.1 — day la lo hong nghiem trong nhat ma ban nhap bo sot hoan toan |
| G6 | `base.group_system` yeu hon RCE | **Sai tren Odoo** | `ir.actions.server` `state='code'` chay Python tuy y trong process Odoo ⇒ **A4 = A5** | 12.6.1 |
| G7 | Dong ho Odoo va dong ho chuoi khop nhau | Khong bao dam | `expiry` tinh sai ⇒ intent chet luc sinh, hoac song qua lau | 12.7.4 |
| G8 | Audit tim ra loi ⇒ deploy an toan | Khong suy ra duoc | Bytecode deploy khac bytecode audit | 12.7.3, va `to_impl_codehash` cua §1.11.1 |
| G9 | Supply chain chi la toolchain contract | **Thieu mot nua** | Client SDK (npm/pypi) cam `x` — backdoor o do lay khoa truc tiep | Them A13 |
| G10 | Bulletproofs an toan vi da co bai bao | Bai bao an toan, **trien khai thi khong** | Fiat-Shamir yeu = proof gia | 12.3.2 |

#### 12.0.2. Ranh gioi tin cay theo process (thieu hoan toan o ban nhap)

Mo hinh de doa phai ve theo **process**, khong theo module, vi mot lo hong chi vuot duoc ranh gioi process qua mot giao dien co the liet ke duoc.

```
[ Browser / Mobile ]                     tin cay: 0
        | JWT bamboo_token_auth, call_kw + /json/2
        v
[ Odoo worker ]         <-- A4/A6 song o day. KHONG bao gio giu private key.
        | outbox table (Postgres), KHONG phai HTTP  (§08.2b)
        v
[ relay-pool worker ]   <-- A10. Giu nonce lease (Redis), goi signer, broadcast.
        | mTLS + tenant_uuid trong client cert
        v
[ confidential-signer ] <-- A5 muon toi day. Enforce policy TRUOC khi ky.
        | PKCS#11 / KMS Recipient=attestation
        v
[ HSM / Nitro Enclave ] <-- bien khoa. A5 khong lay duoc khoa, nhung CO THE lam dung.
        
[ indexer ]  --(ghi finalized)-->  [ Postgres ]   <-- A11. Duong ghi `done` duy nhat.
        ^ 3 RPC provider doc lap (§06.7)          <-- A7
```

Bon bat bien ve ranh gioi, moi cai la mot dong test:

1. **Odoo khong bao gio giu vat lieu khoa.** Grep gate trong CI: khong file nao trong `dms_blockchain/` chua `eth_keys`, `eth_account`, `coincurve`, `PKCS11`, `boto3.client('kms')`.
2. **Odoo khong goi truc tiep signer.** Chi `relay-pool` co credential mTLS. Odoo ghi outbox.
3. **`confidential-signer` khong tin `tenant_uuid` do body gui len**, chi tin cai trong client cert (§07.11).
4. **Indexer khong co quyen ghi bang nghiep vu nao ngoai `blockchain.chain.event`, `blockchain.chain.effect`, `blockchain.transaction`.** DB role rieng, `GRANT` hep. Neu indexer bi chiem ma van ghi duoc `account.move` thi ranh gioi la gia.

#### 12.0.3. Bang doi thu (mo rong tu 8 len 13)

| # | Doi thu | Nang luc gia dinh | Khong co | Bien phap chinh |
|---|---|---|---|---|
| A1 | Nguoi ngoai tren public chain | Doc toan bo state + mempool, submit tx bat ky, tra gas khong gioi han hop ly | Khoa cua ai | Contract |
| A2 | Open relayer ac y | Nhu A1 + nhan intent truoc khi len chain, tri hoan / bo qua / dao thu tu | Sua duoc digest | 12.2, 12.4 |
| A3 | Hub operator | Nhu A2 + thay toan bo intent flow, chon nguoi thang exclusivity | Khoa cua user | 12.4, duong thoat Enterprise Pool |
| A4 | Nhan vien noi bo co `base.group_system` | **Bang A5** — xem 12.6.1 | Khoa trong HSM/enclave | 12.6 |
| A5 | Ke chiem duoc app server Odoo | Goi tuy y vao signer API bang credential cua service | Khoa raw | Policy phia signer (12.5) |
| A6 | Ke chiem duoc admin key cua contract | Upgrade, pause, doi tham so | Khoa cua user | Timelock 48h, guardian chi pause |
| A7 | Ke chiem duoc RPC provider (hoac chinh provider noi doi) | Tra state gia, nuot tx, gia lap receipt | Ghi len chain | 4 lop cua §06.7 |
| A8 | Supply chain toolchain contract (solc, foundry, npm, cargo) | Chen bytecode khac voi source | — | 12.7.3 |
| **A9** | **Insider cua tenant khac** (Odoo multi-company) | Doc/ghi record cua minh, goi moi RPC method public | `signer_ref` cua tenant khac | Rule `company_id` + `resolve()` phia signer |
| **A10** | **Ke chiem `relay-pool` worker** | Nonce lease, chon tx nao broadcast, doc calldata truoc khi len chain | Khoa; policy cua signer | Signer policy la lop cuoi, khong phai relay-pool |
| **A11** | **Ke chiem indexer (hoac chi ghi duoc bang cua no)** | Dat `finalized` cho mot tx khong ton tai ⇒ Odoo `_set_done` ⇒ giao hang | Ghi len chain | DB role hep + xac nhan 2 provider + hash check |
| **A12** | **Validator set cua private chain** (chinh ta, hoac mot nha thau) | Rewind, kiem duyet, doi genesis, doi precompile | Khoa cua user | Anchor head hash sang HCS (§11.3), 4-eyes tren binary |
| **A13** | **Supply chain client SDK** (npm `@bamboo/zether-sdk`, pypi) | Doc `x` trong RAM cua client, doi `recipient` truoc khi ky | — | 12.3.6 |

#### 12.0.4. Tai san, xep theo thiet hai giam dan, kem gia tri quy uoc

| Hang | Tai san | Thiet hai neu mat | Gia tri quy uoc (gia dinh pilot) |
|---|---|---|---|
| 1 | `encKey x` cua Zether + vault ERC-20 phia sau Z-token | Rut sach vault; lo toan bo lich su so tien | = TVL. Pilot B2B gia dinh **$2M** |
| 2 | Admin/upgrade key (`DEFAULT_ADMIN_ROLE`, beacon owner) | Mint vo han, backdoor | = TVL + gia tri thuong hieu |
| 3 | Khoa auditor `x_audit` | Giai ma **toan bo lich su** moi tai khoan, khong hoi to duoc | Bi mat gia ca cua ca mang luoi phan phoi |
| 4 | Treasury EOA | Mat so du treasury | Theo so du, thuong < $200k |
| 5 | Toan ven cua `blockchain.metatx.state = done` | Giao hang ma khong nhan tien | = gia tri hang chua thu tien trong 1 chu ky doi soat |
| 6 | Tinh bi mat cua so tien | Doi thu biet bang gia | Khong dinh gia duoc; la ly do ton tai cua Zether |
| 7 | Hot wallet gas | Mat runway 4h gas | < $2,000 |

#### 12.0.5. So rui ro uu tien (doc bang nay truoc, phan con lai la chi tiet)

Xep theo `likelihood × impact`, va cot cuoi la thu quyet dinh ngan sach.

| Hang | Rui ro | Kha nang | Thiet hai | Bien phap co ty le loi ich/chi phi cao nhat |
|---|---|---|---|---|
| 1 | Fiat-Shamir yeu trong Bulletproof verifier tu viet | **Cao** (lop bug pho bien nhat cua BP trien khai tay) | Mint vo han = 100% TVL | Audit mat ma Phase B + bo negative test tung public input (12.3.2) |
| 2 | **Lap nonce/randomness trong prover ⇒ lo `x`** | Trung binh | 100% so du cua tai khoan do | Nonce tat dinh RFC-6979-style + test known-answer (12.3.1) |
| 3 | `withdraw` proof khong bind `chainId`/`address(this)` | **Da xac nhan trong note** | Replay cross-chain, mat tien that | Sua challenge (12.3.3) |
| 4 | A4/A5 lam dung HSM (khong trich xuat khoa) | Trung binh | Treasury + upgrade | `SigningPolicyService` cung phia signer (12.5.1) |
| 5 | RPC noi doi / indexer bi chiem ⇒ `_set_done` sai | Trung binh | Hang giao khong thu tien | 2 provider + hash + canary (12.7.1) |
| 6 | Rut sach cham qua mot bug chua biet | Trung binh | Toan bo TVL | **`WithdrawLimiter` on-chain** (12.11) — bien "mat tat ca" thanh "mat 0.5%" |
| 7 | Upgrade key compromise | Thap | 100% TVL | Timelock 48h + monitor `Upgraded` realtime |
| 8 | Toolchain/bytecode drift | Thap | 100% TVL | `EXTCODEHASH` doi chieu truoc execute (12.7.3) |
| 9 | Precompile Go tu viet tren private chain sai | Trung binh | Chain halt hoac accept proof gia | Audit rieng cho Go, differential test (12.1.1) |
| 10 | Ro ri do thi brand-distributor tren public chain | **Chac chan** (la thiet ke) | Tinh bao canh tranh | Quyet dinh kinh doanh: ep B2B ve private (12.12) |

---

### 12.1. Smart contract

| Vector | Kich ban cu the tren thiet ke nay | Bien phap chot |
|---|---|---|
| Reentrancy | `withdraw()` chuyen ERC-20 cho `recipient`; token co hook (ERC-777, hoac underlying la contract) goi nguoc vao `transferConfidential` khi `zetherNonce` chua tang | CEI nghiem: `zetherNonce++` va tru `(C,D)` **truoc** `safeTransfer`; `ReentrancyGuardTransient` tren moi ham doi state tai chinh; `MetaTxForwarder` tang `batchNonce` truoc inner call (§04.5, buoc 5 truoc 6) |
| Reentrancy **cross-function** | `withdraw` va `migrateAccount` dung chung `(C,D)` nhung khac guard | Mot guard duy nhat theo **contract**, khong theo ham; test `ReentrancyCross.t.sol` goi cheo tung cap ham doi state |
| Upgrade key compromise (A6) | Doi implementation cua `ZTokenBase` sang ban co backdoor `mint()` | Upgrade **chi** qua `TimelockController` 48h (§1.11 la nguon su that); beacon owner = timelock va dung `Ownable2Step` (§1.11.1 muc 1); `GUARDIAN` chi duoc `pause()`, khong bao gio `upgrade()`; **`ZetherAccountRegistry` khong upgradeable** (§02.3) |
| Registry key swap | Neu registry la UUPS, admin doi `getPublicKey(addr)` sang khoa cua minh; moi khoan chuyen den sau do bi ma hoa duoi khoa attacker, nan nhan khong doc duoc va khong biet | Da chan boi quyet dinh registry immutable + `successorAddr` set mot lan qua `selfMigrate`. Day la ly do ky thuat quan trong nhat de **khong** ap UUPS len moi contract nhu note yeu cau |
| Storage collision tren proxy | Them field vao giua struct cua v2; beacon nang cap ca ho proxy cung luc | ERC-7201 namespaced storage cho moi module; CI gate `validateUpgrade` (§14.9) doi chieu `smartcontracts/evm/storage-layouts/v<N-1>/*.json`, fail build; cam `__gap` thu cong |
| Initialisation front-running | Factory `create2` roi goi `initialize()` o tx thu hai; A1 xen vao giua, chiem owner | Deploy + init **nguyen tu trong mot call** cua `DeterministicFactory`; `_disableInitializers()` trong constructor cua implementation; salt = `keccak256(msg.sender, userSalt)` de khong ai squat duoc dia chi da predict (§1.4.3) |
| Unchecked delegatecall | Note (§TOKEN) yeu cau "dung co che delegate de dung chung code". Mot `delegatecall(target, data)` voi `target` do caller cung cap = xoa slot 0, doi owner | `delegatecall` **chi** toi dia chi lay tu `ContractPrototypeRegistry` co `approved = true`; khong `delegatecall` trong vong lap; CI grep chan `delegatecall` ngoai 2 file duoc allowlist |
| `selfdestruct` lam brick proxy | **Sua so voi ban nhap**: sau EIP-6780 (Cancun), `SELFDESTRUCT` chi xoa code khi nam trong **cung tx voi lan tao**. Gnosis da kich hoat Dencun (2024), Celo la OP-stack post-Cancun ⇒ vector "brick implementation bang selfdestruct" **da chet tren ca hai chain muc tieu** | Van cam `selfdestruct` trong implementation (chi phi bang 0), nhung dung dua no vao ho so rui ro nhu mot moi de doa song. Rui ro that con lai cua delegatecall la **ghi de storage + doi owner** |
| ERC-20 approve race (nghia goc) | Nan nhan `approve(spender, 100)` roi doi y `approve(spender, 50)`; spender front-run tx thu hai, tieu 100, roi tieu tiep 50 = **150** | Khong bao gio dung `approve` de dat lai gia tri khac 0. Chi `approve(0)` roi `approve(n)`, hoac dung `permit` (EIP-2612) co `deadline` va `nonce` |
| Approve race (dang nguy hiem hon o thiet ke nay) | Hinh thai `MetaTxForwarder` generic can `approve`. `approve(forwarder, type(uint256).max)` + forwarder bi upgrade = rut sach moi nguoi | Uu tien `ERC1776Native` mixin (khong can approve, §04.6.4). Neu buoc dung forwarder: EIP-2612 `permit` dung so, co `deadline`; tran approve = `fee_ceiling × 30 ngay`; **forwarder khong upgradeable**; `require(m.to != address(this))` va `!targets[to].isFeeToken` (§04.9) |
| `transferFrom` khong tra `bool` | USDT tren nhieu chain khong tra gia tri; `require(token.transferFrom(...))` revert nham hoac bo qua that bai | `SafeERC20` o **moi** cho, khong ngoai le. CI grep chan `.transfer(` / `.transferFrom(` tho tren kieu `IERC20` |
| `ecrecover` tra `address(0)` | Chu ky rac ⇒ `ecrecover` tra 0; neu `from` chua khoi tao cung la 0 thi so sanh bang cho **pass** | `ECDSA.tryRecover` cua OZ (da reject `v` sai va `s` cao) + `require(signer != address(0) && signer == m.from)` |
| Fee-on-transfer | `WrappedToken.deposit(amount)` mint `amount` nhung vault chi nhan `amount - fee`. FoT 1% tren vault $1M = lo hong $10,000 va no lon dan | Do delta thuc: `received = after - before`, mint theo `received`; allowlist underlying kem test `assertEq(received, amount)` khi onboarding |
| Rebasing token | `balanceOf(vault)` cua stETH/aToken tu tang giam ⇒ invariant `totalSupply == balanceOf(vault)` sai moi ngay, khong con phan biet duoc bug voi rebase | **Cam tuyet doi** rebasing token cho archetype `WRAP_1_1`. Muon ho tro thi wrap ban share-based (wstETH) chu khong wrap ban rebasing |
| `decimals` khac nhau | Underlying 6 decimals (USDC) vs Z-token 18; `peg_ratio` nhan sai luy thua ⇒ sai 10^12 lan | `decimals` doc mot lan tu underlying luc `initialize` va **luu immutable**; khong doc lai runtime (mot token co the noi doi hoac doi qua upgrade) |
| Precision / rounding drain | `peg_ratio` 1 DAI → 25,000 Z-VND, Zether dung don vi cent (§03.2). Lap deposit/withdraw dust de moi vong an 1 cent | Lam tron **luon co loi cho pool**: mint floor, burn ceil; `require(erc20Amount % 10**(decimals-2) == 0)` (§03.2); `MIN_WRAP = 100 cent`; invariant test `SupplyInvariant.t.sol` 50,000 run kiem `vaultBalance >= totalSupply` sau moi chuoi thao tac ngau nhien |
| Share-inflation / first-depositor | **Khong ap dung** — vault la 1:1, khong phat hanh share, khong co `totalAssets/totalSupply`. Ghi ra day de reviewer khong phai hoi | Neu bao gio doi sang mo hinh share (yield-bearing reserve) thi vector nay quay lai va phai them dead-share |
| Gas-limit DoS cua verifier | Neu giu Bulletproofs 128/128, verify **~3.87M gas** (§03.3.6) = **22.8% block limit Gnosis (17M)**. Doi thu spam vai tx/block lam nghen chuoi | Da chot: `n_v = 32`, `n_b = 64` ⇒ **~1.88M gas** contract-level, **1.72–2.62M** ca envelope (§04.10). Public profile di Groth16/Baby Jubjub **~215k gas** (181k pairing + ~30k), **khong phai 250–350k** — sua so voi ban nhap |
| Verifier tieu gas roi moi revert | Attacker gui proof rac; contract chay 1.5M gas MSM roi revert ⇒ relayer mat tien | **Thu tu fail-fast bat buoc**: (1) `status(from)==ACTIVE && status(to)!=NONE` (2 SLOAD ≈ 4.2k), (2) `zetherNonce` (2.1k), (3) on-curve + subgroup + reject identity (~1.5k), (4) `expiry`, (5) **roi moi** MSM. Ty le: reject som **~1,000× re hon** reject muon. Ghi thanh test `VerifierFailFast.t.sol` do gas cua tung nhanh revert |
| Event thieu ⇒ indexer phai doc state | Reorg lam state-read sai, event thi khong | Moi thay doi tai chinh **phai** phat event mang du du lieu de dung lai state, gom `bytes32 ref` (§11.5 tang 1). Test: chay indexer chi tu log, khong `eth_call` nao, phai dung so du |

#### 12.1.1. Private chain: precompile Go la mot be mat tan cong moi (ban nhap bo trong)

§03.3.9 chot **native precompile trong go-quorum/geth-QBFT** de dat ~500 tx/s. Do la lua chon dung, nhung no doi ban chat rui ro va khong cho nao trong ban nhap noi dieu do:

| Rui ro moi | Vi sao no khac contract | Bien phap |
|---|---|---|
| **Bug trong precompile = consensus bug** | Mot revert sai o Solidity chi hong mot tx. Mot ket qua khac nhau giua hai validator lam **fork chain** | Moi validator chay **cung mot binary, cung mot hash**. Kich hoat theo block number trong genesis, khong theo flag. Do hash binary vao monitoring |
| **Precompile tra `true` cho proof gia** | Khong co lop nao ben tren bat duoc: contract tin no tuyet doi | **Differential test bat buoc**: cung `testvectors/zether_transfer_v1.json` chay qua ca `BulletproofsVerifier.sol` va precompile Go, 100% khop, gom ca **negative vector**. Day la ly do §03.3.9 giu ban Solidity lam oracle |
| **Gia gas co dinh sai** | Dat 60,000 cho mot phep tinh 1 ms ⇒ mot attacker mua duoc 1 giay CPU voi gia 60k gas ⇒ DoS re | Benchmark thuc, nhan he so an toan 3×, **va** dat `blockGasLimit` sao cho worst-case block khong vuot 500 ms CPU |
| **A12: validator la chinh ta** | `block.timestamp`, thu tu tx, va ca lich su deu do ta quyet | Anchor `head_hash` moi 15 s sang Hedera HCS (~$0.6/ngay, §11.3). Do la thu bien "toi hua" thanh "co bang chung thoi diem" |
| Nang cap precompile | Doi logic verify = doi consensus = phai coordinate downtime | Hard-fork co lich, `proofSystemId` doi theo, contract chon verifier qua `IZetherVerifier` chu khong hard-code dia chi |

**Ngan sach audit rieng**: code Go nay **khong** nam trong pham vi audit Solidity. Uoc **$30k–60k** cho mot review chuyen ve implementation crypto Go + consensus integration (co so: gia thi truong cho review 2,000–5,000 dong code crypto Go, 2 tuan, 2 nguoi). Ban nhap khong phan bo dong nao cho no.

---

### 12.2. Meta-transaction (EIP-1776)

- **Replay cross-chain / cross-contract / cross-mode.** EIP-712 domain `{name, version, chainId, verifyingContract}` chan hai cai dau. Cai thu ba chan bang viec `mode` nam **trong** struct duoc hash (§04.4); bo `mode` ra la MODE_OPEN va MODE_RESTRICT_* voi `relayer = 0` trung digest. Domain separator phai tinh lai khi `block.chainid` doi (hard fork): dung `EIP712` cua OpenZeppelin (no cache theo `address(this)` + `chainid` va tu tinh lai), **khong** hard-code separator vao `immutable`.
- **Digest injectivity — cho ban nhap chi noi mot nua.** Chan replay chua du; con phai chan **hai struct khac nhau cho ra cung digest**. Loi kinh dien: `bytes data` khong duoc `keccak256` truoc khi dua vao `abi.encode` cua struct hash, khien `("ab","c")` va `("a","bc")` trung digest. Khong fuzz nao tim ra (xac suat 0), solver tim ra trong vai giay. Bat buoc property `check_digest_injective` bang `halmos` (§14.9) — day la property dang gia nhat trong ca bo formal.
- **Canonical zeroing.** Chu "hoac" trong note ("khong bao gom, **hoac** hash voi `address(0)`") la loi spec: hai cach cho hai digest. Chot `_canon()` (§04.4), verifier tu chuan hoa, khong bao gio hash `m.relayer` tho. Mot type string, hai gia tri canonical — khong duoc tao `TYPEHASH` thu hai cho MODE_OPEN.
- **Malleability.** `ECDSA.tryRecover` (reject `s > n/2`, `v ∉ {27,28}`, reject `signer == address(0)`). Khoa idempotency phia Odoo la **EIP-712 digest**, khong phai `keccak256(signature)` va khong phai `keccak256(calldata)`: trong MODE_OPEN hai calldata khac nhau cung verify voi mot chu ky.
- **EIP-1271 la stateful, va do la mot cua so tan cong.** Voi smart account, `isValidSignature` co the tra `true` luc simulate va `false` luc inclusion (doi owner, revoke session key). Relayer mat gas, user mat 0 — dung phia chiu, nhung phai (a) `expiry` ngan, (b) re-simulate tai block muc tieu, (c) hub khong tra bounty cho relayer trong truong hop nay. Nguoc lai: mot account co the tra `true` **sau** khi da revoke neu implementation cache — khong phai loi cua ta, nhung phai co trong danh sach kiem tra khi allowlist mot loai smart account.
- **EIP-7702 pha vo mot gia dinh cu.** Sau Pectra, mot EOA **co the co code**. Moi kiem tra dang `require(from.code.length == 0)` hoac `msg.sender == tx.origin` deu khong con nghia. Neu contract nao trong `smartcontracts/evm/` dung mot trong hai mau nay thi phai bo. Grep gate CI.
- **Expiry bypass.** Validator lech timestamp ±12s khong dang ke. Rui ro that la `expiry` qua dai: mot metaTx ky voi expiry 15 phut (con so trong note §10.3) cho relayer quyen giu no nhu mot **free option**, broadcast khi co loi cho relayer. Chot theo §04.5: **60s cho Zether** (khong phai 20s — epoch da bi loai boi owner-exclusive rollover), 120s cho call co doc state, 300s cho ERC-20 transfer thuong, 900s cho anchor/log. Check `expiry` phai nam **truoc** `nonce++` va truoc thu fee: relayer tre han thi revert, nonce khong tieu, fee khong tra.
- **Thu tu check la mot quyet dinh kinh te, khong phai phong cach.** `mode` va `expiry` ton **0 gas**; `nonce` ton 2,100 (cold SLOAD); chu ky ton ~3,000. Kiem cai mien phi truoc. Ban nhap dat `nonce` truoc `expiry` — sai thu tu.
- **Relayer griefing.** Bang day du o §04.9. Ba muc phai co trong contract: `innerGasLimit` trong digest (thieu no la lo hong GSN v1); `MAX_RETURN_BYTES = 1024` voi `out = 0` trong `call` de chan return bomb (memory bac hai) — chi phi con lai **98 gas**; `require(gasleft() >= g + g/63 + FLOOR_GAS)` **truoc** inner call va hau kiem trong nhanh `!success` de chan relayer co tinh cap thieu gas.
- **User griefing nguoc lai relayer** (note khong nhac): user ky `innerGasLimit = 20,000,000`, relayer phai du tru gas do de bid. Hai lop: `targets[to].maxInnerGas` **on-chain** (khong chi hub) va hub reject `innerGasLimit > 3,200,000` cho Zether / `> 1,500,000` cho phan con lai, dinh gia bid theo `gasUsed` mo phong chu khong theo `innerGasLimit`.
- **Rut `approve` sau khi publish** (§5.5, ban nhap 12 bo sot): attacker publish 100 intent hop le, cho relayer broadcast, roi `approve(forwarder, 0)` trong cung block. 100 tx revert, attacker mat **mot** tx. Ty le 100:1. Bien phap: `hints.allowance_ok` kiem o tang 4; `origin_grief_score` theo `meta_tx.from` (3 lan revert/24h ⇒ ep PoW + `max_inflight = 1`); duong ban chat la `permit`/Permit2 de allowance nam **trong** tx.
- **Cross-lane reordering.** `batchNonce` chi bao dam thu tu **trong mot lane**. Neu Odoo dat `escrow` va `settle` o hai `batchId` khac nhau, relayer duoc phep dao thu tu. Quy tac cung phia Odoo (§15.2.1): moi chuoi phu thuoc phai dung **cung mot** `batchId` duoc dan xuat tat dinh tu `origin_key`; `_build_metatx` raise khi phat hien mot `origin_ref` sinh ra hai lane.
- **Lane exhaustion.** `batchId` la `uint256` ngau nhien ⇒ khong het. Nhung mot lane **ket** (nonce da cap, tx khong bao gio len chuoi) khoa vinh vien moi giao dich phu thuoc. Phai co `lane_epoch++` (§04.3) va `bumpBatchNonce` on-chain; thieu no thi mot tx treo lam chet ca chuoi settlement va khong ai go duoc.

---

### 12.3. Zether

#### 12.3.1. Randomness — lo hong nghiem trong nhat ma ban nhap khong nhac mot chu

Toan bo bao mat cua Zether nam tren gia dinh rang `r`, `s`, va nonce Schnorr `k` la **ngau nhien va khong bao gio lap**. Ba he qua neu sai, tat ca deu la mat sach tai khoan chu khong phai ro ri nho:

| Loi | Toan hoc | Hau qua |
|---|---|---|
| Lap `k` giua hai chu ky Schnorr | `k = (z1 - z2)/(c1 - c2) mod q`, roi `x = (z1 - c1·k)/1` | **Lo `x` hoan toan.** Day la loi da giet Sony PS3 va nhieu vi Android |
| Lap `s` giua hai transfer cho **cung** nguoi nhan | `C1/C2 = g^(v1-v2)` ⇒ hieu hai so tien lo ra; voi mot so tien da biet thi ca hai lo | Lo so tien, pha bo mat |
| RNG yeu (seed theo `time()`, `Math.random()`, `/dev/urandom` trong container moi khoi dong chua co entropy) | Khong gian tim kiem nho | Brute-force ra `x` |

**Chot, bat buoc, va phai co test:**

1. **Nonce tat dinh kieu RFC 6979 / synthetic nonce** cho moi chu ky Schnorr va moi randomness cua sigma proof:
   `k = HMAC-SHA512(key = x, msg = domain_sep || chainId || address(this) || zetherNonce || H(statement) || 32_byte_random)`, roi reduce mod `q`. Ket hop **tat dinh + entropy** (synthetic): tat dinh chan lap khi RNG chet, entropy chan phan tich sai lech theo fault injection.
2. **`s` cua ElGamal khong duoc tat dinh theo (v, y_recv)** — neu tat dinh thuan thi hai lan chuyen cung so tien cho cung nguoi cho ra **cung ciphertext**, lo ngay. Phai them `zetherNonce` vao input HMAC. Do la mot khac biet tinh te giua chu ky va ma hoa ma nhieu implementation lam sai.
3. **Test bat buoc** `test_no_nonce_reuse`: chay 10,000 proof voi RNG bi ep tra hang so, assert rang tat ca `k` va `s` van khac nhau (vi da co `zetherNonce` trong transcript). Va `test_extract_x_fails`: hai proof cho cung `zetherNonce` phai **khong the** tao ra (contract da tang nonce), va neu ep tao thi bo test phai chung minh khong giai duoc `x`.
4. **Cam dung RNG cua ngon ngu.** `Math.random`, `random.random()`, `rand()` bi CI grep chan trong `smartcontracts/` va trong client SDK. Chi `getrandom(2)` / `crypto.getRandomValues` / `OsRng`.

#### 12.3.2. Proof forgery — rui ro so 1, va no la loi transcript chu khong phai loi toan hoc

Lop bug pho bien nhat cua Bulletproofs trien khai tay la Fiat-Shamir yeu ("Frozen Heart"): thieu mot public input trong transcript la proof gia duoc. Transcript **bat buoc** hap thu, dung thu tu, **dung do dai co dinh, co domain separation va length-prefix**:

```
absorb("ZETHER_BP_V1")                 // domain, 12 byte co dinh
absorb_u64(chainId)
absorb_addr(address(verifier))
absorb_b32(proofSystemId)              // "BP_BN254_V1" | "G16_BJJ_V1" | "NATIVE_BP_V1"
absorb_b32(fromAddr); absorb_b32(toAddr)
absorb_u64(zetherNonce); absorb_u64(authEpoch)
absorb_point(C_transfer); absorb_point(D_transfer)
absorb_point(C_debit);    absorb_point(C_audit)
absorb_u256(fee); absorb_b32(feeRecipient)
absorb_b32(keccak(generators_blob))    // tap generator, KHONG hap thu tung diem
absorb_u64(deadline)
```

Ba quy tac ma neu thieu thi transcript van "trong nhu dung":

- **Length-prefix moi truong do dai bien.** Neu hap thu `bytes` tho, `("ab","c")` va `("a","bc")` cho cung challenge. Day la cung mot lop loi voi digest injectivity o §12.2.
- **Hap thu `generators_blob` hash, khong hap thu tung generator.** Vua re vua chan duoc "doi generator" — mot vector that neu generator doc tu SSTORE2 (§03.3.5).
- **`proofSystemId` phai nam trong transcript**, khong chi trong interface. Nguoc lai, mot proof Groth16 co the duoc trinh cho verifier Bulletproof va nguoc lai trong tuong lai da-verifier.

Kiem chung: mot file `smartcontracts/testvectors/zether_transfer_v1.json` dung chung cho prover Rust, verifier Solidity **va** precompile Go, cong mot bo **negative test** doi tung byte cua tung public input va assert revert. Bo negative test phai co **it nhat mot case cho moi truong** trong transcript o tren (13 truong ⇒ >= 13 negative vector). **Khong co bo negative test nay thi khong duoc deploy.**

#### 12.3.3. Loi that trong note: `withdraw` khong bind chain

Note bam `recipient, amount, zetherNonce` vao challenge — dung, chan duoc relayer doi `recipient`. Nhung `schnorrAddress = keccak256(pkX, pkY)` **giong het nhau tren moi EVM chain** (§02.8). Neu cung mot tai khoan ton tai tren Gnosis va Celo va `zetherNonce` tinh co bang nhau, mot proof withdraw hop le tren chain A replay duoc tren chain B. Phai them `block.chainid`, `address(this)` va `authEpoch` vao challenge. Day la lo hong mat tien that, khong phai gop y phong cach.

He qua tuong tu, va ban nhap cung bo sot: **thieu `address(this)` thi chu ky/proof cho Z-USDC dung duoc tren Z-VND** (§02.4.2 da neu cho `assertAuthorized`, nhung dieu do phai ap cho ca Fiat-Shamir challenge cua `transferConfidential`, khong chi cho `withdraw`). Va note goc bam `recipient` vao challenge cho `withdraw` nhung **khong** bam `feeRecipient` vao challenge cho `transferConfidential` — do la mot lo hong anti-MEV that: relayer doi `feeRecipient` sang vi cua no.

#### 12.3.4. Malformed ciphertext va diem xau

- alt_bn128 G1 co **cofactor 1** nen chi can on-curve check; nhung neu chuyen sang **Baby Jubjub** (public profile, va §03.3.9 khuyen nghi dung ngay tu dau) cofactor la **8** ⇒ **bat buoc subgroup check** (`[q]P == O`), khong co ngoai le. Bo qua no = small-subgroup attack, ro ri tung bit cua `x`.
- **Diem identity phai bi reject moi noi**: `y = O` lam `C = g^v` (lo thang so tien), `D = O` lam giai ma tam thuong. Registry PoP (§02.2) da chan `y = O` luc dang ky; contract van phai reject identity trong ciphertext — khong duoc gia dinh input den tu registry.
- **Invalid-curve**: diem khong nam tren duong cong nhung precompile van tinh (bn254 precompile cua EVM tu reject, nhung mot implementation Go tu viet thi **khong** neu quen). Test vector am phai co ca diem off-curve va diem trong subgroup nho.
- **`C_audit` phai duoc validate nhu moi diem khac.** No la duong lot de nhat vi no "chi de kiem toan".

#### 12.3.5. Epoch race, va cai gia cua quyet dinh owner-exclusive

Voi thiet ke epoch goc, xac suat lech epoch giua simulate va inclusion la dang ke tren Gnosis (block 5s, epoch 5 block = 25s: mot tx nam o 20% cuoi epoch va cham 1 block la lech). Quyet dinh **owner-exclusive rollover** (§03.5) xoa han vector nay: `acc[from]` chi doi trong tx cua chinh `from`.

Nhung phai noi thang hai dieu ban nhap khong noi:

1. **Do la mot thay doi tang giao thuc so voi bai bao Zether.** No **khong** duoc quyet bang suy luan trong tai lieu nay. No la muc trung tam cua audit Phase B. Neu reviewer bac, thi `uint64 targetEpoch` quay lai struct **va** `expiry` cua Zether tut ve <= 1 epoch — hai thu di cung nhau (§04.10).
2. **Neu deployment nao giu thiet ke goc**: thieu `require(currentEpoch() == targetEpoch)` thi proof cua epoch `e` mined o `e+1` co the **pass tren state cu** neu `rollOver` chua chay, va do la **mat tien** chu khong phai revert. Day la khac biet giua "kho chiu" va "mat quy".

#### 12.3.6. Recipient DoS bang pending flooding — kinh te thuc te, sua lai con so cua ban nhap

Storage la O(1) nho tinh dong hinh, nen chuoi khong sao. Nan nhan la **client**: vi phai giai ma de giu so cuc bo.

Ban nhap tinh: `10,000 dust transfer × 60k gas ≈ 600M gas ≈ $0.60`, ty le thiet hai 1,700:1, ket luan "kinh te khong chan duoc". **Ca ba con so deu sai:**

| | Ban nhap | Dung |
|---|---|---|
| Gas mot Zether transfer | 60,000 | **1.72M–2.62M** (§04.10) |
| Tong gas cho 10,000 tx | 600M | **~20 Ggas** |
| Chi phi tien mat (Gnosis @1.5 gwei, xDAI=$1) | $0.60 | **~$30** (va base fee se tang khi chiem block) |
| Thoi gian de land 10,000 tx | khong tinh | 20 Ggas ÷ 3.4 Mgas/s = **~98 phut o 100% block space cua ca Gnosis** |
| Thiet hai phia nan nhan | 17 phut BSGS | 17 phut, **hoac ~0 neu co memo (§03.2.5)** |

Ket luan doi chieu: ty le thiet hai khong phai 1,700:1 ma vao khoang **1:1 den 10:1**, va tan cong bi chan boi chinh block space chu khong boi vi tien. **Khong** con la "kinh te khong chan duoc". Van phai chan, nhung bang thiet ke client chu khong bang hoang loan:

- (a) Vi doc `getPendingBalance` va BSGS **mot lan tren tong** khi so event chua xu ly > 200, thay vi cong don tung khoan. Voi tinh dong hinh day la mot phep giai ma, khong phai N.
- (b) **Memo ma hoa so tien** (§03.2.5) xoa bo BSGS hoan toan cho duong thong thuong. Do la bien phap thuc su, (a) chi la du phong.
- (c) Indexer phia Odoo tinh `pending_event_count` va canh bao (bang 12.11 dong 13).
- (d) **Khong** them allowlist nguoi gui o tang contract — no pha tinh nhan tien khong can xin phep va khong giai quyet duoc goc.

**Con so quan trong hon, va ban nhap khong co no:** neu 10,000 tx rac chiem 98 phut block space cua Gnosis thi **chinh he thong cua ta bi DoS**, khong phai mot client. Xem 12.7.5.

#### 12.3.7. Ro ri metadata

Bon duong, ba trong so do phai chan bang quy tac:

1. **Phi tuyet doi khong duoc la ham cua so tien bi mat.** Neu bao gia relayer theo phan tram gia tri giao dich (mot quy tac nghiep vu rat tu nhien), `metaTx.fee` cong khai **lo chinh xac so tien**: `v = fee / 0.003`, mot phep chia, pha huy toan bo Zether. Chot: **phi phang lay tu mot thang roi rac nho** (vi du `{0.01, 0.05, 0.25, 1.00}` don vi), hoac bac thang theo `innerGasLimit`. Day la rang buoc **thiet ke contract**, khong phai tuy chon van hanh. Ghi vao `_build_zether_metatx` mot assert **va** ghi vao `TargetPolicy` mot `CalldataRule` (§04.10 muc 3).
2. **Cam ca hai kenh phi cung > 0** (§04.10): thu phi hai lan, va hai con so cong khai cung luc cho quan sat vien mot he phuong trinh ve co cau phi. Enforce o ca ba cho: builder Odoo, `ERC1776Native` mixin, `CalldataRule` cua forwarder.
3. **`deposit`/`withdraw` cong khai so tien.** Mot cong ty nap $250k roi 3 transfer roi rut $0 da lo tong luong. **Dinh luong:** voi thang 8 menh gia va < 5 tai khoan hoat dong moi epoch, tinh an danh cua so tien **sup do gan nhu hoan toan** (§11.10). Giam thieu: giu float lam viec, nap theo lich co dinh va so tron (buoc $50k), khong nap "vua du" ngay truoc mot lan thanh toan, va **dwell time toi thieu** giua deposit va transfer.
4. **Gas nhu kenh phu.** Proof size co dinh nen verify khong lo gi. Nhung bat ky nhanh re nao (`if (fee == 0)`, `if (feeRecipient == 0)`) lam gas khac nhau va ro ri mot bit. Quy tac: **thuc thi phai cung hinh dang** cho moi input hop le; test `GasUniformity.t.sol` do gas cua 3 nhom input va assert lech < 2,000 gas.
5. **`simulateAccounts` la mot oracle** (ban nhap khong nhac). No la `view`, khong ton gas, khong xac thuc, va cho phep bat ky ai **liet ke** tap tai khoan da dang ky va quan sat `pending` doi theo thoi gian thuc. Do khong phai so tien, nhung no la do thi + timing voi do phan giai cao hon ca event. Khong the bo (client can no), nen: (a) chap nhan tren public profile, (b) tren private profile dat node RPC sau mTLS, (c) rate-limit o RPC gateway.

#### 12.3.8. Danh tinh cong khai la thiet ke, nhung he qua thi phai noi thang

Doi thu doc chuoi biet **toan bo danh sach distributor** cua mot brand, biet khi nao mot distributor bi cat, biet tan suat thanh toan, va biet **luc luong** (so transfer moi cap moi ky). Do la tinh bao canh tranh, khong phai so tien. Tren public chain khong co cach nao giau do thi ma khong quay lai mixer (da bi loai theo yeu cau AML). Neu do thi la bi mat ⇒ B2B settlement **phai** chay tren `chain_profile = private`. Day la mot quyet dinh kinh doanh, dua vao muc 12.12.

Them mot he qua phap ly ma §02.7.6 da chi ra va ban nhap 12 khong nhac: **lo danh tinh khong lam thoa man FATF Travel Rule.** Rec.16 doi thong tin originator/beneficiary **va so tien**. Danh tinh khong kem so tien khong du. Do la ly do `C_audit` ton tai va la ly do no phai **bat buoc** tren B2B, khong phai tuy chon.

#### 12.3.9. Khoa auditor `x_audit`

No giai ma duoc moi giao dich co `C_audit`, **ca lich su**, va mot lan lo la lo vinh vien (khong co forward secrecy). No la muc tieu gia tri cao hon bat ky tai khoan don le nao. Bat buoc, theo §02.7.6:

- `y_audit` la khoa **threshold k-of-n** giua n auditor (DKG Pedersen). Khong ton them gas on-chain (van la mot diem G1); toan bo do phuc tap nam o quy trinh off-chain.
- Rieng theo **chain profile va theo phap nhan phat hanh**, khong dung chung mot khoa toan cau.
- Luu offline/HSM, tach hoan toan khoi ha tang van hanh; khong bao gio nam trong cung tai khoan cloud voi production.
- Xoay theo ky (de xuat 12 thang), **xoay khong lam mat hieu luc lich su** — ciphertext cu van duoi khoa cu ⇒ phai luu tru khoa cu theo lich luu ho so, khong huy.
- Gia thuc: `C_audit` + equality proof Chaum-Pedersen = **~25,300 gas/transfer (~+11%)**, khong phai 13,200 nhu mot ban nhap truoc ghi (§02.7.6 da sua).

#### 12.3.10. Client SDK (A13) — vector ma ban nhap bo hoan toan

`x` song trong RAM cua client. Ke chen duoc mot dong vao `@bamboo/zether-sdk` hoac vao mot dependency cua no lay duoc `x` cua **moi** nguoi dung, khong can cham chain, khong cham Odoo, khong cham HSM. Do la duong re nhat trong ca mo hinh nay.

| Bien phap | Cu the |
|---|---|
| Pin va lock | `package-lock.json` commit, `npm ci --ignore-scripts`, cam `postinstall` |
| Toi thieu hoa dependency | Prover Rust bien dich sang WASM, chi lo mot mat cat API. Muc tieu: **< 10 dependency truc tiep** cho duong cham `x` |
| Subresource Integrity | Web client tai SDK bang `<script integrity="sha384-...">`, khong bao gio tu CDN khong pin |
| Reproducible build + ky | Artifact WASM co hash cong bo; client kiem hash truoc khi nap. Ky bang khoa release rieng, khong phai khoa CI |
| Tach `x` khoi UI | Prover chay trong Web Worker / enclave, UI khong bao gio doc duoc `x`. Khong xoa duoc XSS nhung nang chi phi khai thac |
| `recipient` phai hien thi tu **du lieu da ky** | Client render `to` tu chinh struct sap ky, khong tu bien state khac. Chan "UI hien A, ky B" |

---

### 12.4. Mang luoi relayer

| Vector | Danh gia | Bien phap |
|---|---|---|
| Sybil | Chi phi tao intent gia ~50 µs (mot ECDSA) vs 15–40 ms simulate (**60–150 ms** neu Zether) ⇒ ty le **500:1**, len **~3,000:1** voi Zether | 6 tang cua §5.5. **Sua so voi ban nhap:** tang 0 (IP) phai o **nginx `limit_req`**, khong trong Odoo (moi worker la mot process, bo dem trong bien module dem sai theo he so `workers`); tang 1 (`from`) o Redis |
| PoW | Ban nhap ghi "PoW 20 bit o tang 3" | **Sua:** 20 bit ≈ 1M keccak ≈ **5 s tren Android tam trung** — khong chap nhan duoc cho app ban hang. Mobile luon di duong **JWT `bamboo_token_auth`** (§5.5 lua chon c). PoW chi cho nguoi la hoan toan, va khi buoc phai co tren mobile thi **16 bit** (~0.3 s). `blockchain.intent.pow_bits` la config, tang tu dong khi hang doi simulate > 500, **tat hoan toan khi private profile** |
| Storage DoS | Botnet 10,000 dia chi × 10 intent/phut = 1,667 intent/s × 1.5 KB = **216 GB/ngay** neu persist | **Khong persist gi truoc tang 3.** Intent song trong Redis `TTL = expiry - now`. Chi qua tang 4 moi `create()` row `blockchain.metatx` |
| Intent theft | **Khong the** — digest chan sua noi dung; `feeRecipient` la thu duy nhat doi duoc va no dang tra cho chinh no | Khong can them |
| Fee front-run giua N relayer | Ke thua revert, EV giam ve ~18% khi N=5 | Soft-exclusivity **W = 3s tren Gnosis, va W = 0 cho `is_zether`** (§5.4.4a — ban nhap bo mat ve thu hai) + lottery |
| **Lottery weighting** | Ban nhap ghi `sqrt(stake) × reputation`. **Sai, va sai theo huong nguy hiem** | §5.4.4a da bac: voi trong so can bac hai, tach stake `S` thanh `k` danh tinh cho tong `sqrt(k)·sqrt(S)` — **thuong sybil `sqrt(k)` lan mien phi** (k=100 ⇒ 10×). Trong so can bac hai chi co nghia khi co registry danh tinh duy nhat; o day khong co. **Chot: trong so tuyen tinh × reputation, `MIN_BOND` ~$500, `CAP_SHARE = 0.20`, `REP_FLOOR = 0.10`** |
| Kiem duyet cua mot relayer | Hub re-publish sau `W` | Reputation EWMA |
| **Kiem duyet cua toan bo hub** (A3) | Note khong xu ly | Duong thoat bat buoc: `blockchain.relay.job` chuyen sang **Enterprise Relay Pool** noi bo bang mot co switch; **drill blackout hub hang thang**, do thoi gian chuyen mach. Duong thoat khong duoc kiem thu la duong thoat khong ton tai |
| Ro ri du lieu qua intent bus | §5.4.5: `MODE_OPEN` = moi nguoi doc duoc calldata **truoc** khi len chuoi. Voi ERC-20 B2B do la **toan bo** giao dich | Private profile: bus chi nghe noi bo, **mTLS hai chieu, khong federation**. Public profile: `blockchain.chain.max_public_intent_value_base` — builder tu choi publish `MODE_OPEN` khi `amount > nguong` va khong confidential |
| MEV sandwich quanh deposit/withdraw | Voi `WRAP_1_1` khong co gia ⇒ khong sandwich duoc. Voi `PeggedToken` **co**: front-run mot lan cap nhat rate | `minAmountOut` tren moi phep quy doi peg; `SignedRateSource` k-of-n publisher, `maxRateAge = 3600s`, `maxDeviationBps = 200`/lan cap nhat, **halt mint (khong halt burn)** khi lech > 500 bps |
| MEV tren `withdraw` Zether | `recipient` da bam vao Fiat-Shamir ⇒ khong doi duoc. Nhung **`amount` cua withdraw la plaintext**, nen mot withdraw lon van la tin hieu giao dich cho ke khac | `blockchain.rpc.endpoint.propagation`: tx co `mev_sensitive=True` chi gui toi endpoint `private orderflow`, **khong fan-out** (§06.7.2 quy tac 3). Ban nhap bo mat quy tac nay |
| Slashing | v1 **khong co**. Xay adjudication on-chain cho khieu nai $0.005 la vo ly (§5.6) | `UNBOND_PERIOD = 7 days` de chan bond-chiem-lottery-rut. Bond bang **native cua chain (xDAI)**, khong bang enterprise token — bond bang token minh in ra khong phai la stake |
| Relayer doc bus de thu thap tinh bao thuong mai | **Co the**, va khong slashing nao chan duoc | Chan bang **quyen truy cap bus** (mTLS, NDA cho `MODE_RESTRICT_RELAYER`), khong bang tien |

---

### 12.5. Custody

#### 12.5.1. HSM khong biet no dang ky cai gi

Day la hieu lam nguy hiem nhat quanh yeu cau "FIPS 140-2 L3". Mot HSM PKCS#11 ky bat ky 32 byte nao ban dua vao. A5 chiem duoc app server thi ky duoc mot tx rut sach treasury **ma khong can trich xuat khoa**. **FIPS L3 chong trich xuat khoa, khong chong lam dung khoa.**

Bien phap: **policy phai nam cung phia voi signer**, khong nam trong Odoo. Ban nhap dung o ket luan nhung hand-wave o co che. Cu the:

```python
# confidential-signer/policy.py  — chay TRONG enclave, truoc moi lan ky
def authorize(tenant_uuid: str, signer_ref: str, payload: bytes) -> None:
    tx = parse_typed_tx(payload)          # BAT BUOC ho tro type 0x00,0x01,0x02,0x03,0x04
    assert signer_ref.startswith(f"blockchain/{tenant_uuid}/")   # §07.11
    assert tx.chain_id in ALLOWED_CHAINS[tenant_uuid]
    assert tx.to in ALLOWLIST[tenant_uuid][tx.chain_id]
    assert tx.selector in ALLOWED_SELECTORS[tx.to]
    assert tx.value <= VALUE_CAP[signer_ref]
    assert hourly_spend(signer_ref) + tx.value <= HOURLY_CAP[signer_ref]
    assert tx.nonce == expected_nonce(signer_ref)   # signer giu nonce, KHONG tin caller
    assert digest_not_seen(sha256(payload))         # chong replay VAO signer
```

Sau diem ma neu thieu thi lop nay chi la trang tri:

1. **Parse duoc moi tx type, ke ca `0x04` (EIP-7702 SetCode).** Mot payload type 4 ky duoc se gan code vao EOA cua treasury. Neu parser khong biet type 4, mac dinh phai la **tu choi**, khong phai bo qua.
2. **Signer tu giu nonce.** Neu no tin `tx.nonce` do relay-pool gui thi A10 ky duoc hai tx cung nonce (mot cho ta, mot cho no) va thay the trong mempool.
3. **Chong replay vao chinh signer.** Cung mot payload gui hai lan phai bi tu choi; neu khong, A10 tua lai mot lenh rut hop le.
4. **Enclave image duoc pin.** Tren AWS: `kms:Decrypt` voi tham so `Recipient` (attestation document COSE_Sign1 ky boi Nitro PKI) va key policy dieu kien tren `kms:RecipientAttestation:PCR0` / `ImageSha384`. Ket qua: **chi dung mot image, do bang hash, moi unwrap duoc `x`**. Root tren EC2 host cung khong doc duoc. Tren GCP: Confidential Space + attribute condition tren `submods.container.image_digest`.
5. **Doi image la mot su kien governance, khong phai mot lan deploy.** Pin PCR0 nghia la moi ban va deu phai duoc them vao key policy — do la co y. Phai co runbook, 2 nguoi duyet, va monitoring tren thay doi key policy.
6. **Rollback protection.** Neu key policy con cho phep PCR0 cu, mot attacker chay lai image cu co bug. Chinh sach: giu **toi da 2 PCR0** (hien tai + ban truoc, de rollback khan), xoa cai thu ba.

Va mot cau phai viet vao hop dong khach hang: **o mo hinh nay `x` khong nam trong bien FIPS 140-2 Level 3 tai thoi diem su dung.** Nitro Enclave / Intel TDX khong co chung nhan FIPS L3 cho vai tro nay. Neu mot co quan quan ly doi FIPS L3 cho khoa ma hoa so du, cau tra loi trung thuc la yeu cau do **hom nay khong thoa man duoc voi Zether** (§07.2).

#### 12.5.2. Hai lop khoa, va cho note sai

Note yeu cau moi private key nam trong HSM/MPC. **Mot HSM PKCS#11 khong tinh duoc Bulletproof/ElGamal**: `encKey x` phai o trong process prover, duoc dung lien tuc. (Chi tiet ky thuat: `CKM_ECDH1_DERIVE` *la* phep nhan vo huong, nhung khong HSM nao co OID cho BN254/Baby Jubjub, va hang nghin round-trip PKCS#11 cho mot transfer la vai giay — §07.2.)

| Lop khoa | Dung de | Noi song | Ai duyet | Throughput |
|---|---|---|---|---|
| `authKey` treasury / contract admin | Upgrade, pause, refill, mint | HSM FIPS L3 hoac MPC, **dual control** | Governance Safe | 10^3/s (khong can) |
| `authKey` relayer hot | Ky vo tx cua relayer EOA | Nitro Enclave / SGX, **xoay 30 ngay** (khong phai moi gio — sua so voi ban nhap, §06.5.1), runway 4h | Ops | 10^4/s |
| Session key cua Agent | Ky `MetaTransaction` | Enclave hoac secure element cua thiet bi | Policy on-chain | — |
| **`encKey x` (Zether)** | Giai ma so du, dung proof | Enclave; hoac MPC threshold ElGamal (chi phi ky cao); toi thieu la DEK wrap boi KMS, giai trong RAM, **khong bao gio persist** | Bat buoc backup Shamir 2-of-3 **truoc khi mo tai khoan dau tien** | 1 proof/200–800 ms |

**Nut co chai phai biet truoc:** MPC SaaS cho **5–30 sign/s va p50 300 ms – 3 s** cho mot vault (§06.6). Neu moi business action = 1 chu ky thi tran he thong la 5–30 action/s — thap hon ca chuoi. Duong ra la `MetaTxBatcher.executeBatch` (1 chu ky HSM cho N=50 meta-tx) chu khong phai them EOA. Nhung batcher **mo ra mot vector moi**: mot item hong keo ca batch chet, va mot relayer co the dot nonce cua user. Ba rang buoc bat buoc len batcher (§06.6): `require(gasleft() >= g + g/63 + 12_000)` truoc moi item; **khong** revert ca batch khi mot item fail; thu fee **truoc** inner call.

#### 12.5.3. Session-key over-scoping

Mot session key voi `to = MetaTxForwarder` va calldata tu do la **toan quyen**. Scope phai la `(chainId, target, selector, tokenContract, cumulative_value_cap, expiry, batchId range)` va phai duoc enforce **on-chain** boi smart account, khong chi trong Odoo — vi A5 va A10 di vong qua Odoo duoc.

Bon quy tac them:

- **`authEpoch` phai nam trong digest** (§02.4.2). Thieu no thi xoay khoa khong vo hieu hoa chu ky cu, va toan bo co che thu hoi la trang tri.
- **Cumulative cap phai on-chain**, khong phai per-tx cap. Mot tran $1,000/tx voi 500 tx la $500,000.
- **Thoi han 1–8 gio**, va revoke phai la mot lenh **on-chain** (`authEpoch++`), khong phai mot co trong Odoo.
- **Khong pre-sign hang loat theo nonce** (§06.6.4): mot kho tx da ky trong Redis la mot kho tien ai doc duoc Redis cung phat song duoc, va khong huy duoc. Ngoai le duy nhat duoc xem xet la **mot** tx cancel (self-send, 21,000 gas) cho moi nonce inflight, luu trong enclave chu khong trong Redis, va mac dinh **tat**.

#### 12.5.4. Custodial mode va rui ro noi bo

**Custodial mode**: omnibus `schnorrAddress` chung ⇒ operator thay moi so tien cua moi khach, va so phu Odoo tro thanh nguon su that duy nhat. Ve mat phap ly do la **nhan giu tien cua nguoi khac** (§13.4 — co the roi vao pham vi giay phep trung gian thanh toan). Ghi ro trong tai lieu deploy; khong bat mac dinh.

**Insider risk, cu the chu khong chung chung:**

| Kich ban | Chan bang |
|---|---|
| Mot ky su co ca quyen deploy va quyen duyet | Tach `DEPLOYER_ROLE` (service account) khoi `PROTOTYPE_ADMIN` (Safe 3-of-5) — §1.11. Nguoi khong duoc o ca hai |
| Nguoi giu treasury cung la nguoi duyet relayer | `group_blockchain_treasury` va `group_blockchain_relayer_admin` **khong bao gio** cung mot user; test ACL assert giao rong (§10.5) |
| Nhan vien nghi viec van con quyen | Offboarding checklist co: xoa khoi Safe (on-chain tx!), xoay `authEpoch`, thu hoi client cert mTLS, xoay credential RPC. Cron doi chieu `getOwners()` cua moi Safe voi `blockchain.governance.signer` **hang ngay** (§1.11.1 muc 2) |
| Break-glass bi lam dung | Moi lan dung khoa break-glass phat event on-chain + page toan doi + post-mortem bat buoc, ke ca khi hop le |

---

### 12.6. Tang Odoo

```python
@api.model
def relay_submit_intent(self, caip2, target_address, calldata_hex, ...):
    # 1. KHONG sudo() o day. sudo() trong entry point RPC = bat ky user noi bo nao
    #    cung dieu khien duoc quy gas cua doanh nghiep.
    self.check_access('create')          # check_access mang @api.private => khong goi duoc qua RPC
    if not self.env.user.has_group('dms_blockchain.group_relay_submitter'):
        raise AccessError(_('Khong co quyen gui intent.'))
    # 2. Allowlist target o server, khong tin client.
    self._assert_target_allowed(caip2, target_address, calldata_hex[:10])
    # 3. Velocity theo user, khong theo IP (IP la nginx lo).
    self._assert_velocity(self.env.user.id)
    # 4. Cong ty lay tu env, KHONG bao gio tu payload.
    return self._submit_intent(self.env.company, ...)   # logic private
```

#### 12.6.1. `base.group_system` = RCE trong process Odoo (sua mot sai lam cua ban nhap)

Ban nhap tach A4 (`base.group_system`) va A5 (chiem app server) thanh hai muc do khac nhau. **Tren Odoo do la mot.** Mot user `base.group_system` co the tao `ir.actions.server` voi `state = 'code'` va chay Python tuy y **trong chinh process Odoo**, voi moi bien moi truong, moi socket, moi credential ma process do co. Cung nhu vay voi `base.automation`, voi `ir.cron` (`state='code'`), va voi cai dat mot module tuy y.

He qua, phai viet ra chu khong duoc de nguoi doc tu suy:

1. **Moi bien phap dua tren "chi group_system moi doc duoc" deu bang khong.** `ir.config_parameter` chi la mot vi du; ke ca `fields.Char(groups=...)` cung khong chan duoc A4 vi A4 chay code, khong goi `read()`.
2. **Do do policy signer phai o ngoai Odoo** (12.5.1). Do khong phai "defense in depth", do la **duy nhat** lop con lai khi A4 xuat hien.
3. **Danh sach nguoi co `base.group_system` phai ngan va phai duoc review dinh ky** nhu danh sach signer cua Safe. Trong Odoo 19, kiem bang `group_ids` (khong con `groups_id`).
4. **Monitoring bat buoc**: bat ky `create`/`write` tren `ir.actions.server`, `base.automation`, `ir.cron`, `ir.model`, `ir.model.fields` deu la su kien bao mat, khong phai su kien cau hinh (bang 12.11 dong 12).
5. Cau hoi con lai cho nguoi quyet: `base.group_system` co nam trong bien tin cay khong. Hien tai **co** — va do la mot lua chon, khong phai mot su that.

#### 12.6.2. Bang vector tang Odoo

| Vector | Cu the | Bien phap |
|---|---|---|
| Record-rule bypass | Rule dung `('organization_id', 'child_of', ...)` tren mot Char `parent_path` ⇒ `ValueError`, va o Odoo 19 mot rule loi lam **moi** search raise (bay §2 CLAUDE.md). `dms_blockchain` khong co `organization_id`; dung `company_id` many2one + `('company_id', 'in', company_ids)` | Guard CI da co; them test doc/ghi cheo company cho **tung** model `blockchain.*` (A9) |
| Ro ri qua `read_group` / `search_read` | Rule loc **dong**, va `read_group` van bi rule chan — nhung mot `read_group` tren `amount_base` cua model khong company-scoped (`blockchain.transaction`, §10.9) lo tong hop cho tenant khac | `blockchain.transaction` phai co rule gian tiep `['|', ('settlement_ids','=',False), ('settlement_ids.company_id','in',company_ids)]`. Test: user cong ty A `read_group` khong thay tong cua B |
| Ro ri cot, khong phai dong | Rule khong loc cot. `signer_ref`, `endpoint_ref`, `pow` cua account | `fields.Char(groups='dms_blockchain.group_blockchain_manager')` — **Odoo thuc su chan o `read()`**, khac han `password=True` von khong ton tai o Odoo 19 va chua bao gio chan `read()`/RPC/export |
| RPC lo method nguy hiem | Bat ky method khong `_` va khong `@api.private` deu goi duoc qua `call_kw` **va** `/json/2` | Quy tac cung: **khong method public nao duoc gay ra mot chu ky HSM dong bo**. Ky chi xay ra trong cron/worker, tren record da o state duoc rule cho phep. Test liet ke moi method public cua `blockchain.*` va assert no nam trong allowlist da review (§10.6) |
| Nhan `allowed_company_ids` tu client | Mot method public nhan `company_id` la mot lo hong leo thang pham vi | `self.env.companies` do session/JWT quyet dinh. Grep gate: khong signature nao cua method public chua `company_id` hay `allowed_company_ids` |
| `ir.config_parameter` doc duoc boi `base.group_system` | `get_param` goi duoc qua RPC; **va** dump DB chua no nguyen ven | Chi luu **handle** (`signer_ref`, `url_ref`, `key_ref`). Bi mat that nam trong bien moi truong / file doc luc khoi dong (`odoo.tools.config`) hoac secret manager. §06.7 de nghi luu URL RPC **kem API key** trong `ir.config_parameter` — **do la ro ri credential toi moi Settings admin va toi moi ban backup**, phai sua |
| Backup DB va filestore | Mot ban dump `.sql` la mot ban sao cua moi `ir.config_parameter`, moi `res.users.password` hash, moi attachment metadata | Backup ma hoa at-rest, khoa nam ngoai Odoo; **khong bao gio** restore production dump len staging ma khong chay script scrub (`ir.config_parameter` `blockchain.*`, `ir.mail_server`, `fetchmail.server`) |
| Ro ri qua log | Traceback cua `requests` in ca URL kem query string; mot API key trong URL vao thang `ir.logging` va vao Sentry | Credential khong bao gio o query string; `logging` filter cho `Authorization`; `ir.logging` retention 30 ngay |
| SQL injection | Indexer xu ly reorg thuong viet raw SQL co ten bang dong | Dung `odoo.tools.SQL` (Odoo 17+ co object nay va `cr.execute` nhan truc tiep) hoac `cr.execute(query, params)` voi `%s`; ten bang dong dung `SQL.identifier(...)`; **cam f-string trong `execute` bang mot grep gate trong CI** |
| Privilege escalation qua `sudo()` | `sudo()` de ghi audit row roi vo tinh dung `self` da sudo cho ca nhanh nghiep vu | `sudo()` chi tren mot recordset **moi lay lai** (`self.env['x'].sudo().create(...)`), khong bao gio tren `self`; moi `sudo()` phai co comment mot dong ly do; CI dem so lan `sudo()` va fail khi tang ma khong co review |
| `ir.attachment` cua audit report / proof blob | Attachment `public=True` hoac lo `access_token` ⇒ bao cao kiem toan reserve doc duoc boi bat ky ai. Chung nam tren Garage (S3) | `public=False`, `res_model`/`res_id` tro dung record, khong sinh `access_token`; bucket Garage **khong** public-read; presigned URL TTL <= 15 phut |
| Consumer suy sai trang thai | `payment.transaction._set_done()` goi tu `mined` | `_set_done()` **chi** khi `blockchain.metatx.state == 'done'` (finalized **va** `innerSuccess = true`), roi `_post_process()`. `_set_pending()` cho moi trang thai truoc do. Voi hoan tien: settlement moi + refund tx, **khong** `_set_canceled()` tren tx cu (§10.8) |
| **Duong ghi `done` khong duoc kiem soat** (ban nhap thieu) | Ngoai Finality Gate con: sua tay tren UI, `sudo()` trong bridge, script migration, A4 | Guard trong `write()`: chuyen sang `done` chi hop le khi `self.env.context.get('finality_gate')` va caller la cron; moi chuyen trang thai ghi mot dong vao `blockchain.settlement.transition` (append-only, khong `unlink`); monitoring dong 12 canh bao khi co `done` khong kem transition row |
| Trap Odoo 19 | `_sql_constraints` dang list bi bo qua hoan toan ⇒ tuong co UNIQUE ma khong co ⇒ double-spend theo digest | `models.Constraint('UNIQUE(metatx_digest)', ...)` + test tich hop `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_metatx'::regclass;` |
| Trap Odoo 19 (2) | Stored computed field khong duoc nhan `default`; mot nhanh compute khong gan gi ⇒ cot `required` bi NULL ⇒ INSERT chet | Ap dung cho `lane_slot` (§04.3) va moi compute stored cua `blockchain.*`: **moi nhanh phai gan gia tri** |
| Bridge lam ro ri nguoc | `dms_blockchain_bridge` depend `dms`; mot rule cua `dms` bi loi lam hong ca `blockchain.*` | Core `dms_blockchain` **khong** depend `dms` (locked #7). Test: cai dat core tren mot DB khong co `dms` va chay full test suite |

---

### 12.7. Van hanh

#### 12.7.1. RPC noi doi (A7) va indexer bi chiem (A11) — duong mat tien lon nhat ngoai smart contract

Mot provider bi chiem tra ve mot receipt cho tx chua bao gio ton tai ⇒ Finality Gate confirm ⇒ Odoo `_set_done` ⇒ hang duoc giao. Bien phap, **bon lop** (ban nhap ghi "3 lop", §06.7 co bon):

| Lop | Kiem gi | Chu ky | Hanh dong khi lech |
|---|---|---|---|
| 1 | Liveness: `eth_blockNumber` + `head_age` | 5s | `head_lag > 3` hoac `head_age > 4×block_time` ⇒ demote |
| 2 | `blockhash(head - witness_depth)` k-of-n | 30s | Lech lan dau ⇒ `divergence_suspect`, hoi lai sau 2 block **o chieu sau moi**; van lech ⇒ **eject vinh vien** (khong auto-recover) + P1 |
| 3 | **Canary state**: cung mot `eth_call` pin theo `blockHash`, byte-identical tren moi endpoint | 60s | Lech ⇒ P1. **Day la lop duy nhat bat duoc archive node phuc vu state sai** — blockhash khop khong chung minh `eth_call` trung thuc |
| 4 | Drop im lang: sau 2 block, xac nhan tx ton tai qua **provider khac** | per-tx | Khong thay ⇒ re-broadcast qua provider khac; 3 lan ⇒ eject |

**`witness_depth` khong phai hang so 12.** `max(finality_depth, 2)` cho chain BFT, `max(finality_depth, 12)` cho chain probabilistic (§06.7.1).

**Xac nhan finality khong dem block tren Gnosis.** §11.3 chot `finality_source = 'tag'`: hoi node `eth_getBlockByNumber("finalized")`. Va sua mot con so quan trong cua note: **Gnosis 2 epoch ≈ 3–4 phut** (16 slot/epoch × 5s = 80s/epoch), **khong phai 12.8 phut**. Con so sai theo huong bat loi cho UX va cho SLA.

Yeu cau cung cho Finality Gate: **hai provider doc lap khop nhau ca `receipt` va `blockhash(receipt.blockNumber)`**, cong `tag=finalized` bao trum block do; log/topic doc tu chinh log, khong tin field da decode cua provider; sticky provider cho `getTransactionCount` (§06.7.2 quy tac 1).

**A11 (indexer) can mot lop rieng ma ban nhap khong co:** indexer la thu **ghi** `finalized`. Neu chiem duoc no thi khong can noi doi RPC nua. Ba bien phap:
- DB role rieng, `GRANT INSERT/UPDATE` chi tren 3 bang cua indexer, khong co quyen tren `blockchain.settlement`.
- Chuyen trang thai `finalized → done` do **Odoo cron** thuc hien sau khi **doc lai** receipt tu mot provider (khong tin bang cua indexer).
- Doi soat dinh ky (§15.5): tong tren chuoi vs tong trong so ke toan; lech ≠ 0 la P1.

#### 12.7.2. Oracle cho peg

Rate tu TWAP mot pool DEX mong la manipulable: voi $50k thanh khoan, mot swap $10k day gia ~20% ⇒ attacker mint them 20%. Dung `SignedRateSource` k-of-n publisher ky EIP-712, lay **median** (khong phai trung binh — trung binh bi keo boi mot outlier), `maxRateAge = 3600s`, `maxDeviationBps = 200`/lan cap nhat, va **halt mint (khong halt burn)** khi lech > 500 bps. Halt burn la giam giu tien nguoi khac; halt mint chi la ngung ban.

Reserve ratio kiem moi 5 phut, `< 100%` la P1. Va mot dieu ban nhap khong noi: **publisher key la mot khoa nong voi quyen in tien gian tiep.** No phai o enclave, xoay theo lich, va k-of-n phai co `k >= 2` ke ca trong pilot.

#### 12.7.3. Supply chain toolchain (A8)

- `forge install` theo tag la **mutable**; pin bang commit SHA trong `foundry.lock` va commit file do.
- Pin `solc_version` **chinh xac** (khong `^`), kiem checksum binary, build trong container hermetic co digest co dinh.
- Sau deploy, **doi chieu bytecode on-chain voi bytecode build lai cuc bo** (`cast code <addr>` vs `forge inspect <C> deployedBytecode`) va verify tren Sourcify. Mot buoc, chan duoc ca "compiler noi doi" lan "deploy nham branch".
- **`to_impl_codehash` phai khop `EXTCODEHASH` doc lai tu chain truoc khi `execute` timelock** (§1.11.1 muc 3). Da tung co du an upgrade nham dia chi implementation cua testnet len mainnet.
- Phia Python: `requirements.txt` hash-pinned (`--require-hashes`), khong `--extra-index-url` (chan dependency confusion).
- Phia client SDK: xem 12.3.10 — do la mot chuoi cung ung **khac**, khong duoc gop chung.
- CI runner co quyen deploy la mot muc tieu: khoa deploy khong bao gio nam trong CI secret. CI **de xuat** tx; nguoi ky.

#### 12.7.4. Thoi gian (G7)

`expiry` duoc tinh o Odoo, kiem o chain. Odoo lech dong ho 90 giay ⇒ moi Zether intent (expiry 60s) chet luc sinh, hoac song 150s ma ta tuong 60s. Bien phap: NTP bat buoc, va **`_build_metatx` lay moc thoi gian tu `block.timestamp` cua head da doc gan nhat**, khong tu `fields.Datetime.now()`. Monitoring: `abs(chain_head_timestamp - odoo_now)` > 30s la ticket.

Tren private chain, `block.timestamp` do chinh validator cua ta dat ⇒ `expiry` khong con la mot bao dam mat ma, chi la mot bao dam van hanh (A12).

#### 12.7.5. DoS chuoi nen (ban nhap khong co muc nay)

Con so quyet dinh: **17M gas/block × 17,280 block/ngay = ~294 Ggas/ngay** tren Gnosis. O 1.5 gwei va xDAI = $1, mua **100% block space cua ca Gnosis mot ngay ton ~$441** (uoc tinh, chua tinh EIP-1559 base fee tang khi block day). Thuc te base fee tang ~12.5%/block khi block day, nen mot gio phong toa ton vao khoang **$200–500** (uoc tinh, can do lai).

Nghia la: mot doi thu co dong co canh tranh co the **day chi phi va do tre giao dich cua ta len bat cu luc nao voi ngan sach vai tram do la mot gio**, va Zether cua ta tieu 1.88M gas/tx nen ta la nan nhan tu nhien. Hai bien phap:

1. **Lop uu tien gas (§06.4.4)**: R3/R4 khong bao gio bi throttle, chap nhan tra tip cao. R1/R2 dung.
2. **Duong lui sang private profile** cho B2B — day la mot ly do dinh luong nua cho quyet dinh khoa #5, ngoai block space (§04.10).

---

### 12.8. Ke hoach kiem toan

| Phase | Pham vi | Ai lam | Thoi luong | Uoc tinh chi phi | Gate |
|---|---|---|---|---|---|
| A | Slither + `slither-check-upgradeability`, Halmos tren `MetaTxLib`/`Bn254`/`PegController`, Echidna + `forge` invariant 50k run, `validateUpgrade` | Noi bo | CI, moi PR | 0 | Fail = fail build |
| B | **Mat ma hoc**: transcript, Bulletproof verifier, sigma protocol, **sinh nonce/randomness (12.3.1)**, bien the *owner-exclusive rollover* (day la thay doi tang giao thuc, **khong** duoc quyet bang suy luan trong tai lieu) | Hang chuyen ZK (ZKSecurity / Least Authority / Veridise / ABDK) | 3–4 tuan | **$60k–120k** | Khong deploy co gia tri that neu chua dong |
| **B2** | **Precompile Go + consensus integration** cho private chain (12.1.1) | Hang co nang luc Go + crypto | 2 tuan | **$30k–60k** | Chi bat buoc khi bat private profile |
| C | Factory, proxy, token, peg, registry, forwarder, batcher, `WithdrawLimiter` | Hang audit EVM tuyen 1–2 | 2–3 tuan | **$40k–80k** | Nhu tren |
| C2 | Certora tren `MetaTxForwarder` + `WrappedToken` (§14.9) | Certora / noi bo co license | 1–2 tuan | $15k–30k | Truoc mainnet co tien that |
| D | Hub relayer, Odoo control plane, RPC gateway, custody + **enclave attestation chain** | Pentest | 2 tuan | $20k–40k | Truoc go-live |
| D2 | **Client SDK + supply chain** (12.3.10) | Cung don vi D | 3–5 ngay | $8k–15k | Truoc khi phat hanh SDK |
| E | Re-audit | Bat ky thay doi nao cham vao: verifier, transcript, storage layout, ngu nghia `mode`, sinh nonce, hoac them chain adapter | Cung hang phase B/C | 3–5 ngay/lan | Bat buoc |

**Tong ngan sach chuong trinh: $173k–345k** cho lan dau (khong ke bounty float), cong ~$15k/nam cho re-audit dinh ky. Ban nhap ghi $120k–240k vi thieu B2, C2, D2.

Bon quy tac quy trinh ma ban nhap khong co, va thieu chung thi con so tren la tien vut:

1. **B truoc C.** Mot loi tang giao thuc lam vo hieu ket qua audit contract.
2. **Scope freeze.** Commit SHA duoc audit phai duoc dong bang. Moi commit sau do vao pham vi audit di vao **danh sach delta** va phai duoc reviewer xac nhan lai bang van ban. Khong co "sua nho sau audit".
3. **"Dong" nghia la** moi finding Critical/High da fix **va** duoc chinh reviewer xac nhan lai bang van ban. Remediation retest phai nam trong hop dong, khong phai mua them.
4. **Ai so huu fix nao, SLA bao lau**: Critical 48h, High 5 ngay, Medium 30 ngay, Low vao backlog co ngay. Mot finding qua han la mot muc trong risk register, khong phai mot dong Slack.

Va mot dieu can noi thang: **audit khong thay the duoc `WithdrawLimiter`.** Moi he thong bi hack deu da tung duoc audit. Ngan sach $250k cho audit ma khong co tran rut on-chain la phan bo sai.

### 12.9. Bug bounty

**Khong mo bounty truoc khi Phase B + C dong** — mo som la thue nguoi ngoai lam viec ma audit se lam, chat luong thap hon va lo som hon. Bat dau tren testnet (ca public lan private profile) voi state giong production, 3 thang truoc go-live.

| Muc | Vi du | Thuong |
|---|---|---|
| Critical | Proof forgery, mint trai phep, rut khoi vault khong co proof, **trich duoc `x` tu prover/SDK**, bypass Finality Gate lam `_set_done` sai, chiem admin/upgrade | 10% so tien co the mat, **tran $250,000**, san $25,000 |
| High | Khoa vinh vien tien nguoi khac, an cap phi relayer o quy mo, doi `recipient`/`feeRecipient`, bypass `WithdrawLimiter` | $10,000 |
| Medium | Griefing lam relayer lo, DoS verifier, ro ri so tien bi mat, ro ri cross-tenant trong Odoo | $2,500 |
| Low / Info | Thieu event, sai NatSpec | $250 / ghi nhan |

Vi tri cu the (ban nhap chi co mot dong "safe harbour"):

- **Nen tang**: Immunefi cho contract (no la noi nguoi san contract o), **self-hosted** cho Odoo/hub (khong muon lo topology noi bo len mot marketplace cong khai).
- **Primacy of impact**: tra theo tac dong chung minh duoc, khong theo nhan cua ta ve muc do.
- **PoC bat buoc** tren fork hoac testnet cua ta. **Cam tuyet doi test tren mainnet co gia tri that**; vi pham = mat quyen nhan thuong va co the bi truy cuu.
- **Safe harbour** viet ro: khong kien, khong bao cong an, mien tru CFAA/luat tuong duong, voi dieu kien tuan thu scope va khong exfiltrate du lieu nguoi dung.
- **Triage 72h**, phan hoi trang thai moi 7 ngay, thanh toan trong 30 ngay sau khi xac nhan.
- **KYC cho payout > $10,000** va sang loc danh sach cam van — bat buoc voi mot to chuc Viet Nam co nghia vu AML (§13). Noi truoc, khong noi luc tra tien.
- **Duplicate**: bao cao dau tien co PoC hop le duoc tra. Khong tra cho van de da nam trong bao cao audit **da cong bo**.
- **Loai tru**: hub availability, gia token, loi cua chain nen, social engineering nhan vien, DoS thuan tuy khong co lo hong logic.
- **Ngan sach float**: giu san **$300,000** thanh khoan (tran $250k + du phong). Mot bounty khong tra duoc la mot bounty tra bang danh tieng.

### 12.10. Ung pho su co va duong pause on-chain

```
GUARDIAN (1-of-5 ky su truc, KHONG timelock)  -> pause()   : dung deposit, transferConfidential, mint
   |  tu het hieu luc sau 7 ngay (MAX_PAUSE), redeem/withdraw tu mo lai
   |
   +-- Safe 4-of-7 (GUARDIAN + board), KHONG timelock -> WIND_DOWN  [MOT CHIEU]
           : mint tat vinh vien, reserve chuyen sang RecoveryVault (code khac)

TimelockController 48h (proposer Safe 4-of-7, executor mo) -> upgrade() / unpause()
```

**Sua so voi ban nhap:** ban nhap ghi "Guardian 2-of-3" va "Governance 3-of-5"; §1.11 (chu so huu cua quan tri token) chot **GUARDIAN 1-of-5** (tuc thi, chi `pause` va `deprecatePrototype`, tu het hieu luc 7 ngay), **DEFAULT_ADMIN Safe 4-of-7**, **PROTOTYPE_ADMIN 3-of-5**, **RECOVERY 6-of-7 timelock 30 ngay**. Hai ban so khong khop nhau la mot bug tai lieu; **lay §1.11 lam nguon su that** va sua o day.

`pause()` **khong duoc chan `withdraw`**. Neu pause khoa luon duong rut, thi chinh cai pause la vu tan cong: ai chiem duoc guardian se dong bang tien cua khach. Thay vao do `withdraw` van mo nhung di qua `WithdrawLimiter` (tran theo tai khoan/gio va tran toan cuc/gio). Chi `WIND_DOWN` — 4-of-7, mot chieu, phat event kem ly do — moi duoc dung han duong mint, va no khong dung `withdraw` ma **chuyen** no sang `RecoveryVault`.

Va mot cau tra loi ban nhap khong co: **neu chinh `withdraw` la ham co bug thi sao?** Tu dong mo lai sau 7 ngay la mo lai lo hong. Loi thoat duy nhat la `WIND_DOWN` (§1.10.1): ban khong duoc keo dai pause; ban chi duoc **tu bo token va tra tien qua mot duong khac**. Do la mot lua chon dat, va no dung phai dat.

Runbook (dong ho bat dau tu alert dau tien):

| T | Hanh dong | Ai |
|---|---|---|
| T+0 | Alert P1 (12.11) | Tu dong |
| T+1' | **Bao toan chung cu truoc khi cham vao gi**: snapshot `head`, dump mempool, snapshot DB (`pg_dump` vao bucket write-once), giu nguyen log. Khong restart service | Tu dong (script `ir-preserve.sh`) |
| T+2' | Xac nhan bang nguon thu hai (provider khac + explorer) | On-call |
| T+5' | `GUARDIAN.pause()` tren contract lien quan; dat `blockchain.chain.profile.state = 'halted'` ⇒ moi cron dung, moi `blockchain.relay.job` treo o `held` | On-call |
| T+10' | Dong bang custody: `authEpoch++` (revoke session key), rut hot wallet ve treasury, xoay credential RPC, thu hoi client cert mTLS cua worker nghi ngo | Ops + Security |
| T+15' | **Ai duoc tuyen bo su co**: on-call co quyen pause khong can hoi. Chi CEO/CTO duoc tuyen bo "breach" ra ben ngoai | Lead |
| T+15' | Thong bao noi bo + doi tac dang co giao dich treo (mau thu soan san, khong viet luc 3h sang) | Lead |
| T+30' | Danh gia phap ly: co du lieu ca nhan lien quan khong (ND 13/2023) ⇒ nghia vu thong bao. Co nghi ngo AML ⇒ nghia vu bao cao | Legal |
| T+60' | Root cause so bo, quyet dinh `WIND_DOWN` hay khong | Lead + Sec |
| T+2h | Neu private chain: quyet dinh **co rewind khong**. Day la quyet dinh cua nguoi, phai co bien ban, va phai thong bao doi tac — mot rewind im lang la mot su co thu hai | Lead + Legal |
| T+24h | Post-mortem viet, khong quy loi ca nhan, kem test hoi quy da merge | Team |

Bon luu y bat buoc, tat ca deu la bay:

1. **Job dang `held` khong duoc auto-cancel.** Mot tx da broadcast van co the len chuoi sau khi ta pause. Consumer phai giu `pending`, khong `_set_canceled`, cho den khi reconcile.
2. **`encKey` bi lo thi khong the khac phuc nguoc.** Khong co forward secrecy: attacker giai ma duoc **toan bo lich su** da ghi tren chuoi. Hanh dong duy nhat la `migrateAccount()` ngay lap tuc sang khoa moi (giam thiet hai tuong lai) va thong bao pham vi lo cho doi tac. **Phai co trong hop dong, khong chi trong runbook.**
3. **`x_audit` bi lo la mot su co lon hon `encKey` cua mot tai khoan.** No lo toan bo lich su cua **moi** tai khoan. Runbook rieng: dung ngay `C_audit` moi (doi `y_audit`), thong bao **moi** doi tac, va chap nhan rang lich su cu khong cuu duoc.
4. **Pause tren public chain lam ke thu ba mat tien.** `ZTokenOpen` co the dang lam collateral o cho khac; phat `Paused(uint64 autoUnpauseAt)` de bot cua ho doc duoc moc tu dong mo, va cong bo `MAX_PAUSE` trong tai lieu tich hop (§1.10.2).

### 12.11. Giam sat: phat hien trong vai phut, khong phai vai ngay

Nguyen tac chon chi so: **uu tien invariant co the kiem bang mot cau hoi RPC, va uu tien cai chan duoc thiet hai chu khong chi bao cao no.**

| # | Invariant / tin hieu | Tan suat | Nguong bao | MTTD ky vong |
|---|---|---|---|---|
| 1 | `WrappedToken.totalSupply() == underlying.balanceOf(vault)` | moi block | lech ≠ 0 | <= 10s |
| 2 | `zether.depositTotal - zether.withdrawTotal == underlying.balanceOf(zether)` | moi block | lech ≠ 0 | <= 10s |
| 3 | **Withdraw velocity** tong theo gio vs baseline | moi block | > 3σ hoac > `2% TVL/gio` ⇒ **auto-pause**, khong chi alert | <= 30s |
| 4 | Su kien `Upgraded(address)` / `BeaconUpgraded` tren bat ky proxy nao | realtime | bat ky, neu khong khop `blockchain.upgrade.proposal` o state `executable` | <= 15s |
| 5 | Tx bat ky tu admin/timelock/guardian address | realtime | bat ky | <= 15s |
| 6 | `AuthRotationRequested`, `successorAddr` set, `RecoveryAnnounced` | realtime | bat ky | <= 15s |
| 7 | Ty le revert cua verifier | 1' | > 1% (baseline) | <= 2' |
| 8 | RPC divergence lop 2 (`blockhash`) **va lop 3 (canary state)** | 30s / 60s | bat ky lech (sau xac nhan lan 2) ⇒ eject vinh vien + P1 | <= 60s |
| 9 | `nonce_allocated - nonce_confirmed` moi relayer; `nonce_desync` (`latest > next`) | 30s | > 20; hoac desync >= 1 ⇒ P1 + quarantine | <= 1' |
| 10 | Fee spread relayer am | 1' | am lien tuc > 10' | <= 10' |
| 11 | Peg: lech rate vs median publisher; reserve ratio | 5' | > 200 bps; < 100% | <= 5' |
| 12 | Odoo: `relay_submit_intent` theo user; user ngoai group; ghi `ir.config_parameter` key `blockchain.*`; **ghi `ir.actions.server` / `base.automation` / `ir.cron`**; `done` khong kem transition row | realtime | vuot baseline 5×; hoac bat ky voi nhom `ir.*` | <= 1' |
| 13 | `pending_event_count` cua mot `schnorrAddress` | 5' | > 500 (dau hieu flooding 12.3.6) | <= 5' |
| 14 | **Dead man's switch**: indexer da xu ly block trong N phut qua chua? worker relay-pool con heartbeat? | 60s | khong co tien do > 5 phut ⇒ P1 | <= 5' |
| 15 | **Doi chieu Safe**: `getOwners()`/`getThreshold()` moi chain vs `blockchain.governance.signer` | hang ngay | lech ⇒ incident | <= 24h |
| 16 | **Hash binary validator** (private chain) va **PCR0 cua enclave dang chay** | 5' | khac gia tri da duyet ⇒ P1 | <= 5' |
| 17 | Lech dong ho `abs(chain_head_ts - odoo_now)` | 1' | > 30s ⇒ ticket | <= 1' |

Ba dieu ve **cach** giam sat, khong phai giam sat cai gi, ma ban nhap khong noi:

- **Giam sat khong duoc chay tren ha tang no dang giam sat.** Neu Prometheus + alertmanager song cung cum Odoo thi mot ke chiem cum do tat luon canh bao. Toi thieu: alerting o mot tai khoan cloud/khu vuc khac, va mot heartbeat ra ngoai (dead man's switch #14 phai duoc mot dich vu **ben ngoai** kiem).
- **Alert phai co chu.** Nam alert page nguoi luc 3h sang (§06.8): `nonce_gap_age`, `nonce_desync`, `signed_orphan`, `rpc_divergence` (gom canary), `hot_wallet_runway < 1h`. Cong tu section nay: #3 (auto-pause, page sau khi da pause), #4, #5, #14, #16. Con lai la ticket.
- **Vang tin hieu la mot tin hieu.** Cach hong ton tai nhieu ngay nhat khong phai mot alert bi bo qua, ma la mot pipeline chet im lang. Do la ly do #14 ton tai va la ly do no phai duoc test bang cach **that su tat indexer** trong drill.

**Dong quan trong nhat cua bang nay la #3.** Proof forgery, mint trai phep, bug rounding — **tat ca deu chi bien thanh tien khi ai do `withdraw`**. Cong thuc de dat tham so:

```
thiet_hai_toi_da = cap_rate_per_hour × thoi_gian_phan_ung
Muc tieu: thiet_hai_toi_da <= 0.5% TVL, voi thoi_gian_phan_ung = 15 phut (SLA P1 den luc pause)
=> cap_rate_per_hour <= 0.5% / 0.25h = 2% TVL/gio          <-- chot 2%/gio
Kiem tra nguoc: neu phan ung mat 1 gio (dem, on-call ngu quen) => mat toi da 2% TVL.
Voi TVL pilot $2M: tran 40,000 USD/gio, thiet hai xau nhat 40,000 USD thay vi 2,000,000 USD.
Tran theo tai khoan: max(5,000 USD, 20% cua tran toan cuc) — de mot tai khoan bi chiem
khong tieu het han muc cua ca he thong.
```

Do la bien phap co ty le loi ich/chi phi cao nhat trong ca section nay (mot contract ~80 dong, ~5,000 gas/withdraw), va no phai duoc trien khai **on-chain** (`WithdrawLimiter`), khong phai trong Odoo — vi Odoo khong nam tren duong di cua mot tx truc tiep.

**Nam drill dinh ky co bien ban** (ban nhap co ba):

| Drill | Chu ky | Do cai gi |
|---|---|---|
| Blackout toan bo hub | hang thang | Thoi gian chuyen sang Enterprise Relay Pool |
| `GUARDIAN.pause()` tren staging | hang quy | T+5' co dat khong; ai bam nut khi on-call chinh nghi |
| Gia lap mot RPC noi doi | hang quy | Lop 2 va lop 3 eject dung endpoint |
| **Tat indexer khong bao truoc** | hang quy | Dead man's switch #14 co keu khong, sau bao lau |
| **Khoi phuc Shamir cua `x`** tren tai khoan thu nghiem | 6 thang | Quy trinh co chay duoc khong, ai giu share nao, share co con doc duoc khong (§02.7.5) |

### 12.12. Con phai quyet

Muoi diem con can nguoi quyet (ban nhap co bay):

1. **Do thi brand-distributor lo tren public chain** — chap nhan hay ep B2B settlement ve `chain_profile = private`. Anh huong: kien truc, chi phi van hanh chain rieng, va §13.
2. **Ai giu `y_audit`**, theo co so phap ly nao, k-of-n bang bao nhieu, xoay the nao, va ai chiu trach nhiem khi lo.
3. **Quyen freeze tren private chain thuoc vai tro nao**, co duong lenh toa an khong (`forceTransfer` co su chung kien cua N validator, §1.10.3).
4. **`WITHDRAW_CAP_PER_HOUR`** — de xuat 2% TVL/gio voi co so o 12.11; can nguoi chap nhan rang thiet hai xau nhat la 2% TVL.
5. **Compliance co chap nhan relayer hot key trong enclave** (thay vi HSM L3) de doi tu 10–30 len 10^4 sign/s khong. Neu khong, tran he thong la ~10–30 tx/s va **batch executor tro thanh bat buoc**, khong phai toi uu.
6. **Ngan sach $173k–345k** cho toan bo chuong trinh audit (gom B2 precompile Go, C2 Certora, D2 SDK) co duoc duyet truoc go-live khong, hay ship thiet ke epoch goc truoc de tranh audit Phase B cho bien the.
7. **`base.group_system` co nam trong bien tin cay khong** — hien tai **co**, va 12.6.1 chi ra rang do dong nghia voi RCE. Neu khong chap nhan duoc thi phai giam so nguoi co group nay xuong con 1–2 va them break-glass.
8. **Bounty float $300,000** co duoc phong toa khong, va ai la ben tra (issuer hay platform).
9. **Duong cong cua ElGamal: BN254 G1 hay Baby Jubjub.** §03.3.9 khuyen nghi dut khoat Baby Jubjub **ngay tu dau** vi do la dieu kien can de giu duong Groth16 ma khong phai migrate (migrate = lo toan bo so du). Day la quyet dinh **khong sua duoc sau khi deploy contract dau tien** va no la quyet dinh bao mat, khong chi hieu nang.
10. **Chinh sach rewind tren private chain**: ta co quyen ky thuat de rewind. Co duoc phep khong, ai duyet, va co phai thong bao doi tac khong. Neu khong tra loi truoc, cau tra loi se duoc dua ra luc 3h sang boi mot nguoi dang hoang.

### 12.13. Rui ro ton du — cai khong co bien phap, va phai ky nhan

Mot mo hinh de doa trung thuc phai co muc nay. Bay rui ro duoi day **khong** co bien phap trong pham vi du an; chung phai duoc ghi vao ho so rui ro va co nguoi ky chap nhan.

| # | Rui ro ton du | Vi sao khong chan duoc | Neu xay ra |
|---|---|---|---|
| R1 | >1/3 stake Gnosis equivocate | Ngoai tam kiem soat | Finality bi dao ⇒ `finality_violation`, halt chain, dao but toan thu cong (§11.4) |
| R2 | BN254 chi con **~100 bit** an toan sau cac tan cong TNFS | La thuoc tinh cua duong cong | Chap nhan cho "money in motion"; voi "money at rest" dai han thi phai co ke hoach doi curve (§03.1.2) |
| R3 | **Harvest-now-decrypt-later** tren ciphertext ElGamal | Ciphertext da tren chuoi vinh vien; PQ khong cuu duoc cai da ghi | So tien cua hom nay bi giai ma khi co CRQC. Do la ly do B2B nen o private chain, noi chuoi khong cong khai (§02.6.6) |
| R4 | Mat `x` = mat vinh vien quyen chi tieu | Thuoc tinh giao thuc | Uoc **0.3–1.0%/nam** tai khoan tu quan; 10,000 outlet ⇒ 30–100 tai khoan/nam, 15–50 trieu VND/nam khoa vinh vien (§07.10). Chap nhan duoc voi loyalty, **khong** voi B2B |
| R5 | Khong tich thu duoc (seizure) tren public chain | Contract khong biet so du bang bao nhieu | Neu quy dinh doi seizure thi Zether public **khong dap ung duoc, cham het** (§1.10.3) |
| R6 | Luc luong (cardinality) cua do thi thanh toan la cong khai | La thiet ke anti-mixer | Doi thu biet tan suat dat hang. Phai noi voi khach hang, khong duoc giau |
| R7 | Mat 4 trong 7 khoa Safe | `RECOVERY` 6-of-7 cung khong cuu duoc | He thong chet vinh vien. Phai o ho so rui ro, khong duoc lo di (§1.11.1 muc 4) |

### 12.14. Ma tran truy vet: bien phap -> noi enforce -> test chung minh

Mot bien phap khong co test la mot y dinh. Bang nay la thu ma team dung de biet **da xong hay chua**; moi dong phai co mot file test that.

| Bien phap | Enforce o dau | Test chung minh no song |
|---|---|---|
| Transcript day du (12.3.2) | `BulletproofsVerifier.sol` + prover Rust + precompile Go | `testvectors/zether_transfer_v1.json` + >= 13 negative vector; differential 3 chieu |
| Nonce khong lap (12.3.1) | Prover (Rust/WASM) | `test_no_nonce_reuse` voi RNG bi ep hang so |
| `withdraw` bind chain (12.3.3) | Fiat-Shamir challenge | `ReplayCrossChain.t.sol`: proof hop le tren chainId A phai revert tren B |
| Fail-fast verifier (12.1) | Thu tu check trong `transferConfidential` | `VerifierFailFast.t.sol` do gas tung nhanh revert, assert < 20k |
| Gas uniformity (12.3.7 muc 4) | Verifier | `GasUniformity.t.sol`, lech < 2,000 gas |
| Digest injectivity (12.2) | `MetaTxLib` | `halmos` `check_digest_injective` |
| MODE_OPEN bo qua relayer (12.2) | `_canon()` | `halmos` `check_mode_open_ignores_relayer` |
| Khong `delegatecall` tu do (12.1) | CI grep + `ContractPrototypeRegistry` | `grep_gate.sh` + `PrototypeOnly.t.sol` |
| Storage layout khong va cham (12.1) | `validateUpgrade` | CI fail khi lech `storage-layouts/v<N-1>/` |
| `WithdrawLimiter` 2%/gio (12.11) | `WithdrawLimiter.sol` | `LimiterInvariant.t.sol`: 50k run, tong rut/gio khong bao gio > cap |
| Registry khong cache trong token (12.1) | `ZTokenBase` doc truc tiep | Freeze o block N, `transferConfidential` o N+1 phai revert |
| Signer policy (12.5.1) | `confidential-signer/policy.py` (enclave) | `test_policy_rejects_type4`, `test_policy_rejects_replay`, `test_policy_owns_nonce` |
| PCR0 pin (12.5.1) | KMS key policy | Drill: chay image khac ⇒ `kms:Decrypt` phai fail |
| Khong method public gay chu ky (12.6) | Quy uoc + test | `test_public_methods_allowlist` liet ke moi method cua `blockchain.*` |
| Cross-tenant (A9) | Rule `company_id` + `resolve()` | `test_cross_company_read`, `test_signer_rejects_foreign_ref` |
| `done` chi tu Finality Gate (12.6) | Guard trong `write()` + `settlement.transition` | `test_cannot_set_done_from_ui`, `test_done_requires_transition_row` |
| `models.Constraint` that su ton tai | Postgres | `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_metatx'::regclass;` |
| RPC canary (12.7.1) | `relay-pool` lop 3 | Drill quy: fake mot endpoint tra state cu |
| Dead man's switch (12.11 #14) | Dich vu ngoai | Drill quy: tat indexer, do thoi gian den alert |
| Bytecode khop audit (12.7.3) | Runbook deploy | `cast code` vs `forge inspect` trong script deploy, fail = abort |
