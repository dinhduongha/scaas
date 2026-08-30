## 02. Singleton Account Registry va cac so do chu ky

### 2.0. Ket luan truoc, ly luan sau

| Quyet dinh | Chon | Ly do mot dong |
|---|---|---|
| Identity | `bytes32 schnorrAddress = keccak256(abi.encode(pkX, pkY))`, chi dan xuat tu **encryption key** | Chain-independent, khong doi khi xoay auth key |
| Truyen tham so | Truyen `(pkX, pkY)` trong calldata, **KHONG truyen `bytes32 addr`** — contract tu `keccak256` | Hash 36 gas re hon 32 bytes calldata 512 gas; ban nhap truoc truyen ca hai la thua |
| Registry | 1 Singleton **non-upgradeable** cho moi Zether Token tren mot chain, co con tro `successor`, **toi da 2 the he** | Tranh proxy-governance tren component ma toan he sinh thai phu thuoc |
| Tach khoa | `encKey` (alt_bn128 G1, bat bien) **tach roi** `authKey` (pluggable scheme) | Zether math bat buoc encKey la G1; moi so do chu ky khac chi la lop uy quyen |
| **Token BAT BUOC goi `assertAuthorized`** | Khong phai tuy chon | Neu khong, lop authKey chi la trang tri: biet `x` la du chi tieu. Xem §2.4.2 — day la lo hong lon nhat cua ban nhap truoc |
| Multisig mac dinh | k-of-n ECDSA qua `ecrecover` (3,000 gas/chu ky + ~1,040 calldata) | Nham chan, re, khong crypto moi |
| Threshold Schnorr | **FROST** (t-of-n), **khong phai MuSig2** (n-of-n) | Ban nhap truoc lan hai khai niem. MuSig2 chi dung khi that su can n-of-n |
| BLS | BLS12-381 (EIP-2537) bien the **min-signature-size** (sig∈G1, pk∈G2), probe runtime | Hash-to-G1 re hon hash-to-G2 ~37k gas/verify; bn254 BLS chi private chain va chi khi khong con lua chon |
| FALCON on-chain | **Khong trien khai duoc hom nay**, nhung **khong phai vi tien** | Uoc tinh sua lai: ~0.6M–2.5M gas (ban nhap truoc noi 2M–10M, **qua cao**). Tren Gnosis do la ~$0.003. Rao can that: khong co verifier duoc audit + DoS surface, khong phai chi phi |
| PQ thuc dung neu bat buoc on-chain | **SLH-DSA-SHA2-128s** (~0.4–0.8M gas, dung precompile SHA-256 0x02) | Ban nhap truoc bo qua hoan toan. Hash-only, khong can NTT, khong can SHAKE trong Solidity |
| PQ mac dinh | Commitment on-chain + verify off-chain; native precompile tren **private chain** truoc | Dung quyet dinh khoa so 5 |
| Cross-chain | Dang ky **per-chain** (re, khong trust), trang thai freeze/revoke **attestation k-of-n ECDSA** | 32 bytes state monotonic khong dang danh doi mot bridge |
| Custody cua `encKey` | **Khong the nam trong HSM FIPS 140-2 L3 tieu chuan** — alt_bn128 khong duoc ho tro | Xem §2.4.4. Day la mau thuan truc tiep voi `blockchain.md` §10.3.1 va phai giai quyet o cap hop dong |
| Khong xay | Bridge (CCIP/LayerZero), upgradeable registry, global admin freeze tren public chain, point compression | YAGNI + vector tap trung hoa |

**Nhung gi ban nhap truoc noi sai va da sua o ban nay** (chi tiet o tung muc):

| # | Ban nhap truoc | Sua |
|---|---|---|
| 1 | Pack `status` vao 2 bit cao cua `pkY` | **Chi con 2 bit tu do** (`p` = 254 bit) nhung co **5 trang thai** → khong vua. Chuyen sang slot `meta` rieng (§2.1.4) |
| 2 | Truyen ca `addr` lan `(pkX, pkY)` | Thua 512 gas/tham so. Chi truyen point, dan xuat addr on-chain (§2.1.3) |
| 3 | "Hash identity dat hon ~9,500 gas" | Quy sai nguyen nhan: phan lon 9,500 gas do la **chi phi tra cuu registry**, phai tra du dinh danh la gi (§2.1.2) |
| 4 | `MUSIG2` cho MPC threshold | MuSig2 la n-of-n. MPC t-of-n la **FROST** (§2.4.3) |
| 5 | BLS12-381 verify ~150,000 gas voi 1× `MAP_FP2_TO_G2` | hash_to_curve can **2×** map + 1 add. Bien the min-pubkey ~155k; bien the **min-sig ~118k** — nen chon bien the min-sig (§2.5.2) |
| 6 | FALCON verify 2M–10M gas | Dem lai thao tac: ~0.6M–2.5M. Ket luan khong doi nhung **ly do doi** (§2.6.3) |
| 7 | `REVOKED` chan ca inflow | Mau thuan voi chinh ly le da dung de bien minh cho `FROZEN` cho inflow. **Moi trang thai deu cho inflow** (§2.7.3) |
| 8 | `cancelAuthRotation` boi guardian | Guardian doc hai huy vinh vien moi lan xoay = DoS. Can co duong ep buoc (§2.7.1) |
| 9 | "EIP-7623 khong bao gio binh" | Binh khi `execution_gas < 24 × non_zero_bytes`. Voi chu ky PQ 7,856 bytes nguong la 188,544 gas — **binh that** (§2.1.1, §2.6.4) |
| 10 | Khong noi gi ve non-EVM | TON la actor model bat dong bo → **khong the goi registry dong bo**; toan bo mo hinh `require(isRegistered)` sup do (§2.9) |

---

### 2.1. Dinh danh `bytes32` bang hash: duoc gi, mat gi

Note goc (`blockchain.md` §10.5.3, Nguyen Tac 1) khang dinh hash identity "toi uu hoa calldata **va chi phi gas luu tru on-chain**". Ve calldata thi dung; ve tong gas thi **sai dau**, va can noi ro vi no doi lai kien truc.

#### 2.1.1. Tinh toan calldata (va khi nao EIP-7623 that su binh)

Post-EIP-2028: 16 gas/non-zero byte, 4 gas/zero byte. Truyen `(pkX, pkY)` truc tiep = 64 bytes thay vi 32 bytes → chenh toi da 32 × 16 = **512 gas/tham so**. Mot `transferConfidential` co 2 tham so (`from`, `to`) → **~1,024 gas**.

Ban nhap truoc noi "EIP-7623 khong bao gio binh". **Sai** — no binh theo mot cong thuc cu the, va cong thuc do quan trong o §2.6. EIP-7623 (Pectra, 2025-05-07):

```
tokens        = zero_bytes × 1 + non_zero_bytes × 4
cost_standard = 21_000 + 4 × tokens + execution_gas
cost_floor    = 21_000 + 10 × tokens
tx_cost       = max(cost_standard, cost_floor)

=> floor BINH khi:  execution_gas < 6 × tokens = 24 × non_zero_bytes (bo qua zero byte)
```

| Payload | non-zero bytes | Nguong `execution_gas` de floor binh |
|---|---|---|
| 2 G1 point (128 B) | 128 | 3,072 |
| `register()` calldata (~200 B) | 200 | 4,800 |
| Chu ky FALCON-512 (666 B) | 666 | 15,984 |
| Chu ky ML-DSA-65 (3,309 B) | 3,309 | 79,416 |
| Chu ky SLH-DSA-128s (7,856 B) | 7,856 | **188,544** |

Voi giao dich Zether (~200k–250k gas execution) floor khong binh → giu 16 gas/byte. Voi mot giao dich **chi neo commitment PQ** (execution ~30k) va chu ky PQ lon, floor **binh** va chi phi calldata thuc te la **40 gas/byte**, khong phai 16. Ghi con so nay vao bang chi phi cua §2.6.

#### 2.1.2. Tinh toan chi phi doc lai — va quy dung nguyen nhan

Zether **bat buoc** can diem `y` that (khong phai hash) de kiem tra sigma protocol: ciphertext `(C, D) = (g^v · y^s, g^s)` chi verify duoc khi contract co `y` duoi dang G1 point de dua vao `ecMul`. Voi hash identity thuan tuy (registry giu point, token doc ve):

| Thao tac | Gas |
|---|---|
| `CALL` sang registry, lan dau (cold account access, EIP-2929) | 2,600 |
| 2 × cold `SLOAD` cho `(pkX, pkY)` cua `from` | 4,200 |
| 2 × cold `SLOAD` cho `(pkX, pkY)` cua `to` | 4,200 |
| `CALL` thu hai (warm account) neu khong gop | 100 |
| Calldata/return/memory overhead cua external call | ~600 |
| **Tong** | **~11,700 gas** |

Ban nhap truoc ket luan "hash identity dat hon ~9,500 gas/transfer". **Quy sai nguyen nhan.** Tach ra:

| Thanh phan | Gas | Co tranh duoc khong? |
|---|---|---|
| Tra cuu **trang thai** tai khoan (registered? frozen?) | ~2,600 + 2 × 2,100 = 6,800 | **Khong.** Bat ky registry nao cung tra, du dinh danh la hash hay la point. Note goc bat buoc `require(registry.isRegistered(from) && registry.isRegistered(to))` |
| Doc **point** tu storage thay vi calldata | +4,200 | **Co** — bang cach truyen point trong calldata |
| Tiet kiem calldata do dung hash | −1,024 | — |
| **Chi phi rong that su cua hash identity** | **+3,176** | Khong phai 9,500 |

Nghia la: 6,800 gas trong con so 9,500 la **gia cua mo hinh Shared Registry**, khong phai gia cua hash identity. Neu ai do doc ban nhap truoc va ket luan "bo hash identity di, tiet kiem 9,500 gas" thi ho se that vong: bo hash identity chi tiet kiem 3,176 gas, va lam mat tinh chain-independent (§2.1.6, diem 4).

#### 2.1.3. Giai phap: **khong truyen `addr`**, dan xuat on-chain

Ban nhap truoc de xuat "caller truyen ca hai: `bytes32 addr` va `(pkX, pkY)`". Thua. `keccak256(abi.encode(pkX, pkY))` ton **30 + 6×2 = 42 gas** (KECCAK256 = 30 + 6/word); truyen them 32 bytes ton **512 gas**. Chi truyen point:

```solidity
function transferConfidential(
    uint256 fromPkX, uint256 fromPkY,
    uint256 toPkX,   uint256 toPkY,
    EncryptedTransfer calldata data,
    bytes calldata authSig
) external returns (bool);
// addr duoc dan xuat: bytes32 from = keccak256(abi.encode(fromPkX, fromPkY));
```

Chi phi hot path sau khi sua:

| Thao tac | Gas |
|---|---|
| Calldata 4 × 32 bytes cho 2 point | 2,048 |
| 2 × `keccak256` dan xuat addr | 84 |
| 1 × `CALL` gop sang registry (`assertUsable(from, to)`) | 2,600 |
| 2 × cold `SLOAD` slot `meta` (1 slot/account) | 4,200 |
| Overhead call | ~400 |
| **Tong** | **~9,300 gas** |

So voi 11,700 cua thiet ke doc-point-tu-storage: tiet kiem **~2,400 gas/transfer**. Tren Gnosis @2 gwei ≈ $0.0000048/tx — khong dang ke; tren Ethereum L1 @10 gwei/ETH $3,000 ≈ $0.072/tx — dang ke o quy mo 10^5 tx/thang ($7,200/nam). **Uoc tinh, co so: bang gia EIP-2929 / EIP-2028 / EIP-1108.**

**Ham gop `assertUsable` (mot CALL cho ca hai tai khoan)** — ban nhap truoc de hai lan goi:

```solidity
/// @notice Kiem tra ca hai tai khoan trong MOT call. Revert voi ly do phan biet duoc.
/// @dev Khong revert khi tai khoan `to` o trang thai FROZEN/REVOKED: moi trang thai deu nhan duoc (§2.7.3).
function assertUsable(bytes32 from, bytes32 to) external view;
```

#### 2.1.4. Bo tri slot — **sua mot bug that trong ban nhap truoc**

Ban nhap truoc de xuat pack `status` vao 2 bit cao cua `pkY` vi `p < 2^254`. Kiem chung:

```
p     = 21888242871839275222246405745257275088696311157297823662689037894645226208583
p.bit_length() = 254  =>  chi con 2 bit tu do (bit 254, 255)  =>  toi da 4 gia tri
```

Nhung §2.7 cua chinh ban nhap truoc dinh nghia **5 trang thai** (`NONE, ACTIVE, FROZEN, REVOKED, MIGRATED`). **Khong vua.** Va ngay ca khi vua, moi lan doc status phai `AND` mask roi shift, va moi lan ghi status phai doc-sua-ghi ca `pkY` — nguy hiem.

Bo tri dung: gop toan bo metadata **nong** vao mot slot rieng, de hot path chi cham `pkX`/`pkY` khi that su can (ma sau §2.1.3 thi khong bao gio can):

```solidity
// 4 slot / account. Hot path chi doc slot 2.
struct Account {
    uint256 pkX;          // slot 0 — encKey.x, BAT BIEN suot doi tai khoan
    uint256 pkY;          // slot 1 — encKey.y, BAT BIEN
    uint256 meta;         // slot 2 — packed, xem duoi. 240/256 bit dung.
    bytes32 authKeyHash;  // slot 3 — 0 neu authScheme == SELF_SCHNORR
}
// meta layout (little-end -> big-end):
//   [  0.. 7]  uint8   status        NONE|ACTIVE|FROZEN|REVOKED|MIGRATED   (con cho 251 gia tri)
//   [  8..15]  uint8   authScheme
//   [ 16..79]  uint64  authEpoch
//   [ 80..239] address verifier
//   [240..255] uint16  reserved       (khong dung; giu de mo rong khong doi layout)
mapping(bytes32 => Account) internal _accounts;
```

Kiem chung do rong: `8 + 8 + 64 + 160 = 240 ≤ 256`. Con 16 bit du tru.

Hau qua chi phi:

| Thao tac | Truoc (pack vao pkY) | Sau (slot `meta`) |
|---|---|---|
| Doc status | 1 cold SLOAD + mask/shift ≈ 2,110 | 1 cold SLOAD + mask ≈ 2,105 |
| Ghi status (freeze) | SLOAD 2,100 + SSTORE-dirty 2,900 = 5,000, **rui ro hong `pkY`** | SLOAD 2,100 + SSTORE-dirty 2,900 = 5,000, khong cham `pkY` |
| `register()` SSTORE | 2 slot × 22,100 | 3 slot × 22,100 = 66,300 (`authKeyHash` = 0 khong ghi) |

`register()` dat hon 22,100 gas so voi ban nhap truoc, va bang gas cua §2.2 duoc sua theo.

#### 2.1.5. Nen dung point compression khong? **Khong** — va day la con so

`p ≡ 3 (mod 4)` nen `sqrt(a) = a^((p+1)/4)`, tinh duoc bang precompile `MODEXP` (0x05). Truyen `pkX` + 1 bit parity thay vi `(pkX, pkY)`:

| | Gas |
|---|---|
| Tiet kiem calldata (32 bytes) | −512 |
| `MODEXP` 32/32/32 byte (EIP-2565) | +~1,360 |
| `mulmod` kiem tra + chon nhanh parity | +~50 |
| **Rong** | **+898 gas — dat hon** |

**Quyet dinh: khong nen. Luon truyen `(pkX, pkY)` khong nen.** Ghi vao doc de khong ai "toi uu" lai.

#### 2.1.6. Cai that su mat khi bo (x, y) khoi dinh danh

1. **Khong the gui cho nguoi chua dang ky.** Tren Ethereum ban gui duoc cho bat ky 20 bytes nao. O day `transferConfidential(...)` phai `revert` neu `to` chua dang ky, vi khong co `y_to` de mã hóa. He qua nghiep vu: **onboarding la buoc bat buoc truoc khi nhan tien** — brand khong the settle cho mot distributor moi cho den khi distributor do `register()`. Phai co luong "invite + gasless register" (§2.3d) va, quan trong hon, **giao dien Odoo phai chan tu truoc** chu khong de revert on-chain: mot `dms.trade.settlement` chi duoc phep confirm khi moi payee co `blockchain.zether.account` o trang thai `active` tren dung chain. Tinh than "quet QR khong phai la da thu tien": chan o tang gan nguoi dung, chain la lop cuoi.
2. **Khong verify offline duoc.** Auditor cam mot event log khong the tu kiem chung minh neu khong co state cua registry tai block do. Bat buoc: indexer luu snapshot `(schnorrAddress → pkX, pkY, blockNumber)` va gan hash snapshot vao `ir.attachment` tren S3/Garage. **Sau khi ap dung §2.1.3, van de nay tu bien mat mot phan**: `(pkX, pkY)` nam ngay trong calldata cua tx nen log + tx la du de tai lap; snapshot chi con can cho `status`/`authEpoch`.
3. **Khong co checksum kieu EIP-55.** Go nham 1 ky tu → mot `bytes32` hop le ve cu phap. Nhung **registry lai la bo loc go nham**: 32 bytes ngau nhien gan chac chan chua dang ky → `revert`. Day la thuoc tinh an toan **tot hon** dia chi EOA, phai ghi vao tai lieu van hanh. (Xac suat trung mot tai khoan da dang ky voi 10^6 tai khoan: 10^6 / 2^256 ≈ 10^{-71}.)
4. **Loi ich mien phi:** `keccak256` khong phu thuoc chain → cung `(pkX, pkY)` cho **cung mot `schnorrAddress` tren moi EVM chain**. Lop identity da giai quyet xong cho cross-chain; chi con lop *trang thai* (§2.8).
5. **Chi phi an: xung dot khong gian ten voi EIP-1271 / smart account.** `bytes32` khong phai `address`, nen khong the dung truc tiep lam `msg.sender` hay lam owner. Moi lien ket `bytes32 ↔ address` deu phai di qua `authKeyHash` (§2.4). Chap nhan; nhung nghia la **khong the tai su dung thu vien access-control cua OpenZeppelin** — tat ca phai viet tay va do la be mat bug.

#### 2.1.7. Ba loi cu the trong interface cua note, phai sua truoc khi code

| Van de | Sua |
|---|---|
| `struct SchnorrPublicKey { bytes32 x; bytes32 y; }` — trong chinh tai lieu nay `x` la **private key** va `y` la **public key point**. Truong `y` o day lai la *toa do y*. Se sinh bug. | Doi ten `pkX`, `pkY`. Cam dung ky tu `x`/`y` don le trong Solidity cua du an. Them mot lint rule trong CI (`slither`/`solhint` custom) chan bien ten `x`, `y`, `X`, `Y` o pham vi file. |
| `abi.encodePacked(x, y)` | Dung `abi.encode(pkX, pkY)`. Voi 2 `bytes32` ket qua giong nhau, nhung `encodePacked` de sinh collision khi ai do them tham so dong sau nay. |
| Kieu `bytes32` cho toa do | Doi sang `uint256`. Toa do la so trong `F_p`, moi phep kiem tra deu la so hoc; `bytes32` buoc cast lien tuc va che di viec thieu range check. |
| Khong co validation ranh gioi truong | `require(pkX < P && pkY < P)` voi `P = 21888242871839275222246405745257275088696311157297823662689037894645226208583`, va `require(mulmod(pkY,pkY,P) == addmod(mulmod(mulmod(pkX,pkX,P),pkX,P), 3, P))` (on-curve `y² = x³ + 3`). Tu choi `(0,0)`. alt_bn128 G1 co cofactor = 1 nen **khong can** subgroup check tren G1 (can tren G2 — lien quan BLS, §2.5.3). |
| `getPublicKey()` tra ve `(x, y)` cho token doc | Giu lam ham view cho indexer/SDK, nhung **token khong duoc dung** (§2.1.3). Danh dau `/// @dev Off-chain use only. Do NOT call from a token hot path.` |

**Quy tac bat bien:** `schnorrAddress` dan xuat **chi tu encKey**, khong bao gio nhung scheme tag hay authKey vao hash. Neu nhung vao, xoay auth key se doi dia chi → mat toan bo so du. Ghi thanh comment `@dev INVARIANT` tren ham dan xuat **va** thanh mot Foundry invariant test (§2.10, muc 8).

---

### 2.2. Proof-of-Possession tren `register()`

Note co tham so `schnorrSignature` nhung khong dinh nghia challenge. Phai dinh nghia, vi PoP chan 4 lop tan cong khac nhau:

1. **Rogue-key (nghiem trong nhat, va la ly do that su).** Trong bat ky so do tong hop khoa nao (MuSig2, FROST, BLS), ke tan cong chon `pk_rogue = pk_victim^{-1} · g^a`. Khoa tong hop `pk_agg = pk_victim · pk_rogue = g^a` — ke tan cong ky mot minh cho ca nhom. PoP buoc no phai biet dlog cua `pk_rogue`, triet tieu tan cong. Registry **khong biet** khoa nao se duoc dung trong aggregation nao, nen PoP phai **bat buoc cho moi khoa, khong ngoai le**.
2. **Diem khong hop le / unknown-dlog.** Diem khong tren duong cong lam `ecMul` revert (DoS mem), hoac tao ciphertext khong bao gio giai ma duoc — mot tai khoan "den" nhan tien vao va khong ai rut ra duoc, ke ca chinh chu.
3. **Dang ky khoa nguoi khac (griefing).** Xem xu ly duoi.
4. **Cross-registry / cross-chain replay cua chinh PoP.**

#### 2.2.1. Challenge cu the (Schnorr tren alt_bn128 G1)

```
n = 21888242871839275222246405745257275088548364400416034343698204186575808495617   // group order
R = g^k                     (k random, tu HSM/MPC DRBG, KHONG bao gio tai su dung)
c = keccak256(abi.encode(
        "ZETHER_POP_V1",    // domain tag
        block.chainid,      // chan cross-chain replay
        address(this),      // chan cross-registry replay (ke ca giua registry v1 va v2)
        pkX, pkY,
        Rx, Ry
    )) mod n
s = k + c * sk  (mod n)
```

On-chain verify: `g^s == R + pk·c` (ky hieu cong tinh) → 2 × `ecMul` (6,000 moi cai, EIP-1108) + 1 × `ecAdd` (150) = **12,150 gas** thuan precompile. Cong overhead thuc: 3 × `staticcall` (warm precompile ~100 moi cai) + memory expansion + copy ≈ **+700** → **~12,900 gas** thuc te. Ban nhap truoc bo qua overhead nay; sai lech 6% nhung phai ghi dung vi bang uoc tinh se duoc doi chieu voi do do that (§2.10, muc 7).

`c mod n` phai lam **sau** keccak va phai kiem `c != 0`; `s < n` va `R != O` phai kiem tuong minh — mot `s ≥ n` hoac `R = O` la duong tam thuong de gia mao trong nhieu ban hien thuc cau tha.

#### 2.2.2. Quyet dinh gay tranh cai — **KHONG dua `msg.sender` vao challenge**

| | Bind `msg.sender` | Khong bind (**chon**) |
|---|---|---|
| Front-running `register()` | Ke tan cong copy PoP tu mempool, submit truoc, chiem quyen owner → **DoS that su** | Ke tan cong submit truoc → ket qua la **dung mot ban ghi giong het** (cung `(pkX,pkY)`, cung addr, cung `meta` khoi tao). Vo hai. Ke tan cong con **tra gas ho**. |
| Gasless register qua EIP-1776 | Phai them relayer allowlist hoac EIP-712 wrapper | Chay ngay, bat ky relayer nao |
| Gan owner EOA | Trong `register()` | Tach sang `setGuardians()` rieng, xac thuc bang PoP thu hai |

Vi vay: **`register()` la thao tac dang ky khoa thuan tuy, khong sinh bat ky state nao dan xuat tu `msg.sender`.** Day la dieu kien de "user khong co native gas" hoat dong ngay tu buoc dau tien — neu khong, toan bo cau chuyen Open Relayer gay o buoc 0. Note khong de cap dieu nay.

**Tinh vo hai nay la mong manh va phai co CI bao ve.** Ngay khi ai do them mot truong lay tu `msg.sender` (vi du `registrar`, `sponsor`, `guardianInit`), front-running tro thanh chiem quyen. Foundry invariant test bat buoc (§2.10, muc 2): goi `register()` voi cung PoP tu hai `msg.sender` khac nhau → so sanh **toan bo storage diff** phai giong het, khong chi so sanh `isRegistered`.

#### 2.2.3. Idempotency: `register()` tren addr da ton tai

Ban nhap truoc khong noi. Hai lua chon, phai chon:

| | No-op tra `true` | **Revert `AlreadyRegistered()`** (chon) |
|---|---|---|
| Hai relayer cung nhat mot intent | Ca hai thanh cong → ca hai doi `fee` → **issuer tra 2 lan** | Ke thu hai revert; theo EIP-1776 `fee` chi chuyen khi thuc thi thanh cong → khong mat tien |
| Relayer simulation | Khong phat hien duoc lang phi | `eth_estimateGas` revert → relayer bo intent truoc khi broadcast, khong ton gas |
| Trai nghiem SDK | Mo ho | Ro rang, va SDK doc `statusOf` truoc |

Chon revert. **Nhung** ket hop voi §2.2.2 no tao mot canh cua griefing nho: ke tan cong front-run `register()` cua nan nhan bang dung PoP do → nan nhan revert va **relayer cua nan nhan mat gas** (relayer da broadcast). Danh gia: thiet hai = 1 lan gas that bai (~24k gas ≈ $0.00005 tren Gnosis), ke tan cong tra ~82k gas de gay ra. **Kinh te nguoc dau, bo qua.** Ghi vao threat model chu khong xay bien phap.

#### 2.2.4. Chong spam / bao ve be tai tro — **thieu hoan toan trong ban nhap truoc**

`register()` mo, gasless, va duoc issuer tai tro (§2.3d). Do la mot voi tien cong khai.

| Thong so | Gia tri |
|---|---|
| Gas mot `register()` | ~105,000 (bang §2.2.5) |
| Chi phi tren Gnosis @2 gwei, xDAI $1 | **$0.00021** |
| Be tai tro $1,000 → so lan dang ky rac | **~4.76 trieu** |
| State them vao chain | 4.76M × 3 slot × 32 B = **457 MB** |

457 MB state rac tren Gnosis la mot su co van hanh cho toan mang, khong chi cho ta. Va $1,000 la mot be tai tro nho. **Bat buoc co gate.** Chon:

```solidity
// Invite-based sponsorship: issuer ky EIP-712 mot lan, registry theo doi nonce da dung.
struct RegistrationInvite {
    bytes32 inviteId;      // ngau nhien, 1 lan
    bytes32 boundTo;       // 0 = bat ky addr; khac 0 = chi addr nay
    uint64  expiry;
    uint32  maxUses;
}
mapping(bytes32 => uint32) public inviteUses;   // inviteId -> so lan da dung
```

Gate nay **khong** nam trong `register()` (giu `register()` thuan tuy theo §2.2.2) ma nam trong **`IRegistrationPolicy`** (§2.3c) — `OpenRegistrationPolicy` la no-op cho public chain khong tai tro, `InviteRegistrationPolicy` cho luong onboarding tai tro, `AttestedRegistrationPolicy` cho private chain. Chi phi them: 1 × cold SLOAD + 1 × SSTORE-dirty + 1 × `ecrecover` ≈ 2,100 + 2,900 + 3,000 = **8,000 gas**.

Lop bao ve thu hai nam o relayer/gateway chu khong o chain: **rate limit theo issuer-sponsored intent** (xem section 05/06). Mot lop on-chain + mot lop off-chain, vi lop off-chain co the bi vong qua neu ai do tu tra gas — nhung neu ho tu tra gas thi ho tu chiu chi phi va khong con la van de kinh te cua ta, chi con la van de state growth cua chain.

#### 2.2.5. Uoc tinh gas `register()` (co so: bang gia EIP-1108 + EIP-2929 + EIP-2028)

| Muc | Gas |
|---|---|
| Base tx | 21,000 |
| Calldata ~200 non-zero bytes (2 point + 2 scalar + selector) | 3,200 |
| On-curve + range check (`mulmod` × 4, `addmod`) | ~250 |
| Schnorr PoP verify (12,150 precompile + ~700 overhead) | 12,850 |
| Policy check (`OpenRegistrationPolicy` = no-op) | ~250 |
| 3 × SSTORE (0 → non-zero): `pkX`, `pkY`, `meta` | 66,300 |
| Event `AccountRegistered` (3 topic + 64 B data) | ~1,900 |
| **Tong** | **~105,750** |

Chi phi thuc:

| Chain | Gia gas | Native | USD/register |
|---|---|---|---|
| Gnosis xDAI | 2 gwei | xDAI ≈ $1 | **$0.00021** |
| Celo (L2 OP Stack, phi cUSD) | ~0.01 gwei L2 + L1 data | cUSD ≈ $1 | **~$0.0001** (uoc tinh; L1 data cost bien dong) |
| Ethereum L1 | 10 gwei | ETH $3,000 | **$3.17** |
| Private chain (Besu, gas price 0) | 0 | — | **$0** |

**Ket luan: dang ky lai tren tung chain la re den muc khong dang thiet ke bridge** (§2.8). Voi 5,000 tai khoan × 4 chain = 20,000 lan dang ky = **$4.20** tren Gnosis. Con so nay mot minh no da quyet dinh xong §2.8.

#### 2.2.6. Interface `register()` day du

```solidity
/// @notice Dang ky mot encKey moi. Khong doc msg.sender. Idempotent-fail.
/// @param pkX,pkY  Toa do encKey tren alt_bn128 G1.
/// @param popRx,popRy,popS  Chu ky Schnorr PoP theo challenge o §2.2.1.
/// @param policyAux  Du lieu cho IRegistrationPolicy (invite, attestation, hoac rong).
/// @return addr keccak256(abi.encode(pkX, pkY))
function register(
    uint256 pkX, uint256 pkY,
    uint256 popRx, uint256 popRy, uint256 popS,
    bytes calldata policyAux
) external returns (bytes32 addr);

error AlreadyRegistered(bytes32 addr);
error NotOnCurve();
error FieldOverflow();
error BadProofOfPossession();
error PolicyRejected(bytes reason);

event AccountRegistered(
    bytes32 indexed addr,
    uint256 pkX, uint256 pkY,       // KHONG indexed: indexer can gia tri, khong can filter
    uint8   indexed authScheme,
    uint64  registeredAtBlock
);
```

---

### 2.3. Singleton vs ZSC nguyen khoi cua ConsenSys

Trong `anonymous-zether`, `ZSC.sol` gop token + registry: `register(G1Point y, uint c, uint s)` nam ngay trong contract token. N token → N lan dang ky, N ban sao khoa. Singleton sua dung van de. Nhung no **de lai 6 hau qua ma note khong xu ly**:

**(a) Single point of failure ve governance.** Moi token phu thuoc mot contract. Neu registry la UUPS proxy (note §10.2.1 bat buoc UUPS cho *moi* contract), thi mot admin key duy nhat co the doi `getPublicKey()` → doi `y` cua nan nhan → moi khoan tien chuyen den sau do bi mã hóa duoi khoa ke tan cong, **va nan nhan khong the phat hien tu client cua minh** vi ho van thay giao dich thanh cong. Day la vu trom hoan hao. **Quyet dinh: registry KHONG upgradeable.** Ngoai le duy nhat cho quy tac UUPS cua note, va phai ghi ro trong `blockchain.md` khi cap nhat. Migration bang con tro the he:

```solidity
address public immutable predecessor;   // 0 neu la v1
address public successor;               // set 1 lan, boi governance timelock 30 ngay
uint8   public immutable generation;    // v1 = 1; require(generation <= 2)

function resolve(bytes32 addr) external view returns (Account memory);
// resolve() doc local truoc; neu status == NONE va predecessor != 0 -> doc predecessor.
```

**Gioi han 2 the he, cung.** Ban nhap truoc khong dat gioi han. Chi phi moi hop fallback = 2,600 (cold CALL) + 2,100 (cold SLOAD) + overhead ≈ **5,000 gas**. Voi 4 the he, hot path them 15,000 gas va tro thanh khong xac dinh (phu thuoc tai khoan dang ky doi nao). `require(generation <= 2)` trong constructor; truoc khi deploy v3, phai chay **migration sweep**: mot ham `bulkImport(bytes32[] addrs)` permissionless doc tu predecessor va ghi vao local (chi phi ~25,000 gas/account, 5,000 account = 125M gas ≈ $0.25 tren Gnosis). Sau sweep, set `predecessor = 0` khong duoc (immutable) — thay vao do dat co `sweepComplete` de `resolve()` bo qua fallback.

**(b) Linkability chéo token.** Mot `schnorrAddress` dung cho Z-USDC + Z-VND + Z-Loyalty → moi hoat dong cua phap nhan do lien ket duoc. Voi triet ly "lo danh tinh, an so tien" thi day la **chap nhan duoc theo thiet ke**, nhung phai co loi thoat: registry **khong duoc** ep 1 khoa/phap nhan. Mot legal entity dang ky N `schnorrAddress` cho N muc dich (treasury, payroll, loyalty, settlement voi tung distributor). Mapping entity → tap dia chi nam **off-chain trong Odoo**, khong len chain.

Con so de dinh lieu: neu mot brand co 200 distributor va muon mot dia chi settlement rieng cho tung distributor, do la 200 lan `register()` = **$0.042** tren Gnosis. Chi phi khong phai rao can; **quan ly khoa la rao can** — 200 encKey nghia la 200 lan backup Shamir (§2.7.5). Khuyen nghi thuc te: **1 dia chi/muc dich (4–6 dia chi/phap nhan), khong phai 1 dia chi/doi tac.** Linkability giua cac giao dich cung muc dich la chap nhan duoc; so tien van an.

**(c) Truc chain profile (locked #5) song hanh voi truc chain adapter.** `register()` tren public chain la mo; tren private/permissioned chain phai qua KYC attestor. Mot interface, ba implementation — day la truong hop hiem ma abstraction xung dang:

```
smartcontracts/evm/registry/src/policy/IRegistrationPolicy.sol
    function check(bytes32 addr, uint256 pkX, uint256 pkY, bytes calldata aux) external;
    // KHONG phai `view`: InviteRegistrationPolicy ghi inviteUses.
smartcontracts/evm/registry/src/policy/OpenRegistrationPolicy.sol      // no-op, public chain khong tai tro
smartcontracts/evm/registry/src/policy/InviteRegistrationPolicy.sol    // §2.2.4, public chain co tai tro
smartcontracts/evm/registry/src/policy/AttestedRegistrationPolicy.sol  // EIP-712 sig cua KYC attestor, private chain
```

`policy` la `immutable` trong registry — doi policy = deploy registry moi. Khong co setter. (Ban nhap truoc de `check` la `view`; sai, invite policy phai ghi state.)

**(d) Gasless registration.** Vi `register()` khong dung `msg.sender` (§2.2.2), no chay tu nhien qua EIP-1776: `metaTx.to = registry`, `metaTx.amount = 0`, `metaTx.fee = phi token`, `metaTx.data = abi.encodeCall(register, ...)`. Nhung buoc dau tien nguoi dung **chua co token** de tra `fee` → phai co `mode` sponsorship: issuer tra. Ghi ro trong section relayer: **onboarding luon la subsidized intent, khong bao gio la open-market intent.**

He qua ma ban nhap truoc khong noi: mot intent subsidized khong co `fee` on-chain → **relayer thi truong tu do khong co dong co xu ly no**. Chi relayer cua issuer (hoac relayer co hop dong rebate off-chain) moi nhat. Nghia la **luong onboarding phu thuoc vao relayer pool noi bo cua issuer**, va do la mot SPOF nghiep vu: neu relayer pool cua issuer chet, khong ai onboard duoc, ke ca khi mang blockchain hoan toan khoe. SLO phai ghi rieng cho luong nay (dich: 99.5%, RTO 15 phut) — chi tiet o section 06.

**(e) Registry la dependency cung cua moi token → SLO cua no la SLO cua toan he thong.** Neu registry deploy sai (vi du policy sai), khong sua duoc (non-upgradeable), va moi token da deploy tro toi dia chi do. Bat buoc: token luu `registry` la `immutable` nhung co ham `registryOf()` doc qua mot **`RegistryPointer`** cuc nho, chi co mot bien va mot timelock 30 ngay? **Khong** — do la dua proxy vao bang cua sau. Chon thay the: token luu `registry` `immutable`, va **quy trinh deploy bat buoc**: registry len testnet → chay full test suite → deploy len mainnet → **cho 7 ngay va chay mot token thu nghiem** → moi deploy token that. Ghi vao runbook, khong ghi vao code.

**(f) Registry khong duoc giu tien.** Kiem tra: registry khong co `receive()`, khong co `payable`, khong co `transfer` token nao. Neu no khong bao gio giu gia tri, mot bug trong no khong the bi khai thac de rut tien truc tiep — chi de gia mao trang thai. Do la mot bac giam thiet hai dang ke va phai la mot invariant test.

---

### 2.4. Tach `encKey` khoi `authKey` — nen mong cho moi so do chu ky

Day la diem kien truc quan trong nhat cua section nay, va note khong co.

#### 2.4.1. Tai sao bat buoc tach

**Zether bat buoc `encKey` la diem alt_bn128 G1 `y = g^x`.** Khong the thay bang FALCON key, BLS key, hay ECDSA key: ElGamal mã hóa *toi* `y`, va sigma protocol chung minh *biet* `x`. Moi de xuat "registry ho tro FALCON" ma khong tach hai khoa deu se dam vao tuong nay.

```solidity
// Xem bo tri slot o §2.1.4. Doc/ghi qua getter/setter, khong cham raw.
enum AuthScheme {
    SELF_SCHNORR,        // 0 — ZK proof cua Zether CHINH LA uy quyen
    ECDSA_MULTISIG,      // 1
    FROST_BN254,         // 2 — threshold Schnorr t-of-n (KHONG phai MuSig2)
    MUSIG2_BN254,        // 3 — n-of-n
    BLS_BN254,           // 4 — chi private chain
    BLS_12381,           // 5 — neu chain co EIP-2537
    PQ_COMMITMENT,       // 6 — verify off-chain
    SMART_ACCOUNT_1271   // 7
}
```

```solidity
interface ISignatureVerifier {
    /// @return magic 0x1626ba7e neu hop le (tuong thich EIP-1271)
    /// @dev PHAI la view. PHAI khong reentrancy. PHAI hoan tat trong GAS_CAP_VERIFY.
    function verify(bytes32 addr, bytes32 authKeyHash, bytes32 digest, bytes calldata sig)
        external view returns (bytes4 magic);
}
```

#### 2.4.2. **Lo hong lon nhat cua ban nhap truoc: khong ai bat buoc goi `assertAuthorized`**

Ban nhap truoc viet "Token goi `registry.assertAuthorized(addr, digest, sig)`" nhu mot cau mo ta, roi khong bao gio noi:

- Digest gom nhung gi?
- Dieu gi xay ra neu token **khong** goi?
- Tai sao lop authKey khong phai la trang tri, khi ma **biet `x` la du de tao ZK proof va chi tieu**?

Cau tra loi cho cau hoi thu ba la diem then chot cua ca thiet ke, va phai duoc viet ra:

> **Bat bien an ninh #1.** `transferConfidential` va `withdraw` PHAI xac thuc **hai** thu doc lap: (i) ZK proof chung minh biet `x` (tinh dung dan cua so du), va (ii) chu ky theo `authScheme` tren mot digest bao trum toan bo giao dich (quyen chi tieu). Neu bo (ii), thi compromise `encKey` = compromise toan phan, va toan bo cot `authScheme` chi la trang tri.

He qua truc tiep, va la ly do thuong mai manh nhat cho ca §2.4: **compromise `encKey` chi lam lo so du (read-only breach), khong lam mat tien**, mien la `authScheme != SELF_SCHNORR`. Do la su khac biet giua "doi thu doc duoc bang gia cua ta" va "doi thu rut sach quy". Voi custody model trong locked #6, day cung la thu cho phep dat `encKey` o mot ranh gioi bao mat yeu hon `authKey` — xem §2.4.4, noi ma dieu do tro thanh bat buoc chu khong phai tuy chon.

**Digest phai bao trum tat ca:**

```solidity
bytes32 digest = keccak256(abi.encode(
    "ZETHER_AUTH_V1",
    block.chainid,
    address(this),          // token contract, khong phai registry
    from, to,               // ca hai schnorrAddress
    keccak256(abi.encode(data)),   // TOAN BO EncryptedTransfer, ke ca fee va feeRecipient
    authEpoch,              // doc tu registry -> xoay khoa vo hieu chu ky cu tuc thi
    deadline
));
```

Ba diem ma neu thieu se thanh lo hong:
- Thieu `keccak256(data)` → relayer doi `feeRecipient` hoac `C_fee`.
- Thieu `authEpoch` → chu ky cu con hieu luc sau khi xoay khoa; toan bo §2.7.1 vo nghia.
- Thieu `address(this)` → chu ky cho Z-USDC dung duoc tren Z-VND.

**Toi uu cho `SELF_SCHNORR`** (ban nhap truoc tinh 12,150 gas cho no — thua): khi `authScheme == SELF_SCHNORR`, `authKey ≡ encKey`, va ZK proof cua Zether **da** chung minh biet `x`. Chu ky Schnorr thu hai la du thua. `assertAuthorized` tra ve ngay:

```solidity
if (scheme == AuthScheme.SELF_SCHNORR) return;   // ZK proof la uy quyen. ~2,100 gas (chi doc meta).
```

Nhung khi do digest **phai** duoc nhung vao Fiat-Shamir challenge cua chinh ZK proof, neu khong `feeRecipient` van bi doi. Note goc da lam dung dieu nay cho `withdraw` (bam `recipient` vao challenge) nhung **khong lam cho `transferConfidential`** — do la mot lo hong Anti-MEV that trong note, phai sua trong section 03.

Chi phi phu troi cua lop auth, tinh theo % cua mot giao dich Zether (~200k–250k gas):

| Scheme | Gas auth | % them |
|---|---|---|
| `SELF_SCHNORR` | ~2,100 | +0.9% |
| `ECDSA_MULTISIG` 3-of-5 | 3 × 3,000 + 3 × 1,040 calldata + ~2,000 logic = ~14,120 | +6.3% |
| `MUSIG2_BN254` / `FROST_BN254` | ~12,900 | +5.7% |
| `BLS_12381` (min-sig) | ~118,000 | +52% — **khong dung cho hot path** |
| `PQ_COMMITMENT` | ~2,600 (chi doc, verify off-chain) | +1.2% |
| `SMART_ACCOUNT_1271` | ~5,000 + chi phi cua account (cap 100k) | +2.2% .. +45% |

Bang nay quyet dinh: **BLS khong bao gio la authScheme cho tai khoan giao dich.** No chi hop ly cho attestor quorum (§2.8), noi tan suat la ~500 lan/nam chu khong phai moi transfer.

#### 2.4.3. MuSig2 vs FROST — **ban nhap truoc lan hai khai niem**

| | MuSig2 | FROST |
|---|---|---|
| Nguong | **n-of-n** (moi thanh vien phai ky) | **t-of-n** |
| Khoa tong hop | `X = Σ H_agg(L, X_i) · X_i` | Khoa chia se qua DKG (Feldman/Pedersen VSS) |
| On-chain | 1 G1 point + 1 Schnorr sig, gas **khong doi theo n** | Y het |
| Vong giao tiep | 2 (nonce round + sign round) | 2 (voi FROST2/preprocessing co the 1) |
| Hop cho | Ban dieu hanh nho bat buoc dong thuan tuyet doi | **MPC custody, treasury t-of-n, moi thu con lai** |

Ban nhap truoc anh xa "MPC → `MUSIG2`". **Sai**: nha cung cap MPC (Fireblocks, Fordefi, Turnkey) lam threshold ECDSA hoac FROST, khong lam MuSig2. Va treasury 3-of-5 khong the dung MuSig2 (no doi 5-of-5). Sua anh xa custody (locked #6):

| Custody model | authScheme | Ghi chu |
|---|---|---|
| HSM (FIPS 140-2 L3) | `ECDSA_MULTISIG` | HSM lam secp256k1/P-256 tot; khong lam bn254 Schnorr (§2.4.4) |
| MPC | `SELF_SCHNORR` neu provider ho tro bn254 threshold, **nguoc lai** `ECDSA_MULTISIG` | On-chain khong phan biet duoc; khong quan trong |
| MPC voi threshold Schnorr bn254 | `FROST_BN254` | Chi khi provider that su ho tro curve nay — hoi truoc, dung gia dinh |
| Custodial | `ECDSA_MULTISIG` | Custodian ky, khach hang co 1 trong n |
| Non-custodial | `SELF_SCHNORR` | Nguoi dung tu giu, tu chiu |
| Smart-account / passkey | `SMART_ACCOUNT_1271` | P-256 verify trong account (hoac EIP-7212 neu chain co) |
| Ban dieu hanh n-of-n | `MUSIG2_BN254` | Truong hop hiem; chi khi can giau co cau nhom |

**Registry khong biet gi ve custody model** — dung nhu locked #6 yeu cau. Cot `custody_model` chi ton tai trong Odoo (`blockchain.zether.account.custody_model`) de van hanh, khong len chain.

**Bay chet nguoi trong MuSig2/FROST: tai su dung nonce lam lo khoa bi mat** (tan cong Wagner/ROS tren so do 2 vong). Bat buoc: nonce `(R1, R2)` sinh trong HSM/MPC voi bo dem chong-lap **cung** (khong phai bien trong RAM), va message duoc dua vao ham dan xuat nonce (`nonce = KDF(sk_share, msg, counter)`). Ghi thanh `SECURITY:` comment trong SDK va thanh mot test negative: ky hai message khac nhau voi cung nonce phai bi SDK tu choi o tang API, khong chi tang doc.

**MuSig2/FROST va rogue-key tai registry.** He so `H_agg` da chan rogue-key ngay trong so do, nen PoP cho `X` khong con la yeu cau mat ma — nhung registry **khong the phan biet** `X` la khoa don hay khoa tong hop, nen van bat buoc PoP; nhom san xuat PoP bang chinh mot phien MuSig2/FROST.

**Thay doi thanh vien nhom.** Them/bot mot thanh vien doi `X_agg` → doi `authKeyHash` → phai qua `requestAuthRotation` (§2.7.1) voi chu ky cua `X_agg` **hien tai**. Vi MuSig2 la n-of-n, mot thanh vien roi nhom co the chan viec bi loai bo (ho khong ky). Voi FROST t-of-n thi t nguoi con lai lam duoc. **Day la mot ly do van hanh nua de mac dinh FROST chu khong MuSig2.**

#### 2.4.4. **`encKey` khong nam duoc trong HSM FIPS 140-2 L3 tieu chuan** — mau thuan truc tiep voi note

`blockchain.md` §10.3.1 va §14.2.8 tuyen bo: "Khoa cá nhân ... bắt buộc phải lưu trong ... FIPS 140-2 Level 3 HSM (AWS CloudHSM, Google Cloud KMS)". Ap dung cho `encKey` thi **khong lam duoc**, va day la mot rui ro trien khai phai duoc bao cao truoc khi ky hop dong:

- AWS CloudHSM, GCP Cloud KMS, Azure Managed HSM ho tro cac duong cong NIST (P-256/384/521), secp256k1 (mot so), Ed25519. **Khong ho tro alt_bn128 (BN254)** va khong co API de nap duong cong tuy y.
- Zether can `ecMul` tren bn254 G1 voi khoa bi mat `x`, va can `x` trong **mach tinh Bulletproofs/sigma** — khong chi mot phep ky don le. Ngay ca mot HSM co bn254 cung khong du: prover can hang nghin phep nhan vo huong voi `x` la mot trong cac input.

| Lua chon | Ranh gioi bao mat that su | Chi phi / thoi gian | Danh gia |
|---|---|---|---|
| (a) HSM giu **seed**, host dan xuat `x` va prove trong RAM | `x` o plaintext trong RAM cua host khi prove | thap | Vi pham cau chu cua note. Chap nhan duoc **chi khi** ket hop bat bien #1 (§2.4.2) |
| (b) Prover chay trong TEE (SGX / SEV-SNP / TDX) | `x` trong enclave; van co side-channel | trung binh, 2–4 tuan tich hop | **Khuyen nghi cho public chain** |
| (c) HSM lap trinh duoc (Thales Luna Functionality Module, Utimaco CryptoServer CP5) | Dung FIPS L3, `x` khong bao gio roi HSM | **cao**: firmware phai duoc ky, lead time 3–6 thang, ~$30k–80k thiet bi + phat trien | Kha thi nhung khong cho MVP |
| (d) MPC provider ho tro bn254 | Phan tan, khong co diem `x` day du | Phu thuoc provider; **phai hoi truoc, phan lon khong ho tro** | Kiem tra som |
| (e) Khong bao ve `encKey` bang phan cung; bao ve `authKey` bang HSM | `encKey` compromise = lo so du; **khong mat tien** nho bat bien #1 | thap | **Day la ly do that su de tach hai khoa** |

**Quyet dinh de xuat: (e) + (b).** `authKey` (quyen chi tieu) nam trong HSM FIPS L3 that su — dieu nay lam duoc vi `ECDSA_MULTISIG` dung secp256k1/P-256. `encKey` (quyen giai ma) nam trong TEE hoac o muc mem hon. Sua cau chu cua note thanh: *"Khóa có quyền chi tiêu bắt buộc HSM/MPC FIPS 140-2 L3; khóa giải mã ElGamal chạy trong TEE, và compromise của nó là read-only breach theo thiết kế."*

**Day la mot thay doi cam ket voi khach hang, khong phai mot chi tiet ky thuat.** Phai dua len bang cau hoi mo (§2.12).

---

### 2.5. BLS: alt_bn128 vs BLS12-381 tren EVM

#### 2.5.1. Su that ve bao mat bn254

Sau exTNFS (Kim–Barbulescu 2016), do kho DLP trong `F_p^12` cua bn254 tut xuong **~100 bit**. Dieu nay dan den mot bat doi xung ma phai noi cho dung, vi note bo qua:

- **ElGamal / Schnorr / Bulletproofs cua Zether tren bn254 G1 van an toan ~127 bit** — chung dua vao ECDLP tren G1, khong dua vao pairing. exTNFS khong cham vao day. **Zether tren bn254 la lua chon dung.**
- **BLS tren bn254 KHONG an toan 128 bit** — bao mat cua no quy ve co-CDH, bi chan boi DLP trong `F_p^12` → ~100 bit. **Khong xay chu ky BLS tuoi tho dai tren bn254.**

100 bit nghia la gi ve tien: chi phi pha ~2^100 phep tinh. Khong ai pha duoc hom nay. Nhung mot attestation quorum ky trang thai freeze/revoke la thu co **tuoi tho phap ly 7–10 nam** (thoi han luu ho so kiem toan). Do la khoang thoi gian ma bien do an toan tu 128 xuong 100 bit tro nen dang lo. Ket luan giu nguyen.

#### 2.5.2. Precompile hien co, va **bien the BLS phai chon**

| Curve | Precompile | Gia (gas) |
|---|---|---|
| alt_bn128 | `ecAdd` 0x06 / `ecMul` 0x07 / `ecPairing` 0x08 (EIP-196/197, dinh gia lai EIP-1108) | 150 / 6,000 / 45,000 + 34,000·k |
| alt_bn128 | hash-to-curve | **KHONG CO** — phai viet Solidity (try-and-increment: ~20k–60k gas) |
| alt_bn128 | G2 arithmetic / G2 subgroup check | **KHONG CO** — xem §2.5.3 |
| BLS12-381 | EIP-2537, addr 0x0b..0x11, vao mainnet cung **Pectra (2025-05-07)** | G1ADD 375, G1MSM 12,000 (k=1), G2ADD 600, G2MSM 22,500 (k=1), PAIRING 32,600·k + 37,700, MAP_FP_TO_G1 5,500, MAP_FP2_TO_G2 23,800 |

**Ban nhap truoc tinh thieu.** `hash_to_curve` theo RFC 9380 (`_XMD:SHA-256_SSWU_RO_`) can **hai** field element → **hai** lan map → **mot** lan add. Va co hai bien the BLS ma ban nhap truoc khong phan biet:

| Bien the | pk | sig | hash-to | Kich thuoc |
|---|---|---|---|---|
| min-pubkey-size | G1 (48 B) | G2 (96 B) | G2 | pk nho, sig to |
| **min-signature-size** (chon) | G2 (96 B) | G1 (48 B) | **G1** | pk to, **sig nho** |

Chi phi verify **mot** chu ky, tinh lai day du:

| Buoc | min-pubkey (sig∈G2) | **min-sig (sig∈G1)** |
|---|---|---|
| `expand_message_xmd` (SHA-256 precompile 0x02, ~5 call) | ~500 | ~500 |
| map field → curve, 2× | 2 × 23,800 = 47,600 | 2 × 5,500 = 11,000 |
| clear cofactor / add, 1× | 600 (G2ADD) | 375 (G1ADD) |
| pairing check k=2 | 32,600×2 + 37,700 = 102,900 | 102,900 |
| calldata sig | 96 B = 1,536 | **48 B = 768** |
| **Tong** | **~153,100** | **~115,500** |

**Chon min-signature-size.** Tiet kiem ~37,600 gas/verify va mot nua calldata. Doi lai pk 96 B thay vi 48 B — nhung pk luu **mot lan** khi dang ky attestor, con sig tra **moi lan**. Ban nhap truoc chon nham bien the ngam dinh.

bn254 BLS de doi chieu: pairing k=2 (45,000 + 68,000 = 113,000) + hash-to-curve Solidity (~20k–60k) ≈ **150,000–180,000 gas**, o muc bao mat ~100 bit. **Dat hon va yeu hon BLS12-381.** Chi dung khi chain khong co EIP-2537 va khong co lua chon nao khac.

#### 2.5.3. Subgroup check — cai bay ma ban nhap truoc chi nhac mot dong

Ban nhap truoc viet "can tren G2 — lien quan BLS". Dung, nhung hau qua nang hon ve:

- **bn254 G2 co cofactor ≠ 1** va **EVM khong co precompile nhan vo huong tren G2**. Kiem tra subgroup cho mot pk∈G2 tren bn254 = nhan diem voi order `r` bang so hoc `F_p^2` viet tay trong Solidity ≈ **500k–1.5M gas** (uoc tinh: ~254 lan double + add, moi lan ~4 mulmod trong Fp2 = ~12 mulmod, ~2,000–5,000 gas/buoc). **Khong lam duoc on-chain.** Duong duy nhat: kiem tra off-chain khi dang ky attestor, va coi tap attestor la permissioned. Chap nhan duoc vi attestor set von la permissioned; nhung phai ghi thanh runbook, khong duoc quen.
- **EIP-2537 co kiem tra subgroup, nhung khong phai o moi precompile.** `G1MSM`/`G2MSM` va `PAIRING_CHECK` kiem tra subgroup membership cua input. `G1ADD`/`G2ADD` **chi** kiem tra diem nam tren duong cong, **khong** kiem tra subgroup. Nghia la: neu ta tong hop khoa attestor bang mot chuoi `G2ADD` re tien, ta **khong** duoc bao ve. Sua: khi **dang ky** mot attestor pk, goi mot lan `G2MSM` voi k=1 (22,500 gas) de ep kiem tra subgroup; sau do `G2ADD` de tong hop la an toan (tong cua cac phan tu trong subgroup van trong subgroup).

#### 2.5.4. Diem hoa von voi ECDSA — va tai sao no khac tren rollup

Gia tri thuc cua aggregate: n nguoi ky **cung mot message** → 1 chu ky, chi phi verify **khong doi**, cong (n−1) `G2ADD` = 600 moi cai de gop khoa (hoac dung bitmap + pre-aggregated key theo epoch).

Chi phi ECDSA: `ecrecover` 3,000 + calldata `(r,s,v)` dong goi chat 65 B = 1,040 + logic sort/dedupe ~500 ≈ **4,540 gas/signer**.

| Moi truong | BLS co dinh | BLS/signer | ECDSA/signer | Hoa von n |
|---|---|---|---|---|
| L1 / Gnosis / chain doc lap | 115,500 | 600 | 4,540 | **n ≈ 29** |
| bn254 BLS (neu buoc phai) | 165,000 | 150 | 4,540 | **n ≈ 38** |
| **Rollup (Celo L2, Base, Arbitrum)** — calldata tra tien L1 | 115,500 + 48 B L1 | 600 + 0 | 4,540 + **65 B L1** | Xem duoi |

Tren rollup, byte calldata bi tinh gia L1. O 10 gwei L1, mot byte non-zero calldata co the ton **~160–240 gas-tuong-duong** (16 gas × he so nen/scalar cua rollup, tuy chinh sach `l1FeeScalar`; uoc tinh, phai do). Voi ECDSA: 65 B/signer × ~200 = **13,000 gas-tuong-duong/signer** thay vi 1,040. Hoa von tut xuong:

```
115,500 + 600n  =  (3,000 + 13,000 + 500) n
n ≈ 115,500 / 15,900 ≈ 7.3
```

**Tren rollup, BLS thang tu n ≈ 8.** Ban nhap truoc noi "BLS chi thang khi quorum > ~35" — dung tren L1/Gnosis, **sai tren rollup**, va Celo (locked #4, chain thu hai) **la mot OP Stack rollup**. Day la mot ket luan dao chieu.

**Quyet dinh cuoi:**
- Quorum attestor 5-of-9 tren Gnosis / private chain → **ECDSA multisig** (5 × 4,540 ≈ 22,700 gas). Dung.
- Cung quorum tren Celo (rollup) → **BLS12-381 min-sig neu chain co EIP-2537**, nguoc lai ECDSA. Probe runtime.
- Kien truc §2.4 cho phep doi verifier ma khong migration, nen quyet dinh nay **khong khoa cung**; do gas thuc te sau 1 thang van hanh roi chot.

#### 2.5.5. Kha dung theo chain — phai probe, khong duoc gia dinh

Gnosis va Celo theo lich fork rieng (Celo da chuyen thanh L2 OP Stack; OP Stack nhan EIP-2537 qua hard fork Isthmus). Deploy-time probe:

```solidity
// smartcontracts/evm/registry/src/lib/CurveCapability.sol
function hasBls12381() internal view returns (bool ok) {
    // staticcall G1ADD (0x0b) voi vector (P + O = P) da biet, so sanh output.
    (bool s, bytes memory out) = address(0x0b).staticcall(_G1ADD_IDENTITY_VECTOR);
    ok = s && out.length == 128 && keccak256(out) == _EXPECTED_G1ADD_RESULT;
}
```
Chi `success == true` la **khong du**: mot chain khong co precompile o 0x0b se coi do la mot dia chi rong va `staticcall` tra `success = true` voi `returndata` rong. Phai so sanh ket qua. Ban nhap truoc chi kiem `ok` — **bug**.

Ket qua ghi vao Odoo record `blockchain.chain.profile.has_bls12381` luc onboarding chain, khong hardcode trong Python.

---

### 2.6. FALCON / post-quantum: noi that

#### 2.6.1. Trang thai chuan hoa (tinh den 2026-08)

NIST hoan tat **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)** va **FIPS 205 (SLH-DSA)** ngay 2024-08-13. **FIPS 206 (FN-DSA, tuc FALCON) chua ban hanh chinh thuc.**

**Canh bao ve do tin cay cua chinh cau tren:** trang thai FIPS 206 co the da thay doi giua thoi diem viet va thoi diem doc. Truoc khi dua "FALCON" vao bat ky hop dong, SOW, hay tai lieu tuan thu nao, **phai kiem tra lai truc tiep tai `csrc.nist.gov/pubs/fips/206`** va ghi ngay kiem tra vao tai lieu. Bat ky ke hoach nao coi FALCON la "chuan NIST da co" ma khong kiem tra deu la rui ro phap ly, khong chi rui ro ky thuat.

| Scheme | Public key | Signature | NIST level | Ham bam |
|---|---|---|---|---|
| FALCON-512 | 897 B | ~666 B (max 752) | 1 | SHAKE256 |
| FALCON-1024 | 1,793 B | ~1,280 B (max 1,462) | 5 | SHAKE256 |
| ML-DSA-44 | 1,312 B | 2,420 B | 2 | SHAKE128/256 |
| ML-DSA-65 | 1,952 B | 3,309 B | 3 | SHAKE128/256 |
| ML-DSA-87 | 2,592 B | 4,627 B | 5 | SHAKE128/256 |
| SLH-DSA-SHA2-128s | 32 B | 7,856 B | 1 | **SHA-256** |
| SLH-DSA-SHA2-128f | 32 B | 17,088 B | 1 | **SHA-256** |
| (so sanh) Schnorr bn254 | 64 B | 64 B | ~127-bit classical | keccak256 |

#### 2.6.2. Verify FALCON on-chain: **ban nhap truoc uoc tinh qua cao, va ket luan dung vi ly do khac**

Dem lai thao tac (uoc tinh, co so: dem opcode × bang gia; **chua co verifier FALCON Solidity nao duoc audit cong khai** nen khong co so do that de doi chieu):

| Thanh phan | Chi tiet | Gas uoc tinh |
|---|---|---|
| `HashToPoint` (SHAKE256) | ~1,180 B output can ~10 lan keccak-f[1600]; **EVM khong co precompile keccak-f tho**, `KECCAK256` opcode co padding SHA-3 khac SHAKE → phai hien thuc keccak-f trong Solidity: ~25k–60k gas/permutation | **250k–600k** |
| NTT-512 tren `Z_12289` | 9 tang × 256 butterfly = 2,304 butterfly; moi butterfly ~1 `mulmod` + 2 `addmod` + memory ≈ 30–60 gas | **70k–140k / NTT** |
| So NTT can | `s1 = c − s2·h`: giu `h` o dang NTT (nhung `h` den tu calldata → phai NTT), NTT(s2), va INTT ket qua | **3 NTT ≈ 210k–420k** |
| Giai nen chu ky (Golomb-Rice) | 666 B bit-unpacking trong Solidity | **30k–80k** |
| Kiem tra chuan `‖(s1,s2)‖² ≤ β²` | 1,024 `mulmod` + `addmod` | **~30k** |
| Calldata (pk 897 + sig 666 = 1,563 B) | 16 gas/byte | **~25k** |
| **Tong** | | **~0.6M – 2.5M gas** |

Ban nhap truoc noi **2M–10M**. Con so do cao gap 3–4 lan. Sua lai, va ket luan **doi ly do**:

| Chieu | Danh gia |
|---|---|
| **Chi phi tien** | Gnosis @2 gwei: 1.5M gas = **$0.003**. Celo tuong duong. **Tien KHONG phai rao can.** Ethereum L1 @10 gwei/$3,000: **$45/verify** — o day tien la rao can |
| **Block gas limit** | Gnosis ~17–30M, Ethereum ~45M (2025). Mot verify chiem **5–15%** mot block Gnosis. Chap nhan duoc cho tan suat thap, **khong** cho hot path |
| **DoS surface** | Mot ham 2M gas ai cung goi duoc la mot vector spam re tien tren chain co gas re. Phai gate |
| **Ky thuat** | **Khong ton tai verifier FALCON Solidity duoc audit.** Tu viet = 3–6 thang + audit $80k–150k, cho mot thuat toan chua co FIPS |
| **Phia ky** | FALCON can Gaussian sampling voi so hoc dau phay dong / fixed-point emulation — **rat it HSM ho tro firmware nay**. Constant-time implementation la mot bai toan kho da tung co CVE |

**Ket luan sua lai: khong trien khai FALCON on-chain hom nay — khong phai vi gas, ma vi (a) khong co verifier duoc audit, (b) FIPS 206 chua ban hanh, (c) phia ky khong co ho tro HSM.** Ket luan cuoi cung giong ban nhap truoc, nhung ly do khac han, va dieu do doi huong dan: neu mai co mot verifier FALCON duoc audit, **quyet dinh nay dao chieu ngay tren Gnosis**, vi chi phi tien da chap nhan duoc. Phai theo doi.

#### 2.6.3. **Lua chon PQ on-chain thuc dung nhat lai la SLH-DSA-SHA2 — ban nhap truoc bo qua hoan toan**

SLH-DSA (SPHINCS+) la **hash-based**: khong NTT, khong lattice, khong so hoc dau phay dong, va bien the `SHA2` dung dung ham bam ma EVM **da co precompile** (`SHA256` tai `0x02`, gia `60 + 12/word`).

Uoc tinh verify SLH-DSA-SHA2-128s (co so: dem so lan goi ham bam trong thuat toan verify):

| Thanh phan | So lan bam | Ghi chu |
|---|---|---|
| FORS: k=14 tree, a=12 | 14 × (1 + 12) = 182 | leaf + auth path |
| Hypertree: d=7 lop, h/d=9 | 7 × 9 = 63 | auth path |
| WOTS+ chain: len=35, trung binh w/2≈7.5 buoc | 7 × 35 × 7.5 ≈ 1,838 | chi phi troi nhat |
| Tweakable hash overhead, PRF, message compress | ~250 | |
| **Tong** | **~2,330 lan bam** | |
| Gas: `staticcall` 0x02, ~100 overhead + 60 + 12/word (input ~64–128 B) | 2,330 × ~200 | **~466,000** |
| Calldata sig 7,856 B | 16 × 7,856 = 125,700 **hoac** floor EIP-7623 | xem duoi |
| **Tong verify** | | **~0.6M gas** |

**EIP-7623 o day binh hay khong?** Nguong: floor binh khi `execution_gas < 24 × non_zero_bytes = 24 × 7,856 = 188,544`. Execution ~466k > 188.5k → **floor khong binh**, calldata tinh 16 gas/byte. Nhung neu ai do chi **neo** mot chu ky SLH-DSA ma khong verify (execution ~30k), floor **binh**: chi phi = `21,000 + 10 × 31,424 = 335,240` thay vi `21,000 + 125,700 + 30,000 = 176,700`. **Neo mot chu ky PQ dat gan gap doi khi khong verify no.** Do la mot con so phan truc giac va phai nam trong bang chi phi cua team.

So sanh cuoi:

| Scheme PQ | Gas verify (uoc tinh) | Ton tai verifier duoc audit? | FIPS |
|---|---|---|---|
| FALCON-512 | 0.6M–2.5M | **Khong** | **Chua** (FIPS 206) |
| ML-DSA-65 | 1.5M–4M (SHAKE trong Solidity + NTT-256 × nhieu) | Khong | **Co** (FIPS 204) |
| **SLH-DSA-SHA2-128s** | **~0.6M** | Khong, **nhung don gian nhat de viet + audit** | **Co** (FIPS 205) |

**Khuyen nghi sua doi so voi ban nhap truoc:** neu buoc phai co PQ verify **on-chain** tren EVM cong khai, ung vien la **SLH-DSA-SHA2-128s**, khong phai FALCON va khong phai ML-DSA. Ly do: dung precompile san co, khong co so hoc lattice, be mat audit nho nhat. Doi lai chu ky 7,856 B — chap nhan duoc cho attestation/anchor tan suat thap, khong chap nhan duoc cho moi transfer. Giu FALCON va ML-DSA nhu cac gia tri `pqSchemeId` cho verify **off-chain** va cho native precompile tren private chain.

#### 2.6.4. Bay phai chan ngay: "PQ trong SNARK"

"Verify FALCON ben trong mot SNARK Groth16 tren bn254, chi ton ~200–250k gas on-chain". Con so gas dung, nhung **bao mat sai hoan toan**: soundness cua Groth16/bn254 (va cua Groth16/BLS12-381, va cua moi SNARK dua tren pairing) dua tren gia thiet pairing/discrete-log, thu ma may tinh luong tu pha duoc. Mot ke tan cong luong tu gia mao SNARK truc tiep, khong can pha FALCON. **PQ-trong-SNARK-pairing la an ninh trinh dien.**

Duong PQ that su tren EVM chi co hai:
1. **STARK/FRI (chi dua vao hash, PQ-safe)** — verifier tren EVM ton ~1–5M gas (co so: verifier SHARP cua StarkWare tren mainnet o thang do nay). Kha thi ky thuat, dat, va cong kenh. Chu y: nhieu he "STARK" trong san xuat **boc mot lop Groth16 cuoi cung** de re gas — lop boc do pha huy tinh PQ. Phai doc ky, khong tin nhan.
2. **Native precompile** — chi lam duoc khi ta so huu client. **Tuc la private chain (locked #5).**

#### 2.6.5. Duong di cu the (4 buoc, khong phai lo trinh mo ho)

| Giai doan | Public EVM (Gnosis, Celo) | Private chain |
|---|---|---|
| **Ngay bay gio** | `authScheme = PQ_COMMITMENT`. Registry luu **duy nhat** `authKeyHash = keccak256(pqSchemeId, pqPubKey)` (32 B, 1 SSTORE = 22,100 gas). Khoa day + chu ky luu `ir.attachment` tren S3/Garage, hash neo vao event. Verify FALCON/ML-DSA/SLH-DSA **off-chain** tai gateway va tai relayer. Cho **non-repudiation hoi to** ma khong ton gas | Giong hệt, cong them: bat buoc dual-sign (classical on-chain + PQ off-chain) cho moi giao dich > nguong |
| **Khi private chain len phien ban co plugin** | (khong doi) | Them precompile ML-DSA/SLH-DSA o dia chi du tru (Besu plugin API / Nethermind plugin), deploy `PqNativeVerifier`, `rotateAuthScheme()` sang verify on-chain that. **Khong dong den so du, khong migration** — nho tach encKey/authKey (§2.4) |
| **Khi co verifier SLH-DSA Solidity duoc audit** | Deploy `SlhDsaSha2Verifier`, rotate `verifier` cho cac tai khoan gia tri cao. ~0.6M gas/verify = $0.0012 tren Gnosis — **chap nhan duoc** | Hop nhat |
| **Neu khong bao gio co** | Giu commitment + off-chain vinh vien. Chap nhan. Ghi vao hop dong khach hang | Da xong o buoc 2 |

#### 2.6.6. Van de PQ nghiem trong hon: **harvest-now-decrypt-later tren ciphertext**

Chu ky chi anh huong *tuong lai*, nhung **ciphertext ElGamal tren chain cong khai la vinh vien**. Mot may tinh luong tu du manh (CRQC) pha ECDLP tren bn254 G1 → **giai ma nguoc toan bo lich su so tien va so du Zether**. Day la harvest-now-decrypt-later ap dung thang vao bi mat thuong mai. Note hoan toan khong nhac.

Dinh lieu bang so:

| Yeu to | Gia tri |
|---|---|
| Muc tieu di chuyen PQ cua CNSA 2.0 (NSA) cho ha tang quoc gia | **2030–2033** |
| Uoc tinh phan tan cua gioi hoc thuat ve CRQC pha ECC-256 | 2030–2045, khong co dong thuan |
| Tuoi tho bi mat cua **gia ban thu cap FMCG / chiet khau trade** | 2–5 nam |
| Tuoi tho bi mat cua **gia von / dieu khoan hop dong B2B** | 5–15 nam |
| Tuoi tho bi mat cua **so du quy** | 1–3 nam |

Cong thuc Mosca: neu `tuoi_tho_bi_mat + thoi_gian_migrate > thoi_diem_CRQC` thi da tre. Voi B2B settlement gia von (15 nam) va CRQC bi quan (2035), ta **da tre tu bay gio**.

Ba lua chon, phai chon cong khai:

1. **Giu so cai bao mat tren private chain** (ciphertext khong cong khai) — dung voi locked #5, va day la **ly do ky thuat manh nhat cho quyet dinh do**, manh hon ly do gas ma user dua ra.
2. **Chap nhan chan troi bao mat** va ghi thanh so: "gia mua va so du bi lo neu CRQC xuat hien truoc nam X". Chap nhan duoc voi Z-Loyalty (tuoi tho bi mat ~1 nam) va thanh toan nguoi dung cuoi; **khong** chap nhan duoc voi B2B settlement gia von.
3. **Khong dua so tien len chain chut nao** cho luong nhay cam nhat: chain chi giu `keccak256(so_tien ‖ salt)`, so tien nam trong sub-ledger Odoo, doi soat theo lo. Day chinh la **payment mode (4)** trong locked #8, va no la mien nhiem PQ theo dinh nghia. Chi phi: mat tinh cong dong hinh, mat kha nang chung minh khong am on-chain. Doi lai: khong co gi de giai ma.
4. Migration sau nay sang scheme lattice-based confidential transfer — **chua ton tai o muc san xuat**. Khong lap ke hoach dua tren no.

**Khuyen nghi phan tang (dung theo locked #3):**

| Use case | Chain | Che do | Ly do |
|---|---|---|---|
| Loyalty / reward points | Gnosis, Celo (cong khai) | Zether day du | Tuoi tho bi mat ngan; gia tri thap |
| End-user payment | Gnosis, Celo (cong khai) | Zether day du | Nhu tren |
| **B2B settlement (gia von, chiet khau)** | **Private chain** | Zether day du, ciphertext khong cong khai | HNDL |
| B2B settlement — neo bang chung | Gnosis (cong khai) | Chi hash chung tu | Bat bien + kiem toan doc lap |

---

### 2.7. Xoay khoa, thu hoi, khoi phuc

#### 2.7.1. Xoay `authKey` — re, phai co timelock, **va phai chan DoS cua guardian**

```solidity
function requestAuthRotation(bytes32 addr, uint8 newScheme, bytes32 newAuthKeyHash,
                             address newVerifier, uint64 deadline, bytes calldata sigByCurrentAuth)
    external;   // digest: "ZETHER_ROTATE_V1", chainid, address(this), addr, authEpoch,
                //          newScheme, newAuthKeyHash, newVerifier, deadline
function executeAuthRotation(bytes32 addr) external;                  // sau ROTATION_DELAY
function vetoAuthRotation(bytes32 addr, bytes calldata sigByGuardians) external;
function forceAuthRotation(bytes32 addr) external;                    // sau FORCE_DELAY, khong the veto
```

`ROTATION_DELAY` mac dinh **24 gio**. Ly do: neu khoa bi trom, ke trom se lap tuc xoay sang khoa cua no de khoa chu that ra ngoai. Timelock + event `AuthRotationRequested` + veto cua guardian bien tan cong do thanh mot canh bao co 24 gio de xu ly. `authEpoch++` moi lan xoay → chu ky cu vinh vien vo hieu (nho §2.4.2 digest).

**Ban nhap truoc de `cancelAuthRotation` cho guardian ma khong gioi han → guardian doc hai (hoac guardian mat khoa) chan vinh vien moi lan xoay.** Sua:

| Co che | Chi tiet |
|---|---|
| `vetoAuthRotation` | Can `g-of-m` guardian. Hieu luc: huy request **va** dat `status = FROZEN` (khong tra lai `ACTIVE` — neu co tranh chap thi tai khoan phai dung, khong phai chay tiep duoi khoa cu co the da bi trom) |
| Dem veto | `vetoCount[addr]++`. Khi `vetoCount >= 2`, `ROTATION_DELAY` cho request tiep theo doi thanh `FORCE_DELAY` |
| `FORCE_DELAY` | **14 ngay**, va guardian **khong the veto** trong che do nay. Chu tai khoan luon co duong ra, chi la duong cham |
| Reset | `vetoCount` reset ve 0 sau mot lan `executeAuthRotation` thanh cong |

Ly le: 14 ngay du lau de mot vu trom bi phat hien va xu ly qua duong phap ly / freeze; va du ngan de mot guardian bo di khong khoa chet tai san vinh vien.

**Guardian set — ban nhap truoc nhac ten nhung khong dinh nghia.** Dinh nghia:

```solidity
// slot 4 cua Account (them vao §2.1.4)
bytes32 guardianSetHash;   // keccak256(abi.encode(threshold_g, sortedGuardianAddrs[]))
// Dat/doi qua chinh co che rotation (cung timelock, cung veto), ham rieng:
function requestGuardianChange(bytes32 addr, bytes32 newGuardianSetHash, uint64 deadline,
                               bytes calldata sigByCurrentAuth) external;
```

Guardian la `address` (EOA/multisig/smart account), **khong** phai `schnorrAddress` — ho khong can tai khoan Zether. Xac thuc bang `ecrecover` tren digest, so sanh tap ky voi `guardianSetHash` do caller cung cap day du danh sach (calldata 20 B/guardian = 320 gas cho m=16; re hon luu on-chain m slot).

`guardianSetHash = 0` (mac dinh) → **khong co guardian, khong co veto, khong co recovery.** Do la mac dinh dung: da so tai khoan loyalty khong can guardian, va mot guardian mac dinh do he thong dat la mot backdoor.

#### 2.7.2. Xoay `encKey` — **khong lam tai cho duoc**

So du duoc mã hóa duoi `y`. Duong duy nhat: chuyen tai san sang mot `schnorrAddress` moi. Dung `withdraw()` roi `deposit()` (lo so tien ra cong khai — khong chap nhan duoc), ma them mot ham tren **token** (khong phai registry):

```solidity
/// @notice Chuyen toan bo so du bi mat sang schnorrAddress moi, khong lo so tien.
/// @dev proof: sigma proof chung minh ciphertext duoi y_old va y_new mã hóa CUNG mot gia tri v,
///      cong voi chung minh biet x_old. Chi phi: 4 ecMul + 2 ecAdd ≈ 24,300 gas
///      (ban nhap truoc ghi 12,150 — thieu mot nua: equality proof Chaum-Pedersen can 2 cap).
function migrateAccount(bytes32 fromAddr, bytes32 toAddr, EncryptedTransfer calldata data,
                        bytes calldata authSigOld, bytes calldata authSigNew)
    external returns (bool);
```

**Can chu ky cua ca hai** (`authSigOld` va `authSigNew`): chu ky cu chung to chu that dong y ra di; chu ky moi chung to dia chi dich la cua chinh ho chu khong phai dia chi ke tan cong bom vao. Ban nhap truoc chi co mot ben.

Lien ket `old → new` **cong khai** — dung voi triet ly "lo danh tinh". Registry danh dau `status(old) = MIGRATED` va luu `successorAddr` (slot 5) de indexer noi chuoi kiem toan.

**Ranh gioi trach nhiem:** `migrateAccount` nam tren token, nhung `status(old) = MIGRATED` nam tren registry → token phai duoc phep ghi vao registry. Do la mot quyen nguy hiem. Giai phap: registry giu `mapping(address => bool) trustedTokens` **immutable qua constructor** (danh sach cac token duoc deploy cung lo), va bat ky token nao them sau phai qua registry the he moi. **Hoac** — don gian hon va chon cai nay — `MIGRATED` do **chinh chu** dat qua `selfMigrate(bytes32 old, bytes32 new, bytes sigByAuth)` tren registry, va token chi doc. Khong co token nao ghi vao registry. Bo `trustedTokens` hoan toan. **Registry chi-doc-tu-token la mot bat bien dang gia.**

#### 2.7.3. Thu hoi — 5 trang thai, ngu nghia phai dung (**va sua mot mau thuan noi tai**)

| status | Gui di | **Nhan vao** | `rollOver` | `withdraw` | Ai dat duoc |
|---|---|---|---|---|---|
| `NONE (0)` | x | x | x | x | — |
| `ACTIVE (1)` | co | co | co | co | — |
| `FROZEN (2)` | **khong** | **co** | co | **khong** | Compliance role (private) / chi chinh chu (public) |
| `REVOKED (3)` | khong | **co** ← *sua* | co | khong | Nhu tren, + timelock 7 ngay |
| `MIGRATED (4)` | khong | **co** ← *sua* | co | khong | `selfMigrate` |

**Ban nhap truoc mau thuan voi chinh no**: no dung ly le "chan inflow lam ben thu ba vo can mat gas" de bien minh cho `FROZEN` nhan vao, roi lai chan inflow o `REVOKED` va `MIGRATED` — cung ly le do ap dung y het. Sua: **moi trang thai != NONE deu nhan duoc.** Chi outflow bi gate. Ket qua:

- Quy tac tro nen mot dong, de kiem chung: `assertUsable(from, to)` chi kiem `status(from) == ACTIVE` va `status(to) != NONE`.
- Tien co the bi day vao mot tai khoan REVOKED va ket o do. Do la dung: mot tai khoan bi thu hoi vi ly do AML thi tien vao no **nen** bi dong bang, khong nen bi tra lai cho nguoi gui.
- Nguoi gui phai duoc canh bao truoc o tang Odoo (`blockchain.zether.account.chain.onchain_state`), khong phat hien khi da mat tien. Lai la "quet QR khong phai la da thu tien": UI chan truoc.

**Ai duoc dong bang?** Tren public chain, mot admin key co quyen dong bang moi tai khoan la vector tap trung hoa va la trach nhiem phap ly. **Mac dinh public chain: chi `selfFreeze()` (chinh chu, khong the tu unfreeze duoi 72 gio).** Quyen dong bang cua compliance chi bat tren chain profile `private`, qua `IRegistrationPolicy` mo rong (`ICompliancePolicy`, cung mo hinh immutable). Neu deployment nao do can freeze tren public chain, do la lua chon co y thuc phai ky duyet, khong phai mac dinh, va phai duoc ghi vao `blockchain.chain.profile.compliance_freeze_enabled` de hien thi trong UI Odoo.

`selfFreeze()` co 72 gio khoa nguoc: chan kich ban ke trom freeze de che dau, roi unfreeze de rut. 72 gio la du de chu that lien lac.

#### 2.7.4. **Khong bao gio cache trang thai registry trong token**

Cam do la ta muon tiet kiem 2,100 gas. Ket qua se la: dong bang mot tai khoan tren registry nhung Z-USDC van cho no rut tien vi cache chua het han. Doc truc tiep, moi lan. Ghi thanh mot Foundry test: freeze tren registry o block N, `transferConfidential` o block N+1 phai revert khong co bat ky do tre nao.

#### 2.7.5. Khoi phuc — phan biet ro hai thu

- **Khoi phuc quyen uy quyen (`authKey`)**: guardian `g-of-m` + timelock 7 ngay + event cong khai `RecoveryAnnounced` + kha nang chu that huy trong 7 ngay do (bang `authKey` cu, neu con). Lam duoc. Interface = chinh `requestAuthRotation` nhung voi `sigByGuardians` thay cho `sigByCurrentAuth`, va `RECOVERY_DELAY = 7 ngay` (dai hon `ROTATION_DELAY = 24h` vi khoi phuc la kenh yeu hon).
- **Khoi phuc kha nang giai ma (`encKey`, tuc `x`)**: **KHONG THE.** Mat `x` = mat vinh vien so du bi mat. Khong co admin key nao giai ma duoc — do la thuoc tinh cua giao thuc, khong phai thieu sot.

Hai he qua bat buoc, **va chung la dieu kien mo tai khoan chu khong phai khuyen nghi**:

1. **Sao luu `x` la bat buoc luc cap phat.** Shamir 2-of-3 (share 1: HSM/TEE production; share 2: niem phong offline trong ket, hai nguoi mo; share 3: custodian phap ly hoac ngan hang) hoac co che recovery cua nha cung cap MPC. Quy trinh phai co **truoc khi mo tai khoan dau tien**, phai co dien tap khoi phuc dinh ky (de xuat: 6 thang/lan tren mot tai khoan thu nghiem), va ket qua dien tap phai duoc ghi nhan.
   Chi phi van hanh: voi 4–6 dia chi/phap nhan (§2.3b), mot brand co 1 nha phan phoi lon = ~10 bo Shamir. Voi 200 distributor moi ben 4 dia chi = 800 bo — **khong quan ly noi thu cong**. Do la mot ly do nua de khong cap 1 dia chi/doi tac.
2. Phai nam trong **hop dong voi khach hang**, khong chi trong tai lieu ky thuat. Cau chu de xuat: *"Việc mất khóa giải mã dẫn tới mất vĩnh viễn số dư bảo mật; nhà cung cấp không có và không thể có cơ chế khôi phục. Khách hàng chịu trách nhiệm vận hành quy trình sao lưu Shamir được mô tả tại Phụ lục X."*

#### 2.7.6. Viewing key — mot lo hong tuan thu trong note

Note tuyen bo "tuan thu 100% AML/KYC va FATF Travel Rule" chi bang cach lo danh tinh nguoi gui/nhan. **Dieu nay khong dung Travel Rule**: FATF Recommendation 16 yeu cau thong tin originator/beneficiary **va so tien** di kem giao dich, va o phia VASP thu nhan phai co kha nang doi chieu. Danh tinh khong kem so tien khong thoa man. (Nghiem ngat hon: Travel Rule rang buoc **VASP**, khong rang buoc mot he thong ERP noi bo — nen muc do ap dung tuy thuoc viec deployment co duoc coi la VASP hay khong. Do la cau hoi phap ly, khong phai ky thuat; xem section 13.)

Phuong an ky thuat cu the:

```
Them mot ciphertext thu ba trong EncryptedTransfer:
    C_audit = g^v · y_audit^s        (dung chung randomness s voi C_transfer)
    (D dung chung: D = g^s, khong can them)
cong mot equality proof (Chaum-Pedersen) chung minh C_transfer va C_audit ma hoa CUNG v duoi cung s.
Chi phi: +64 bytes calldata (1,024 gas) + 4 ecMul + 2 ecAdd (24,300 gas) ≈ 25,300 gas/transfer  (~+11%)
```

Ban nhap truoc ghi 13,200 gas; thieu mot nua vi dem thieu cap thu hai cua equality proof. Sua.

`y_audit` la khoa cua auditor/co quan, dang ky trong chinh registry voi mot flag `isAuditor` (bit trong `meta.reserved`). Bat/tat theo chain profile: bat buoc tren private chain va tren luong B2B settlement; tuy chon tren loyalty.

**Rui ro tap trung hoa cua chinh viewing key — ban nhap truoc khong noi:** neu `x_audit` bi lo, **toan bo lich su** cua moi giao dich co `C_audit` bi giai ma cung mot luc. Do la mot muc tieu gia tri cao hon bat ky tai khoan don le nao. Giam thieu:

- `y_audit` la khoa **threshold** k-of-n giua n auditor (DKG Pedersen), giai ma can k ben phoi hop. **Khong ton them gas on-chain** — on-chain van chi la mot diem G1. Toan bo do phuc tap nam o quy trinh off-chain.
- Xoay `y_audit` theo ky (de xuat 12 thang). Ciphertext cu van duoi khoa cu → phai luu tru khoa cu theo lich luu ho so, khong huy.
- `y_audit` **rieng theo chain profile va theo phap nhan phat hanh**, khong dung chung mot khoa toan cau.

**Loi ich phu, va no lon hon ve ngoai:** neu `x` cua mot ben bi mat, auditor van tai dung duoc **lich su so lieu** tu chuoi `C_audit` — day la co che khoi phuc *so lieu* duy nhat ton tai, du khong khoi phuc duoc *quyen chi tieu*. Nghia la ke toan van dong duoc so; chi co tien la khoa. Voi mot he thong ERP, do la su khac biet giua "mot su co" va "mot tham hoa".

---

### 2.8. Nhat quan cross-chain

`keccak256(pkX, pkY)` khong phu thuoc chain → `schnorrAddress` **da giong nhau tren moi EVM chain, mien phi**. Van de con lai chi la *trang thai*: da dang ky chua, `authScheme`/`authKeyHash` hien tai, va `status`.

| Mo hinh | Trust | Chi phi | Rui ro |
|---|---|---|---|
| **(A) Registry doc lap moi chain** | Khong them gia dinh nao | ~105,750 gas/chain (~$0.00021 Gnosis) | Phan ky: freeze o chain A, con ACTIVE o chain B |
| **(B) Canonical + attestation** | k-of-n attestor quorum | ~23,000 gas/attestation (ECDSA 5-of-9) | Do tre lan truyen; quorum bi chiem |
| **(C) Bridge (CCIP/LayerZero/Hyperlane)** | Ben thu ba + validator set cua bridge | Cao nhat | Them mot he thong co the sap, cho 32 bytes state |

**Chon (A) cho dang ky + (B) cho trang thai. Loai (C) thang.** Ly do loai (C) mot dong: khong dan mot bridge vao duong tin cay de dong bo mot so nguyen tang dan.

#### 2.8.1. Co che (B) cu the

Canonical registry dat tren **private chain** (locked #5 — no da la nguon su that cho KYC). Attestor quorum ky:

```
msg = abi.encode("ZETHER_REG_ATTEST_V1", canonicalChainId, targetChainId, schnorrAddress,
                 authScheme, authKeyHash, verifier, status, epoch)
```

`targetChainId` **phai co** — ban nhap truoc thieu. Khong co no, mot attestation cho Gnosis dung duoc tren Celo; thuong thi vo hai (cung noi dung) nhung khong phai luon: neu `verifier` la mot dia chi contract, no khac nhau tren moi chain, va ap dung nham dia chi verifier = tai khoan khong xac thuc duoc nua. Bug im lang.

```solidity
function applyAttestation(Attestation calldata a, bytes[] calldata sigs, address[] calldata signers)
    external
{
    require(a.targetChainId == block.chainid, "wrong chain");
    require(a.epoch > _epochOf[a.addr], "stale");        // monotonic => replay-safe, khong can nonce
    require(_quorum.verify(_digest(a), sigs, signers), "quorum");
    _apply(a);                                            // ghi de status/authKey local
}
```

- **Permissionless relay**: bat ky ai submit duoc, khong can relayer allowlist. Attestation la du lieu tu-xac-thuc.
- **Monotonic `epoch`** thay cho nonce → khong co van de sap xep, khong co replay. `epoch` la mot bo dem tang dan **tren canonical**, khong phai block number (block number cua canonical khong co y nghia tren mirror).
- **Quorum**: 5-of-9 → **ECDSA multisig** (~23,000 gas) tren Gnosis; **BLS12-381 min-sig** tren Celo neu chain co EIP-2537 (§2.5.4 dao chieu ket luan tren rollup).
- Storage layout cua `ZetherRegistryMirror` **giong hệt** `ZetherAccountRegistry` → mot chain co the chay standalone (khong nhan attestation) ma token khong biet khac biet.

#### 2.8.2. Vong luan quan cua tap attestor — **ban nhap truoc khong xu ly**

Mirror phai biet tap attestor. Neu tap do thay doi, ai bao mirror? Cau tra loi ngay: chinh tap hien tai ky mot attestation loai `ATTESTOR_SET_CHANGE`. Nhung do la mot chuoi tin cay khong co diem dung, va no co hai che do that bai:

| Che do that bai | Xu ly |
|---|---|
| Mirror bi tut lai qua xa (offline dai ngay), tap attestor da doi nhieu the he | `require(a.epoch <= _epochOf[a.addr] + MAX_EPOCH_GAP)` voi `MAX_EPOCH_GAP = 64`. Vuot qua → mirror **tu dung** va doi governance re-anchor thu cong. Tha dung con hon ap dung nham |
| Quorum bi chiem (k khoa bi trom) | Mirror co mot `pauseGuardian` **cuc bo** (multisig cua chinh deployment tren chain do) chi co **mot** quyen: `pauseAttestations()`. Khong co quyen doi state tai khoan. Mot quyen, khong the lam dieu gi khac |
| Attestor set change bi replay len mot mirror khac | `targetChainId` trong digest (§2.8.1) |
| Attestor mat khoa (khong bi trom) | Rotation binh thuong, nhung phai giu `k` du: 5-of-9 chiu duoc 4 attestor chet. Neu chet 5, phai re-anchor thu cong |

**Re-anchor thu cong** = mot ham `governanceSetAttestorSet(bytes32 newSetHash)` chi goi duoc boi `pauseGuardian` sau khi da `pause`, voi timelock 7 ngay va event cong khai. Do la duong thoat cuoi cung; no la mot quyen tap trung hoa va phai duoc ghi nhan la nhu vay.

#### 2.8.3. Do tre = cua so phoi nhiem, va tan suat = chi phi

**Do tre.** Muc tieu p95 < 60 giay tu luc freeze tren canonical den luc mirror cap nhat. Phan ra:

| Chang | Muc tieu p95 |
|---|---|
| Ghi tren canonical (private chain, CometBFT/IBFT ~1 block) | 2 s |
| Finality gate cua canonical | 5 s |
| Attestor quan sat + ky (k=5 nguoi ky, song song) | 10 s |
| Gom chu ky + submit len mirror | 5 s |
| Block time + finality soft cua mirror (Gnosis 5 s soft) | 10 s |
| Dem an toan | 28 s |
| **Tong** | **60 s** |

Trong 60 giay do, phong tuyen thu hai la **Odoo gateway tu choi dung proof ngay lap tuc** — dung tinh than "quet QR khong phai la da thu tien": chan o tang gan nguoi dung truoc, chain la lop cuoi cung chu khong phai lop duy nhat. Cu the: khi `blockchain.zether.account.canonical_state` chuyen sang `frozen`, gateway tu choi ky/relay bat ky intent nao cua tai khoan do **tren moi chain** ngay lap tuc, khong doi mirror.

**Tan suat va chi phi** (uoc tinh cho mot deployment co 5,000 tai khoan):

| Su kien | Ty le/nam | So attestation/nam |
|---|---|---|
| Freeze/unfreeze | 0.5% tai khoan | 50 |
| Revoke | 0.1% | 5 |
| Auth rotation | 10% (chinh sach xoay khoa 1 lan/10 nam + su co) | 500 |
| Migrate | 1% | 50 |
| Attestor set change | — | 4 |
| **Tong/chain** | | **~609** |

609 × 23,000 gas = 14.0M gas/nam/chain ≈ **$0.028/nam tren Gnosis**. **Chi phi cua co che (B) la khong dang ke; toan bo rui ro nam o do tre va o quorum.** Do la ket luan quan trong: dung toi uu gas o day, hay toi uu do tin cay.

#### 2.8.4. Cay `smartcontracts/` (locked #9)

```
smartcontracts/
  evm/
    registry/
      foundry.toml
      src/ZetherAccountRegistry.sol
      src/ZetherRegistryMirror.sol
      src/interfaces/IZetherAccountRegistry.sol
      src/interfaces/ISignatureVerifier.sol
      src/interfaces/IRegistrationPolicy.sol
      src/interfaces/ICompliancePolicy.sol
      src/verifiers/EcdsaMultisigVerifier.sol
      src/verifiers/SchnorrBn254Verifier.sol       # dung chung cho SELF_SCHNORR, FROST, MUSIG2
      src/verifiers/BlsBn254Verifier.sol
      src/verifiers/Bls12381Verifier.sol           # min-signature-size
      src/verifiers/PqCommitmentVerifier.sol
      src/verifiers/SmartAccount1271Verifier.sol
      src/policy/OpenRegistrationPolicy.sol
      src/policy/InviteRegistrationPolicy.sol
      src/policy/AttestedRegistrationPolicy.sol
      src/lib/Bn254.sol
      src/lib/CurveCapability.sol
      test/     # unit + invariant + fork
      script/   # deploy, probe, gas-report
  private/besu/precompiles/slhdsa/                 # Rust plugin, giai doan 2
  hbar/ ton/ sui/ soroban/ cosmwasm/               # thiet ke tren giay (§2.9), xay sau
```

#### 2.8.5. Phia Odoo (`dms_blockchain`, standalone — locked #7)

Khong `depends` `dms`; `res.partner` nam trong `base` nen lien ket doi tac khong tao phu thuoc. `_name` tien to `blockchain.` de khong dung ten voi bat ky addon nao.

```python
class BlockchainChainProfile(models.Model):
    _name = 'blockchain.chain.profile'
    _description = 'Blockchain Chain Profile'

    name = fields.Char(required=True)
    evm_chain_id = fields.Integer(required=True)          # KHONG dat ten 'chain_id' (de nham M2o)
    is_private = fields.Boolean(default=False)            # truc chain profile, locked #5
    registry_address = fields.Char()
    mirror_address = fields.Char()
    has_bls12381 = fields.Boolean(default=False)          # ghi boi probe, KHONG hardcode
    compliance_freeze_enabled = fields.Boolean(default=False)
    finality_depth = fields.Integer(default=1)
    company_id = fields.Many2one('res.company', default=lambda s: s.env.company)

    _unique_evm_chain = models.Constraint(
        'UNIQUE(evm_chain_id, company_id)', 'Moi chain chi co mot profile cho moi company.')


class BlockchainZetherAccount(models.Model):
    _name = 'blockchain.zether.account'
    _description = 'Zether Account Registry Entry'

    schnorr_address = fields.Char(required=True, index=True)   # 0x + 64 hex
    pk_x = fields.Char(required=True)
    pk_y = fields.Char(required=True)
    auth_scheme = fields.Selection([
        ('self_schnorr', 'Self Schnorr'), ('ecdsa_multisig', 'ECDSA Multisig'),
        ('frost_bn254', 'FROST bn254'), ('musig2_bn254', 'MuSig2 bn254'),
        ('bls_bn254', 'BLS bn254'), ('bls_12381', 'BLS12-381'),
        ('pq_commitment', 'PQ Commitment'), ('smart_account_1271', 'Smart Account (EIP-1271)'),
    ], default='self_schnorr', required=True)
    auth_key_hash = fields.Char()
    auth_epoch = fields.Integer(default=0)
    custody_model = fields.Selection([
        ('hsm', 'HSM'), ('mpc', 'MPC'), ('custodial', 'Custodial'),
        ('non_custodial', 'Non-custodial'), ('smart_account', 'Smart Account / Passkey'),
    ])                                                     # locked #6, KHONG len chain
    secret_ref = fields.Char()                             # tro sang HSM/MPC/KMS. KHONG chua khoa.
    partner_id = fields.Many2one('res.partner', index=True)    # base only
    owner_ref = fields.Reference(selection='_selection_owner_ref')  # seam cho dms.*, KHONG dependency
    register_date = fields.Datetime()                      # KHONG dat ten 'date'
    purpose = fields.Selection([
        ('treasury', 'Treasury'), ('loyalty', 'Loyalty'),
        ('settlement', 'B2B Settlement'), ('payroll', 'Payroll'), ('audit', 'Auditor Key'),
    ], required=True)
    canonical_state = fields.Selection([
        ('none', 'None'), ('active', 'Active'), ('frozen', 'Frozen'),
        ('revoked', 'Revoked'), ('migrated', 'Migrated'),
    ], default='none', required=True)
    successor_account_id = fields.Many2one('blockchain.zether.account')
    company_id = fields.Many2one('res.company', required=True,
                                 default=lambda s: s.env.company, index=True)
    chain_state_ids = fields.One2many('blockchain.zether.account.chain', 'account_id')
    divergent = fields.Boolean(compute='_compute_divergent', store=True, default=False)

    _unique_schnorr_address = models.Constraint(
        'UNIQUE(schnorr_address)', 'schnorrAddress phai duy nhat.')
```

**Bay Odoo 19 phai chu y o day** (bay #6 trong danh sach du an): `divergent` la stored computed. Neu `_compute_divergent` co nhanh nao khong gan gia tri, cot se NULL. Voi `Boolean` khong `required` thi NULL doc ra `False` nen khong chet, **nhung** neu sau nay ai do them `required=True` thi INSERT se chet im lang o mot nhanh hiem. Quy tac: gan `rec.divergent = False` o dong dau tien cua compute, roi moi tinh.

```python
class BlockchainZetherAccountChain(models.Model):
    _name = 'blockchain.zether.account.chain'
    _description = 'Zether Account State Per Chain'

    account_id = fields.Many2one('blockchain.zether.account', required=True,
                                 ondelete='cascade', index=True)
    profile_id = fields.Many2one('blockchain.chain.profile', required=True, index=True)
    onchain_state = fields.Selection([...], default='none', required=True)
    auth_epoch = fields.Integer(default=0)
    last_synced_block = fields.Integer(default=0)
    # Vong doi giao dich: "broadcast KHONG phai la da dang ky"
    tx_state = fields.Selection([
        ('draft', 'Draft'), ('submitted', 'Submitted to relayer'),
        ('broadcast', 'Broadcast'), ('mined', 'Mined (unconfirmed)'),
        ('final', 'Final'), ('failed', 'Failed'), ('reorged', 'Reorged'),
    ], default='draft', required=True)
    tx_hash = fields.Char(index=True)

    _unique_account_chain = models.Constraint(
        'UNIQUE(account_id, profile_id)', 'Moi tai khoan chi co mot ban ghi tren mot chain.')
```

**`tx_state` la cho ma nguyen tac VietQR duoc ap dung truc tiep.** `onchain_state` chi duoc phep chuyen sang `active` khi `tx_state == 'final'` — tuc la sau Finality Gate cua chain do (`profile_id.finality_depth`). Mot `register()` da `broadcast` va da `mined` van **chua** la mot tai khoan dung duoc; UI phai hien "Dang cho xac nhan (N/M block)". Ban nhap truoc co `canonical_state` nhung khong co vong doi giao dich, nen khong the dien dat trang thai nay.

Cron mot dong theo dung bay #4 (`ir.cron` khong co `fields`, khong co `relativedelta` trong eval context):
```xml
<field name="state">code</field>
<field name="code">model._cron_reconcile_registry()</field>
```

Entry point RPC (phuc vu ca `call_kw` va `/json/2`), khong nhan `allowed_company_ids`:
```python
@api.model
def zether_account_bootstrap(self, purpose):
    """POST /web/dataset/call_kw/blockchain.zether.account/zether_account_bootstrap
       POST /json/2/blockchain.zether.account/zether_account_bootstrap
    Khong nhan company/partner tu client: suy ra tu env.user."""
    return self._bootstrap(self.env.user, purpose)

def _bootstrap(self, user, purpose):   # private: khong lo qua RPC
    ...
```

Khoa bi mat `x`: **khong bao gio** nam trong DB — `secret_ref` chi la mot con tro, va gia tri that nam trong HSM/MPC/KMS; `ir.config_parameter` giu endpoint va credential ref, khong giu khoa. Nhac lai bay #5: `password=True` khong ton tai o Odoo 19 va chua bao gio chan `read()`/RPC/export.

**Bao mat record-level:** `blockchain.zether.account` chua `secret_ref` va lien ket phap nhan → phai co record rule theo `company_id` va mot group `blockchain_key_admin` rieng cho quyen doc `secret_ref`. Vi Odoo khong co field-level ACL trong Community, `secret_ref` nen tach sang mot model rieng `blockchain.key.ref` voi ACL rieng, hoac de rong trong DB va tra cuu qua ten quy uoc (`zether/{company}/{schnorr_address}`) trong KMS. **Chon phuong an ten quy uoc: khong luu gi ca.** Mot cot ma khong ai duoc doc thi tot nhat la khong ton tai.

---

### 2.9. Registry tren cac chuoi khong phai EVM (thiet ke tren giay, locked #4)

Ban nhap truoc khong co muc nay. Brief yeu cau nhat quan cross-chain, va bon trong nam chuoi con lai **pha vo mot gia dinh nen tang cua thiet ke EVM**: rang token co the goi registry **dong bo** trong cung mot giao dich.

| Chuoi | Registry o dau | Van de rieng | Giai phap de xuat |
|---|---|---|---|
| **HBAR (HSCS)** | Contract EVM y het | Gas theo USD-peg; `ecPairing`/`ecMul` bn254 **co** tren HSCS nhung gia khac. HCS dung lam audit log cho event registry | Tai su dung nguyen code EVM. Neo `AccountRegistered` vao HCS topic de co consensus timestamp phap ly |
| **TON** | **Van de nghiem trong** | Actor model **bat dong bo**: mot contract **khong the** goi contract khac va nhan ket qua trong cung transaction. `require(registry.isRegistered(to))` **khong ton tai** | **Dao nguoc mo hinh**: registry phat mot **certificate** (cell ky boi registry key, chua `addr, pkX, pkY, status, epoch, expiry`). Token verify chu ky certificate **cuc bo**, khong goi ra ngoai. `expiry` ngan (de xuat 1 gio) de gioi han cua so freeze. Doi lai: freeze khong tuc thi tren TON, tre toi da 1 gio — **phai ghi vao hop dong** |
| **SUI** | Object-centric | Mot registry la **Shared Object** → moi transfer cham vao no → **serialize toan bo throughput** qua consensus, mat loi the fast-path | Tach: `AccountCap` la **Immutable Object** cho `(pkX, pkY)` (bat bien, doc song song, khong consensus); chi `status` nam trong mot Shared Object nho, va chi doc khi can. Hoac dung chinh mo hinh certificate nhu TON |
| **Soroban (Stellar)** | Persistent storage + **TTL** | **Entry registry het han → tai khoan bien mat → so du khoa vinh vien.** Day la mot che do that bai khong ton tai tren EVM | Registry entry phai o `Persistent` (khong `Temporary`), va **relayer/gateway phai co cron `extend_ttl` cho moi tai khoan hoat dong**. Chi phi rent phai duoc mo hinh hoa va tinh vao gia dich vu. Neu khong ai tra rent trong X thang, tai khoan phai duoc canh bao va di chuyen |
| **CosmWasm** | Contract rieng, `wasmd` | Goi cross-contract dong bo **duoc** (`WasmQuery::Smart`) → mo hinh EVM ap dung duoc | Tai su dung logic EVM. `x/feegrant` lo gasless register |

**Ket luan kien truc phat sinh:** co **hai** mo hinh registry, khong phai mot.

| Mo hinh | Chuoi | Freeze tuc thi? | Gas/transfer |
|---|---|---|---|
| **Pull (query dong bo)** | EVM, HSCS, CosmWasm | Co | +~9,300 gas |
| **Push (certificate co han)** | TON, SUI (khuyen nghi), Soroban | Khong — tre toi `expiry` | Verify chu ky cuc bo, re hon |

Mo hinh Push la mot **suy giam an ninh co the do luong duoc**: cua so ma mot tai khoan da bi freeze van chi tieu duoc = `expiry`. Dat `expiry = 1 gio` va ghi con so do vao SLA tuan thu. Voi luong B2B settlement gia tri cao, **khong dung mo hinh Push** — dung chuoi Pull. Do la mot rang buoc chon chain theo use case, khong phai mot chi tiet trien khai.

---

### 2.10. Kiem chung bat buoc (khong tin code, tin `pg_constraint` va chain)

**Odoo:**

1. `SELECT conname, contype FROM pg_constraint WHERE conrelid='blockchain_zether_account'::regclass;` phai co dong `u` (UNIQUE) — `_sql_constraints` dang list bi Odoo 19 bo qua **hoan toan**, khong warning.
2. Y het cho `blockchain_zether_account_chain` (UNIQUE `account_id, profile_id`) va `blockchain_chain_profile` (UNIQUE `evm_chain_id, company_id`).
3. `grep -rn "groups_id" dms_blockchain/` phai tra ve rong (Odoo 19 doi thanh `group_ids`).
4. Cai `dms_blockchain` tren mot DB **khong co `dms`** → phai thanh cong. Day la kiem chung truc tiep cua locked #7 va phai nam trong CI, khong phai lam thu cong.
5. Tao mot ban ghi voi moi `purpose` va moi nhanh cua `_compute_divergent` → `SELECT divergent FROM blockchain_zether_account WHERE divergent IS NULL;` phai tra 0 dong.

**Foundry:**

6. `register()` voi PoP hop le tu **hai** `msg.sender` khac nhau phai cho **storage diff giong het** (khong chi `isRegistered` giong nhau) — chung minh front-running vo hai (§2.2.2).
7. `register()` voi PoP tu chain khac (`chainid` khac trong challenge) phai revert `BadProofOfPossession`.
8. `register()` lan thu hai tren cung addr phai revert `AlreadyRegistered`, **khong** duoc thanh cong im lang (§2.2.3).
9. Fuzz: `(0,0)`, `pkX >= P`, `pkY >= P`, diem khong tren duong cong, `popS >= n`, `R = O` — tat ca phai revert.
10. **Invariant**: voi moi chuoi thao tac hop le, `keccak256(abi.encode(pkX, pkY)) == addr` luon dung, va `pkX`/`pkY` cua mot addr **khong bao gio** thay doi sau `register()` (§2.1.7 bat bien).
11. **Invariant**: `address(registry).balance == 0` va registry khong giu so du ERC-20 nao (§2.3f).
12. Sau `requestAuthRotation` + `executeAuthRotation`, chu ky bang authKey cu bi tu choi **o cung block** (khong co do tre) nho `authEpoch` trong digest (§2.4.2).
13. Freeze tren registry o block N → `transferConfidential` o block N+1 revert. Khong cache (§2.7.4).
14. `to` o trang thai `FROZEN`/`REVOKED`/`MIGRATED` van **nhan** duoc; chi `from` bi chan (§2.7.3).
15. Guardian veto 2 lan → lan xoay thu 3 dung `FORCE_DELAY` va guardian khong veto duoc (§2.7.1).
16. `applyAttestation` voi `targetChainId` sai phai revert; voi `epoch` cu hoac bang phai revert; voi `epoch` nhay > `MAX_EPOCH_GAP` phai revert (§2.8.2).
17. Bit-packing `meta`: fuzz 5 status × 8 scheme × epoch 2^64−1 × verifier ngau nhien → doc lai phai bang gia tri da ghi (**day la test chan lai bug §2.1.4**).

**Tren chain that:**

18. Probe `CurveCapability.hasBls12381()` tren Gnosis va Celo mainnet, **so sanh returndata chu khong chi `success`** (§2.5.5), ghi ket qua vao `blockchain.chain.profile` — khong hardcode.
19. Do gas thuc te cua `register()`, `assertUsable()`, `transferConfidential` tren Gnosis Chiado va Celo Alfajores; so voi bang uoc tinh §2.1.3 / §2.2.5 / §2.4.2. **Sai lech > 25% thi bang uoc tinh sai, sua bang, khong sua ky vong.**
20. Do gas that cua verify BLS12-381 min-sig tren mot chain co EIP-2537 → xac nhan hay bac bo con so 115,500 va do do bac bo hay xac nhan diem hoa von n ≈ 8 tren rollup (§2.5.4).
21. Do do tre thuc te end-to-end cua co che attestation (freeze tren canonical → mirror cap nhat) tren testnet, 100 mau, bao cao p50/p95/p99. Muc tieu p95 < 60 s (§2.8.3).

---

### 2.11. Bang so tong hop (de tra cuu nhanh)

| Dai luong | Gia tri | Co so |
|---|---|---|
| `register()` | ~105,750 gas | §2.2.5 |
| `register()` tren Gnosis @2 gwei | $0.00021 | xDAI = $1 |
| `register()` tren Ethereum L1 @10 gwei | $3.17 | ETH = $3,000 |
| Kiem tra registry trong `transferConfidential` | ~9,300 gas | §2.1.3 |
| Chi phi rong cua hash identity (vs point identity) | +3,176 gas | §2.1.2 |
| Schnorr PoP verify | 12,850 gas | §2.2.1 |
| ECDSA multisig 3-of-5 | ~14,120 gas | §2.4.2 |
| BLS12-381 min-sig verify | ~115,500 gas | §2.5.2 |
| BLS12-381 min-pubkey verify | ~153,100 gas | §2.5.2 |
| BLS bn254 verify | 150,000–180,000 gas | §2.5.2 |
| Hoa von BLS vs ECDSA, L1/Gnosis | n ≈ 29 | §2.5.4 |
| Hoa von BLS vs ECDSA, rollup (Celo) | **n ≈ 8** | §2.5.4 |
| FALCON-512 verify on-chain | 0.6M–2.5M gas ($0.003 Gnosis) | §2.6.2 |
| SLH-DSA-SHA2-128s verify on-chain | ~0.6M gas | §2.6.3 |
| EIP-7623 floor binh khi | `execution_gas < 24 × non_zero_bytes` | §2.1.1 |
| Storage/account | 4–6 slot = 128–192 B | §2.1.4 |
| Attestation 5-of-9 ECDSA | ~23,000 gas | §2.8.1 |
| Attestation/nam/chain (5,000 tai khoan) | ~609 | §2.8.3 |
| Tong chi phi attestation/nam/chain | ~$0.028 | §2.8.3 |
| Do tre freeze canonical → mirror, p95 muc tieu | 60 s | §2.8.3 |
| Cua so phoi nhiem mo hinh Push (TON/SUI/Soroban) | = certificate `expiry`, de xuat 1 gio | §2.9 |
| `ROTATION_DELAY` / `FORCE_DELAY` / `RECOVERY_DELAY` | 24 h / 14 ngay / 7 ngay | §2.7 |
| `selfFreeze()` khoa nguoc | 72 h | §2.7.3 |
| Chi phi 20,000 lan dang ky (5,000 tai khoan × 4 chain) | $4.20 tren Gnosis | §2.2.5 |
| Be tai tro $1,000 khong gate → so lan dang ky rac | 4.76 trieu, 457 MB state | §2.2.4 |

---

### 2.12. Cau hoi con mo (can quyet dinh cua nguoi, khong phai cua tai lieu)

1. **`encKey` va FIPS 140-2 L3 (§2.4.4).** Note cam ket HSM L3 cho moi private key. Khong lam duoc voi alt_bn128. Chap nhan TEE cho `encKey` va giu HSM cho `authKey`, hay dau tu HSM lap trinh duoc ($30k–80k, 3–6 thang)? **Day la cam ket voi khach hang, phai tra loi truoc khi ky.**
2. **FIPS 206 (§2.6.1).** Ai chiu trach nhiem kiem tra lai trang thai FIPS 206 truoc moi lan phat hanh tai lieu ban hang co chu "FALCON"? De xuat: mot muc trong checklist release.
3. **Chan troi HNDL cho B2B settlement (§2.6.6).** Chap nhan phuong an 1 (private chain), 2 (chap nhan rui ro co ghi nhan), hay 3 (khong dua so tien len chain chut nao — payment mode 4)? Ba phuong an nay co chi phi trien khai rat khac nhau.
4. **Travel Rule (§2.7.6).** Deployment nay co duoc coi la VASP theo phap luat Viet Nam khong? Neu co, `C_audit` la bat buoc va `y_audit` phai la khoa cua co quan nao? Neu khong, `C_audit` co the la tuy chon va tiet kiem 25,300 gas/transfer. Cau hoi phap ly, chuyen sang section 13.
5. **Nguong `MAX_EPOCH_GAP` va quy trinh re-anchor (§2.8.2).** Ai giu `pauseGuardian` cua moi mirror? De xuat: multisig 3-of-5 gom 2 ky thuat + 2 tai chinh + 1 phap che. Can xac nhan.
6. **Chinh sach so luong dia chi/phap nhan (§2.3b, §2.7.5).** 4–6 dia chi/phap nhan (khuyen nghi) hay 1 dia chi/doi tac (linkability tot hon nhung 800 bo Shamir)? Anh huong truc tiep den chi phi van hanh.
7. **Chain nao cho use case nao (§2.6.6, §2.9).** Bang phan tang da de xuat, nhung no khoa cung viec B2B settlement khong chay tren public chain. Neu khach hang muon B2B tren Gnosis vi ly do thuong mai, phai co van ban chap nhan rui ro HNDL.
8. **MuSig2 hay FROST cho tai khoan nhom (§2.4.3).** Neu nha cung cap MPC dang dung khong ho tro FROST tren bn254, `ECDSA_MULTISIG` la phuong an lui — nhung khi do gas cao hon va co cau nhom lo ra on-chain. Can hoi provider truoc khi chot.
