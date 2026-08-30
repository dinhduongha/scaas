## 01. Token Factory, vong doi Token va co che Peg/Wrap

### 1.0. Ket luan truoc, ly luan sau

Muoi hai quyet dinh cua section nay, de mot nguoi doc plan khong phai doc het:

| # | Quyet dinh | Muc |
|---|---|---|
| 1 | Proxy pattern = **Beacon**, mot `UpgradeableBeacon` cho moi cap `(archetype, majorVersion)`. Khong Diamond. Clone EIP-1167 chi cho token co chu y bat bien | 1.3 |
| 2 | Chuoi xac dinh dia chi co **ba tang**: deployer xac dinh to factory xac dinh to beacon xac dinh to proxy. Thieu mot tang la mat parity | 1.4 |
| 3 | `salt` cam ket ca `initData` bang hash, con `init_code` thi khong. Nho vay doi ten token khong doi dia chi ma van chong front-run `initialize()` | 1.4 |
| 4 | Them archetype moi = 1 tx `registerPrototype`, **khong** upgrade factory | 1.5 |
| 5 | Invariant `WRAP_1_1` la **`<=`**, khong phai `==`. Ai cung co the tang ton (donate) underlying vao vault | 1.6 |
| 6 | `PEG_RATIO` cho Z-VND: reserve **bang VND**, khong phai USDT. `FIXED_RATE` + spread hai chieu + hang doi redemption T+1 | 1.7 |
| 7 | Rang buoc that len decimals khong phai la decimals, ma la **`totalSupply` tinh theo raw unit phai `<= 2^44`** — do la tran chi phi giai ma Zether | 1.8 |
| 8 | Range proof width = **64 bit** (luy thua cua 2), tach hoan toan khoi tran giai ma. `2^48` trong ban nhap truoc la sai vi Bulletproofs can `n*m` la luy thua cua 2 | 1.8 |
| 9 | Bat bien chong in tien la **`confidentialLocked == balanceOf(address(this))`**, khong phai mot cong thuc tren "tong so du cong khai" (khong the liet ke on-chain) | 1.9 |
| 10 | `blacklist` mo: **tu choi tren public profile**. `pause` co tran 7 ngay, va loi thoat duy nhat khoi tran do la `WIND_DOWN` mot chieu | 1.10 |
| 11 | Upgrade: timelock 48h, executor mo, khong co duong tat. Guardian duoc phep **dung**, khong duoc phep **doi** | 1.11 |
| 12 | Con so quyet dinh kien truc: mot Zether transfer 64-bit ton **~1.9M gas**. Tren Gnosis (block limit ~17M, 5s) day la ~0.4 tx/s ben vung. Tren Besu QBFT zero-gas, tran that la CPU validator, ~20-45 tx/s | 1.12, 1.16 |

---

### 1.1. Pham vi, gia dinh an, va nhung cho `blockchain.md` con bo ngo

Note goc (dong 3-11) neu 6 yeu cau, tat ca deu dung y dinh nhung khong du de code:

| Yeu cau trong note | Trang thai | Xu ly o muc 1.2-1.11 |
|---|---|---|
| Tu mint (issuer token) | Ro | archetype `ISSUER_NATIVE` |
| Wrap ERC-20 san co (USDT to Z-USDT) | Thieu xu ly fee-on-transfer, blacklist cua underlying, decimals, donate, rebase | archetype `WRAP_1_1`, muc 1.6 |
| Mint/burn theo ty le (1 USDT to 25000 Z-VND) | **Thieu hoan toan**: ai chiu FX risk, rate tu dau, de-peg, redemption, spread, hang doi | archetype `PEG_RATIO`, muc 1.7 |
| "Mint/burn tu 1 hoac 1 **group** ERC-20" | **Chua ai thiet ke gio (basket)**: trong so, rebalance, NAV, N oracle = N diem gay | muc 1.7.6 |
| "Dung co che delegate de chia se code, khac data, support nhieu version" | Chua chon pattern; va note khong he nhac den ky luat storage layout — thu duy nhat lam `delegatecall` nguy hiem | muc 1.3, khuyen nghi Beacon |
| "Factory Contract de tu do create2" | Chua co cong thuc dia chi, chua noi salt gom gi, chua noi ai deploy chinh factory | muc 1.4 |
| "Co kha nang them nguyen mau Contract" | Chua co registry | muc 1.5 |

Bon thu note **khong** nhac den nhung chan moi thiet ke: **decimals cua VND**, **total-supply invariant khi mot token vua la ERC-20 cong khai vua giu so du Zether ma hoa**, **quyen upgrade thuoc ve ai**, va **tran giai ma quyet dinh tran cung tien**. Cac muc 1.8, 1.9, 1.11.

Truc **chain profile** (public/private, khoa quyet dinh #5) khong phai la mot truong config phu: no quyet dinh archetype nao duoc phep deploy, va tren private profile no con noi lien EIP-170 (xem 1.16). Model chinh tac la `blockchain.chain` voi truong `chain_profile` (dinh nghia o §08.1 va §10.4.2); section nay khong dinh nghia lai model do.

#### 1.1.1. Muoi hai gia dinh an — noi ra de con kiem chung duoc

Ban nhap dau tien im lang ve muoi hai dieu duoi day. Moi dong la mot cho co the lam hong he thong ma khong ai thay truoc.

| # | Gia dinh an | Neu sai thi sao | Kiem chung o dau |
|---|---|---|---|
| A1 | Co mot khoa nao do deploy duoc `DmsTokenFactory`, va khoa do khong bao gio mat | Mat khoa = khong deploy duoc token moi tren chain do, **va** mat parity dia chi cross-chain vinh vien | 1.4, 1.11 |
| A2 | `initialize()` khong bi front-run giua `CREATE2` va lan goi dau | Ke tan cong lam admin cua token ta vua deploy | 1.4 |
| A3 | `solc` build la deterministic | Cung source, hai may, hai `init_code`, hai dia chi. Mac dinh solc **khong** deterministic | 1.14 |
| A4 | Code cham dat tai dia chi du doan chinh la code ta muon | Metamorphic contract / squatting | 1.2, 1.4 |
| A5 | Chain da co Cancun (EIP-6780) | Implementation chua `initialize` co the bi chiem va `SELFDESTRUCT` to brick toan bo N proxy | 1.3 |
| A6 | `underlying.balanceOf(vault)` chi doi qua wrap/unwrap | Donate + rebase pha vo bat bien `==` | 1.6 |
| A7 | Reserve off-chain doi soat duoc tuc thi | Mint on-chain nhanh hon tien ve tai khoan. Can `in_flight` buffer va mint cap | 1.7 |
| A8 | Mot rate duy nhat dung chung cho mint va redeem | Round-trip arbitrage quanh moi lan cap nhat oracle, mien phi | 1.7.3 |
| A9 | `totalSupply` khong lien quan gi den kha nang giai ma so du Zether | Sai. `totalSupply` raw chinh la khong gian tim kiem BSGS | 1.8 |
| A10 | Odoo la nguon su that | Chain la nguon su that; Odoo la ban chieu. Huong doi soat phai duoc phat bieu, khong duoc suy dien | 1.13 |
| A11 | Mot token = mot lan deploy | Cron chay hai lan, hai broadcast, hai dia chi, mot record | 1.13 |
| A12 | Block gas limit du cho mot Zether tx | 128-bit range proof (~3.5M) chiem 20% mot block Gnosis. Tren mot so L2 no khong vao noi mot block | 1.12 |

---

### 1.2. Nguyen tac chu dao: "deploy khong phai la da co token"

Ap dung nguyen tac `dms_vietqr` ("quet QR khong phai la da thu tien") vao vong doi contract. Mot `CREATE2` da broadcast **khong** la mot token dang ton tai. State machine cua `blockchain.token`:

```
draft -> predicted -> broadcast -> pending_finality -> verified -> live
                          |              |               |          |
                          v              v               v          v
                       failed         failed          mismatch    paused -> wind_down -> retired
```

So voi ban nhap, them mot trang thai: **`verified`**. Ly do la gia dinh A4. Giua `pending_finality` va `live` phai co mot buoc **kiem tra code that su nam o dia chi do**, chu khong chi kiem tra receipt `status == 1`:

```python
def _verify_deployed_code(self):
    """Chay sau finality, truoc khi set live. Ba phep kiem, khong phep nao bo duoc."""
    for tok in self:
        code_hash = tok._rpc_extcodehash(tok.contract_address)          # eth_getCode + keccak
        if code_hash != tok.prototype_id.expected_proxy_code_hash:
            tok.deploy_state = 'mismatch'; continue
        if tok._rpc_call('beacon()') != tok.prototype_id.beacon_address:
            tok.deploy_state = 'mismatch'; continue
        if tok._rpc_call('owner()') != tok.chain_id.governance_safe:
            tok.deploy_state = 'mismatch'; continue
        tok.deploy_state = 'live'
```

`live` chi duoc set boi Finality Gate **cong** ba phep kiem tren. Nguong finality doc tu `blockchain.chain.finality_hard_blocks` / `finality_hard_seconds` (Gnosis: 2 epoch ~12.8 phut cho hard; 1 block ~5s cho soft — xem §08). Truoc do moi RPC tra ve dia chi deu phai kem `deploy_state`, va client **khong duoc phep** mint vao mot token o trang thai `broadcast`.

Ly do khong phai ly thuyet: reorg tren Gnosis truoc finality checkpoint la co that, va mot `CREATE2` bi reorg de lai mot dia chi da duoc ghi vao Odoo nhung khong co code. Sau reorg, dia chi do **van du doan duoc boi bat ky ai** — ke tan cong chi can doc `TokenDeployed` event da bi reorg, tinh lai salt, va deploy truoc ta bang chinh Arachnid deployer neu factory cua ta khong permissioned. Trang thai `mismatch` la mot incident, khong phai mot warning.

---

### 1.3. Proxy pattern: EIP-1167 vs UUPS vs Beacon vs Diamond

Yeu cau cua note la "chia se code, khac data, support nhieu version". Bon lua chon khong tuong duong nhau:

| Pattern | Deploy gas/token | Upgrade N token | Overhead call **lanh** (lan dau/tx) | Overhead call **am** | Dia chi du doan co on dinh qua cac version? | Hiem hoa storage |
|---|---|---|---|---|---|---|
| EIP-1167 minimal proxy | ~45,000 | **Khong the** (impl hardcode trong 45 byte runtime) | ~2,700 | ~150 | **Khong** — doi impl la doi `init_code` la doi dia chi tuong lai | Khong co (khong upgrade) |
| UUPS (ERC-1822) | ~200,000 - 240,000 | **N transaction** | ~4,800 (SLOAD lanh 2,100 + DELEGATECALL lanh 2,600) | ~200 | **Khong** — cung ly do | Impl quen ke thua `UUPSUpgradeable` to brick vinh vien |
| Beacon proxy | ~200,000 - 240,000 | **1 transaction cho ca N** | **~9,400** (SLOAD 2,100 + STATICCALL 2,600 + SLOAD trong beacon 2,100 + DELEGATECALL 2,600) | ~400 | **Co** — `init_code` chi chua dia chi beacon | Blast radius = toan bo N token |
| Diamond (EIP-2535) | ~400,000+ | 1 `diamondCut`/proxy | ~4,900 (SLOAD selector map 2,100 + DELEGATECALL 2,600) | ~200 | Co (voi `DiamondCutFacet` co dinh) | Cao nhat: AppStorage/Diamond Storage phai ky luat tuyet doi |

**Sua so lieu so voi ban nhap:** ban nhap ghi Beacon `~4,800` va Diamond `~4,800` — sai o hai cho. Beacon co **mot external call phu** (STATICCALL sang beacon) ma Diamond khong co, nen Beacon dat hon Diamond, khong bang nhau. Con so lanh cho Beacon la **~9,400**, khong phai 4,800. Con so nay chi phat sinh **mot lan cho moi transaction** (sau do dia chi beacon va impl da warm, cost ve ~400). Voi mot `transfer` don le do la ~9,000 gas tren tong ~46,000 — **20% overhead**, khong phai 10%. Con so nay la co so cho quyet dinh o 1.12.

**Khuyen nghi: Beacon proxy, mot `UpgradeableBeacon` cho moi cap (archetype, majorVersion), deploy qua CREATE2.**

Ly do, xep theo suc nang:

1. **Ky ban an cua UUPS trong bai toan nay la N transaction de va mot lo hong.** Neu ban co 40 token loyalty cua 40 nha phan phoi va can va gap, 40 tx tren 2 chain la 80 tx phai dieu phoi qua timelock, moi tx mot co hoi that bai rieng. Beacon lam viec do bang 1 tx moi chain.
2. **Beacon la pattern duy nhat giu dia chi du doan on dinh qua cac version** — cot moi ma ban nhap bo sot. Voi UUPS va voi clone, `init_code` chua dia chi implementation. Doi implementation to doi `keccak256(init_code)` to **moi dia chi du doan trong tuong lai deu doi**. Neu ta hua voi doi tac "dia chi Z-VND cua ban se la 0x..." roi va mot lo hong, loi hua do gay. Voi Beacon, `init_code = BeaconProxy.creationCode ++ abi.encode(beacon, "")` — khong co impl trong do.
3. EIP-1167 re nhat va an toan nhat nhung mau thuan truc tiep voi "support nhieu version". No van co cho: mot token phat hanh cho ben thu ba yeu cau bat bien (immutability) thi deploy bang clone, va **ghi ro trong `blockchain.token.upgradeable = False`**.
4. Diamond: **khong dung cho token.** Ly do khong phai gas ma la audit surface va tooling. Blockscout cua Gnosis va explorer cua Celo verify Diamond rat kem (moi facet phai verify rieng, va giao dien "Read/Write contract" khong gop lai), `diamondCut` mo rong be mat tan cong bang so facet, va Diamond Storage sai mot slot la mat tien. Diamond chi giai quyet duoc **mot** van de that: gioi han 24,576 byte (EIP-170).

**Ve EIP-170, va tai sao no khong con la ly do chon Diamond:**

- Neu `ZToken` + Zether + Bulletproofs verifier vuot 24KB tren **public profile**, giai phap re hon la tach `BulletproofVerifier` thanh mot contract **stateless** goi bang `staticcall`, khong phai facet: cung chia se code, khong co Diamond Storage, va verifier co the duoc audit doc lap va tai su dung cho moi token.
- Chi phi cua viec tach: mot `staticcall` lanh (2,600 gas) cong voi chi phi copy calldata cua proof (~1.3 KB to ~700 gas memory + copy). Tong ~3,500 gas tren mot giao dich ~1.9M — **0.18%**. Doi lay mot contract duoi 24KB va mot audit boundary sach. Khong co ly do gi de chon Diamond.
- Tren **private profile** (Besu, §1.16), `contractSizeLimit` la mot tham so genesis va co the dat 64KB. Nhung **khong duoc dua vao dieu do**: neu source cua public build va private build khac nhau, ta co hai codebase. Quy tac: **moi contract phai fit 24,000 byte tren moi profile**; CI enforce (1.14).

**Hiem hoa storage collision, cu the cho tung pattern:**

1. ERC-1967 dat impl o slot `keccak256("eip1967.proxy.implementation") - 1` = `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`, beacon o `keccak256("eip1967.proxy.beacon") - 1` = `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50`, admin o `keccak256("eip1967.proxy.admin") - 1` = `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`. Tru 1 la de khong slot Solidity nao roi trung (khong ton tai preimage cho `keccak(x) - 1` ma solc sinh ra). **Tuyet doi khong tu che slot.**
2. Doi thu tu ke thua giua hai version se **im lang** doi map slot. Chong bang **ERC-7201 namespaced storage**: moi module giu struct rieng tai
   `keccak256(abi.encode(uint256(keccak256("dms.blockchain.token.v1")) - 1)) & ~bytes32(uint256(0xff))`.
   Khi do thu tu ke thua khong con y nghia, va bo `__gap[50]` co dien tro nen khong can thiet. **Rang buoc bat buoc di kem:** ten namespace **khong duoc chua so version cua implementation**. `"dms.blockchain.token.v1"` la ten cua *lop du lieu*, khong phai cua *lan build*. Doi ten namespace giua hai implementation = mat toan bo state cua N token trong mot tx. Day la cach nhanh nhat de xoa so mot he thong Beacon, va no khong revert.
3. `constructor` **khong chay tren proxy**. Moi gia tri `immutable` set trong constructor la gia tri cua *implementation*, khong phai cua token. Bat buoc: `initialize()` voi modifier `initializer`, va constructor cua implementation phai goi `_disableInitializers()`. Bo qua buoc nay thi ke tan cong `initialize()` chinh implementation. Voi UUPS ho goi tiep `upgradeToAndCall` va `SELFDESTRUCT` implementation, brick toan bo N proxy. **EIP-6780 (Cancun) da lam SELFDESTRUCT bot nguy hiem — nhung chi tren chain da co Cancun.** Gnosis da fork Dencun; mot chain private Besu chay client cu, hoac mot chain trong 5 he sinh thai con lai, co the chua. Gia dinh A5 phai duoc kiem chung bang mot test on-chain thuc te tren moi chain truoc khi deploy, khong bang doc changelog.
4. `MAX_AMOUNT()` trong note (`blockchain.md`, interface `IZetherToken`) khai bao la `external pure`. **Voi Beacon proxy dieu do co nghia la moi token dung chung mot beacon deu co cung tran.** Neu Z-VND can tran khac Z-USDT ma hai token dung chung archetype, `pure` lam dieu do bat kha thi. Sua thanh `external view` doc tu bien duoc set trong `initialize()`. Day la mot loi cu the trong note, khong phai mot y kien.
5. CI gate: luu `storage-layouts/v<N>/*.json` vao repo, moi PR chay `forge inspect <c> storageLayout` va OpenZeppelin `validateUpgrade` doi chieu voi version da deploy. Khong co gate nay thi ky luat o (2) chi la loi hua.

**Giam blast radius cua Beacon** (nhuoc diem duy nhat that su): mot beacon cho moi archetype **va** moi risk tier, cong them `PinnedProxy` — mot bien the doc `implementation()` mot lan trong `initialize()` roi ghi cung vao slot ERC-1967 cua chinh no, khong bao gio doc lai beacon. Token nao muon "khong ai upgrade duoc toi" thi deploy `PinnedProxy`.

`PinnedProxy` co mot hau qua ke toan phai noi ro: no **khong** re hon BeaconProxy khi call (van la 1 SLOAD + 1 DELEGATECALL = ~4,800 lanh) nhung no **re hon 4,600 gas** vi bo duoc STATICCALL sang beacon. Voi mot token co 1M transfer/nam tren Gnosis, do la 4.6e9 gas = ~6.9 xDAI/nam o 1.5 gwei. Khong dang ke ve tien; dang ke ve viec no cat duoc rui ro upgrade.

---

### 1.4. CREATE2 va du doan dia chi

```
address = keccak256(0xff ++ factory ++ salt ++ keccak256(init_code))[12:32]
```

#### 1.4.1. Chuoi xac dinh ba tang

Ban nhap chi noi ve tang thu ba. Thuc te muon `predictAddress()` tra ra cung mot dia chi tren Gnosis va Celo, ca **ba** tang phai xac dinh:

```
Tang 1: deployer      -> Arachnid 0x4e59b44847b379578588920cA78FbF26c0B4956C (hoac EIP-2470 0xce0042B868300000d44A59004Da54A005ffdcf9f)
Tang 2: factory       -> CREATE2 tu tang 1, salt = keccak256("dms.blockchain.factory.v1")
Tang 3: beacon        -> CREATE2 tu tang 2, salt = keccak256("beacon" | archetype | majorVersion)
Tang 4: token proxy   -> CREATE2 tu tang 2, salt = xem 1.4.3, init_code chua dia chi beacon (tang 3)
```

Gay mot tang la gay tat ca tang duoi. Cu the: neu beacon cua `WRAP_1_1 v1` nam o dia chi khac nhau tren hai chain, thi moi token `WRAP_1_1 v1` cung co dia chi khac nhau, du salt giong het. Ban nhap bo sot phu thuoc nay.

#### 1.4.2. Bay so 1 — `initData` trong `init_code`

Voi `BeaconProxy`, `init_code = type(BeaconProxy).creationCode ++ abi.encode(beacon, data)`. Neu `data` la calldata cua `initialize(name, symbol, ...)` thi **doi ten token la doi dia chi**. Xu ly: luon deploy voi `data = ""`.

Nhung `data = ""` mo ra bay so 2.

#### 1.4.3. Bay so 2 — front-run `initialize()` (gia dinh A2)

Voi `data = ""`, contract sinh ra chua duoc initialize. Neu factory deploy o tx 1 va initialize o tx 2, bat ky ai cung co the chen giua va goi `initialize()` truoc, tro thanh admin. Ba lop chong, phai co **ca ba**:

1. **Atomic**: factory `deploy()` goi `CREATE2` roi `token.initialize(...)` **trong cung mot ham**, mot transaction. Khong bao gio de khoang trong.
2. **Factory-only guard**: `initialize()` co `require(msg.sender == FACTORY)`. `FACTORY` la mot `immutable` cua *implementation* (constructor cua implementation chay binh thuong, gia tri nay dung cho moi proxy tro toi no). Ke ca khi ai do dua duoc mot proxy chua init vao trang thai lo, ho khong initialize duoc.
3. **Salt cam ket `initData`**: dia chi phai phu thuoc vao noi dung khoi tao, nhung `init_code` thi khong duoc. Giai bang cach dua hash cua initData vao salt:

```solidity
bytes32 salt = keccak256(abi.encode(
    uint64(issuerOrgId),      // dinh danh to chuc phat hanh, khong phai ten
    bytes32(archetype),       // keccak256("PEG_RATIO")
    bytes8(assetCode),        // "ZVND", "ZUSDT"
    uint16(series),           // 0, 1, 2... cho phep re-deploy sau khi retire
    keccak256(initData)       // <-- cam ket noi dung khoi tao MA KHONG nam trong init_code
));
```

Ket qua: `predictAddress(salt)` van tra loi duoc truoc khi deploy (client tu tinh `keccak256(initData)`), dia chi cam ket vao `name`/`symbol`/`decimals`/`maxSupply`, va `init_code` van chi phu thuoc beacon. Day la thu ban nhap thieu.

Khong dua `chainId` vao salt: ta *muon* cung dia chi tren nhieu chain. `chainId` da nam trong EIP-712 domain separator o tang meta-tx (§04), do la cho dung cua no.

#### 1.4.4. Bay so 3 — squatting va metamorphic

Neu `DeterministicFactory.deploy()` la **permissionless**, bat ky ai doc duoc `PrototypeRegistered` event cung tinh duoc dia chi tuong lai cua ta va deploy truoc voi initData cua ho. Ho khong chiem duoc dia chi cua ta (salt khac vi `keccak256(initData)` khac) nhung ho **rac dia chi** va lam nhieu indexer.

Xu ly cu the: `deploy()` gan `DEPLOYER_ROLE`. Deploy tu do khong phai la mot yeu cau nghiep vu — note viet "tu do create2" voi nghia "khong phai sua factory moi them duoc kieu token", va yeu cau do duoc `registerPrototype` (1.5) dap ung day du.

**Metamorphic:** truoc EIP-6780, mot contract co the `SELFDESTRUCT` roi duoc `CREATE2` lai cung dia chi voi code khac. Tren chain chua Cancun, dieu nay bien "dia chi = danh tinh" thanh sai. Xu ly: `BeaconProxy` khong co `SELFDESTRUCT`; nhung `expected_proxy_code_hash` trong Odoo (1.2) phai duoc **kiem lai dinh ky**, khong chi mot lan luc deploy. Mot cron hang ngay so `EXTCODEHASH` cua moi token `live` voi gia tri da luu; lech = incident.

#### 1.4.5. Deployer co san khong?

Arachnid deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C` duoc bootstrap bang mot **pre-EIP-155 signed transaction** (nonce 0 tu `0x3fab184622dc19b6109349b94811493bf2a45362`, gas price 100 gwei, gas limit 100,000 to can 0.01 ETH-tuong-duong tren chain do). Chain khong chap nhan legacy tx thi khong co san.

Kiem chung bang mot lenh, khong bang doc doc:

```bash
cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url $RPC
# khac "0x" = co san
```

- Gnosis: co san.
- Celo: **phai kiem lai.** Celo L1 dung cac transaction type rieng va tung han che legacy tx; sau khi Celo chuyen sang L2 tren OP Stack (2025) thi ho tro tx type chuan. Chay lenh tren truoc khi chot kien truc parity.
- Private Besu: ta tu bootstrap bang chinh presigned tx do (funding 0.01 native cho `0x3fab18...` roi broadcast raw tx). Neu chain o che do zero-gas thi buoc funding bo qua.

#### 1.4.6. Khuyen nghi thuc dung ve parity

Coi cross-chain address parity la *nice-to-have*, khong phai rang buoc. Client cua ta **khong bao gio hardcode dia chi** — no resolve tu `blockchain.token` qua RPC (`blockchain_list_tokens`). Neu parity kho tren mot chain, ghi nhan dia chi khac nhau va di tiep; dung dinh CI vao mot rang buoc khong can thiet.

Cai *phai* co, va khac han parity, la **tinh tai lap (reproducibility)**: cung salt + cung factory + cung beacon phai luon ra cung dia chi, tren cung mot chain, tu bat ky may nao. Cai do la CI gate (1.14), va no phu thuoc `bytecode_hash = "none"`.

---

### 1.5. Prototype / Implementation Registry

Yeu cau "co kha nang them nguyen mau Contract" duoc thoa man bang mot registry on-chain, **khong** bang cach sua factory:

```solidity
struct Prototype {
    bytes32 archetype;       // keccak256("WRAP_1_1")
    uint16  majorVersion;
    address beacon;          // != 0 => BeaconProxy
    address implementation;  // != 0 && beacon == 0 => EIP-1167 clone (bat bien)
    bytes32 initCodeHash;    // keccak256(init_code) — de predictAddress khong can rebuild bytecode
    bytes32 implCodeHash;    // EXTCODEHASH ky vong cua implementation, de Odoo doi chieu
    uint8   profileMask;     // bit0 = public chain, bit1 = private chain
    bytes4  interfaceId;     // ERC-165: indexer phan loai contract khong can registry
    bool    deprecated;
}

interface IContractPrototypeRegistry {
    function registerPrototype(Prototype calldata p) external;              // PROTOTYPE_ADMIN + timelock 48h
    function deprecatePrototype(bytes32 archetype, uint16 v) external;      // GUARDIAN, tuc thi
    function prototypeOf(bytes32 archetype, uint16 v) external view returns (Prototype memory);
    function predictAddress(bytes32 archetype, uint16 v, bytes32 salt) external view returns (address);
    function deploy(bytes32 archetype, uint16 v, bytes32 salt, bytes calldata initData)
        external returns (address token);                                   // DEPLOYER_ROLE

    event PrototypeRegistered(bytes32 indexed archetype, uint16 indexed majorVersion,
                              address beacon, bytes32 initCodeHash, uint8 profileMask);
    event PrototypeDeprecated(bytes32 indexed archetype, uint16 indexed majorVersion, bytes32 reason);
    event TokenDeployed(bytes32 indexed archetype, uint16 majorVersion, bytes32 indexed salt,
                        address indexed token, bytes32 initDataHash);
}
```

So voi ban nhap, them bon truong va mot event, moi thu deu co ly do van hanh:

- `initCodeHash`: `predictAddress` off-chain (trong Odoo, bang Python) khong phai giu ban sao bytecode cua `BeaconProxy`. Doc mot lan tu chain, cache trong `blockchain.token.prototype`.
- `implCodeHash`: buoc verify o 1.2 can no. Neu chi luu trong Odoo thi mot Odoo bi xam nhap tu sua ky vong cua chinh no.
- `interfaceId` (ERC-165): indexer (§11) phan loai mot dia chi la `WRAP_1_1` hay `PEG_RATIO` **khong can** goi registry. Voi mot chain co hang tram token, mot `supportsInterface` re hon mot vong loop registry.
- `PrototypeDeprecated` co `reason` (bytes32): khi guardian deprecate luc 3 gio sang, cai ma nguoi truc can la ly do, khong phai mot event trong.
- `TokenDeployed` index ca `salt` va `token`: indexer tra nguoc tu dia chi ve salt duoc.

`profileMask` la truc chain profile o tang contract: registry tu choi `deploy` mot archetype `permissioned` tren chain public va nguoc lai. Contract khong tu biet minh dang o chain nao ngoai `block.chainid`, nen `profileMask` duoc doi chieu voi mot bien `PROFILE` set luc deploy registry (`immutable`, mot registry moi chain).

Them archetype moi (vi du `REVENUE_SHARE_TOKEN` sau nay) = 1 tx `registerPrototype` + 1 record Odoo. Factory khong bao gio phai upgrade.

`deprecatePrototype` khong xoa: token da deploy van chay. No chi chan `deploy` moi. Dieu nay phai duoc noi ro voi doi van hanh: **deprecate khong cuu duoc mot lo hong dang bi khai thac tren cac token da song** — cai do la `pause` (1.10) roi `upgrade` (1.11).

---

### 1.6. Ba nguon goc token

| Archetype | Contract | Collateral | Invariant kiem tra duoc on-chain |
|---|---|---|---|
| `ISSUER_NATIVE` | `IssuerNativeToken` | Khong | `totalSupply() <= maxSupply` |
| `WRAP_1_1` | `WrappedToken` + `ReserveVault` | 1:1 cung asset | `totalSupply() <= reserveAccounted && reserveAccounted <= underlying.balanceOf(vault)` |
| `PEG_RATIO` | `PeggedToken` + `PegController` + `ReserveVault` | 1 hoac gio ERC-20, hoac reserve off-chain | `totalSupply() <= mulDiv(reserveValue(), rateNum, rateDen)` |

#### 1.6.1. `WRAP_1_1` — bay cu the

**Sua so voi ban nhap:** invariant khong phai `totalSupply() == underlying.balanceOf(vault)`. Dang `==` sai vi hai huong:

- **Donate.** Bat ky ai cung co the `underlying.transfer(vault, x)`. Khi do `balanceOf(vault) > totalSupply()` va mot invariant test dang `==` se fail tren mot hanh vi vo hai. Te hon: neu code contract *tin* vao dang `==` (vi du tinh redeem theo `balanceOf`) thi donate tro thanh mot vector thao tung.
- **Rebase.** Neu underlying la aToken, stETH, hay bat ky token rebasing nao, `balanceOf(vault)` thay doi ma khong co ai goi ham nao. Dang `==` gay ngay lap tuc.

Thiet ke dung: giu mot bien ke toan noi bo.

```solidity
uint256 public reserveAccounted;   // chi thay doi trong wrap/unwrap

function wrap(uint256 amountIn, address to) external nonReentrant {
    uint256 before = underlying.balanceOf(address(this));
    underlying.safeTransferFrom(msg.sender, address(this), amountIn);
    uint256 received = underlying.balanceOf(address(this)) - before;   // fee-on-transfer safe
    reserveAccounted += received;
    _mint(to, received);                                               // 1:1 raw unit
}

function sweepDonation(address to) external onlyRole(TREASURY_ROLE) {
    uint256 excess = underlying.balanceOf(address(this)) - reserveAccounted;
    require(excess > 0, "no excess");
    underlying.safeTransfer(to, excess);
    emit DonationSwept(to, excess);
}
```

Invariant `totalSupply() == reserveAccounted` (cai nay dung dang `==`) **va** `reserveAccounted <= underlying.balanceOf(vault)`.

Voi rebasing token: **tu choi wrap** o tang registry. `WRAP_1_1` khong ho tro rebasing underlying, cham het. Muon ho tro thi do la mot archetype khac (`WRAP_SHARES`, kieu ERC-4626) — khong lam trong v1.

Bay con lai:

1. **Fee-on-transfer.** USDT tren Ethereum co `basisPointsRate` (hien 0, nhung code song, va contract la upgradeable proxy nen "hien 0" khong phai la bao dam). USDT bridge sang Gnosis/Celo la contract khac voi behaviour khac. **Khong bao gio tin tham so `amount`**: do `balanceAfter - balanceBefore` nhu tren.
2. **USDT khong tuan thu ERC-20**: `transfer`/`approve` khong return bool tren mainnet. Dung `SafeERC20`. Va `approve` phai ve 0 truoc khi set gia tri moi.
3. **Underlying co the freeze vault.** USDC/USDT co the blacklist dia chi vault. Khi do Z-USDT van transfer duoc nhung khong redeem duoc — de facto de-peg tren mot tai san ta da hua la 1:1. Bat buoc co state `REDEMPTION_HALTED` phat `event RedemptionHalted(bytes32 reason)`, **khong duoc de `redeem` revert im lang**. Mot `revert` khong co ly do la mot su co ho tro khach hang; mot event co ly do la mot muc trong incident log.
4. **Underlying la mot proxy va co the doi hanh vi ngay mai.** USDT, USDC deu upgradeable. Ta khong the audit mot muc tieu di dong. Xu ly toi thieu: mot cron doc `EXTCODEHASH` cua implementation cua underlying hang ngay; doi = canh bao, khong tu dong halt (halt tu dong tren mot upgrade routine cua Circle la mot su co tu gay ra).
5. **Decimals**: **mirror y het underlying**, khong "chuan hoa ve 18". Doc bang `underlying.decimals()` **tai thoi diem initialize** va luu vao storage; khong hardcode trong Odoo. Wrap 1:1 theo raw unit thi rounding = 0, dust = 0, va invariant la mot phep so sanh bang. Bat ky phep scale nao cung tao ra mot huong lam tron. Luu y phu: `decimals()` **khong** thuoc interface ERC-20 bat buoc; mot underlying kho tinh co the khong co ham do. Neu khong co, tu choi wrap.

#### 1.6.2. `ISSUER_NATIVE`

Don gian nhat, nhung `maxSupply` phai la `immutable`-tuong-duong (set trong `initialize`, khong co setter). Mot `maxSupply` co the tang duoc thi khong phai la tran, no la mot cai nut.

Hai thu ban nhap thieu:

- **`maxMintPerEpoch`.** `maxSupply` bao ve tong; no khong bao ve toc do. Mot khoa MINTER bi lo co the in het `maxSupply` trong mot block. Them `uint256 mintedThisEpoch` + `uint64 epochLength` (mac dinh 1 ngay) + `require(mintedThisEpoch + amount <= maxMintPerEpoch)`. Dat `maxMintPerEpoch` = 2% `maxSupply`: mot ke tan cong can 50 ngay, con doi truc co 24 gio de phat hien.
- **`maxSupply` cung la tran giai ma Zether.** Xem 1.8. `require(maxSupply <= MAX_DECRYPTABLE_RAW)` trong `initialize()` — mot dong, va no chan mot lop loi khong the sua sau khi da mint.

---

### 1.7. `PEG_RATIO`: ai chiu FX risk, rate tu dau, de-peg

Vi du trong note — `1 USDT -> 25000 Z-VND` — **khong phai la mot peg. No la mot loi hua hoan tra, va no la mot vi the short USD cua issuer.**

Neu ty gia thi truong ve 27,000 VND/USD ma ta van cam ket doi 25,000 Z-VND lay 1 USDT, moi 25,000 Z-VND redeem lam issuer mat 2,000 VND gia tri kinh te. Dinh luong: float 10 ty VND (= 400,000 USDT o rate 25,000), VND mat gia 6%/nam (2024 VND mat khoang 4.5-5% so voi USD — uoc tinh, co so la bien dong ty gia trung tam) to **~24,000 USDT P&L mot nam**. Con so nay phai la mot dong trong `account.move`, khong phai mot bat ngo.

#### 1.7.1. Ba che do, va cai nao dung cho cai gi

| Che do | Ai chiu FX | Redemption guarantee | Dung khi nao |
|---|---|---|---|
| `FIXED_RATE` | **Issuer** | Luon dung ty le da cong bo | Loyalty/reward diem, closed-loop. Ty le la *chinh sach thuong mai*, khong phai ty gia |
| `ORACLE_RATE` | **Holder** | Theo rate tai thoi diem redeem | Khi Z-VND that su muon la stablecoin VND |
| `RESERVE_FLOAT` | Chia se qua bo dem over-collateral | Theo rate, halt khi CR thap | B2B settlement co quy du phong |

**Khuyen nghi cho ca ba use case trong scope:** dung `FIXED_RATE`, **nhung dat reserve bang VND, khong phai USDT**. Sai lam cot loi la giu tai san USDT doi ung mot nghia vu ghi bang VND. Neu token la Z-VND thi:

- reserve la so du VND o mot tai khoan ngan hang tach biet (hoac tai san thanh toan bang VND);
- chan USDT chi la **on-ramp mot chieu**, quy doi theo spot rate **tai thoi diem nap**, doc tu oracle **chi tai bien gioi do**;
- redemption guarantee phat bieu bang VND: 25,000 Z-VND doi 25,000 VND. Khong bao gio phat bieu bang USDT.

Lam vay thi FX mismatch bien mat hoan toan, va `1 USDT -> 25000 Z-VND` tro thanh mot ty gia tuc thoi chu khong phai mot cam ket vinh vien.

#### 1.7.2. Mint cap khi reserve nam ngoai chain (gia dinh A7)

Ban nhap bo qua do tre thanh toan. On-chain mint la tuc thi; tien VND vao tai khoan la T+0 den T+2. Neu contract cho phep mint theo attestation gan nhat, ta mint truoc khi tien den.

Cong thuc mint cap bat buoc, danh gia o moi lan mint:

```
mintable = attested_reserve_minor
         - totalSupply_in_minor
         - in_flight_redemption_minor        // da requestRedeem, chua settle
         - safety_buffer_minor               // mac dinh 2% attested_reserve
```

`attested_reserve_minor` co **staleness**. Quy tac cu the:

| Tuoi attestation | Mint | Redeem | Ghi chu |
|---|---|---|---|
| <= 7 ngay | Binh thuong | Binh thuong | — |
| 8 - 35 ngay | Cho phep, nhung `safety_buffer` tang len 10% | Binh thuong | Canh bao |
| 36 - 60 ngay | **Chan** | Binh thuong | Incident |
| > 60 ngay | Chan | Chan mint, redeem pro-rata theo CR gia dinh = 100% | Chuyen `UNDERCOLLATERALIZED` |

Ly do khong bao gio chan redeem theo staleness: staleness la loi cua issuer, khong phai cua nguoi giu token.

#### 1.7.3. Spread — thu ban nhap bo sot va no la mot lo hong kinh te

Neu `mintRate == redeemRate` va khong co phi, thi moi lan oracle cap nhat la mot co hoi arbitrage khong rui ro: ke tan cong mint ngay truoc khi rate tang va redeem ngay sau, an tron delta, va tien do ra thang tu reserve. Voi circuit breaker 2%/lan cap nhat (duoi day) va 96 lan cap nhat/ngay, be mat mat mat toi da la khong gioi han.

Bat buoc co spread hai chieu:

```solidity
// spreadBps ap dung doi xung, luon co loi cho reserve
uint256 mintRate   = Math.mulDiv(oracleRate, 10_000 - spreadBps, 10_000);   // nguoi mint nhan it Z hon
uint256 redeemRate = Math.mulDiv(oracleRate, 10_000 + spreadBps, 10_000);   // nguoi redeem tra nhieu Z hon
```

Chon `spreadBps`: phai `>= ` bien dong toi da giua hai lan cap nhat. Voi breaker 200 bps/lan cap nhat, `spreadBps >= 100` (1%) la nguong toi thieu ly thuyet. Thuc dung cho VND/USD (bien dong ngay thuong duoi 30 bps): **`spreadBps = 50`** (0.5%), cong `redemptionDelaySeconds = 86400` cho moi khoan redeem vuot 100 trieu VND. Do tre nay la thu bien arbitrage tu "khong rui ro" thanh "co rui ro qua dem", va do la du.

Voi `FIXED_RATE` khong dung oracle, spread co the = 0 — nhung khi do phai co `redemptionDelay` va `dailyRedemptionCap`, vi rui ro khong con la arbitrage ma la bank run.

#### 1.7.4. Nguon rate, xep theo do tin cay

1. **AMM TWAP** — **loai bo cho VND**. Khong co pool VND thanh khoan on-chain. Thao tung mot pool sau $50k trong mot block ton khoang $1-2k voi flashloan; ke tan cong mint theo rate gia. Chi chap nhan neu depth >= $5M va TWAP >= 30 phut, dieu khong ton tai voi VND.
2. **Oracle ben thu ba** — Chainlink khong co feed VND/USD tren Gnosis hay Celo (kiem chung tai `data.chain.link` truoc khi chot; tinh den thoi diem viet la khong co). Thuc te la **ta phai tu van hanh feed**:

```solidity
struct SignedRate {
    bytes32 pair;            // keccak256("VND/USD")
    uint128 price;           // gia, theo priceDecimals
    uint8   priceDecimals;
    uint64  publishTime;
    uint64  roundId;         // tang dan, chan replay mot round cu
}
// 2-of-3 signer, EIP-712, domain co chainId + verifyingContract
require(block.timestamp - r.publishTime <= 900, "stale");
require(r.roundId > lastRoundId, "replay");
require(_absDeltaBps(r.price, lastPrice) <= 200, "breaker");   // 2% moi lan cap nhat
```

**Cai ban nhap chua tra loi: khi oracle stale thi sao?** Neu `require(stale)` lam `mint` revert, mot su co oracle 20 phut lam dung toan bo luong nap tien — mot DoS ta tu gay ra. Chinh sach ro rang:

| Tinh trang oracle | `mint` | `redeem` | `CR` |
|---|---|---|---|
| Tuoi <= 15 phut | Rate hien tai | Rate hien tai | Tinh binh thuong |
| 15 phut - 6 gio | **Chan** | `lastGoodRate` + spread gap doi | Dung `lastGoodRate` |
| > 6 gio | Chan | `lastGoodRate` + spread gap doi, cap 10 trieu VND/ngay/dia chi | Coi nhu stale, khong tu dong doi state |
| Breaker nay lien tuc 3 lan | Chan | Nhu tren | `GUARDIAN` duoc goi day |

3. **Admin-set qua timelock** — lua chon trung thuc cho loyalty closed-loop. `setRate` qua timelock 48h, va mint/burn dung rate **da co hieu luc tai thoi diem tich luy** (luu theo lo), khong phai rate hien tai. Nguoi dung tich diem hom qua khong bi dinh gia lai sau mot dem.

**Bo sung bat buoc cho lua chon 3:** "rate theo lo" nghia la contract phai luu `mapping(uint64 batchId => uint256 rateNum)` va nguoi redeem phai chi ra lo. Do la mot cau truc du lieu tang khong gioi han. Thuc dung hon: **rate khong bao gio giam** cho loyalty (mot chinh sach thuong mai, khong phai mot rang buoc ky thuat), khi do rate hien tai luon co loi cho nguoi giu diem va khong can luu theo lo. Neu ban khong the cam ket dieu do, thi phai luu theo lo va phai co `pruneBatches` sau 24 thang.

#### 1.7.5. De-peg: state machine bat buoc co tu ngay dau

```
PEGGED  --CR < 100%-->  UNDERCOLLATERALIZED  --CR < 90%-->  REDEMPTION_HALTED
   ^                            |                                  |
   +----CR >= 102% trong 24h----+                                  v
                                                              WIND_DOWN
```

`CR = reserveValue() * rateDen / (totalSupply() * rateNum)`, tinh lai o moi mint/burn va moi lan cap nhat rate. Lam tron: **floor tren tu so, ceil tren mau so** — CR luon duoc bao cao thap hon hoac bang su that.

Diem quan trong nhat, va la cho de sai nhat: **trong `UNDERCOLLATERALIZED`, redemption phai la pro-rata tai muc CR, khong duoc first-come-first-served.** FCFS duoi tinh trang thieu tai san bao dam la **mot co che sinh ra bank run**: nguoi rut dau lay 100%, nguoi cuoi lay 0%, va ai cung biet dieu do nen ai cung rut ngay. Pro-rata (`payout = amount * CR`) la quy tac cong bang duy nhat va **phai nam trong contract tu dau**, khong the them sau — them sau tuc la doi dieu kien hoan tra giua chung.

`WIND_DOWN`: mint tat vinh vien, redeem `min(1, CR)` pro-rata, cua so claim 180 ngay, phan du chuyen ve `RecoveryVault`. `RecoveryVault` phai la mot contract rieng khong nam sau beacon cua token — neu no nam sau beacon, mot upgrade beacon dieu khien duoc so tien du.

**`ReserveVault` khong nam sau beacon dung chung.** Ban nhap khong noi dieu nay va no la mot lo hong nghiem trong: neu vault dung chung beacon voi token, mot lan `upgradeTo` sai (hoac ac y) doi hanh vi cua **moi vault dang giu tien** cung luc. Quy tac: `ReserveVault` la UUPS rieng voi timelock **7 ngay** (khong phai 48h), hoac tot hon la bat bien hoan toan va thay bang migration co giam sat.

#### 1.7.6. Gio (basket) — thu note yeu cau va chua ai thiet ke

Note viet "mint/burn tu 1 hoac 1 group ERC-20". Mot gio khong phai la mot vault voi nhieu token; no la mot bai toan NAV. Toi thieu can:

```solidity
struct BasketLeg {
    address token;
    uint16  targetBps;      // tong 10,000
    uint16  bandBps;        // duoc lech bao nhieu truoc khi bat buoc rebalance
    bytes32 pricePair;      // khoa doc tu SignedRateSource
    uint8   tokenDecimals;
}
function reserveValue() public view returns (uint256 minorUnits) {
    // sum over legs: balanceOf(vault) * price / 10^tokenDecimals, quy ve minor unit cua Z-token
    // MOI leg can mot rate tuoi. Mot leg stale => toan bo reserveValue stale.
}
```

Ba he qua ma nguoi quyet dinh phai nghe truoc khi dong y:

1. **N leg = N oracle = N diem gay.** Voi quy tac staleness o 1.7.2, xac suat "co it nhat mot leg stale" tang gan tuyen tinh theo N. Voi 3 leg va uptime oracle 99.5% moi leg, uptime tong = 98.5% — tuc ~5.5 ngay/nam khong mint duoc.
2. **Rebalance la mot giao dich giao ngay tren DEX**, tuc la slippage, MEV, va mot khoa co quyen chi tieu reserve. Khoa do la be mat tan cong lon nhat trong toan bo he thong. Neu rebalance thu cong qua Safe 4-of-7, no khong kip voi bien dong; neu tu dong, ta vua tao mot bot co quyen ban reserve.
3. **Gio lam ke toan Odoo phuc tap gap N lan** vi moi leg la mot `res.currency` khac nhau va mot `account.account` khac nhau.

**Khuyen nghi dut khoat: khong lam basket trong v1.** Neu can da tai san, lam N token `WRAP_1_1` doc lap (Z-USDT, Z-USDC) va de viec tron nam o tang nghiep vu (Odoo), noi ma bo phan tai chinh nhin thay va kiem soat duoc. Thiet ke gio de o day duoi dang giay, va `profileMask` cua archetype `BASKET_PEG` de la `0x00` (khong deploy duoc o dau) cho den khi co quyet dinh nguoc lai.

#### 1.7.7. Reserve accounting va proof-of-reserve

| Loai reserve | Bang chung kha thi | Cadence |
|---|---|---|
| On-chain ERC-20 trong `ReserveVault` | `underlying.balanceOf(vault)` — la bang chung, khong can attest | moi block, indexer ghi vao `blockchain.reserve.snapshot` |
| Off-chain VND o ngan hang | **Khong co PoR mat ma nao**. Chi co attestation | snapshot so du hang ngay, attestation ky hang thang |

Cho reserve off-chain:

```solidity
function attest(
    bytes32 statementHash,   // keccak256 cua ban PDF luu tren Garage
    uint256 amountMinor,     // so du VND * 100
    uint64  asOf,
    bytes   calldata sig     // EIP-712, signer = khoa cua don vi kiem toan
) external;
```

Ban ke PDF luu tren Garage duoi dang `ir.attachment` (Many2many, khong base64 trong DB, khong JSON blob) va `keccak256` cua no ghi on-chain. Phia Odoo, `blockchain.reserve.attestation` doi soat voi mot `account.account` (tai khoan ngan hang tach biet) de con so tren GL va con so cong bo on-chain la mot.

**Goi dung ten: day la "attested reserve", khong phai "proof of reserve".** Cay Merkle kieu san giao dich chung minh *nghia vu* (tong so du nguoi dung), khong chung minh *tai san*; no khong giai bai toan o day. Noi "proof of reserve" trong tai lieu marketing la mot phat bieu sai su that ma bo phan phap che se phai go lai sau.

Ba dieu ban nhap chua noi:

- **Neu don vi kiem toan ky sai so thi sao?** Attestation la mot chu ky tren mot con so; contract khong the biet no dung. Bien phap duy nhat co that: `require(amountMinor <= lastAmountMinor * 3)` — mot breaker chan sai so kieu them so 0, khong chan gian lan. Va **hai** signer doc lap cho moi attestation vuot 50 ty VND.
- **Reserve khong duoc la tai khoan van hanh.** Neu tai khoan giu reserve cung la tai khoan tra luong, so du dao dong vi ly do khong lien quan va CR nhay lung tung. Phai la mot tai khoan tach biet, va so hieu tai khoan do phai nam trong `blockchain.token.peg` de doi soat kiem duoc.
- **Ai chiu chi phi attestation?** Mot cong ty kiem toan lon se khong ky hang thang cho mot float nho voi gia hop ly. Do la mot cau hoi ngan sach, khong phai ky thuat — dua vao 1.19.

Invariant `attested_reserve_minor >= totalSupply() * unit` chain **khong the** tu kiem tra (chain khong biet so du ngan hang). No thuoc ve mot cron Odoo (`model._cron_reserve_check()`), va vi pham thi mo incident, khong phai ghi log.

---

### 1.8. Decimals, lam tron, dust — va VND khong co don vi phu

VND co ISO 4217 exponent = 0. Decimals "dung" cho Z-VND la 0. Nhung `decimals = 0` khien moi phi phan tram khong bieu dien duoc va moi phep quy doi tu USDT (6 decimals) sinh dust.

**Khuyen nghi: `decimals = 2` cho Z-VND** (don vi toi thieu on-chain = 0.01 VND, khong bao gio hien thi cho nguoi dung). Ly do dinh luong: 1 raw unit USDT = 0.000001 USDT = 0.025 VND. Voi `decimals = 0` thi moi phep mint bo mat toi 0.999 VND; voi `decimals = 2` thi bo mat toi 0.009 VND — nho hon 100 lan, va du de bieu dien phi 1.5% tren cac gia tri nho.

Hai rang buoc ban nhap khong dat ra:

- **`decimals` la bat bien.** Vi khong co setter, va vi vi va block explorer cache no. Doi decimals sau khi mint la doi y nghia cua moi so da phat ra. Dieu nay lam viec chon `decimals = 2` thanh mot quyet dinh nghiep vu can chu ky, khong phai mot config (1.19).
- **`decimals()` khong thuoc ERC-20 bat buoc.** Mot so tich hop gia dinh 18. Ta khong the sua the gioi; ta chi co the **ghi decimals vao ten hien thi trong metadata** va **khong bao gio phat hanh Z-VND len mot DEX cong khai ma khong co canh bao**.

#### 1.8.1. Bien gioi Odoo — mot van de ke toan, khong phai mot van de contract

`res.currency` cua VND trong Odoo co `rounding = 1.0`. Chain co granularity 0.01 VND. Hai he thong khong the khop tuyet doi.

> Quy tac cung: lam tron **luon co loi cho ben giu quy**: floor khi chi tra, ceil khi thu. Phan du duoc hach toan vao mot tai khoan `Dust`, khong bao gio bi bo im lang.

| Thao tac | Huong lam tron | Ai huong phan le | Ghi so |
|---|---|---|---|
| mint (nap underlying to Z) | floor `zOut` | reserve | `reserveDust` on-chain |
| redeem (Z to underlying) | floor payout | reserve | `reserveDust` on-chain |
| fee thu | ceil | fee recipient | doanh thu |
| refund / rebate tra | floor | reserve | `reserveDust` |
| CR | floor tu so / ceil mau so | bao thu | — |
| Post len `account.move` | round half-up ve 1 VND | GL | tai khoan `Dust` |

**Rang buoc thuc dung de dust khong sinh ra tu phia Odoo:** moi lenh mint/burn **khoi tao tu Odoo** phai la boi so cua `10^decimals` (tuc so nguyen VND). Enforce o tang Odoo (`_check_amount_is_whole_major`), khong o tang contract — contract van phai chap nhan don vi le vi luong on-chain (Zether transfer, phi relayer) sinh ra chung. Nho vay 100% cac but toan GL la so nguyen VND, va dust chi ton tai o cac luong on-chain thuan tuy.

#### 1.8.2. Cong thuc mint/burn khong sinh dust

```solidity
uint256 zOut       = Math.mulDiv(amountIn, rateNum, rateDen);              // floor
uint256 consumedIn = Math.mulDiv(zOut, rateDen, rateNum, Math.Rounding.Ceil);
uint256 refund     = amountIn - consumedIn;
if (refund >= refundThreshold) underlying.safeTransfer(msg.sender, refund);
else reserveDust += refund;   // giu lai => CR tang, khong bao gio ve tay admin
```

`Math.mulDiv` cua OpenZeppelin dung 512-bit trung gian nen khong overflow.

**`refundThreshold` khong duoc la hang so** — ban nhap de no la hang so va dieu do sai tren chuoi. Nguong dung la "gia tri refund > chi phi gas de tra no". Mot `safeTransfer` ~35,000 gas:

| Chain | Gas price | Native | Chi phi 1 transfer | `refundThreshold` hop ly (USDT raw, 6 dec) |
|---|---|---|---|---|
| Gnosis | 1.5 gwei | xDAI = $1 | ~$0.00005 | 100 (= $0.0001) |
| Celo | ~5 gwei | CELO ~$0.4 | ~$0.00007 | 100 |
| Ethereum L1 | 10 gwei | ETH $3,000 | ~$1.05 | 2,000,000 (= $2) |
| Besu private (zero gas) | 0 | — | $0 | 1 |

Ket luan: `refundThreshold` la mot bien storage set trong `initialize()` va sua duoc qua `TREASURY_ROLE` + timelock 48h.

#### 1.8.3. Rang buoc bat ngo tu Zether — va ban nhap truoc cung sai o day

Note (`blockchain.md`, muc 10.5.2 va 10.5.3) khang dinh nang `MAX` tu `2^32 - 1` len `2^128 - 1` la du. **Dieu nay sai o mot diem quan trong**: gioi han `2^32` trong `anonymous-zether` cua ConsenSys khong (chi) la gioi han range proof, no la **gioi han giai ma**. Chu tai khoan phai khoi phuc `b` tu `g^b` bang baby-step giant-step; voi khong gian `2^128` thi BSGS can `2^64` phep tinh — bat kha thi. Nang MAX len `2^128` khong lam so du doc duoc. (Chi tiet mat ma o §03; o day chi lay he qua len token design.)

**Nhung ban nhap truoc cua chinh section nay cung sai khi de xuat `MAX_CONFIDENTIAL = 2^48 - 1`.** Hai ly do:

1. **48 khong phai luy thua cua 2.** Bulletproofs inner-product argument doi `n * m` la luy thua cua 2. Voi `n = 48`, prover phai pad len 64, va **chi phi verify la chi phi cua 64 bit**. Chon 48 la tra tien cho 64 ma nhan soundness cua 48. Chon **`n = 64`**.
2. **Range proof width va tran giai ma la hai thu khac nhau va phai duoc tach ra.** Range proof bao dam *soundness* (khong ai chuyen so am, khong ai tieu qua so du). Tran giai ma bao dam *usability* (chu tai khoan doc duoc so du cua minh). Gan chung vao mot hang so la loi thiet ke.

**Cong thuc dung:** chi phi BSGS bi chan boi **`totalSupply` tinh theo raw unit**, khong phai boi `2^n`. Ly do: tong moi so du confidential = `confidentialLocked <= totalSupply`, nen moi so du ca nhan cung `<= totalSupply`. Do do:

> **Quy tac chot: `maxSupply` tinh theo raw unit phai `<= 2^44` (= 1.759e13). Enforce trong `initialize()`.**

Dinh luong BSGS voi khong gian tim kiem `S`, bang baby-step kich thuoc `B = sqrt(S)`:

| Token | decimals | Tran cung tien | `S` (raw) | `log2 S` | `B = sqrt(S)` | Bo nho bang | Thoi gian giai ma xau nhat |
|---|---|---|---|---|---|---|---|
| Z-VND | **2** | 100 ty VND | 1.0e13 | 43.2 | 3.2e6 | ~130 MB | ~0.8 - 1.0 s |
| Z-VND | 0 | 100 ty VND | 1.0e11 | 36.5 | 3.2e5 | ~13 MB | ~0.08 s |
| Z-USDT | 6 | 10 trieu USDT | 1.0e13 | 43.2 | 3.2e6 | ~130 MB | ~0.8 - 1.0 s |
| (note de xuat) | — | `2^128` | 3.4e38 | 128 | 1.8e19 | bat kha thi | bat kha thi |

Co so: mot phep cong diem affine tren `bn254` trong Rust toi uu ~250-300 ns; vong giant-step la (1 cong diem + 1 tra bang hash) ~350-400 ns; `3.2e6 * 350ns ≈ 1.1 s` xau nhat, ~0.55 s trung binh. Bo nho: 3.2e6 entry x (32 byte toa do nen + 8 byte index) ≈ 128 MB, cong overhead hash map ~1.5x neu dung `HashMap` chuan; dung mot open-addressing table thi sat 130 MB.

**Do la mot uoc tinh, va no thay doi mot quyet dinh:** `decimals = 2` dat gap 10 lan `decimals = 0` ve thoi gian khoi phuc (1 s vs 0.08 s). Van khuyen nghi `decimals = 2`, vi:

- duong hanh phuc khong dung BSGS: moi giao dich kem mot ciphertext phu `encSelf = AEAD(kdf(x), value || randomness)` trong event log. Vi doc so du bang cach giai AEAD, `O(1)`, khong toi 1 ms. BSGS chi chay khi **recovery** (mat cache cuc bo, dong bo may moi).
- 1 giay cho mot thao tac chay vai lan trong doi mot tai khoan la chap nhan duoc; mat kha nang bieu dien phi phan tram thi khong.

Chot tham so cho v1:

```solidity
uint8   public constant RANGE_BITS          = 64;          // luy thua cua 2, soundness
uint256 public constant MAX_DECRYPTABLE_RAW = 1 << 44;     // 1.759e13, usability
// initialize(): require(maxSupply_ <= MAX_DECRYPTABLE_RAW, "supply exceeds decryptable range");
// mint():       require(totalSupply() + amount <= maxSupply, "cap");
```

Neu mot ngay nao do can vuot `2^44`, duong nang cap khong phai la tang `RANGE_BITS` — do la **chia token thanh nhieu series** (`series` da co trong salt, 1.4.3), moi series co so cai rieng. Do la mot van de ke toan, khong phai mat ma.

Dinh luong gas cua chinh quyet dinh nay o muc 1.12.

---

### 1.9. Total-supply invariants

Viet duoi dang property test (Foundry invariant), khong phai comment:

```
inv_wrap_1  : totalSupply() == reserveAccounted
inv_wrap_2  : reserveAccounted <= underlying.balanceOf(vault)
inv_peg     : totalSupply() <= mulDiv(reserveValue(), rateNum, rateDen)
inv_native  : totalSupply() == mintedCumulative - burnedCumulative <= maxSupply
inv_cap     : maxSupply <= MAX_DECRYPTABLE_RAW
inv_conf    : confidentialLocked == balanceOf(address(this))
inv_conf_2  : confidentialLocked <= totalSupply()
inv_rate    : |rate_t - rate_{t-1}| * 10000 / rate_{t-1} <= 200   // stateful, qua nhieu lan cap nhat
inv_state   : pegState != PEGGED  =>  mint reverts
```

**Sua so voi ban nhap:** ban nhap viet `inv_conf : confidentialLocked == totalSupply() - sum(public ERC20 balances)`. Sai o hai cho:

1. **`sum(public ERC20 balances)` khong the danh gia duoc on-chain** — khong co cach nao liet ke holder cua mot ERC-20. Mot bat bien khong danh gia duoc khong phai la mot bat bien; no la mot cau van.
2. Cong thuc dung don gian hon nhieu: token contract giu chinh so token da nap vao vung confidential, nen `balanceOf(address(this))` **la** so do. Vay `confidentialLocked == balanceOf(address(this))`, mot phep so sanh mot SLOAD voi mot mapping read. Danh gia duoc trong `assert` cuoi moi `deposit`/`withdraw`, khong chi trong test.

`inv_conf` la thu note bo sot va no la thu de mat tien nhat. Mot Zether token vua la ERC-20 cong khai vua giu so du ma hoa co **hai khong gian so du**. Phia ma hoa khong the cong on-chain (do la muc dich cua no). Bat bien duy nhat re tien la mot bien dem **cong khai** `confidentialLocked`, tang khi `deposit`, giam khi `withdraw`, voi `unchecked` bi cam — mot underflow o day chinh la mot lan in tien.

Danh doi: `confidentialLocked` **lo tong float confidential** (khong lo tung tai khoan). Day la mot tiet lo **co chu y va chap nhan duoc** — no la cai gia de co the phat hien mot lo hong mint vo han. Neu khong co no, mot bug trong Bulletproof verifier co the in tien ma khong ai thay cho den khi vault can.

Cau hinh fuzz cu the (khong phai "chay invariant test"):

```toml
[invariant]
runs = 50_000
depth = 64
fail_on_revert = false
shrink_run_limit = 5_000
```

`depth = 64` vi cac loi de-peg chi lo ra sau mot chuoi mint/burn/rate-update dan xen; `depth = 15` mac dinh cua Foundry khong bao gio cham toi `UNDERCOLLATERALIZED`. Handler phai co mot `warp` ngau nhien (0 - 30 ngay) de invariant staleness (1.7.2) duoc thu.

---

### 1.10. Pause / freeze / blacklist — cai nao chap nhan duoc

Ba thu nay khong giong nhau va phai duoc doi xu khac nhau:

| Co che | Public chain profile | Private chain profile | Rang buoc bat buoc |
|---|---|---|---|
| `pause()` toan cuc | Chap nhan | Chap nhan | **`MAX_PAUSE = 7 ngay`**: sau moc do, `redeem`/`withdraw` tu dong mo lai bat ke pause. Pause khong gioi han thoi han la tich thu tai san co giay to |
| `freeze(account)` | Chi cho `WRAP_1_1` cua underlying von da freeze duoc, va chi theo lenh toa | Chap nhan | Phat `AccountFrozen(account, bytes32 caseRef)`, role giu boi multisig, khong bao gio EOA |
| `blacklist` mo (admin tu them) | **Tu choi** | Thua (transfer da bi allowlist cua registry chan) | — |

Ly do tu choi blacklist tren public chain khong phai y thuc he: mot token co the bi blacklist tuy y **khong dung lam collateral o bat cu dau khac**, va lam cho tuyen bo "wrapped 1:1" tro thanh sai su that. Voi `WRAP_1_1` cua USDC thi ta **da** thua ke kha nang freeze cua USDC roi; giau dieu do di moi la khong trung thuc — cong bo no.

**Bien no thanh dac tinh cua archetype, khong phai co runtime:**

- `ZTokenOpen` — khong `freeze`, khong `blacklist`, `pause` gioi han 7 ngay. Deploy duoc tren profile public.
- `ZTokenPermissioned` — transfer gated boi allowlist cua registry. Chi deploy duoc tren profile private (`profileMask` bit1).

Khi da mint duoi `ZTokenOpen` thi **khong ai bat duoc blacklist ve sau**, ke ca admin, ke ca qua upgrade — vi beacon cua `ZTokenOpen` chi nhan implementation cung archetype (registry kiem tra `archetype` trong `validateUpgrade`, va beacon cua archetype nay khong duoc tro sang implementation cua archetype khac).

#### 1.10.1. Loi thoat khoi tran pause 7 ngay

Ban nhap dat `MAX_PAUSE = 7 ngay` nhung khong tra loi: **neu chinh `withdraw` la ham co bug thi sao?** Tu dong mo lai `withdraw` sau 7 ngay la mo lai lo hong.

Loi thoat duy nhat, va no phai la mot chieu:

```
paused --(7 ngay het han)--> auto-unpause redeem/withdraw
   |
   +--(GUARDIAN + Safe 4-of-7, KHONG timelock)--> WIND_DOWN  [mot chieu, khong quay lai]
```

`WIND_DOWN` khong phai la "pause lau hon". No la: mint tat vinh vien, `RecoveryVault` duoc cap von bang toan bo reserve, va nguoi giu token doi qua `RecoveryVault` (mot contract khac, code khac, khong chia se bug voi token). Nghia la ban khong duoc phep keo dai pause; ban chi duoc phep **tu bo token va tra tien qua mot duong khac**. Do la mot lua chon dat, va no dung phai dat — no la thu ngan mot pause "tam thoi" keo dai 3 nam.

#### 1.10.2. Pause va tinh kha ket hop

Mot token bi pause dang nam trong mot pool DEX hoac lam collateral o mot giao thuc khac se lam ke thu ba khong thanh ly duoc vi the, va ho se mat tien vi quyet dinh cua ta. Hai he qua thuc te:

- Voi `ZTokenOpen` phat hanh cong khai, phai cong bo `MAX_PAUSE` trong tai lieu tich hop, va phat `Paused(uint64 autoUnpauseAt)` de bot cua ho doc duoc moc tu dong mo.
- Voi `ZTokenPermissioned` tren private chain, khong co ben thu ba, van de nay khong ton tai. Day la mot ly do nua de moi luong tien co quy dinh nen o private profile truoc.

#### 1.10.3. Freeze giao voi Zether

Dong bang mot `schnorrAddress` (co trong registry, §02) chan `rollOver` va `withdraw`, nhung **khong the tich thu** so du ma hoa — contract khong biet no bang bao nhieu. Freeze o tang Zether nghia la "ket", khong phai "thu hoi". Bo phan phap che se hoi cau nay; tra loi truoc.

He qua phap ly ma ban nhap khong keo den tan cung: **neu quy dinh doi hoi kha nang tich thu (seizure) theo lenh co quan, thi Zether tren public chain khong dap ung duoc, cham het.** Chi co hai duong: (a) token khong the redeem ra tien phap dinh (loyalty thuan tuy) nen khong thuoc pham vi dieu chinh do, hoac (b) chay tren private chain noi mot lenh toa duoc thuc thi bang mot `forceTransfer` co su chung kien cua N validator. Ket noi voi 1.15 va §13.

---

### 1.11. Quan tri upgrade

Khong dung `Ownable`. `AccessControl` voi cac role tach bach:

| Role | Ai giu | Nguong | Do tre |
|---|---|---|---|
| `DEFAULT_ADMIN_ROLE` | Safe 4-of-7 (board + CTO + 1 ben ngoai) | 4/7 | 7 ngay de doi role |
| `PROTOTYPE_ADMIN` | Safe 3-of-5 (engineering) | 3/5 | 48h de `registerPrototype` |
| Beacon owner (`UPGRADE_ADMIN`) | `TimelockController` (proposer = Safe 4-of-7, executor = `address(0)` mo) | — | **48h, khong co duong tat** |
| `DEPLOYER_ROLE` | service account cua Odoo, khoa trong HSM | — | khong tre |
| `MINTER` / `BURNER` | service account, khoa trong HSM FIPS 140-2 L3 | — | khong tre, nhung `maxMintPerEpoch` on-chain |
| `TREASURY_ROLE` | Safe 3-of-5 | 3/5 | 48h cho `setRefundThreshold`, `sweepDonation` |
| `RATE_SIGNER` | 2-of-3 | 2/3 | staleness 15 phut |
| `ATTESTOR` | khoa cua don vi kiem toan (ngoai cong ty) | 1, hoac 2 khi > 50 ty | — |
| `GUARDIAN` | 1-of-5 ky su truc | 1/5 | tuc thi, **chi `pause` va `deprecatePrototype`**, tu het hieu luc sau 7 ngay |
| `RECOVERY` | Safe 6-of-7 | 6/7 | **30 ngay**, chi de thay toan bo signer set khi mat khoa |

Nguyen tac: **guardian duoc phep dung, chi timelock duoc phep doi.** Mot quyen upgrade thuc thi tuc thi khong phan biet duoc voi mot khoa mint. Neu co bug can va gap, cau tra loi trung thuc la pause to cho 48h to upgrade, va chap nhan downtime. Moi role "emergency upgrade" deu la mot backdoor co thu tuc.

Executor cua timelock de mo (`address(0)`) de mot executor mat khoa khong the chan mot upgrade da queue.

#### 1.11.1. Bon cho quyen upgrade van ro ri neu chi lam nhu tren

Ban nhap dung nhung chua du. Bon lo con lai:

1. **Beacon la `Ownable`, khong phai `AccessControl`.** `UpgradeableBeacon` cua OZ chi co `owner()`. Neu `transferOwnership` cua beacon goi duoc tuc thi, thi timelock la trang tri. Bat buoc: beacon owner = timelock, **va** dung `Ownable2Step` (implementation rieng, khong dung `UpgradeableBeacon` mac dinh) de `transferOwnership` can hai buoc. Doi owner cua beacon la mot hanh dong phai qua chinh timelock 48h do.
2. **Governance drift cross-chain.** Safe tren Gnosis va Safe tren Celo la hai contract khac nhau voi hai signer set co the lech nhau. Sau mot nam co the khong ai biet ai dang ky duoc gi tren Celo. Bat buoc: mot cron Odoo hang ngay doc `getOwners()` + `getThreshold()` cua moi Safe tren moi chain va so voi `blockchain.governance.signer` (danh sach ky vong trong Odoo); lech = incident. Day la ~40 dong Python va no chan mot lop rui ro khong co cach nao khac de phat hien.
3. **Khong co duong tu mot ban audit den mot lan execute.** Timelock 48h bao ve chong sua doi lut, khong bao ve chong upgrade sang mot implementation chua ai doc. Bat buoc mot record Odoo lam so ghi chep:

```python
class BlockchainUpgradeProposal(models.Model):
    _name = 'blockchain.upgrade.proposal'
    _inherit = ['mail.thread']

    beacon_address   = fields.Char(size=42, required=True, index=True)
    chain_id         = fields.Many2one('blockchain.chain', required=True, index=True)
    from_impl        = fields.Char(size=42, required=True)
    to_impl          = fields.Char(size=42, required=True)
    to_impl_codehash = fields.Char(size=66, required=True)   # doi chieu on-chain truoc khi execute
    storage_diff_ids = fields.Many2many('ir.attachment', 'bc_upgrade_storage_rel',
                                        string='Storage layout diff')   # Garage, khong base64
    audit_report_ids = fields.Many2many('ir.attachment', 'bc_upgrade_audit_rel',
                                        string='Audit report')
    queue_tx_hash    = fields.Char(size=66)
    eta_datetime     = fields.Datetime(readonly=True)        # KHONG dat ten 'date'
    execute_tx_hash  = fields.Char(size=66)
    proposal_state   = fields.Selection([
        ('draft','Draft'), ('reviewed','Reviewed'), ('queued','Queued'),
        ('executable','Executable'), ('executed','Executed'),
        ('cancelled','Cancelled'), ('mismatch','Code Mismatch')],
        default='draft', required=True, tracking=True)
```

Chuyen sang `reviewed` doi it nhat mot `audit_report_ids` va mot `storage_diff_ids`; chuyen sang `executed` doi `to_impl_codehash` khop voi `EXTCODEHASH` doc lai tu chain. Khong phai vi quy trinh; vi da tung co du an upgrade nham dia chi implementation cua testnet len mainnet.

4. **Mat 4 trong 7 khoa.** Khong co `RECOVERY` thi he thong chet vinh vien va khong ai noi ra dieu do. Safe 6-of-7 voi timelock 30 ngay la du cham de ke tan cong bi phat hien, va du de cuu neu chi mat 3 khoa. Neu mat 4 khoa thi ke ca `RECOVERY` cung khong cuu duoc — do la mot rui ro ton du phai duoc ghi vao ho so rui ro, khong phai duoc lo di.

---

### 1.12. Dinh luong gas, calldata va thong luong

Co so: chi phi opcode EVM sau EIP-1108 (`ecAdd` = 150, `ecMul` = 6,000, `ecPairing` = 45,000 + 34,000k) va EIP-2929 (cold account 2,600, cold SLOAD 2,100). Code deposit = 200 gas/byte (EIP-170 gioi han 24,576 byte; EIP-3860 gioi han initcode 49,152 byte + 2 gas/word). Gnosis: ~1.5 gwei, xDAI = 1 USD. Ethereum L1 doi chieu: 10 gwei, ETH = 3,000 USD. **Tat ca la uoc tinh; do lai bang `forge test --gas-report` truoc khi chot ngan sach.**

| Thao tac | Gas | Gnosis | Ethereum L1 |
|---|---|---|---|
| Deploy implementation `ZTokenBase` (~13 KB runtime) | ~2,800,000 | $0.0042 | $84 |
| Deploy `UpgradeableBeacon` | ~350,000 | $0.00053 | $10.50 |
| Deploy BeaconProxy qua CREATE2 + `initialize` | ~230,000 | $0.00035 | $6.90 |
| Deploy EIP-1167 clone | ~45,000 | $0.00007 | $1.35 |
| `transfer`, nguoi nhan da co so du (warm slot) | ~37,000 | $0.00006 | $1.11 |
| `transfer`, nguoi nhan moi (slot 0 to non-0) + overhead beacon lanh | ~54,000 | $0.00008 | $1.62 |
| `mint` `PEG_RATIO` (doc rate + vault transferFrom) | ~120,000 | $0.00018 | $3.60 |
| `attest()` | ~85,000 | $0.00013 | $2.55 |
| Zether `transferConfidential`, `RANGE_BITS = 32` | ~1,150,000 | $0.0017 | $34.50 |
| Zether `transferConfidential`, **`RANGE_BITS = 64` (chot)** | **~1,900,000** | **$0.0029** | **$57** |
| Zether `transferConfidential`, `RANGE_BITS = 128` (note de xuat) | ~3,500,000 | $0.0053 | $105 |

#### 1.12.1. Phan bac con so Zether — va sua lai chinh ban nhap

Ban nhap ket luan "con so 180,000 - 250,000 gas trong note thap hon thuc te khoang mot bac". **Ket luan do dung cho Bulletproofs nhung sai o cho no khong noi ra rang con so cua note la dat duoc voi mot he chung minh khac.** Phan bac day du:

Bulletproofs verify la mot multi-scalar multiplication kich thuoc `2*n*m + 2*ceil(log2(n*m)) + ~7` diem, va EVM khong co precompile MSM — moi diem la mot `ecMul` rieng:

| `n` (bit) | `m` (so gia tri) | So diem MSM | Gas MSM | Sigma-protocol | Cap nhat state | **Tong** |
|---|---|---|---|---|---|---|
| 32 | 2 | 128 + 14 + 7 = 149 | ~916k | ~150k | ~50k | ~1.15M |
| **64** | **2** | 256 + 14 + 7 = 277 | ~1.70M | ~150k | ~50k | **~1.90M** |
| 128 | 2 | 512 + 16 + 7 = 535 | ~3.29M | ~150k | ~50k | ~3.50M |

Calldata cua proof: `2*log2(n*m)` diem cho inner-product + 4 diem cam ket + 5 scalar. Voi `n=64, m=2`: 14 + 4 = 18 diem x 64 byte + 5 x 32 byte = **1,312 byte**, ~21,000 gas calldata tren L1 (16 gas/byte khac 0). Tren mot L2 dung calldata (khong dung blob), calldata la thanh phan chi phi **lon nhat**, khong phai execution. Do la mot ly do nua de Zether o private chain hoac o Gnosis L1-nhu-L2, khong o mot rollup.

Con so `~7.2M gas` ma `anonymous-zether` cua ConsenSys bao cao la cho **anonymity set 16**; kien truc cua ta khong co anonymity set (nguoi gui/nhan cong khai theo khoa quyet dinh cua note), nen phan `many-out-of-many` bien mat. Dung con so 1.9M, khong dung 7.2M, khi lam ngan sach.

**Con so 180k-250k cua note dat duoc bang mot he chung minh pairing-based, khong bang Bulletproofs:**

| He chung minh | Gas verify | Kich thuoc proof | Prover time (client) | Trusted setup |
|---|---|---|---|---|
| Bulletproofs, n=64 | ~1.9M | ~1.3 KB | ~150 - 400 ms | Khong |
| Groth16 (bn254) | **~230k - 280k** (1 `ecPairing` 4 cap = 181k + ~8 `ecMul` input) | 128 byte | ~0.5 - 3 s | **Co, per-circuit ceremony** |
| PLONK / Halo2-KZG | ~350k - 500k | ~500 byte - 1 KB | ~1 - 5 s | Universal (co the tai su dung) |

Doi lai 1.9M to 250k gas (**giam 87%**) la: mot ceremony trusted setup (Groth16) hoac mot circuit phuc tap hon (PLONK), cong voi viec circuit tro thanh mot artifact phai version va audit rieng. **Khuyen nghi v1: Bulletproofs**, vi private chain lam gas thanh don vi ke toan noi bo (khoa quyet dinh #5) va vi khong co ceremony la mot bot ganh nang van hanh that. Nhung ghi ro trong plan rang duong nang cap ton tai va no la duong duy nhat dua Zether len public chain o quy mo. Xem §03.

#### 1.12.2. Thong luong — con so ban nhap khong co, va no doi kien truc

Gas per tx la mot con so. Con so quyet dinh la **bao nhieu giao dich bao mat mot giay**.

| Chain | Block gas limit (uoc, kiem lai) | Block time | Zether tx/block neu chiem 100% block | Thuc te (gia dinh chiem 25% block) |
|---|---|---|---|---|
| Ethereum L1 | ~36M | 12 s | 18 | 0.37 tx/s |
| Gnosis | ~17M | 5 s | 8 | **0.45 tx/s** |
| Celo (L2) | ~30M | ~1 s | 15 | 3.7 tx/s |
| Besu QBFT private, gas limit 200M | 200M | 2 s | 105 | **xem duoi** |

Tren private chain, gas limit khong con la rang buoc — nhung **CPU cua validator thi con**. 277 `ecMul` tren bn254; Besu dung thu vien native cho alt_bn128 precompile, ~50-100 us moi `ecMul`. `277 * 80us ≈ 22 ms` de verify mot proof. EVM chay tuan tu trong mot block, nen tran that la:

```
2000 ms / 22 ms = ~90 proof/block  ->  ~45 confidential tx/s
```

Con so nay, khong phai gas limit, la thu phai xuat hien trong tai lieu nang luc. Va no la mot con so **du** cho moi khoi luong B2B thuc te (45 tx/s = 3.9 trieu giao dich/ngay), dong thoi la mot con so **khong du** cho thanh toan nguoi dung cuoi ban le o quy mo quoc gia. Ket noi voi 1.15.

#### 1.12.3. Con so cung co khoa quyet dinh #5

Tren chain rieng, gas la gia tri ke toan noi bo (zero-gas mode). Va no dinh luong loi ich cua viec chon `RANGE_BITS = 64` thay vi 128: **giam ~46% gas** va **~46% thoi gian CPU validator** (90 to 49 proof/block neu dung 128 bit), doi lay mot tran range 1.8e19 raw — thua xa `MAX_DECRYPTABLE_RAW = 1.76e13` von la rang buoc that su.

---

### 1.13. Phia Odoo — `dms_blockchain` doc lap

`__manifest__.py`: `'depends': ['base', 'mail']`. **Khong co `dms`.** Model prefix la `blockchain.`, khong phai `dms.` — dung `dms.` khi DMS khong duoc cai la mot lo noi doi ve pham vi. (Prefix nay duoc chot o §10.3; section nay tuan theo.)

```
dms_blockchain/
├── __manifest__.py
├── models/
│   ├── chain.py                # blockchain.chain              (dinh nghia o §08.1 / §10.4.2)
│   ├── token_archetype.py      # blockchain.token.archetype
│   ├── token_prototype.py      # blockchain.token.prototype    (mirror on-chain registry)
│   ├── token.py                # blockchain.token
│   ├── token_peg.py            # blockchain.token.peg          (rate_num, rate_den, cr, peg_state)
│   ├── reserve_snapshot.py     # blockchain.reserve.snapshot
│   ├── reserve_attestation.py  # blockchain.reserve.attestation (M2M ir.attachment tren Garage)
│   └── upgrade_proposal.py     # blockchain.upgrade.proposal
├── data/ir_cron.xml
└── security/{ir.model.access.csv, blockchain_security.xml}
```

#### 1.13.1. `blockchain.token`

```python
class BlockchainToken(models.Model):
    _name = 'blockchain.token'
    _description = 'Deployed token contract'
    _inherit = ['mail.thread']
    _order = 'chain_id, symbol'

    name             = fields.Char(required=True)
    symbol           = fields.Char(required=True)
    active           = fields.Boolean(default=True)
    company_id       = fields.Many2one('res.company', required=True, index=True,
                                       default=lambda s: s.env.company)
    token_decimals   = fields.Integer(required=True, default=2)
    archetype        = fields.Selection([('issuer_native', 'Issuer Native'),
                                         ('wrap_1_1', 'Wrapped 1:1'),
                                         ('peg_ratio', 'Ratio Pegged')], required=True)
    chain_id         = fields.Many2one('blockchain.chain', required=True, index=True)
    prototype_id     = fields.Many2one('blockchain.token.prototype', required=True)
    upgradeable      = fields.Boolean(default=True)

    contract_address = fields.Char(size=42, index=True)   # LUON lowercase (xem _normalize)
    predicted_address= fields.Char(size=42)
    expected_codehash= fields.Char(size=66)
    salt_hex         = fields.Char(size=66)
    init_data_hex    = fields.Char()
    deploy_tx_hash   = fields.Char(size=66)
    deploy_date      = fields.Datetime(readonly=True)      # KHONG dat ten 'date'

    # uint256 luon la chuoi thap phan base unit (quy uoc §10.4.1). Integer/Float deu tran.
    max_supply_base  = fields.Char(help='uint256 decimal string, base units.')

    deploy_state     = fields.Selection([
        ('draft', 'Draft'), ('predicted', 'Predicted'), ('broadcast', 'Broadcast'),
        ('pending_finality', 'Pending Finality'), ('verified', 'Verified'), ('live', 'Live'),
        ('failed', 'Failed'), ('mismatch', 'Code Mismatch'),
        ('paused', 'Paused'), ('wind_down', 'Wind Down'), ('retired', 'Retired'),
    ], default='draft', required=True, tracking=True)

    _unique_addr = models.Constraint(
        'UNIQUE(chain_id, contract_address)',
        'Mot dia chi contract chi duoc dang ky mot lan tren mot chain.')
    _unique_salt = models.Constraint(
        'UNIQUE(chain_id, salt_hex)',
        'Mot salt chi sinh mot token tren mot chain — chan deploy trung.')
    _check_addr_lower = models.Constraint(
        r"CHECK (contract_address IS NULL OR contract_address ~ '^0x[0-9a-f]{40}$')",
        'contract_address phai la hex lowercase co 0x.')
    _check_maxsupply = models.Constraint(
        r"CHECK (max_supply_base IS NULL OR max_supply_base ~ '^[0-9]{1,78}$')",
        'max_supply_base phai la chuoi thap phan uint256.')

    @api.model
    def blockchain_predict_address(self, archetype, major_version, salt_hex, chain_code):
        """POST /web/dataset/call_kw/blockchain.token/blockchain_predict_address
           POST /json/2/blockchain.token/blockchain_predict_address
        Khong nhan allowed_company_ids tu client; pham vi suy tu self.env.company."""
        return self._predict_address(archetype, major_version, salt_hex, chain_code)

    @api.model
    def blockchain_list_tokens(self, chain_code=None):
        """Metadata cong khai cho client. Chi tra token deploy_state == 'live'."""
        dom = [('deploy_state', '=', 'live')]
        if chain_code:
            dom.append(('chain_id.code', '=', chain_code))
        return self.search_read(dom, ['symbol', 'token_decimals', 'contract_address',
                                      'archetype', 'chain_id'])

    def _predict_address(self, archetype, major_version, salt_hex, chain_code):
        ...
```

#### 1.13.2. Sau chi tiet Odoo ban nhap bo sot

1. **Dia chi phai duoc chuan hoa lowercase.** EIP-55 checksum nghia la `0xAbC...` va `0xabc...` la **cung mot dia chi** nhung la hai chuoi khac nhau. Mot `UNIQUE(chain_id, contract_address)` tren chuoi mixed-case khong chan duoc trung. Luu lowercase (`create`/`write` override, hoac `_normalize` trong `_inherits`), hien thi checksummed bang mot compute khong luu.
2. **`company_id` va record rule.** Cai gi giu tien thi co `company_id` (§10.9). Record rule chuan `[('company_id','in',company_ids)]`. Neu mot ngay nao do can hierarchy don vi, dung `child_of` tren mot **many2one**, khong bao gio tren `parent_path`.
3. **`res.users.group_ids`** (Odoo 19 doi ten tu `groups_id`) — dung ten moi trong moi data XML va moi doan Python cua addon.
4. **Deploy phai idempotent (gia dinh A11).** Cron broadcast khong duoc broadcast hai lan cho cung mot record. Khoa o tang DB, khong o tang Python:

```python
def _cron_broadcast_pending_deploys(self):
    self.env.cr.execute("""
        SELECT id FROM blockchain_token
         WHERE deploy_state = 'predicted' AND active
         ORDER BY id
         FOR UPDATE SKIP LOCKED
         LIMIT 20
    """)
    ids = [r[0] for r in self.env.cr.fetchall()]
    for tok in self.browse(ids):
        tok._broadcast_deploy()     # set deploy_state='broadcast' + deploy_tx_hash truoc khi commit
```

`UNIQUE(chain_id, salt_hex)` la lop chan thu hai: ke ca khi hai worker vuot qua khoa, lan insert thu hai chet.

5. **Cron XML chi mot dong.** `<field name="code">model._cron_reserve_check()</field>` — eval context khong co `fields` lan `relativedelta`. Bon cron cua section nay: `_cron_verify_deployed_code`, `_cron_broadcast_pending_deploys`, `_cron_reserve_check`, `_cron_governance_drift_check`.
6. **`deploy_state` la Selection thuong, khong la stored computed field.** Mot stored compute co nhanh khong gan gi se cho INSERT chet vi NULL tren cot required — bay da biet cua stack nay.

Nhac lai hai bay cu, vi chung se quay lai:

- `_sql_constraints` dang list bi Odoo 19 **bo qua hoan toan**; dung `models.Constraint` nhu tren va **kiem chung bang SQL, dung tin code**:
  `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_token'::regclass;`
- Khoa deployer/HSM: `ir.config_parameter` giu **`key_ref`** (ten cua khoa trong HSM/KMS), khong bao gio giu khoa. `password=True` khong ton tai o Odoo 19 va chua bao gio chan `read()`/RPC/export.

#### 1.13.3. Huong doi soat — Odoo khong phai nguon su that (gia dinh A10)

Phai phat bieu ro trong plan, vi no quyet dinh cach viet moi cron:

> **Chain la nguon su that cho: `contract_address`, `totalSupply`, `reserveAccounted`, `CR`, `pegState`, danh sach role holder.
> Odoo la nguon su that cho: y dinh (`draft`/`predicted`), gan ket nghiep vu, va lich su phe duyet.**

Ket qua: moi cron dong bo chay theo huong chain to Odoo va **ghi de** gia tri trong Odoo. Neu Odoo va chain lech ve mot gia tri thuoc nhom thu nhat, chain thang va Odoo mo mot activity, khong phai nguoc lai. Mot cron ghi chieu nguoc lai ("sua chain cho khop Odoo") khong duoc phep ton tai.

#### 1.13.4. Cau (seam) noi sang `dms`

Mot addon cau `dms_blockchain_bridge` sau nay se map `dms.trade.settlement.line.payout_line_ids` va `dms.payment.collection` sang mint/burn, va `dms.incentive.rule.line` sang `ISSUER_NATIVE`. `dms_blockchain` khong biet ten nao trong so do, va khong duoc `import` chung. Cach kiem chung rang buoc nay khong bi vi pham theo thoi gian: mot CI grep

```bash
grep -rnE "\bdms\.[a-z_]+\b|from odoo.addons.dms\b" dms_blockchain/ && exit 1
```

va mot test cai `dms_blockchain` tren mot database **khong co** `dms`.

---

### 1.14. Bo cuc `smartcontracts/` (ngoai addon, o goc repo)

```
smartcontracts/
├── evm/
│   ├── foundry.toml
│   ├── src/
│   │   ├── factory/{DeterministicFactory.sol,ContractPrototypeRegistry.sol}
│   │   ├── proxy/{DmsBeaconProxy.sol,PinnedProxy.sol,DmsUpgradeableBeacon.sol}
│   │   ├── token/{ZTokenBase.sol,ZTokenOpen.sol,ZTokenPermissioned.sol,
│   │   │          IssuerNativeToken.sol,WrappedToken.sol,PeggedToken.sol}
│   │   ├── peg/{ReserveVault.sol,SignedRateSource.sol,PegController.sol,
│   │   │        ReserveAttestation.sol,RecoveryVault.sol}
│   │   ├── zether/{ZetherAccountRegistry.sol,ZetherTokenModule.sol,BulletproofVerifier.sol}
│   │   └── governance/{DmsTimelock.sol,Guardian.sol}
│   ├── test/
│   │   ├── invariant/{WrapInvariant.t.sol,PegInvariant.t.sol,SupplyInvariant.t.sol,
│   │   │              ConfidentialInvariant.t.sol}
│   │   └── fork/{UsdtGnosisFork.t.sol,UsdcCeloFork.t.sol}
│   ├── script/{Deploy.s.sol,PredictAddress.s.sol,QueueUpgrade.s.sol}
│   └── storage-layouts/v1/*.json
├── hedera/  ton/  sui/  soroban/  cosmwasm/     # thiet ke tren giay truoc
└── .github/workflows/contracts.yml
```

#### 1.14.1. `foundry.toml` — ba dong quyet dinh tinh tai lap

```toml
[profile.default]
solc_version   = "0.8.28"     # PIN. Doi minor version doi bytecode doi dia chi CREATE2.
bytecode_hash  = "none"       # BAT BUOC: mac dinh solc gan IPFS metadata hash vao cuoi bytecode
cbor_metadata  = false        # BAT BUOC: bo not phan metadata CBOR con lai
optimizer      = true
optimizer_runs = 200          # PIN. Doi con so nay doi bytecode doi dia chi.
via_ir         = true         # struct MetaTransaction 12 truong => stack too deep neu khong bat
evm_version    = "cancun"     # doi chieu voi tung chain; Besu genesis phai khai cung fork
```

Khong co `bytecode_hash = "none"`, cung mot source build tren hai may CI cho hai `init_code` khac nhau, hai dia chi CREATE2 khac nhau, va toan bo muc 1.4 sup do. Day la gia dinh A3, va no la mot dong config.

`evm_version` phai khop chinh xac giua public va private profile. Neu Besu genesis khai `shanghai` con Foundry build `cancun`, contract dung `TSTORE`/`MCOPY` se revert tren private chain sau khi da pass moi test.

#### 1.14.2. CI gate (fail build, khong phai warning)

1. `forge test` + `forge coverage` >= 90% tren `src/token`, `src/peg`, `src/factory`;
2. `forge build --sizes` fail neu bat ky contract nao > 24,000 byte (le an toan 576 byte duoi EIP-170); rieng `init_code` phai < 49,152 byte (EIP-3860);
3. `slither` + `slither-check-upgradeability`;
4. OZ `validateUpgrade` doi chieu `storage-layouts/v<N-1>/`;
5. mot job rieng chay bon invariant o muc 1.9 voi 50,000 run, `depth = 64`;
6. **fork test** tren Gnosis va Celo mainnet fork voi **dia chi USDT/USDC that**, khong voi mock. Mot mock ERC-20 khong co fee-on-transfer, khong co blacklist, va khong thieu return value — tuc la no khong thu duoc bat ky cai bay nao o 1.6.1;
7. **determinism gate**: build hai lan trong hai container sach, `diff` `keccak256(init_code)`. Khac nhau = fail. Day la CI test duy nhat bao ve muc 1.4;
8. `PredictAddress.s.sol` chay tren moi chain trong `blockchain.chain` va so ket qua voi `blockchain.token.predicted_address` da luu; lech = fail.

---

### 1.15. Ba use case to archetype to profile — bang quyet dinh

Khoa quyet dinh #3 dua ca ba use case vao pham vi. Ban nhap khong anh xa chung. Day la bang quyet dinh, va no la thu doi truc can khi mot yeu cau nghiep vu moi den:

| Use case | Archetype | Token class | Profile khoi diem | Peg mode | Doi ra tien phap dinh? | Pause/Freeze | Rui ro phap ly chinh |
|---|---|---|---|---|---|---|---|
| **Loyalty / reward point** | `ISSUER_NATIVE` | `ZTokenOpen` | public (Gnosis) hoac private | `FIXED_RATE`, rate khong giam | **Khong.** Chi doi hang/chiet khau | `pause` 7 ngay. Khong `freeze` | Thap. Khong redeem tien = kho bi coi la phuong tien thanh toan |
| **B2B settlement (brand to distributor)** | `PEG_RATIO` (Z-VND) hoac `WRAP_1_1` (Z-USDT) | `ZTokenPermissioned` | **private truoc** | `FIXED_RATE`, reserve VND | Co, hang doi T+1 | `pause` + `freeze` theo lenh toa | Cao. §13 |
| **Thanh toan nguoi dung cuoi** | `WRAP_1_1` cua mot token e-money da co giay phep, HOAC `PEG_RATIO` Z-VND | tuy giay phep | public sau khi co giay phep | theo giay phep | Co | theo giay phep | Cao nhat. Khong lam truoc §13 |

Ba he qua dieu huong ke hoach:

1. **Loyalty di truoc**, khong phai vi de nhat ky thuat ma vi no la use case duy nhat khong phu thuoc mot ket luan phap ly con treo. `ISSUER_NATIVE` + `ZTokenOpen` + Gnosis co the deploy va chay that trong wave 1.
2. **B2B settlement can Zether va can private chain**, va con so o 1.12.2 noi ro tai sao: 45 tx/s tren Besu la du cho B2B, 0.45 tx/s tren Gnosis thi khong.
3. **Thanh toan nguoi dung cuoi khong the chay tren Zether o quy mo** voi Bulletproofs. Neu use case do that su duoc theo duoi, no bat buoc keo theo lua chon Groth16 o 1.12.1 hoac bo confidentiality o luong do. Do la mot danh doi phai duoc dat ra truoc khi viet dong code dau tien, khong phai sau.

---

### 1.16. Chain profile o tang token — private chain la chain nao

§08.10 chot stack private la **Hyperledger Besu + QBFT**. Section nay chi ghi lai nhung tham so cua chain do **anh huong truc tiep den token design**, vi chung la dieu kien bien cua moi con so o tren:

| Tham so genesis Besu | Gia tri de xuat | Vi sao token design quan tam |
|---|---|---|
| `blockperiodseconds` (QBFT) | 2 | Mau so cua con so thong luong o 1.12.2 |
| `gaslimit` | `0xBEBC200` (200,000,000) | Cho phep 105 Zether tx/block ve mat gas; tran that la CPU |
| `zeroBaseFee` / gas price 0 | bat | Hien thuc hoa khoa quyet dinh #5: "gas khong phai la moi lo" |
| `contractSizeLimit` | **giu 24576** | Khong noi long. Neu noi long, public build va private build phan nhanh, va ta co hai codebase de audit |
| `evmStackSize` | mac dinh | — |
| Fork | `cancun` | Phai khop `foundry.toml`. Neu Besu build khong ho tro cancun, ha `evm_version` cho **ca hai** profile |
| So validator | 4 (chiu duoc 1 loi) hoac 7 (chiu duoc 2) | 4 la toi thieu BFT that. 3 khong chiu duoc loi nao |
| Permissioning | on-chain node + account allowlist | La co so cua `ZTokenPermissioned` (1.10) |

**Diem quan trong ma ban nhap khong noi: "private chain" khong xoa bo nhu cau finality gate.** QBFT co instant finality (mot block da vote la final), nen `finality_hard_blocks = 1`. Nhung neu chi co 4 validator va 2 trong so do la may cua ta trong cung mot AZ, thi "finality" la mot phat bieu ve mot he thong ta so huu. Nguyen tac `dms_vietqr` van ap dung, chi la nguong khac: `_set_done` khi block da final **va** it nhat 2 validator doc lap (khac chu so huu ha tang) da ky.

**Cau con treo:** ai chay 4 validator do? Neu ca 4 la cua ta thi "permissioned blockchain" ve mat ky thuat la mot database Postgres dat tien co chu ky. Dieu do khong sai — no van cho immutability, audit trail, va Zether — nhung phai goi dung ten trong tai lieu ban hang. Xem 1.19.

---

### 1.17. Vong doi day du: runbook deploy, migrate, retire

#### 1.17.1. Deploy (16 buoc, tuong ung state machine o 1.2)

| # | Buoc | Actor | State sau buoc |
|---|---|---|---|
| 1 | Tao `blockchain.token`, chon archetype + prototype + chain | Nghiep vu | `draft` |
| 2 | Kiem `prototype.profileMask` khop `chain.chain_profile` | He thong | `draft` |
| 3 | Kiem `max_supply_base <= 2^44` | He thong | `draft` |
| 4 | Sinh `initData`, tinh `keccak256(initData)`, dung `salt` (1.4.3) | He thong | `draft` |
| 5 | Goi `registry.predictAddress()`, luu `predicted_address` | He thong | `predicted` |
| 6 | Phe duyet (Safe 3-of-5 neu `PEG_RATIO`, tu dong neu `ISSUER_NATIVE` loyalty) | Nguoi | `predicted` |
| 7 | `_cron_broadcast_pending_deploys` khoa record (`FOR UPDATE SKIP LOCKED`) | Cron | `predicted` |
| 8 | Broadcast `registry.deploy(archetype, v, salt, initData)` | HSM key | `broadcast` |
| 9 | Nhan tx hash, luu `deploy_tx_hash`, commit **truoc** khi lam gi khac | He thong | `broadcast` |
| 10 | Receipt `status == 1` | Indexer | `pending_finality` |
| 11 | Dat `finality_hard_blocks` cua chain | Indexer | `pending_finality` |
| 12 | So `EXTCODEHASH` voi `prototype.expected_proxy_code_hash` | Cron | `verified` hoac `mismatch` |
| 13 | So `token.beacon()` voi `prototype.beacon_address` | Cron | `verified` hoac `mismatch` |
| 14 | So `token.owner()`/`getRoleMember(DEFAULT_ADMIN_ROLE)` voi Safe ky vong | Cron | `verified` hoac `mismatch` |
| 15 | Verify source tren Blockscout/explorer (chain public) | CI | `verified` |
| 16 | Set `live`; tu day `blockchain_list_tokens` moi tra ve token nay | He thong | `live` |

Buoc 9 la buoc de sai nhat: neu broadcast xong ma chua commit tx hash da co exception, record ve `predicted` va cron se broadcast lan hai. `UNIQUE(chain_id, salt_hex)` khong cuu duoc vi salt giong nhau va `CREATE2` lan hai revert — nhung ta mat mot lan gas va co mot tx that bai trong so sach. Commit ngay sau khi co tx hash.

#### 1.17.2. Migrate (khi upgrade khong du)

Upgrade beacon giai quyet loi logic. No **khong** giai quyet duoc: doi storage layout khong tuong thich, doi decimals, doi archetype, doi chain. Cho nhung viec do can migration:

```solidity
contract MigrationSink {
    IERC20Burnable public immutable oldToken;
    IERC20Mintable public immutable newToken;
    uint256 public immutable ratioNum;     // thuong 1:1
    uint256 public immutable ratioDen;
    uint64  public immutable deadline;     // sau moc nay, phan chua doi ve RecoveryVault

    function migrate(uint256 amount) external {
        oldToken.burnFrom(msg.sender, amount);
        newToken.mint(msg.sender, Math.mulDiv(amount, ratioNum, ratioDen));
    }
}
```

Ba dieu kien bat buoc di kem, khong duoc bo:

- `oldToken` phai vao `WIND_DOWN` truoc (mint tat) — neu khong, tong cung tien cua hai token cong lai vuot `maxSupply`.
- `newToken.MINTER` cap cho `MigrationSink` phai co `maxMintPerEpoch = oldToken.totalSupply()` va **het han** sau `deadline`.
- So du **confidential** khong migrate duoc bang `burnFrom` (contract khong biet no bang bao nhieu). Nguoi giu phai `withdraw` ve cong khai truoc. Do la mot chien dich truyen thong, khong phai mot ham. **Cua so `deadline` toi thieu 180 ngay** vi ly do nay.

#### 1.17.3. Retire

`retired` nghia la: khong mint, khong migrate, `RecoveryVault` da dong, va record Odoo giu lai vinh vien de doi soat lich su. Contract on-chain **khong bien mat** va van co the co nguoi cam token. Odoo phai tiep tuc index no (o muc toi thieu: log `Transfer`) trong 10 nam theo yeu cau luu tru chung tu ke toan. `active = False` trong Odoo **khong** duoc dung tat indexer.

---

### 1.18. Nhung gi co y KHONG lam trong v1

Danh sach nay ton tai de mot nguoi doc plan sau nay khong tuong day la thieu sot:

| Khong lam | Ly do | Them khi nao |
|---|---|---|
| Diamond (EIP-2535) | Tach `BulletproofVerifier` bang `staticcall` giai quyet EIP-170 voi 0.18% gas overhead | Khong bao gio, tru khi co mot yeu cau ma facet la cach duy nhat |
| Basket / gio nhieu ERC-20 | N oracle = N diem gay; rebalance can mot khoa co quyen ban reserve | Khi co mot use case cu the va mot nguoi chiu trach nhiem treasury |
| AMM TWAP oracle | Khong co pool VND thanh khoan | Khong bao gio cho VND |
| Groth16 / PLONK verifier | Can trusted setup ceremony; Bulletproofs du cho private chain | Khi Zether phai chay tren public chain o quy mo (1.12.1) |
| Anonymity set trong Zether | Khoa quyet dinh: lo danh tinh, an so tien. Anonymity set con lam gas x4 | Khong bao gio (mau thuan voi AML) |
| CI gate cho cross-chain address parity | Parity la nice-to-have; client resolve dia chi qua RPC | Khong |
| `WRAP_SHARES` (rebasing underlying, kieu ERC-4626) | `WRAP_1_1` tu choi rebasing token o registry | Khi co yeu cau wrap stETH/aToken |
| Rate theo lo (`mapping(batchId => rate)`) | Thay bang chinh sach "rate khong giam" | Neu chinh sach do khong duoc chap nhan (1.7.4) |
| Bridge private to public cho Z-VND | Mot bridge la mot he thong rieng voi mo hinh de doa rieng | §08, wave sau |

---

### 1.19. Cau hoi con lai cho nguoi quyet dinh

Tam cau duoi day khong the tra loi bang ky thuat, va moi cau chan mot phan cua implementation:

1. **Z-VND co doi ra tien phap dinh VND duoc khong?** Cau tra loi quyet dinh giay phep (§13), quyet dinh `ZTokenOpen` co hop phap khong, va quyet dinh ca kien truc reserve o 1.7. Neu cau tra loi la "khong" thi 60% do phuc tap cua section nay bien mat.
2. **`decimals` cua Z-VND: 2 hay 0?** Bat bien sau khi deploy. `2` cho phep phi phan tram va giam dust 100 lan; `0` giam thoi gian khoi phuc Zether 10 lan va khop `res.currency` VND. Khuyen nghi `2`. Can chu ky.
3. **Tran cung tien (`maxSupply`) cua moi token la bao nhieu?** Phai `<= 2^44` raw. Voi decimals 2 do la 175,900 ty VND — nhung con so *nghiep vu* thi thap hon nhieu va no phai duoc chon truoc khi `initialize()`.
4. **Ai la 7 nguoi ky Safe `DEFAULT_ADMIN_ROLE`, va co it nhat mot nguoi ngoai cong ty khong?** Bay khoa cua bay nhan vien cung mot cong ty la mot chu ky, khong phai bay.
5. **Ai chay 4 validator cua private chain?** Neu ca 4 la cua ta, phai goi dung ten trong tai lieu (1.16).
6. **Ai ky reserve attestation, cadence nao, ngan sach bao nhieu?** Mot cong ty kiem toan lon se khong ky hang thang cho mot float nho. Neu khong co ai ky, thi `PEG_RATIO` voi reserve off-chain khong the chay va chi con `WRAP_1_1` on-chain.
7. **Chap nhan `MAX_PAUSE = 7 ngay` va loi thoat duy nhat la `WIND_DOWN` mot chieu?** Day la mot cam ket voi nguoi giu token ma sau nay khong the rut lai.
8. **Neu quy dinh doi hoi kha nang tich thu (seizure), ta chon (a) token khong redeem duoc, hay (b) private chain voi `forceTransfer`?** Khong co lua chon thu ba tren Zether (1.10.3).

---

### 1.20. Kiem chung bat buoc — khong tin code, tin chain va `pg_constraint`

Tam lenh, chay truoc khi bat ky ai noi "xong":

```bash
# 1. Constraint co that su ton tai trong Postgres khong (Odoo 19 bo qua _sql_constraints dang list)
psql -c "SELECT conname, contype FROM pg_constraint WHERE conrelid='blockchain_token'::regclass;"

# 2. Deterministic deployer co tren chain khong
cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url $RPC

# 3. Build hai lan trong hai container sach, init_code hash phai giong het
docker run --rm -v $PWD:/w -w /w/smartcontracts/evm foundry forge build && \
  cast keccak $(jq -r '.bytecode.object' out/BeaconProxy.sol/BeaconProxy.json)

# 4. Dia chi du doan trong Odoo khop dia chi tinh tu chain
forge script script/PredictAddress.s.sol --rpc-url $RPC --sig "run(bytes32)" $SALT

# 5. Code that su nam o dia chi do (chan A4 va metamorphic)
cast keccak $(cast code $TOKEN --rpc-url $RPC)

# 6. Beacon owner la timelock, khong phai mot EOA
cast call $BEACON "owner()(address)" --rpc-url $RPC

# 7. Kich thuoc contract duoi 24,000 byte tren MOI contract
forge build --sizes | awk '$3 > 24000 {print; found=1} END {exit found}'

# 8. Addon cai duoc tren database khong co dms
odoo -d test_no_dms -i dms_blockchain --stop-after-init --test-enable
```

Lenh 8 la lenh quan trong nhat trong section nay: khoa quyet dinh #7 (`dms_blockchain` doc lap) la thu de vi pham nhat va de phat hien nhat, va no chi duoc dam bao boi mot lenh chay trong CI, khong boi mot dong trong tai lieu nay.
