## 14. Cay smartcontracts/, toolchain va chien luoc kiem thu

> `blockchain.md` không có một dòng nào về repo hợp đồng, toolchain hay kiểm thử. Toàn bộ phần này là bổ sung. Nó cũng là nơi **hoà giải bốn cây thư mục mâu thuẫn** mà §01.14, §02.8.4, §03.9 và §04 đã đưa ra độc lập với nhau, và là nơi **phát hiện ba mâu thuẫn nữa** giữa các section mà không section nào tự thấy được: client private chain (§03 chọn go-quorum, §08.10 chọn Besu), `evm_version` (§01 chọn `cancun`, genesis §08.10 khai `shanghaiTime`), và đường cong ElGamal (§03 khuyến nghị Baby Jubjub, §14.1 bản nháp vẫn liệt kê `CurveBN254/CurveBLS12381`).

---

### 14.0. Kết luận trước

| Quyết định | Chọn | Lý do một dòng |
|---|---|---|
| Số Foundry project cho EVM | **Một**, tại `smartcontracts/evm/` | `ZetherToken` import `MetaTxLib`, `registry` import `Bn254`, `adapters` import cả hai — bốn project rời sẽ phải submodule lẫn nhau và mất invariant xuyên biên |
| Foundry vs Hardhat | **Foundry, không cài Hardhat** | Test viết bằng Solidity ⇒ fuzz/invariant/fork miễn phí; khoảng trống duy nhất (OZ upgrade safety) đã có `openzeppelin-foundry-upgrades` chạy qua FFI |
| Ngoại lệ Node duy nhất | `evm/ts-conformance/` (~400 dòng viem) | CIP-64 fee currency và EIP-712 cross-check **không** làm được bằng `forge`; xem §14.6 và §14.13(4) |
| Non-EVM | Toolchain **bản địa**, không lớp bọc chung | `sui move test`, `cargo test` + `soroban-sdk::testutils`, `cw-multi-test`, `@ton/sandbox` — mỗi cái đã là runner tốt nhất cho VM của nó |
| Điều phối đa toolchain | `Makefile` ở gốc + `mise.toml` ghim version, **không** npm workspace | Không có JS ở giữa Rust/Move/Solidity thì đừng dựng một cái |
| Public vs private build | **Hai contract cụ thể** từ một abstract base, **không** phải build profile | Solidity không có `#ifdef`; xem mâu thuẫn (2) §14.13 |
| `via_ir` | **Tắt mặc định**, bật riêng khi legacy pipeline thật sự gãy | Bản nháp coi nó là bắt buộc. Không đúng với `struct calldata`; và bật nó **chặn `forge coverage`** cùng ×6–13 thời gian build — xem §14.2b |
| `bytecode_hash` | **`"ipfs"` (mặc định)**, tính tái lập bảo đảm bằng determinism gate | `"none"` mua tính tái lập bằng cách **mất full-match trên Sourcify**; ta không cần mua vì nguyên nhân nondeterminism là toolchain, không phải metadata — §14.2 |
| Invariant runs | 1,000 trên PR / 50,000 nightly | 50k × depth 50 = 2.5M call ≈ 25–60 phút, quá chậm cho vòng lặp PR |
| Verifier trong invariant suite | **`MockVerifier` trả `true`** cho mọi invariant kế toán | Verifier thật tốn 9–28 ms CPU/call ⇒ 50k call = 8–23 phút chỉ riêng crypto. Invariant kế toán không cần crypto thật — §14.4b |
| Devnet CI | **anvil** cho public profile, **Besu QBFT một node** cho private profile | anvil ≠ Besu ở gas semantics, permissioning, `contractSizeLimit` và `zeroBaseFee`; test private trên anvil là test sai chain |
| Native precompile Zether | **Hoãn wave 1**; nếu làm thì làm **trong Besu bằng Java 21 FFM**, không đổi sang go-quorum | §08.10 đã loại GoQuorum (maintenance mode). §03 chọn go-quorum vì "Besu cần JNI" — lập luận đó đã cũ, xem §14.13(9) |
| Test Odoo chạm chain | Job riêng, có sidecar anvil, `evm_snapshot`/`evm_revert` quanh mỗi test | Odoo rollback transaction; chain **không** rollback |
| ABI | **Artifact commit vào repo** (`evm/abi/*.json`), Odoo đọc file, không copy tay | ABI trôi là cách hỏng phổ biến nhất giữa hai cây repo; §14.12b |
| Gate quan trọng nhất | `forge snapshot --check`, storage-layout diff, **determinism gate**, **ABI drift gate** | Đây là bốn thứ hỏng âm thầm và chỉ lộ ra khi đã deploy |
| Licence | `interfaces/` + `relayer-ref/` **Apache-2.0**; core **BUSL-1.1 → Apache sau 24 tháng** | Open Relayer thứ ba không tồn tại nếu không có phần mềm cho phép chạy; §14.15(6) |

---

### 14.0b. Bảy giả định bản nháp không nói ra

Bản nháp đọc trơn tru vì nó im lặng về bảy thứ. Viết ra thành lời, mỗi cái đều đổi một con số hoặc một quyết định:

| # | Giả định ngầm | Có đúng không | Hệ quả nếu sai |
|---|---|---|---|
| A1 | Toàn bộ test chạy trên **GitHub-hosted runner 2 vCPU / 7 GB** | Chưa ai chốt. Toàn bộ bảng thời lượng §14.14 chỉ đúng với ≥ 4 vCPU | 25 phút thành 50 phút; đội sẽ tắt gate |
| A2 | Invariant suite gọi **verifier thật** | Bản nháp không nói. Nếu thật thì 1,000×50 run mất 8–23 phút CPU chỉ cho `ecMul` | PR pipeline vỡ ngân sách; xem §14.4b |
| A3 | `via_ir = true` là bắt buộc và miễn phí | Sai cả hai vế | Build ×6–13, `forge coverage` không chạy được ⇒ gate coverage 90% ở §14.14 là gate chết |
| A4 | Fork test có RPC không giới hạn | Sai. Không cache, mỗi lần chạy đốt 2k–10k request | CI đỏ ngẫu nhiên vì 429, và hết quota Alchemy giữa tháng |
| A5 | Verifier Solidity là **implementation duy nhất** trên chain | Sai nếu §03.3.9 làm native precompile ⇒ **ba** implementation phải khớp | Một chain nói proof hợp lệ, chain kia nói không |
| A6 | `ZetherToken` chỉ có một đường chạm `underlying` (I11) | Đúng **chỉ khi** token không đồng thời là ERC-20 công khai. `IZetherToken is IERC20` (blockchain.md §10.5.3) phá vỡ giả định này | I11 sai âm thầm: `transfer()` công khai cũng đổi số dư mà không qua deposit/withdraw. Xem I11' ở §14.4 |
| A7 | `dms_blockchain` được test trong một DB đã có `dms` | Vi phạm locked #7 | Một `depends` lén hoặc một `env['dms.x']` sẽ không bị bắt cho tới lúc khách cài standalone. Xem §14.11b |

Giả định A6 là nguy hiểm nhất trong bảng vì nó làm một invariant **xanh mà vô nghĩa** — dạng lỗi tệ hơn không có invariant.

---

### 14.1. Cây `smartcontracts/` chuẩn (gốc repo, ngoài addon — locked #9)

```
/home/dockers/odoo19/smartcontracts/
├── mise.toml                      # ghim foundry, rust, node, sui, stellar, wasmd, slither
├── Makefile                       # test | lint | snapshot | devnet | deploy | rehearse | kat
├── README.md
├── LICENSE                        # Apache-2.0 (mặc định cây)
├── LICENSE-BUSL                   # áp cho src/zether/, src/peg/ — xem §14.15(6)
├── CODEOWNERS                     # src/zether/** -> @crypto-pod; src/metatx/** -> @protocol-pod
├── SECURITY.md                    # điểm liên hệ, bug bounty scope, SLA vá
├── evm/                           # MỘT Foundry project cho toàn bộ EVM
│   ├── foundry.toml
│   ├── remappings.txt
│   ├── .solhint.json              # bổ trợ forge fmt: naming, custom-error, no-tx-origin
│   ├── lib/                       # git submodule GHIM COMMIT: forge-std, openzeppelin-contracts(-upgradeable), solady
│   ├── src/
│   │   ├── factory/{DeterministicFactory.sol,ContractPrototypeRegistry.sol}
│   │   ├── proxy/{DmsBeaconProxy.sol,DmsUpgradeableBeacon.sol,PinnedProxy.sol}
│   │   ├── metatx/
│   │   │   ├── MetaTxForwarder.sol            # verifyingContract, UUPS
│   │   │   ├── MetaTxBatcher.sol              # §16 P03: batch N=50, try/catch từng item
│   │   │   └── lib/{MetaTxLib.sol,ExcessivelySafeCall.sol}
│   │   ├── registry/
│   │   │   ├── ZetherAccountRegistry.sol      # singleton canonical
│   │   │   ├── ZetherRegistryMirror.sol
│   │   │   ├── interfaces/{IZetherAccountRegistry,ISignatureVerifier,IRegistrationPolicy,
│   │   │   │               ICompliancePolicy}.sol
│   │   │   ├── verifiers/{SchnorrBn254,EcdsaMultisig,MuSig2Bn254,BlsBn254,Bls12381,
│   │   │   │              PqCommitment,SmartAccount1271}Verifier.sol
│   │   │   └── policy/{Open,Invite,Attested}RegistrationPolicy.sol
│   │   ├── token/{ZTokenBase,ZTokenOpen,ZTokenPermissioned,IssuerNativeToken,
│   │   │          WrappedToken,PeggedToken}.sol
│   │   ├── peg/{ReserveVault,SignedRateSource,PegController,ReserveAttestation,RecoveryVault}.sol
│   │   ├── zether/
│   │   │   ├── ZetherTokenBase.sol            # abstract: toàn bộ logic chung
│   │   │   ├── ZetherTokenOpen.sol            # public profile — KHÔNG có recoverAccount
│   │   │   ├── ZetherTokenRecoverable.sol     # private profile — CÓ recoverAccount (§07.10)
│   │   │   ├── verifier/{IZetherVerifier,BulletproofsVerifier,Groth16Verifier,
│   │   │   │             NativePrecompileVerifier}.sol
│   │   │   ├── curve/{IZetherCurve,CurveBabyJubjub,CurveBn254}.sol   # SỬA: Baby Jubjub là mặc định (§03.3.9)
│   │   │   └── lib/{Transcript.sol,Bn254.sol,BabyJubjub.sol}
│   │   ├── adapters/{EIP1776ForwarderAdapter.sol,EIP1776EntryPointAdapter.sol}
│   │   └── governance/{DmsTimelock.sol,Guardian.sol}
│   ├── test/
│   │   ├── base/{ProfileParityBase.t.sol,CurveParityBase.t.sol}   # abstract test base dùng chung
│   │   ├── unit/          *.t.sol
│   │   ├── invariant/{SupplyInvariant,WrapInvariant,PegInvariant,NonceInvariant,
│   │   │              FeeInvariant,ZetherPoolInvariant,RegistryInvariant,
│   │   │              PauseInvariant,EpochInvariant}.t.sol
│   │   ├── handlers/{TokenHandler,ForwarderHandler,ZetherHandler,RegistryHandler}.sol
│   │   ├── differential/{ZetherProofDiff.t.sol,KatVectors.t.sol,Eip712Kat.t.sol}
│   │   ├── fork/{GnosisFork.t.sol,CeloFork.t.sol,HederaFork.t.sol}
│   │   ├── symbolic/{MetaTxLib.halmos.t.sol,Bn254.halmos.t.sol,Peg.halmos.t.sol}
│   │   └── mocks/{MockERC20,MockUsdtNoReturn,MockFeeOnTransfer,MockBlacklistToken,
│   │              MockFeeCurrency,MockVerifier,MockHts,RevertingTarget,
│   │              ReentrantTarget,GasGriefTarget,Returns64KBTarget}.sol
│   ├── script/{Deploy.s.sol,PredictAddress.s.sol,UpgradeRehearsal.s.sol,
│   │           SyncAddressBook.s.sol,ProbePrecompiles.s.sol,BootstrapCreate2.s.sol}
│   ├── abi/                       # ARTIFACT COMMIT — nguồn ABI duy nhất cho Odoo (§14.12b)
│   ├── snapshots/{.gas-snapshot,.gas-snapshot.l2,.gas-snapshot.private}
│   ├── storage-layouts/v1/*.json
│   └── build-info/                # solc input/output JSON theo commit, cho verify sau nhiều năm
├── evm/ts-conformance/            # NGOẠI LỆ Node duy nhất: CIP-64, EIP-712 cross-check (§14.6)
├── crates/
│   ├── zether-core/               # Rust: prover + verifier tham chiếu (nguồn chân lý mật mã)
│   │   ├── fuzz/                  # cargo-fuzz: deserialize_proof, verify, transcript
│   │   └── benches/               # criterion: bsgs.rs, prove.rs, msm.rs
│   ├── zether-ffi/                # .so Android / xcframework iOS
│   ├── zether-wasm/               # browser + Node
│   ├── zether-oracle-{enclave,threshold}/   # §07: ba impl key oracle
│   └── kat-gen/                   # sinh & ký test vector, chạy tay, không chạy trong CI
├── besu-precompile/               # nếu quyết làm native verify: Java 21 FFM + lib Rust (§14.13(9))
├── circuits/zether_transfer/      # circom/noir, đường thay thế Groth16 (§03)
├── testvectors/
│   ├── zether_transfer_v1.json    # KAT dương
│   ├── zether_transfer_v1.neg.json# KAT âm (proof phải FAIL)
│   ├── eip1776_digest_v1.json     # EIP-712 digest + typehash, ký bởi khoá cố định
│   ├── eip1776_digest_v1.neg.json # digest phải KHÁC (field bị đổi, dynamic bytes bị splice)
│   ├── schnorr_pop_v1.json
│   └── intent_v1.json             # §05, dùng chung với relayer-ref
├── relayer-ref/                   # TypeScript, ~400 dòng, Docker image bamboo/relayer (§05)
├── devnet/
│   ├── docker-compose.ci.yml      # anvil + besu-qbft (+ blockscout tuỳ chọn)
│   ├── besu/{genesis.qbft.json,config.toml,permissions_config.toml}
│   ├── check-genesis-fork.sh      # gate: evm_version của foundry.toml == fork của genesis
│   └── seed.sh                    # deploy full stack, ghi addresses/ci.json
├── addresses/                     # address book, một file mỗi CAIP-2
│   ├── eip155-100.json            # Gnosis
│   ├── eip155-42220.json          # Celo
│   └── eip155-1337001.json        # Besu private
├── hbar/  ton/  sui/  soroban/  cosmwasm/     # xem §14.3
└── .github/workflows/{contracts.yml,contracts-nightly.yml,verify-drift.yml}
```

Hoà giải với các section trước: §01.14 đặt `src/` phẳng, §02.8.4 đặt `evm/registry/foundry.toml`, §03.9 đặt `evm/zether/src/`, §04 đặt `evm/metatx/`. **Cả bốn đều bị thay bởi cây trên.** Chia theo *purpose* vẫn giữ nguyên — nhưng ở mức `src/<purpose>/`, không ở mức project. Lý do cụ thể, không phải thẩm mỹ: `ZetherTokenBase` gọi `MetaTxLib._msgSender()`, `AttestedRegistrationPolicy` dùng `Bn254`, `EIP1776ForwarderAdapter` cần cả `MetaTxForwarder` lẫn interface OZ. Bốn project rời ⇒ ba `remappings` trỏ vào submodule chéo, `forge snapshot` bốn file rời, và **không** viết được invariant "một meta-tx Zether không tạo ra token từ hư không" vì nó cắt qua ba project.

Bốn thư mục bản nháp **thiếu**, và mỗi cái đều đắt nếu thêm sau:

- `evm/abi/` — nếu Odoo copy ABI bằng tay thì ngày verifier đổi signature, addon sẽ encode calldata sai và **giao dịch revert on-chain sau khi đã trả gas**. Gate ở §14.12b.
- `evm/build-info/` — Sourcify/Blockscout cần Standard JSON Input để verify. Ba năm nữa, khi cần chứng minh với kiểm toán rằng bytecode ở địa chỉ X đến từ commit Y, không ai dựng lại được môi trường solc cũ nếu không có file này. ~2–8 MB mỗi build, commit theo tag release, không theo mỗi commit.
- `test/base/` — abstract test base là cách duy nhất để `ZetherTokenOpen` và `ZetherTokenRecoverable` chạy **cùng một** bộ test. Không có nó, private profile sẽ có ít test hơn public đúng vào chỗ nó khác biệt.
- `crates/zether-core/fuzz/` — verifier Rust chạy **trong relayer**, tức là nó parse byte từ Internet. Một `panic!` khi deserialize proof dị dạng là DoS toàn mạng relayer. Đây không phải "nice to have".

---

### 14.2. `foundry.toml`: profile và cái mà profile **không** làm được

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"
solc = "0.8.28"                      # GHIM. Đổi minor ⇒ đổi bytecode ⇒ đổi địa chỉ CREATE2
evm_version = "cancun"               # PHẢI khớp genesis private chain — gate ở devnet/check-genesis-fork.sh
optimizer = true
optimizer_runs = 200                 # GHIM. Đổi con số này ⇒ đổi địa chỉ CREATE2
via_ir = false                       # SỬA so với bản nháp: mặc định TẮT, xem §14.2b
bytecode_hash = "ipfs"               # SỬA: giữ mặc định để Sourcify full-match được
cbor_metadata = true
ffi = false                          # bật riêng ở profile differential/upgrade
fs_permissions = [{ access = "read", path = "../testvectors" }]
build_info = true
extra_output = ["storageLayout"]

[profile.ci]
verbosity = 3
fuzz = { runs = 1000, max_test_rejects = 200000, failure_persist_dir = "cache/fuzz" }
invariant = { runs = 1000, depth = 50, fail_on_revert = false, shrink_run_limit = 2000 }

[profile.deep]                        # nightly
fuzz = { runs = 100000 }
invariant = { runs = 50000, depth = 100, shrink_run_limit = 5000 }

[profile.differential]
ffi = true                            # gọi binary Rust zether-core làm oracle

[profile.viair]                       # CHỈ dùng nếu profile.default gãy vì stack-too-deep
via_ir = true

[profile.coverage]                    # via_ir tắt bắt buộc; optimizer tắt cho line mapping đúng
via_ir = false
optimizer = false

[profile.l2]                          # Celo: L2 OP Stack — snapshot riêng, xem cảnh báo §14.7
gas_price = 1

[profile.private]                     # Besu QBFT: contractSizeLimit nâng, zeroBaseFee
gas_price = 0

[rpc_endpoints]
gnosis = "${RPC_GNOSIS}"
celo   = "${RPC_CELO}"
besu   = "${RPC_BESU}"
hedera = "${RPC_HEDERA_TESTNET}"

[etherscan]
gnosis = { key = "${BLOCKSCOUT_KEY}", url = "https://gnosis.blockscout.com/api/" }
celo   = { key = "${BLOCKSCOUT_KEY}", url = "https://celo.blockscout.com/api/" }
```

Bốn dòng đáng giải thích, và **hai dòng bản nháp đã sai**:

**`optimizer_runs = 200` chứ không phải 1,000,000.** `BulletproofsVerifier` là contract lớn nhất và ta đang ép nó xuống dưới EIP-170 (24,576 byte). Runs thấp ⇒ bytecode nhỏ hơn, gas runtime cao hơn. Đánh đổi này phải được **đo**, không đoán — xem gate `--sizes` ở §14.7.

**`ffi = false` ở default là an ninh, không phải khẩu vị:** một dependency mới trong `lib/` có `vm.ffi` sẽ chạy lệnh shell trên máy dev. Bổ sung bản nháp thiếu: `lib/` chỉ nhận **submodule ghim commit SHA**. `forge install <org>/<repo>@v1.2.3` ghim theo tag, và **tag có thể bị move**. Dependabot không quét git submodule của Foundry ⇒ cần một job nightly `git submodule foreach 'git fetch && git log --oneline HEAD..origin/HEAD | head -5'` mở issue khi upstream có commit mới. Không tự update.

**`bytecode_hash = "none"` — SỬA so với §01.14 và bản nháp §14.** §01.14 viết: *"Không có `bytecode_hash = "none"`, cùng một source build trên hai máy CI cho hai `init_code` khác nhau."* Điều đó **không đúng với Foundry**. Metadata CBOR chứa hash IPFS của **metadata JSON**, mà metadata JSON chỉ phụ thuộc: nội dung source, **đường dẫn tương đối** của source, version solc, và settings compiler. Foundry dùng đường dẫn tương đối tính từ project root ⇒ với cùng solc, cùng settings, cùng cây source, hash giống nhau trên mọi máy. Nguồn nondeterminism thật là: solc khác version (đã ghim), `lib/` khác commit (đã ghim submodule), và remapping khác nhau (đã commit `remappings.txt`).

Cái giá của `"none"` thì có thật: **Sourcify không thể cho full match** khi không có metadata hash, chỉ còn partial match dựa trên so runtime bytecode. Với một hệ thống mà toàn bộ luận điểm là *"ai cũng có thể làm relayer, ai cũng verify được contract"*, mất full match là mất một phần niềm tin công khai.

⇒ **Quyết định: giữ `bytecode_hash = "ipfs"`, và chứng minh tính tái lập bằng determinism gate thay vì bằng cách xoá bằng chứng.**

```bash
# CI job: determinism (chạy mọi PR chạm src/ hoặc lib/)
for d in /tmp/build-a /tmp/build-b; do
  rm -rf "$d" && git worktree add "$d" HEAD
  docker run --rm -v "$d":/w -w /w/evm ghcr.io/foundry-rs/foundry:$FOUNDRY_TAG \
    sh -c 'forge build --force && jq -r ".bytecode.object" out/*/*.json | sha256sum' > "$d.hash"
done
diff /tmp/build-a.hash /tmp/build-b.hash || { echo "BUILD KHONG TAI LAP"; exit 1; }
```

Hai worktree ở hai đường dẫn khác nhau (`/tmp/build-a` vs `/tmp/build-b`) là chủ ý: nếu metadata có nhét đường dẫn tuyệt đối vào, gate này bắt được ngay. Đây là **test duy nhất bảo vệ toàn bộ mục CREATE2 của §01.4** và nó rẻ (2 lần build).

**`evm_version = "cancun"` là một quả mìn cross-section.** §08.10 khai genesis Besu là `"shanghaiTime": 0`, **không** có `cancunTime`. Một contract compile ở `cancun` có thể sinh `TSTORE`/`TLOAD` (OZ `ReentrancyGuardTransient` dùng nó) hoặc `MCOPY` (solc ≥ 0.8.25 tự sinh cho copy memory). Trên Besu shanghai, đó là `INVALID` opcode ⇒ **revert sau khi mọi test đã pass**. Gate cụ thể, 15 dòng bash, chạy mọi PR:

```bash
# devnet/check-genesis-fork.sh
FOUNDRY_FORK=$(grep -Po 'evm_version\s*=\s*"\K[a-z]+' evm/foundry.toml)
if [ "$FOUNDRY_FORK" = "cancun" ] && ! jq -e '.config.cancunTime' devnet/besu/genesis.qbft.json >/dev/null; then
  echo "foundry.toml=cancun nhung genesis Besu chua khai cancunTime"; exit 1
fi
```

Và một test on-chain thật (không phải đọc changelog — §01 gọi đây là giả định A5):

```solidity
// test/unit/ForkCapability.t.sol — chạy trên MỌI chain trong addresses/
function test_chain_supports_transient_storage() public {
    (bool ok,) = address(new TstoreProbe()).call(abi.encodeCall(TstoreProbe.probe, ()));
    assertTrue(ok, "chain khong ho tro TSTORE — ha evm_version cho CA HAI profile");
}
```

---

### 14.2b. `via_ir`: bản nháp trả giá cho một thứ có thể không cần

Bản nháp viết `via_ir = true` với lý do *"cần cho struct MetaTransaction 12 field (stack too deep)"*. Câu đó gộp hai thứ khác nhau. `stack too deep` xảy ra khi có quá nhiều **biến local sống đồng thời** trong một scope, không phải khi một struct có nhiều field. Với chữ ký

```solidity
function executeMetaTransaction(MetaTransaction calldata metaTx, bytes calldata signature)
```

các field được đọc trực tiếp từ calldata (`metaTx.from`, `metaTx.fee`, …) và **không** chiếm stack slot. Stack-too-deep chỉ xuất hiện nếu code destructure struct ra 12 biến local — mà đó là thứ nên sửa ở code, không phải mua `via_ir` để che.

Cái giá của `via_ir`, đo được:

| Đại lượng | `via_ir = false` | `via_ir = true` | Cơ sở |
|---|---|---|---|
| `forge build --force`, ~60 contract, có 1 verifier lớn | 40–70 s | **4–9 phút** | **Ước tính**, hệ số ×6–13 quan sát phổ biến trên project có contract nhiều branch; phải đo lại trên repo thật ở tuần 1 |
| `forge coverage` | chạy | **hỏng hoặc phải `--ir-minimum`** | Foundry issue đã biết: instrumentation coverage + IR pipeline xung đột; `--ir-minimum` đôi khi vẫn stack-too-deep |
| Gas runtime | mốc | thường −3% đến −12% | IR optimizer tốt hơn ở vòng lặp |
| Kích thước bytecode | mốc | thường nhỏ hơn 5–15% | Có ích cho EIP-170 |
| Tính ổn định bytecode giữa các patch solc | cao | thấp hơn | IR pipeline thay đổi nhiều hơn giữa các patch ⇒ nguy cơ đổi địa chỉ CREATE2 khi bump solc |

**Quyết định:** `via_ir = false` mặc định. Nếu `BulletproofsVerifier` không lọt EIP-170 với legacy pipeline, bật `[profile.viair]` **chỉ cho contract đó** (Foundry chưa hỗ trợ per-contract `via_ir` ⇒ thực tế là bật cả project và chấp nhận trả giá, hoặc tách verifier ra library `delegatecall`). Gate coverage ở §14.14 chạy bằng `[profile.coverage]`.

Hệ quả cho §14.14: `build-sizes` là 1–2 phút, không phải 2 phút cố định; nếu buộc phải bật `via_ir`, cột thời lượng của **mọi** job dùng build tăng thêm 4–9 phút và tổng đường tới hạn PR nhảy từ ~25 lên ~35 phút. Đó là con số phải biết **trước** khi bật cờ, không sau.

---

### 14.3. Toolchain theo chain, và cách chúng sống chung

| Chain | Build/test | Runner test | Vì sao chọn |
|---|---|---|---|
| EVM (Gnosis, Celo, Besu) | `forge` | `forge test` (Solidity) | Fuzz + invariant + fork + cheatcode trong cùng một ngôn ngữ với contract; không cần Node |
| Hedera HSCS | **`forge`, dùng lại `evm/`** | `forge test --fork-url $HEDERA_TESTNET_JSONRPC` | HSCS là EVM; khác ở gas model USD-pegged, throttle 15M gas/s toàn mạng, max 15M gas/call, và HTS precompile ở `0x167` — mock ở `test/mocks/MockHts.sol` |
| Sui | `sui move build/test` | `#[test]` trong Move | Không có lựa chọn khác đáng cân nhắc |
| Soroban | `cargo build --target wasm32v1-none` + `stellar contract` | `cargo test` + `soroban_sdk::testutils::Env` | Test chạy trong host env thật của Soroban, nhanh hơn devnet |
| CosmWasm | `cargo wasm` + `cosmwasm-check` | `cargo test` + `cw-multi-test` | `cw-multi-test` mô phỏng cả bank/wasm module, đủ để test `x/feegrant` seam |
| TON | `@ton/blueprint` (func + tact) | `@ton/sandbox` + jest | Sandbox chạy emulator TVM thật; không có tương đương Foundry |
| Rust crypto core | `cargo` | `cargo test` + `proptest` + `cargo-fuzz` + `criterion` | Nguồn chân lý mật mã; xem §14.5 |

**Sống chung mà không đánh nhau — ba quy tắc, hết:**

1. **Không có build system ở gốc.** `Makefile` chỉ là ~15 dòng `cd <dir> && <lệnh bản địa>`. Không Nx, không Turborepo, không npm workspace. Lý do: cây này có Rust, Move, Solidity, TypeScript và WASM; bất kỳ orchestrator nào cũng chỉ hiểu một trong số đó và sẽ nói dối về ba cái còn lại.
2. **Version ghim ở một chỗ**, `mise.toml`. Cảnh báo thực dụng bản nháp bỏ qua: **mise không ghim được Foundry theo commit SHA** (plugin foundry cài theo release tag / `nightly`). Cách ghim thật:
   - CI: dùng **docker image tag bất biến** `ghcr.io/foundry-rs/foundry:nightly-<sha>` — image tag là thứ duy nhất thực sự bất biến.
   - Dev: `foundryup --version nightly-<sha>` ghi trong `README.md` + một `make doctor` so `forge --version` với giá trị mong đợi và **cảnh báo**, không chặn.
   - `rust = "1.85.0"` (tối thiểu cho target `wasm32v1-none` của Soroban), `node = "22"`, `sui = "1.39.x"`, `stellar-cli`, `wasmd`, `slither = "0.10.x"`, `halmos`.
3. **CI chạy theo path filter.** `dorny/paths-filter` chia `evm/**`, `crates/**`, `sui/**`, … Một PR sửa Solidity **không** được kéo theo 9 phút toolchain Sui. Job non-EVM chỉ chạy khi thư mục của nó đổi, cộng một lần nightly cho tất cả.

**Năm thư mục stub `hbar/ ton/ sui/ soroban/ cosmwasm/` — tiêu chí nghiệm thu cụ thể, không phải "hello-world".** Bản nháp nói "một hello-world biên dịch được". Chưa đủ để có giá trị. Mỗi stub phải chứng minh đúng **một** thứ mà §08 đã đặt cược, và đó là thứ sẽ đắt nhất nếu sai:

| Thư mục | Hello-world phải chứng minh | Lệnh CI | Nếu fail thì §08 sai ở đâu |
|---|---|---|---|
| `sui/` | Sponsored transaction hai chữ ký (`sender` ≠ `gas_data.owner`) chạy được trong `sui move test` + một PTB gộp 2 lệnh | `sui move test && sui client ptb --dry-run` | Mô hình relayer trên Sui |
| `soroban/` | `FeeBumpTransactionEnvelope` bọc một invoke, và `extend_ttl` gia hạn được | `cargo test -p soroban-hello` | State rent TTL không phải chuyện "để sau" |
| `cosmwasm/` | `x/feegrant` `BasicAllowance` trả phí hộ một `ExecuteMsg` trong `cw-multi-test` | `cargo test -p cw-hello` | Toàn bộ meta-tx trên Cosmos |
| `ton/` | External message do ví B phát, internal message do ví A ký, Jetton fee về B, trong `@ton/sandbox` | `npx jest` | Mô hình gasless W5 |
| `hbar/` | Không cần thư mục riêng: `HederaFork.t.sol` trong `evm/` gọi HTS precompile `0x167` trên testnet | `forge test --mc HederaFork` | HSCS là EVM thật hay không |

Mục đích không phải chức năng — nó là **kiểm chứng toolchain còn build được và giả định meta-tx còn đúng**, để ngày bắt đầu wave 2 không mất một tuần dựng lại môi trường và một tháng phát hiện mô hình sai. Chi phí: ~2–3 ngày/chain, một lần. Chạy nightly, 9 phút.

---

### 14.4. Invariant: danh sách cụ thể, viết được ngay

Invariant chạy theo mô hình **handler**: fuzzer không gọi thẳng contract mà gọi `TokenHandler`/`ForwarderHandler`, nơi tham số được `bound()` vào miền hợp lệ và **ghost variable** được cập nhật. Không có handler thì 95% call revert và invariant "đúng" một cách vô nghĩa.

Bản nháp nói "mô hình handler" nhưng không nói **cách buộc fuzzer chỉ gọi handler** — thiếu ba dòng đó thì Foundry vẫn fuzz mọi contract đã deploy và mọi thứ ở trên là trang trí:

```solidity
// test/invariant/SupplyInvariant.t.sol
contract SupplyInvariant is StdInvariant, Test {
    TokenHandler handler;
    ZTokenBase   token;

    function setUp() public {
        token   = new ZTokenBase(); token.initialize("Z", "Z", 18);
        handler = new TokenHandler(token);

        targetContract(address(handler));          // CHỈ handler, không phải token
        bytes4[] memory sel = new bytes4[](5);
        sel[0] = TokenHandler.mint.selector;       sel[1] = TokenHandler.burn.selector;
        sel[2] = TokenHandler.transfer.selector;   sel[3] = TokenHandler.wrap.selector;
        sel[4] = TokenHandler.unwrap.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: sel}));
        excludeSender(address(token));             // token tự gọi mình = kịch bản giả
        excludeSender(address(0));
    }

    function invariant_supply_equals_sum_of_balances() public view {
        uint256 sum;
        for (uint256 i; i < handler.actorCount(); ++i) sum += token.balanceOf(handler.actorAt(i));
        assertEq(sum, token.totalSupply(), "supply != sum(balances)");
    }

    function invariant_no_balance_from_nothing() public view {
        assertEq(token.totalSupply(), handler.ghostMinted() - handler.ghostBurned());
    }

    /// Gate chống "invariant chạy không tải" — bản nháp có ý này, đây là chỗ nó phải sống
    function invariant_handler_actually_did_work() public view {
        assertGt(handler.successCount(), 100, "handler hau nhu luon revert: suite dang chay rong");
    }
}
```

`handler.successCount()` phải so với một **ngưỡng tuyệt đối** (100), không phải `runs / 10`: hàm `invariant_*` được gọi sau **mỗi run**, nên `runs/10` sẽ fail ở run thứ nhất dù handler hoàn toàn khoẻ. Đây là lỗi trong bản nháp và nó sẽ làm suite đỏ ngay ngày đầu.

| # | Invariant | Contract | Sai thì mất gì |
|---|---|---|---|
| I1 | `totalSupply == Σ balanceOf` | `ZTokenBase` | Kế toán sai |
| I2 | `totalSupply == ghostMinted − ghostBurned` | `ZTokenBase` | In tiền |
| I3 | `underlying.balanceOf(vault) ≥ wrapped.totalSupply()` | `WrappedToken` | Bank run |
| I4 | `reserveValue × 10^18 ≥ pegged.totalSupply() × rate` | `PegController` | Peg vỡ |
| I5 | `meta_nonce(from,batchId)` **không giảm** và tăng đúng 1 mỗi lần execute thành công | `MetaTxForwarder` | Replay |
| I6 | Với mọi `(from,batchId,nonce)` đã dùng, execute lại **phải** revert | `MetaTxForwarder` | Replay |
| I7 | Execute không revert ⇒ `balanceOf(feeRecipient)` tăng **đúng** `metaTx.fee` | `MetaTxForwarder` | Relayer làm không công ⇒ mạng chết |
| I8 | `block.timestamp > expiry` ⇒ luôn revert | `MetaTxForwarder` | Delayed replay |
| I9 | `mode & MODE_RESTRICT_RELAYER != 0 ∧ msg.sender != relayer` ⇒ revert | `MetaTxLib` | Vô hiệu hoá `mode` |
| I10 | `mode == MODE_OPEN` ⇒ digest **không** phụ thuộc `relayer`/`feeRecipient` | `MetaTxLib` | Chữ ký người dùng bị đóng băng vào một relayer |
| I11 | `ghostDeposited − ghostWithdrawn == underlying.balanceOf(zetherToken)` | `ZetherTokenBase` | Rút nhiều hơn nạp |
| **I11'** | **`ghostDeposited − ghostWithdrawn + ghostErc20In − ghostErc20Out == underlying.balanceOf(zetherToken)`** | `ZetherTokenBase is IERC20` | **Xem ghi chú A6 bên dưới — I11 nguyên bản SAI** |
| I12 | `zetherNonce(addr)` không giảm; tăng đúng 1 mỗi `transferConfidential`/`withdraw` thành công | `ZetherTokenBase` | Replay proof |
| I13 | `isRegistered(a)` một khi `true` không bao giờ về `false`; `keccak256(x,y) == a` | `ZetherAccountRegistry` | Khoá tài khoản người khác |
| I14 | Khi `paused()`, không call nào đổi bất kỳ balance/ciphertext nào | `Pausable` | Circuit breaker giả |
| I15 | `Σ` ciphertext toàn hệ bảo toàn qua `transferConfidential` (cộng đồng hình) | `ZetherTokenBase` | Tạo tiền mã hoá từ hư không |
| **I16** | `keccak256(bytecode(ZetherTokenOpen))` **không chứa** selector `recoverAccount`; `methodIdentifiers` không liệt kê nó | build gate | Backdoor lọt vào public profile |
| **I17** | Mọi hàm public của `ZetherTokenOpen` và `ZetherTokenRecoverable` **trừ** `recoverAccount` cho **cùng kết quả** trên cùng input | `ProfileParityBase` | Hai profile phân kỳ âm thầm; private ít test hơn public |
| **I18** | **[BẢN 5]** `accSeq[x]` chỉ tăng khi `pendingSeq[x]` đã tăng kể từ lần roll trước; `rollOverPublic(x)` trên `pending` rỗng là **no-op không revert**; và nó **revert** khi `mode[x] == OWNER_ONLY` | `ZetherTokenBase` | Griefing rỗng ~30k gas (§03.4.4) lặp vô hạn, miễn phí |
| **I19** | Storage slot của mọi biến trong `v<N>` khớp `v<N-1>` cho các biến trùng tên; slot mới chỉ được **thêm vào cuối** | `storage-layouts/` | Upgrade ghi đè số dư |
| **I20** | `fee` được chuyển **trước** inner call trong mọi đường thực thi (đo bằng thứ tự event) | `MetaTxForwarder` | Xem I7 |
| **I21** | Tổng `escrow` của `SponsorshipPool` ≥ tổng cam kết chưa chi | `SponsorshipPool` (§05) | Relayer relay xong không được trả |
| **I22** | Với mọi curve impl, `add/mul/isOnCurve` cho cùng kết quả trên cùng test vector | `CurveParityBase` | Đổi curve = viết lại test |

**I11 nguyên bản là một invariant xanh mà vô nghĩa.** `blockchain.md` §10.5.3 nguyên tắc 3 nói rõ: *"Mỗi Zether Token Contract kế thừa đầy đủ `IERC20`... vừa hỗ trợ `transfer`, `approve`, `transferFrom` công khai, vừa tích hợp Zether"*. Nếu contract vừa giữ `underlying` cho phần bảo mật vừa là ERC-20 công khai, thì `underlying.balanceOf(zetherToken)` bị đổi bởi **bốn** đường, không phải hai. Viết I11 như bản nháp sẽ pass trong test (vì handler không gọi đường ERC-20 công khai) và fail trên production.

Hai cách sửa, phải chọn một **trước khi viết contract**:

| Lựa chọn | Hệ quả |
|---|---|
| (a) `ZetherToken` **không** phải ERC-20; wrap/unwrap qua `WrappedToken` riêng | I11 nguyên bản đúng lại. Trái với `blockchain.md` §10.5.3 nguyên tắc 3 |
| (b) Giữ `is IERC20`, đổi thành **I11'** với 4 ghost variable, và handler **phải** gọi cả đường công khai | Đúng với note, nhưng invariant phức tạp hơn và dễ viết sai hơn |

**Khuyến nghị (a)**, và ghi vào §14.15 như một câu hỏi cần người quyết: một contract vừa là ERC-20 công khai vừa giữ escrow bảo mật có **hai** kế toán trên **một** số dư, và mọi bug hợp nhất số dư trong lịch sử DeFi đều ở đúng chỗ đó. Nếu buộc phải theo (b), thì `deposit`/`withdraw`/`transfer`/`transferFrom` là bốn hàm duy nhất chạm `underlying` và mọi refactor thêm đường thứ năm là finding Critical.

**I7 là invariant đáng giá nhất trong bảng** và cũng là thứ dễ mất nhất khi refactor: một `try/catch` bọc inner call mà quên revert nhánh fail sẽ khiến relayer trả gas cho một tx không trả phí. Fee phải được chuyển **trước** inner call (I20), và invariant phải chạy với `RevertingTarget`, `ReentrantTarget`, `GasGriefTarget`, `Returns64KBTarget` trong bộ target của handler. `Returns64KBTarget` là mock bản nháp thiếu: một target trả về 64 KB returndata làm forwarder tốn ~2M gas chỉ để copy memory nếu nó không dùng `ExcessivelySafeCall` — đó là cách rẻ nhất để làm cạn ví relayer, và nó không phải lý thuyết.

**I18 chưa có ở bản nháp và nó là lỗ hổng kinh tế, không phải lỗ hổng kế toán.** §03.4.4 đã tính: `rollOver(victim)` permissionless **không có điều kiện** tốn ~30k gas (≈ $0.00006 trên Gnosis) và làm proof đang bay của nạn nhân revert, nạn nhân mất phí relayer và phải prove lại (0.5–1.25 s trên Android). Tỉ lệ chi phí tấn công/thiệt hại là ~1:1000.

**[BẢN 5, 2026-09-03] — invariant đổi hình, không đổi mục đích.** `rollOver` bây giờ permissionless theo mặc định (`RollOverMode.PUBLIC`), nên "cấm bên thứ ba gọi" **không còn là điều được kiểm**. Thứ chặn grief là **điều kiện bump**: một lần bump `accSeq` phải *mua* được bằng một credit thật cho nạn nhân. Ba mệnh đề, và cả ba phải fail được:

```solidity
// 1. Bump phai duoc "mua" bang mot credit that: pendingSeq phai tang truoc.
function invariant_accseq_bump_requires_new_pending() public {
    bytes32 v = handler.victim();
    uint64 accBefore = zether.accSeq(v);
    uint64 pendBefore = zether.pendingSeq(v);
    vm.prank(handler.attacker());
    try zether.rollOverPublic(v) {} catch { return; }
    if (zether.accSeq(v) != accBefore) {
        assertGt(pendBefore, zether.lastRolledPendingSeq0(), "accSeq tang ma khong co pending moi");
    }
}

// 2. Pending rong => NO-OP, khong revert, acc va accSeq khong doi.
//    Revert o day cung sai: no bien mot cron don dep thanh mot cron gay loi.
function invariant_rollover_empty_is_noop() public {
    bytes32 v = handler.idleAccount();                 // khong co credit moi
    (bytes32[2] memory C,) = zether.getEncryptedBalance(v);
    uint64 accBefore = zether.accSeq(v);
    vm.prank(handler.attacker());
    zether.rollOverPublic(v);                          // KHONG duoc revert
    (bytes32[2] memory C2,) = zether.getEncryptedBalance(v);
    assertEq(C[0], C2[0], "no-op ma van doi acc");
    assertEq(zether.accSeq(v), accBefore, "no-op ma van bump accSeq");
}

// 3. Tai khoan OWNER_ONLY: duong permissionless dong hoan toan.
function invariant_owner_only_rejects_public_path() public {
    bytes32 t = handler.treasuryOwnerOnly();
    vm.prank(handler.attacker());
    vm.expectRevert();
    zether.rollOverPublic(t);
}
```

Cộng một test cho `rollOverBatch`: một lô trộn tài khoản `PUBLIC` và `OWNER_ONLY` phải **bỏ qua** phần tử `OWNER_ONLY` chứ **không revert cả lô** — revert cả lô biến một tài khoản treasury thành một cách chặn việc dọn dẹp của mọi tài khoản khác.

`fail_on_revert = false` là đúng cho suite này, nhưng nó phải đi cùng `invariant_handler_actually_did_work` ở trên. Không có cặp đó, `fail_on_revert = false` biến toàn bộ §14.4 thành trang trí.

---

### 14.4b. Vì sao invariant suite **phải** chạy với `MockVerifier` — và tại sao đó không phải gian lận

Bản nháp không nói invariant suite gọi verifier nào. Con số nói tại sao điều đó quyết định cả pipeline:

| Đại lượng | Giá trị | Cơ sở |
|---|---|---|
| MSM cấu hình chốt (§03.3.6, n_v=32 / n_b=64) | 230 điểm | §03 |
| Chi phí một `bn256ScalarMult` trong revm/`gnark-crypto` | 40–120 µs | §03.3.9 |
| ⇒ CPU một lần `verifyTransfer` | **9–28 ms** | 230 × 40–120 µs |
| Số call trong `invariant runs=1000, depth=50` | 50,000 | định nghĩa |
| Nếu 30% call là `transferConfidential` | 15,000 lần verify | giả định handler |
| ⇒ **thời gian chỉ riêng crypto** | **135–420 giây** | 15,000 × 9–28 ms |
| Ở profile `deep` (50,000 runs × depth 100) | 1.5M call, 450k verify | **1.1–3.5 giờ chỉ crypto** |

Ba trăm giây cho một job PR là chấp nhận được; ba tiếng rưỡi cho nightly thì không, vì nó đẩy nightly qua cửa sổ 8 tiếng. Và quan trọng hơn: **các invariant từ I1 đến I22 không có cái nào kiểm tính đúng của mật mã.** Chúng kiểm kế toán, nonce, phí, pause, upgrade. Tính đúng mật mã do §14.5 lo (KAT + differential + fuzz Rust), và đó là chỗ nó thuộc về.

**Quy tắc:** invariant suite deploy `MockVerifier` (`verifyTransfer` luôn `true`, ghi lại statement để assert). Một test riêng, `test/unit/VerifierWiring.t.sol`, chứng minh contract thật **có** gọi verifier và **có** revert khi verifier trả `false` — đó là mối nối duy nhất cần kiểm ở tầng invariant:

```solidity
function test_transfer_reverts_when_verifier_rejects() public {
    mockVerifier.setResult(false);
    vm.expectRevert(ZetherToken.InvalidProof.selector);
    zether.transferConfidential(A, B, _validLookingTransfer());
}
function test_verifier_address_is_immutable_or_timelocked() public {
    vm.expectRevert();           // đổi verifier không được là quyền của owner thường
    vm.prank(owner); zether.setVerifier(address(0xdead));
}
```

Test thứ hai đáng giá riêng: nếu `setVerifier` là `onlyOwner` không timelock, thì toàn bộ bảo mật Zether bằng đúng bảo mật của một khoá EOA. Đó là finding Critical mà không invariant nào bắt được.

---

### 14.5. Differential testing prover ZK, và known-answer vectors

**Bốn** implementation phải đồng ý với nhau, không phải ba như bản nháp nói:

| # | Implementation | Vị trí | Vai trò |
|---|---|---|---|
| 1 | Prover Rust | `crates/zether-core` | **Nguồn chân lý** |
| 2 | Verifier Rust | `crates/zether-core` | Chạy trong relayer và trong client SDK |
| 3 | Verifier Solidity | `src/zether/verifier/BulletproofsVerifier.sol` | Chạy trên public chain |
| 4 | **Native precompile** | `besu-precompile/` hoặc geth patch | Chạy trên private chain **nếu** §03.14 Q4 chốt "có" |

Bản nháp bỏ sót (4). Đó là một sai sót nghiêm trọng vì (4) là thứ **quyết định consensus**: một validator chạy binary có precompile hơi khác sẽ fork chain. Ma trận differential phải là **mọi cặp**, không phải chỉ 1↔3:

```
make kat-matrix
# 1->2  prover Rust  -> verifier Rust        (proptest, 100k witness)
# 1->3  prover Rust  -> verifier Solidity    (forge ffi, profile differential)
# 1->4  prover Rust  -> precompile qua RPC   (cast call 0x...0100 tren devnet Besu)
# 3<->4 CUNG statement, CUNG proof, hai verifier PHAI cho cung ket qua, ke ca voi KAT AM
```

Cặp 3↔4 với **KAT âm** là cặp quan trọng nhất và dễ bị bỏ nhất: hai implementation dễ đồng ý trên proof hợp lệ, và phân kỳ đúng ở chỗ xử lý input dị dạng (điểm không trên đường cong, scalar ≥ p, độ dài proof sai). Một verifier từ chối, một verifier chấp nhận ⇒ **chain split**.

```solidity
// test/differential/ZetherProofDiff.t.sol  (profile differential, ffi = true)
function testFuzz_rust_prover_accepted_by_solidity(uint64 v, uint64 b, uint256 seed) public {
    vm.assume(b >= v && v > 0 && b < (1 << 63));          // n_b = 64, khong phai 128
    string[] memory a = new string[](6);
    a[0] = "../crates/zether-core/target/release/zether-cli"; a[1] = "prove";
    a[2] = vm.toString(v); a[3] = vm.toString(b); a[4] = vm.toString(seed); a[5] = "--abi";
    bytes memory out = vm.ffi(a);
    (bytes memory proof, bytes memory statement) = abi.decode(out, (bytes, bytes));
    assertTrue(verifier.verifyTransfer(statement, proof), "rust proof rejected by solidity");
}

function testFuzz_single_bit_flip_must_fail(uint256 byteIdx, uint8 bitIdx) public {
    bytes memory proof = _katProof();
    byteIdx = bound(byteIdx, 0, proof.length - 1);
    proof[byteIdx] ^= bytes1(uint8(1) << (bitIdx % 8));
    assertFalse(verifier.verifyTransfer(_katStatement(), proof), "mutated proof accepted");
}

/// KHONG duoc quen: bit-flip tren STATEMENT, khong chi tren proof
function testFuzz_statement_bit_flip_must_fail(uint256 byteIdx, uint8 bitIdx) public {
    bytes memory st = _katStatement();
    byteIdx = bound(byteIdx, 0, st.length - 1);
    st[byteIdx] ^= bytes1(uint8(1) << (bitIdx % 8));
    assertFalse(verifier.verifyTransfer(st, _katProof()), "proof reused for different statement");
}
```

Test thứ ba là **frozen-heart** viết dưới dạng fuzz và bản nháp chỉ có nó ở dạng liệt kê. Nó đắt hơn nhưng nó là test duy nhất bắt được lỗi Fiat-Shamir dạng "quên absorb một public input vào transcript" — lỗi đã hạ gục nhiều triển khai Bulletproofs thật.

**Sáu lớp test mật mã, không thay thế nhau được** (bản nháp có bốn):

1. **Round-trip property** (Rust, `proptest`): `verify(prove(w)) == true` với 100k witness ngẫu nhiên; `decrypt(encrypt(v)) == v` với `v ≤ DECRYPT_BOUND`. §03.2 chốt `DECRYPT_BOUND = 2^40` cho mỗi khoản chuyển riêng lẻ, là tham số **client**, tách khỏi `RANGE_BITS_VALUE = 32` và `RANGE_BITS_BALANCE = 64`. KAT phải chứng minh BSGS giải được trong ngân sách đã công bố, đo bằng `criterion`, gate: **p99 < 300 ms trên ARM64**.
2. **Differential ma trận 4 chiều** (ở trên).
3. **KAT** (`testvectors/*.json`): vector cố định, sinh một lần bằng `crates/kat-gen`, **commit vào repo**, không bao giờ sinh lại trong CI. Mỗi vector ghi: `curve_id`, `n_v`, `n_b`, `proof_system_id`, seed, witness, statement, proof hex, kết quả mong đợi. `.neg.json` chứa proof phải **fail**: điểm không nằm trên đường cong, scalar ≥ `p`, điểm ở vô cực, độ dài proof sai (ngắn và dài), proof của statement khác, proof hợp lệ nhưng `zetherNonce` cũ, proof hợp lệ nhưng `recipient` bị sửa (anti-MEV, `blockchain.md` §10.5.3), proof của **curve khác** (BN254 proof nộp cho verifier Baby Jubjub).
4. **Transcript/Fiat-Shamir** (`Transcript.frozenheart.t.sol`, §03.9): với **từng** public input, đảo một bit rồi dùng lại proof cũ ⇒ **phải** revert. Viết bằng vòng lặp trên danh sách field, không viết tay từng case — thêm field mới vào statement mà quên absorb vào transcript sẽ làm test fail vì độ dài danh sách không khớp.
5. **Fuzz deserialization (MỚI — bản nháp thiếu, và đây là lỗ DoS thật).** Verifier Rust chạy **trong relayer**, tức là nó parse byte đến từ Internet, từ những người không quen biết. Một `panic!` (index out of bounds, `unwrap()` trên `Option`, subtract overflow ở debug) là DoS toàn mạng relayer bằng một gói tin 200 byte. Ba target `cargo-fuzz` bắt buộc:
   ```
   crates/zether-core/fuzz/fuzz_targets/deserialize_proof.rs   # bytes -> Proof, KHONG duoc panic
   crates/zether-core/fuzz/fuzz_targets/verify_arbitrary.rs    # verify(random statement, random proof) -> bool | Err
   crates/zether-core/fuzz/fuzz_targets/transcript_absorb.rs   # absorb(arbitrary) khong panic, khong OOM
   ```
   Gate: `cargo fuzz run <target> -- -max_total_time=600` mỗi nightly, corpus commit vào `fuzz/corpus/`. Bất kỳ crash nào ⇒ P1. Ngoài ra `#![deny(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]` trên module parse.
6. **Side-channel và zeroize (MỚI).** Prover chạy trên điện thoại người dùng và trong enclave (§07). Yêu cầu tối thiểu, kiểm được bằng lint chứ không cần thiết bị đo: mọi phép scalar arithmetic dùng `subtle::ConstantTimeEq`/`ConditionallySelectable`, mọi struct chứa `x` (private key) hoặc `r` (randomness) implement `Zeroize + ZeroizeOnDrop`, và một test `assert!(!std::mem::needs_drop::<...>() || zeroized)`. Không có test này thì randomness `r` nằm lại trong heap sau khi prove xong, và §07 threat model về memory dump là giả.

---

### 14.5b. Kích thước và chi phí — **sửa lại theo cấu hình đã chốt ở §03**

Bản nháp tính cho **128-bit range proof aggregate m=2**. Cấu hình đó đã bị §03.2.1 loại bỏ: `MAX = 2^128 − 1` như `blockchain.md` viết **làm hỏng giao thức** (không ai giải mã được số dư của chính mình — BSGS trên 2^128 là bất khả thi). Cấu hình đã chốt là **`n_v = 32` / `n_b = 64`, hai proof chung transcript, MSM 230 điểm**. Toàn bộ bảng phải tính lại:

| Đại lượng | Bản nháp (128/128) | **Đúng (32/64)** | Cơ sở |
|---|---|---|---|
| Điểm MSM | 536 | **230** | §03.3.6 |
| Điểm L/R trong proof | 16 | **22** | 2·⌈log₂32⌉ + 2·⌈log₂64⌉ = 10 + 12 |
| Điểm cam kết | 4 | **8** | A, S, T₁, T₂ cho **mỗi** proof |
| Scalar | 5 | **10** | τ_x, μ, t̂, a, b × 2 proof (trừ phần chia sẻ transcript) |
| **Proof size, nén 32 B/điểm** | ~1,440 B | **~1,280 B** | 30 × 32 + 10 × 32 |
| **Proof size, không nén 64 B/điểm** | — | **~2,240 B** | 30 × 64 + 10 × 32 |
| Gas verify Bulletproofs | 1.5–2.5 M | **1.507 M** | §03.3.6, 230 × (6,000 + 150 + 400) |
| Gas Sigma protocol | (bỏ sót) | **171 k** | §03.3.6 |
| **Gas một `transferConfidential` trọn vẹn** | (không có) | **~1.88 M** | §03.3.6, gồm calldata 55k + storage 70k + fee 30k + base 45k |
| Chi phí trên Gnosis @2 gwei | ~$0.004 | **$0.002–0.006** | 1.88M × 1–3 gwei xDAI |
| **Ràng buộc thật trên Gnosis** | (không có) | **31,300 tx/ngày ở 20% block space** | §03.3.8; block limit 17M, 5 s |
| Chi phí trên Besu private | 0 | **0 tiền, nhưng 26 tx/block** | gasLimit 50M (§08.10) ÷ 1.88M |

**Ba con số bản nháp thiếu hoàn toàn, và cả ba đều đổi quyết định:**

**(i) EIP-7623 — sàn giá calldata.** Từ Prague/Pectra (2025, đã kích hoạt trên Gnosis), một transaction trả `max(chi phí thực thi thường, 21,000 + 10 × tokens)` với `tokens = zero_bytes + 4 × nonzero_bytes`. Với proof 2,240 byte gần như toàn non-zero:

```
tokens ≈ 2,240 × 4 = 8,960
san  = 21,000 + 10 × 8,960 = 110,600 gas
```

Trên public chain, sàn 110.6k **không ràng buộc** vì thực thi đã 1.88M. Nhưng trên private chain **có native precompile** (§03.3.9 đề xuất giá cố định 60,000 gas), tổng thực thi rơi xuống ~200k và **sàn calldata trở thành chi phí chi phối**. Hệ quả cụ thể: throughput private chain bị chặn bởi băng thông block chứ không bởi CPU, và việc nén điểm (32 B thay vì 64 B) đột nhiên đáng giá — nó cắt sàn từ 110.6k xuống ~65k, tức **41%** chi phí tx. Nén điểm tốn ~2,000 gas/điểm để giải nén trên EVM (tính căn bậc hai modular) nhưng **0 gas trong native precompile**. ⇒ **Trên private profile, dùng điểm nén; trên public profile, dùng không nén.** Đó là một quyết định về format proof phải chốt trước khi sinh KAT, vì KAT ghi format.

**(ii) Celo là L2 OP Stack (từ 03/2025) ⇒ chi phí bị chi phối bởi L1 data fee, không bởi L2 gas.** §02.5.4 và §06 đều xác nhận. Với 2,240 byte calldata post-Ecotone (blob):

| Blob base fee | Chi phí L1 data cho 1 tx Zether | Ghi chú |
|---|---|---|
| 1 wei (bình thường) | ~$0.000001 | không đáng kể |
| 1 gwei | ~$0.004 | ngang chi phí Gnosis |
| 100 gwei (nghẽn blob) | **~$0.40** | **×100 so với bình thường** |

Điều này đâm thẳng vào luận điểm chọn Celo: *"phí gas bằng stablecoin ⇒ chi phí dự báo được 100%"*. Phí **được trả** bằng cUSD, nhưng **độ lớn** của nó theo dõi thị trường blob của Ethereum L1, thứ biến động 100×. Predictability nằm ở đơn vị tiền tệ, không nằm ở số tiền. Hệ quả cho §14.7: `.gas-snapshot.l2` đo L2 execution gas là **không đủ** — phải có một job riêng ước tính L1 data fee từ `len(calldata)` và alert khi nó vượt ngân sách.

**(iii) Con số verify của `blockchain.md`.** §10.5.2 ghi "~180,000–250,000 gas". §03.3.7 đã chẩn đoán chính xác: đó là chi phí `ecPairing` với k=4 (`45,000 + 4 × 34,000 = 181,000`), tức là chi phí verify một **Groth16 SNARK**, không phải Bulletproofs — Bulletproofs không dùng pairing chút nào. Sai số **19×** ở cấu hình 128/128, **9×** ở cấu hình 32/64 đã chốt. Xem §14.13(3).

---

### 14.6. Fork testing Gnosis và Celo

```solidity
uint256 gnosis = vm.createSelectFork(vm.rpcUrl("gnosis"), 38_500_000);  // block GHIM
```

Ghim block. Fork ở head làm test không tái lập được và CI sẽ đỏ ngẫu nhiên vào những ngày mạng bận. Cập nhật block ghim là một PR có chủ đích, mỗi quý hoặc sau mỗi hard fork của chain — cái nào đến trước.

**Bản nháp bỏ qua hai thứ làm fork test không chạy được trong CI thật:**

**(1) Cache RPC.** Foundry cache state fork vào `~/.foundry/cache/rpc/<chain>/<block>/`. Không cache ⇒ mỗi lần chạy phát **2,000–10,000** `eth_getStorageAt`/`eth_getCode`. Với Alchemy free tier (300M CU/tháng, `eth_getStorageAt` ≈ 26 CU), một suite fork chạy 30 lần/ngày đốt ~2.3M CU/ngày — hết quota trong 4 tháng chỉ riêng CI, và trong khi đó là 429 ngẫu nhiên. Fix, ba dòng:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.foundry/cache/rpc
    key: rpc-${{ hashFiles('evm/test/fork/**') }}-gnosis38500000-celo<N>
```

Key gồm block number ⇒ đổi block ghim là đổi cache, đúng như mong muốn. Cache đầy đủ ~50–300 MB, dưới hạn 10 GB của GitHub.

**(2) Celo không còn là chain nó từng là.** `blockchain.md` §10.4 mô tả Celo là "Istanbul BFT (IBFT 2.0), 5 giây/block, 1 block confirmation, immediate finality". Từ tháng 03/2025, Celo là **L2 trên OP Stack**: block 1 giây, sequencer, `safe` derive được từ batch trên L1 sau vài phút, `finalized` khi block L1 đó finalized (**~15–20 phút**). "Immediate finality" **không còn tồn tại**. Điều này đổi:
- Bảng Finality Gate của `blockchain.md` §10.4 (xem §14.13(10));
- Test `CeloFork.t.sol` phải dùng tag `safe`/`finalized`, không dùng depth counting;
- Test phía Odoo §14.11 phải phủ trường hợp `safe` bị lật (unsafe head reorg của OP Stack là chuyện thật khi sequencer restart).

Cái mà fork test bắt được và local test không bắt được:

| Test | Chain | Bắt được gì |
|---|---|---|
| `GnosisFork.t.sol::test_wrap_real_usdc` | Gnosis | Token thật lệch chuẩn: USDT-style `approve` không trả `bool`, fee-on-transfer, blacklist, `permit` khác chuẩn. Một `MockERC20` không có cái nào trong số đó |
| `GnosisFork.t.sol::test_deploy_size_on_chain` | Gnosis | Deploy thật với EIP-170 thật, không phải `--sizes` cục bộ; và EIP-3860 initcode ≤ 49,152 byte |
| `GnosisFork.t.sol::test_create2_factory_exists` | cả hai | `0x4e59b44847b379578588920cA78FbF26c0B4956C` (deterministic-deployment-proxy) có tồn tại trên chain này không. Nếu không, `Deploy.s.sol` phải bootstrap nó trước — xem §14.12 |
| `CeloFork.t.sol::test_feecurrency_cusd` | Celo | CIP-64: tx trả gas bằng cUSD. Foundry **không** ký được tx có field `feeCurrency` ⇒ xem mâu thuẫn (4) §14.13 |
| `CeloFork.t.sol::test_l1_fee_oracle` | Celo | Đọc `GasPriceOracle` (`0x420...0F`) để lấy L1 fee thực tế cho calldata của ta — đầu vào cho ngân sách ở §14.5b(ii) |
| `*Fork.t.sol::test_precompile_ecmul_gas` | cả hai | Chain có thể tính giá precompile khác nhau; đây là input trực tiếp vào ngân sách gas Zether |
| `*Fork.t.sol::test_transient_storage_available` | cả hai + Besu | `TSTORE` có chạy không (giả định A5 §01) |
| `*Fork.t.sol::test_eip2537_bls_available` | cả hai | Có `BLS12_G1ADD` ở `0x0b` không — §02.5.4 đảo kết luận BLS/ECDSA dựa trên điều này. **Probe runtime, không hardcode** |
| `*Fork.t.sol::test_stale_simulation_reverts_cleanly` | cả hai | Simulate ở block N, execute ở N+3 sau khi có `rollOver` xen vào ⇒ phải revert với custom error rõ ràng, không phải panic |
| `HederaFork.t.sol::test_hts_precompile_0x167` | Hedera testnet | HSCS có thật sự hành xử như EVM ở chỗ ta cần không |

Test `test_stale_simulation_reverts_cleanly` là hiện thân on-chain của nguyên tắc *"quét QR không phải là đã thu tiền"*: mô phỏng thành công **không** phải là giao dịch thành công, và hệ thống phải xử lý được khoảng cách giữa hai thời điểm đó bằng một error **có tên**, để §11 phân loại được `fail_reason` thay vì ghi "unknown revert".

**Bí mật RPC và PR từ fork.** `RPC_GNOSIS`/`RPC_CELO` là GitHub secret; PR từ fork repo **không** có secret. Ba quy tắc, không thương lượng:
- Job fork test `continue-on-error: true` trên PR ngoài, **required** trên `main` và nightly.
- **Không bao giờ** dùng `pull_request_target` để "cho fork thấy secret" — đó là cách rò secret kinh điển vì nó checkout code của người lạ với quyền của repo gốc.
- Mọi GitHub Action ghim theo **commit SHA**, không theo tag (`uses: actions/checkout@8f4b7f8...`), vì tag của action bên thứ ba move được.

**`evm/ts-conformance/` — ngoại lệ Node, và nó nhỏ.** Hai thứ `forge` không làm được:
```
evm/ts-conformance/
├── package.json            # viem ^2.x, @celo/abis, vitest — 3 dependency, khong hon
├── celo-cip64.test.ts      # ~120 dong: gui tx type 0x7b voi feeCurrency = cUSD tren Alfajores
└── eip712-crosscheck.test.ts # ~80 dong: viem.hashTypedData vs testvectors/eip1776_digest_v1.json
```
`eip712-crosscheck.test.ts` là oracle độc lập cho digest EIP-712 — quan trọng hơn `celo-cip64` vì mọi chữ ký người dùng phụ thuộc vào nó, và một bug ở đây làm **toàn bộ meta-tx không verify được** ở phía nào đó. Ba runner đọc cùng một file KAT: `forge` (`Eip712Kat.t.sol`), `pytest` (§14.11 tầng 1), `vitest` (ở đây). Ba implementation độc lập, một sự thật.

---

### 14.7. Gas snapshot regression, kích thước, và ngân sách theo hàm

```
forge snapshot --snap snapshots/.gas-snapshot                          # ghi
forge snapshot --check --tolerance 1 --snap snapshots/.gas-snapshot    # gate CI
```

`--tolerance 1` (1%) để tránh nhiễu do đổi thứ tự test. Snapshot **commit vào repo**; diff nằm ngay trong PR review. Một PR làm `transferConfidential` tăng 200k gas mà không ai nhắc đến trong mô tả là một PR bị chặn.

**Cảnh báo bản nháp không nêu: `forge snapshot` là bề mặt CLI hay đổi nhất của Foundry.** `--tolerance` đã đổi ngữ nghĩa và vị trí giữa các phiên bản, và Foundry ≥ v1 khuyến khích cheatcode `vm.startSnapshotGas("name")` / `vm.stopSnapshotGas()` ghi ra `snapshots/*.json`. Chiến lược không gãy khi Foundry đổi:

- **Bulk regression**: `forge snapshot` cho toàn bộ test, gate bằng một script `bash` tự so hai file với ngưỡng, **không** phụ thuộc cờ `--tolerance` tồn tại:
  ```bash
  forge snapshot --snap /tmp/new.txt
  python3 tools/gas_diff.py snapshots/.gas-snapshot /tmp/new.txt --max-pct 1 --max-abs 5000
  ```
  30 dòng Python, sở hữu bởi ta, không bao giờ bị deprecate. Nó cũng cho ta thứ `--tolerance` không cho: **ngưỡng tuyệt đối** — 1% của 1.88M là 18,800 gas, quá rộng để bắt regression thật; `--max-abs 5000` mới là gate có ích cho hàm đắt.
- **Ngân sách theo hàm**, khai báo trong test chứ không trong tài liệu:
  ```solidity
  function test_gas_budget_executeMetaTransaction() public {
      uint256 g = gasleft();
      forwarder.executeMetaTransaction(metaTx, sig);
      assertLt(g - gasleft(), 220_000, "executeMetaTransaction over budget");
  }
  ```

Danh sách ngân sách tối thiểu, và **mỗi con số là input của một chỗ khác** — hai chỗ phải khớp, và test là nơi giữ sự thật:

| Hàm | Ngân sách | Con số này là input của |
|---|---|---|
| `executeMetaTransaction` (target rẻ) | < 220,000 | `max_gas_per_tx` §06; công thức lợi nhuận relayer §05 |
| `MetaTxBatcher.executeBatch(50)` | < 4,500,000 | §06.6: batch là đòn bẩy 50× cho nút thắt custody |
| `register()` (Schnorr) | < 200,000 | Chi phí onboarding một đối tác B2B |
| `deposit()` | < 120,000 | UX nạp tiền |
| `transferConfidential` | < 2,000,000 | §03.3.6 (1.88M) + biên 6%; **và** trần 26 tx/block trên Besu 50M |
| `withdraw()` | < 1,400,000 | §03: withdraw rẻ hơn transfer ~32% (1.27M) |
| `rollOver()` | < 60,000 | Cron gọi hàng loạt; đây là chi phí vận hành định kỳ |
| Attestation quorum 5-of-9 ECDSA | < 30,000 | §02.8: 609 attestation/năm/chain |

**Ba snapshot riêng** vì gas model khác nhau: `.gas-snapshot` (default), `.gas-snapshot.l2` (profile `l2`), `.gas-snapshot.private` (Besu). Với `.gas-snapshot.l2`, ghi thêm một cột **L1 data fee ước tính** tính từ `len(calldata)` (§14.5b(ii)) — chỉ đo L2 execution gas trên một OP Stack chain là đo sai thứ đắt tiền.

**Hai gate cứng về kích thước, và cả hai đều cần parse JSON — `forge build --sizes` không nhận ngưỡng:**

```bash
forge build --sizes --json | python3 - <<'PY'
import json,sys
LIM_RUNTIME, LIM_INITCODE = 24_000, 49_152          # EIP-170 lề 576B; EIP-3860
bad = []
for name, v in json.load(sys.stdin).items():
    if v["runtime_size"]  > LIM_RUNTIME:  bad.append((name,"runtime", v["runtime_size"]))
    if v["init_size"]     > LIM_INITCODE: bad.append((name,"initcode",v["init_size"]))
if bad: print(bad); sys.exit(1)
PY
```

`BulletproofsVerifier` là contract sẽ chạm trần đầu tiên. **Ba đường thoát, đã biết, theo thứ tự ưu tiên:**

| Đường thoát | Chi phí | Khi nào dùng |
|---|---|---|
| Tách multi-exp sang library `delegatecall` | ~2,600 gas/lần gọi, +1 contract phải deploy và verify | Đầu tiên; rẻ nhất |
| Bật `via_ir` (bytecode nhỏ hơn 5–15%) | Build ×6–13, mất `forge coverage` (§14.2b) | Chỉ nếu (1) không đủ |
| Chuyển sang `NativePrecompileVerifier` | Consensus change, chỉ private chain | Không phải giải pháp cho public |

**Không** dùng `contractSizeLimit: 65536` của Besu làm đường thoát. §01.122 đã chốt: nếu private build và public build khác source thì ta có hai codebase và mọi test parity (I17) trở nên vô nghĩa. Quy tắc: **mọi contract fit 24,000 byte trên mọi profile**, và CI enforce nó ở profile default.

---

### 14.8. Mutation testing

Test suite xanh không chứng minh test suite có ích. Mutation testing đo điều đó: sửa một toán tử trong source, nếu không test nào đỏ thì test suite có lỗ.

| Công cụ | Dùng ở đâu | Cấu hình |
|---|---|---|
| `gambit` (Certora) | `src/metatx/`, `src/zether/verifier/`, `src/registry/verifiers/`, `src/peg/` | Bốn thư mục — nơi một dấu `>=` thành `>` là mất tiền |
| `necessist` (Trail of Bits) | `test/unit/` | Xoá từng statement trong test; test vẫn pass ⇒ statement đó là trang trí |
| `cargo-mutants` | `crates/zether-core/src/verify.rs` | Verifier Rust là oracle của mọi thứ khác; nếu test của **nó** yếu thì cả ma trận differential yếu |

Bản nháp bỏ sót `cargo-mutants`, và đó là chỗ đau nhất: verifier Rust là nguồn chân lý. Một mutant sống sót trong `verify()` nghĩa là bộ test Rust không phân biệt được verifier đúng với verifier sai, và toàn bộ test differential ở §14.5 đang so Solidity với một oracle chưa được kiểm chứng.

Chi phí thật, tính lại có cơ sở:

| Hạng mục | Số mutant | Thời gian/mutant | Tổng |
|---|---|---|---|
| `gambit` trên 4 thư mục (~2,500 dòng Solidity) | ~400 | ~40 s (chỉ chạy subset test liên quan) | **4.4 giờ** |
| `cargo-mutants` trên `verify.rs` (~600 dòng) | ~120 | ~25 s | **0.8 giờ** |
| `necessist` trên `test/unit/` (~3,000 dòng test) | ~800 statement | ~15 s | **3.3 giờ** |
| **Tổng** | | | **~8.5 giờ** |

⇒ **nightly, không phải PR**, và chia làm ba job song song để lọt cửa sổ 8 tiếng (mỗi job < 4.5 h). Chi phí tiền mặt trên GitHub-hosted 2 vCPU Linux ($0.008/phút): 510 phút × $0.008 = **$4.08/đêm ≈ $122/tháng**. Đó là con số cần biết để không ai phải tranh luận về nó: nó rẻ hơn một ngày công engineer, và nó là gate duy nhất đo chất lượng test.

Gate: mutation score ≥ 80% trên bốn thư mục Solidity, ≥ 85% trên `verify.rs`. Mutant sống sót phải được kill hoặc gắn nhãn `equivalent` kèm lý do trong `mutation-allowlist.txt`. Allowlist tăng lên là tín hiệu xấu; review hàng tháng, và một dòng allowlist không có lý do bằng văn xuôi là một PR bị chặn.

Nightly đỏ **mở issue tự động, không chặn merge**. Một nightly chặn merge sẽ bị vô hiệu hoá trong hai tuần — đó là quy luật, không phải dự đoán.

---

### 14.9. Static analysis và formal methods — chỗ nào đáng bỏ tiền

| Công cụ | Chạy khi nào | Phạm vi | Gate |
|---|---|---|---|
| `forge fmt --check` | mọi PR | tất cả | fail |
| `solhint` | mọi PR | `src/` | fail trên `error`; ruleset: `no-tx-origin`, `custom-errors`, `func-visibility`, `reentrancy` |
| `slither` | mọi PR | `src/` | fail trên High/Medium; Low/Informational vào `slither.db.json` triage |
| `slither-check-upgradeability` | mọi PR | mọi contract UUPS/beacon | fail |
| `aderyn` | mọi PR | `src/` | báo cáo, chưa gate (còn nhiều false positive, gate sau 3 tháng dữ liệu) |
| **`semgrep` rule nội bộ** | mọi PR | `src/` | fail — xem dưới |
| OZ `validateUpgrade` (qua `openzeppelin-foundry-upgrades`) | mọi PR | so với `storage-layouts/v<N-1>/` | fail |
| `halmos` | mọi PR (subset) | `MetaTxLib`, số học `Bn254`/`BabyJubjub`, `PegController` | fail |
| Certora Prover | trước mỗi lần deploy có giá trị thật | `MetaTxForwarder`, `WrappedToken` | fail |
| Kontrol | không dùng wave 1 | — | Chi phí học >> lợi ích khi đã có halmos + Certora |

**`semgrep` rule nội bộ — bản nháp không có, và đây là chỗ rẻ nhất trong bảng.** Bốn rule, mỗi cái ~10 dòng YAML, mỗi cái chặn một lỗi đã biết sẽ xảy ra trong repo này:

```yaml
# tools/semgrep/dms-contracts.yml
- id: no-selfdestruct              # EIP-6780 chi vo hieu hoa tren chain DA co Cancun (§01, gia dinh A5)
  pattern: selfdestruct($X)
- id: fee-transfer-before-call     # I7/I20: phi phai chuyen TRUOC inner call
  patterns: [{pattern-inside: "function executeMetaTransaction(...) { ... }"},
             {pattern-either: [{pattern: "$T.call($D); ... _payFee(...)"}]}]
- id: no-raw-transfer              # token lech chuan tren Gnosis khong tra bool
  pattern: $TOKEN.transfer($A, $B)
  # phai dung SafeERC20.safeTransfer
- id: no-initializer-without-disable  # constructor implementation phai _disableInitializers()
  patterns: [{pattern-inside: "contract $C is UUPSUpgradeable { ... }"},
             {pattern-not-inside: "constructor() { ... _disableInitializers(); ... }"}]
```

Rule cuối chặn đúng lỗi §01.130 mô tả: quên `_disableInitializers()` ⇒ kẻ tấn công `initialize()` chính implementation, gọi `upgradeToAndCall` và brick toàn bộ N proxy. Slither có detector cho một phần chuyện này; semgrep cho ta rule **đúng với repo này** trong 10 dòng.

**Formal chỉ trả lãi ở số học và ở máy trạng thái nhỏ.** Ba property đáng viết bằng halmos vì fuzzing không bao giờ chạm tới:

```solidity
// test/symbolic/MetaTxLib.halmos.t.sol
function check_mode_open_ignores_relayer(MetaTransaction memory m, address r1, address r2) public pure {
    vm.assume(m.mode == 0);
    m.relayer = r1; bytes32 h1 = MetaTxLib.hash(m);
    m.relayer = r2; assert(MetaTxLib.hash(m) == h1);      // I10, chứng minh chứ không lấy mẫu
}
function check_mode_restrict_changes_digest(MetaTransaction memory m, address r1, address r2) public pure {
    vm.assume(m.mode & 0x01 != 0 && r1 != r2);
    m.relayer = r1; bytes32 h1 = MetaTxLib.hash(m);
    m.relayer = r2; assert(MetaTxLib.hash(m) != h1);      // mat nay quan trong khong kem
}
function check_no_overflow_in_fee_path(uint256 amount, uint256 fee) public pure {
    vm.assume(amount <= type(uint128).max && fee <= type(uint128).max);
    assert(amount + fee >= amount);
}
```

Certora chỉ dùng cho hai contract và chỉ trước deploy có tiền thật: license và thời gian viết CVL là chi phí thật, và §12.8 đã phân bổ $120k–240k cho audit người — đừng tiêu ngân sách đó vào việc formal-verify một `Ownable`.

---

### 14.9b. Cái mà halmos **không** chứng minh được — và tại sao test tâm đắc nhất của bản nháp gần như vô nghĩa

Bản nháp gọi `check_digest_injective` là *"thứ đáng giá nhất"*:

```solidity
function check_digest_injective(MetaTransaction memory a, MetaTransaction memory b) public pure {
    vm.assume(keccak256(abi.encode(a)) != keccak256(abi.encode(b)));
    assert(MetaTxLib.hash(a) != MetaTxLib.hash(b));
}
```

Test này **gần như vacuous**, và lý do là kỹ thuật: mọi symbolic executor cho EVM (halmos, hevm, Kontrol) đều mô hình hoá `keccak256` như một **uninterpreted function có giả định injective** — solver không giải được SHA-3 thật. Nghĩa là:
- giả thiết `keccak256(abi.encode(a)) != keccak256(abi.encode(b))` được solver dịch thành `abi.encode(a) != abi.encode(b)`;
- kết luận `hash(a) != hash(b)` được dịch thành "preimage của hai lời gọi keccak khác nhau";
- và solver kết luận đúng **bằng chính giả định injectivity nó tự đặt**, không bằng bất cứ tính chất nào của `MetaTxLib.hash`.

Test sẽ pass kể cả khi `MetaTxLib.hash` có lỗi encoding thật. Lớp lỗi mà nó **định** bắt — hai struct khác nhau cho cùng digest vì một field `bytes` động được nối thẳng vào thay vì `keccak256(data)` trước, đúng như EIP-712 quy định — nằm ở tầng **byte layout**, không ở tầng hash.

**Ba test thay thế, mỗi cái bắt đúng lớp lỗi đó:**

```solidity
// 1. Structural: EIP-712 struct hash PHAI dai dung (1 + nField) * 32 byte.
//    Mot field dong bi noi tho se lam do dai thay doi theo do dai data.
function test_struct_encoding_length_is_fixed() public {
    MetaTransaction memory m = _base(); m.data = hex"";
    uint256 l0 = MetaTxLib.encodeForHash(m).length;
    m.data = new bytes(1000);
    assertEq(MetaTxLib.encodeForHash(m).length, l0, "dynamic field khong duoc keccak truoc khi encode");
    assertEq(l0, 13 * 32, "typehash + 12 field");
}

// 2. Sensitivity: doi TUNG field mot => digest PHAI doi. Vong lap tren danh sach,
//    khong viet tay, de them field moi ma quen absorb se lam test do vi do dai lech.
function test_every_field_affects_digest() public {
    bytes32 base = MetaTxLib.hash(_base());
    for (uint256 i; i < 12; ++i) {
        assertTrue(MetaTxLib.hash(_mutateField(_base(), i)) != base, string.concat("field ", vm.toString(i)));
    }
}

// 3. KAT lien nganh: digest phai khop viem VA eth_account, khong chi khop chinh no.
function test_digest_matches_kat() public view {
    string memory j = vm.readFile("../testvectors/eip1776_digest_v1.json");
    assertEq(MetaTxLib.hash(_fromJson(j)), vm.parseJsonBytes32(j, ".expected_struct_hash"));
    assertEq(MetaTxLib.domainSeparator(), vm.parseJsonBytes32(j, ".expected_domain_separator"));
}
```

Test (3) là cái duy nhất trong ba cái có **oracle độc lập** — và đó là điều làm nó đáng tin. `viem` và `eth_account` được hàng nghìn dự án dùng; `MetaTxLib` thì chưa. §14.5b đã chốt: một file KAT, ba runner (`forge`, `pytest`, `vitest`).

Kết luận cho §14.9: halmos vẫn đáng chạy — cho `check_mode_open_ignores_relayer` (thuần bitwise + so sánh, solver giải được thật), cho số học `Bn254`/`BabyJubjub` (`addmod`/`mulmod`, đúng thế mạnh của SMT solver), và cho `PegController` (bất đẳng thức số nguyên). **Đừng dùng nó cho bất kỳ property nào có `keccak256` ở tâm.**

---

### 14.10. Devnet cục bộ cho CI

```yaml
# devnet/docker-compose.ci.yml
services:
  anvil:
    image: ghcr.io/foundry-rs/foundry:nightly-<sha>
    entrypoint: ["anvil","--host","0.0.0.0","--chain-id","31337","--block-time","1",
                 "--accounts","10","--balance","10000",
                 "--mnemonic","test test test test test test test test test test test junk",
                 "--hardfork","cancun"]
    # KHONG dat --code-size-limit: gioi han EIP-170 phai giong public chain, xem duoi
    ports: ["8545:8545"]
    healthcheck:
      test: ["CMD","cast","block-number","--rpc-url","http://localhost:8545"]
      interval: 2s
      retries: 30
  besu:
    image: hyperledger/besu:24.12.0
    command: ["--genesis-file=/cfg/genesis.qbft.json","--config-file=/cfg/config.toml",
              "--rpc-http-enabled","--rpc-http-host=0.0.0.0","--min-gas-price=0",
              "--permissions-accounts-config-file-enabled",
              "--permissions-config-file=/cfg/permissions_config.toml"]
    volumes: ["./besu:/cfg:ro"]
    ports: ["8546:8545"]
    healthcheck:
      test: ["CMD","sh","-c","wget -qO- --post-data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"id\":1}' --header 'Content-Type: application/json' http://localhost:8545"]
      interval: 3s
      retries: 40
```

Mnemonic `test test ... junk` là mnemonic mặc định của anvil ⇒ account 0 luôn là `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`. **Địa chỉ và khoá hardcode trong test là chuyện bình thường và đúng ở đây** — chúng là hằng số công khai của một devnet dùng một lần, không phải secret. Điều phải cấm là ngược lại: một khoá thật lọt vào `devnet/`. CI có job `gitleaks` chặn việc đó, và `.gitleaks.toml` phải **allowlist** đúng mnemonic anvil, nếu không gitleaks sẽ đỏ mỗi ngày và bị tắt trong một tuần.

**`--block-time 1` chứ không phải instant-mine:** Zether có epoch tính theo block (`blockchain.md` §10.5.2, Δ = 5 block) và finality gate của §11 đếm depth. Instant-mine làm cả hai cơ chế không bao giờ được test.

**Bốn cái bẫy của devnet mà bản nháp không nêu:**

**(1) `--code-size-limit` là con dao hai lưỡi.** anvil cho phép nâng giới hạn EIP-170. Nếu đặt nó, `BulletproofsVerifier` quá khổ sẽ deploy được trong CI và fail trên Gnosis. **Không đặt.** Ngược lại, Besu genesis *có* `contractSizeLimit: 65536` (§08.10) ⇒ một contract quá khổ pass trên Besu job và fail trên anvil job. Đó là tính năng, không phải bug: nó cho ta đúng tín hiệu ở đúng chỗ. Gate ở §14.7 vẫn là 24,000 cho **cả hai**.

**(2) Precompile vắng mặt trả về success rỗng, không revert.** Nếu `NativePrecompileVerifier` gọi `staticcall(0x...0100)` trên một node **không** có precompile đó, EVM coi đó là gọi vào một địa chỉ không có code: **`success = true`, `returndata` rỗng**. Một verifier viết cẩu thả sẽ đọc `returndata` rỗng thành `false` (may) hoặc thành `true` (chết người, nếu nó chỉ kiểm `success`). Kiểm bắt buộc, chạy lúc khởi động contract **và** trong test:

```solidity
function _requirePrecompile(address p) internal view {
    (bool ok, bytes memory ret) = p.staticcall(abi.encode(KAT_STATEMENT, KAT_PROOF));
    require(ok && ret.length == 32 && abi.decode(ret, (bool)), "precompile vang mat hoac sai phien ban");
}
```

Gọi nó trong `initialize()` và trong `ProbePrecompiles.s.sol` trước mỗi deploy. Cùng lý lẽ áp cho `ecMul` (`0x07`) và `BLS12_G1ADD` (`0x0b`) — §02.5.4 đảo kết luận BLS/ECDSA dựa trên sự tồn tại của `0x0b`, nên **probe runtime, đừng hardcode theo tên chain**.

**(3) Besu QBFT một node vẫn cần cấu hình đúng, và bản nháp chưa liệt kê cái nào là bắt buộc:**

| Tham số genesis/CLI | Giá trị | Vì sao test sai nếu thiếu |
|---|---|---|
| `zeroBaseFee: true` + `--min-gas-price=0` | bật | §08 chốt "gas price = 0 không phải gas = 0". Thiếu cái thứ hai, node từ chối tx `gasPrice=0` và mọi test private đỏ |
| `contractSizeLimit: 65536` | đặt | Verifier lọt trên private |
| **`cancunTime: 0`** | **đặt** | §08.10 hiện khai `shanghaiTime` ⇒ mâu thuẫn với `foundry.toml`. Gate `check-genesis-fork.sh` §14.2 |
| `blockperiodseconds: 2`, `requesttimeoutseconds: 4` | ≥ 2× blockperiod | Dưới ngưỡng ⇒ round change liên tục, CI đỏ ngẫu nhiên |
| `permissions_config.toml` account allowlist | bật | "Ai được gửi tx" là kiểm soát an ninh **chính** của private chain. Một test private profile trên anvil sẽ pass trong khi thực tế bị `AccountRules` từ chối |
| `gasLimit` | 50,000,000 | §08.10. Lưu ý §01.789 ghi 200M — **hai section lệch nhau**, xem §14.13(11) |

**(4) Native precompile không test được trên cả anvil lẫn Besu stock.** Cả hai đều không có `0x...0100`. Ba lựa chọn, phải chọn:

| Lựa chọn | Chi phí | Đánh giá |
|---|---|---|
| `vm.etch` một mock Solidity vào `0x...0100` trong test | 0 | Đủ cho test **wiring**, vô dụng cho test **differential** (mock không phải implementation thật) |
| Build image Besu patched trong CI | 1 job ~8 phút build, cache theo SHA | Đúng, và bắt buộc **nếu** Q4 §03.14 chốt "có" |
| Hoãn precompile sang wave 2 | 0 | **Khuyến nghị.** Xem §14.13(9) |

`devnet/seed.sh` chạy `Deploy.s.sol` lên cả hai node và ghi `addresses/ci.json` — cùng format với address book production, để code Odoo đọc chain CI bằng đúng đường đi nó đọc Gnosis. Không có "chế độ test" trong addon; nếu có, thì cái được test không phải là cái chạy production.

---

### 14.11. Test phía Odoo đối với một chain thật trong CI

Bốn tầng, tách bạch; chỉ tầng 3 cần chain, và tầng 0 là thứ bản nháp bỏ sót hoàn toàn:

| Tầng | Ở đâu | Chạy bằng | Cần chain? | Thời lượng |
|---|---|---|---|---|
| **0. Lint theo bẫy Odoo 19** | toàn addon | `grep`/`python` script trong CI | không | 20 s |
| 1. Thuần Python | `dms_blockchain/lib/eip1776.py`, `lib/caip2.py`, `lib/abi.py` | `pytest`, **không import odoo** | không | 40 s |
| 2. Odoo unit | `dms_blockchain/tests/test_*.py`, adapter giả | `odoo -i dms_blockchain --test-enable --test-tags dms_blockchain` | không | 5 phút |
| 3. Odoo ↔ chain | `dms_blockchain/tests/test_chain_*.py` | job riêng có sidecar anvil + besu | **có** | 10–14 phút |

#### Tầng 0 — bẫy Odoo 19 thành gate CI, không thành ghi chú trong CLAUDE.md

Repo đã có tiền lệ: `.github/workflows/dms-ci.yml` có guard `No child_of on parent_path`. `dms_blockchain` cần năm guard nữa, mỗi cái ~5 dòng, mỗi cái chặn một lỗi **im lặng** mà CLAUDE.md §5 đã ghi là đã xảy ra thật:

```bash
# 1. _sql_constraints dang list bi Odoo 19 BO QUA HOAN TOAN
grep -rn "_sql_constraints\s*=\s*\[" dms_blockchain/models/ && exit 1

# 2. Ten field trung ten kieu du lieu Odoo
grep -rnE "^\s+(date|datetime|char|text|float|integer|boolean|binary|html|json|selection|monetary|reference)\s*=\s*fields\." \
     dms_blockchain/models/ && exit 1

# 3. groups_id da doi thanh group_ids o Odoo 19
grep -rn "groups_id" dms_blockchain/ && exit 1

# 4. Body cron phai nam trong method model, XML chi goi mot dong
python3 tools/check_cron_body.py dms_blockchain/data/*.xml   # fail neu <field name="code"> co "fields." hoac nhieu hon 1 statement

# 5. password=True khong ton tai o Odoo 19 va chua bao gio chan read()/RPC
grep -rn "password\s*=\s*True" dms_blockchain/models/ && exit 1
```

Và một guard **runtime**, không phải grep, vì nó là thứ duy nhất chứng minh được: sau khi cài module trong job tầng 2, hỏi thẳng PostgreSQL xem constraint có tồn tại không.

```python
# dms_blockchain/tests/test_constraints_exist.py
@tagged('post_install', '-at_install')
class TestConstraintsReallyExist(TransactionCase):
    EXPECTED = {'blockchain_chain_profile': ['blockchain_chain_profile_unique_evm_chain'],
                'blockchain_zether_account': ['blockchain_zether_account_unique_schnorr'],
                'blockchain_transaction':    ['blockchain_transaction_unique_tx_hash_chain']}

    def test_unique_constraints_in_pg_constraint(self):
        for table, names in self.EXPECTED.items():
            self.env.cr.execute(
                "SELECT conname FROM pg_constraint WHERE conrelid = %s::regclass AND contype = 'u'", (table,))
            found = {r[0] for r in self.env.cr.fetchall()}
            for n in names:
                self.assertIn(n, found, f"{n} KHONG ton tai trong PostgreSQL — models.Constraint bi bo qua?")
```

CLAUDE.md §5 nói rõ: *"Kiểm tra thật bằng SQL, đừng tin code"*. Test trên là câu đó viết thành code, và nó là thứ duy nhất phát hiện được việc ai đó quay lại dạng list.

Thêm một guard cho bẫy stored-computed field: mọi field `store=True, required=True` có `compute=` phải có test khẳng định mọi nhánh của hàm compute đều gán giá trị. Kiểm rẻ nhất: tạo record ở mọi tổ hợp trạng thái đầu vào và assert không có `NOT NULL violation`. Với `blockchain.transaction` thì đó là ma trận `(chain, mode, has_receipt)`.

#### Tầng 1 — nhanh nhất, bắt nhiều lỗi nhất

`lib/eip1776.py` không được `import odoo` — nó tạo digest EIP-712 và **phải** khớp bit-for-bit với `MetaTxLib.hash()`. Cách kiểm: cùng file `testvectors/eip1776_digest_v1.json` được đọc bởi `pytest`, `KatVectors.t.sol` và `vitest`. Một file, ba runner, không có "phiên bản Python của test".

Tầng 1 cũng là nơi test `lib/caip2.py` (parse/format `eip155:100`), `lib/abi.py` (encode/decode calldata từ ABI đã commit), và **bộ chuyển đổi đơn vị** — chỗ mà một lỗi 10^18 không gây exception mà gây mất tiền. Property test bắt buộc:

```python
@given(st.integers(min_value=0, max_value=10**30), st.integers(min_value=0, max_value=18))
def test_scale_roundtrip(raw, decimals):
    assert to_wei(from_wei(raw, decimals), decimals) == raw     # khong lam tron mat mat
```

#### Tầng 2 — Odoo unit, và hai thứ bản nháp không nói

**RPC surface hai đường (CLAUDE.md §6) phải có test, không phải chỉ có tài liệu.** Mọi method public của addon phục vụ client phải chạy được qua **cả hai** `POST /web/dataset/call_kw/<model>/<method>` và `POST /json/2/<model>/<method>`. Một `HttpCase` duy nhất phủ cả hai:

```python
@tagged('post_install', '-at_install')
class TestRpcSurface(HttpCase):
    def test_dms_get_chain_context_both_routes(self):
        self.authenticate('admin', 'admin')
        a = self.url_open('/web/dataset/call_kw/blockchain.chain.profile/blockchain_get_context',
                          data=json.dumps({'jsonrpc':'2.0','method':'call',
                                           'params':{'model':'blockchain.chain.profile',
                                                     'method':'blockchain_get_context',
                                                     'args':[], 'kwargs':{}}}),
                          headers={'Content-Type':'application/json'})
        b = self.url_open('/json/2/blockchain.chain.profile/blockchain_get_context',
                          data=json.dumps({}), headers={'Content-Type':'application/json',
                                                        'Authorization': f'Bearer {self._jwt()}'})
        self.assertEqual(a.json()['result'], b.json())

    def test_client_cannot_inject_allowed_company_ids(self):
        """Server tu intersect voi assignment; khong nhan cong ty do client gui len."""
        other = self.env['res.company'].create({'name': 'Khong duoc thay'})
        res = self._call_json2('blockchain_get_context', {'allowed_company_ids': [other.id]})
        self.assertNotIn(other.id, [c['id'] for c in res['companies']])

    def test_private_methods_not_reachable(self):
        r = self.url_open('/json/2/blockchain.chain.profile/_blockchain_build_context', data='{}')
        self.assertNotEqual(r.status_code, 200)
```

Test thứ hai và thứ ba là kiểm soát an ninh, không phải kiểm tra tính năng. Chúng nằm ở tầng 2 vì chúng không cần chain.

#### Tầng 3 — hai chi tiết quyết định nó chạy được hay không

```python
# dms_blockchain/tests/test_chain_relay.py
@tagged('post_install', '-at_install', 'dms_blockchain_chain')
class TestChainRelay(TransactionCase):

    @classmethod
    def setUpClass(cls):
        cls.rpc = os.environ.get('BLOCKCHAIN_TEST_RPC')
        if not cls.rpc:
            raise unittest.SkipTest('BLOCKCHAIN_TEST_RPC not set')
        super().setUpClass()

    def setUp(self):
        super().setUp()
        self.snap = self._rpc('evm_snapshot', [])
        self.addCleanup(lambda: self._rpc('evm_revert', [self.snap]))
```

1. **Odoo rollback transaction; chain thì không.** Không có `evm_snapshot`/`evm_revert` thì test thứ hai chạy trên state do test thứ nhất để lại, và thứ tự test quyết định kết quả. Đây là lỗi sẽ xuất hiện ở tuần thứ ba và mất một ngày để tìm. Lưu ý ngữ nghĩa mà bản nháp không nêu: **`evm_revert` tiêu huỷ snapshot id** (một lần dùng) và **huỷ mọi snapshot mới hơn**. Vì thế snapshot phải lấy trong `setUp` của **từng** test, không lấy một lần trong `setUpClass`. Song song hoá test tầng 3 trên cùng một node anvil là **không thể** vì snapshot là toàn cục — muốn song song thì mỗi worker một container anvil, mỗi container một port.
2. **Cron không được gọi qua cron trong test.** Theo CLAUDE.md §5 bẫy 4, body cron nằm trong method model; test gọi thẳng `self.env['blockchain.transaction']._cron_poll_finality()` sau khi `cast rpc anvil_mine 12`. Không `cr.commit()`, không `time.sleep` chờ scheduler.

**Bộ test tầng 3 tối thiểu — bản nháp có 4 case, đây là 9, và mỗi cái bổ sung đóng một đường hỏng thật:**

| # | Case | Khẳng định |
|---|---|---|
| a | Đăng ký `blockchain.zether.account` gasless qua relayer subsidized | Record `registered`, event khớp `schnorrAddress` |
| b | Meta-tx đi trọn vòng `draft → signed → broadcast → pending → done` | `done` **chỉ** khi đủ finality depth; đứng yên ở `pending` khi chưa đủ |
| c | **Reorg**: `evm_revert` rồi mine nhánh khác | Record quay về `pending`, **không** ở `done`; sinh `blockchain.reorg.event` |
| d | **Reorg lật một record đã `final`** | Chain chuyển `halted`, **không** tự đảo bút toán, page người thật (§11) |
| e | Relayer claim trùng | Một thắng, một nhận lỗi **có tên** (`AlreadyRelayed`), không phải "unknown revert" |
| f | **Tx bị drop khỏi mempool** (`anvil_dropTransaction`) | Sau timeout, record về `pending` và replacement được phát, không kẹt vĩnh viễn |
| g | **Replacement tx với nonce trùng** thắng cuộc | Record theo tx hash **mới**, tx hash cũ đánh dấu `replaced`, không sinh hai `account.move` |
| h | **Idempotency**: index cùng một block hai lần | Không nhân đôi record; unique constraint `(chain, tx_hash, log_index)` chặn |
| i | **Chain `halted`** rồi resume | Watermark tiếp đúng chỗ dừng, không bỏ sót block, không index lại |

(b), (c) và (d) là nguyên tắc *"broadcast không phải là thanh toán"* được viết thành test. Nếu không có (c) và (d) trong CI thì Finality Gate chỉ là một comment. (g) và (h) là hai lỗi đắt nhất trong lớp hệ thống này: chúng tạo **tiền từ hư không trong sổ kế toán Odoo** trong khi on-chain hoàn toàn đúng.

---

### 14.11b. Test cho ràng buộc "standalone" (locked #7) — một job, và nó không tuỳ chọn

Ràng buộc *"`dms_blockchain` MUST NOT depend on `dms`"* là thứ vỡ **âm thầm**: một `self.env['dms.trade.settlement']` trong một nhánh code hiếm, hoặc một `<field name="partner_id" domain="[('outlet_code','!=',False)]"/>` trong view, sẽ chạy hoàn hảo trên máy dev (nơi `dms` luôn được cài) và nổ ở khách hàng đầu tiên cài standalone.

Ba job, chạy **song song**, mỗi job một DB sạch:

| Job | DB | Khẳng định |
|---|---|---|
| `odoo-standalone` | chỉ `base` + `dms_blockchain` | Cài được, mọi test tầng 2 xanh, mọi view render được |
| `odoo-with-dms` | `dms` + `dms_blockchain` (không có bridge) | Hai addon cùng tồn tại, không đụng tên model/field |
| `odoo-bridge` | `dms` + `dms_blockchain` + `dms_blockchain_bridge` | Seam §14 P14 hoạt động |

Cộng một gate tĩnh 3 dòng, chạy trước cả khi dựng DB:

```bash
python3 - <<'PY'
import ast, pathlib, sys
man = ast.literal_eval(pathlib.Path('dms_blockchain/__manifest__.py').read_text())
assert 'dms' not in man['depends'], "locked #7: dms_blockchain khong duoc depend dms"
PY
grep -rn "env\[['\"]dms\." dms_blockchain/ --include='*.py' && exit 1
grep -rn "\bdms\." dms_blockchain/views/ dms_blockchain/security/ && exit 1
```

Job `odoo-standalone` là **required check**; hai job kia chạy nightly. Lý do phân biệt: standalone là ràng buộc khách hàng đã chốt, hai cái kia là tích hợp nội bộ.

---

### 14.12. Deploy script, address book, verify, và diễn tập nâng cấp

**Deploy.** `forge script script/Deploy.s.sol --rpc-url $CHAIN --broadcast --verify --slow`. Mọi contract đi qua `DeterministicFactory` (CREATE2) với salt = `keccak256(abi.encode(purpose, version, chainSalt))`. `PredictAddress.s.sol` in địa chỉ dự kiến **trước** khi broadcast; số này được dán vào PR deploy và so lại sau khi chạy. Không khớp ⇒ dừng, vì nó có nghĩa là bytecode hoặc salt đã khác so với cái đã audit.

**Ba thứ bản nháp bỏ qua và cả ba đều chặn deploy ngày đầu tiên:**

**(1) Ai giữ khoá, và khoá nằm ở đâu.** Bản nháp đẩy câu này xuống mục "câu hỏi cần người quyết". Nó không thể chờ: `forge script --broadcast` cần một signer, và mặc định của mọi hướng dẫn trên Internet là `--private-key $PK` — tức là một khoá plaintext trong biến môi trường, vi phạm thẳng ràng buộc *"cấm Agent lưu private key plaintext"* của `blockchain.md`. Ba đường hợp lệ, theo profile:

| Profile | Signer | Lệnh |
|---|---|---|
| Devnet CI | Khoá anvil hardcode (công khai, dùng một lần) | `--private-key 0xac09...` |
| Testnet | Hardware wallet của một dev | `forge script --ledger --hd-paths "m/44'/60'/0'/0/0"` |
| **Mainnet / private production** | **AWS KMS qua `--aws`**, và **owner của mọi contract là Safe 3-of-5 ngay từ block đầu** | `forge script --aws --sender $KMS_ADDR` |

Điểm mấu chốt của cột 3 không phải KMS mà là **Safe từ block đầu**: nếu deployer EOA là owner "tạm thời để test rồi chuyển sau", thì luôn có một cửa sổ (thường là vài tuần) mà toàn hệ thống bằng đúng một khoá. Chuyển owner là một transaction, và transaction đó luôn bị hoãn.

**(2) CREATE2 factory có thể không tồn tại trên chain đích.** Foundry mặc định dùng `0x4e59b44847b379578588920cA78FbF26c0B4956C` (deterministic-deployment-proxy của Arachnid). Nó có mặt trên hầu hết chain lớn nhưng **không** tự động có trên một Besu private chain mới tinh, và không đảm bảo trên Celo. Bootstrap, theo §01.208:

```
BootstrapCreate2.s.sol:
  1. if (address(FACTORY).code.length > 0) return;                  // da co
  2. fund 0x3fab184622dc19b6109349b94811493bf2a45362 voi 0.01 native  // deployer cua presigned tx
     (bo qua buoc nay neu chain o che do zero-gas)
  3. broadcast raw presigned tx (hang so cong khai, cung mot tx tren moi chain)
  4. require(address(FACTORY).code.length > 0, "bootstrap that bai")
```

Test `test_create2_factory_exists` ở §14.6 là thứ phát hiện việc này **trước** ngày deploy, không phải trong lúc deploy.

**(3) Deploy phải chạy được lại (idempotent).** `forge script` không tự biết contract nào đã deploy. `Deploy.s.sol` phải kiểm `address(predicted).code.length > 0` trước mỗi bước và bỏ qua nếu đã có. Không có điều này, một lần deploy bị đứt giữa chừng (RPC timeout ở contract thứ 7 trên 12) sẽ không có đường chạy tiếp ngoài việc làm bằng tay — đúng lúc căng thẳng nhất.

**Address book.** `forge script` ghi `broadcast/<script>/<chainId>/run-latest.json` — đầy đủ nhưng ồn. `SyncAddressBook.s.sol` chắt ra `addresses/eip155-<id>.json`:

```json
{ "caip2": "eip155:100", "deployedAt": "2026-09-14T03:11:02Z", "commit": "a1d658b",
  "solc": "0.8.28", "optimizerRuns": 200, "viaIr": false, "evmVersion": "cancun",
  "contracts": { "MetaTxForwarder": { "proxy": "0x…", "impl": "0x…", "version": "1.2.0",
                                      "initCodeHash": "0x…",
                                      "storageLayout": "storage-layouts/v2/MetaTxForwarder.json",
                                      "abi": "abi/MetaTxForwarder.json",
                                      "buildInfo": "build-info/a1d658b.json" } } }
```

Bốn field bản nháp thiếu (`solc`, `optimizerRuns`, `viaIr`, `evmVersion`, `initCodeHash`, `buildInfo`) tồn tại vì một lý do: **ba năm nữa, để verify lại contract này hoặc để chứng minh với kiểm toán, cần dựng lại đúng môi trường build.** Ghi commit hash là chưa đủ nếu `foundry.toml` đã đổi kể từ đó.

Odoo **không hardcode địa chỉ**. Một data loader đọc file này thành record `blockchain.contract` (many2one tới `blockchain.chain`, **không** phải `Integer chain_id` — §02.8.5 đã chốt đặt tên `evm_chain_id` để không nhầm với m2o). Địa chỉ là dữ liệu vận hành, không phải hằng số nguồn — điều này cũng là thứ cho phép một deployment thứ hai (tenant khác, chain khác) chạy cùng code.

**Verify.** `forge verify-contract --verifier sourcify` là mặc định vì Sourcify chạy trên cả Gnosis lẫn Celo mà không cần API key; `--verifier blockscout --verifier-url https://gnosis.blockscout.com/api/` cho trang explorer đẹp. Private chain **không có explorer công cộng** ⇒ dựng Blockscout tự host trong `devnet/docker-compose.yml`, verify vào đó bằng cùng lệnh. Ghi chú §14.2: giữ `bytecode_hash = "ipfs"` chính là điều kiện để Sourcify cho **full match** thay vì partial.

Job CI `verify-drift` chạy hàng tuần: `cast code <addr>` trên chain thật, hash, so với `out/<C>.sol/<C>.json` build lại từ commit ghi trong address book. Lệch ⇒ page. Đây là cách phát hiện một upgrade không qua quy trình. Với proxy, phải so **cả hai**: `implementation()` slot (EIP-1967 `0x360894a1...bbc`) và code của implementation đó — chỉ so code proxy sẽ không bao giờ đổi và job trở nên vô dụng.

**Diễn tập nâng cấp (upgrade rehearsal) — bắt buộc, không tuỳ chọn:**

```
make rehearse CHAIN=gnosis BLOCK=head-32
```

`UpgradeRehearsal.s.sol` fork chain thật ở block gần head, rồi:
1. `vm.prank(timelock)` → `schedule` + `execute` **đúng** calldata sẽ gửi lên timelock thật;
2. chạy **toàn bộ** `test/invariant/` lên state đã fork-and-upgrade (chứ không lên state sạch — đây là điểm mấu chốt: bug upgrade nằm ở dữ liệu cũ, không nằm ở dữ liệu mới);
3. `forge inspect` storage layout mới, diff với `storage-layouts/v<N-1>/`;
4. in ra `keccak256(calldata)`;
5. **(bổ sung) diễn tập đường lùi**: `schedule` + `execute` calldata **downgrade** về `v<N-1>`, rồi chạy lại invariant. Nếu không lùi được thì phải biết điều đó **trước** khi tiến, không phải sau.

Gate: hash ở bước 4 phải khớp calldata thực sự được submit lên timelock production. Không khớp ⇒ đó không phải là thứ đã được diễn tập. Timelock delay tối thiểu **48 giờ** trên public profile để hash này kịp được đối chiếu công khai.

Ba câu hỏi mà rehearsal phải trả lời và bản nháp không đặt:
- **Có ai còn đọc số dư Zether được sau upgrade không?** §07 cảnh báo: mất khoá ⇒ số dư mã hoá không giải mã lại được. Rehearsal phải giải mã một số dư thật (từ fork state) **sau** upgrade bằng một khoá test đã biết. Đây là kiểm chứng duy nhất rằng upgrade không phá format ciphertext.
- **`proofSystemId()` có đổi không?** Nếu có, mọi proof đang bay trong mempool trở nên vô hiệu. Cần một cửa sổ grace, và rehearsal phải đo nó.
- **Pending transfer trong epoch hiện tại có sống sót không?** `rollOver` chưa gọi ⇒ có tiền đang treo trong `pending_transfers`. Upgrade giữa hai epoch là chuyện sẽ xảy ra.

---

### 14.12b. ABI drift: gate mà không ai nhớ cho đến khi mất tiền

`dms_blockchain` encode calldata. Nếu ABI trong addon lệch một chữ so với contract đã deploy, kết quả **không** phải là exception rõ ràng — nó là một `eth_call` trả về rác hoặc một transaction revert **sau khi relayer đã trả gas**. Với `mode = MODE_OPEN`, người trả giá là một bên thứ ba không quen biết, và đó là cách nhanh nhất để mất Open Relayer.

Cơ chế, ba phần:

```bash
# 1. Sinh ABI la mot buoc build, khong phai viec chep tay
make abi     # forge inspect <C> abi > evm/abi/<C>.json cho moi contract trong danh sach public

# 2. Gate PR: ABI trong repo phai khop build hien tai
make abi && git diff --exit-code evm/abi/ || { echo "ABI doi ma chua commit"; exit 1; }

# 3. Gate cross-repo: addon doc ABI tu file da commit, va CI khang dinh dieu do
grep -rn '"inputs"' dms_blockchain/ --include='*.py' && { echo "ABI hardcode trong Python"; exit 1; }
```

Addon nạp ABI như dữ liệu, không như hằng số:

```python
class BlockchainContract(models.Model):
    _name = 'blockchain.contract'
    abi_attachment_id = fields.Many2one('ir.attachment')   # file JSON, S3, KHONG base64 trong DB
    abi_sha256 = fields.Char(index=True)                   # so voi addresses/*.json luc khoi dong

    def blockchain_check_abi_matches_chain(self):
        """POST /json/2/blockchain.contract/blockchain_check_abi_matches_chain
        Doi chieu selector cua ABI voi code on-chain. Chay trong cron hang ngay."""
        return self._check_selectors_present()
```

Kiểm mạnh nhất và rẻ nhất: với mỗi selector trong ABI, `eth_call` một lời gọi dị dạng và khẳng định nó **không** trả về `0x` rỗng của "function not found". Chạy hàng ngày trong cron, kết quả vào `blockchain.chain.health`. Nó phát hiện upgrade ngoài quy trình nhanh hơn `verify-drift` hàng tuần.

---

### 14.13. Chỗ `blockchain.md` (và các section trước) sai, thiếu, hoặc mâu thuẫn nhau

1. **Bốn cây `smartcontracts/` mâu thuẫn** (§01.14 phẳng, §02.8.4 `evm/registry/foundry.toml`, §03.9 `evm/zether/src/`, §04 `evm/metatx/`). Không thể cùng đúng: bốn `foundry.toml` là bốn project độc lập. §14.1 thay cả bốn bằng một project, chia theo purpose ở mức `src/`.
2. **§07 (và §07.504) nói "build profile `public` không chứa selector `recoverAccount`".** Foundry profile chỉ đổi *cấu hình compiler* — nó **không** loại bỏ hàm khỏi source; Solidity không có tiền xử lý điều kiện. Cách đúng: `ZetherTokenBase` abstract + hai contract cụ thể. **Và cách kiểm của bản nháp §14 cũng sai**: `forge inspect deployedBytecode | grep <selector>` cho **false positive** vì một chuỗi 4 byte bất kỳ xuất hiện trong constant, immutable hay jump table. Kiểm đúng, hai tầng:
   ```bash
   forge inspect ZetherTokenOpen methodIdentifiers | jq -e 'has("recoverAccount(bytes32,bytes)")' && exit 1
   ```
   cộng một test on-chain: `vm.expectRevert(); address(open).call(abi.encodeWithSelector(0x…))` phải revert vì không match hàm nào (`fallback` phải không tồn tại hoặc phải revert).
3. **`blockchain.md` §10.5.2 ghi ZKP verify "~180,000–250,000 gas".** Đó là bậc của **Groth16** (`45,000 + 4 × 34,000 = 181,000` cho `ecPairing` k=4). Bulletproofs **không dùng pairing**. §03.3.7 đã chẩn đoán chính xác và §03.3.6 cho con số đúng: **1.88 M** ở cấu hình 32/64 đã chốt (sai **9×**), **3.87 M** ở cấu hình 128/128 mà note mô tả (sai **19×**). Bản nháp §14 ghi "1.5–2.5M" — gần đúng nhưng đến từ một cấu hình (128-bit) đã bị §03 loại bỏ; đã sửa ở §14.5b. Hệ quả: (a) `BulletproofsVerifier` có nguy cơ chạm EIP-170; (b) trên Gnosis (block limit 17M) chỉ ~9 transfer/block, và ở 20% block space là **31,300 tx/ngày toàn mạng**; (c) muốn 200k thì phải đi Groth16, và đó là đánh đổi trusted setup, không phải tối ưu hoá.
4. **CIP-64 `feeCurrency` không ký được bằng Foundry.** Celo dùng transaction type `0x7b` có field `feeCurrency`; `cast`/`forge` không encode nó. Test "trả gas bằng cUSD" phải viết bằng `viem` (chain formatter `celo` hỗ trợ CIP-64) trong `evm/ts-conformance/`. **Đề xuất: viết, ~120 dòng**, vì §08 chốt Celo là chain thứ hai và fee currency là **lý do duy nhất** chọn Celo.
5. **`blockchain.md` yêu cầu "Simulation Gate với tỷ lệ revert bằng 0%".** Không đạt được và không nên hứa. Mô phỏng ở block N, thực thi ở N+k; giữa hai thời điểm có `rollOver()`, có transfer đến, có relayer khác giành nonce. Mục tiêu đúng: revert **có tên** và **rẻ** (§03.7.5: sắp checks rẻ trước verify ⇒ chi phí thua cuộc 30k thay vì 1.3M gas), cộng một SLO đo được (< 0.5% revert trên intent đã simulate).
6. **`blockchain.md` không nói gì về test vector, CI, hay quy trình nâng cấp** — trong khi §10.5.3 đặc tả `simulateAccounts` là "hàm view sống còn" và §10.2.1 đặt UUPS làm mô hình nâng cấp. Hai thứ đó không có test regression thì là bề mặt tấn công, không phải tính năng.
7. **BN254 (`alt_bn128`) ở mức ~100-bit security**, không phải 128 (Kim–Barbulescu 2016). Hệ quả cho kiểm thử: KAT phải sinh kèm `curve_id`, và mọi curve impl chạy **cùng một** bộ test qua `CurveParityBase` (I22).
8. **`ffi = true` toàn cục là rủi ro chuỗi cung ứng thật.** Đã xử lý bằng profile riêng; cần thêm: `lib/` chỉ nhận submodule ghim commit — `forge install` với tag là không đủ vì tag move được, và Dependabot không quét submodule của Foundry.
9. **[MỚI] §03.3.9 chọn `go-quorum/geth-QBFT`; §08.10 chọn `Hyperledger Besu + QBFT` và loại thẳng GoQuorum ("đã ở chế độ maintenance").** Hai section mâu thuẫn trực tiếp về **client của private chain**, tức là về cái image chạy trong `devnet/docker-compose.ci.yml`. Lập luận của §03 ("Besu là Java, cần JNI, gấp 5 lần công") đã cũ: Besu chạy trên **Java 21+**, và **Foreign Function & Memory API** (`java.lang.foreign`, GA từ JDK 22) gọi được thư viện Rust/C mà không cần một dòng JNI. Ước tính lại: đăng ký một precompile trong Besu = ~150 dòng Java + một `MethodHandle` FFM, ngang với ~150 dòng Go trong geth. **Đề xuất giải quyết: giữ Besu (§08.10 thắng, vì GoQuorum thật sự ở maintenance mode), hoãn native precompile sang wave 2, và nếu làm thì làm trong `besu-precompile/` bằng Java 21 FFM.** Wave 1 chạy `BulletproofsVerifier.sol` trên Besu: 50M gas limit ÷ 1.88M = **26 tx/block**, ở block 2 s là **13 tx/s** — đủ cho B2B settlement (§01.1019 cần 45 tx/s cho kịch bản đầy đủ, nhưng không phải ngày đầu).
10. **[MỚI] Bảng Finality Gate của `blockchain.md` §10.4 mô tả Celo là "IBFT 2.0, immediate finality, ~5 giây".** Sai kể từ 03/2025: Celo là **L2 trên OP Stack** (§02.5.4 và §06.352 đều xác nhận). Không có immediate finality; `safe` sau vài phút, `finalized` sau ~15–20 phút theo L1. Bảng đó đang được dùng làm nguồn cho `finality_depth` ở §11 ⇒ **nếu không sửa, hệ thống sẽ ghi `_set_done` cho một block Celo có thể bị lật.** Đây là vi phạm trực tiếp nguyên tắc "broadcast không phải là thanh toán", ở đúng chỗ nó tốn tiền.
11. **[MỚI] `evm_version` và genesis private chain không khớp.** §01.14.1 và §14.2 đặt `cancun`; genesis §08.10 khai `"shanghaiTime": 0` và không có `cancunTime`. `TSTORE`/`MCOPY` sẽ là `INVALID` opcode trên private chain **sau khi mọi test đã pass**. Gate `devnet/check-genesis-fork.sh` ở §14.2 là fix; và §08.10 phải thêm `cancunTime: 0`.
12. **[MỚI] `gasLimit` của Besu lệch giữa hai section**: §08.10 ghi `0x2FAF080` (50M), §01.789 ghi "200M" trong bảng throughput. Chênh 4× ⇒ chênh 4× throughput dự kiến (26 vs 106 tx/block). Phải chốt một số. **Đề xuất 50M**: block 200M ở QBFT 2 s nghĩa là mỗi validator phải thực thi 100M gas/s, vượt xa năng lực thực tế và biến block time thành lý thuyết.
13. **[MỚI] Đường cong ElGamal chưa nhất quán giữa các cây thư mục.** §03.3.9 khuyến nghị **dứt khoát** đặt ElGamal trên **Baby Jubjub** ngay từ đầu (điều kiện cần để sau này đi Groth16 mà không phải đổi curve — đổi curve = lộ toàn bộ số dư). Bản nháp §14.1 vẫn liệt kê `curve/{CurveBN254,CurveBLS12381}.sol`. Đã sửa ở §14.1: `CurveBabyJubjub.sol` là mặc định, `CurveBn254.sol` giữ làm reference. Quyết định này phải chốt **trước khi deploy contract đầu tiên**.
14. **[MỚI] `via_ir = true` được §01.14.1 gọi là bắt buộc ("struct 12 field ⇒ stack too deep nếu không bật").** Không đúng với `struct calldata` đọc trực tiếp field. Và nó có giá: build ×6–13, `forge coverage` hỏng ⇒ gate coverage 90% ở §01.14.2 và §14.14 là gate chết. Xem §14.2b.
15. **[MỚI] `bytecode_hash = "none"` được §01.14.1 gọi là BẮT BUỘC cho tính tái lập.** Không đúng: Foundry dùng đường dẫn tương đối, metadata đã deterministic khi đã ghim solc/settings/submodule. Cái giá thật là **mất Sourcify full match**. Xem §14.2, và determinism gate thay thế nó.
16. **[MỚI] I11 của bản nháp sai vì `IZetherToken is IERC20`.** `blockchain.md` §10.5.3 nguyên tắc 3 cho contract vừa là ERC-20 công khai vừa giữ escrow bảo mật ⇒ `underlying.balanceOf(token)` đổi qua 4 đường, không phải 2. Xem I11' §14.4.
17. ~~**Không section nào nói `rollOver` có permissionless hay không.**~~ **ĐÃ ĐÓNG — [BẢN 5, 2026-09-03].** Câu trả lời: **permissionless theo mặc định**, với cờ per-account `RollOverMode` và `OWNER_ONLY` opt-in cho R3/R4; grief bị chặn bằng quy tắc **no-op khi `pending` rỗng** chứ không bằng kiểm quyền. Nguồn chuẩn tắc: `00-CANON.md` §C5 [BẢN 5] và §03.5.3–§03.5.4. I18 đã viết lại theo ba mệnh đề ở §14.4.

---

### 14.14. Pipeline CI: job, thời lượng, gate, và tiền

Bảng dưới giả định **GitHub-hosted runner 4 vCPU / 16 GB Linux** (giả định A1 ở §14.0b, viết ra thành lời). Trên runner 2 vCPU mặc định, nhân mọi con số CPU-bound với **1.8–2.2×** và tổng đường tới hạn PR nhảy từ ~25 lên ~45 phút — ngưỡng mà đội sẽ bắt đầu bỏ qua CI.

| Job | Trigger | Ước tính | Gate |
|---|---|---|---|
| `fmt-lint` (`forge fmt`, `solhint`, `semgrep`) | PR | 45 s | fail |
| `odoo-trap-lint` (tầng 0 §14.11) | PR | 20 s | fail |
| `build-sizes` (runtime 24,000 + initcode 49,152) | PR | 1–2 phút | fail |
| `determinism` (build 2 lần, 2 đường dẫn, diff hash) | PR chạm `src/`+`lib/` | 3 phút | fail |
| `genesis-fork-match` | PR chạm `foundry.toml`/`genesis` | 5 s | fail |
| `test-unit` | PR | 1–2 phút | fail |
| `test-fuzz` (1,000 runs) | PR | 3–5 phút | fail |
| `test-invariant` (1,000 × depth 50, **MockVerifier**) | PR | 4–7 phút | fail |
| `gas-snapshot` (`gas_diff.py`, 1% **và** 5,000 gas tuyệt đối) | PR | 2 phút | fail |
| `storage-layout + validateUpgrade` | PR | 1 phút | fail |
| `slither + slither-check-upgradeability` | PR | 3 phút | fail High/Medium |
| `halmos` (subset: `MetaTxLib`, `Bn254`, `Peg`) | PR | 5–8 phút | fail |
| `kat + differential` (ma trận 1↔2↔3, không có 4) | PR | 4 phút | fail |
| `abi-drift` (§14.12b) | PR | 30 s | fail |
| `odoo-unit` (tầng 1+2) | PR | 6 phút | fail |
| `odoo-standalone` (§14.11b) | PR | 6 phút | fail |
| `odoo-chain` (anvil + besu sidecar, tầng 3, 9 case) | PR | 10–14 phút | fail |
| `fork-gnosis`, `fork-celo` (RPC cache) | main + nightly | 5 phút | fail trên main; `continue-on-error` trên PR từ fork |
| `test-invariant-deep` (50,000 runs) | nightly | 25–60 phút | issue tự động |
| `mutation` (gambit / necessist / cargo-mutants, 3 job) | nightly | 3 × ~3 giờ | score < 80% ⇒ issue |
| `cargo-fuzz` (3 target × 600 s) | nightly | 30 phút | crash ⇒ P1 |
| `coverage` (`[profile.coverage]`, via_ir tắt) | nightly | 15 phút | < 90% trên `src/token`, `src/peg`, `src/metatx`, `src/zether` ⇒ issue |
| `submodule-drift` | nightly | 1 phút | issue nếu upstream có commit mới |
| `non-evm-smoke` (5 stub theo tiêu chí §14.3) | nightly | 12 phút | fail |
| `differential-precompile` (1↔4, 3↔4) | nightly **nếu** làm precompile | 15 phút | fail |
| `odoo-with-dms`, `odoo-bridge` | nightly | 12 phút | fail |
| `verify-drift` (proxy slot + impl code) | weekly | 2 phút | page |

**Tổng đường tới hạn trên PR: ~25 phút** với job chạy song song; `odoo-chain` (10–14 phút) và `halmos` (5–8 phút) là hai bottleneck. Đó là ngưỡng còn dùng được. Mọi thứ đắt hơn đẩy sang nightly — và nightly đỏ thì mở issue tự động chứ không chặn merge, vì một nightly chặn merge sẽ bị vô hiệu hoá trong hai tuần.

**Chi phí tiền mặt** (GitHub-hosted Linux, $0.008/phút cho 2 vCPU, $0.016 cho 4 vCPU):

| | Phút/lần | Lần/tháng | $/tháng |
|---|---|---|---|
| PR pipeline (tổng phút máy, không phải wall-clock) | ~85 | 60 PR | $82 |
| Nightly (invariant deep + mutation + fuzz + coverage + smoke) | ~700 | 30 | $336 |
| Weekly + main | ~40 | 12 | $8 |
| **Tổng** | | | **~$430/tháng** |

Con số này đáng nêu vì nó là con số duy nhất trong section có thể bị cắt bởi một quyết định ngân sách, và nó **rẻ hơn một ngày công engineer**. Nếu phải cắt, cắt theo thứ tự: `coverage` (thấp giá trị nhất, dễ gian lận nhất) → `necessist` → `cargo-fuzz` giảm còn 2 lần/tuần. **Không** cắt `determinism`, `gas-snapshot`, `storage-layout`, `abi-drift`, `odoo-chain` — đó là năm gate bảo vệ những thứ hỏng âm thầm.

**Danh sách required check trên `main`** (thứ chặn merge thật sự, ngắn có chủ đích): `fmt-lint`, `odoo-trap-lint`, `build-sizes`, `determinism`, `test-unit`, `test-invariant`, `gas-snapshot`, `storage-layout`, `slither`, `kat + differential`, `abi-drift`, `odoo-unit`, `odoo-standalone`, `odoo-chain`.

**An ninh CI, ba dòng không thương lượng:**
- `permissions: contents: read` mặc định ở workflow level; nâng quyền per-job, không per-workflow.
- Mọi action ghim theo **commit SHA** (`actions/checkout@8f4b7f8…`), không theo tag.
- **Không bao giờ** `pull_request_target`. PR từ fork chạy không secret; fork test `continue-on-error`.

Workflow đặt tại `smartcontracts/.github/workflows/`, **tách khỏi** `dms-ci.yml` hiện có: hai cây, hai vòng đời, hai nhóm reviewer, hai CODEOWNERS. Job `odoo-chain` là job duy nhất bắc cầu, và nó sống ở `.github/workflows/blockchain-addon.yml` bên phía repo addon, gọi `smartcontracts/devnet/docker-compose.ci.yml` làm sidecar. Nếu hai repo tách ra thật (khả năng cao khi `smartcontracts/` mở nguồn — §14.15(6)), job này trở thành job duy nhất phải sửa.

---

### 14.15. Câu hỏi cần người quyết

Sáu câu đầu giữ từ bản nháp; sáu câu sau là mới và mỗi câu chặn một thứ cụ thể.

1. **Ai giữ khoá deploy production, và Certora có mua license không?** ($12k–40k/năm; nếu không thì bỏ dòng Certora ở §14.9 và tăng phạm vi audit người ở §12.8.) *Phần khoá đã có đề xuất ở §14.12: AWS KMS + Safe 3-of-5 từ block đầu — cần xác nhận, không cần thiết kế thêm.*
2. **Block ghim cho fork test cập nhật theo chu kỳ nào** — quý, hay chỉ khi có hard fork? (Ảnh hưởng chi phí bảo trì test và kích thước RPC cache.)
3. **Có viết `evm/ts-conformance/` bằng TypeScript không** (mâu thuẫn 4), hay chấp nhận đường fee-currency chỉ được kiểm thủ công cho tới wave 2? *Khuyến nghị: viết. ~200 dòng cho cả CIP-64 lẫn EIP-712 cross-check, và cái thứ hai đáng giá độc lập.*
4. **Besu image version ghim ở đâu và ai theo dõi CVE của nó?** Một node private chạy image cũ 18 tháng là rủi ro lớn hơn mọi thứ trong bảng invariant.
5. **Mutation score 80% là gate cứng hay chỉ báo cáo?** Cứng thì phải chấp nhận nightly đỏ trong 4–6 tuần đầu.
6. **`relayer-ref/` phát hành công khai (Apache-2.0) hay chỉ nội bộ?** Mở nguồn là **điều kiện cần** để có Open Relayer thứ ba, mà đó lại là toàn bộ luận điểm của EIP-1776. Câu hỏi kèm theo, phải trả lời cùng lúc: **licence của `src/`**. Đề xuất cụ thể: `src/*/interfaces/**` + `relayer-ref/` + `crates/zether-core` (phần verifier) **Apache-2.0**; `src/zether/`, `src/peg/` **BUSL-1.1 với change date +24 tháng**. Lý do: relayer bên thứ ba cần verify được proof và encode được intent (⇒ interface và verifier phải mở), nhưng không cần fork toàn bộ token stack ngày đầu.
7. **[MỚI] `ZetherToken` có kế thừa `IERC20` không?** (§14.4, I11 vs I11'.) `blockchain.md` §10.5.3 nói có; hệ quả là hai kế toán trên một số dư và một invariant khó hơn hẳn. **Khuyến nghị: không** — tách `WrappedToken` công khai khỏi `ZetherToken` bảo mật. Quyết định này phải chốt **trước khi viết contract**, không sửa được sau khi có số dư thật.
8. ~~**`rollOver` permissionless hay không?**~~ **ĐÃ CHỐT 2026-09-03 — cả hai, theo cờ per-account.** `PUBLIC` mặc định (ai gọi cũng được, no-op khi `pending` rỗng, batch không chữ ký — giải đúng câu "ai gọi hộ tài khoản không hoạt động"), `OWNER_ONLY` opt-in cho R3/R4 (không grief được, đổi lại kẹt nếu chủ offline). Cờ **phải có trong `v1`** vì token bất biến. I18 đã viết lại tương ứng (§14.4).
9. **[MỚI] Curve của ElGamal: Baby Jubjub hay BN254 G1?** (§14.13(13).) §03 khuyến nghị dứt khoát Baby Jubjub. Chọn sai ⇒ ngày muốn đi Groth16 phải đổi curve, và đổi curve nghĩa là **giải mã lại toàn bộ số dư để mã hoá lại**, tức là lộ hết. Đây là quyết định một chiều, cần chốt trước contract đầu tiên.
10. **[MỚI] Native precompile Zether: wave 1 hay wave 2, và trên client nào?** (§14.13(9).) Wave 1 không có precompile ⇒ 13 tx/s trên Besu, đủ cho B2B settlement khởi động. Có precompile ⇒ ~500 tx/s nhưng là consensus change, phải tự maintain một fork client, và cần thêm hai job differential (1↔4, 3↔4). **Khuyến nghị: wave 2**, giữ `IZetherVerifier` để đường này không bị khoá.
11. **[MỚI] Runner CI: 2 vCPU hay 4 vCPU?** (Giả định A1.) Chênh lệch $200/tháng và chênh lệch 20 phút wall-clock mỗi PR. Với đội 4 người, 20 phút × 60 PR/tháng = 20 giờ chờ/tháng. Con số đó tự trả lời câu hỏi, nhưng ngân sách CI thường thuộc người khác.
12. **[MỚI] `smartcontracts/` có tách thành repo riêng không, và khi nào?** Hôm nay nó ở cùng repo với addon Odoo, nghĩa là mọi PR Solidity đều hiện trong lịch sử của repo DMS và mọi reviewer Odoo đều là CODEOWNER tiềm năng. Nếu §14.15(6) chốt mở nguồn thì tách là bắt buộc, và job `odoo-chain` phải đổi sang gọi Docker image đã publish thay vì `docker-compose` cục bộ. Tách muộn đắt hơn tách sớm, nhưng tách sớm mất tính nguyên tử của một PR chạm cả hai phía.
