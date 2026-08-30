# smartcontracts

Cây hợp đồng của `dms_blockchain`. **Nằm ngoài addon Odoo, ở gốc repo** — hợp đồng
có vòng đời riêng (audit, deploy, immutability) không trùng vòng đời của một addon.

Chưa có implementation. Đây là **interface đã compile được**, chốt lại những gì đã
quyết. Implementation đi theo plan.

## Mô hình: factory mở

Ai cũng tạo token được. Ai cũng wrap thành Meta Token hoặc Zether Token được. Mười
người wrap xDAI thành mười contract khác nhau là hợp lệ và không ai chặn — **không có
wrapper chính thức**, và factory không có hàm nào hàm ý là có.

Ba hệ quả xuyên suốt cây này:

1. **Hỗ trợ mọi curve, không ưu tiên cái nào.** Người tạo token truyền địa chỉ verifier.
   Vì bn254 mã hoá G1 bằng 64 byte còn BLS12-381 bằng 128 byte, interface chung nhận
   điểm dạng `bytes` — `struct G1Point { uint256 x; uint256 y; }` là kiểu của bn254,
   không phải kiểu của "một điểm".
2. **Không Beacon proxy.** Beacon nghĩa là chủ beacon thay được implementation của mọi
   token người lạ từng tạo. Mặc định là EIP-1167 clone bất biến; UUPS do chính người
   tạo sở hữu là tuỳ chọn.
3. **Bỏ gác cổng thì bù bằng xuất xứ.** `factory()`, `creator()`, `underlying()`,
   `verifier()` bất biến và công khai, `isDeployedHere()` để đối chiếu ngược. Đủ để
   trả lời "cái này wrap gì, ai tạo, verifier nào" — không đủ để trả lời "cái này có
   phải bản nên dùng không", và đó là câu hỏi của thị trường.

### Chọn curve nào — hướng dẫn, không phải quy định

Đo thật trên Gnosis, `eth_estimateGas`, k = 277 điểm (quy mô Bulletproofs):

| | bn254 | BLS12-381 |
|---|---|---|
| Gas MSM ở k=277 | **1,70 M** | 1,74 M (đắt hơn ~2%) |
| Gas ở k=1 | **6.000** | 12.357 (đắt hơn 106%) |
| An toàn | ~100 bit | **~126 bit** |
| Chain chạy được | **mọi chain EVM** (Byzantium 2017) | chỉ chain có Prague |
| G1 on-chain | 64 byte | 128 byte |

Canon từng ghi BLS *"rẻ hơn 45–60%"*. Đo được là **sai** — không có mức tiết kiệm đó
ở bất kỳ `k` nào. Chọn BLS khi và chỉ khi chân trời bảo mật vượt thời hạn an toàn của
bn254; trả bằng gas nhỉnh hơn và mất khả năng chạy trên chain không có Prague.

```
src/
├── common/     chain-agnostic: struct, phí, chữ ký
├── metatx/     tầng NỀN — mọi token đều gasless được
├── zether/     tầng BẢO MẬT — child của metatx, không phải nhánh song song
└── chains/     cấu hình và script deploy theo từng chain
```

## Phân tầng

```
IERC20
 └── IERC20MetaTx          ← tầng nền
      ├── IERC20Payment    ← token thanh toán công khai
      └── IZetherToken     ← token bảo mật, kế thừa TOÀN BỘ meta-tx
```

Quyết định của user: *"Zether riêng, là child của MetaTransaction."* Hệ quả: mọi
Zether token tự động gọi được qua relayer, không cần đường riêng.

## Chạy

```bash
forge build                              # profile default (evm cancun)
forge test
FOUNDRY_PROFILE=private9000 forge build  # evm berlin — xem bảng dưới
```

`lib/` không commit (`.gitignore`). Dựng lại:

```bash
forge install foundry-rs/forge-std
forge install OpenZeppelin/openzeppelin-contracts   # cần v5.2+
```

## Vì sao mỗi chain một profile EVM

| Profile | EVM | Lý do |
|---|---|---|
| `private9000` | **berlin** | Chain Nethermind private chạy **trước London**. Genesis khai `londonBlock: 0`/`pragueBlock: 0` nhưng Nethermind dùng chainspec riêng và **bỏ qua key kiểu Geth trong im lặng**. Không hạ EVM version thì bytecode sinh ra có `PUSH0` (Shanghai) và chain không hiểu. Xem `TRAPS.md` §"Private chain". |
| `gnosis` | cancun | Có EIP-2537 (đã đo: `0x0b/0x0c/0x0f/0x10` sống) |
| `celo` | cancun | Như trên |

## Ba bug chặn build đã sửa so với code cũ

| Ở đâu | Lỗi | Sửa |
|---|---|---|
| `metatx/MtxTradeOrderLib.sol` | `address contract;` — `contract` là **từ khoá**. `Error 2314` | Bỏ hẳn: `verifyingContract` thuộc EIP-712 **domain**, không thuộc struct |
| `metatx/AddressCheck.sol` | `account.nonce` không tồn tại trong Solidity | Bỏ `isEOA` — nó không quyết định được gì đúng ở EVM (xem ghi chú dưới) |
| `metatx/IERC20MetaTx` (thiết kế) | `MetaTx(...)` 12 tham số vị trí, **không có `signature`** | Struct + `bytes signature` **tách riêng** |

Cùng lớp lỗi bắt được khi viết lại: `bytes32 indexed reference` trong một event —
`reference` cũng là từ khoá dành riêng. Đổi thành `entryRef`.

> **`isEOA` bị bỏ chứ không sửa.** Không có cách nào đúng để hỏi "đây có phải EOA
> không" trong EVM: `extcodesize == 0` đúng với ví chưa deploy, với địa chỉ đang
> trong constructor, và (từ EIP-7702) với EOA có code. Mọi kiểm tra dựa trên nó là
> một giả định sẽ hỏng. Cần chấp nhận cả hai loại ví thì dùng ERC-1271
> (`SigLib.requireValid` đã làm), đừng phân loại người gọi.

## Ba thay đổi thiết kế so với code cũ

1. **EIP-712 thay `personal_sign`.** Ví hiển thị nội dung thay vì 32 byte mù.
2. **`SignatureValidator.verifySignature2` bị loại** — `ecrecover` thô, không chặn
   malleability `s`. Chưa ai gọi, nhưng là súng đã lên đạn.
3. **Bỏ `mode` bitmask, dùng wildcard `relayer == address(0)`.** Bitmask đòi đổi nội
   dung digest theo mode ⇒ cross-mode replay. Wildcard giữ digest cố định.

Mẫu số phần trăm thống nhất **ppm (1e6)**, trần cứng **1% = 10.000 ppm**.
`setTransferFeePerMille` (1e3) bị loại: nó không biểu diễn được 0,05%.

## Tham chiếu

Mọi quyết định ở đây có nguồn trong
`docs/superpowers/specs/blockchain-research/_USER-DECISIONS.md` (thẩm quyền cao nhất)
và `00-CANON.md`.
