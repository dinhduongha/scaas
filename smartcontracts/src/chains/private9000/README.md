# chain 9000 — Nethermind private, Clique

Chain đích **đầu tiên** cho Zether (quyết định #5: gas không phải ràng buộc, nên
chạy private trước).

| | |
|---|---|
| chainId | 9000 (`0x2328`) |
| consensus | Clique, period 5s, **một** signer `0xdE36845C…` |
| gasLimit | `0x1000000` = 16.777.216 |
| EVM thực tế | **trước London** — xem cảnh báo dưới |
| MinGasPrice | 0 |

## Cảnh báo: genesis khai một đằng, chain chạy một nẻo

`genesis.json` khai `londonBlock: 0`, `cancunBlock: 0`, `pragueBlock: 0`. **Không
key nào có tác dụng.** Nethermind đọc chainspec riêng và bỏ qua key kiểu Geth mà
không log gì. Đo được:

| Kiểm | Kết quả |
|---|---|
| `0x0b/0x0c/0x0f/0x10` (BLS12-381, EIP-2537) | **rỗng — không tồn tại** |
| `0x06/0x07` (alt_bn128) | sống — đối chứng hợp lệ |
| `baseFeePerGas` trong header | **không có** ⇒ London chưa bật |
| `withdrawalsRoot`, `blobGasUsed` | không có ⇒ Shanghai/Cancun chưa bật |

Hai hệ quả trực tiếp:

1. **Build với `FOUNDRY_PROFILE=private9000`** (evm `berlin`). Profile default sinh
   `PUSH0` và chain không hiểu opcode đó.
2. **`bn254` là lựa chọn duy nhất chạy được ở đây** — và đó là một trong ba lý do
   D1 chốt `bn254` (xem `_USER-DECISIONS.md` §19).

Muốn bật London/Prague thì phải viết lại `params` theo key Nethermind
(`eip1559TransitionTimestamp`, `eip2537TransitionTimestamp`, …) **và reset toàn bộ
data** vì genesis hash đổi. Chưa làm, và với D1 = `bn254` thì chưa cần.

## gasLimit có đủ không

Đủ cho spike đo gas per-transaction. Một `transferConfidential` với ring = 2 nằm
dưới 16,7 M. Nếu sau này bật batch lớn hoặc ring lớn thì phải nâng — nâng gasLimit
trên Clique làm được **không cần reset** (signer vote), khác với đổi genesis.
