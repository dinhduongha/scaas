> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

## 13. Phap ly Viet Nam, CBDC, AML/KYC va Travel Rule

### 13.0. Giới hạn của chương này (đọc trước khi đọc bất cứ dòng nào bên dưới)

Kiến thức của tôi có **cutoff tháng 5/2026**. Mảng tài sản mã hoá ở Việt Nam đang chuyển động nhanh hơn bất kỳ mảng pháp lý nào khác: riêng 2025 đã có Luật Công nghiệp công nghệ số, một nghị quyết thí điểm thị trường tài sản mã hoá, một nghị định sandbox ngân hàng, và một Luật Bảo vệ dữ liệu cá nhân. Vì vậy:

- Mỗi khẳng định dưới đây gắn nhãn độ tin cậy: **[C-Cao]** = luật đã ban hành, nội dung ổn định, tôi tin số hiệu văn bản; **[C-TB]** = tôi tin bản chất quy định nhưng **không** tin số hiệu điều/khoản hoặc con số ngưỡng; **[C-Thấp]** = tôi biết vấn đề tồn tại nhưng nội dung có thể đã thay đổi hoặc tôi có thể nhầm văn bản.
- **Không có dòng nào ở đây là ý kiến pháp lý.** Trước khi mint token đầu tiên trên mainnet, hoặc trước khi ký hợp đồng có điều khoản thanh toán on-chain, cần một **thư tư vấn bằng văn bản** từ luật sư Việt Nam về đúng bộ câu hỏi ở §13.9. Chi phí một thư tư vấn nhỏ hơn chi phí một quyết định xử phạt cộng với việc phải viết lại kiến trúc token.
- Chương này **không chặn** việc build. §13.8 là ma trận những gì triển khai được ngay hôm nay bất kể luật ngã về đâu — và nó bao phủ gần như toàn bộ khối lượng kỹ thuật của các section 01–12.

#### 13.0.1. "Phải xác minh" là một câu vô nghĩa nếu không nói xác minh bằng cách nào

Bản nháp trước rải chữ *"phải xác minh"* khắp chương mà không nói ai xác minh, ở đâu, bao lâu một lần, và điều gì xảy ra khi không ai làm. Đó là hand-wave. Cơ chế cụ thể, rẻ, và chạy được trong CI:

**Một file duy nhất:** `docs/legal/vn_legal_claims.yaml` — mỗi khẳng định pháp lý trong chương này là một entry.

```yaml
- id: nd52_2024_closed_list
  claim: "ND 52/2024/ND-CP liet ke danh sach dong phuong tien thanh toan khong dung tien mat; crypto khong nam trong danh sach."
  confidence: high
  primary_source: "vbpl.vn | congbao.chinhphu.vn"
  section_refs: ["13.1", "13.8"]
  verified_on: 2026-05-01
  verified_by: null          # ho ten nguoi/hang luat da doi chieu ban goc
  recheck_after_days: 180
  blocks: ["mint_mainnet", "enable_payment_mode_1"]
```

**Một CI job:** `tools/check_legal_register.py` chạy trong pipeline `docs`, fail khi bất kỳ entry nào có `verified_on + recheck_after_days < today`, hoặc khi `verified_by` còn `null` mà `blocks` không rỗng. Kết quả: không ai có thể merge một PR bật mainnet trong khi register đang quá hạn. Đây là toàn bộ cơ chế — **không** tạo model Odoo cho việc này (một bảng để chứa ~30 dòng tài liệu là một bảng thừa).

**Nguồn sơ cấp bắt buộc dùng khi đối chiếu** (không dùng bài báo, không dùng blog): `vbpl.vn` (CSDL quốc gia về VBQPPL), `congbao.chinhphu.vn` (Công báo), `sbv.gov.vn` (NHNN), `mof.gov.vn` (BTC), `chinhphu.vn`. Một số hiệu nghị định đọc từ nguồn thứ cấp là một số hiệu chưa được xác minh.

#### 13.0.2. Những giả định ngầm mà bản nháp không nói ra

Toàn bộ phân tích pháp lý bên dưới chỉ đúng khi các giả định này đúng. Mỗi giả định sai làm đổ một phần kết luận, nên chúng phải nằm trên mặt bàn:

| # | Giả định ngầm | Hệ quả nếu sai |
|---|---|---|
| A1 | Pháp nhân vận hành deployment là **doanh nghiệp thành lập tại Việt Nam** | Nếu issuer là entity nước ngoài, §13.1/§13.4 gần như không áp dụng cho hành vi phát hành, nhưng "cung ứng/sử dụng" trên lãnh thổ VN vẫn áp dụng cho phía VN |
| A2 | Cả brand lẫn distributor đều là **người cư trú** theo Pháp lệnh Ngoại hối | Hạn chế ngoại hối chỉ ràng buộc giao dịch **giữa người cư trú**. Một bên không cư trú làm đổi hoàn toàn kết luận §13.1 về stablecoin USD |
| A3 | Chain public = dữ liệu rời khỏi lãnh thổ VN | Trên chain permissioned với **toàn bộ node đặt tại VN**, lập luận "chuyển dữ liệu xuyên biên giới" biến mất. Nhưng khi đó **sơ đồ node là một hồ sơ tuân thủ**, phải được ghi và duy trì |
| A4 | Chủ outlet là **cá nhân / hộ kinh doanh**, không phải doanh nghiệp | Đúng với ~90% kênh GT ở VN (ước tính theo thực tế ngành phân phối). Nghĩa là `owner_partner_id` trên `blockchain.account` **gần như luôn là dữ liệu cá nhân**, và phần thưởng cho họ là thu nhập cá nhân, không phải chiết khấu doanh nghiệp |
| A5 | Nhà cung cấp phần mềm (SCaaS) **không** là bên phát hành token | Nếu vendor mint hộ khách hàng, vendor bước thẳng vào chữ "cung ứng" của NĐ 88. Xem §13.3.1 |
| A6 | Deployment **không** giữ khoá hộ bên thứ ba | Ngay khi `custody_mode='custodial'` xuất hiện trên một `blockchain.account` có `role='user'`, khả năng bị coi là VASP tăng vọt. Xem §13.4 |
| A7 | Chỉ có **một** issuer trong một deployment | Nhiều issuer trên cùng registry biến registry thành hạ tầng dùng chung cho bên thứ ba — một dịch vụ, không phải một công cụ nội bộ |
| A8 | Rủi ro pháp lý = tiền phạt | Sai và nguy hiểm. Rủi ro thật nặng hơn: ngân hàng từ chối xử lý chân fiat, cơ quan thuế loại chi phí khi tính thuế TNDN, đối tác có giấy phép bị thanh tra vì hợp tác với ta, và rủi ro hình sự ở §13.1 |
| A9 | Sự kiện pháp lý đầu tiên là lúc mint token | Sai. Sự kiện đầu tiên thường là **trang marketing** viết "thanh toán bằng crypto" — hành vi "cung ứng" cấu thành trước khi có dòng code nào chạy trên mainnet |

---

### 13.1. Bản đồ văn bản: crypto có phải phương tiện thanh toán ở Việt Nam không?

Câu trả lời ngắn: **không, và điều đó chưa thay đổi sau Luật Công nghiệp công nghệ số.**

| Văn bản | Nội dung liên quan | Hệ quả cho `dms_blockchain` | Độ tin cậy |
|---|---|---|---|
| **Nghị định 52/2024/NĐ-CP** về thanh toán không dùng tiền mặt (hiệu lực 01/7/2024, thay NĐ 101/2012) | Liệt kê **danh sách đóng** các phương tiện thanh toán không dùng tiền mặt: séc, lệnh chi/uỷ nhiệm chi, nhờ thu, thẻ ngân hàng, ví điện tử, và phương tiện khác **do NHNN quy định**. Crypto không nằm trong danh sách. | Mọi token của ta đều là "phương tiện thanh toán **không hợp pháp**" nếu dùng để thanh toán. Đây là gốc rễ, không phải NĐ 88. | [C-Cao] về danh sách đóng; [C-TB] về số hiệu điều |
| **Nghị định 88/2019/NĐ-CP** (sửa bởi NĐ 143/2021) xử phạt VPHC lĩnh vực tiền tệ, ngân hàng | Phạt tiền **50–100 triệu VND** với hành vi **phát hành, cung ứng, sử dụng** phương tiện thanh toán không hợp pháp | Ba động từ, ba chủ thể khác nhau: issuer (phát hành), platform (cung ứng), merchant/outlet (sử dụng). Một kiến trúc "chúng tôi chỉ làm phần mềm" **không** né được chữ "cung ứng". | [C-Cao] về hành vi; [C-TB] về mức phạt và số điều |
| ↳ **Sửa lỗi so với bản nháp** | Mức 50–100 triệu là mức áp dụng cho **cá nhân**. Theo nguyên tắc chung của Luật Xử lý VPHC, mức phạt với **tổ chức bằng 2 lần** mức phạt với cá nhân | Con số thực tế cho một doanh nghiệp là **100–200 triệu VND cho mỗi hành vi**, cộng biện pháp khắc phục hậu quả (buộc nộp lại số lợi bất hợp pháp). Bản nháp ghi 50–100 triệu là **thiếu một nửa**. | [C-Cao] về nguyên tắc nhân đôi; [C-TB] về mức gốc |
| **Bộ luật Hình sự 2015, Điều 206** (sửa 2017) | Hành vi phát hành/cung ứng/sử dụng phương tiện thanh toán không hợp pháp **gây thiệt hại từ 100 triệu VND** trở lên có thể bị truy cứu hình sự; khung cao nhất tới 20 năm tù | Rủi ro không dừng ở hành chính, và ngưỡng 100 triệu là **rất thấp** so với quy mô một chương trình DMS. Đây là lý do end-user payment (§13.2c) phải bị khoá bằng code, không chỉ bằng tài liệu. | [C-TB] về ngưỡng và khung hình phạt |
| **Luật Công nghiệp công nghệ số 2025** (thông qua 6/2025, hiệu lực 01/01/2026) | Lần đầu định danh **"tài sản số" / "tài sản mã hoá"** là một loại tài sản theo pháp luật dân sự; giao Chính phủ quy định chi tiết. **Không** hợp pháp hoá crypto làm phương tiện thanh toán. | Sở hữu, chuyển nhượng, hạch toán token có cơ sở pháp lý. **Dùng token để trả tiền thì không.** Phân biệt này là trục chính của cả chương. | [C-Cao] về việc thông qua và về việc không hợp pháp hoá thanh toán; [C-Thấp] về số hiệu luật và số điều |
| **Nghị quyết 05/2025/NQ-CP** về thí điểm thị trường tài sản mã hoá | Cho phép thí điểm sàn giao dịch tài sản mã hoá có giấy phép, giao dịch bằng VND, yêu cầu lưu ký, vốn điều lệ rất lớn (mức tôi nhớ là hàng nghìn tỷ VND), thời hạn thí điểm 5 năm | Không áp dụng cho ta trừ khi ta muốn làm sàn. Quan trọng ở chỗ khác: nó cho thấy hướng đi của Nhà nước là **cấp phép có kiểm soát**, không phải mở tự do. | [C-TB] về nội dung; [C-Thấp] về số hiệu và các con số |
| **Nghị định 94/2025/NĐ-CP** cơ chế thử nghiệm có kiểm soát (sandbox) trong lĩnh vực ngân hàng (hiệu lực 01/7/2025) | Sandbox chỉ gồm **ba** giải pháp: chấm điểm tín dụng, chia sẻ dữ liệu qua Open API, cho vay ngang hàng | **Đây là chỗ dễ hiểu sai nhất.** Sandbox ngân hàng **không** bao gồm crypto/token thanh toán. Không thể xin vào sandbox này để hợp thức hoá Z-VND. | [C-Cao] về việc crypto ngoài phạm vi; [C-TB] về danh sách ba giải pháp |
| **Pháp lệnh Ngoại hối + NĐ 70/2014/NĐ-CP** | Nguyên tắc **hạn chế sử dụng ngoại hối trên lãnh thổ VN**: giao dịch, thanh toán, niêm yết, quảng cáo **giữa người cư trú** không được thực hiện bằng ngoại hối | **Điểm gần như luôn bị bỏ sót.** Xem §13.1.1 về việc lập luận này mạnh ở đâu và yếu ở đâu — bản nháp trước phát biểu nó chắc hơn mức nó chịu được. | [C-Cao] về nguyên tắc; xem §13.1.1 về phạm vi |
| **Luật Giao dịch điện tử 2023 (20/2023/QH15)** | Thông điệp dữ liệu có giá trị pháp lý; phân biệt chữ ký số (có CA) với chữ ký điện tử chuyên dùng | Chữ ký EIP-712 **không phải chữ ký số** theo luật VN. Nó chỉ ràng buộc nếu hai bên **thoả thuận trước bằng hợp đồng giấy** rằng chữ ký đó có giá trị. Không có điều khoản đó, một settlement on-chain không tự chứng minh được nghĩa vụ. | [C-Cao] về phân biệt; [C-TB] về điều khoản |
| **Luật Kế toán 2015** | Chứng từ kế toán phải có đủ các nội dung bắt buộc (tên, ngày, nội dung nghiệp vụ, số tiền, chữ ký) | Một **tx hash không phải chứng từ kế toán**. Bản nháp không nêu điểm này. Xem §13.7.1 để biết chứng từ thật phải trông thế nào. | [C-Cao] |
| **Luật Bảo vệ dữ liệu cá nhân 2025** | Nâng cấp NĐ 13/2023 thành luật, bổ sung chế tài tiền, trong đó có mức phạt tính theo **phần trăm doanh thu** cho một số hành vi | Nếu đúng, mức trần rủi ro dữ liệu cao hơn hẳn mức rủi ro "phương tiện thanh toán". Đây là con số **có thể làm đổi quyết định** — phải xác minh trước khi chốt chính sách dữ liệu. | [C-Thấp] về số hiệu và mức phạt; [C-TB] về việc luật đã được thông qua |

**Kết luận §13.1 (không né tránh):** dùng bất kỳ token nào — kể cả stablecoin, kể cả trên chain riêng — để **cấn trừ dứt điểm một nghĩa vụ thanh toán** giữa hai pháp nhân Việt Nam là hành vi có rủi ro xử phạt hôm nay. Ghi nhận, đối soát, bù trừ, chứng cứ thì không.

#### 13.1.1. Sửa một mâu thuẫn nội tại của bản nháp: stablecoin USD có phải "ngoại hối" không?

Bản nháp nói **hai điều không thể cùng đúng**:

- §13.1: "một stablecoin neo USD dùng để quyết toán giữa hai pháp nhân VN vi phạm quy định ngoại hối";
- §13.7.1: "stablecoin USD **không phải** ngoại tệ theo Pháp lệnh Ngoại hối, nên quy định đánh giá lại khoản mục gốc ngoại tệ không áp dụng".

Nếu nó không phải ngoại tệ thì nó không vi phạm quy định ngoại hối; nếu nó vi phạm thì nó phải được đánh giá lại. Bản nháp lấy vế thuận lợi ở cả hai chỗ. Phân giải:

1. **USDC/USDT không phải "ngoại tệ"** theo định nghĩa (đồng tiền của quốc gia khác). Nó là quyền đòi nợ đối với một tổ chức phát hành tư nhân, mệnh giá tham chiếu USD. [C-TB]
2. Nhưng lập luận cấm **không cần** nó là ngoại tệ. Hành vi bị cấm rõ ràng và độc lập là **niêm yết, quảng cáo, định giá bằng ngoại tệ** giữa người cư trú. Một hợp đồng phân phối ghi "chiết khấu 1.200 USDC" đang niêm yết theo USD dù công cụ thanh toán là gì. [C-Cao] về nguyên tắc niêm yết.
3. Đồng thời, cơ quan quản lý hoàn toàn có thể áp dụng **bản chất hơn hình thức**: một công cụ neo 1:1 vào USD, có quyền đòi lại USD, dùng để thanh toán giữa hai người cư trú — rủi ro bị xử lý như giao dịch ngoại hối là **thật, không lý thuyết**. [C-Thấp — đây chính xác là loại câu hỏi cần luật sư]

**Chốt thiết kế, an toàn dưới cả hai nhánh:** ở `compliance_profile = 'vn_conservative'`, mọi chứng từ, hợp đồng, giao diện và báo cáo **niêm yết bằng VND**; token chỉ xuất hiện như một **đơn vị đo lường kỹ thuật** kèm quy đổi VND tại `finality_datetime` (§15.4.3 đã có `fx_rate`, `fx_rate_source`, `fx_rate_datetime` — đúng chỗ để đặt ràng buộc này). Kỹ thuật: một guard trên báo cáo/portal cấm hiển thị giá chỉ bằng ký hiệu token khi profile là `vn_conservative`.

#### 13.1.2. Nguyên tắc hợp nhất: **khả năng chuyển nhượng cho bên thứ ba không liên quan** là ranh giới duy nhất

Bản nháp phân tích ba use case riêng lẻ và vì thế bỏ sót việc cả ba đều vấp cùng một ngưỡng. Viết một lần cho cả chương:

| Loại token | Khi **không** chuyển nhượng được | Khi chuyển nhượng được cho bên thứ ba |
|---|---|---|
| Điểm thưởng | Nghĩa vụ phải trả của issuer, thuộc pháp luật khuyến mại | Có giá tham chiếu → tiến gần **tiền điện tử** (§13.4) |
| Bản ghi công nợ (`tokenised_receivable`) | Sổ phụ nội bộ giữa các bên có hợp đồng | Chuyển giao quyền đòi nợ có tổ chức → chạm **công cụ chuyển nhượng / chứng khoán** [C-Thấp] |
| Đơn vị ghi sổ nội bộ (`utility_internal`) | Không phải phương tiện thanh toán | Bên thứ ba chấp nhận → đúng định nghĩa **phương tiện thanh toán** |

Vì cùng một biến quyết định cả ba, nó phải là **một field, không phải ba lập luận rời**:

```python
# dms_blockchain/models/blockchain_token.py
transfer_policy = fields.Selection([
    ('non_transferable', 'Chi mint/burn giua issuer va chu so huu'),
    ('closed_loop',      'Chuyen duoc trong allowlist do issuer kiem soat'),
    ('open',             'Chuyen tu do toi bat ky dia chi nao'),
], required=True, default='non_transferable', index=True)
```

Và nó phải được **cưỡng chế on-chain**, không chỉ trong Odoo — vì Odoo không nằm trên đường đi của một direct call: `non_transferable` ⇒ contract override `transfer`/`transferFrom` revert với `TransferDisabled()`; `closed_loop` ⇒ kiểm tra một `ITransferAllowlist` do issuer quản trị. Một field Odoo mô tả một hành vi mà contract không cưỡng chế là một field nói dối.

---

### 13.2. Ba use case, ba mức rủi ro

Trục phân loại duy nhất có ý nghĩa: **token có làm chấm dứt nghĩa vụ trả tiền hay không** (payment vs record). Trục thứ hai, ngang qua cả ba: `transfer_policy` (§13.1.2).

#### (a) Loyalty / reward points — an toàn nhất, và biết vì sao

Điểm thưởng không phải phương tiện thanh toán khi thoả **đồng thời** các điều kiện sau. Đây là danh sách thiết kế, không phải danh sách mong muốn:

| Điều kiện | Ràng buộc kỹ thuật tương ứng |
|---|---|
| Đơn vị là "điểm", **không** neo VND, không niêm yết tỷ giá điểm↔VND ra công khai | `blockchain.token.token_legal_class = 'loyalty_point'`; contract **không** có oracle giá; UI cấm hiển thị "1.000 điểm = 1.000đ" |
| Không quy đổi ra tiền mặt, không rút về tài khoản ngân hàng | Zether/ERC-20 contract của loyalty token **không deploy hàm `withdraw` về fiat**; chỉ `redeem(orderRef)` |
| Chỉ đổi lấy hàng hoá/dịch vụ **của chính issuer** hoặc trong mạng lưới do issuer chi trả | Allowlist merchant on-chain, hoặc redeem chỉ qua contract của issuer |
| Không có thị trường thứ cấp | `transfer_policy = 'non_transferable'` **và** contract revert trên `transfer`/`transferFrom`. Với Zether: `transferConfidential` bị chặn ngay trong token contract, không chỉ bằng policy ở registry |
| Có hạn sử dụng, có trần phát hành, có điều kiện công bố | Chương trình khuyến mại theo **NĐ 81/2018/NĐ-CP**: thông báo tới Sở Công Thương (hoặc **đăng ký** với Bộ Công Thương nếu là chương trình mang tính may rủi), hạn mức giá trị khuyến mại thông thường 50% (100% trong chương trình khuyến mại tập trung), tổng giá trị hàng khuyến mại trong năm không quá 50% doanh thu [C-TB] |

**Bản nháp chọn sai đầu thuế.** Nó viết: "thu nhập từ trúng thưởng trên 10 triệu VND chịu TNCN 10%". Ba sai:

1. Thuế suất 10% áp lên **phần vượt trên 10 triệu VND cho mỗi lần trúng thưởng**, không phải trên toàn bộ số tiền. [C-TB]
2. Đầu thuế "trúng thưởng" chỉ đúng với chương trình **mang tính may rủi**. Một chương trình tích điểm **xác định** (mua bao nhiêu được bấy nhiêu điểm) không phải trúng thưởng.
3. Với chủ outlet là **hộ kinh doanh** (giả định A4), một khoản thưởng xác định theo doanh số về bản chất là **chiết khấu thương mại / hỗ trợ bán hàng**, và nó rơi vào doanh thu của hộ kinh doanh, chịu thuế theo phương pháp khoán/kê khai của họ, đồng thời bên chi trả có nghĩa vụ **khấu trừ** trong một số trường hợp chi trả cho cá nhân kinh doanh. [C-TB]

Hệ quả kiến trúc, không phải hệ quả văn bản: `blockchain.settlement.use_case = 'loyalty'` **không đủ** để quyết định xử lý thuế. Cần một field phân loại chương trình ở tầng nghiệp vụ (bridge DMS, không phải core):

```python
# dms_blockchain_bridge — vi day la khai niem cua chuong trinh khuyen mai, khong phai cua chain
reward_tax_head = fields.Selection([
    ('chance_prize',   'Trung thuong may rui (TNCN 10% phan vuot 10 trieu/lan)'),
    ('trade_discount', 'Chiet khau thuong mai / ho tro ban hang'),
    ('gift_in_kind',   'Hang hoa khuyen mai (hoa don gia tinh thue 0)'),
], required=True)
```

**Cái bẫy VAT mà bản nháp bỏ hẳn, và nó tốn tiền thật:** hàng hoá dùng để khuyến mại **vẫn phải xuất hoá đơn** theo NĐ 123/2020, và chỉ được ghi giá tính thuế GTGT bằng 0 khi chương trình khuyến mại **được thực hiện theo đúng quy định pháp luật thương mại** — tức là đã thông báo/đăng ký. Nếu không thông báo, cơ quan thuế có căn cứ ấn định GTGT trên **giá bán của hàng hoá tương đương**. [C-TB]

Định lượng để thấy quy mô: một chương trình đổi 200.000 điểm/tháng, giá trị bình quân 20.000 VND/điểm-đổi ⇒ 4 tỷ VND/tháng hàng khuyến mại. GTGT 10% trên phần bị ấn định = **400 triệu VND/tháng** — lớn hơn một bậc so với mức phạt VPHC ở §13.1. Việc "quên nộp một thông báo cho Sở Công Thương" là rủi ro tài chính lớn nhất trong toàn bộ use case loyalty, không phải rủi ro NĐ 88.

#### (b) B2B settlement (brand ↔ distributor) — trung bình, và có một cách làm sạch

Hai mô hình, khác nhau về pháp lý chứ không phải về code:

1. **Token là *bản ghi* nghĩa vụ (khuyến nghị).** Chain giữ sổ công nợ ròng giữa các bên; chấm dứt nghĩa vụ vẫn bằng chuyển khoản ngân hàng / VietQR. Cơ sở pháp lý: **bù trừ nghĩa vụ, Bộ luật Dân sự 2015 Điều 378** [C-TB] — hoàn toàn hợp pháp, đã dùng hàng ngày trong ngành phân phối. Zether ở đây có giá trị thật: brand không muốn distributor A nhìn thấy chiết khấu của distributor B, mà vẫn cần đồ thị công nợ minh bạch với kiểm toán.
2. **Token *chấm dứt* nghĩa vụ.** Rơi thẳng vào §13.1. Nếu token neo USD thì cộng thêm rủi ro ngoại hối ở §13.1.1. Không khuyến nghị trong nước.

**Sửa một ánh xạ sai trong bản nháp.** Bản nháp viết mô hình (1) là *"payment integration mode 4 (sub-ledger) và mode 2 (chain là lớp đối soát) ở §10.8"*. Sai ở hai chỗ: (i) danh sách chế độ đầy đủ nằm ở **§09.2 (M1–M13)**, còn §10.8 chỉ có 5 chế độ cấu hình rút gọn (1–5); (ii) trong **cả hai** hệ đánh số, "mode 2" là **acquirer crypto bên ngoài**, không phải "chain là lớp đối soát". Ánh xạ đúng:

| Mô hình pháp lý | Chế độ §09.2 | Chế độ §10.8 |
|---|---|---|
| Chain chỉ là bằng chứng, tiền đi hoàn toàn đường fiat | **M12** (anchor-only) | mode 4 |
| Sổ phụ token + quyết toán ròng bằng ngân hàng theo kỳ | **M4**, và **M13** nếu bảo mật số tiền | mode 4 |
| Bút toán từng giao dịch B2B khi đã có `account` | **M3** | mode 3 |
| Giao cho một đơn vị có giấy phép đứng ra nhận tiền | **M2** | mode 2 |

Điểm phải nói với khách hàng bằng chữ: mô hình (1) **không** giảm số lệnh chuyển khoản về 0; nó giảm về **một lệnh ròng mỗi kỳ**. Với 200 distributor, 4 giao dịch/tháng/distributor: từ 800 lệnh xuống 200 lệnh/tháng nếu netting theo cặp, hoặc xuống ~200 lệnh nếu netting song phương theo kỳ — con số thật phụ thuộc chiều dòng tiền, và nó **không bao giờ là 0**. Nếu bán hàng bằng câu "không cần ngân hàng nữa" thì đó là bán sai sản phẩm và tạo kỳ vọng dẫn tới mô hình (2).

Một điều bản nháp không nói: **hợp đồng phải có điều khoản, và điều khoản đó phải tồn tại trước giao dịch đầu tiên.** Câu chữ tối thiểu, để đây cho luật sư sửa chứ không phải để dùng nguyên:

> *"Sổ ghi nhận điện tử (bao gồm bản ghi trên sổ cái phân tán do Bên A vận hành) được hai Bên thống nhất là chứng cứ về số dư công nợ tại từng thời điểm. Bản ghi này **không** làm phát sinh, thay thế hoặc chấm dứt nghĩa vụ thanh toán. Nghĩa vụ thanh toán chỉ chấm dứt khi (i) tiền được ghi có vào tài khoản ngân hàng của bên có quyền, hoặc (ii) hai Bên ký biên bản bù trừ công nợ theo Điều 378 Bộ luật Dân sự. Hai Bên công nhận giá trị của chữ ký điện tử chuyên dùng theo Luật Giao dịch điện tử 2023 đối với các thông điệp dữ liệu được ký bằng khoá do hệ thống cấp, theo quy trình mô tả tại Phụ lục [X]."*

Không có đoạn thứ hai, chữ ký EIP-712 không chứng minh được gì trước toà. Không có đoạn cuối, hai bên không cùng cách hiểu về thời điểm chấm dứt nghĩa vụ, và toàn bộ giá trị đối soát biến mất đúng lúc cần nhất.

#### (c) End-user payment — rủi ro cao nhất, phải khoá bằng code

Người tiêu dùng quét mã, trả bằng token, outlet giao hàng: đây là **phát hành + cung ứng + sử dụng** đủ cả ba động từ của NĐ 88. Thêm một lớp nữa: đứng giữa người trả và người nhận để chuyển giá trị là hoạt động **trung gian thanh toán**, cần giấy phép NHNN (§13.4).

Chỉ có hai đường đi được:
- **Chain là lớp đối soát, fiat là lớp thanh toán** (M12, hoặc M1 với chain chỉ ghi reference): người dùng trả bằng VietQR/thẻ; chain ghi nhận, tính điểm, tính chiết khấu, chống gian lận. Không có token nào đổi chủ để trả tiền. Triển khai được **hôm nay**.
- **Pháp nhân nước ngoài, người dùng nước ngoài**: đây là quyết định về cấu trúc doanh nghiệp và thuế, **không** phải quyết định kiến trúc phần mềm. Kiến trúc đã sẵn sàng (chain profile + compliance profile); phần còn lại nằm ngoài repo này.

**Khoá bằng code nghĩa là gì, cụ thể.** Không phải một cảnh báo trong UI. Ba chốt, ở ba tầng khác nhau, vì một chốt duy nhất sẽ bị ai đó tắt:

```python
# 1. Core: chan tao settlement 'payment' voi token co the chuyen gia tri, o profile VN.
@api.constrains('use_case', 'token_id', 'settle_state')
def _check_enduser_payment_allowed(self):
    profile = self.env['ir.config_parameter'].sudo().get_param(
        'blockchain.compliance_profile', 'vn_conservative')
    if profile != 'vn_conservative':
        return
    for rec in self:
        if rec.use_case == 'payment' and rec.token_id.token_legal_class != 'test':
            raise ValidationError(_(
                'Compliance profile vn_conservative: settlement use_case=payment chi duoc '
                'dung voi token_legal_class=test. Dung M12 (anchor-only) cho luong tien that.'))
```

```
# 2. Payment bridge: dms_blockchain_payment khong tao payment.provider record enabled
#    khi profile = vn_conservative (§10.10 muc 5 da co co che, day la mot ly do nua).
# 3. Contract: loyalty/receivable token khong co ham nao chuyen gia tri cho mot dia chi
#    khong nam trong allowlist cua issuer (transfer_policy, §13.1.2).
```

---

### 13.3. Một mâu thuẫn trực tiếp với `blockchain.md` cần sửa

`blockchain.md` §TOKEN viết: *"Mint/burn từ 1 hoặc 1 group ERC20 theo 1 tỉ lệ nào đó. Ví dụ 1 USDT (DAI) → 25000 Z-VND"*.

Về bản chất pháp lý Việt Nam, cấu trúc này là **hai vi phạm chồng lên nhau**, không phải một:

1. **Z-VND neo VND, được pre-fund, có thể đổi lại, được bên thứ ba chấp nhận** → đúng định nghĩa **tiền điện tử** theo NĐ 52/2024 (giá trị tiền VND lưu trữ trên phương tiện điện tử, đối ứng với số tiền trả trước). Tiền điện tử chỉ được phát hành dưới hình thức **ví điện tử và thẻ trả trước**, bởi **ngân hàng hoặc tổ chức được cấp phép trung gian thanh toán** [C-Cao về nguyên tắc, C-TB về câu chữ]. Một addon Odoo mint Z-VND không phải một trong hai chủ thể đó.
2. **1 DAI → 25.000 Z-VND là một nghiệp vụ chuyển đổi ngoại hối.** Mua bán ngoại tệ tại tổ chức không được phép là một vi phạm **riêng biệt** theo NĐ 88 [C-TB]. Lưu ý sắc thái ở §13.1.1: lập luận này mạnh khi có **niêm yết tỷ giá**, và tỷ lệ "1 DAI = 25.000 Z-VND" chính là một tỷ giá được niêm yết.

**Chốt thiết kế:** giữ nguyên `TokenFactory` và cơ chế wrap/peg ở section 01 — nó đúng về kỹ thuật và cần cho thị trường ngoài VN. Nhưng thêm **một trường và một constraint** để cái sai không thể xảy ra do vô ý:

```python
# dms_blockchain/models/blockchain_token.py
token_legal_class = fields.Selection([
    ('test',                 'Testnet / khong mang gia tri'),
    ('utility_internal',     'Don vi ghi so noi bo, khong quy doi tien'),
    ('loyalty_point',        'Diem thuong (khong quy doi tien mat)'),
    ('tokenised_receivable', 'Ban ghi cong no / nghia vu, khong cham dut nghia vu'),
    ('stablecoin_fx',        'Stablecoin neo tien phap dinh'),
    ('cbdc',                 'CBDC / tien gui token hoa do to chuc duoc cap phep phat hanh'),
], required=True, default='test', index=True)

ALLOWED_LEGAL_CLASS = {
    'vn_conservative': {'test', 'utility_internal', 'loyalty_point', 'tokenised_receivable'},
    'vn_pilot':        {'test', 'utility_internal', 'loyalty_point', 'tokenised_receivable', 'cbdc'},
    'offshore':        {'test', 'utility_internal', 'loyalty_point', 'tokenised_receivable',
                        'stablecoin_fx', 'cbdc'},
}

@api.constrains('token_legal_class', 'deploy_state', 'transfer_policy')
def _check_legal_class_allowed(self):
    profile = self.env['ir.config_parameter'].sudo().get_param(
        'blockchain.compliance_profile', 'vn_conservative')
    allowed = ALLOWED_LEGAL_CLASS.get(profile, set())
    for rec in self:
        if rec.deploy_state != 'deployed':
            continue
        if rec.token_legal_class not in allowed:
            raise ValidationError(_(
                'Token legal class "%(cls)s" khong duoc phep duoi compliance profile "%(p)s".',
                cls=rec.token_legal_class, p=profile))
        if (profile == 'vn_conservative'
                and rec.token_legal_class in ('loyalty_point', 'tokenised_receivable')
                and rec.transfer_policy == 'open'):
            raise ValidationError(_(
                'transfer_policy=open bien token nay thanh phuong tien thanh toan tren thuc te '
                '(§13.1.2). Khong duoc phep o profile vn_conservative.'))
```

**Ba lỗi trong đoạn code của bản nháp, đã sửa ở trên:**

1. Nó dùng `rec.state`. Field trạng thái của `blockchain.token` theo §10.4.4 là **`deploy_state`**, không phải `state` — `state` đã bị đổi tên chính vì lý do đó. Constraint cũ sẽ raise `AttributeError` ngay lần chạy đầu.
2. Nó bỏ sót `transfer_policy`. Một `loyalty_point` với `transfer_policy='open'` là một phương tiện thanh toán mang tên khác; `token_legal_class` một mình không chặn được.
3. **Lỗi nặng nhất và im lặng:** `@api.constrains` **chỉ chạy khi record bị ghi**. Đổi `blockchain.compliance_profile` từ `offshore` về `vn_conservative` **không** làm constraint chạy lại — mọi token `stablecoin_fx` đang deployed vẫn nằm nguyên đó, và hệ thống báo "tuân thủ". Phải chặn ở chiều còn lại:

```python
# dms_blockchain/models/res_config_settings.py
def set_values(self):
    super().set_values()
    new = self.blockchain_compliance_profile
    bad = self.env['blockchain.token'].sudo().search([
        ('deploy_state', '=', 'deployed'),
        ('token_legal_class', 'not in', list(ALLOWED_LEGAL_CLASS.get(new, set()))),
    ])
    if bad:
        raise UserError(_(
            'Khong the chuyen sang profile "%(p)s": dang co %(n)s token deployed khong hop le '
            '(%(names)s). Phai retire cac token nay truoc.',
            p=new, n=len(bad), names=', '.join(bad.mapped('name')[:5])))
```

Không tạo model `blockchain.jurisdiction.profile`. Một Selection ba giá trị trong `ir.config_parameter` là đủ; một bảng để chứa ba dòng là một bảng thừa (cùng lý do §10.12 loại bỏ `blockchain.chain.profile` như một model).

Mặc định là `vn_conservative`. Đổi profile là một hành vi có chủ ý, ghi log, và phải kèm thư tư vấn.

#### 13.3.1. Ai là "cung ứng"? Ranh giới trách nhiệm vendor / deployer

Bản nháp nêu đúng rằng *"chúng tôi chỉ làm phần mềm"* không né được chữ "cung ứng", rồi dừng lại. Đó là chỗ hand-wave đắt nhất trong chương, vì nó là rủi ro của **chính đơn vị viết repo này**, không phải của khách hàng.

Phân tích thẳng: "cung ứng phương tiện thanh toán" mô tả hành vi **đưa phương tiện đó vào lưu thông**, không phải hành vi viết trình biên dịch. Một addon Odoo mã nguồn có sẵn, cài đặt ở trạng thái không có chain nào `enabled` (§10.10), không mint token nào, không cấu hình RPC nào, thì gần với "công cụ" hơn "phương tiện". Nhưng khoảng cách đó bị thu hẹp bởi mọi thứ vendor làm thêm: vận hành relayer hộ khách, giữ khoá hộ khách, mint hộ khách, viết marketing nói "thanh toán bằng token". [C-Thấp — đây là câu hỏi định tính, cần luật sư]

**Bốn biện pháp cụ thể, rẻ, làm được ngay** (và ba trong bốn đã có sẵn trong kiến trúc, chỉ cần nói rõ chúng cũng phục vụ mục đích pháp lý):

| Biện pháp | Trạng thái | Chi tiết |
|---|---|---|
| Cài đặt mặc định là vô hại | **đã có** — §10.10 | Không chain `enabled`, cron `active=False`, provider `state='disabled'` |
| Profile mặc định `vn_conservative` | **đã có** — §13.3 | Không thể deploy `stablecoin_fx` nếu không chủ động đổi |
| Vendor không giữ khoá của khách | **đã có** — §07 | `signer_ref` trỏ tới KMS/HSM **của khách hàng**, không của vendor |
| Bản ghi khách hàng tự chịu trách nhiệm khi đổi profile | **cần thêm** | Xem dưới |

Cái thứ tư, tối thiểu và không tạo bảng mới: khi `set_values()` chuyển profile khỏi `vn_conservative`, ghi một message vào `mail.thread` của `res.company` với nội dung, người thực hiện, thời điểm, và một checkbox xác nhận đã có ý kiến pháp lý. Đó là bằng chứng rằng quyết định là của khách hàng. Một dòng log không cứu được ai trước toà, nhưng nó dịch chuyển câu chuyện từ "phần mềm tự làm" sang "người dùng đã chủ động bật", và đó là toàn bộ điều nó cần làm.

---

### 13.4. Tiền điện tử, VASP và giấy phép trung gian thanh toán

#### 13.4.1. Sáu câu hỏi, không phải bốn

Bản nháp có bài test bốn câu. Thiếu hai câu quan trọng nhất:

1. Có neo mệnh giá VND (hoặc một đồng fiat) không?
2. Có được pre-fund 1:1 bằng tiền thật không?
3. Người giữ có **quyền đòi lại tiền mặt** không?
4. Bên thứ ba (không phải issuer) có chấp nhận nó để giao hàng không?
5. **Nó có chuyển được giữa hai người dùng cuối mà không đi qua issuer không?** (`transfer_policy`)
6. **Có ai bán nó lấy VND ở bất kỳ đâu, kể cả chợ đen, kể cả ngoài ý muốn của issuer không?** (một giá tham chiếu tồn tại là một sự thật, không phải một chính sách)

**Bốn "có" trở lên = tiền điện tử trên thực chất = cần giấy phép**, bất kể nó chạy trên chain nào và tên gọi là gì. Câu 5 và 6 quan trọng vì chúng là hai câu duy nhất **không** do issuer kiểm soát bằng tài liệu — chỉ kiểm soát được bằng contract.

#### 13.4.2. VASP: một field quyết định, và nó là `custody_mode`

Bản nháp nhắc "VASP" nhiều lần nhưng không đưa ra bài test. Theo định nghĩa FATF, một VASP là bên **thay mặt người khác** thực hiện: (i) đổi tài sản ảo ↔ fiat, (ii) đổi tài sản ảo ↔ tài sản ảo, (iii) chuyển tài sản ảo, (iv) **giữ hộ hoặc quản lý công cụ kiểm soát tài sản ảo**, (v) cung ứng dịch vụ tài chính liên quan phát hành/bán. [C-Cao về nội dung khuyến nghị FATF; C-Thấp về việc VN đã nội luật hoá tới đâu]

Ánh xạ vào chính data model của addon — đây là điều làm cho phân tích này hữu dụng thay vì chỉ đúng:

| Cấu hình trong `dms_blockchain` | Khả năng bị coi là VASP |
|---|---|
| `blockchain.account.role='treasury'`, `custody_mode='hsm'`, chỉ giữ tài sản của chính mình | Thấp — tự giữ tài sản của mình không phải dịch vụ |
| `role='relay'` — relayer ứng gas, không chạm tài sản người dùng | Thấp; nhưng xem §13.4.4 về thuế |
| `role='user'`, `custody_mode='non_custodial'` / `'smart_account'` | Thấp — người dùng tự giữ khoá |
| **`role='user'`, `custody_mode='custodial'`** | **Cao — đây chính là mục (iv) của FATF.** Deployment đang giữ hộ công cụ kiểm soát tài sản của bên thứ ba |
| Bất kỳ luồng nào đổi token ↔ VND | **Cao — mục (i)** |

**Chốt thiết kế:** thêm một constraint, không thêm một model:

```python
@api.constrains('role', 'custody_mode', 'state')
def _check_custodial_allowed(self):
    profile = self.env['ir.config_parameter'].sudo().get_param(
        'blockchain.compliance_profile', 'vn_conservative')
    for rec in self:
        if (profile == 'vn_conservative' and rec.state == 'active'
                and rec.role == 'user' and rec.custody_mode == 'custodial'):
            raise ValidationError(_(
                'Giu ho khoa cho nguoi dung cuoi (custody_mode=custodial tren role=user) co kha '
                'nang cau thanh hoat dong VASP. Khong duoc phep o profile vn_conservative. '
                'Dung non_custodial hoac smart_account.'))
```

Custody vẫn **pluggable đủ cả 6 mô hình** như decision đã khoá — constraint này chỉ chặn đúng một tổ hợp (custodial × end-user × VN profile), không chặn HSM/MPC/enclave/custodial cho ví treasury của chính doanh nghiệp.

#### 13.4.3. Giấy phép: những con số làm đổi quyết định

Giấy phép cung ứng dịch vụ trung gian thanh toán (NĐ 52/2024 + Thông tư hướng dẫn của NHNN): các dịch vụ gồm cổng thanh toán điện tử, hỗ trợ thu hộ/chi hộ, ví điện tử, chuyển tiền điện tử.

| Chỉ tiêu | Giá trị | Nguồn / độ tin cậy |
|---|---|---|
| Vốn điều lệ tối thiểu | **50 tỷ VND** | [C-TB] |
| Thời gian thực tế từ hồ sơ tới giấy phép | **12–24 tháng** (ước tính, cơ sở: kinh nghiệm thị trường; thời hạn luật định ngắn hơn nhiều nhưng vòng bổ sung hồ sơ mới là biến số) | ước tính |
| Yêu cầu khác | Nhân sự có bằng cấp/kinh nghiệm, hệ thống kỹ thuật đạt yêu cầu, phương án kinh doanh, phương án đảm bảo an toàn | [C-TB] |
| Vốn điều lệ cho sàn tài sản mã hoá theo khung thí điểm | Hàng nghìn tỷ VND | [C-Thấp] |
| Chi phí + thời gian một thư tư vấn pháp lý có phạm vi (3–5 câu hỏi §13.9) | **80–400 triệu VND, 3–6 tuần** (ước tính, cơ sở: 15–40 giờ luật sư ở mức 250–500 USD/giờ tại hãng luật hàng đầu VN) | ước tính |

Kết luận thực dụng, và con số ở trên là lý do: **hợp tác với một đơn vị đã có giấy phép luôn nhanh hơn tự xin** — 2 person-week tích hợp (M2, §09.2) so với 12–24 tháng và 50 tỷ vốn. Điều đó ánh xạ thẳng vào **M2 / mode 2** — chế độ đó tồn tại chính vì lý do pháp lý này, không phải vì lý do kỹ thuật.

#### 13.4.4. Vấn đề không ai nêu: **lấy đâu ra native gas một cách hợp pháp?**

Đây là lỗ hổng lớn nhất của bản nháp, và nó chặn deployment public chain trước cả câu hỏi về token.

Để chạy một relayer trên Gnosis, ví relayer phải có xDAI. Để chạy trên Celo, phải có CELO hoặc cUSD. Mua xDAI bằng VND là **mua tài sản mã hoá bằng tiền đồng** — và tính tới cutoff, ở Việt Nam **không có tổ chức nào được cấp phép cung ứng dịch vụ đó**. Doanh nghiệp không có một đường mua hợp pháp, không có hoá đơn đầu vào, và không có chứng từ để hạch toán chi phí gas.

Hệ quả, xếp theo mức độ nghiêm trọng:

1. **Chi phí gas không có hoá đơn hợp lệ ⇒ không được trừ khi tính thuế TNDN.** Với thuế suất 20%, mỗi 100 triệu VND phí gas không chứng từ là 20 triệu VND thuế phải nộp thêm. [C-Cao về nguyên tắc chứng từ]
2. Việc mua bản thân nó có thể là một vi phạm riêng biệt (§13.1).
3. Nếu mua qua một cá nhân/sàn nước ngoài bằng thẻ tín dụng doanh nghiệp, phát sinh thêm câu hỏi về chuyển tiền ra nước ngoài và mục đích thanh toán.

**Ba lối ra, và chỉ ba:**

| Lối ra | Cơ chế | Đánh giá |
|---|---|---|
| **Chain permissioned, gas = 0** | `chain_profile='private'`, `fee_mode='gasless'` (§08, §10.4.2). Không có native coin để mua, không có thị trường phí, không có giao dịch nào phải hạch toán | **Đây là lối ra sạch nhất**, và nó là một lý do độc lập — ngoài lý do chi phí Zether — để quyết định #5 (private chain trước) là đúng |
| Entity nước ngoài mua gas và vận hành relayer | Entity VN chỉ ký meta-tx, entity nước ngoài trả gas. Phát sinh giao dịch liên kết, chuyển giá, và phí dịch vụ giữa hai bên | Khả thi nhưng là một quyết định về cấu trúc tập đoàn, không phải về kiến trúc |
| Đối tác có giấy phép ứng gas như một dịch vụ, xuất hoá đơn dịch vụ bằng VND | Ta mua "dịch vụ tiếp vận giao dịch", không mua crypto | Sạch về chứng từ; phụ thuộc có tìm được đối tác |

**Điều này phải được ghi vào §13.8 như một dòng riêng**, vì nó biến "chạy trên Gnosis mainnet" từ XANH thành ĐỎ ở profile VN, độc lập với việc token là gì.

#### 13.4.5. Phí trả cho Open Relayer nước ngoài: thuế nhà thầu và hoá đơn

Hệ quả thứ hai của mô hình Open Relayer, cũng chưa từng được nêu. Khi một relayer ẩn danh trên mempool nhận `metaTx.fee` từ hợp đồng của ta:

- Nếu relayer là **tổ chức/cá nhân nước ngoài có thu nhập phát sinh tại VN**, khoản phí đó thuộc diện **thuế nhà thầu (FCT)**: bên VN có nghĩa vụ khấu trừ và nộp thay (thông thường 5% GTGT + 5% TNDN cho dịch vụ, tổng khoảng 10%). [C-TB về thuế suất]
- Ta **không biết relayer là ai**. Đó là toàn bộ điểm của một open relayer network. Không biết ai thì không khấu trừ được, không kê khai được, không có hoá đơn.
- Không có hoá đơn ⇒ phí relayer không được trừ khi tính TNDN (lại 20%).

**Đây là một xung đột cấu trúc, không phải một thiếu sót thủ tục:** một thị trường relayer thực sự mở là **không tương thích** với nghĩa vụ khấu trừ thuế của bên chi trả tại Việt Nam.

Cách giải, và nó có sẵn trong chính thiết kế EIP-1776 ở §04 — biến `mode`:

```
Profile vn_conservative  ⇒ moi MetaTransaction bat buoc mode >= MODE_RESTRICT_RELAYER (0x01),
                           relayer nam trong blockchain.relayer voi allowlist_state='approved',
                           moi relayer approved phai co mot hop dong dich vu va mot partner_id.
Profile offshore         ⇒ MODE_OPEN (0x00) duoc phep, open relayer market chay dung thiet ke.
```

Nói cách khác: **Open Relayer Network là một tính năng của profile `offshore`, không phải của mọi deployment.** Ở VN nó suy biến thành một relayer pool có hợp đồng — vẫn dùng đúng chuẩn EIP-1776, đúng struct, đúng 2D nonce, chỉ khác một bit trong `mode`. Đó là một ràng buộc thật lên §04 và §05, và nó nên được ghi ở đó chứ không chỉ ở đây.

Định lượng để biết có đáng quan tâm không: phí relayer trên Gnosis ở mức ~$0.0002/tx (§05). Với 1,8 triệu giao dịch/năm (§15.4.4) đó là ~$360/năm ≈ 9 triệu VND. **Số tiền không đáng kể; nghĩa vụ kê khai thì không phụ thuộc số tiền.** Rủi ro ở đây là rủi ro thủ tục và uy tín khi thanh tra, không phải rủi ro tài chính.

---

### 13.5. CBDC: Việt Nam chưa có, vậy "tích hợp CBDC" nghĩa là gì?

Sự thật cần nói thẳng: **Việt Nam không có CBDC bán lẻ, và tính đến cutoff cũng chưa công bố pilot** [C-Cao]. NHNN có nhiệm vụ nghiên cứu tiền kỹ thuật số theo các đề án thanh toán không dùng tiền mặt [C-TB]. Mọi tuyên bố "CBDC-ready" trước khi NHNN công bố spec là **không kiểm chứng được** và không nên xuất hiện trong tài liệu bán hàng.

Ba hình thái khả dĩ, và cái ta phải chuẩn bị cho từng cái:

| Hình thái | Vai trò của ta | Cần gì từ kiến trúc | Đã có chưa? |
|---|---|---|---|
| **Wholesale CBDC / tiền gửi token hoá** trên chain permissioned do NHNN hoặc consortium ngân hàng vận hành | **Participant node + adapter**, không phải issuer | Chain adapter cho stack chưa biết; `blockchain.chain` với `chain_profile='private'`, `fee_mode='gasless'`; Finality Gate đọc BFT instant finality | **Có** — chính là trục chain profile (locked #5) và §08 |
| **Cross-border wholesale** kiểu mBridge | Không liên quan tới một hệ DMS | — | Ngoài phạm vi |
| **Retail e-VND** | Token là **đồng tiền pháp định** → toàn bộ vấn đề "phương tiện thanh toán" biến mất *cho riêng token đó* | `token_legal_class='cbdc'`; **bắt buộc** viewing key auditor; không được ẩn số tiền với NHTW | **Có** — `C_audit` ở §2.7.6 |

#### 13.5.1. "Cần gì từ kiến trúc" — cụ thể hoá, vì bản nháp dừng ở mức tên gọi

Nếu một wholesale pilot xuất hiện, xác suất cao stack là một trong ba: **Hyperledger Besu (QBFT/IBFT2)**, **Hyperledger Fabric**, hoặc **R3 Corda** — đó là ba nền được các NHTW dùng nhiều nhất trong các pilot công bố tới cutoff [C-TB]. Ba nền này khác nhau ở đúng những chỗ làm gãy giả định của một adapter viết cho EVM public:

| Giả định của adapter EVM public | Besu QBFT | Fabric | Corda |
|---|---|---|---|
| Có mempool công khai | **Không** — tx đi thẳng tới validator qua RPC có xác thực | Không (endorsement → ordering) | Không (point-to-point) |
| Có thị trường phí, `gasPrice` có nghĩa | **Không** — gas price 0 | Không có gas | Không có gas |
| Finality theo độ sâu block | **Không** — instant finality ngay khi block được commit | Instant | Notary-based |
| Tx nhìn thấy được bởi mọi node | Có | **Không** — private data collections | **Không** — chỉ các bên liên quan |
| Địa chỉ là `0x` + 20 byte | Có | Không (MSP identity, x509) | Không (`Party` + x500 name) |

Hệ quả cứng lên `blockchain.chain` và Finality Gate, và đây là ba đường may duy nhất cần giữ:

```python
# 1. finality_hard_blocks = 1 va finality_hard_seconds = 0 phai la mot cau hinh HOP LE,
#    khong phai mot gia tri "chua cau hinh". §11 phai phan biet 0 (instant final) voi None.
# 2. Adapter interface KHONG duoc co gas_price(), estimate_gas(), mempool_peek() o tang base.
#    Chung thuoc mot mixin cua chain_family='evm_public', khong thuoc BaseChainAdapter.
# 3. blockchain.account.address size=42 va CHECK '^0x[0-9a-f]{40}$' (§10.4.3) SE GAY
#    voi Fabric/Corda. Truoc khi lam adapter phi-EVM dau tien phai noi long constraint nay
#    theo chain_family, hoac them mot cot address_kind. Ghi lai o day de khong ai quen.
```

Điểm (3) là một phát hiện thật: constraint hiện tại của §10.4.3 **hard-code giả định EVM** vào một model được quảng cáo là đa chuỗi. Nó không sai hôm nay (Gnosis, Celo đều EVM), nhưng nó là nợ kỹ thuật phải trả trước adapter phi-EVM đầu tiên — HBAR, TON, SUI, Soroban, CosmWasm đều không dùng địa chỉ 20 byte hex.

**Yêu cầu vận hành cho một participant node**, nếu pilot xảy ra: node đặt tại Việt Nam (gần như chắc chắn là điều kiện tham gia), kết nối mTLS với CA của mạng, khoá ký của participant nằm trong HSM của **ngân hàng tham gia**, không phải của ta; nhật ký node lưu theo yêu cầu của cơ quan vận hành. Không có mục nào trong danh sách đó cần code mới trong `dms_blockchain` — chúng là yêu cầu hạ tầng.

Việc cần làm bây giờ: **không build gì cho CBDC.** Chỉ giữ ba đường may để tích hợp sau này là một thay đổi cấu hình chứ không phải một cuộc viết lại: (1) `token_legal_class` có sẵn giá trị `cbdc`; (2) cờ *bắt buộc auditor* ở cấp token, không phải cấp deployment; (3) interface adapter **không giả định** có mempool mở hoặc có thị trường phí. Điểm (3) là ràng buộc thật lên §08 và §05, và §13.4.5 vừa cho nó một lý do thứ hai hoàn toàn độc lập với CBDC.

---

### 13.6. AML/KYC, FATF Travel Rule, và chỗ Zether thật sự giúp (và chỗ không)

#### 13.6.1. Nghĩa vụ theo luật Việt Nam

**Luật Phòng, chống rửa tiền 2022 (14/2022/QH15)** + NĐ 19/2023/NĐ-CP + Thông tư hướng dẫn của NHNN [C-Cao về sự tồn tại; C-TB về chi tiết]. Đối tượng báo cáo là tổ chức tài chính và một số ngành nghề phi tài chính; **VASP chưa được liệt kê rõ ràng ở thời điểm luật ban hành**, nhưng khung thí điểm đang đưa sàn vào diện đối tượng báo cáo [C-Thấp — phải xác minh]. Việt Nam nằm trong danh sách giám sát tăng cường của FATF từ 6/2023 với một action plan; tình trạng hiện tại **phải kiểm tra lại tại nguồn FATF (fatf-gafi.org), không qua báo chí** [C-Thấp].

Nếu rơi vào diện đối tượng báo cáo, nghĩa vụ tối thiểu và các ngưỡng — bản nháp để hầu hết ở [C-Thấp] mà không nêu văn bản; nêu ra đây để có cái mà đối chiếu:

| Nghĩa vụ | Ngưỡng / thời hạn | Văn bản (cần đối chiếu) | Tin cậy |
|---|---|---|---|
| Nhận biết khách hàng (CDD) + chủ sở hữu hưởng lợi | Khi thiết lập quan hệ | Luật PCRT 2022 | [C-Cao] |
| Báo cáo giao dịch giá trị lớn | **400 triệu VND** | Quyết định 11/2023/QĐ-TTg | [C-TB] |
| Báo cáo chuyển tiền điện tử | Ngưỡng riêng cho chuyển tiền quốc tế (mức tôi nhớ là **1.000 USD**) và nội địa (**500 triệu VND**) | Thông tư của NHNN hướng dẫn Luật PCRT | [C-Thấp] |
| Báo cáo giao dịch đáng ngờ (STR) | Không có ngưỡng tiền; theo dấu hiệu | Luật PCRT 2022 | [C-Cao] |
| Lưu trữ hồ sơ | **5 năm** kể từ khi kết thúc giao dịch/quan hệ | Luật PCRT 2022 | [C-TB] |
| Đánh giá rủi ro nội bộ, quy định nội bộ về PCRT | Định kỳ | Luật PCRT 2022 | [C-Cao] |

Ngưỡng 400 triệu VND là con số **làm đổi thiết kế**: với B2B settlement giữa brand và distributor, một lệnh quyết toán ròng theo kỳ vượt 400 triệu là chuyện bình thường, không phải ngoại lệ. Nghĩa là nếu deployment rơi vào diện đối tượng báo cáo, **phần lớn** settlement B2B đều phải báo cáo — chứ không phải một thiểu số. Đó là chi phí vận hành phải tính vào từ đầu, không phải một tính năng bật sau.

#### 13.6.2. Travel Rule: Zether làm đúng một nửa, và đó là nửa khó hơn

FATF Recommendation 16 yêu cầu đi kèm mỗi lệnh chuyển: tên originator, định danh tài khoản/ví, địa chỉ hoặc số giấy tờ; tên beneficiary và định danh tài khoản; **và số tiền cùng loại tiền**. Ngưỡng thông lệ 1.000 USD/EUR.

- **Zether cho không phần khó:** `schnorrAddress` của người gửi và người nhận nằm vĩnh viễn trên chain, không mixer, đồ thị chuyển tiền nguyên vẹn. Đây chính xác là thứ mà một privacy coin hay một tumbler **không thể** cung cấp, và là lý do triết lý "lộ danh tính, ẩn số tiền" là lựa chọn đúng cho doanh nghiệp.
- **Zether không cho phần còn lại:** số tiền bị mã hoá. **Tuyên bố "tuân thủ 100% FATF Travel Rule" chỉ nhờ lộ danh tính là sai** — §2.7.6 đã chỉ ra điều này về mặt kỹ thuật; ở đây tôi khẳng định lại nó như một kết luận pháp lý.
- **Và một điều kiện tiên quyết mà cả note lẫn bản nháp đều bỏ:** Travel Rule ràng buộc **VASP-to-VASP**. Nếu cả hai đầu của một giao dịch B2B đều là tài khoản do **cùng một doanh nghiệp** kiểm soát, hoặc là hai doanh nghiệp phi tài chính có hợp đồng thương mại với nhau, thì **không có VASP nào trong luồng và Travel Rule không áp dụng**. Xây bộ máy Travel Rule cho một luồng như vậy là xây thừa. Bài test ở §13.4.2 quyết định điều này, không phải cảm tính.

**Sửa một con số sai trong bản nháp:** nó ghi `C_audit` tốn **≈13.200 gas/transfer**. Con số đó đã bị **§2.7.6 bác bỏ tại chỗ** — nó đếm thiếu cặp thứ hai của equality proof. Con số đúng:

| Thành phần | Chi phí |
|---|---|
| +64 bytes calldata | 1.024 gas |
| 4 × `ecMul` + 2 × `ecAdd` (EIP-196 precompile) | 24.300 gas |
| **Tổng `C_audit` + Chaum-Pedersen equality proof** | **≈ 25.300 gas/transfer (~+11% trên một confidential transfer)** |

Và con số thật sự quyết định được câu hỏi "có bắt buộc `C_audit` không" **không phải là gas**. Trên Gnosis ở ~1 gwei với xDAI ≈ 1 USD: 25.300 gas ≈ 0,0000253 xDAI ≈ **$0,000025 mỗi giao dịch**. Với 1,8 triệu giao dịch/năm: **≈ $46/năm**. Con số đó không đáng để họp bàn. Thời gian prover tăng thêm là 2 phép mũ trên đường cong — **dưới 5 ms** so với 0,5–1,25 s của Bulletproof (§03) [ước tính, cơ sở: một phép mũ alt_bn128 ~0,1–1 ms trong thư viện Rust/Go tối ưu]. Cũng không đáng.

**Vậy câu hỏi thật của `C_audit` không phải chi phí mà là quản trị khoá** (`y_audit` threshold, xoay khoá, ai giữ share) và **rủi ro tập trung** (lộ `x_audit` = lộ toàn bộ lịch sử, §2.7.6). Bản nháp đặt câu hỏi số 5 ở §13.9 dưới dạng đánh đổi chi phí. Đó là câu hỏi sai; xem §13.9 đã sửa.

#### 13.6.3. Năm hệ quả pháp lý mà các section trước chưa nêu

*(Bản nháp ghi "ba hệ quả" rồi liệt kê bốn. Sửa: năm.)*

**(1) Travel Rule payload không nằm trên chain, và không được nằm trên chain.** On-chain chỉ có pseudonym + ciphertext. Bản tin Travel Rule (PII originator/beneficiary + số tiền) đi **off-chain** giữa hệ compliance của hai pháp nhân, định dạng **IVMS101**, qua một kênh kiểu TRP/OpenVASP. On-chain chỉ giữ một **hash ràng buộc**.

```python
class BlockchainTravelRuleMessage(models.Model):
    _name = 'blockchain.travel.rule.message'
    _description = 'FATF Rec.16 originator/beneficiary message (IVMS101)'

    company_id      = fields.Many2one('res.company', required=True, index=True,
                                      default=lambda s: s.env.company)
    settlement_id   = fields.Many2one('blockchain.settlement', required=True, index=True,
                                      ondelete='restrict')
    direction       = fields.Selection([('out', 'Outbound'), ('in', 'Inbound')], required=True)
    counterparty_ref = fields.Char(required=True, help='Dinh danh VASP/phap nhan doi tac. Khong phai PII.')
    ivms_version    = fields.Char(required=True, default='101.2023',
                                  help='Phien ban schema IVMS101 dung de chuan hoa truoc khi hash.')
    payload_hash    = fields.Char(required=True, index=True, size=66,
                                  help='0x + keccak256 cua ban tin IVMS101 da chuan hoa.')
    payload_attachment_ids = fields.Many2many('ir.attachment')  # S3/Garage, ma hoa cho doi tac
    envelope_key_ref = fields.Char(help='Tham chieu KMS toi khoa ma hoa payload. KHONG BAO GIO la khoa.')
    msg_state       = fields.Selection([('draft', 'Draft'), ('sent', 'Sent'),
                                        ('acked', 'Acknowledged'), ('rejected', 'Rejected')],
                                       required=True, default='draft', index=True)
    sent_datetime   = fields.Datetime()
    retain_until_date = fields.Date(required=True, index=True,
                                    help='Han luu tru PCRT (5 nam). Truoc ngay nay moi yeu cau xoa '
                                         'deu bi tu choi voi can cu phap luat. Xem §13.7.3.')

    _unique_payload_hash = models.Constraint('UNIQUE(payload_hash)',
                                             'Moi ban tin Travel Rule phai duy nhat.')
    _check_payload_hash  = models.Constraint("CHECK (payload_hash ~ '^0x[0-9a-f]{64}$')",
                                             'payload_hash phai la hex 32-byte lowercase.')
```

Payload là `ir.attachment` trên S3/Garage theo quy ước repo — **không** field JSON, **không** base64 trong DB. Tên field là `msg_state` chứ không phải `state`; `payload_hash`/`sent_datetime`/`retain_until_date` tránh trùng tên kiểu dữ liệu Odoo.

Ba thứ bản nháp thiếu và đã thêm ở trên: `company_id` (mọi model giữ dữ liệu nghiệp vụ đều company-scoped, §10.9), `retain_until_date` (xung đột lưu trữ vs xoá, §13.7.3), và `envelope_key_ref` — bản nháp nói payload "mã hoá cho đối tác" mà không nói khoá ở đâu; nói ra thì thấy ngay là khoá **không được** nằm trong DB.

Định lượng để không ai over-engineer chỗ này: một bản tin IVMS101 đầy đủ ≈ **1,5–3 KB JSON**. Nếu 200 distributor × 2 settlement/tháng vượt ngưỡng = 4.800 bản tin/năm × 3 KB ≈ **14 MB/năm** trên Garage. Đây là một khối lượng dữ liệu không đáng kể — nên giải pháp đúng là đơn giản nhất chạy được, không phải một message bus.

**(2) Ngưỡng Travel Rule phải được đánh giá *trước khi broadcast*, từ bản ghi nghiệp vụ, không từ chain.** Số tiền on-chain đã mã hoá — hệ thống không thể tự hỏi "giao dịch này có vượt 1.000 USD không" bằng cách đọc chain. Nó phải hỏi `blockchain.settlement.amount_base` mà originator đang giữ. Đây là phiên bản đảo ngược của nguyên tắc VietQR trong repo: **không thể rút lại một lần broadcast**, nên mọi kiểm tra tuân thủ phải nằm ở phía trước cổng broadcast, không phải trong Finality Gate.

Chỗ chính xác để đặt nó, bằng tên method có thật: gate nằm trong `_authorize()` của `blockchain.settlement` (chuyển `draft → authorized`), **không** trong `_set_finality`. Nếu bản tin Travel Rule bắt buộc mà chưa ở trạng thái `sent`/`acked`, `_authorize()` raise và settlement không bao giờ tới `submitted`.

**(3) Mỗi lần giải mã `C_audit` phải là một bản ghi.** Khoá `y_audit` giữ theo t-of-n với ít nhất một share ngoài tổ chức (§07.4a: DKG 3-of-5). Nhưng threshold custody chỉ trả lời "ai có thể giải mã"; NĐ 13/2023 và bất kỳ cuộc thanh tra nào đều hỏi "**ai đã** giải mã, dữ liệu của ai, căn cứ gì".

```python
class BlockchainAuditDisclosure(models.Model):
    _name = 'blockchain.audit.disclosure'
    _description = 'Nhat ky giai ma viewing key C_audit'

    company_id        = fields.Many2one('res.company', required=True, index=True,
                                        default=lambda s: s.env.company)
    schnorr_address   = fields.Char(required=True, index=True, size=66)
    legal_basis       = fields.Selection([('court_order', 'Quyet dinh cua toa/co quan dieu tra'),
                                          ('regulator_request', 'Yeu cau co quan quan ly'),
                                          ('internal_audit', 'Kiem toan noi bo'),
                                          ('str_investigation', 'Dieu tra giao dich dang ngo')],
                                         required=True)
    case_ref          = fields.Char(required=True)
    range_from_datetime = fields.Datetime(required=True)
    range_to_datetime   = fields.Datetime(required=True)
    approver_ids      = fields.Many2many('res.users', 'bc_disclosure_approver_rel')
    share_holder_refs = fields.Char(required=True, help='Cac share da tham gia, dang tham chieu.')
    disclosed_datetime = fields.Datetime(required=True, default=fields.Datetime.now)

    def write(self, vals):
        raise UserError(_('blockchain.audit.disclosure la append-only. Tao ban ghi moi de dinh chinh.'))

    def unlink(self):
        raise UserError(_('blockchain.audit.disclosure khong duoc xoa.'))
```

Bản nháp viết *"Không ai được `write` trên model này — chỉ `create`"* rồi chỉ đặt ACL. **ACL không đủ:** bất kỳ đoạn code nào gọi `.sudo()` đều đi vòng qua ACL, và trong một codebase Odoo `.sudo()` xuất hiện ở khắp nơi. Phải override `write()`/`unlink()` như trên. ACL vẫn giữ (`group_blockchain_auditor` đọc, `group_blockchain_compliance` tạo, `perm_unlink=0` cho mọi nhóm) nhưng nó là lớp thứ hai, không phải lớp duy nhất.

**Lưu ý:** `group_blockchain_compliance` **chưa tồn tại** trong §10.5 (ở đó có viewer/operator/treasury/relayer_admin/manager/auditor). Section này bổ sung nó, và nó phải nằm trong `security/blockchain_security.xml` của §10:

| Nhóm | Được gì | `implied_ids` |
|---|---|---|
| `group_blockchain_compliance` | Tạo `blockchain.travel.rule.message`, `blockchain.audit.disclosure`, gọi `blockchain_erase_subject`, đổi `sanctions_state` | viewer |

Tách khỏi `manager` là có chủ đích, cùng logic §10.5: người cấu hình hệ thống không được đồng thời là người quyết định khi nào giải mã dữ liệu của người khác.

**(4) Sàng lọc cấm vận là công việc *hai thời điểm*, và cách làm rẻ hơn cách bản nháp ngụ ý.** Lần một ở `register()` (trên private chain qua `AttestedRegistrationPolicy` của §2.7); lần hai **trước mỗi settlement**, vì danh sách thay đổi và một địa chỉ sạch năm ngoái có thể không sạch hôm nay. Thêm vào `blockchain.account`: `sanctions_state` (`clear`/`flagged`/`blocked`), `sanctions_checked_datetime`, `sanctions_list_version`, `kyc_level`.

Bản nháp nói "một cron rà lại toàn bộ tài khoản `active` mỗi ngày" mà không hỏi nó tốn gì. Hỏi: với 200.000 outlet, gọi một sanctions-screening API ở 10 req/s mất **5,5 giờ mỗi đêm** và tốn tiền theo lượt gọi. Đó là thiết kế sai. Thiết kế đúng, và nó đơn giản hơn:

- **Sàng lọc theo địa chỉ ví: làm cục bộ.** OFAC công bố các địa chỉ crypto ngay trong danh sách SDN; tổng số địa chỉ crypto bị chỉ định là **hàng trăm tới vài nghìn** [ước tính, cơ sở: quy mô SDN crypto listings tới cutoff]. Tải danh sách hợp nhất (UN, OFAC SDN, EU, và danh sách theo Luật PCRT của VN), nạp vào một `set` trong bộ nhớ, tra cứu O(1). Không API, không rate limit, không chi phí biến đổi.
- **Sàng lọc theo tên/pháp nhân: chỉ làm lúc onboarding và khi thông tin đối tác thay đổi.** Đây mới là chỗ cần fuzzy matching và có thể cần dịch vụ trả tiền, và nó xảy ra vài trăm lần/năm, không phải 200.000 lần/đêm.
- **Cron chỉ chạy lại toàn bộ khi danh sách đổi.** So sánh `sanctions_list_version` (hash của file danh sách) — nếu không đổi thì không có gì để rà.

```python
def _cron_sanctions_rescreen(self):
    """Cron XML chi goi mot dong: model._cron_sanctions_rescreen()
    (CLAUDE.md §5.4 — eval context khong co fields, khong co relativedelta)."""
    version = self._load_sanctions_lists()          # tra ve hash cua bo danh sach hop nhat
    stale = self.search([('state', '=', 'active'),
                         ('sanctions_list_version', '!=', version)])
    for batch in (stale[i:i + 1000] for i in range(0, len(stale), 1000)):
        batch._screen_against_local_lists(version)
        self.env.cr.commit()                        # cron chay lau: commit theo lo
```

**Điều xảy ra khi có hit là chỗ khó, và bản nháp không nói.** Đặt `sanctions_state='blocked'` trong Odoo chặn được settlement **mới**. Nó **không** chặn được người đó tiêu số token họ đang giữ, vì họ có thể gọi trực tiếp contract (§10.5.5 của note: "Gọi Trực Tiếp"). Luật PCRT yêu cầu **phong toả**. Chỉ có một cách phong toả thật:

> Token contract phải có `freeze(bytes32 schnorrAddress)` / `unfreeze(...)` do một `COMPLIANCE_ROLE` gọi, và `transferConfidential`/`withdraw` phải `require(!frozen[from] && !frozen[to])`.

Đây là một **đánh đổi phải nói thẳng chứ không giấu**: hàm này là một backdoor tập trung, nó mâu thuẫn với lời hứa phi tập trung, và nó là một mục tiêu tấn công (§12 phải bổ sung nó vào threat model — một `COMPLIANCE_ROLE` bị chiếm có thể đóng băng toàn hệ thống). Nhưng **không có nó thì deployment không thể tuân thủ một lệnh phong toả**, và ở profile `vn_conservative` đó không phải một lựa chọn. Chốt: `freeze` là **bắt buộc** với `token_legal_class ∈ {loyalty_point, tokenised_receivable, utility_internal, stablecoin_fx, cbdc}` ở profile VN, và `COMPLIANCE_ROLE` phải là một multisig 2-of-3 khác với multisig quản trị, không phải một EOA.

**(5) Lệnh tịch thu / thu hồi thì sao?** Nặng hơn phong toả một bậc. Toà có thể ra lệnh chuyển tài sản cho một bên khác. Ba lựa chọn, mỗi cái có một cái giá:

| Lựa chọn | Cơ chế | Cái giá |
|---|---|---|
| Không có gì | Contract không có đường thu hồi | Không thể thi hành án ⇒ rủi ro cho chính doanh nghiệp, và nó **không** miễn trừ trách nhiệm |
| `freeze` + burn/mint bởi issuer | Đóng băng, burn số dư, mint cho bên được thi hành án | Chỉ khả thi với token do chính ta phát hành; là một quyền lực lớn, phải multisig + timelock + log on-chain có lý do |
| Ghi nhận off-chain, thi hành bằng tài sản khác | Chain giữ nguyên; nghĩa vụ được thi hành bằng tiền/tài sản ngoài chain | **Đây là lựa chọn đúng khi token chỉ là bản ghi** (§13.2b mô hình 1) — và là một lý do nữa để chọn mô hình đó |

Với `token_legal_class='tokenised_receivable'` (token không chấm dứt nghĩa vụ), lựa chọn thứ ba là câu trả lời tự nhiên và không cần thêm quyền lực nào vào contract. Đó là một lợi ích của mô hình "token là bản ghi" mà bản nháp chưa kể ra.

---

### 13.7. Thuế, kế toán và bảo vệ dữ liệu

#### 13.7.1. Kế toán (VAS) — chỗ chưa có chuẩn

| Vấn đề | Tình trạng | Xử lý đề xuất |
|---|---|---|
| Không có chuẩn VAS nào cho tài sản mã hoá; Thông tư 200/2014/TT-BTC không có tài khoản tương ứng | [C-Cao] | Giữ số dư token trong **sub-ledger** (`blockchain.settlement`, M4 / mode 4). Chỉ ghi `account.move` khi **chuyển đổi ra tiền pháp định** hoặc khi ghi nhận doanh thu/chi phí có hoá đơn |
| Đánh giá lại theo tỷ giá cuối kỳ | Stablecoin USD **không phải "ngoại tệ"** theo Pháp lệnh Ngoại hối → quy định đánh giá lại khoản mục tiền tệ gốc ngoại tệ (TT 200) **về lý thuyết không áp dụng** [C-TB] | Xem §13.7.1.1 — bản nháp chốt vội và mâu thuẫn với §15.4.3 |
| **Chứng từ kế toán** | Luật Kế toán 2015 quy định nội dung bắt buộc của chứng từ. Một `tx_hash` không phải chứng từ | Chứng từ là một **phiếu kế toán nội bộ** (hoặc bảng kê theo lô của `blockchain.reconciliation.run`, §15.5) có đủ nội dung bắt buộc, trong đó `tx_hash` và `finality_datetime` là **thông tin tham chiếu**, không phải bản thân chứng từ. Bản nháp bỏ hẳn mục này |
| Hoá đơn | NĐ 123/2020 (và bản sửa đổi 2025): hoá đơn điện tử là bắt buộc | Một settlement on-chain **không thay thế hoá đơn**. Bridge DMS phải sinh hoá đơn theo luồng thường; chain chỉ ghi tham chiếu hoá đơn dạng hash. Với hàng khuyến mại: vẫn phải xuất hoá đơn, xem §13.2(a) |
| Điểm loyalty | Nghĩa vụ phải trả (deferred revenue) khi phát hành, ghi nhận doanh thu khi đổi thưởng hoặc hết hạn | Tương tự IFRS 15 material right; VAS không nói rõ → cần policy được kiểm toán duyệt. **Định lượng cần cho policy đó:** tỷ lệ điểm hết hạn không sử dụng (breakage). Không có số breakage thì không ước tính được nghĩa vụ phải trả, và kiểm toán sẽ không ký |
| Chi phí gas và phí relayer | Không có hoá đơn hợp lệ ⇒ không được trừ khi tính TNDN | Xem §13.4.4 và §13.4.5. Đây là chi phí thật, định lượng được, và nó là một trong những lý do mạnh nhất để chọn private chain |

##### 13.7.1.1. Chính sách FX: giải mâu thuẫn với §15.4.3

§15.4.3 nói: token neo một fiat khác (USDC trên sổ VND) thì tạo một `res.currency` tên `USDC`, nạp `res.currency.rate` từ oracle, để Odoo tự sinh chênh lệch tỷ giá. Bản nháp §13.7.1 nói: ghi nhận theo giá gốc, **không** đánh giá lại. Hai câu này không thể cùng chạy trên một database.

Phân giải, và nó là một phân giải kỹ thuật chứ không phải một thoả hiệp: **cơ chế của §15.4.3 vẫn là cơ chế duy nhất đúng** — sub-ledger phải biết token trị giá bao nhiêu VND tại `finality_datetime`, nếu không thì không đối soát được. Câu hỏi kế toán không phải "có tính tỷ giá không" mà là **"chênh lệch đánh giá lại cuối kỳ có được ghi vào kết quả kinh doanh không"**. Đó là một chính sách, và nó là một cờ:

```python
# ir.config_parameter
# blockchain.fx_policy = 'monetary_revalue' | 'historical_cost'
#   monetary_revalue : coi token la khoan muc tien te goc ngoai te -> danh gia lai cuoi ky,
#                      chenh lech vao 413/635/515 theo TT200. Doi hoi kiem toan chap nhan
#                      rang token la "khoan muc tien te goc ngoai te" — chua chac.
#   historical_cost  : ghi theo gia goc tai finality_datetime, khong danh gia lai,
#                      chenh lech chi ghi nhan khi thanh ly. Mac dinh o vn_conservative.
```

`fx_rate`, `fx_rate_source`, `fx_rate_datetime` (§15.4.3) được ghi trong **cả hai** chính sách — chúng là dữ liệu, không phải chính sách. Chỉ bút toán cuối kỳ khác nhau. Mặc định `historical_cost` vì nó là lựa chọn không cần một phán đoán kế toán chưa có cơ sở, và vì **đổi chính sách kế toán về sau là điều chỉnh hồi tố báo cáo tài chính** — phải có ý kiến bằng văn bản của công ty kiểm toán **trước** khi mint đồng token đầu tiên.

#### 13.7.2. Thuế: bốn đầu thuế, và ba trong số đó bản nháp không nhắc

| Đầu thuế | Khi nào phát sinh | Rủi ro định lượng |
|---|---|---|
| **TNCN** | Thưởng/quà cho cá nhân, chủ hộ kinh doanh | 10% trên phần vượt 10 triệu/lần **nếu** là trúng thưởng may rủi; khác hẳn nếu là chiết khấu (§13.2a) |
| **GTGT** | Hàng khuyến mại không thông báo/đăng ký đúng quy định ⇒ bị ấn định giá tính thuế | 10% trên giá hàng tương đương. Ví dụ §13.2a: **~400 triệu VND/tháng** ở quy mô 4 tỷ hàng khuyến mại/tháng |
| **TNDN** | Chi phí không có hoá đơn/chứng từ hợp lệ bị loại | 20% trên phần bị loại. Áp dụng cho: phí gas (§13.4.4), phí relayer (§13.4.5), giá trị điểm thưởng nếu không đủ hồ sơ |
| **FCT (nhà thầu)** | Trả phí cho relayer/nhà cung cấp nước ngoài | ~10% tổng (5% GTGT + 5% TNDN cho dịch vụ) [C-TB], và **không thực hiện được nếu relayer ẩn danh** (§13.4.5) |

Bản nháp chỉ nêu TNCN. Ba đầu còn lại cộng lại có quy mô lớn hơn, và tất cả đều là hệ quả **trực tiếp** của lựa chọn kiến trúc, không phải của lựa chọn pháp lý: open relayer ⇒ FCT không kê khai được; public chain ⇒ gas không có hoá đơn; loyalty on-chain ⇒ khuyến mại phải thông báo.

#### 13.7.3. Bảo vệ dữ liệu: NĐ 13/2023 (và Luật BVDLCN 2025) đấu với tính bất biến

Xung đột cốt lõi: **quyền xoá dữ liệu** và **quyền rút lại sự đồng ý** không thể thực hiện được trên một sổ cái bất biến. Nhưng bản nháp áp một câu trả lời duy nhất (crypto-shredding) cho mọi loại dữ liệu, và đó là sai.

##### Ai là bên kiểm soát, ai là bên xử lý?

Câu hỏi đầu tiên của bất kỳ hồ sơ dữ liệu nào, và bản nháp không hỏi. NĐ 13/2023 phân biệt **Bên Kiểm soát dữ liệu**, **Bên Xử lý dữ liệu**, và **Bên Kiểm soát và xử lý**. Với `dms_blockchain`:

| Kịch bản | SCaaS là | Khách hàng là |
|---|---|---|
| Khách tự host Odoo, tự vận hành node | Không phải bên nào (chỉ bán phần mềm) | Bên Kiểm soát và xử lý |
| SCaaS host SaaS cho khách | **Bên Xử lý** | Bên Kiểm soát |
| SCaaS vận hành relayer/indexer dùng chung nhiều khách | **Bên Xử lý** cho từng khách, và nếu tự quyết định mục đích xử lý thì thành **Bên Kiểm soát** | Bên Kiểm soát |

Hệ quả cụ thể, làm ngay: kịch bản 2 và 3 **bắt buộc có hợp đồng xử lý dữ liệu (DPA)** giữa hai bên. Một điều khoản trong hợp đồng SaaS, không phải một dòng code — nhưng nó là điều kiện tiên quyết để bán SaaS, nên nó thuộc backlog chứ không thuộc "sau này".

##### Bốn quy tắc, theo thứ tự ưu tiên

1. **Không bao giờ đặt dữ liệu cá nhân lên chain.** On-chain chỉ có `schnorrAddress = keccak256(pkX, pkY)` — một pseudonym. Ánh xạ `schnorrAddress → res.partner` nằm off-chain trong Odoo (§2.6 đã chốt vì lý do privacy; đây là **lý do pháp lý** cho cùng quyết định).

2. **Quy tắc cứng về calldata: không free-text, không mã đối tác, không tên outlet, không số điện thoại — chỉ hash và pseudonym.** Mỗi byte không phải hash trong calldata của một public chain là một lần **chuyển dữ liệu ra nước ngoài** tới mọi node trên trái đất, mà NĐ 13 đòi hồ sơ đánh giá tác động chuyển dữ liệu ra nước ngoài nộp Bộ Công an [C-TB].

   Bản nháp nói "đáng đặt một guard CI" rồi dừng. Guard cụ thể, ~30 dòng, chạy trong CI của `smartcontracts/`:

   ```
   tools/check_calldata_types.py
     1. Doc mo ta ABI cua moi contract da build (artifacts/*.json).
     2. Voi moi ham external/public khong phai view: kiem tra moi input type.
     3. Allowlist type: address, bool, uint*, int*, bytes32, bytes32[], va struct
        chi gom cac type tren.
     4. DENY: string, bytes (dong dai tuy y), va bat ky struct nao chua chung.
     5. Exception phai khai bao tuong minh trong tools/calldata_exceptions.yaml
        kem ly do va nguoi duyet. File rong la trang thai mac dinh.
     6. Exit 1 khi co vi pham -> pipeline do.
   ```

   Lý do dùng ABI đã build chứ không grep source: `bytes` có thể đến từ một struct lồng nhau mà grep không thấy, và ABI là nguồn sự thật duy nhất về cái thực sự lên chain. Ngoại lệ hợp lệ duy nhất tôi thấy trước được: `bytes zkpProof` và `bytes signature` — cả hai đều là dữ liệu mật mã, không phải PII, và cả hai phải nằm trong file exception có ghi lý do.

3. **Xoá không phải một hành động duy nhất — có ba loại dữ liệu, ba câu trả lời khác nhau.** Đây là chỗ bản nháp sai nặng nhất:

   | Loại dữ liệu | Câu trả lời đúng cho yêu cầu xoá |
   |---|---|
   | Hồ sơ AML/KYC, bản tin Travel Rule, `blockchain.audit.disclosure` | **Từ chối, kèm căn cứ.** Luật PCRT buộc lưu **5 năm**; nghĩa vụ pháp luật là một căn cứ hợp pháp để tiếp tục xử lý và là ngoại lệ của quyền xoá. Đây là lý do có `retain_until_date` ở §13.6.3(1). Xoá dữ liệu này **là một vi phạm khác**, không phải một sự tuân thủ |
   | Dữ liệu cá nhân off-chain không còn cần cho mục đích ban đầu (liên hệ marketing, ảnh, số điện thoại) | **Xoá thật**, `unlink`, không phải `active=False` |
   | Pseudonym on-chain (`schnorrAddress`, ciphertext) | **Crypto-shredding**: xoá ánh xạ off-chain và vật liệu giải mã; dữ liệu on-chain trở thành pseudonym không liên kết được |

   **Cơ quan quản lý Việt Nam có chấp nhận crypto-shredding là "xoá" hay không thì chưa có hướng dẫn** [C-Thấp]. Đây là căng thẳng pháp lý–kỹ thuật lớn nhất còn lại của cả dự án và nó cần một ý kiến pháp lý riêng. Nhưng lưu ý điều làm nhẹ đi rất nhiều: nếu quy tắc (1) và (2) được tuân thủ tuyệt đối, **on-chain không chứa dữ liệu cá nhân ngay từ đầu**, và khi đó câu hỏi "xoá dữ liệu trên chain" không còn là câu hỏi phải trả lời. Đầu tư vào việc giữ chain sạch rẻ hơn nhiều so với đầu tư vào việc biện hộ cho crypto-shredding.

4. **Phải xoá được thật ở tầng dòng dữ liệu, và phải từ chối được đúng cách.** Method public, phục vụ cả `call_kw` lẫn `/json/2`, không nhận `allowed_company_ids`:

```python
@api.model
def blockchain_erase_subject(self, partner_id, reason):
    """POST /web/dataset/call_kw/blockchain.account/blockchain_erase_subject
       POST /json/2/blockchain.account/blockchain_erase_subject
    Tra ve {'erased': [...], 'refused': [{'model':..., 'id':..., 'legal_basis':...}]}.
    Khong bao gio raise chi vi co du lieu bi giu lai — nguoi yeu cau CO QUYEN biet
    cai gi bi giu va vi sao."""
    self.env.user._ensure_compliance_officer()      # group_blockchain_compliance
    return self._erase_subject(int(partner_id), reason)

def _erase_subject(self, partner_id, reason):
    held = self.env['blockchain.travel.rule.message'].sudo().search([
        ('settlement_id.partner_id', '=', partner_id),
        ('retain_until_date', '>', fields.Date.today()),
    ])
    # ... null hoa owner_partner_id/partner_id tren blockchain.account,
    #     xoa signer_ref, unlink attachment khong bi giu lai,
    #     ghi mot dong blockchain.erasure.log CHI chua hash cua dinh danh chu the.
```

Bản nháp bỏ mất **legal hold**: nó xoá tất cả. Một method xoá không kiểm tra `retain_until_date` sẽ xoá đúng những hồ sơ mà luật PCRT buộc giữ, và biến một yêu cầu tuân thủ thành hai vi phạm.

Cũng cần: hồ sơ đánh giá tác động xử lý dữ liệu cá nhân (DPIA) lập và nộp trong vòng **60 ngày** kể từ khi bắt đầu xử lý [C-TB], hồ sơ đánh giá tác động **chuyển dữ liệu ra nước ngoài** nếu có bất kỳ dữ liệu cá nhân nào rời VN (bao gồm: node RPC ở nước ngoài, nhà cung cấp KYC nước ngoài, S3 region nước ngoài — **Garage tự host tại VN loại bỏ một trong ba**), và lưu ý **Luật Bảo vệ dữ liệu cá nhân 2025** có thể đã thay thế/nâng cấp NĐ 13 với chế tài nặng hơn [C-Thấp — phải xác minh, và đây là claim có mức phạt tính theo % doanh thu nên nó đứng đầu danh sách cần xác minh].

---

### 13.8. Ma trận: build và deploy được gì **hôm nay**, bất kể luật ngã về đâu

Đây là phần quan trọng nhất của chương. Cột "Trạng thái" chỉ có bốn giá trị: **XANH** (làm ngay, rủi ro pháp lý gần bằng 0), **VÀNG** (làm được nếu tuân thủ ràng buộc ở cột cuối), **ĐỎ** (cần giấy phép hoặc pháp nhân nước ngoài), **CẤM** (không làm trong nước, không có ngoại lệ).

| Hạng mục | Trạng thái | Ràng buộc / lý do |
|---|---|---|
| Toàn bộ tầng off-chain: `blockchain.chain/.account/.token/.transaction/.event/.settlement`, custody, relayer, indexer, Finality Gate, adapter, ACL, RPC surface | **XANH** | Không giữ tiền, không chuyển giá trị. Đây là ~80% khối lượng của section 01–12 |
| Anchoring / công chứng hash: hash của settlement, biên bản kiểm kê, ảnh POSM, log audit → `blockchain.event` (M12) | **XANH** | Không phải thanh toán. Luật GDĐT 2023 cho thông điệp dữ liệu giá trị chứng cứ. Đây là use case bán được ngay |
| Chain riêng/permissioned + `token_legal_class='utility_internal'`, `transfer_policy='non_transferable'`, token không rời consortium | **XANH** | Sổ cái nội bộ, không phải phương tiện thanh toán. Với hai pháp nhân riêng biệt thì lập luận theo bù trừ nghĩa vụ (BLDS Đ.378) và quyết toán ròng bằng chuyển khoản. **Không có native coin để mua** ⇒ tránh luôn §13.4.4 |
| Loyalty point không chuyển nhượng, không quy đổi tiền mặt, một issuer | **XANH** với điều kiện | Đủ các điều kiện §13.2(a) **và** đã thông báo/đăng ký khuyến mại NĐ 81/2018 **trước khi chạy**. Không thông báo thì rủi ro GTGT (§13.7.2) lớn hơn mọi rủi ro khác trong bảng này |
| Zether + `C_audit` bắt buộc trên private chain | **XANH** | Bảo mật số tiền, lộ danh tính, có viewing key. Không có mixer nào ở đây. Chi phí gas ≈ $46/năm ở quy mô 1,8 triệu tx (§13.6.2) |
| Mọi thứ trên testnet, bao gồm cả Z-VND | **XANH** | `token_legal_class='test'`, token không mang giá trị |
| `freeze()` / `COMPLIANCE_ROLE` trong token contract | **XANH và bắt buộc** ở profile VN | Không có nó thì không thi hành được lệnh phong toả (§13.6.3(4)). Phải multisig 2-of-3, tách khỏi multisig quản trị, và nằm trong threat model §12 |
| B2B settlement dạng **bản ghi nghĩa vụ** + quyết toán ròng bằng ngân hàng (M4/M12) | **VÀNG** | Hợp đồng phải có điều khoản ở §13.2(b) — cả hai đoạn, không chỉ đoạn đầu |
| Loyalty point **chuyển nhượng được** giữa các outlet | **VÀNG** | `transfer_policy` rời khỏi `non_transferable` là ngưỡng ở §13.1.2. Ngay khi có thị trường thứ cấp và giá tham chiếu, lập luận "không phải phương tiện thanh toán" sụp đổ. Cần ý kiến luật sư trước khi bật |
| Đối soát on-chain cho end-user payment, tiền thật đi qua VietQR/thẻ | **VÀNG** | Không có token nào đổi chủ để trả tiền. Rủi ro nằm ở khâu mô tả sản phẩm, không ở kiến trúc |
| **Chạy relayer trên public mainnet (Gnosis/Celo) bằng pháp nhân VN** | **ĐỎ** | Không có đường mua xDAI/CELO hợp pháp bằng VND; chi phí gas không có hoá đơn ⇒ loại khi tính TNDN (§13.4.4). Đây là dòng **mới**, và nó chặn public-chain deployment độc lập với mọi câu hỏi về token |
| **Open Relayer Network chế độ `MODE_OPEN` với relayer ẩn danh** | **ĐỎ** ở profile VN | Không kê khai được thuế nhà thầu (§13.4.5). Ở VN dùng `MODE_RESTRICT_RELAYER` + allowlist có hợp đồng. Ở `offshore` thì XANH |
| Phát hành Z-VND neo VND, có quy đổi | **ĐỎ** | Tiền điện tử theo NĐ 52/2024 → cần giấy phép NHNN hoặc đối tác đã có giấy phép (M2) |
| Giữ hộ khoá/tài sản cho bên thứ ba (`custody_mode='custodial'` trên `role='user'`) | **ĐỎ** | Chạm mục (iv) định nghĩa VASP (§13.4.2); chưa có khung cấp phép trong nước |
| Đứng giữa người trả và người nhận để chuyển giá trị | **ĐỎ** | Trung gian thanh toán → cần giấy phép, 50 tỷ vốn, 12–24 tháng |
| Dùng bất kỳ token nào để **chấm dứt** nghĩa vụ thanh toán giữa hai bên cư trú VN | **CẤM** | NĐ 88/2019 (100–200 triệu/hành vi với tổ chức) + BLHS Đ.206 (ngưỡng thiệt hại 100 triệu) |
| Quy đổi crypto ↔ VND/ngoại tệ ngoài tổ chức được phép | **CẤM** | Vi phạm riêng biệt, độc lập với vi phạm phương tiện thanh toán |
| Niêm yết giá hàng hoá bằng USD-stablecoin trong nước | **CẤM** | Hạn chế niêm yết bằng ngoại tệ giữa người cư trú (§13.1.1) |
| Quảng cáo "chấp nhận thanh toán bằng crypto" | **CẤM** | Cấu thành hành vi "cung ứng" **trước cả khi có dòng code chạy** (giả định A9); ngoài ra là rủi ro truyền thông và thanh tra |
| Đặt bất kỳ chuỗi ký tự tự do nào vào calldata của public chain | **CẤM** | Chuyển dữ liệu cá nhân ra nước ngoài không có hồ sơ. Chặn bằng CI, không bằng review (§13.7.3 quy tắc 2) |

Đọc bảng này theo một câu: **mọi thứ trong section 01–12 đều build được và deploy được ngay, chỉ trừ đúng ba hành vi — để token chấm dứt một nghĩa vụ trả tiền, chạy public mainnet bằng pháp nhân VN, và mở relayer market cho bên ẩn danh.** Kiến trúc đã tách được cả ba thành ba điểm cấu hình (`token_legal_class` + `chain_profile` + `mode` của EIP-1776), nên chúng bật/tắt được bằng cấu hình chứ không phải bằng một cuộc viết lại. Hai điểm sau là **mới** so với bản nháp, và cả hai đều củng cố quyết định đã khoá #5: private chain trước.

---

### 13.9. Câu hỏi cần con người quyết định

#### 13.9.1. Gói tài liệu giao cho luật sư (đừng hỏi miệng)

Một câu hỏi mở tốn gấp ba một câu hỏi có phạm vi. Gói cần gửi kèm, để thư tư vấn dùng được thay vì chỉ đúng:

1. Sơ đồ một trang: ai giữ khoá, tiền đi đường nào, token đi đường nào, ranh giới giữa hai đường.
2. Bản in §13.8 (ma trận) — hỏi luật sư đánh dấu lại chứ không hỏi "chúng tôi làm thế này được không".
3. Draft điều khoản hợp đồng ở §13.2(b) — hỏi sửa, không hỏi soạn.
4. Danh sách entity: ai phát hành, ai vận hành node, ai giữ khoá, ai ký hợp đồng với outlet, quốc tịch từng bên.
5. Ước tính khối lượng và giá trị: số outlet, số giao dịch/tháng, giá trị bình quân, giá trị lớn nhất. Ngưỡng 400 triệu và 10 triệu ở trên chỉ có nghĩa khi đặt cạnh những con số này.

Ước tính: **80–400 triệu VND, 3–6 tuần** (§13.4.3). Rẻ hơn một quyết định xử phạt, rẻ hơn nhiều so với việc viết lại kiến trúc token.

#### 13.9.2. Câu hỏi pháp lý (nội dung thư tư vấn)

1. Một token `utility_internal`, `transfer_policy='non_transferable'`, trên chain permissioned, dùng để ghi và bù trừ công nợ giữa brand và distributor (đều là pháp nhân VN), quyết toán ròng cuối kỳ bằng chuyển khoản — có bị coi là "phương tiện thanh toán không hợp pháp" không?
2. Điểm loyalty chuyển nhượng được giữa các outlet trong cùng hệ thống phân phối, không quy đổi tiền mặt — ranh giới nào biến nó thành tiền điện tử?
3. Crypto-shredding (xoá khoá + xoá ánh xạ off-chain) có thoả mãn "quyền xoá dữ liệu" theo NĐ 13/2023 hoặc Luật BVDLCN 2025 không? Và ngược lại: từ chối xoá hồ sơ AML với căn cứ Luật PCRT có đúng không?
4. Với giả định A4 (chủ outlet là hộ kinh doanh): một khoản thưởng theo doanh số trả bằng điểm là **trúng thưởng**, **chiết khấu thương mại**, hay **hàng khuyến mại**? Ba đầu thuế khác nhau (§13.7.2).
5. **Doanh nghiệp VN mua native gas (xDAI/CELO) như thế nào cho hợp pháp và có chứng từ?** Nếu không có câu trả lời, public-chain deployment bằng pháp nhân VN là không khả thi (§13.4.4).
6. Trả phí cho một relayer không xác định danh tính — nghĩa vụ khấu trừ thuế nhà thầu xử lý ra sao? (§13.4.5)
7. Ở kịch bản SaaS, SCaaS là Bên Xử lý hay Bên Kiểm soát, và DPA cần những điều khoản nào? (§13.7.3)

#### 13.9.3. Quyết định kinh doanh / kỹ thuật cần một người ký tên

8. Pháp nhân nào phát hành token: entity VN hay entity nước ngoài? Quyết định này chi phối §13.4 và toàn bộ mô hình thuế, và **không thể hoãn tới sau khi mint**.
9. `C_audit` bắt buộc trên **mọi** giao dịch hay chỉ trên luồng B2B? **Lưu ý câu hỏi đã đổi so với bản nháp:** chi phí không còn là biến số (25.300 gas ≈ $0,000025/tx, ≈ $46/năm ở quy mô đầy đủ, prover +<5 ms). Biến số thật là **quản trị khoá `y_audit`** và rủi ro một điểm lộ làm giải mã toàn bộ lịch sử (§2.7.6).
10. Ai giữ share của `y_audit`? Cần tối thiểu một share do bên ngoài tổ chức nắm — kiểm toán độc lập hay ngân hàng lưu ký? Ai được nằm trong quorum 3-of-5, và ai ký duyệt mỗi lần giải mã?
11. Chính sách kế toán cho số dư token: `historical_cost` hay `monetary_revalue` (§13.7.1.1) — công ty kiểm toán có ký không, và ký trước khi mint hay sau?
12. Với loyalty: chặn trần mỗi lần đổi thưởng, hay xây cơ chế khấu trừ thuế tại nguồn? Câu trả lời phụ thuộc câu hỏi 4.
13. Compliance profile mặc định khi cài addon là `vn_conservative` — ai có quyền đổi, quy trình phê duyệt là gì, và ai ký vào bản ghi xác nhận ở §13.3.1?
14. `COMPLIANCE_ROLE` có quyền `freeze()`: ai giữ 2-of-3, và quy trình nào cho phép gọi nó? Không có quy trình thì nó là một backdoor không có chủ.
15. Tình trạng FATF grey list của Việt Nam và việc VASP có đã trở thành đối tượng báo cáo theo Luật PCRT hay chưa — ai chịu trách nhiệm xác minh, và entry nào trong `docs/legal/vn_legal_claims.yaml` mang tên người đó?
16. Ai là chủ sở hữu của `docs/legal/vn_legal_claims.yaml` và của CI job `legal-register-freshness`? Một register không có chủ là một register hết hạn sau sáu tháng.
