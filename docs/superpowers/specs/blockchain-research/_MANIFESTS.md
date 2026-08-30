# Per-section manifests: key findings, open questions, corrections to blockchain.md


## 01-token-factory.md  (10500 words)

**Key findings**

- Proxy pattern chot la Beacon, va ly do manh nhat khong phai gas ma la tinh on dinh cua dia chi du doan: voi UUPS va voi EIP-1167 clone, dia chi implementation nam trong init_code nen moi lan doi implementation la moi dia chi CREATE2 tuong lai deu doi; voi Beacon thi khong.
- Tinh xac dinh dia chi co bon tang (deterministic deployer -> factory -> beacon -> proxy), gay mot tang la gay tat ca tang duoi; ban nhap chi mo ta tang cuoi.
- Salt phai cam ket keccak256(initData) trong khi init_code thi khong duoc chua initData: nho vay dia chi rang buoc vao name/symbol/decimals/maxSupply ma van du doan duoc, va ket hop voi deploy+initialize atomic cong require(msg.sender == FACTORY) thi chan duoc front-run initialize().
- Rang buoc that su len decimals khong phai decimals ma la totalSupply tinh theo raw unit: chi phi BSGS giai ma so du Zether bi chan boi totalSupply chu khong boi 2^n, nen quy tac chot la maxSupply <= 2^44 (1.76e13) enforce trong initialize().
- Range proof width va tran giai ma la hai thu doc lap va phai tach: chon RANGE_BITS = 64 (luy thua cua 2, Bulletproofs yeu cau n*m la luy thua cua 2) cho soundness, va MAX_DECRYPTABLE_RAW = 2^44 cho usability.
- Invariant WRAP_1_1 phai la totalSupply() == reserveAccounted && reserveAccounted <= underlying.balanceOf(vault), khong phai dang == truc tiep voi balanceOf: bat ky ai cung donate duoc underlying vao vault, va rebasing underlying lam balanceOf doi ma khong ai goi ham nao.
- Bat bien chong in tien cho Zether la confidentialLocked == balanceOf(address(this)) — mot phep so sanh danh gia duoc on-chain; cong thuc cua ban nhap dua tren tong so du cong khai khong the liet ke duoc nen khong phai la mot invariant.
- PEG_RATIO thieu spread hai chieu la mot lo hong kinh te, khong chi mot thieu sot: mint rate = redeem rate cho phep arbitrage khong rui ro quanh moi lan cap nhat oracle; can spreadBps >= 50 cong redemptionDelay 24h cho khoan lon.
- Reserve off-chain co do tre thanh toan T+0..T+2 nen mint cap phai la attested_reserve - totalSupply - in_flight_redemption - buffer(2%), voi mot bang chinh sach ro rang theo tuoi attestation (7/35/60 ngay) va nguyen tac khong bao gio chan redeem vi staleness.
- Mot Zether transferConfidential 64-bit ton ~1.9M gas (phan bac: 277 diem MSM x 6000 gas ecMul + sigma + state), tuc ~0.45 tx/s ben vung tren Gnosis va ~45 tx/s tren Besu QBFT noi tran that la CPU validator (~22ms/proof) chu khong phai gas limit.
- Con so 180k-250k gas cua note dat duoc bang Groth16 (1 ecPairing 4 cap = 181k) chu khong bang Bulletproofs; day la duong nang cap duy nhat dua Zether len public chain o quy mo, doi lai mot trusted-setup ceremony.
- Ba use case anh xa ro rang: loyalty (ISSUER_NATIVE + ZTokenOpen + Gnosis) di truoc vi la use case duy nhat khong cho mot ket luan phap ly; B2B settlement can Zether va can private chain vi con so thong luong; thanh toan nguoi dung cuoi khong chay duoc tren Bulletproofs o quy mo.

**Open questions (need a human decision)**

- Z-VND co doi ra tien phap dinh VND duoc khong? Cau tra loi quyet dinh giay phep, quyet dinh ZTokenOpen co hop phap khong, va quyet dinh ca kien truc reserve; neu 'khong' thi phan lon do phuc tap cua muc 1.7 bien mat.
- decimals cua Z-VND: 2 hay 0? Bat bien sau khi deploy. 2 cho phep phi phan tram va giam dust 100 lan; 0 giam thoi gian khoi phuc BSGS 10 lan (0.08s vs 1.0s) va khop res.currency VND rounding=1.0. Khuyen nghi 2, can chu ky nghiep vu.
- Tran cung tien (maxSupply) nghiep vu cua moi token la bao nhieu? Phai <= 2^44 raw ve mat ky thuat, nhung con so kinh doanh phai duoc chon truoc khi initialize() vi khong co setter.
- Ai la 7 nguoi ky Safe DEFAULT_ADMIN_ROLE, va co it nhat mot nguoi ngoai cong ty khong? Bay khoa cua bay nhan vien cung mot cong ty la mot chu ky, khong phai bay.
- Ai chay 4 validator cua private chain Besu? Neu ca 4 la ha tang cua ta thi 'permissioned blockchain' phai duoc goi dung ten trong tai lieu ban hang.
- Ai ky reserve attestation, cadence nao, ngan sach bao nhieu? Neu khong co don vi kiem toan nao ky hang thang cho float nho, thi PEG_RATIO voi reserve off-chain khong chay duoc va chi con WRAP_1_1 on-chain.
- Chap nhan MAX_PAUSE = 7 ngay voi loi thoat duy nhat la WIND_DOWN mot chieu? Day la cam ket voi nguoi giu token khong the rut lai sau khi da mint.
- Neu quy dinh doi hoi kha nang tich thu (seizure): chon (a) token khong redeem duoc ra fiat nen ngoai pham vi dieu chinh, hay (b) private chain voi forceTransfer co N validator chung kien? Khong co lua chon thu ba tren Zether.
- Chinh sach 'rate khong bao gio giam' cho loyalty co duoc chap nhan khong? Neu khong, phai luu rate theo lo (mapping batchId => rate) — mot cau truc du lieu tang khong gioi han can pruneBatches sau 24 thang.
- Co chap nhan mot trusted-setup ceremony cho Groth16 khong? Cau tra loi quyet dinh Zether co bao gio len duoc public chain o quy mo hay khong.

**Where blockchain.md is wrong / under-specified**

- MAX = (1 << 128) - 1 khong lam so du doc duoc. Gioi han 2^32 cua ConsenSys anonymous-zether la gioi han GIAI MA (baby-step giant-step tren g^b), khong chi la gioi han range proof; voi 2^128 thi BSGS can 2^64 phep tinh. Sua: tach RANGE_BITS = 64 (soundness) khoi MAX_DECRYPTABLE_RAW = 2^44 (usability), va chan chi phi giai ma bang maxSupply chu khong bang 2^n.
- Con so '~180,000 - 250,000 gas' cho xac thuc ZKP (note muc 10.5.2) khong dat duoc voi Bulletproofs. Phan bac: MSM kich thuoc 2*n*m + 2*log2(n*m) + 7 diem, moi diem mot ecMul 6,000 gas; n=64,m=2 cho ~1.9M gas, n=128 cho ~3.5M. Con so cua note chi dat duoc voi Groth16 (1 ecPairing 4 cap = 181k), doi lai mot trusted-setup ceremony.
- interface IZetherToken khai bao 'function MAX_AMOUNT() external pure returns (uint256)'. Voi Beacon proxy, 'pure' co nghia moi token dung chung mot beacon deu co cung tran, nen Z-VND va Z-USDT khong the co tran khac nhau neu cung archetype. Sua thanh 'external view' doc tu bien set trong initialize().
- Note muc 10.2.1 chot UUPS (ERC-1822) cho toan bo contract EVM, mau thuan voi chinh yeu cau 'support nhieu version' o muc TOKEN: UUPS can N transaction de va mot lo hong tren N token, va vi init_code chua dia chi implementation nen moi lan doi implementation la moi dia chi CREATE2 tuong lai deu doi. Khuyen nghi Beacon.
- Note viet 'tat ca dung co che delegate de chia se code, khac data' nhung khong he nhac den ky luat storage layout — thu duy nhat lam delegatecall nguy hiem. Bo sung bat buoc: ERC-7201 namespaced storage, constructor goi _disableInitializers(), va CI gate voi OZ validateUpgrade doi chieu storage-layouts/v<N-1>/.
- Note yeu cau 'mint/burn tu 1 hoac 1 GROUP ERC-20' nhung khong ai thiet ke gio: thieu trong so, bang gia NAV, quyen rebalance, va thuc te la N leg = N oracle = N diem gay (3 leg voi uptime 99.5%/leg cho uptime tong 98.5%, ~5.5 ngay/nam khong mint duoc). Khuyen nghi khong lam basket trong v1; profileMask cua BASKET_PEG de 0x00.
- Vi du '1 USDT -> 25000 Z-VND' duoc note trinh bay nhu mot tinh chat cua token; thuc te no la mot vi the short USD cua issuer. Dinh luong: float 10 ty VND voi VND mat gia 6%/nam cho ~24,000 USDT P&L mot nam. Sua: reserve phai bang VND, khong phai USDT; USDT chi la on-ramp mot chieu quy doi theo spot tai thoi diem nap.
- Note dinh nghia deposit(schnorrAddress, amount) khong co bat ky cap nao ngoai MAX_AMOUNT, va khong co bat bien nao rang buoc so du confidential voi so du ERC-20 cong khai cua chinh contract. Thieu confidentialLocked == balanceOf(address(this)) la thieu lop duy nhat co the phat hien mot bug in tien trong Bulletproof verifier truoc khi vault can.
- Note goi co che dam bao du tru la mot dieu hien nhien nhung khong phan biet 'proof of reserve' voi 'attested reserve'. Cay Merkle kieu san giao dich chung minh NGHIA VU (tong so du nguoi dung), khong chung minh TAI SAN; voi reserve VND off-chain khong ton tai bang chung mat ma nao, chi co chu ky cua don vi kiem toan. Goi sai ten la mot phat bieu sai su that trong tai lieu phap ly.
- Note noi 'Factory Contract de tu do create2' nhung mot factory permissionless cho phep bat ky ai tinh truoc dia chi tuong lai va rac dia chi bang initData cua ho; va tren chain chua Cancun (EIP-6780) con cho phep metamorphic contract lam 'dia chi = danh tinh' tro thanh sai. Sua: deploy() gan DEPLOYER_ROLE (yeu cau 'tu do' duoc dap ung boi registerPrototype, khong boi factory mo), cong mot cron doi chieu EXTCODEHASH hang ngay.

## 02-account-registry.md  (16135 words)

**Key findings**

- Bat bien an ninh #1 (thieu hoan toan trong ban nhap truoc): transferConfidential/withdraw PHAI xac thuc hai thu doc lap — ZK proof biet x, VA chu ky authScheme tren mot digest bao trum toan bo EncryptedTransfer + authEpoch + address(this); neu khong, biet encKey la du chi tieu va toan bo cot authScheme chi la trang tri.
- Digest bat buoc gom keccak256(EncryptedTransfer), authEpoch va address(this); thieu bat ky thanh phan nao lan luot cho phep relayer doi feeRecipient, chu ky cu song sot sau khi xoay khoa, va chu ky Z-USDC dung duoc tren Z-VND.
- Pack status vao 2 bit cao cua pkY (ban nhap truoc) khong chay: p co bit_length = 254 nen chi con 2 bit tu do = 4 gia tri, nhung thiet ke dinh nghia 5 trang thai — thay bang mot slot `meta` rieng chua status|authScheme|authEpoch|verifier = 240/256 bit.
- Khong truyen `bytes32 addr` cung voi (pkX, pkY): dan xuat addr on-chain ton 42 gas, truyen them 32 bytes ton 512 gas; hot path registry tut xuong ~9,300 gas voi mot CALL gop `assertUsable(from, to)`.
- Chi phi rong that su cua hash identity la +3,176 gas, khong phai 9,500 — 6,800 gas trong con so do la gia cua mo hinh Shared Registry, phai tra du dinh danh la hash hay la point.
- encKey KHONG nam duoc trong HSM FIPS 140-2 L3 tieu chuan (CloudHSM/Cloud KMS/Managed HSM khong ho tro alt_bn128 va khong nap duoc duong cong tuy y); de xuat authKey trong HSM that + encKey trong TEE, hop le vi bat bien #1 bien encKey compromise thanh read-only breach.
- BLS12-381 phai chon bien the min-signature-size (sig in G1, pk in G2): ~115,500 gas so voi ~153,100 gas cua min-pubkey, vi hash_to_curve can HAI lan map cong mot add — ban nhap truoc dem mot lan map va chon nham bien the.
- Diem hoa von BLS vs ECDSA dao chieu tren rollup: n ≈ 29 tren L1/Gnosis nhung n ≈ 8 tren Celo (OP Stack) vi 65 bytes calldata/signer bi tinh gia L1 — Celo la chain thu hai theo locked #4 nen ket luan 'BLS chi thang khi n > 35' cua ban nhap truoc sai cho nua so chain trong scope.
- FALCON verify on-chain uoc tinh lai la 0.6M–2.5M gas (khong phai 2M–10M) = ~$0.003 tren Gnosis: tien KHONG phai rao can, rao can la khong co verifier duoc audit, FIPS 206 chua ban hanh, va HSM khong ho tro Gaussian sampling.
- SLH-DSA-SHA2-128s la ung vien PQ on-chain thuc dung nhat (~0.6M gas, dung precompile SHA-256 0x02, khong NTT khong SHAKE, FIPS 205 da ban hanh) — ban nhap truoc bo qua hoan toan va chi so sanh FALCON voi ML-DSA.
- TON pha vo gia dinh nen tang cua ca thiet ke: actor model bat dong bo khien token khong the goi registry trong cung transaction, nen require(isRegistered) khong ton tai; phai dao nguoc sang mo hinh certificate co expiry, va cua so freeze tre bang expiry (de xuat 1 gio) phai vao SLA.
- Chi phi attestation cross-chain la khong dang ke (~609 attestation/nam/chain cho 5,000 tai khoan ≈ $0.028/nam tren Gnosis) — toan bo rui ro nam o do tre p95 60 giay va o quorum, nen dung toi uu gas o §2.8.

**Open questions (need a human decision)**

- encKey va FIPS 140-2 L3: chap nhan TEE cho encKey + HSM cho authKey, hay dau tu HSM lap trinh duoc (Thales Luna FM / Utimaco CP5, ~$30k–80k, lead time 3–6 thang)? Day la cam ket voi khach hang phai tra loi truoc khi ky hop dong.
- Ai chiu trach nhiem kiem tra lai trang thai FIPS 206 (FN-DSA/FALCON) tai csrc.nist.gov truoc moi lan phat hanh tai lieu ban hang co chu 'FALCON'?
- Chan troi harvest-now-decrypt-later cho B2B settlement gia von: chon private chain (locked #5), chap nhan rui ro co van ban, hay khong dua so tien len chain chut nao (payment mode 4)? Ba phuong an co chi phi trien khai rat khac nhau.
- Deployment nay co duoc coi la VASP theo phap luat Viet Nam khong? Neu co, C_audit la bat buoc (+25,300 gas/transfer) va y_audit phai la khoa cua co quan nao; neu khong, C_audit la tuy chon.
- Ai giu pauseGuardian cua moi ZetherRegistryMirror, va quy trinh re-anchor thu cong khi quorum attestor bi chiem? De xuat multisig 3-of-5 (2 ky thuat + 2 tai chinh + 1 phap che), can xac nhan.
- Chinh sach so luong schnorrAddress moi phap nhan: 4–6 dia chi theo muc dich (khuyen nghi) hay 1 dia chi moi doi tac (linkability tot hon nhung 800 bo Shamir 2-of-3 phai quan ly)?
- Neu khach hang muon B2B settlement chay tren Gnosis cong khai vi ly do thuong mai thay vi private chain, ai ky van ban chap nhan rui ro HNDL cho gia von voi tuoi tho bi mat 5–15 nam?
- Nha cung cap MPC dang dung co ho tro FROST tren bn254 khong? Neu khong, phuong an lui la ECDSA_MULTISIG (gas cao hon va lo co cau nhom on-chain) — phai hoi provider truoc khi chot authScheme cho treasury.
- MAX_EPOCH_GAP = 64 co dung khong cho tan suat attestation thuc te, hay nen tinh theo thoi gian (vi du 90 ngay) thay vi theo so epoch?

**Where blockchain.md is wrong / under-specified**

- blockchain.md §10.5.3 Nguyen Tac 1: hash identity 'toi uu hoa calldata VA chi phi gas luu tru on-chain'. Sai dau ve tong gas: hash identity dat hon point identity ~3,176 gas/transfer (tiet kiem 1,024 calldata, tra them 4,200 doc point). Calldata thi dung.
- blockchain.md §10.5.3 interface IZetherAccountRegistry: `struct SchnorrPublicKey { bytes32 x; bytes32 y; }` dung ky tu x cho toa do trong khi ca tai lieu dung x cho private key va y cho public key point. Doi thanh pkX/pkY kieu uint256 (toa do la so trong F_p, moi phep kiem tra la so hoc) va them lint rule chan bien ten x/y.
- blockchain.md §10.5.3: `keccak256(abi.encodePacked(x, y))`. Dung abi.encode: voi hai bytes32 ket qua giong nhau nhung encodePacked de sinh collision khi them tham so dong ve sau.
- blockchain.md §10.5.3: `register(bytes32 x, bytes32 y, bytes schnorrSignature)` khong dinh nghia challenge cua PoP va khong co validation ranh gioi. Phai co domain tag + block.chainid + address(this) trong challenge, require(pkX < P && pkY < P), on-curve check y^2 = x^3 + 3, tu choi (0,0), va require(popS < n, R != O).
- blockchain.md §10.2.1 bat buoc UUPS cho MOI contract. Ap dung cho registry la lo hong chi mang: mot admin key doi getPublicKey() doi y cua nan nhan, moi khoan tien den sau do bi ma hoa duoi khoa ke tan cong va nan nhan van thay giao dich thanh cong. Registry phai KHONG upgradeable; migration bang con tro successor/predecessor gioi han 2 the he.
- blockchain.md §10.3.1 va §14.2.8: 'khoa ca nhan bat buoc luu trong HSM FIPS 140-2 Level 3 (AWS CloudHSM, Google Cloud KMS)'. Khong lam duoc cho encKey: cac HSM nay khong ho tro alt_bn128 va Zether can x trong mach prove Bulletproofs chu khong chi mot phep ky. Phai sua cau chu: khoa chi tieu trong HSM L3, khoa giai ma ElGamal trong TEE.
- blockchain.md §11 va §14.2.8: 'tuan thu 100% FATF Travel Rule' chi bang cach lo danh tinh nguoi gui/nhan. FATF Rec.16 yeu cau ca thong tin originator/beneficiary VA so tien. Can them ciphertext thu ba C_audit duoi khoa auditor cong equality proof (~25,300 gas/transfer), va y_audit nen la khoa threshold k-of-n.
- blockchain.md §10.5.3 muc 5 bam recipient vao Fiat-Shamir challenge cua withdraw (dung) nhung KHONG lam dieu tuong duong cho transferConfidential — nen khi authScheme = SELF_SCHNORR, relayer doi duoc feeRecipient va C_fee. Phai nhung digest vao challenge cua chinh ZK proof.
- blockchain.md ngam dinh mot mo hinh registry duy nhat (token goi registry dong bo). Khong ap dung duoc cho TON (actor model bat dong bo, khong the goi cross-contract dong bo), SUI (shared object serialize throughput), Soroban (state rent TTL: entry het han thi tai khoan bien mat va so du khoa vinh vien). Can mo hinh thu hai: certificate ky boi registry, co expiry, verify cuc bo.
- blockchain.md khong nhac gi den harvest-now-decrypt-later: ciphertext ElGamal tren chain cong khai la vinh vien, mot CRQC pha ECDLP bn254 G1 giai ma nguoc toan bo lich su so tien va so du. Voi tuoi tho bi mat gia von B2B 5–15 nam va cong thuc Mosca, luong nay da tre tu bay gio neu chay tren public chain.

## 03-zether-crypto.md  (18400 words)

**Key findings**

- MAX = 2^128 - 1 la cann giai ma (decryption bound), khong phai tham so range proof: BSGS o 2^128 can 1.8e19 buoc nen khong ai doc duoc so du cua chinh minh; phai tach ba hang so RANGE_BITS_VALUE / RANGE_BITS_BALANCE / DECRYPT_BOUND va doi don vi ledger theo tung token.
- Bo sung co che con thieu hoan toan: memo AEAD 32 byte moi chieu, khoa dan xuat tu shared secret y_to^s = D_out^{x_to}, chi ton ~1.6k gas, thay BSGS bang giai ma O(1) va rut recovery 10,000 giao dich tu 8 gio xuong 0.6 giay.
- Con so 180k-250k gas cua note la chi phi verify Groth16 tren alt_bn128 (45,000 + 4 x 34,000 = 181k pairing), khong phai Bulletproofs; Bulletproofs 128/128 ton ~3.87 M gas, sai lech 19 lan, va Bulletproofs khong dung pairing.
- Rang buoc that tren Gnosis khong phai tien ($0.004/tx) ma la block space: 3.4 M gas/s toan mang, mot tx 1.88 M gas o 20% block space cho 31,300 tx/ngay; loyalty o 10^5-10^6 tx/ngay khong the chay tren Gnosis.
- Cau hinh 128/128 cua note khong deploy duoc tren EVM: 512 generator x 64 byte = 32,768 byte, vuot EIP-170 (24,576); phai dung SSTORE2 tren 2 data contract, cau hinh 32/64 chi can 8,192 byte nen vua mot contract.
- Diem trong calldata phai truyen uncompressed: compressed tiet kiem 512 gas nhung ton 1,349 gas modexp de decompress on-chain (EIP-2565), tuc dat hon 1.8 lan.
- Thiet ke rollOver dung la accSeq: acc va pending tach roi, khong bao gio tu gop, pending -> acc chi trong rollOver co chu ky Schnorr cua chu tai khoan, va accSeq bam vao Fiat-Shamir; xac suat revert do race ve ~0 va khong ai grief duoc bang cach gui 1 xu.
- Phi phai la public scalar va tra cho relayer bang ERC-20 cong khai truc tiep tu escrow (totalDepositedScaled -= fee): neu cong vao so du ma hoa thi relayer phai co tai khoan Zether, phai chay prover va phai withdraw de tieu, pha vo mo hinh Open Relayer.
- feeRecipient KHONG duoc nam trong Fiat-Shamir challenge de MODE_OPEN hoat dong; he qua la moi relayer copy duoc calldata va dua fee, relayer thua cuoc van mat gas, nen mac dinh phai la MODE_RESTRICT_RELAYER cong private orderflow.
- Sigma-Bullets linkage la cho de hong nhat: tai lieu dua ra protocol 3-move day du (7 phuong trinh verifier, 23 ecMul + 16 ecAdd ~ 156k gas) va layout serialize 768 byte, cong bay cau hoi anti-replay bay tang.
- Nen dat ElGamal tren Baby Jubjub ngay tu dau thay vi BN254 G1: doi curve ve sau bat buoc withdraw/deposit toan bo va lo cong khai so du cua tat ca moi nguoi trong mot snapshot; Baby Jubjub giu duoc duong Groth16 (~215k gas verify) ma khong phai migrate.
- Zether khong co co che nao cho kiem toan vien doc SO TIEN - do thi cong khai khong du cho BCTC, thue VAT hay FATF Travel Rule; giai phap la auditor ciphertext bat buoc (C_aud, D_aud + equality proof, +25k gas) va phai bat tu block dau tien.

**Open questions (need a human decision)**

- Loyalty points co that su can bao mat so du khong? Neu khong, ERC-20 cong khai + EIP-1776 re hon ~40 lan gas, khong can prover tren dien thoai, khong can memo, khong can recovery.
- Chot curve babyjubjub hay bn254 G1? Quyet dinh khong dao nguoc duoc sau khi deploy contract dau tien va no quyet dinh co giu duoc duong Groth16 hay khong.
- auditor_pubkey bat hay tat, va ai giu khoa? Neu bat thi phai bat tu block dau tien; neu ben thu ba giu thi can thoa thuan phap ly (xem muc 13).
- Co xay native precompile ZetherVerifier tren private chain khong? Loi 25-60 lan throughput nhung day la consensus change va khoa vao mot fork geth phai tu maintain.
- Chap nhan n_v = 40 cho Z-VND B2B (tran 1,100 ty VND) hay chia nho giao dich lon thanh nhieu lan n_v = 32 (tran 4.29 ty VND)? Can so lieu doanh so that cua nha phan phoi.
- Tran thi phan block space chap nhan duoc tren Gnosis la bao nhieu? Moi tinh toan throughput gia dinh 20%; neu that su la 5% thi moi tran ngay chia 4.
- Co chay trusted setup ceremony cho Groth16 khong, va bat dau khi nao? Mat 4-8 tuan lich va phai bat dau truoc khi code xong.
- Mat khoa x thi xu ly the nao tren tung custody profile? MPC khoi phuc duoc, non-custodial thi mat vinh vien va ERC-20 tuong ung khoa trong escrow mai mai.
- Chon underlying nao cho pool lon? USDC/USDT co blacklist se dong bang toan bo so du ma hoa vinh vien va khong co duong phuc hoi ky thuat nao; xDAI va DAI khong co blacklist.
- Owner-signed rollOver co giu duoc chung minh an toan cua paper FC 2020 khi N = 2 va nonce don dieu khong? Can mot reviewer mat ma xac nhan truoc khi viet Solidity.

**Where blockchain.md is wrong / under-specified**

- MAX = (1 << 128) - 1 lam hong giao thuc: MAX la cann giai ma chu khong phai tham so range proof, o 2^128 khong ai doc duoc so du cua chinh minh (1.8e19 buoc BSGS). Da sua: tach ba hang so va doi don vi ledger (scale_exponent theo tung token) de xoa van de '4.29e9 wei = 0.00000000429 token' ma khong dung toi range proof.
- Con so gas '~180,000 - 250,000' cho verify ZKP sai 15-20 lan. Do la chi phi Groth16 (45,000 + 4 x 34,000 = 181k pairing), va note tu to giac bang cach vien dan ecPairing/EIP-197. Bulletproofs khong dung pairing; con so dung la ~1.88 M (32/64) va ~3.87 M gas (128/128). Da sua kem bang bottom-up.
- Ly do co Epoch trong note sai: khong co 'xung dot r va C, D' khi nhieu khoan den cung block - ElGamal cong dong hinh cong duoc vo han. Ly do that: proof cua NGUOI GUI noi ve mot gia tri acc cu the, mot khoan den lam doi acc se lam proof het hieu luc. Da sua.
- Note noi 'dau Epoch e+1 nguoi dung goi rollOver()', ngu y tien ket neu nguoi nhan khong goi. Sai: rollOver that su la idempotent, permissionless, contract tu goi noi bo; nguoi nhan khong bao gio phai lam gi va khong phai tra gi. Da sua, va thay bang accSeq owner-signed vi permissionless rollOver la vector griefing ~30k gas.
- Struct EncryptedTransfer tu mau thuan ve phi: khai uint256 fee (public) nhung goi la 'phi bi mat' roi them bytes32[2] C_fee. Kinh te hoc Open Relayer bat buoc phi cong khai. Da sua: xoa C_fee, tru dong hinh C' = C x g^(-fee) (~7k gas), tra relayer bang ERC-20 cong khai.
- Note liet ke bon rang buoc ZKP; chi con hai range statement. 'fee >= 0' va 'b - fee >= 0' bi suy ra tu '(b - fee) - v >= 0' va 'v >= 0'; hai cai kia thua vi fee la public scalar.
- Note khong co domain separator o tang ZKP (chi co o tang EIP-1776). Voi Shared Singleton Registry, mot proof cua Z-USDT verify duoc tren Z-VND khi hai contract moi deploy deu co zetherNonce = 0. Da bo sung chainId, address(this), domain tag, proofSystemId, accSeq vao transcript (chong Frozen Heart).
- Note khong nhac mot chu ve Sigma-Bullets. Ghep ngay tho Sigma + Bulletproof la KHONG an toan: ke gian chung minh range cho mot v vo hai roi chuyen mot v khac - in tien khong gioi han. Da bo sung protocol day du va test bat buoc. Tuong tu, note khong noi gi ve generators NUMS: h = g^alpha voi alpha da biet lam moi range proof gia mao duoc.
- Note khang dinh Zether 'tuan thu 100% AML/KYC va kiem toan' vi lo sender/receiver. Sai: do thi cong khai khong cho kiem toan vien, co quan thue hay FATF Travel Rule thay SO TIEN. Da bo sung auditor ciphertext + equality proof (+25k gas) va canh bao no chi ap dung cho giao dich tuong lai.
- Note ghi Celo la 'IBFT 2.0, immediate finality, ~5 giay' trong bang Finality Gate. Sai tu thang 3/2025: Celo da migrate thanh OP-stack L2, block 1 giay, soft confirmation tuc thi nhung hard finality bam Ethereum ~13-19 phut. Anh huong truc tiep den nguong _set_done.

## 04-eip1776-metatx.md  (10900 words)

**Key findings**

- Lỗ hổng nghiêm trọng nhất bản nháp bỏ sót (04.6.6): một `MetaTxForwarder` generic giữ ERC-20 allowance cộng với `to`/`data` tự do cho phép bất kỳ ai ký một metaTx của chính mình với `to = USDC, data = transferFrom(victim, attacker, X)` và rút sạch mọi user đã approve — chặn bằng `to != address(this)`, `!targets[to].isFeeToken`, target allowlist, và gốc rễ là không giữ allowance (permit đúng số).
- Ngân sách gas Zether của bản nháp sai một bậc độ lớn: `innerGasLimit = 400_000` và "200k–280k cho Bulletproofs" là con số của một cặp `ecPairing` (Groth16), không phải Bulletproofs; tính lại với tham số §03.4 (32+64 bit aggregate, ~214 điểm, `ecMul` 6,000 gas sau EIP-1108) ra 1.72M–2.62M gas ⇒ chốt `innerGasLimit = 3_000_000`.
- Ràng buộc thật của Zether trên public chain không phải tiền mà là block space: ~3.18M gas/tx trên Gnosis (17M block limit, 5s) ⇒ ~13,800 confidential tx/ngày nếu chiếm 15% block — đây là lập luận định lượng mạnh nhất cho quyết định khoá số 5 (private chain trước), mạnh hơn lập luận chi phí ($239/tháng cho 50k tx, không phải $19 như bản nháp).
- Va chạm bitmask giữa hai section đã giải quyết: §05.3.3 xin `0x04` cho `MODE_METERED_FEE` trong khi §04 đã dùng `0x04` cho `MODE_REQUIRE_SUCCESS`; dời METERED_FEE sang `0x08` và mở rộng `mode` từ `uint8` sang `uint32` (chi phí 0 gas — ABI pad cả hai về 32 byte) vì `uint8` chỉ còn 3 bit trống.
- Swallow mode ăn mất principal: bản nháp chuyển `amount` trước inner call mà không ràng buộc mode, nên trong swallow mode tiền đi rồi mà hành động không xảy ra; sửa bằng invariant on-chain `require(m.amount == 0 || (m.mode & MODE_REQUIRE_SUCCESS) != 0)` — phiên bản on-chain của nguyên tắc VietQR.
- Số học 63/64 của bản nháp sai: pre-check phải là `gasleft() >= innerGasLimit * 64 / 63 + FLOOR_GAS`, thiếu hệ số 64/63 là thiếu 41,270 gas ở `innerGasLimit = 2.6M`; và post-check phải nằm trong nhánh `!success`, không vô điều kiện.
- Struct thiếu ba trường, không phải một: thêm `innerGasLimit` (bản nháp đã có), `address feeToken` (loyalty point không trả được relayer — không relayer mở nào nhận điểm thưởng), và mở `mode` thành `uint32`.
- Target không biết `from` là ai: note không có ERC-2771 sender suffix, nên mọi contract nghiệp vụ thấy 1,000 user là cùng một caller; chốt digest hash `data` CHƯA có suffix, forwarder append, và cờ `appendsSender` nằm ở `TargetPolicy` (thuộc tính của target) chứ không phải một mode bit (user không biết target có 2771 hay không).
- Bootstrap allowance không phải "câu hỏi mở" như bản nháp viết: bốn cơ chế cụ thể (EIP-2612 permit bundled qua `executeMetaTransactionWithPermit` với `try/catch` chống front-run permit, EIP-3009, native mixin, approve thủ công), chọn permit cho forwarder generic và native mixin cho Z-token.
- Expiry Zether không còn bị epoch ràng buộc sau quyết định owner-exclusive rollover ở §03.5: bỏ đề xuất `targetEpoch`, nâng expiry từ 20s lên 60s (ràng buộc thật là single-flight §05.4.3 + EIP-1271 revoke window, không phải epoch drift); và thứ tự check sửa lại thành mode → expiry (0 gas) → nonce (2,100 gas), bản nháp để nonce trước.
- Forwarder generic phải KHÔNG upgradeable (khớp §12.1: UUPS + allowance = rug), hệ quả là trường EIP-712 `version` chỉ còn load-bearing trên `ERC1776Native` mixin (token UUPS giữ nguyên address) — bản nháp nói `version` load-bearing cho cả hai.
- Chi phí state bị bỏ qua: mỗi lane là một slot 32 byte vĩnh viễn (EIP-3529 cắt refund), batchId ngẫu nhiên ở 50k tx/tháng sinh ~90–120 MB state/năm so với ~25 MB một lần với pool 64 lane/`from`.

**Open questions (need a human decision)**

- Hình thái deploy cho luồng KHÔNG phải Zether: `MetaTxForwarder` generic (1 contract/chain, cần permit mỗi tx) hay `ERC1776Native` mixin trên từng token? Nó quyết định `verifyingContract`, mà `verifyingContract` nằm trong mọi digest — đổi sau khi đã có chữ ký lưu hành là một migration thật. (Với Zether đã chốt: native mixin.)
- Chi phí verify EIP-1271 của provider custody sẽ chọn: 3,450 gas (precompile RIP-7212) hay tới 330,000 gas (verifier P-256 thuần Solidity)? Chênh hai bậc và cộng thẳng vào `requiredOuterGas` của MỌI metaTx. Phải hỏi provider, không đoán.
- §03.5 owner-exclusive rollover có được reviewer mật mã chấp nhận không? Nếu không: `expiry` Zether tụt về ≤ 1 epoch, `targetEpoch` quay lại `EncryptedTransfer`, và tỷ lệ revert do trôi epoch (~40% trên Gnosis với EPOCH = 5 block) thành bài toán phải giải.
- Giữ Bulletproofs (2.5M gas, không trusted setup) hay đổi sang Groth16/PLONK (180k–250k gas, có trusted setup, mạch cố định)? Envelope chịu được cả hai vì `innerGasLimit` là trường đã ký, nhưng quyết định này đổi toàn bộ bảng thông lượng ở 04.10.
- Gnosis và Celo đã kích hoạt Prague (EIP-7623 calldata floor) và Cancun (EIP-1153 transient storage) chưa? Cái đầu đổi hằng số trong `requiredOuterGas`, cái sau đổi reentrancy guard từ ~2,900 gas xuống ~200 gas.
- `fee_model` cho luồng Zether: §05.3.4 khuyến nghị `flat` cho v1 vì `bps_of_value` cần một range proof bổ sung (+25% gas) và §12.6.1 cấm phí là hàm của số tiền bí mật. Cần xác nhận `flat` chấp nhận được về mặt nghiệp vụ trước khi viết `_build_zether_metatx`.
- Ai sở hữu `TargetPolicy` governance (allowlist target, cờ `appendsSender`, `maxInnerGas` per target, calldata rule per selector)? Multisig? Timelock? Nó là một quyền có thể dùng để chặn hoặc mở lối thoát tiền.
- Trần `innerGasLimit` phía hub: §12.2 nói reject > 1,500,000, nhưng Zether cần 3,000,000. Đã đề xuất trần per-target on-chain (`targets[ZetherToken].maxInnerGas = 3_200_000`); cần §12 xác nhận đổi từ hằng toàn cục sang per-target.

**Where blockchain.md is wrong / under-specified**

- §10.2.1 struct `MetaTransaction` thiếu `innerGasLimit`: relayer tự chọn gas cho inner call ⇒ cấp thiếu, inner call OOG, forwarder sống sót qua quy tắc 63/64, fee vẫn trả, nonce vẫn tăng. Đây đúng là lỗ hổng GSN v1. Sửa: `innerGasLimit` nằm trong digest.
- §10.2.1 gộp `tokenContract` cho cả `amount` lẫn `fee`. Hỏng ở use case loyalty point đã chốt: user giữ điểm thưởng, không relayer mở nào nhận điểm thưởng làm phí vì không có thị trường thứ cấp. Sửa: thêm `address feeToken` (`address(0)` = dùng `tokenContract`, tương thích ngược).
- §10.2.1 `uint8 mode` không đủ chỗ: 04.4 dùng 3 bit, §05.3.3 xin thêm 1, §05.4.4c reserve thêm 1 ⇒ còn 3 bit cho cả vòng đời contract. Sửa: `uint32 mode`, chi phí 0 gas vì ABI pad cả hai về 32 byte.
- §10.2.1 viết chữ ký MODE_OPEN "KHÔNG bao gồm `feeRecipient` và `relayer` trong digest hash (HOẶC hash với `address(0)`)". Chữ "hoặc" cho ra hai digest khác nhau ⇒ client và verifier lệch ⇒ 100% chữ ký fail. Sửa: chốt canonical zeroing (hash `address(0)`), một type string duy nhất — bỏ trường ra khỏi struct sẽ là một EIP-712 type khác, cần TYPEHASH thứ hai, và ví hiển thị hai type cho cùng một hành động.
- §10.2.1 không có bất kỳ cơ chế nào để target biết `from` là ai. Inner call là `to.call(data)` nên tại `to`, `msg.sender == forwarder`; mọi contract nghiệp vụ thấy 1,000 user khác nhau là cùng một caller. Sửa: ERC-2771 sender suffix, hash `data` chưa có suffix, cờ ở `TargetPolicy`.
- §10.2.1 không nói gì về việc forwarder giữ allowance. Với `to`/`data` tự do, allowance của forwarder là một quỹ chung ai cũng rút được (`to = token, data = transferFrom(victim, attacker, X)`). Sửa: ba `require` + ưu tiên permit/native mixin để không có allowance tồn dư.
- §10.3 đặt deadline 15 phút cho mọi meta-tx. Với luồng tiền đó là một free option 900 giây cho relayer (giữ intent, broadcast lúc có lợi cho mình). Sửa: 900s chỉ cho anchor/log, 300s cho ERC-20 công khai, 120s cho call có đọc state, 60s cho Zether.
- §10.5.2 mục 3 ghi ZKP verify tốn "~180,000 – 250,000 gas". Đó là chi phí của một cặp `ecPairing` (Groth16), không phải Bulletproofs — Bulletproofs verify là multi-exponentiation tuyến tính theo số bit, không có precompile multiexp trên alt_bn128. Con số đúng với tham số §03.4 là 1.72M–2.62M gas tổng cho lời gọi ghép.
- §10.5.3 struct `EncryptedTransfer` giữ `bytes32[2] C_fee` và gọi `uint256 fee` là "phí bí mật". Không thể vừa công khai (calldata) vừa bí mật, và §03.4 đã chốt phí là public scalar ⇒ `C_fee` phải bị xoá khỏi struct và khỏi selector. Điều cấm hai-kênh-phí vẫn giữ, nhưng lý do đổi từ bảo mật sang kế toán (double charge) + §12.6.1.
- §10.4 bảng Finality ghi Celo là "Istanbul BFT (IBFT 2.0), 5 giây, immediate finality". Đó là Celo L1; Celo đã migrate lên Ethereum L2 (OP Stack) từ 2025 với ~1s block và mô hình finality soft/hard của rollup, và fee currency dùng typed transaction CIP-64 chứ không phải cơ chế CIP-52 nguyên thuỷ. Cần kiểm chứng lại trước khi chốt hằng số expiry và finality depth cho Celo.

## 05-open-relayer-network.md  (15335 words)

**Key findings**

- Truc `chain_profile` la truc chinh: o profile private (12-18 thang dau theo quyet dinh #5/#9), section 05 rut gon thanh section 06 cong mot allowlist; deliverable that cua quy 1 la §5.2 (envelope format) va §5.8 (state machine), khong phai §5.4 (chong front-run).
- Federated HTTP intent bus thang libp2p, nhung cursor `(write_date, id)` cua ban 1 bo sot row (bigserial cap truoc COMMIT, Odoo dat write_date trong Python) — fix bang `bus_seq` + lag window 500 ms + overlap 200 + dedup theo intent_id.
- Ngan sach latency Zether la ~20 s (expiry <= 1 epoch, §04.5) chu khong phai 900 s: poll 1 Hz + W=3 s + prove 0.2-2.5 s khong vua, nen intent Zether phai co `W = 0` va kenh `?urgent=1` poll 5 Hz.
- Trong so lottery `sqrt(stake)` cua ban 1 *thuong* sybil chu khong chan: tach stake S thanh k danh tinh cho tong trong so sqrt(k)*sqrt(S) — phai doi sang trong so tuyen tinh + MIN_BOND ~$500 + CAP_SHARE 20% + REP_FLOOR.
- Nguon ngau nhien `keccak(intent_id + snapshot_root)` bi nguoi ky grind mien phi vi `batchId` la 256 bit tu chon (2 keccak/lan thu, ~50 lan de trung relayer mong muon) — phai them `beacon.hash` (block hash tai luc hub nhan) vao seed.
- Diem gia nhap tu do cua cuoc dua relayer la N* = 1 + fee_net/revert_cost ≈ 76, tai do 100% phi cua user bi dot thanh gas lang phi (rent dissipation); soft-exclusivity la thu duy nhat giu duoc >2 relayer trong mang.
- Va cham Zether dat gap 75 lan va cham thuong: hai intent khac nhau cua cung schnorr address deu qua duoc envelope nonce, cai thu hai chay het verify Bulletproofs (~1.79 M gas ≈ $0.0018) roi moi fail o `zetherNonce` — single-flight la bat buoc, khong phai toi uu.
- Intent bus la mot kenh ro ri du lieu thuong mai ma ban 1 bo sot hoan toan: o `chain_profile = private` no la duong duy nhat calldata di ra khoi vanh dai, va di ra *truoc* khi len chuoi — bat buoc mTLS/khong federation, cong mot nguong gia tri chan `MODE_OPEN` tren public bus.
- `dailyCap` cua SponsorshipPool la mot be mat MEV that (tai nguyen chung, hien, co han, doc duoc bang eth_call), khong phai va cham ngau nhien — bien phap la `perRelayerDailyCap`, khong phai commit-reveal.
- Ban ke relayer chi doi soat duoc hoan toan tu chain (fee/subsidy tu event, gas tu receipt cua tx do relayer gui) nen khong bao gio chap nhan con so gas do relayer tu khai; va o quy mo $54/thang thi khong bill tung ky — accrue den nguong 2 000 000 VND.
- Uoc luong `relayer-ref` 300-500 dong cua ban 1 la con so ban hang: ban production thuc te ~1 800-2 400 dong (nonce manager, gas bump, RPC failover, crash recovery deu thieu) — loi the so voi ERC-4337 bundler la 5x, khong phai 30x; ship hai muc `--mode=simple` (~500 dong) va `--mode=production`.
- Subsidy bootstrap $0.01/inclusion cua ban 1 cho relayer $100/thang, duoi nguong chu y cua nguoi sau khi tru VPS/RPC; de nghi $0.05 (tran 10 relayer, 6 thang, ~$30 000) cong `perRelayerDailyCap` + `requireRegistered`.

**Open questions (need a human decision)**

- Ngan sach bootstrap: chap nhan $0.05/inclusion x 10 relayer x 6 thang ≈ $30 000, hay giu $0.01 va chap nhan rang khong co relayer ben thu ba nao? Day la quyet dinh ngan sach, khong phai kien truc.
- `fee_model` cho luong B2B: `bps_of_value` la cho duy nhat co bien loi nhuan that (10 bps tren $2 000 = $2), nhung do cung la luong tien phai bi ma hoa bang Zether — chap nhan `flat` cho Zether (khuyen nghi) hay tra +525 000 gas va +0.1-0.3 s prove cho range proof bo sung?
- Sharding vi treasury thanh K schnorr address de vuot tran 3 456 confidential tx/ngay/address (K = peak_tps x 25 x 1.5): ai so huu job re-balance so du giua K address, va ke toan ghi nhan K address la mot tai khoan hay K tai khoan?
- Co bat buoc ERC-2612 `permit` / Permit2 cho luong fee khong? No xoa han vector 'rut approve sau khi publish' (ty le thiet hai 100:1 cho ke tan cong) nhung cham vao thiet ke token cua §01.
- Ai van hanh hub, va co chap nhan rang hub thay intent truoc moi nguoi khac (tuc co the front-run som nhat) khong? Neu khong, can quy tac tach khoa: hub operator khong duoc chay relayer bang khoa nam trong `RelayerRegistry`.
- Nguong `blockchain.chain.max_public_intent_value_base` (chan `MODE_OPEN` tren public bus cho giao dich lon) dat o bao nhieu, va ai duyet ngoai le?
- Tieu chi that bai cua Phase 2: neu sau 6 thang so relayer co >= 1 inclusion/7 ngay van la 1, co dong y cat toan bo §5.4-§5.6 khoi roadmap va rut ve consortium khong?
- Celo: xac nhan lai chuan fee-currency dang chay la CIP-64 (tx type 0x7b) + CIP-66, khong phai CIP-52 nhu `blockchain.md` §10.2.1 viet — sai o day nghia la relayer khong ky duoc tx nao tren Celo.

**Where blockchain.md is wrong / under-specified**

- `blockchain.md` §10.5.2 muc 3: ZKP verify '~180 000 - 250 000 gas' sai 7-15 lan. Do la chi phi `ecPairing` 2-3 cap, tuc Groth16; Bulletproofs khong dung pairing chut nao. Cau hinh da chot (§03.9, 32/64) ton ~1.79 M gas voi verifier Solidity. Ban 1 cua section 05 cung sai theo huong khac (2.5M-6M, dua tren cau hinh 128/128 ma §03.2 da bac bo) — da sua ca hai.
- `blockchain.md` §10.1 muc 1.b: 'tra phi dich vu off-chain/on-chain dinh ky' cho relayer khong trien khai duoc — contract khong doc duoc event log, nen moi thiet ke 'nop batch receipt hang tuan, pool tu xac minh' deu can mot attestor ky ngoai chuoi (tuc tap trung). Chi co `settle()` inline trong chinh tx la chay duoc.
- `blockchain.md` §10.1 `P2P_POOL` 'p2p gossip / mempool': intent EIP-1776 khong phai tx hop le cho den khi relayer boc lai, nen khong the nhet vao mempool EVM; va xay libp2p rieng cho ~10 msg/s la over-engineering. Chon federated HTTP bus.
- `blockchain.md` §10.1 muc 1: 'Thi truong canh tranh mempool lanh manh ... triet tieu nguy co diem nghen don le'. Nguoc lai: canh tranh khong dieu phoi day EV ve 0 tai N* ≈ 76 va dot 100% phi thanh gas lang phi, ket qua la mang tu tap trung ve 1-2 relayer lon — dung cai no dinh tranh.
- `blockchain.md` §10.2.1: chuan fee-currency cua Celo ghi la CIP-52. Ban dang chay la CIP-64 (tx type 0x7b) cong CIP-66 (`maxFeeInFeeCurrency`); CIP-52 la de xuat cu. Sai o day nghia la adapter Celo khong ky duoc tx nao.
- `blockchain.md` §10.2.1: quang cao 2-D nonce 'loai bo hoan toan Head-of-Line Blocking' khong dung cho luong Zether — `zetherNonce` bi bam vao Fiat-Shamir challenge nen diem serialize nam o tang Zether, khong phai tang envelope; single-flight theo schnorr address la mot head-of-line block co that.
- `blockchain.md` §10.3 muc 3: deadline 15 phut cho moi meta-tx sai voi Zether — §04.5 chot `expiry <= 1 epoch` (20 s tren Gnosis); ky 15 phut la cho relayer quyen broadcast o epoch e+3 khi proof chac chan da hong.
- Ban 1 cua chinh section 05: `MODE_METERED_FEE = 0x04` va cham voi `MODE_REQUIRE_SUCCESS = 0x04` cua §04.4. Vi `mode` nam trong digest, va cham nay khong gay loi bien dich ma gay ra hai y nghia cho cung mot chu ky — mot lo hong xac thuc im lang. Da doi sang 0x08, `MODE_KNOWN_MASK` len 0x0F, commit-reveal doi len 0x10.
- Ban 1 cua chinh section 05: cong thuc fee floor `p90(gas) * base_fee * 1.5` sai don vi (cho ra wei native trong khi `metaTx.fee` tinh bang reward token); va thieu he so rui ro cho `MODE_REQUIRE_SUCCESS` (bubble revert): margin' = (1+margin)/(1-p) - 1.
- Ban 1 cua chinh section 05: `fee_wei`/`stake_wei`/`net_wei` nhu field so vi pham §10.4.1 — mot stake 100 token 18 decimals la 1e20, tran int8 (9.22e18) va hong am tham. Phai la Char decimal string + CHECK regex. Va `models.Constraint` khong tao duoc partial unique index (`UNIQUE (col) WHERE ...` khong phai table constraint) — phai dung `init()` voi `CREATE UNIQUE INDEX IF NOT EXISTS`.

## 06-relay-pool-enterprise.md  (15500 words)

**Key findings**

- Nonce leasing chi an toan neu phan biet duoc 'chua ky' voi 'da ky': mot nonce da co raw tx da ky KHONG BAO GIO duoc tra ve freelist, vi hai tx da ky tren cung nonce nghia la mot hanh dong nghiep vu da huy van co the duoc dao — ban nhap dau truoc sai o day va do la loi tai chinh, khong phai loi van hanh.
- Redis khong the la su that ve nonce (AOF everysec mat 1s ghi, replica async roll back khi failover); chain la su that, Postgres la journal, Redis la cache — nen phai co giao thuc cold start bat buoc tai tao `next` tu `max(getTransactionCount(pending), max_signed_nonce_in_journal + 1)` cong mot generation counter `gen` lam fencing that su.
- Fencing token trong ban nhap dau bi hong: no INCR moi lan cap lease nen khong the phat hien mat quyen so huu shard; phai tach `owner_fence` (chi tang khi doi chu, gan vao ownership lease co TTL 10s) khoi lease token, va consistent hash `% N_workers` khong phai la quyen so huu.
- `max_inflight = 16` khong phai con so tuy y ma la `geth --txpool.accountslots`: cap nonce thu 17 la cap mot nonce chac chan roi vao hu vo, nen backpressure phai nam ngay trong Lua script cap lease.
- Chi phi L1 data tren rollup bi bo sot hoan toan: `eth_estimateGas` chi tra gas thuc thi L2, phai goi them GasPriceOracle `0x42...0F` (OP Stack) hoac NodeInterface `0x...C8` (Arbitrum); voi calldata Zether 2 KB phan L1 chiem 60-90% tong chi phi va bien do giua che do blob re va blob dat la ~1000 lan.
- Ba nhom L2 co hanh vi khac han nhau: OP Stack (Base, Optimism, Celo) VAN co replacement theo pricebump 10%, Arbitrum Nitro thi khong dang tin, va gop chung hai nhom nay (nhu ban truoc) dan den ca hai chinh sach deu sai.
- Con so gas Zether cua note (~180-250k) la con so co hinh dang Groth16 (45k pairing base + 3 x 34k + vai ecMul ≈ 207k), khong phai Bulletproofs; note dung ca hai ngon ngu va hai thu chenh nhau ~30 lan — phai chot truoc khi viet contract vi no doi ca client SDK.
- Co che phi bao mat cua note can BA range statement (`fee`, `v`, `b-fee-v`), aggregate phai pad len bon → 512 bit → MSM ~1.049 diem × 6.000 gas ≈ 6,6M gas/tx, tuc chi ~2 tx/block tren Gnosis; ha xuong n=64 bang cach cho Zether token dung 6 decimals noi bo cat gas ~47% va la mot quyet dinh san pham (dust 10^-6), khong phai ky thuat.
- Velocity limit bang `INCRBYFLOAT` + kiem tra rieng co hai bug (TOCTOU cho phep vuot tran khong xac dinh duoi tai song song, va float tich luy sai so tren bucket tien); phai la mot Lua script nguyen tu, don vi micro-USD so nguyen, co reserve → settle → janitor refund, neu khong bucket ro ri den het TTL.
- MPC SaaS 5-30 sign/s la tran cua ca vault (thuong serialize trong vault), nen so relayer EOA khong lam tang throughput; batch executor la don bay duy nhat, va no chi an toan khi contract co guard EIP-150 63/64 chong insufficient-gas griefing va thu phi ke ca khi inner call revert.
- Ba lop kiem tra RPC khong bat duoc mot provider phuc vu state cu — blockhash bang nhau khong chung minh `eth_call` trung thuc; can lop thu tu la canary `eth_call` pin theo `blockHash` giong nhau tren moi endpoint, va lech mot lan khong duoc eject ngay vi reorg nong tao false positive.
- Breaker chan dau vao nhung khong duoc chan loi thoat: gap-filler va replacement cua mot job R3 da broadcast phai la R4 cung voi `rollOver` va `extend_ttl`, vi throttle chung nghia la de nguyen lo thung nonce hoac de tien treo giua duong.

**Open questions (need a human decision)**

- Bulletproofs hay Groth16 cho Zether verifier? Chenh ~30 lan gas; Bulletproofs khong can trusted setup nhung prove tren mobile mat 1-4s va verify 3,5-6,6M gas, Groth16 verify ~210k nhung can ceremony per-circuit va prove ~15-30s tren WASM. Phai chot truoc khi viet contract.
- Range proof n=64 hay n=128? n=64 (Zether token dung 6 decimals noi bo) cat ~47% gas va gap doi toc do prove tren mobile, doi lai dust duoi 10^-6 khong chuyen bao mat duoc va `deposit` phai tu choi so tien khong chia het cho 10^12. Day la quyet dinh san pham.
- `meta_nonce` tang truoc hay sau inner call? (a) tang sau = relayer tra gas cho tx revert va khong duoc gi, open relayer se khong nhan intent; (b) tang truoc + thu phi luon = relayer doc dot duoc nonce va phi cua user; (c) tang truoc + `antiGriefBond = 3 * fee`. De xuat (c), can mot lan audit rieng.
- Phan tang custody: relayer EOA hot dung Nitro Enclave/SGX thay vi HSM FIPS L3 — danh doi throughput 3 bac do lon (10 → 10^4 sign/s), can chu ky cua compliance vi no cham vao cau chu 'bat buoc HSM/MPC FIPS 140-2 Level 3' cua note.
- 'Private chain' la mot node cua ta hay N node cua N doi tac B2B? Toan bo phan RPC divergence va Finality Gate chi co y nghia o phuong an sau. Can chot truoc khi chon client (Besu QBFT / Quorum / Clique).
- Ai so huu ngan sach gas? Velocity limit co ba tang (agent/tenant/global) nhung chua ro tenant mua han muc hay do la chi phi nen tang; neu tenant tra thi can mot mo hinh tinh phi va no cham vao §09 payment modes.
- SLA cho mot job R3 gia tri lon roi vao `quarantined`: bao lau phai co quyet dinh, ai quyet, va co duong tra tien bang kenh khac (bank transfer) khong. Thieu no thi `quarantined` la mot ho den trong quy trinh B2B settlement.
- Ai chiu chi phi gap-filler (21.000 gas/lan)? De xuat la overhead cua pool vi tenant khong gay ra lo thung, nhung can nguoi duyet dong ngan sach nay.
- Ky hai lan cho mot intent (MODE_RESTRICT_RELAYER truoc, MODE_OPEN sau khi het `T_exclusive`) ton hai chu ky; neu la chu ky HSM/MPC thi do la 10% ngan sach ky o 10 sign/s. Chap nhan, hay bat buoc dung session key re cho lan thu hai?
- MPC provider co cho phep nhieu vault de sharding EOA thuc su nhan throughput khong, va gia license theo vault la bao nhieu? Day la rang buoc thuong mai quyet dinh mo hinh nang luc §06.6.1.

**Where blockchain.md is wrong / under-specified**

- §10.3 muc 2 — 'Duy tri bo dem tang dan bat bien (INCRBY) cho tung dia chi Relayer': INCR cap phat nhung khong ai tra lai. Mot HSM timeout duy nhat de lai mot nonce khong bao gio duoc phat song, va moi tx sau do cua vi do nam vinh vien o trang thai queued. Sua: nonce leasing co TTL, freelist, `signed` set, va reconciliation voi chain.
- §10.3 muc 2 — 'Redis Cluster voi co che monotonic distributed lock': Redis Cluster khong phai lock service co fencing, va Redlock mat lock khi replica promote. Sua: loai bo nhu cau lock bang ownership lease mot-worker-mot-shard co fencing token, Redis chi giu state.
- §10.3 muc 2 — 'phi gas cao hon 15% neu treo qua 60 giay': (a) 60 giay la 5 block tren L1 (qua som, gay bao replacement luc nghen mang) va 12 block tren Gnosis (hop ly) — nguong phai tinh bang block; (b) 15% mot lan la khong du, lan bump thu hai phai >= 1,10 lan gia DA bump, va base fee co the tang 12,5%/block. Sua: leo thang hinh hoc `ceil_bump` so nguyen co tran rieng cho tip va max_fee.
- §10.5.2 muc 3 — 'xac thuc ZKP voi chi phi gas toi uu (~180.000 - 250.000 gas)': day la con so cua mot verifier Groth16 (3 pairing + vai ecMul), khong phai cua Bulletproofs ma chinh note khai o cung muc. Bulletproofs n=128 voi co che fee cua note can ~6,6M gas — lech ~30 lan. Hai cau trong note mau thuan nhau.
- §14.2.8 — 'Simulation Gate ... voi ty le revert bang 0%': khong dat duoc va nguy hiem vi khien nguoi ta bo do luong. Sim doc state tai N, tx thuc thi tai N+k. Sua: SLO divergence < 0,5% tong broadcast, < 0,05% cho R3/R4, cong mot bang phan loai 9 nguon divergence va quy trinh xu ly tung loai.
- §10.4 bang finality — 'Celo | 5 giay | Istanbul BFT (IBFT 2.0) | 1 Block Confirmation': loi thoi ca ba cot. Celo da chuyen sang OP Stack L2 thang 3/2025, block 1s, co sequencer va co L1 data fee. He qua: breaker Celo can ba chieu do chu khong mot, va bang `stuck_after_blocks` phai doi.
- §10.5.3 muc 5 — co che 'Confidential Fee Deduction' yeu cau ZKP chung minh dong thoi `fee >= 0`, `v >= 0`, `b-fee >= 0`, `(b-fee)-v >= 0`: do la ba range statement doc lap, aggregate phai pad len bon → 512 bit → gas verify tang tu ~3,5M len ~6,6M. Note khong noi ra chi phi cua chinh co che phi cua no.
- §10.1 muc 2 + §14.2.8 — dat Tenderly trong duong broadcast bat buoc: o 24.000 tx/ngay do la 720k don vi mo phong/thang, mot dong chi phi khong ai du toan. Sua: Tenderly chi dung hau kiem divergence; hot path dung `eth_call` + `debug_traceCall` tren archive node cua chinh minh.
- §10.5.3 — `simulateAccounts(schnorrAddresses, epoch)` duoc mo ta la dam bao '100% ty le chung minh ZKP thanh cong', nhung khong co gi trong note buoc tx phai dao dung epoch do. Voi Δ=5 block tren Gnosis, tre 25s la proof vo hieu. Sua: `zether_epoch_deadline_block`, va khi qua han thi CANCEL chu khong speed-up.
- §10.3 muc 2 gop hai khong gian nonce lam mot: `meta_nonce(from, batchId)` la nonce cua nguoi dung trong contract, nonce EOA la cua relayer — chung doc lap va relay pool phai quan ly ca hai. Relay pool khong bao gio duoc cap `batchNonce` (chu ky phu len no), chi duoc kiem tra truoc broadcast va ghim block cua lan doc do.

## 07-custody-providers.md  (18434 words)

**Key findings**

- Tach prover la ket luan trung tam moi (§07.2b): phan phu thuoc `x` cua mot chung minh Zether KHONG phai Bulletproofs (range proof khong dung `x` lam witness) ma chi la 2 phep nhan vo huong tren diem cong khai + 1 scalar response `s = k + c*x mod r`; dieu do thu gon TCB enclave tu 'ca prover arkworks' xuong mot trait `ZetherKeyOracle` < 300 dong, va lam cho threshold hoa `x` thanh mot giao thuc chuan chu khong phai nghien cuu.
- Custody phai la HAI truc doc lap `auth_custody` (ECDSA/EdDSA, HSM lam duoc) va `conf_custody` (giu `x`, giai ma ElGamal, prove), chon rieng theo tung money flow va chain profile; model `blockchain.custody.policy` la thu hien thuc hoa 'chon luc deploy' cua locked #6 va ban nhap truoc thieu han no.
- Kha nang khoi phuc va tinh non-custodial la CUNG mot truc nguoc chieu nhau: 1-of-1 = khong bao gio khoi phuc duoc quyen chi tieu; t-of-n = khoi phuc duoc tren MOI chain khong can `recoverAccount`, doi lai platform tro thanh mot ben co the chi tieu, tuc nghia vu custody. Quyet dinh t-of-n phai lam LUC TAO TAI KHOAN, khong sua duoc sau.
- Cau hinh backup quyet dinh dust: passkey PRF dong bo ~0.05-0.2%/nam vs seed phrase tu chep ~0.5-2%/nam vs device-bound ~3-8%/nam; voi 10.000 outlet x 500k VND, dust tich luy 5 nam la 12-50 trieu / 125-500 trieu / 750-2.000 trieu VND tuong ung - chenh 10-40x o cung chi phi ky thuat.
- `elgamal_decrypt` la mot decryption oracle tren `x`: `decrypt(C, D)` voi `D` do ke tan cong chon tra ve log cua `C * D^{-x}`, tuc mot ECDH oracle. Signer BAT BUOC tu choi moi `(C,D)` khong chung minh duoc la trang thai that tren chain (`ChainWitness`).
- Signer la mot service chu khong phai mot ham: MPC SaaS p50 300ms-3s se can kiet worker pool cua Odoo o 6-20 request dong thoi. Moi loi goi signer phai qua hang doi `blockchain.signing.request` voi idempotency key, va thieu `idem` thi moi retry la mot giao dich trung tren chain.
- Nitro Enclave khong co network stack (chi vsock) va khong co RTC; phai viet vsock proxy (la toan bo I/O cua enclave, nen nam trong scope audit) va khong duoc enforce `deadline` bang dong ho enclave - dung block number.
- Chung nhan FIPS 140-2 chuyen sang CMVP Historical List ngay 2026-09-21, tuc ba tuan nua; moi cau 'FIPS 140-2 Level 3' trong `blockchain.md`, ho so thau va hop dong phai doi thanh 'FIPS 140-3 Level 3 hoac chung nhan CMVP duong thoi' truoc moc do.
- Chu quyen du lieu la rang buoc chan lua chon: AWS/GCP khong co region tai VN, nen Nitro/Confidential Space kich hoat nghia vu ho so chuyen du lieu xuyen bien gioi (ND 13/2023). Doi lai: on-prem 2 HSM + host SEV-SNP tai VN ~$60-90k capex + ~$2.900/thang, +3-6 thang, phai tu xay chuoi attestation.
- Cau hinh toi thieu (KMS + on_device, ~$107/thang) du cho loyalty va end-user payment - 2 trong 3 use case cua locked #3; chi B2B settlement moi can HSM + enclave ($2.900-9.750/thang). Ke hoach nen bat dau tu day.
- Restore dump production sang staging la su co kinh dien va can ba lop chan doc lap: mTLS cert khac nhau theo moi truong (lop duy nhat dung trong moi truong hop), `data/neutralize.sql`, va `blockchain.environment` doi chieu voi environment gan vao cert. `res.company` phai co `blockchain_tenant_uuid` bat bien vi `res.company.id` khong on dinh giua cac database.
- Omnibus custodial bi cam cho moi luong co Zether: no lam moi giao dich thanh 'platform -> platform', pha huy do thi chuyen tien on-chain va sup toan bo lap luan 'tuan thu 100% AML/KYC' cua §10.5.1.

**Open questions (need a human decision)**

- Cau hinh `x` mac dinh cho tung money flow: 1-of-1 hay t-of-n? Day la danh doi trung tam giua 'khoi phuc duoc' va 'khong phai custodian'. Can luat su xac nhan: giu mot share 1-of-3 cua khoa B2B, khi khong the chi tieu mot minh, co cau thanh custody theo ND 52/2024 khong - chua co tien le o VN.
- Chap nhan rang `x` khong nam trong bien FIPS Level 3 luc su dung? Neu khong thi phai bo Zether hoac tra tien cho Functionality Module (~4-8 tuan phat trien sau §07.2b, cong chu ky tai chung nhan CMVP 12-24 thang, sau chu so USD).
- Enclave dung nen nao va du lieu o dau: AWS Nitro (KMS attestation san co, du lieu o Singapore, 2-4 tuan) hay AMD SEV-SNP tu van hanh tai VN (chu quyen du lieu, +4-8 tuan ky su, +$60-90k capex)? Hai duong khong dung chung code attestation - phai chot truoc khi viet `custody/enclave.py`.
- `C_audit` bat buoc o dau? Chi phi $0.00005/tx nhung no thay doi calldata va struct cua contract, tuc phai chot TRUOC khi deploy, khong sua duoc sau.
- Dust do mat khoa hach toan the nao: no tiem tang, hay thu nhap khac sau N nam khong hoat dong? Co luat escheatment/tai san vo chu ap dung khong? Can ke toan truong va luat su.
- Ai giu share DKG thu 4 va thu 5 cua `y_audit` (de xuat 3-of-5, mot share kiem toan doc lap, mot share niem phong offline)? Can ten nguoi va van ban uy quyen.
- Bat `custody_mode = 'custodial'` o Viet Nam truoc khi khung phap ly ro? De xuat mac dinh khong. Kem cau hoi: co yeu cau kinh doanh nao doi omnibus khong - neu co thi phai bo Zether o luong do.
- Bao hiem custody: co mua khong va o dau? MiCA Art. 75 bat boi thuong khi mat khoa neu ban sang EU. Can bao gia that truoc khi dinh gia dich vu.
- Ai van hanh `confidential-signer` on-call 24/7? Neu la cung doi van hanh Odoo thi phai chap nhan `on_device` lam mac dinh cho moi thu co the, de signer down khong dung luong nao cua nguoi dung cuoi.
- Nguong gia tri nao bat buoc `auth_custody = 'hsm'` thay vi `enclave` cho relayer? De xuat: moi khoa co the mint/pause/upgrade dung HSM khong ngoai le; relayer EOA dung enclave voi runway tran 4 gio.

**Where blockchain.md is wrong / under-specified**

- `blockchain.md` §10.3.1, §10.5.2 muc 1, §14.2.8: 'khoa bi mat x luu an toan trong HSM/MPC FIPS 140-2 Level 3' - KHONG thuc hien duoc. HSM la signing oracle: no nhan digest, tra chu ky, tren duong cong trong firmware da chung nhan. BN254 khong co OID trong danh muc nao cua CloudHSM/Cloud KMS/Managed HSM, va khong HSM thuong mai nao expose phep `k + c*x mod r` tren scalar field tuy y. Sua: `authKey` (quyen chi tieu, secp256k1) trong HSM; `encKey x` trong enclave co attestation hoac chia t-of-n, va compromise cua no la read-only breach theo thiet ke.
- `blockchain.md` dung 'FIPS 140-2 Level 3' xuyen suot: chung nhan FIPS 140-2 chuyen sang CMVP Historical List ngay 2026-09-21. Moi dieu khoan hop dong tro toi 'FIPS 140-2 validated' se tro toi mot danh muc lich su. Sua thanh 'FIPS 140-3 Level 3, hoac chung nhan CMVP duong thoi tuong duong'.
- `blockchain.md` §10.5.2 hoan toan khong nhac toi mat khoa. Mat `x` = mat vinh vien quyen chi tieu va, tren public chain 1-of-1, mat ca so lieu. He qua ke toan nghiem trong hon: `ZetherToken` giu N token ERC-20 lam tai san dam bao, tong so du giai ma duoc tut duoi N, va invariant total-supply §1.9 van dung ve so sach trong khi sai ve kinh te. Phai co mot dong trong so cho dust nay.
- `blockchain.md` §10.5.2 muc 3 uoc 'ZKP verify ~180.000 - 250.000 gas': con so do chi dung cho vai phep ecAdd/ecMul, khong phai mot Bulletproofs range proof 128-bit; thuc te 1,2M-2,5M gas (§06.4 da sua). Section 07 lay 2,0-2,5M lam co so tinh ty le gas cua lop passkey.
- `blockchain.md` §10.5.1 tuyen bo 'tuan thu 100% AML/KYC' chi bang cach lo danh tinh nguoi gui/nhan - nhung neu bat che do custodial omnibus (mot `schnorrAddress` chung cho ca nghin khach), moi giao dich tren chain tro thanh 'platform -> platform' va do thi chuyen tien mat het y nghia voi auditor. Omnibus phai bi cam cung cho moi luong co Zether, khong phai 'khong khuyen khich'.
- `blockchain.md` mac dinh Agent chi giu Ephemeral Session Key 1-8 gio la du an toan; §12.5 va §07.9 chi ra thieu mot dieu: FIPS L3 chong TRICH XUAT khoa, khong chong LAM DUNG khoa. Mot HSM PKCS#11 ky bat ky 32 byte nao. Phai co `SigningPolicyService` (to-allowlist, selector, tran value, tran tich luy theo gio) nam CUNG PHIA voi signer, khong nam trong Odoo - nguoc lai HSM chi la mot cach dat ten khac cho 'khoa nong'.

## 08-chain-adapters.md  (13200 words)

**Key findings**

- Ranh giới Odoo <-> relay-pool truoc day bo trong hoan toan: chot transactional outbox (blockchain.relay.job + SELECT ... FOR UPDATE SKIP LOCKED) thay vi HTTP dong bo, vi chi outbox moi ghi job nguyen tu cung account.move trong mot transaction PostgreSQL.
- ChainAdapter phai co 12 method chu khong phai 9: thieu preflight() thi chain doi duoi chan (Celo -> L2 da chung minh), thieu get_balance() thi relayer pool chet im lang, thieu decode_event() thi khong khop duoc event voi job.
- Mo hinh gas Zether tinh tu gia precompile EIP-1108 (ecMul 6.000 gas, khong co MSM precompile tren EVM): 4x128-bit ~6,6M gas, 4x64-bit ~3,5M, 3x64-bit voi fee cong khai ~2,7M — quyet dinh nay doi ban kha thi cua Hedera va Gnosis.
- Lo hong kinh te cua EIP-1776: neu inner call revert thi lenh chuyen fee cung revert, relayer tra gas nhan 0 — forwarder BAT BUOC tach validation khoi execution va thu fee ke ca khi inner that bai; keo theo blockchain.relay.job can HAI field trang thai chain_state/business_state.
- Ba trong sau he (TON, Soroban, va Sui/Hedera neu chon Ed25519) doi signer ky Ed25519 THUAN (khong ky duoc digest da hash) — day la blocker mua sam cho §07 HSM FIPS 140-2 L3, phai xac nhan vendor truoc khi khoa chain order.
- Mot RPC noi doi la vector tan cong re nhat: finality_quorum mac dinh 2 endpoint doc lap (hai key Alchemy KHONG doc lap) phai khop blockhash + receipt.status truoc khi _set_done; private profile chi tin node cua chinh minh.
- blockchain.rpc.endpoint khong duoc co field url: URL cua moi vendor nhung API key trong path nen URL CHINH LA secret — luu trong ir.config_parameter qua secret_ref, dung lai dung cai sai ma password=True tung che dau.
- BFT khong fork, no DUNG: mat quorum QBFT (2/4 validator chet) lam rail thanh toan dung im hoan toan, khong co degraded mode — can RTO 15 phut, hot standby snapshot <=5 phut, validator o >=3 vung loi, va dien tap mat quorum hang nam.
- Tren private chain gas=0 xoa mat CA hai thu: la chan DoS (thay bang 3 lop permissioning) va co che uu tien (thay bang tach EOA relayer theo lop + admission control) — dieu thu hai bang nhap hoan toan bo sot.
- Cosmos co loi thoat thu ba re hon han: mot chain co san x/evm (Injective/Cronos/Evmos) da co precompile alt_bn128 vi nhung nguyen EVM cua geth, chay contract Zether khong sua mot dong — re hon appchain + module Go.
- Stellar fee-bump khong tieu sequence cua fee source: mot tai khoan relayer duy nhat phuc vu so tx song song khong gioi han, trong khi EVM can 7 EOA cho 100 tx in-flight (geth txpool.accountslots=16).
- Tang truong du lieu private chain: ~2,5 KB calldata/confidential tx, 10.000 tx/ngay => ~100 MB/ngay ~36 GB/nam full node Bonsai; phai chot Bonsai cho validator + mot archive node rieng ngay ngay dau vi doi storage format sau do la resync tu genesis.

**Open questions (need a human decision)**

- Don vi Zether token: 6 decimals + range proof 64-bit (re hon 47-59% gas, tran van $18 nghin ty) hay giu 18 decimals + 128-bit nhu blockchain.md dang viet? Quyet dinh nay doi ban kha thi cua Hedera va Gnosis nen phai chot truoc khi khoa chain order.
- Fee trong Zether la cong khai (uint256) hay bi mat (C_fee)? Note dang co ca hai va khong co menh de ZKP nao buoc chung khop — du thua hoac lo hong soundness.
- Custody da chon co ky duoc Ed25519 thuan khong? Neu khong: chap nhan ECDSA tren Hedera + secp256r1 tren Sui va hoan TON/Soroban, hay doi tu HSM sang MPC provider?
- Sui: Groth16 native (can trusted setup ceremony, proof 128-192 byte) hay Bulletproofs viet tay bang group_ops (dat gas, khong can setup)?
- Sui: co chap nhan thiet ke Zether tren Sui khac tren EVM (bo epoch/rollOver vi object model da tuan tu hoa) tuc la hai bo audit, hai bo tai lieu?
- Cosmos: chon mot chain co san x/evm de chay contract Zether nguyen xi, hay van hanh appchain rieng voi module Go x/zether dung gnark?
- Celo sau khi thanh L2 co con giu vi tri thu hai trong chain order khong, khi loi the immediate finality da mat va chi con feeCurrency? Ung vien thay the: Polygon PoS (milestone 1-2 phut) hay Base?
- Validator set cua Besu private: ai la validator, o may vung loi doc lap, va RTO khi mat quorum la bao nhieu? Neu ca 4 do mot phap nhan van hanh tren cung ha tang thi bat bien la cam ket to chuc, khong phai tinh chat ky thuat.
- Nguong _set_done tren L2: chap nhan soft finality (1 giay, rui ro sequencer) hay bat buoc hard (15-25 phut)? Can mot ma tran money_flow x finality_level, khong mot nguong chung.
- Ai van hanh relay-pool? No nam ngoai addon, ngoai Odoo, va la thanh phan duy nhat giu khoa ky — team nao on-call va deploy o dau so voi Odoo?

**Where blockchain.md is wrong / under-specified**

- blockchain.md §10.4 ghi Gnosis finality 12,8 phut — sai, do la so cua Ethereum (2 epoch x 32 slot x 12s). Gnosis co 16 slot/epoch x 5s = 80s/epoch => finality ~160-240 giay (~3-4 phut). Dat 12,8 phut lam nguong _set_done bat khach hang cho gap 4 lan can thiet tren chinh chain #1.
- blockchain.md §10.4 ghi Polygon PoS 25-30 phut — so cua thoi truoc Heimdall milestone (2023). Bor gio co finality xac dinh ~1-2 phut; 30 phut chi con dung cho checkpoint phuc vu cau noi ve L1.
- blockchain.md §10.4 ghi Celo 'IBFT 2.0, immediate finality, ~5 giay' — het dung tu khi Celo mainnet chuyen sang L2 tren OP Stack (cong bo 3/2025). Phai dat finality_mode='l1_batch'; de nguyen se bao done truoc khi tien an toan.
- blockchain.md §10.1 va §14.2.8 yeu cau Simulation Gate dat 'ty le revert bang 0%' — khong dat duoc, vi estimateGas chay o block N con tx vao block N+k. Thay bang ngan sach revert co so: 0,5-2% tren public co mempool mo, <0,1% tren private permissioned.
- blockchain.md §10.5.3 nang range proof len 128-bit vi 18 decimals — dung ve viec 2^32 vo dung, sai ve don bay. Don bay dung la dinh nghia don vi Zether o 6 decimals (2^64-1 = 18 nghin ty USD), giu range proof 64-bit, giam ~47% gas verify va lot tran 15M gas/tx cua Hedera voi bien an toan.
- blockchain.md §10.5.3 struct EncryptedTransfer co CA 'uint256 fee' cong khai lan ciphertext 'C_fee' ma khong co menh de ZKP nao buoc hai cai khop nhau — du thua hoac lo hong soundness. Giu fee cong khai (dung triet ly Public Relayer Fee), bo C_fee, thay bang sigma proof dang thuc => bot mot menh de range, ~2,7M gas.
- blockchain.md §10.5 mo ta EIP-1776 wrapper cho Zether nhung khong noi: neu inner call revert thi lenh chuyen fee cung revert va relayer tra gas nhan 0 — mot vector tan cong gan nhu mien phi tren mang open relayer. Forwarder phai tach validation khoi execution nhu ERC-4337 lam.
- blockchain.md §10.2.5 trich 'SEP-0043 (Soroban Invocation Authorizations)' — nhieu kha nang la citation sai. Reference chuan tac la CAP-0046-11 voi XDR SorobanAuthorizationEntry/SorobanCredentials; SEP-0041 la Token Interface.
- blockchain.md §10.2.6 dat ICS-29 fee middleware canh x/feegrant nhu the cung loai — ICS-29 CHI cho relay packet IBC, khong lien quan toi sponsoring giao dich cua user; x/authz lai la uy quyen dung (user khong ky gi luc thuc thi), rui ro khac han meta-tx.
- blockchain.md §10.5.2 uoc tinh gas xac thuc ZKP '~180.000-250.000 gas' — qua thap mot bac. Do la chi phi cua vai lan ecPairing, khong phai cua mot Bulletproof verify: MSM 2N+2log2(N)+7 diem khong gop duoc tren EVM (khong co precompile MSM) nen 4x128-bit roi vao ~6,6M gas.

## 09-payment-modes.md  (13200 words)

**Key findings**

- Che do tich hop khong the la mot Selection trong mot addon: `payment` depend `onboarding`+`portal`, va `account_payment` khai `'auto_install': ['account']` — nghia la tren bat ky DB nao co Accounting, cai `dms_blockchain_payment` se TU DONG keo `account_payment` vao, `_post_process()` se goi `_create_payment()`, va thieu `journal_id` se lam giao dich `done` fail im lang trong cron sau khi tien da ve chain.
- Interface handler cua ban nhap (`open_request`, `on_final`, `on_reorg`) la method PUBLIC tren mot Odoo model, tuc la RPC endpoint: bat ky user co ACL read cung goi duoc `/json/2/blockchain.payment.handler.x/on_final` va ep mot `_set_done`. Da doi thanh `_on_*` private + mot facade public duy nhat `payment_request_open` khong nhan `company_id`/`allowed_company_ids` tu client.
- `_set_done()` KHONG keo theo `_post_process()`: post-processing chi chay tu `/payment/status/poll` (nguoi dung mo trinh duyet) hoac cron `payment.cron_post_process_payment_tx` mac dinh 10 phut. Nguoi tra khong bao gio mo app ⇒ khong ai poll ⇒ hoa don khong duoc xac nhan trong 10 phut. Phai goi `tx._post_process()` truc tiep + `ir.cron._trigger()` tu watcher.
- `ir.cron` co do phan giai toi thieu 60 giay, nen `ENDUSER_PAY` (yeu cau do tre giay) khong the dua vao lich cron: watcher phai goi `_trigger()` sau moi block, cho do tre end-to-end ~5-8s tren Gnosis soft finality; cong them mot bus notification cho man hinh thu ngan.
- `available_currency_ids` la stored computed voi `@api.depends('code')`; them token vao `accepted_token_ids` khong recompute no, va `_get_compatible_providers` loc theo chinh field stored do ⇒ provider bien mat khoi checkout ma khong co loi nao. Phai override `_compute_available_currency_ids` voi `@api.depends('code', 'accepted_token_ids')`.
- `account_payment._create_payment()` doc `self.provider_id.journal_id` — mot journal cho mot provider. Quyet dinh: mot `payment.provider` cho moi (company, chain, settlement token), voi journal va outstanding account rieng, de kiem tra doi soat so du theo token cua §15 con lam duoc.
- Vong lap cron cua ban nhap (`for obs: _process(); commit()`) khong co try/except: mot observation hong chan toan bo hang doi (head-of-line blocking). Da thay bang try/except/rollback tung dong + `retry_count` + activity sau 5 lan that bai.
- Zether khong the chay qua M1 vi nguon su that ve so tien la so du giai ma cua nguoi nhan, khong phai mot su kien on-chain; `_extract_amount_data` tra `None` la duong hop phap duy nhat (tien le: `payment_custom` lam dung nhu vay), va he qua la M13 phai la mot bien the cua M4, khong phai cua M1.
- Rang buoc that su chan Zether tren public chain khong phai gia gas ($0.0038/tx tren Gnosis) ma la block space: 1.88 M gas/tx × block limit 17 M × block 5s ⇒ tran ~31,300 tx/ngay toan mang Gnosis o muc chiem 20% block space. Private chain (~500 tx/s) la lua chon duy nhat, dung nhu quyet dinh #5.
- Da bo sung 7 che do ban nhap thieu: M0 (`payment_custom` — chay duoc trong tuan dau, 0.2 pw, va la duong lui vinh vien), M14 auto-convert, M15 netting (giam 20,000 → 500 giao dich/thang cho 500 distributor, don bay lon nhat va khong can Solidity), M16 fiat on/off-ramp (cong phap ly, khong phai task), M17 batch disburse, M18 voucher ky off-chain, M19 payment channel (goi ten de bac bo).
- Ty gia fiat↔token khong duoc noi den o dau trong note lan ban nhap: da them `blockchain.payment.quote` voi ty gia luu dang phan so hai so nguyen (khong Float), `rate_source` bat buoc, `quote_validity_seconds` mac dinh 900s cho cap fiat-stablecoin va 120s cho token bien dong, cung chinh sach reprice khi quote het han truoc khi tien ve.
- `soft_final_max_amount` phai dat bang so tien chiu duoc khi mat mot lan, khong bang ton that ky vong: voi P(reorg) ≈ 1e-4, 1M tx/nam, $5/tx thi E[loss] ≈ $500/nam — chap nhan duoc; nhung cung phep tinh cho mot giao dich $50,000 cho E = $5 ma phuong sai thi khong chiu duoc. De xuat $200/tx + `soft_final_exposure_cap` $5,000.

**Open questions (need a human decision)**

- Chinh sach partner cho nguoi tra vo danh: `anonymous_partner` (mot partner ky thuat), `partner_per_wallet` (co the sinh 200,000 `res.partner` mot thang trong mot chien dich loyalty), hay `require_known_partner`? De xuat mac dinh theo flow, nhung nguong Travel Rule $1,000 cua FATF co the bien no thanh quyet dinh phap ly chu khong phai ky thuat.
- Mot `payment.provider` cho moi (chain, token) — sach ve ke toan nhung N provider hien trong checkout. Chap nhan N ≈ bao nhieu truoc khi chuyen sang phuong an override `_create_payment` (dat hon ve rui ro)?
- M2 (acquirer) hay tu chay? Nguong hoa von uoc ~$300k doanh so crypto/nam (1% phi acquirer vs ~$1,500-3,000/nam van hanh watcher+RPC). Can con so doanh so du kien that de chot.
- Doanh nghiep co chap nhan `finality_mode='soft'` cho `ENDUSER_PAY` (do tre 5s, rui ro reorg co the dinh luong) hay bat buoc `hard` (160s tren Gnosis, khong ban duoc tai quay)? Day la quyet dinh kinh doanh, khong phai ky thuat.
- M16 fiat on/off-ramp VND: co doi tac duoc cap phep nao chua? Neu khong, token bi ket trong he sinh thai va `OUTLET_COLLECT` (noi tien mat chiem phan lon) khong dong duoc vong. Day la rui ro nghiem trong nhat cua ca du an.
- Co bat M9 (escrow) khong? No la che do duy nhat giu so du trong hop dong, nen la che do duy nhat BAT BUOC audit ben ngoai ($25-40k, 3-5 tuan) truoc khi bat.
- `ref_mode = 'plain'` tren private chain lam debug de hon nhieu nhung dat reference nghiep vu len so cai — co dung khong neu sau nay private chain duoc mo cho doi tac doc?
- P(reorg vuot depth 1) tren Gnosis: con so 1e-4 trong tai lieu la UOC TINH khoi dong. Phai lay histogram do sau reorg that tu indexer §11 trong 30 ngay truoc khi chot `soft_final_max_amount`.

**Where blockchain.md is wrong / under-specified**

- Note ghi Gnosis hard finality '~12.8 phut' (bang §10.4). Sai: 12.8 phut la con so cua Ethereum (32 slot × 12s × 2 epoch). Gnosis co 16 slot/epoch va slot 5s ⇒ 2 epoch ≈ 160s (~2.7 phut). Sai lech 4.8 lan, va no doi hoan toan tinh kha thi cua `finality_mode='hard'` cho ban le.
- Note mo ta Celo la 'Istanbul BFT (IBFT 2.0), 1 Block Confirmation (Immediate Finality), ~5 giay'. Loi thoi: Celo da chuyen thanh L2 OP-Stack tren Ethereum (2025), block ~1s, soft finality tu sequencer va hard finality chi khi batch duoc finalize tren L1 (~15-20 phut). §03.3.8 cua chinh bo tai lieu nay cung da coi Celo la L2. Mot Celo adapter viet theo mo ta cu se coi soft la hard — tuc la ghi so cho mot giao dich con co the bi dao nguoc.
- Note cite CIP-52 cho co che tra gas bang stablecoin. CIP-52 la thu muc fee currency; **CIP-64** moi la transaction type mang truong `feeCurrency`. Adapter can so hieu tx type, khong phai so hieu CIP cua thu muc.
- Note (va ban nhap §09.10) uoc Zether `transferConfidential` ~180,000-250,000 gas. Sai 15-20 lan. §03.3.7 da truy ra: 45,000 + 4 × 34,000 = 181,000 la chi phi verify mot Groth16 SNARK tren alt_bn128 (4 pairing) — Bulletproofs khong dung pairing. Con so dung: 1.88 M gas (32/64) den 3.87 M (128/128). He qua that khong phai chi phi ($0.0038 tren Gnosis) ma la tran throughput 31,300 tx/ngay toan mang.
- Note gia dinh moi giao dich di qua Gateway cua doanh nghiep. Truong hop nguoi tra dung vi rieng, khong bao gio cham app — chiem phan lon giao dich B2B thuc te — khong duoc nhac den, va no la truong hop kho nhat vi `ERC20.transfer` khong co truong memo.
- Note khong noi gi ve lop `payment` cua Odoo, ve refund, ve ty gia fiat/token, ve fiat on/off-ramp VND, va ve viec lam gi khi mot soft-final bi reorg SAU khi da ghi so.
- Ban nhap: `support_manual_capture = 'none'` tren `payment.provider` la gia tri khong hop le — selection cua provider chi co `[('full_only',...), ('partial',...)]`; `'none'` chi hop le tren `payment.method`. Dung `False` cho provider.
- Ban nhap: xac suat va cham reference 40 bit voi 10^7 request duoc ghi la 4.5e-2. Sai ba bac: p ≈ n²/2N = 1e14/2.199e12 = 45 ⇒ va cham gan nhu chac chan. Ket luan (dung 64 bit) van dung nhung con so dan toi no phai sua.
- Ban nhap: '1 dong sub-ledger ≈ 400 B, 800k dong/thang ≈ 330 MB/nam'. Sai hai lan (bo qua index, va tinh nham thang thanh nam). Theo co so §11.9 (≈800 B thuc te ke ca index): 640 MB/thang = 7.7 GB/nam.
- Ban nhap: cot chi phi Celo trong bang gas khong khop chinh gia dinh cua no (CELO=$0.50, +50k intrinsic) — dong 65,000 gas phai ra $0.000288 chu khong phai $0.00033. Da tinh lai toan bo bang bang mot cong thuc duy nhat viet ro.

## 10-odoo-addon-design.md  (15850 words)

**Key findings**

- Topology chot: 4 addon (`dms_blockchain` core depends chi `['base','mail']`, plus `_payment`/`_account`/`_bridge`), giu ten `dms_blockchain` (doi ten sau deploy ton ~700 dong `ir_model_data` + 24 ALTER TABLE RENAME), va bridge dung `auto_install: True` chu KHONG `auto_install: ['dms']` — kiem tren `odoo/modules/module.py:445-458`, dang list se keo `dms_blockchain` vao khi ai do cai `dms` mot minh.
- `fields.Char(size=N)` la `deprecated` o Odoo 19: cot van la VARCHAR khong gioi han va `convert_to_cache` **cat chuoi im lang** (`value[:self.size]`) — ban nhap dung `size=42`/`size=66` tren address/tx_hash, tuc se pha du lieu; da bo het `size=` va thay bang `models.Constraint` CHECK theo `chain_family`.
- Ban nhap ep CHECK `^0x[0-9a-f]{40}$` vo dieu kien tren `address` va `size=66` tren `tx_hash` — chan hoan toan 5 ho non-EVM (Hedera `0.0.x@s.ns`, TON base64 48, Sui 66 hex, Stellar StrKey base32 56 uppercase, CosmWasm bech32 39-90); da thay bang CHECK tho (`length BETWEEN 20 AND 128`) + CHECK co dieu kien theo `chain_family` (stored related) + `@api.constrains` goi adapter §08.
- Odoo 19 co `models.Index` va `models.UniqueIndex` (`odoo/orm/table_objects.py:125,185`) — giai quyet duoc partial unique index ma `models.Constraint` khong lam duoc; `UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce)` tuyet doi cua ban nhap lam **khong the thu lai** mot metatx het han (EIP-1776 `meta_nonce` chi tang khi thanh cong, lane khong bi tieu), da doi thanh `UniqueIndex` partial `WHERE metatx_state NOT IN ('expired','failed')` + `attempt_seq`.
- Hand-wave lon nhat cua ban nhap la "Odoo goi worker qua `requests`": mot HTTP call trong transaction cho ra tx da broadcast nhung Odoo rollback (hoac nguoc lai, hai tx). Da thay bang **transactional outbox** `blockchain.outbox.job` (`idempotency_key` UNIQUE, `queued→sent` commit truoc khi goi, backoff 2^n, `sent` treo >10 phut → `dead`), at-most-once phia Odoo + exactly-once phia worker.
- Bon model bat buoc ma ban nhap thieu: `blockchain.contract.deployment` (khong co no thi `verifying_contract` la Char tu do va Policy Gate allowlist khong co cho song), `blockchain.approval.policy`/`.request` (maker-checker cho tien ra), `blockchain.security.event` (§07.13 da tham chieu), `blockchain.outbox.job`.
- ACL cua ban nhap co mot lo that: hai rule tren `blockchain.account` deu gan cho viewer/operator va **khong** co rule cho manager — theo dai so rule cua Odoo (rule khac nhom la OR, roi AND voi global), manager ke thua treasury van **khong nhin thay vi treasury**. Da tach dieu kien company ra rule global va them `rule_account_manager_all` + `rule_account_auditor_all`.
- `field.groups` o Odoo 19 KHONG con am tham bo cot: `read()` khong tham so thi loc, nhung `read(['signer_ref'])`, `search_read`, va domain tren field do deu **raise `AccessError`** (`orm/models.py:2928, 3465, 3553`); `groups='.'` (`NO_ACCESS`) chan ca `group_system`; va `groups` **di theo qua related/`_inherits`** (`orm/fields.py:777`) nen `blockchain.relayer.account` khong ro ri `signer_ref`.
- "Khong nhan `allowed_company_ids`" la mot quy tac khong the thuc thi: `/json/2` truyen `context` vao `with_context()` va `Environment.companies` doc no — nhung no **an toan** vi `environments.py:266-272` raise `AccessError` khi client xin company ngoai `user._get_company_ids()`. Quy tac dung la: khong nhan `company_id` lam **tham so method**, va khong `sudo()` method resolve company tu context (docstring: "No sanity checks applied in sudo mode!").
- Loi tra ve khac nhau giua hai duong RPC: `UserError`/`ValidationError` cho HTTP **200 + JSON-RPC error** tren `call_kw` nhung **422** tren `/json/2`; `AccessError` 403, `MissingError` 404, `LockError` 409, con lai 500 (`odoo/exceptions.py` + `http.py:2674-2694`). `/json/2` con chi nhan **kwargs** nen moi method cong khai phai goi duoc bang keyword.
- `payment.transaction._set_error` allowed_states la `('draft','pending','authorized')` — **`done` khong nam trong do**, va `_update_state` chi log warning roi bo qua khi trang thai nguon sai: sau mot reorg, `_set_error` tren tx da `done` **khong lam gi va khong ai biet**. He qua: Finality Gate phai dung nguong hard, va `on_reorg` bat buoc phai sinh giao dich hoan tien/but toan dao chu khong doi trang thai.
- `_toggle_crons()` bat buoc `.sudo()` (`ir.cron` chi cho `base.group_system`, `base/security/ir.model.access.csv` dong 5), cron phai tu gioi han lo + `env.cr.commit()` tung ban ghi + `_trigger()` khi day lo; va o `chain_profile='private'` (finality tuc thoi) do tre p95 ~90 giay cua `ir.cron` la **toan bo** do tre nguoi dung cam nhan, nen private chain bat buoc phai day qua `chain_event_ingest` thay vi doi cron.

**Open questions (need a human decision)**

- `meta_nonce` trong contract EIP-1776 tang **truoc** hay **sau** `call`? Tang truoc mo duong cho relayer doc dot nonce cua user bang tx chac chan revert; tang sau mo replay khi revert. Quyet dinh nay doi `attempt_seq`/`failure_code='nonce_burned'` va phai chot **truoc khi freeze ABI** (M1).
- `group_blockchain_manager` co dong thoi la `treasury` khong? Mac dinh hien tai la co (gop `implied_ids`); to chuc co kiem toan noi bo se muon tach, nhung doi sau khi da cap quyen cho nguoi that thi phai ra soat lai toan bo user.
- Nguong `blockchain.approval.policy.amount_fiat_max_single` mac dinh dat 0 (luon can nguoi thu hai) — an toan nhung se lam cham loyalty 5,000 diem. Co nen dat mac dinh khac nhau theo `use_case`?
- Gnosis `finality_hard_seconds`: bang chot 780 giay la **uoc tinh**; phai do that tren mainnet (p99 khoang cach `latest` → `finalized` trong 7 ngay) truoc khi chuyen chain sang `enabled`.
- Celo sau khi thanh Ethereum L2 (OP Stack, 2025): `finality_mode` la `l1_batch` hay `depth`, va `finality_hard_seconds` bang bao nhieu? Chua co con so nao dung duoc; moi gia dinh BFT trong note deu phai bo.
- `origin_producer` do ai cap? Neu client tu khai thi mot client gia mao duoc namespace cua client khac va nuot mot settlement. De xuat: suy ra tu service account dang goi (`self.env.user.login`), khong nhan tu tham so — nhung do la mot thay doi chu ky method, can nguoi duyet.
- Retention 90 ngay cho execution trace (va 400 ngay cho tx `reverted`/`orphaned`) co du cho yeu cau kiem toan/luu tru tai VN khong? §13 phai tra loi; §10 chi dat mac dinh.
- Co bo `mail.thread` khoi `blockchain.settlement` ngay tu dau khong? Tren 100k settlement/thang no la ~26 MB/thang `mail_message` + `mail_tracking_value` cong mot subquery follower trong moi search — bo ngay re hon go sau.
- `blockchain.money.flow` (chon duong di cua tien) va `blockchain.approval.policy` (chon ai duoc bam) deu la chinh sach theo (company, luong tien). De xuat khong gop, nhung phai co mot man hinh duy nhat hien ca hai — neu khong khong ai kiem tra duoc cau hinh that su la gi.
- Doi ten module: giu `dms_blockchain` la khuyen nghi, nhung neu muon doi thi **phai quyet hom nay** — sau lan cai dau tien chi phi la ~700 dong `ir_model_data` + 24 rename bang + mot cua so downtime.

**Where blockchain.md is wrong / under-specified**

- Gas Zether sai mot bac do lon: note ghi "~180,000 - 250,000 gas" cho xac thuc ZKP — do la chi phi mot pairing check Groth16 (`ecPairing` ~45k + 34k/cap sau EIP-1108). Bulletproof **khong dung pairing**; no can ~200-350 `ecMul` x 6,000 gas sau khi gom multi-exp, cong ~2.4 KB calldata x 16 gas/byte → **1.2M-2.5M gas** cho mot `transferConfidential` (khop §06.4). He qua: ~$60/tx tren Ethereum L1 o 10 gwei, va ~12-25 giao dich Zether toi da moi block 30M — do la ly do locked #5 (private chain truoc) la dieu kien kha thi chu khong phai su tri hoan.
- Bang finality cua note ghi Celo la "Istanbul BFT 2.0 (IBFT), 5 giay, immediate finality" — **da loi thoi**: Celo la Ethereum L2 tren OP Stack tu 2025, block time ~1 giay, finality dan xuat tu L1. Sua: nap `celo` voi `state='draft'` va bat buoc do lai `finality_hard_seconds` tren mainnet truoc khi `enabled`; khong duoc chep con so BFT cu vao `blockchain.chain`.
- Note yeu cau Simulation Gate "dam bao ty le revert la 0%". Do la mot muc tieu khong dat duoc, khong phai mot rang buoc thiet ke: trang thai chain doi giua luc simulate va luc mine, va o `MODE_OPEN` ta khong kiem soat duoc relayer nao nop. Sua: coi simulate la mot bo loc xac suat, va thiet ke duong xu ly revert (`failure_code`, `attempt_seq`) nhu duong chinh — khong xay UI hua 0%.
- Kich thuoc proof Zether chua bao gio duoc dinh luong trong note (va ban nhap doan 1.0-1.5 KB). Tinh lai cho BN254 tren EVM, noi mot diem G1 trong calldata la **64 byte**: Bulletproof aggregate `2*ceil(log2(m*n))+4 = 20` diem (m=2, n=128) = 1,280 B + 5 scalar 160 B + sigma ~416 B + 4 ciphertext 512 B ≈ **2,370 B calldata** (~1.4-2.0 KB nen). Chi rieng calldata da ~38,000 gas.
- Note khong noi gi ve tang Odoo: khong model, khong ACL, khong bien gioi module, khong noi so uint256 duoc luu the nao qua ORM. Khong co field so nao cua Odoo chua duoc `2^256-1` (`Integer` la int4, `Float` la IEEE754 double het chinh xac tu 2^53) — chot `Char` + CHECK `~ '^(0|[1-9][0-9]{0,77})$'` (chan ca so 0 dan dau, neu khong `'007'` va `'7'` pha moi dedup).
- Note gia dinh Odoo se doc duoc so tien Zether de dua vao ERP. Khong: neu cong ty khong giu khoa giai ma thi `amount_clear_base` rong **vinh vien**. Moi bao cao doanh thu tren so bao mat phai thiet ke voi cot rong la truong hop binh thuong; da them `clear_source` + CHECK `clear_source <> 'none' OR amount_clear_base IS NULL` de ep dieu do vao schema.
- Note khong noi ai duoc phep bam nut chi tien — chi noi R3/R4 "can Arbiter Agent tham dinh". Do khong phai mot co che. Da bo sung `blockchain.approval.policy`/`.request` (nguong single + daily, quorum, `approver_group_id`), tach `group_blockchain_approver` **khong** ke thua `operator`, va rang buoc `self.env.uid != request.requested_uid`; mac dinh `amount_fiat_max_single = 0` (luon can hai nguoi).
- Note dat HSM/MPC FIPS 140-2 L3 nhu bien phap chong lo khoa nhung khong noi Odoo luu gi. Sua: Odoo chi luu `signer_ref` (handle), bao ve bang `groups=` **trong dinh nghia field** (Odoo 19 raise `AccessError` khi doc ro ten, va `groups` di theo qua `_inherits`) — khong bang record rule (loc dong, khong loc cot) va tuyet doi khong bang `password=True` (khong ton tai o Odoo 19).
- Note coi `ir.config_parameter` / cau hinh la noi an toan cho tham chieu ma khong canh bao rang bang `ir_config_parameter` nam trong DB va trong **moi ban backup**, doc duoc boi bat ky ai co `group_system`. Sua: URL RPC **co API key** khong duoc dat o do — `blockchain.rpc.endpoint.endpoint_ref` chi la ten khoa, URL that nam trong bien moi truong cua relay worker.
- Note mo ta Web3 Gateway goi thang RPC/relayer nhung khong noi ranh gioi transaction. Mot `requests.post` trong transaction Odoo cho ra hai loi khong the sua: tx da broadcast ma Odoo rollback (khong co ban ghi), hoac worker nhan roi timeout va cron thu lai (hai tx tren so cai khong co UNDO). Sua: transactional outbox bat buoc; Odoo chi ghi mot dong, cron dispatch, `Idempotency-Key` di theo request va worker chiu trach nhiem dedup.

## 11-indexer-finality.md  (14200 words)

**Key findings**

- Odoo `fields.Integer` is int4 (max 2.1e9), so the draft's `last_block_number` cursor overflows on TON (`lt` ~5e10) and Hedera (consensus nanos ~1.7e18); replaced with a 64-char zero-padded lexicographically sortable `position_key` with a fixed per-family format (E/S/L/T/H prefixes), matching §10.4.1's conclusion that uint256 fits no Odoo numeric field.
- Keying the decoder registry on `topic0` alone (the draft's central claim) is wrong and dangerous: `Transfer(address,address,uint256)` has the same topic0 on every ERC-20 ever deployed; the key must be `(chain, contract_address, topic0, block_range)`, with a bare-topic0 table allowed only for reading bytes, never for crediting money.
- Fake-event injection is the cheapest money-loss hole in the design and the draft never mentions it: any contract can `emit Transfer(x, our_address, huge)` for ~23,000 gas (~$0.000046 on Gnosis at 2 gwei), so a token-address allowlist passed as the `address` parameter of `eth_getLogs`, verified source, 15-minute balance reconciliation, and an explicit `token_quirk` classification are all mandatory, not optional.
- `bamboo_create_idempotent` guarantees the effect ROW is created once, not that its EFFECT runs once; a crash between the idempotent create and `_apply()` silently loses money forever, so both must share one COMMIT, `_apply()` must be self-idempotent behind an `applied_state` flag, and a reconciler cron must sweep `final AND applied_state='pending'`.
- The Zether memo AEAD from §03.2.5 (32 B, ~60 us decrypt) obsoletes the draft's `recipient_decrypted` path as primary: a treasury-owning Odoo can decrypt every amount in and out of its own account, but only if the HSM exposes a narrow `ecdh(D_out) -> shared_secret` operation, which is a new requirement on §07 no section has raised.
- §03.2.6 makes this indexer the wallet recovery infrastructure, not just a reconciliation feed, which kills the draft's blanket 90-day raw-log retention for Zether: the wallet must refuse to spend when an event is missing, so Zether logs stay in Postgres permanently (~4.9 GB/yr at 10k tx/day, 49 GB after 10 years) plus a paginated `zether_history_page` RPC.
- The draft's BRIN-on-block_number recommendation is wrong: backfill inserts old blocks after new ones and state UPDATEs move rows, both destroying the physical correlation BRIN needs, and the saving is only ~3 GB against a ~95 GB table; the right shape is B-tree on `(chain_id, position_key)` plus a partial index on the few thousand non-final rows, with BRIN reserved for the archival scan on `observed_datetime`.
- `ir.cron` has three silent traps the draft ignores: its no-overlap guarantee is a row lock that does not cover an RPC method invoking the same scan (needs `pg_try_advisory_xact_lock`), `limit_time_real_cron` kills long backfills (needs a ~50 s wall-clock deadline with per-chunk `cr.commit()`), and cron interval is a minimum not a schedule (SLA must read `scan_datetime`).
- A `finalized` tag can lie three ways (lagging node, node on a fork, post-checkpoint-sync jump), so the gate needs a hash-level quorum at the lowest agreed height, a never-regress check, and a minimum-age check, all failing toward 'do not advance' rather than toward rollback.
- One `finality_max_wait_seconds` is not enough: warn and stuck must be separate, and Arbitrum's stuck threshold must be ~26 h because the force-inclusion window is 24 h (`delaySeconds = 86400`), otherwise the alarm fires daily and gets muted.
- Head-of-line blocking in the ordered-effect queue has no ceiling in the draft; it needs 900 s to activity, 3 h to `blocked_expired` plus per-flow pause, and an absolute ban on auto-skipping a missing sequence number.
- `block.timestamp` is validator-set (+/-12 s tolerance on Gnosis, arbitrary on a private chain) and must never assign the accounting period; the period comes from `final_datetime` on Odoo's clock, with `clock_skew_seconds` alarmed above 300 s.

**Open questions (need a human decision)**

- Auditor viewing key: cheap `memoAud` (+512 gas, trusts an honest sender) or `C_aud/D_aud` + sigma equality (+40-60k gas, trustless)? §03 currently contradicts itself and the verifier cannot be frozen until this is decided.
- Will the chosen custody provider expose a narrow `ecdh(point) -> shared_secret` operation so Odoo can decrypt Zether memos without ever touching `x`? Fireblocks/Fordefi/Turnkey plausibly can; CloudHSM needs a specific mechanism enabled.
- Is permanent Postgres retention for Zether raw logs (49 GB after 10 years, plus backup/restore SLA impact) acceptable to operations, or must a queryable archive tier be built before go-live?
- Which exact `bytes32 indexed ref` topic layout wins, given only three indexed slots exist and `from`/`to`/`ref` already fill them: is `token` indexed worth dropping one?
- What is the concrete flat Zether fee ladder in ledger units, and is it keyed to transaction type (safe) rather than to value bands (leaks 2-3 bits of `v` per transfer)?
- Is p95 90 s from `included` to UI acceptable for payment UX, i.e. is the `ir.cron` starting point good enough before building the `chain-indexer` service?
- Which specific tokens are allowlisted for automated money flows on Gnosis and Celo, and who approves additions?
- Celo post-L2: what is the archive endpoint for pre-migration history, and does any use case actually need to backfill past the March 2025 migration point?
- Which Soroban archive source (Horizon / Galexie / Hubble) is procured, given RPC event retention defaults to ~24 h not 7 days?
- Runbook for `finality_violation`: who approves the reversing journal entry, within what window, and at what threshold does the whole chain's money flow pause?

**Where blockchain.md is wrong / under-specified**

- Note §10.4 gives Gnosis xDAI '2 Epochs, ~12.8 phut'. Wrong: the Gnosis Beacon Chain has 5 s slots and 16 slots per epoch (epoch = 80 s), so finalization is ~160-240 s (3-4 minutes). This is chain #1 and the note errs in the unfavourable direction. Corrected.
- Note §10.4 says Celo is 'Istanbul BFT (IBFT 2.0), immediate finality, 1 block ~5s'. Obsolete: Celo migrated to an OP Stack L2 on Ethereum (Cel2, March 2025), block time ~1 s, with `unsafe/safe/finalized` rollup semantics and no instant finality. Chain #2 must be designed as a rollup, and pre-migration history needs a separate archive endpoint. Corrected.
- Note §10.4 uses 'Heimdall Checkpoint Milestone, ~25-30 phut' for Polygon PoS, conflating two things: milestones (Heimdall 2/3+ vote, what Bor's `finalized` tag returns, ~5 s after the 2025 Bhilai/Rio upgrades) with L1 checkpoints (~30 min, only needed for the bridge). The note is hundreds of times too conservative, for the wrong reason. Corrected.
- Note §10.4 treats Arbitrum hard finality as ~15 minutes. The typical figure is 20-40 minutes, and the worst case is bounded by the 24-hour force-inclusion window (`delaySeconds = 86400`), so a 15-minute stuck alarm fires daily and gets muted. Corrected with separate warn (1 h) and stuck (26 h) thresholds.
- Note §10.4 calls Hedera / CosmWasm / Celo 'immediate finality' as if it meant irreversibility. On a BFT chain it means no fork under a <=1/3-byzantine assumption; governance rollback, halt-and-restart-from-snapshot, a node serving pruned or forked state, and >1/3 equivocation are all real rewind paths. Consequence: hash verification is never disabled on any chain, even at depth 1. Corrected.
- Note §10.4 lists SUI at '400ms - 2 giay'. 400 ms is the owned-object fast path only; every stateful contract (tokens, Zether) uses shared objects and goes through Mysticeti at 2-3 s. The note promises a latency this system will never reach. Corrected.
- The note's `EncryptedTransfer` struct carries both a public `uint256 fee` and an encrypted `bytes32[2] C_fee`. These are mutually exclusive: if `fee` is public the contract can build its ElGamal form as `(g^fee, 1)` and subtract homomorphically, so `C_fee` is dead weight. Fee must be public anyway, because an Open Relayer cannot price an encrypted number - which is exactly what note §10.1 says with 'Public Relayer Fee'.
- The note's §10.5 Zether description gives no confidential-ledger indexing story at all, and no metadata-leakage analysis. Added: percentage fees algebraically destroy amount privacy (`v = fee / rate`, one division); deposit/withdraw amounts are plaintext so intersection recovers the middle; the ~45k extra gas for a first-time recipient (4 storage slots zero->nonzero) leaks 'new counterparty' from the receipt; and the real anonymity set is active accounts per time window, not registered accounts.
- The note's ingestion story ('Dedicated Blockchain Nodes, RPC endpoints, Indexers va WebSocket listeners thu thap stream block va event theo thoi gian thuc') has no backfill path, no cursor, no reorg handling and no per-chain RPC retention limits. Soroban RPC keeps events for ~24 h by default (17,280 ledgers), Sui and TON public nodes prune, and Erigon/reth with `--prune.r` deletes receipts and logs outright, which breaks Zether wallet recovery entirely. Range scan by cursor is the only source of truth; WebSocket is a wake-up hint.
- The note's HCS anchoring is described as a value ('Tamper-evident Proof of Action') but never costed or scheduled. Quantified: at ~$0.0001/message, anchoring the private-chain head hash every 60 s costs ~$53/year and bounds the undetectable-rewind window to 60 s; every-15-s anchoring costs $210/year and buys nothing, because human detection time is measured in minutes.

## 12-threat-model.md  (13400 words)

**Key findings**

- Ten hidden assumptions were made explicit as table G1-G10; the two most dangerous are G5 (prover RNG assumed good) and G6 (base.group_system assumed weaker than RCE) — both are false and both were silently load-bearing in the draft.
- Prover randomness is the biggest omission in the whole draft: a repeated Schnorr nonce k gives x = (z1 - c1*k) directly, and a repeated ElGamal s to the same recipient leaks the difference of two amounts; fixed with synthetic RFC-6979-style nonces (HMAC over x, chainId, address(this), zetherNonce, H(statement), plus 32 fresh bytes) and two named tests.
- base.group_system is equivalent to remote code execution in the Odoo process (ir.actions.server state='code', base.automation, ir.cron), so adversaries A4 and A5 collapse into one; every mitigation of the form "only group_system can read it" is worth zero, and the signer-side policy engine is not defence-in-depth but the only remaining layer.
- The trust model must be drawn per process (Odoo / relay-pool / confidential-signer / indexer / HSM), which added three adversaries the draft had no place for: A9 cross-tenant insider in multi-company, A10 relay-pool compromise, A11 indexer compromise — A11 matters most because the indexer is the process that writes `finalized`.
- The private-chain native Go precompile chosen in 03.3.9 is an unaudited consensus-critical attack surface the draft never mentioned: a wrong `true` is accepted by every validator with no layer above it to catch it; needs its own $30k-60k review, a 3-way differential test (Solidity / Go / Rust vectors) and binary-hash monitoring.
- Verifier cost ordering is a real mitigation with a number: rejecting on registry status + nonce + on-curve costs ~8k gas versus ~1.5M for a full MSM, so fail-fast ordering is ~1000x cheaper and must be a measured test (`VerifierFailFast.t.sol`), not a style preference.
- The single highest benefit/cost control in the section is an on-chain `WithdrawLimiter`, and it now has a derivation rather than an assertion: max_loss = cap_rate * response_time, so 2% TVL/hour with a 15-minute P1 response caps worst case at 0.5% of TVL ($10k on a $2M pilot) even when nobody understands the bug yet.
- Buying 100% of Gnosis block space costs roughly $441/day at 1.5 gwei (294 Ggas/day), i.e. a competitor can price our 1.88M-gas Zether transactions out of the chain for a few hundred dollars an hour — a new operational DoS section and a second quantitative argument for the private profile.
- Audit programme rebudgeted from $120k-240k to $173k-345k by adding the Go precompile review (B2), Certora on forwarder/wrapper (C2) and a client-SDK supply-chain review (D2), plus four process rules the draft lacked: B before C, scope freeze with a written delta list, remediation retest inside the contract, and per-severity fix SLAs.
- Client SDK supply chain (A13) is the cheapest path to `x` in the entire model — no chain, no Odoo, no HSM touched — and got its own mitigation table (locked deps, --ignore-scripts, SRI, signed reproducible WASM, prover in a worker, recipient rendered from the signed struct).
- Monitoring gained the failure mode that actually costs days rather than minutes: absence of signal. A dead-man's switch checked by an external service, plus the rule that alerting must not run on the infrastructure it watches, plus two new drills (kill the indexer unannounced; restore a Shamir share of x).
- Added a residual-risk register (R1-R7: Gnosis 1/3 equivocation, BN254 ~100-bit, harvest-now-decrypt-later, 0.3-1.0%/yr key loss, no seizure on public chain, public cardinality, loss of 4-of-7 Safe keys) and a traceability matrix mapping every control to where it is enforced and the test file that proves it is alive.

**Open questions (need a human decision)**

- Public-chain exposure of the brand-distributor graph: accept it, or force B2B settlement onto chain_profile = private (drives chain cost, ops headcount and section 13).
- Who holds y_audit, under what legal basis, with what k-of-n threshold and rotation period, and who is accountable if x_audit leaks — it decrypts the entire history of every account with C_audit.
- Does the freeze / forceTransfer authority on the private chain map to a court order path, and which role holds it.
- WITHDRAW_CAP_PER_HOUR: 2% of TVL/hour is proposed with its derivation, but someone must sign off that the accepted worst case is losing 2% of TVL in an hour.
- Does compliance accept a relayer hot key in an enclave instead of an HSM FIPS L3? If no, the system ceiling is ~10-30 tx/s and MetaTxBatcher becomes mandatory rather than an optimisation.
- Is the $173k-345k audit programme approved before go-live, or do we ship the original epoch design first to avoid paying for a Phase B review of the owner-exclusive rollover variant.
- Is base.group_system inside the trust boundary? It currently is, and 12.6.1 shows that means accepting RCE-equivalent insiders.
- Is a $300,000 bounty float actually ring-fenced, and is the payer the issuer or the platform.
- BN254 G1 or Baby Jubjub for ElGamal: 03.3.9 recommends Baby Jubjub from day one because it is the precondition for a Groth16 path without a curve migration, and a curve migration exposes every balance. Unfixable after the first contract deploys.
- Private-chain rewind policy: we hold the technical power to rewind. Is it permitted, who approves it, and must partners be told? Unanswered means it gets answered at 3am by whoever is panicking.

**Where blockchain.md is wrong / under-specified**

- blockchain.md §10.5.2 says the Zether private key x is stored in an HSM/MPC FIPS 140-2 L3. Not implementable: a PKCS#11 HSM is a signing oracle, has no BN254/Baby Jubjub OID, and CKM_ECDH1_DERIVE would need thousands of round-trips per transfer. Correction: HSM holds a KEK that wraps x; x is unwrapped only inside an attested enclave (KMS Recipient + kms:RecipientAttestation:PCR0), and the contract must state plainly that x is NOT inside a FIPS L3 boundary at time of use.
- The note's withdraw proof binds recipient, amount and zetherNonce into the Fiat-Shamir challenge but not block.chainid or address(this). Since schnorrAddress = keccak256(pkX,pkY) is identical on every EVM chain, a valid withdraw proof on Gnosis can be replayed on Celo when zetherNonce coincides. Corrected: chainId, address(this) and authEpoch must all enter the challenge.
- The note binds recipient into the challenge for withdraw but never binds feeRecipient into the challenge for transferConfidential — a real anti-MEV hole letting a relayer redirect the fee. Corrected in 12.3.3.
- The note's EIP-1776 mode rule says the signature either omits relayer/feeRecipient or hashes them as address(0). "Or" is a spec bug: two digests, and any client/verifier mismatch fails every signature. Corrected to a single canonical zeroing rule (_canon) with one TYPEHASH.
- The note's 15-minute meta-transaction expiry is a free option for the relayer. Corrected to 60s for Zether, 120s for stateful calls, 300s for plain ERC-20, 900s for anchors, with the expiry check placed before nonce++ and before fee collection.
- The note's ~180k-250k gas figure for Zether verification is the cost of four ecPairing calls, i.e. Groth16, not Bulletproofs. Real figures: ~1.88M gas at n_v=32/n_b=64, ~3.87M at 128/128 (22.8% of a Gnosis block), ~215k only if the system moves to Groth16 on Baby Jubjub. The draft's own "250-350k" for the Groth16 profile was also wrong and is corrected to ~215k.
- The note asserts 100% FATF Travel Rule compliance from revealing sender/receiver identity. Recommendation 16 requires originator/beneficiary information plus the amount; identity without amount does not satisfy it. This is why C_audit must be mandatory on B2B, not optional (per 02.7.6).
- The note's finality table gives Gnosis 2 epochs ~12.8 minutes. Gnosis Beacon uses 16 slots of 5s per epoch, so 2 epochs is ~160-240s (3-4 minutes), and the correct implementation reads the node's `finalized` tag rather than counting depth.
- blockchain.md §TOKEN asks for delegatecall-based code sharing plus UUPS everywhere. Applying UUPS to ZetherAccountRegistry lets an admin swap getPublicKey and silently redirect every incoming transfer to a key the victim cannot read; the registry must be immutable with a one-time successorAddr.
- The note's EncryptedTransfer carries both a public uint256 fee and a ciphertext C_fee. They are mutually exclusive: if fee is public the contract builds (g^fee, 1) itself and C_fee is dead weight; fee must be public because an Open Relayer cannot price an encrypted number. C_fee is deleted from the struct.

## 13-legal-vn.md  (14278 words)

**Key findings**

- Buying native gas legally is the unstated blocker: a Vietnamese entity has no licensed way to buy xDAI/CELO with VND, so relayer gas has no valid invoice and is disallowed for the 20% CIT deduction - this makes public-mainnet deployment by a VN entity RED independently of any token question, and is a second, independent justification for locked decision #5 (private chain first).
- A genuinely open relayer market is structurally incompatible with Vietnamese foreign-contractor withholding tax: you cannot withhold ~10% FCT from an anonymous mempool relayer, and an uninvoiced fee is non-deductible - therefore MODE_OPEN (0x00) belongs to the `offshore` profile and `vn_conservative` must force MODE_RESTRICT_RELAYER (0x01) over a contracted allowlist.
- Transferability to an unrelated third party is the single boundary that all three legal analyses (loyalty -> e-money, receivable -> negotiable instrument, utility -> payment instrument) cross at, so it must be one enforced field `transfer_policy` on `blockchain.token` plus a contract-level revert, not three scattered arguments.
- The largest quantified financial exposure in the loyalty use case is not ND 88 but VAT: promotional goods not notified/registered under ND 81/2018 lose the zero taxable-price treatment, which at 4 billion VND/month of promo goods is ~400 million VND/month of VAT - an order of magnitude above the administrative fine.
- AML compliance requires a real freeze path: setting `sanctions_state='blocked'` in Odoo blocks new settlements but not a direct contract call, so `freeze(bytes32)` under a 2-of-3 COMPLIANCE_ROLE multisig (separate from the governance multisig) is mandatory at `vn_conservative`, and it must be added to the section 12 threat model as a new centralised attack surface.
- Erasure is three different answers, not one: AML/KYC and Travel Rule records must be REFUSED with a legal basis (5-year PCRT retention, hence `retain_until_date`), surplus off-chain PII must be truly unlinked, and only on-chain pseudonyms get crypto-shredding - the draft applied crypto-shredding uniformly, which would turn a compliance request into a second violation.
- Travel Rule binds VASP-to-VASP; if both legs are controlled by the same enterprise or by two non-financial counterparties under a commercial contract, there is no VASP and no Travel Rule obligation - so `custody_mode='custodial'` on a `role='user'` account is the single field most likely to flip the deployment into VASP status, and it is now blocked by constraint at `vn_conservative`.
- The `C_audit` decision is not a cost decision: at 25,300 gas on Gnosis it is ~$0.000025/tx, ~$46/year at 1.8M tx/year, and under 5 ms of extra prover time - the real variable is `y_audit` threshold-key governance and the single-point-of-exposure risk from section 2.7.6.
- Vendor versus deployer liability for the 'cung ung' verb is a live risk for whoever ships this repo; three of the four mitigations already exist in the architecture (inert default install, `vn_conservative` default, customer-held key material) and the fourth is a logged, attested profile change on `res.company`, costing one mail.thread message.
- The knowledge-cutoff problem is solved by mechanism, not by disclaimer: `docs/legal/vn_legal_claims.yaml` with per-claim `verified_on` / `recheck_after_days` / `blocks`, enforced by `tools/check_legal_register.py` in CI so a stale or unverified claim fails the pipeline that would enable mainnet.
- Section 10.4.3's `address` constraint (size=42, CHECK '^0x[0-9a-f]{40}$') hard-codes an EVM assumption into a model advertised as multi-chain and will break the first Fabric/Corda/HBAR/TON/SUI/Soroban/CosmWasm adapter; recorded here as debt to pay before that adapter, since a CBDC pilot is the most likely trigger.
- A tx hash is not a chung tu ke toan under Luat Ke toan 2015; the accounting document must be an internal voucher or a `blockchain.reconciliation.run` batch statement that carries the mandatory contents, with tx_hash and finality_datetime as reference data only.

**Open questions (need a human decision)**

- How does a Vietnamese legal entity lawfully acquire native gas (xDAI/CELO) with a valid input invoice? Without an answer, public-chain deployment under a VN entity is not viable and only the private-chain or offshore-entity paths remain.
- How is foreign-contractor withholding tax handled on fees paid to an unidentified relayer, and does an allowlisted, contracted relayer set fully discharge the obligation?
- Under assumption A4 (outlet owner is a household business), is a volume-based reward paid in points a chance prize (10% PIT on the excess over 10m per event), a trade discount, or promotional goods? Three different tax heads, three different mechanisms.
- Is a `utility_internal`, non-transferable token on a permissioned chain, used to record and net off receivables between two VN legal entities with a bank transfer for final settlement, an 'illegal means of payment'?
- At what point does a transferable loyalty point become e-money: on secondary-market existence, on a reference price, or on third-party acceptance?
- Does crypto-shredding satisfy the erasure right under ND 13/2023 or the 2025 Personal Data Protection Law, and conversely is refusal to erase AML records on the basis of the PCRT 5-year retention correct?
- In the SaaS scenario, is the vendor a Data Processor or a Data Controller, and what clauses must the DPA carry before SaaS can be sold at all?
- Which legal entity issues the token, VN or offshore? This drives licensing, tax, FX, and the gas question, and cannot be deferred until after the first mint.
- Who holds the 3-of-5 shares of `y_audit`, who must be the mandatory external holder, and who signs off on each decryption event?
- Who owns `docs/legal/vn_legal_claims.yaml` and the `legal-register-freshness` CI job, and who holds the 2-of-3 COMPLIANCE_ROLE that can call `freeze()`?

**Where blockchain.md is wrong / under-specified**

- blockchain.md TOKEN section proposes '1 USDT (DAI) -> 25000 Z-VND'. This is two separate violations stacked, not one: Z-VND pegged to VND, pre-funded and redeemable meets the substance of e-money under ND 52/2024 (issuable only by a bank or a licensed payment-intermediary), and the published 1:25,000 rate is itself a quoted FX rate between residents. Kept TokenFactory and wrap/peg for non-VN markets; gated by `token_legal_class` + `transfer_policy` + a `set_values()` check.
- blockchain.md and section 14.2.8 both claim Zether gives '100% FATF Travel Rule compliance' purely by exposing sender/receiver identity. FATF Recommendation 16 requires the AMOUNT and currency alongside originator/beneficiary data; an encrypted amount does not satisfy it. Corrected: identity is the hard half, the amount half needs `C_audit` plus an off-chain IVMS101 message. Additionally, Travel Rule binds VASP-to-VASP and may not apply at all to an internal B2B chain.
- The prior draft of this section cited `C_audit` at approximately 13,200 gas. That figure was already superseded in section 2.7.6, which found it undercounted the second pair of the Chaum-Pedersen equality proof. Corrected to approximately 25,300 gas per transfer (1,024 gas calldata + 24,300 gas for 4 ecMul and 2 ecAdd), roughly +11% on a confidential transfer.
- The prior draft mapped the recommended B2B model to 'payment integration mode 4 and mode 2 (chain as reconciliation layer) in section 10.8'. Two errors: the full mode list is section 09.2 (M1 to M13), section 10.8 has only five condensed config modes; and in BOTH numbering schemes mode 2 is the external crypto acquirer, not 'chain as reconciliation layer'. Corrected with an explicit mapping table (M12/M4 for record-only, M3 for per-transaction B2B, M2 for a licensed third party).
- The prior draft's `_check_legal_class_allowed` constraint reads `rec.state`. Per section 10.4.4 the token state field is `deploy_state`; `state` was renamed for exactly this reason, so the constraint would raise AttributeError on first run. Corrected.
- The prior draft's compliance gate is only an `@api.constrains`, which never re-fires when `ir.config_parameter` changes. Switching the profile from `offshore` back to `vn_conservative` would leave every deployed `stablecoin_fx` token in place while the system reports compliance. Added the reverse guard in `res_config_settings.set_values()`.
- The prior draft says nobody may `write` on `blockchain.audit.disclosure` and enforces it with ACL alone. Any `.sudo()` call bypasses ACL, and `.sudo()` is ubiquitous in Odoo code. Corrected: override `write()` and `unlink()` to raise, with ACL as a second layer.
- The prior draft contradicts itself on stablecoins: section 13.1 says a USD stablecoin between two VN residents breaches FX rules, while section 13.7.1 says it is not 'ngoai te' so revaluation does not apply. Both cannot rest on the same premise. Resolved: USDC/USDT is not a foreign currency, but the prohibition on QUOTING in foreign currency between residents is independent and still bites, and a substance-over-form challenge remains a real risk. Design answer: quote everything in VND at `vn_conservative`.
- The prior draft's accounting policy ('historical cost, no revaluation') contradicts section 15.4.3, which creates a `res.currency` for the token and lets Odoo generate exchange differences normally. Resolved: 15.4.3's mechanism is retained because the sub-ledger needs a VND value at `finality_datetime` regardless; the policy question is only whether the period-end revaluation hits P&L, exposed as `blockchain.fx_policy = 'monetary_revalue' | 'historical_cost'` with historical_cost as the default.
- The prior draft quotes the ND 88/2019 fine as 50 to 100 million VND. That is the level for individuals; under the Law on Handling of Administrative Violations an organisation pays twice the individual rate, so the real figure for a company is 100 to 200 million VND per act plus remedial measures. Also corrected: the prior draft's 'three consequences' heading in 13.6.3 listed four items; it is now five, and the PIT claim was corrected from '10% on amounts over 10 million' to '10% on the portion exceeding 10 million per prize event', with the further point that a deterministic points programme is probably not a prize at all.

## 14-contracts-repo-testing.md  (16469 words)

**Key findings**

- Mot Foundry project duy nhat tai smartcontracts/evm/ thay the ca bon cay thu muc mau thuan cua §01.14, §02.8.4, §03.9 va §04; chia theo purpose o muc src/<purpose>/ chu khong o muc project, vi invariant 'meta-tx Zether khong tao token tu hu khong' cat qua ba purpose.
- Invariant suite PHAI chay voi MockVerifier: verifier that ton 9-28 ms CPU moi call (230 diem MSM x 40-120 us) ⇒ 1,000 runs x depth 50 la 135-420 giay chi rieng crypto, profile deep la 1.1-3.5 gio; tinh dung mat ma thuoc ve KAT/differential/cargo-fuzz.
- I11 cua ban nhap SAI vi blockchain.md §10.5.3 cho ZetherToken ke thua IERC20 ⇒ underlying.balanceOf bi doi qua bon duong chu khong hai; hoac tach WrappedToken (khuyen nghi) hoac dung I11' voi bon ghost variable.
- Them bay invariant moi (I16-I22): profile parity Open/Recoverable qua abstract test base, rollOver khong griefing duoc, fee chuyen truoc inner call, storage slot append-only, SponsorshipPool escrow, curve parity, selector recoverAccount vang mat.
- via_ir khong bat buoc: struct calldata doc truc tiep field khong gay stack-too-deep; bat no ton build x6-13 va CHAN forge coverage ⇒ gate coverage 90% cua §01.14.2 la gate chet. Mac dinh tat, co [profile.coverage] rieng.
- bytecode_hash='none' khong can cho tinh tai lap (Foundry dung duong dan tuong doi) va no lam MAT Sourcify full-match; thay bang determinism gate build hai lan o hai duong dan khac nhau roi diff hash init_code.
- Halmos mo hinh keccak256 nhu uninterpreted function co gia dinh injective ⇒ check_digest_injective cua ban nhap gan nhu vacuous; thay bang do dai encoding co dinh 13*32 byte, vong lap sensitivity tren tung field, va KAT lien nganh voi viem/eth_account.
- Bon implementation phai dong y chu khong ba: prover Rust, verifier Rust, verifier Solidity, VA native precompile; cap 3<->4 voi KAT AM la cap quan trong nhat vi phan ky o input di dang = chain split.
- Verifier Rust chay trong relayer va parse byte tu Internet ⇒ ba cargo-fuzz target bat buoc; mot panic! la DoS toan mang relayer bang mot goi tin 200 byte.
- Fork test khong cache RPC dot 2,000-10,000 request moi lan (~2.3M CU/ngay tren Alchemy free tier 300M CU/thang) va sinh 429 ngau nhien; actions/cache tren ~/.foundry/cache/rpc voi key gom block number la fix ba dong.
- Them tang 0 kiem thu Odoo: nam guard grep cho bay Odoo 19 cong mot test runtime hoi thang pg_constraint; va job odoo-standalone required check cho locked #7 (dms_blockchain cai duoc trong DB khong co dms).
- Chi phi CI tinh duoc ~$430/thang; mutation testing that su la ~8.5 gio/dem (gambit 4.4h + necessist 3.3h + cargo-mutants 0.8h) chia ba job song song ≈ $122/thang — re hon mot ngay cong engineer.

**Open questions (need a human decision)**

- ZetherToken co ke thua IERC20 khong? blockchain.md §10.5.3 noi co, nhung do la hai ke toan tren mot so du va no quyet dinh I11 vs I11'. Phai chot TRUOC khi viet contract.
- rollOver permissionless hay khong? Permissionless ⇒ griefing 30k gas lap vo han; khong permissionless ⇒ ai goi ho tai khoan khong hoat dong va ai tra gas.
- Curve cua ElGamal: Baby Jubjub (khuyen nghi §03.3.9) hay BN254 G1? Quyet dinh mot chieu — doi curve sau nay = giai ma lai toan bo so du de ma hoa lai = lo het.
- Native precompile Zether wave 1 hay wave 2, va tren client nao (Besu Java 21 FFM hay fork geth)? Wave 1 khong co = 13 tx/s tren Besu; co = ~500 tx/s nhung la consensus change.
- Client private chain: §03.3.9 chon go-quorum, §08.10 chon Besu va loai GoQuorum vi maintenance mode. Hai section mau thuan truc tiep ve image chay trong devnet. Lien quan: Besu gasLimit 50M (§08.10) hay 200M (§01.789)?
- Ai giu khoa deploy production va Certora co mua license khong ($12k-40k/nam)? De xuat AWS KMS + Safe 3-of-5 tu block dau, can xac nhan.
- Licence: relayer-ref/ va src/*/interfaces/ Apache-2.0, core BUSL-1.1 change date +24 thang? Mo nguon la dieu kien can de co Open Relayer thu ba — toan bo luan diem cua EIP-1776.
- Co viet evm/ts-conformance/ (~200 dong viem) cho CIP-64 va EIP-712 cross-check khong, hay chap nhan duong fee-currency chi kiem thu cong?
- Runner CI 2 vCPU hay 4 vCPU? Chenh $200/thang va 20 phut wall-clock moi PR (20 gio cho/thang voi doi 4 nguoi). Va mutation score 80% la gate cung hay chi bao cao?
- smartcontracts/ co tach thanh repo rieng khong va khi nao? Bat buoc neu chot mo nguon; tach muon dat hon tach som nhung tach som mat tinh nguyen tu cua PR cham ca hai phia.

**Where blockchain.md is wrong / under-specified**

- blockchain.md §10.5.2 ghi ZKP verify '~180,000-250,000 gas'. Do la chi phi Groth16 (45,000 + 4 x 34,000 ecPairing k=4); Bulletproofs KHONG dung pairing. Con so dung theo §03.3.6 la ~1.88M gas o cau hinh 32/64 da chot (sai 9x) va ~3.87M o cau hinh 128/128 ma note mo ta (sai 19x). Ban nhap §14 ghi 1.5-2.5M — den tu cau hinh 128-bit da bi §03 loai bo; da sua lai theo 32/64.
- blockchain.md §10.5.3 dat MAX = (1 << 128) - 1. §03.2.1 da chung minh dieu nay LAM HONG giao thuc: BSGS khong giai duoc so du tren 2^128 nen khong ai doc duoc so du cua chinh minh. Cau hinh dung: RANGE_BITS_VALUE=32, RANGE_BITS_BALANCE=64, DECRYPT_BOUND=2^40. Toan bo bang proof size va gas da tinh lai theo do.
- Bang Finality Gate cua blockchain.md §10.4 mo ta Celo la 'IBFT 2.0, immediate finality, ~5 giay'. Sai tu 03/2025: Celo la L2 tren OP Stack — safe sau vai phut, finalized ~15-20 phut theo L1. Neu khong sua, he thong se _set_done cho mot block co the bi lat — vi pham truc tiep 'broadcast khong phai la thanh toan'.
- blockchain.md yeu cau 'Simulation Gate voi ty le revert bang 0%'. Khong dat duoc: simulate o block N, execute o N+k, giua hai thoi diem co rollOver, co transfer den, co relayer khac gianh nonce. Muc tieu dung: revert CO TEN va RE (checks re truoc verify ⇒ 30k thay vi 1.3M gas) cong SLO < 0.5%.
- blockchain.md §10.5.3 dinh nghia 'function rollOver(bytes32 schnorrAddress) external' khong co kiem quyen va nhan dia chi nguoi khac lam tham so ⇒ mac dinh permissionless ⇒ griefing ~30k gas ($0.00006 tren Gnosis) lam proof dang bay cua nan nhan revert, lap vo han.
- §07 (va ban nhap §14) noi build profile 'public' khong chua selector recoverAccount. Foundry profile chi doi cau hinh compiler, khong loai ham khoi source. Va cach kiem cua ban nhap (grep selector trong deployedBytecode) cho false positive — phai dung 'forge inspect methodIdentifiers | jq' cong test on-chain khang dinh call selector do revert.
- §01.14.1 goi bytecode_hash='none' la BAT BUOC cho tinh tai lap. Khong dung: Foundry dung duong dan tuong doi nen metadata da deterministic khi da ghim solc/settings/submodule. Cai gia that la mat Sourcify full-match. Thay bang determinism gate build hai lan o hai duong dan khac nhau.
- §01.14.1 goi via_ir=true la bat buoc vi 'struct 12 field ⇒ stack too deep'. Stack-too-deep den tu qua nhieu bien local song dong thoi, khong tu so field cua mot struct calldata. Bat no ton build x6-13 va chan forge coverage ⇒ gate coverage 90% cua chinh §01.14.2 tro thanh gate chet.
- evm_version='cancun' (§01.14.1, §14.2) khong khop genesis Besu cua §08.10 von khai 'shanghaiTime: 0' va khong co cancunTime. TSTORE/MCOPY se la INVALID opcode tren private chain SAU KHI moi test da pass. Can gate devnet/check-genesis-fork.sh; §08.10 phai them cancunTime: 0.
- §03.3.9 chon go-quorum vi 'Besu la Java, can JNI, gap 5 lan cong'; §08.10 chon Besu va loai GoQuorum vi maintenance mode. Lap luan JNI da cu: Besu chay Java 21+ va Foreign Function & Memory API (GA tu JDK 22) goi thu vien Rust khong can mot dong JNI — ~150 dong Java, ngang 150 dong Go trong geth.

## 15-settlement-layer.md  (13983 words)

**Key findings**

- Settlement stays a three-axis model (intent = `blockchain.settlement`, transport = `blockchain.settlement.batch`, truth = `blockchain.transaction`/`chain.effect`), but the draft's missing fourth object is added: `blockchain.settlement.batch.chunk`, without which a `chunked` batch has nowhere to record 'chunk 3/7 failed, 4..7 never sent'.
- The 2D-nonce lane must be derived from the TRANSPORT unit (chunk when batched, settlement when solo) plus `caip2`, not from each settlement's `origin_key` — a 150-settlement chunk is one metatx and therefore exactly one `(batchId, batchNonce)`.
- `final` is no longer a terminal state: `finalized` tags lie three ways (§11.3b) and a private chain can be rewound by its own operator, so a `disputed` state plus `blockchain_resolve_dispute` (treasury) is required, and no accounting entry is ever reversed automatically on a reorg signal.
- The polymorphic link uses all three Odoo mechanisms (`Many2oneReference` for the query path, `Reference` for UI navigation, an AbstractModel mixin in CORE for the callback contract), with `self.env.registry.get(name)` + `issubclass` as the guard and a per-record savepoint so one bad bridge cannot kill the notify cron.
- Odoo 19 has no fallback for `account.payment.outstanding_account_id` (`_compute_outstanding_account_id` reads only `payment_method_line_id.payment_account_id`), so four things must be configured before the first GL post: both payment-method-line outstanding accounts, the company exchange journal plus gain/loss accounts, and a crypto dust account.
- `res.currency.rounding` is declared `digits=(12,6)`, so `decimal_places` maxes at 6 — a framework ceiling, not a choice; an 18-decimal token therefore drops up to 10^12-1 base units per settlement, which is negligible as money (<=1.83 token/yr at 1.83M settlements) but fatal to a zero-tolerance reconciliation.
- Reconciliation needs five directions, not three: the draft's chain/GL/balance checks miss (D) chunk-sum vs on-chain tx value (catches a chunk that shipped 149 of 150 recipients) and (E) terminal-but-never-notified (catches DMS re-paying a payout that already settled).
- Direction (A) cannot be answered by any RPC — no node answers 'every transfer ever to my address' — so it is a left-anti-join against `blockchain.chain.effect` from the §11 indexer, which makes the indexer a hard dependency of reconciliation.
- Zether reconciliation has three tiers, not one: as account owner the AEAD memo (§03.2.5) yields `v` in ~60 us plus a homomorphic sum check, as counterparty a disclosed `(v, s)` is verifiable in 2 scalar muls, and only when we hold nothing does nonce continuity remain — hence a `partial` run state that must never report `clean`.
- Batching on Gnosis saves no meaningful money ($0.039 -> $0.018 for 300 payees); the real constraint is the mempool per-account pending limit (geth `txpool.accountslots` = 16), which turns 300 solo txs into 19 submission rounds (~95 s) with 300-deep head-of-line risk versus one round for two chunks.
- One transaction is not automatically atomic: a `disperseToken` with per-line try/catch (required by §09 M17) can partially succeed, so `disperseStrict` and `disperseBestEffort` must be two separate contract functions with two selectors, not one boolean flag.
- The three DMS flows attach through `dms.trade.settlement` (one beneficiary, `selection_add` of `settlement_method='onchain'`, reusing the existing `_dms_event_uuid()` UUIDv7 as `origin_key`), `dms.payment.collection` (broadcast maps to the already-existing `pending_reconciliation`, final calls `dms_post_payment` with the settlement uuid as `operation_uuid`), and a three-settlement netting set with a gross-preserving Netting clearing account.

**Open questions (need a human decision)**

- Do loyalty points expire? Without an expiry the `Loyalty liability` balance grows without bound and is never released — an accounting/legal decision that blocks the `gl_policy='liability'` design.
- Is `posting_policy` per money-flow or system-wide? Per-flow is proposed; a single global policy is easier to audit but costs ~6,250 reversal entries per year on the collection flow.
- Should `dms.payment.collection` gain an `event_uuid` like `dms.trade.settlement` has? Without one the bridge's `origin_key` is a bare `model:id` and cannot double as an `_dms_once` operation uuid. This is a change inside `dms`, not the bridge.
- Does the distributor contract actually contain a set-off clause? Without it the netting design (§15.6.3) must stay switched off in production even though the code is correct, because a counterparty bankruptcy could unwind the offset.
- Who is the second pair of eyes on `blockchain_resolve_dispute`? Odoo has no built-in four-eyes mechanism; either build one or accept a single treasury user resolving a disputed settlement.
- Is `recon_slack_base` allowed to be non-zero for any token? Default is 0; any non-zero value is a place to hide drift and must be justified on the token's `mail.thread`.
- On a private chain, who holds the anchoring key? If the operator both rewinds and signs the anchors, the anchor proves the chain to outsiders but does not constrain the operator — is a third-party anchor custodian required?
- Which of §10.1 (`depends: ['base','mail']`) and §11.5 (`depends: ['base','bamboo_idempotency']`) is authoritative for the core manifest? The outbox and GL idempotency in this section both assume `bamboo_idempotency` is present.

**Where blockchain.md is wrong / under-specified**

- blockchain.md gives Zether verification as ~180,000-250,000 gas via EIP-196/197 precompiles. That figure is the cost of verifying a Groth16 SNARK (4 pairings), not Bulletproofs, which use no pairings. Corrected throughout to 1,880,000 gas for the 32/64 configuration per §03.3.6 — a 7.5x difference that changes the batch conclusion from 'three to four blocks' to '33 consecutive Gnosis blocks', i.e. impossible on a public chain.
- blockchain.md §10.5 builds Zether around a 5-block epoch plus `rollOver()`. §03.5.4 replaced epochs entirely with `accSeq` because a simulate-then-submit race reverts ~40% of transactions on a 5-block epoch. Every epoch-based statement (including the draft §15's 'all 300 recipients land in the same epoch') is void; the replacement cost is one extra ~28k-gas `rollOver` per receiving account, which must be in the batch cost model.
- blockchain.md's Zether struct carries both a public `uint256 fee` and an encrypted `C_fee`. These are mutually exclusive: if `fee` is public the contract can build its ElGamal form itself. Fee must be public (an Open Relayer cannot price an encrypted number), and it must be a flat value from a small discrete scale independent of `v` — an ad valorem fee of 0.3% makes `v = fee/0.003`, one division, destroying the confidentiality the whole protocol exists for.
- blockchain.md assumes Odoo can read Zether amounts into the ERP. Only partly true, and the boundary matters: as account owner the AEAD memo makes it cheap; as an outside observer it is impossible, and a reconciliation report must say `partial` rather than `clean`.
- blockchain.md's finality table gives Gnosis as 2 epochs / ~12.8 minutes. Gnosis Beacon runs 16 slots per epoch at 5 s, so an epoch is 80 s and hard finality is ~160-240 s. The note is wrong by ~4x on the first chain in the rollout, in the conservative direction.
- blockchain.md's finality table gives Celo as IBFT 2.0 with immediate finality. Celo migrated to an OP Stack L2 on Ethereum (Cel2, March 2025); chain #2 must be designed as a rollup with `unsafe`/`safe`/`finalized` semantics, not as a BFT chain.
- blockchain.md says nothing about how a uint256 survives the Odoo ORM. No Odoo numeric field holds one (`Integer` is int4/int8, `Float` loses precision above 2^53), so `amount_base` is a `Char` with a regex CHECK — and consequently `SUM()` over it requires an expression index on `(amount_base::numeric)`, without which the batch reconciliation query seq-scans 1.25M rows.
- blockchain.md treats broadcast as settlement ('Agent thanh toan khong ma sat'). Applying the `dms_vietqr` rule, broadcast is a QR shown, not money received: `_set_done` / `settle_state='final'` fires only after the Finality Gate, and in DMS the correct intermediate state (`pending_reconciliation`) already exists on `dms.payment.collection`.
- blockchain.md's Public Relayer Fee model does not say who books the fee. It is real money in a real token: without an explicit `Dr Transaction fee expense / Cr Crypto wallet` entry, the sub-ledger and the GL diverge by the cumulative fee and no one can explain the gap.
- blockchain.md's HSM rule ('agent must never hold a plaintext private key') is right but incomplete for this layer: reading Zether memos requires a narrow `ecdh(D) -> compress(D^x)` operation exposed by the HSM. That is a new requirement on the custody design that no section had stated.

## 16-decomposition-roadmap.md  (5900 words)

**Key findings**

- Effort khong phai lich: da them cong thuc calendar_weeks = ew / (headcount x 0.70) cong 4-6 tuan ramp moi nguoi moi va ap no xuyen suot; ban nhap chia thang cho headcount nen lich 10-11 thang chi dung neu P10 duoc thue ngoai.
- Tong chuong trinh sua tu ~103 ew len 126 ew nen tang + 9-15 ew vertical = 135-141 ew (~2.7 engineer-year), cong $173k-345k audit, $300k float bounty, $30k bootstrap relayer, $107-9,750/thang custody tuy cau hinh.
- Them ba spike vao S0 (6 -> 9 spike, 7 -> 10 ew): S7 chot curve ElGamal, S8 native precompile chay tren Besu hay bat buoc geth-QBFT, S9 dat lich audit vi hang doi hang ZK tuyen 1 la 2-4 thang lead time thuan.
- Gate chot curve (Baby Jubjub vs BN254 G1) phai dung TRUOC P10 chu khong phai truoc P11: prover Rust cung bi khoa vao curve, va doi curve sau khi co so du lam lo toan bo so du cua tat ca.
- Them ba sub-project ban nhap khong co: P18 van hanh/quan trac (4 ew), P19 phap ly VN (0 ew ky su nhung chan go-live, khoi dong tuan 1), P20 WithdrawLimiter + circuit breaker on-chain (3 ew, gate truoc moi dong tien that).
- Them Definition of Done rieng cho tung sub-project P01-P23 (brief yeu cau, ban nhap chi co DoD cho M0); moi dong la mot lenh chay duoc hoac mot test do duoc.
- Chuoi audit B -> B2 -> C -> C2 -> D -> D2 la 9-12 tuan lich khong headcount nao rut ngan duoc, cong ceremony Groth16 4-8 tuan neu public profile di duong do.
- Rang buoc ky nang la rang buoc that: P10 = 14 ew tren nhom Rust/Bulletproofs hiem nhat (tuyen 2-4 thang o VN), chay mot minh la 20 tuan lich; lich thuc te 22-24 thang (3 nguoi) / 12-14 thang (8-9 nguoi tu lam P10) / 10-11 thang (thue ngoai P10).
- M0 tang 4 -> 5 ew va duoc danh dau THROWAWAY; DoD tu 6 len 9 muc, gom job CI standalone that su, test ca hai duong RPC call_kw + json/2, guard chan chain_profile='public', grep chan ten field trung kieu Odoo.
- Kich ban 'S1 va S2 cung fail' duoc viet ra lan dau: Zether rut ve private-only vinh vien, ENDUSER_PAY bo Zether, giam ~22 ew nhung mat use case B2B public.
- Cau hoi cho nguoi quyet tang tu 10 len 20, moi cau van tra loi duoc bang co/khong hoac chon-mot, va da bo lua chon chet (polygon-edge) khoi danh sach chon.

**Open questions (need a human decision)**

- Curve cua ElGamal: `babyjubjub` hay `bn254_g1`? Quyet dinh khong dao nguoc, phai chot truoc dong contract dau tien.
- Duyet ngan sach audit $173k-345k truoc khi khoi dong P10 khong? Neu khong, Zether bi gioi han vinh vien o private chain.
- Duyet rieng $300,000 float thanh khoan cho bug bounty khong?
- Use case nao chay dau tien sau M0: LOYALTY_ACCRUE (custody $107/thang) / B2B_SETTLEMENT (bat buoc custody $2,900-9,750/thang) / ENDUSER_PAY (bi prove-time giet)?
- Chap nhan `x` cua Zether nam ngoai bien FIPS 140-3 L3 luc su dung, hay tra tien Functionality Module (4-8 tuan dev + chu ky tai chung nhan)?
- Nen private chain: `besu-qbft` hay `geth-qbft`? Phu thuoc ket qua S8; polygon-edge da bi loai vi Polygon ngung san pham tu 2024.
- Zether token: 6 decimals + range 64-bit (re hon ~46% gas va CPU validator) hay 18 decimals + 128-bit nhu note dang viet?
- Fee trong Zether cong khai (`uint256`) hay bi mat (`C_fee`)? Note dang co ca hai ma khong co menh de buoc chung khop.
- Quy mo doi: 1 pod 3 nguoi (~22-24 thang) / 4 pod 8-9 nguoi (~12-14 thang) / 4 pod + thue ngoai P10 (~10-11 thang)?
- Enclave chay o dau: AWS Nitro Singapore (rui ro ND 13/2023) hay SEV-SNP on-prem VN (+4-8 tuan, +$60-90k capex)?

**Where blockchain.md is wrong / under-specified**

- Ngan sach audit: ban nhap section 16 ghi $120k-240k. Sai - do la con so cu ma chinh §12.8 da sua thanh $173k-345k (them B2 precompile $30-60k, C2 Certora $15-30k, D2 client SDK $8-15k), cong ~$15k/nam re-audit va $300k float bounty. Da sua trong P15.
- `ChainAdapter` 9 method: ban nhap ghi 9 trong bang pod B. Sai - §08.2 da sua thanh 12 va giai thich 9 sai theo huong nguy hiem (ep ba chuc nang van hanh bat buoc ra ngoai interface). Da sua.
- Kill criterion cua S1 ('> 3.5 M gas tren Gnosis, block gas limit ~17 M => < 5 tx/block'): lech cau hinh. O cau hinh da chot 32/64 uoc tinh la ~1.88 M gas (§3.3.6); 3.87 M la cua 128/128 da bi loai. Rang buoc that khong phai tien ($0.002-0.006/tx) ma la block space (~31,300 tx/ngay o 20% block space). Da doi nguong sang 2.5 M gas VA them nguong wall-time CPU 40 ms/proof.
- Kill criterion cua S2 ('p95 Android > 3 s'): rong den muc khong the fail, tuc khong phai mot gate. §3.8.2 uoc tinh ARM64 native 0.20-0.50 s (x2-3 khi battery saver). Da siet xuong p95 > 1.0 s native / > 2.5 s WASM+SIMD va yeu cau do khi bat battery saver.
- '800k `account.move`/thang cho loyalty (§09.4)': sai ca so lan tham chieu. Con so dung o §15.4.4 la 1.83 trieu `account.move`/NAM voi 5,000 outlet x 1 collection/ngay (~5.5-8 GB/nam). Da sua trong P09.
- P13 'reference relayer ~400 dong TS': §5.9 da sua - ban production thuc te ~1,800-2,400 dong; ~500 dong chi dung cho `--mode=simple`. Loi the so voi ERC-4337 bundler la 5x, khong phai 30x. Da tang P13 tu 5 len 8 ew.
- M0 chon 'Besu QBFT' ma khong noi rang §3.3.9 khuyen nghi go-quorum/geth-QBFT (gnark-crypto la Go) trong khi §08.10 loai go-quorum vi maintenance mode. Do la mau thuan noi tai giua hai section, khong phai mot lua chon. Da them spike S8, kem su that can kiem chung: `besu-native` da co JNI binding toi gnark cho altbn128.
- Cau hoi 8 cua ban nhap cho chon `polygon-edge`. §08.10 da loai dut khoat vi Polygon ngung san pham nay tu 2024; de mot codebase khong con ai va bao mat trong bang quyet dinh la mot cai bay. Da bo khoi danh sach chon.
- Rang buoc serialise #2 cua ban nhap dat gate chot curve truoc P11. Sai - prover Rust cua P10 cung bi khoa vao curve, nen gate phai dung truoc P10. Da nang thanh G1 va ve lai so do phu thuoc.
- `dms_blockchain` depends: §10.2 ghi `['base','mail']`, §11.5 yeu cau `bamboo_idempotency` (addon da ton tai tai /home/dockers/odoo19/addons/bamboo_idempotency). Mau thuan giua hai section; da ghi thanh muc DoD cua P04 va bai test standalone phai cai kem no.