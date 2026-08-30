// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Factory mở. Ai cũng tạo được token. Không ai gác cổng, kể cả người deploy nó.
///
/// @notice Mô hình do user chốt: *"Hệ thống factory, contract này sẽ open cho toàn thế
///         giới. Ai cũng tạo được, ai cũng wrap token thành Meta Token được. Ai cũng
///         wrap token thành Zether được. Thị trường sẽ quyết định dùng cái nào. Tôi
///         chỉ deploy factory thôi."*
///
///         Và: *"Ví dụ wrap xDAI => zDAI, 10 người có thể wrap thành 10 contract khác
///         nhau, kệ họ."*
///
/// ## Ba thứ factory này CỐ TÌNH không làm
///
/// 1. **Không có wrapper chính thức.** Ông A wrap xDAI ra `zDAI-A`; ông B wrap cùng
///    xDAI ra `zDAI-B`. Hai địa chỉ khác nhau, cả hai đều thật, cả hai đều hợp lệ. Thị
///    trường quyết định cái nào được dùng nhiều.
///
///    `getWrapper` **được giữ**, nhưng khoá là `(creator, underlying)` chứ không phải
///    `underlying`. *"Wrapper xDAI của ông A là cái nào"* có đúng một đáp án; *"wrapper
///    xDAI là cái nào"* thì không, và một hàm trả về một địa chỉ cho câu hỏi đó sẽ nói
///    dối. Không ràng buộc duy nhất trên riêng `underlying`.
/// 2. **Không allowlist verifier, không allowlist underlying, không duyệt tên.** Một
///    verifier độc hại chỉ hại đúng token đã chọn nó. Một cái tên giả chỉ lừa được người
///    không kiểm xuất xứ.
/// 3. **Không quyền nâng cấp token của người khác.** Xem `DeployMode` bên dưới — đây là
///    chỗ mô hình mở buộc phải đảo ngược một quyết định của canon.
///
/// ## Một thứ factory này BẮT BUỘC làm: ghi xuất xứ
///
/// Bỏ gác cổng thì phải bù bằng thứ khác, nếu không "kệ họ" biến thành "không ai kiểm
/// được gì". Thứ đó là **provenance kiểm được on-chain**: mọi token do factory sinh ra
/// đều trả lời được `factory()`, `creator()`, `underlying()`, `verifier()`, và factory
/// giữ `isDeployedHere()`.
///
/// Điều đó cho phép ví/indexer trả lời chính xác **"contract này có đúng là wrap xDAI
/// bằng verifier X do địa chỉ Y tạo không"** — một câu hỏi có đáp án on-chain.
///
/// Nó KHÔNG trả lời **"đây có phải cái zDAI mà tôi nên dùng không"** — câu đó không có
/// đáp án on-chain, và giả vờ là có mới là chỗ nguy hiểm thật sự. Đó là câu hỏi của
/// danh tiếng và thanh khoản, tức của thị trường, đúng như thiết kế.
interface IOpenFactory {
    /// Ai giữ quyền nâng cấp token sau khi deploy.
    enum DeployMode {
        /// EIP-1167 clone. **Không ai** nâng cấp được, kể cả người tạo. Rẻ nhất khi
        /// deploy (~45k) và khi gọi (~2.700 warm). **Mặc định.**
        IMMUTABLE,
        /// UUPS, `owner` = người tạo token. Người tạo nâng cấp được token CỦA MÌNH.
        /// Blast radius = một token, và nó thuộc về đúng bên chịu rủi ro.
        UPGRADEABLE_BY_CREATOR
    }

    /// @dev **KHÔNG có mode Beacon, và đây là một đảo ngược có chủ ý so với canon §01.**
    ///
    ///      Canon chọn Beacon proxy — một `UpgradeableBeacon` cho mỗi cặp
    ///      `(archetype, majorVersion)` — và tự ghi nhận nhược điểm là *"blast radius =
    ///      toàn bộ N token"*. Trong một hệ đóng nơi ta sở hữu cả N token thì đó là
    ///      **ưu điểm**: vá 40 token bằng 1 giao dịch.
    ///
    ///      Với factory mở thì cùng cơ chế đó có nghĩa là **chủ beacon thay được
    ///      implementation của mọi token mà mọi người lạ từng tạo** — im lặng, một giao
    ///      dịch, không cần sự đồng ý của ai. Đó là một cửa hậu lên tiền của người khác,
    ///      và nó không phải rủi ro lý thuyết: nó là chính xác cái quyền mà mô hình mở
    ///      hứa là không tồn tại.
    ///
    ///      Beacon do chính người tạo sở hữu thì vô nghĩa — một beacon cho một token là
    ///      UUPS cộng thêm ~4.600 gas mỗi giao dịch.
    ///
    ///      Hệ quả kèm theo, và nó là dọn dẹp chứ không phải mất mát: chuỗi CREATE2 ba
    ///      tầng của canon §1.4 tồn tại **chỉ để** giữ địa chỉ ổn định qua các lần nâng
    ///      cấp. Với clone bất biến thì không có lần nâng cấp nào để mà giữ.
    event TokenDeployed(
        address indexed token,
        address indexed creator,
        address indexed underlying,
        bytes32 archetype,
        address implementation,
        address verifier,
        DeployMode mode
    );

    error VerifierUnsupportedOnThisChain(address verifier, string curveName);
    error ImplementationNotAContract(address implementation);

    /// @notice Địa chỉ này có do factory sinh ra không.
    /// @dev Nền của mọi kiểm tra xuất xứ. Một contract tự xưng `factory()` là địa chỉ
    ///      này thì phải đối chiếu ngược lại đây, nếu không nó chỉ là một chuỗi tự khai.
    function isDeployedHere(address token) external view returns (bool);

    function creatorOf(address token) external view returns (address);

    // ---- Tra cứu theo NGƯỜI TẠO: "wrapper xDAI của ông A là cái nào" ----

    /// @notice Wrapper của `creator` cho `underlying`. Cái đầu tiên họ tạo.
    /// @dev Đây là `getWrapper` của bản thiết kế cũ, đã đổi khoá. Bản cũ khoá trên
    ///      riêng `underlying` nên hàm ý tồn tại một zDAI chính thức. Khoá trên
    ///      `(creator, underlying)` thì câu hỏi có đáp án thật: mỗi người một wrapper.
    /// @return `address(0)` nếu `creator` chưa tạo wrapper nào cho `underlying`.
    function getWrapper(address creator, address underlying) external view returns (address);

    /// @notice Một người tạo VẪN có thể có nhiều wrapper cho cùng một underlying —
    ///         ví dụ một cái trên bn254 và một cái trên BLS12-381, hoặc hai biểu phí.
    ///         `getWrapper` trả cái đầu tiên; danh sách đầy đủ ở đây.
    function getWrapperCount(address creator, address underlying) external view returns (uint256);

    function getWrapperAt(address creator, address underlying, uint256 index)
        external
        view
        returns (address);

    // ---- Tra cứu theo THỊ TRƯỜNG: "có những zDAI nào, của ai" ----

    /// @notice Đếm mọi token wrap `underlying`, của mọi người tạo.
    /// @dev Đây là thứ cho phép so sánh zDAI-A với zDAI-B. Tín hiệu xếp hạng không cần
    ///      hàm mới: `IERC20(underlying).balanceOf(token)` là lượng tài sản thật đang
    ///      bị khoá sau mỗi wrapper. Thị trường bỏ phiếu bằng tiền, và phiếu đó đọc
    ///      được on-chain miễn phí. Factory không xếp hạng hộ.
    function deployCountFor(address underlying) external view returns (uint256);

    function deployedFor(address underlying, uint256 index) external view returns (address);

    /// @notice Tạo một Meta Token (ERC-20 gasless, số dư công khai).
    function createMetaToken(
        address implementation,
        DeployMode mode,
        address underlying,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address token);

    /// @notice Tạo một Zether Token (số dư bí mật), với verifier do người tạo chọn.
    /// @param verifier verifier của curve nào cũng được — bn254, BLS12-381, hay thứ
    ///        chưa ai viết. Factory **không** ưu tiên curve nào.
    /// @dev Kiểm duy nhất factory làm: `verifier.isSupportedOnThisChain()`. Nó không
    ///      phải phán xét chất lượng — nó chỉ chặn đúng một cái bẫy im lặng: verifier
    ///      BLS12-381 deploy **thành công** trên chain không có EIP-2537 (bytecode hợp
    ///      lệ, có code tại địa chỉ), rồi revert ở mọi proof mãi mãi. Precompile vắng
    ///      mặt không revert, nó trả về thành công với output rỗng — nên không có
    ///      triệu chứng nào cho tới khi có người đã nạp tiền vào.
    ///
    ///      Chain 9000 private là đúng trường hợp đó: genesis khai `pragueBlock: 0`
    ///      nhưng Nethermind bỏ qua key kiểu Geth trong im lặng, và 0x0b…0x10 không
    ///      tồn tại. Xem `src/chains/private9000/README.md`.
    function createZetherToken(
        address implementation,
        DeployMode mode,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address token);

    /// @notice Địa chỉ sẽ ra, tính trước khi deploy. CREATE2 hai tầng: factory rồi token.
    function predictAddress(
        address implementation,
        DeployMode mode,
        address creator,
        bytes32 salt
    ) external view returns (address);
}
