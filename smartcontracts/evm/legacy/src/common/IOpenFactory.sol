// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @title Factory mở. Ai cũng tạo được token. Token tạo ra thì BẤT BIẾN VĨNH VIỄN.
///
/// @notice Mô hình do user chốt:
///
///  - *"Hệ thống factory, contract này sẽ open cho toàn thế giới. Ai cũng tạo được…
///    Thị trường sẽ quyết định dùng cái nào. Tôi chỉ deploy factory thôi."*
///  - *"Ông A wrapper thì ra zDAI-A, ông B wrap thì ra TokenContract zDAI-B."*
///  - *"Và không có upgrade cho zDAI-A, zDAI-B. Factory sẽ đăng ký các version zether
///    implement v1, v2, v3 … hoặc meta token v1, v2, v3. User create zether xDAI-A,
///    xDAI-B tùy họ chọn implement version."*
///
/// ## Version nằm ở factory, bất biến nằm ở token
///
/// Đây là chỗ tách đôi mà toàn bộ thiết kế xoay quanh:
///
/// | | Ai đổi được | Ảnh hưởng tới |
/// |---|---|---|
/// | **Catalogue version** ở factory | thêm được v4 | **chỉ token deploy SAU đó** |
/// | **Token đã deploy** | **không ai** | — |
///
/// Đăng ký v4 **không chạm** được vào một byte nào của zDAI-A đang chạy trên v1.
/// Đó là khác biệt tuyệt đối so với beacon, nơi đổi implementation là đổi hành vi của
/// mọi token đang lưu hành, ngay lập tức, không cần ai đồng ý.
///
/// Nên câu hỏi *"ai được đăng ký version"* không phải câu hỏi về quyền lực lên tiền
/// của người khác. Kẻ đăng ký tệ nhất cũng chỉ xuất bản được một v4 dở mà người tạo
/// token mới **có thể chọn hoặc không**. Và họ luôn có `createUnregistered` để bỏ qua
/// catalogue hoàn toàn — nên catalogue là **danh mục**, không phải cổng.
///
/// ## Chỉ một cách deploy: EIP-1167 clone
///
/// Không UUPS, không Beacon, không Diamond. Người tạo cũng không nâng cấp được token
/// của chính mình.
///
/// Cái giá phải nói thẳng: **một lỗi trong v1 là lỗi vĩnh viễn của mọi token trên v1.**
/// Không có bản vá. Đường đi duy nhất là người tạo deploy một token mới trên v2, rồi
/// người dùng `unwrap` khỏi cái cũ và `wrap` vào cái mới — một cuộc di cư tự nguyện,
/// từng người một, không ai bị ép.
///
/// Đó chính xác là thứ được mua bằng việc bỏ upgrade: **không tồn tại một nút bấm nào,
/// của bất kỳ ai, thay đổi được contract đang giữ tiền của bạn.** Không có nút thì
/// không có ai để tin, và không có gì để bị đánh cắp quyền.
interface IOpenFactory {
    enum TokenKind {
        META,   // ERC-20 gasless, số dư công khai
        ZETHER  // số dư bí mật
    }

    event ImplementationRegistered(
        TokenKind indexed kind,
        uint64 indexed version,
        address indexed implementation,
        address registrar
    );

    /// @dev Đánh dấu, KHÔNG chặn. Xem `deprecate()`.
    event ImplementationDeprecated(TokenKind indexed kind, uint64 indexed version, string reason);

    event TokenDeployed(
        address indexed token,
        address indexed creator,
        address indexed underlying,
        TokenKind kind,
        uint64 version,          // 0 nếu deploy qua `createUnregistered`
        address implementation,
        address verifier         // address(0) với token META
    );

    error VersionAlreadyRegistered(TokenKind kind, uint64 version, address existing);
    error VersionUnknown(TokenKind kind, uint64 version);
    error VersionKindMismatch(TokenKind expected, TokenKind got);
    error ImplementationNotAContract(address implementation);
    error VerifierUnsupportedOnThisChain(address verifier, string curveName);
    error VerifierRequiredForZether();
    error SaltAlreadyUsed(address existing);

    // ------------------------------------------------------------------
    // Catalogue version
    // ------------------------------------------------------------------

    /// @notice Đăng ký một implementation dưới một số version.
    /// @dev **APPEND-ONLY. Một cặp `(kind, version)` đã đăng ký thì KHÔNG BAO GIỜ trỏ
    ///      lại chỗ khác** — revert `VersionAlreadyRegistered`.
    ///
    ///      Đây là bất biến quan trọng nhất của catalogue. Nếu `v1` trỏ lại được thì
    ///      "tôi muốn v1" trở thành một mục tiêu di động: người tạo token đọc mã nguồn
    ///      v1 hôm nay, deploy tuần sau, và nhận về một implementation khác. Cho phép
    ///      sửa trỏ là dựng lại đúng cái quyền mà việc bỏ beacon vừa xoá đi — chỉ khác
    ///      là nó tác động lên token tương lai thay vì token hiện tại.
    function registerImplementation(TokenKind kind, uint64 version, address implementation)
        external;

    /// @notice Đánh dấu một version là không nên dùng nữa. **KHÔNG chặn deploy.**
    /// @dev Chặn ở đây sẽ là thứ tự trấn an: `createUnregistered` bỏ qua catalogue
    ///      hoàn toàn, nên bất kỳ rào nào cũng đi vòng được bằng một tham số. Một rào
    ///      đi vòng được không mua thêm an toàn, nó chỉ mua cảm giác an toàn — và nó
    ///      đổi lấy quyền chặn người khác deploy, thứ factory mở không nên có.
    ///
    ///      Việc thật là **phát tín hiệu**: emit event, để ví và UI hiện cảnh báo, để
    ///      indexer đánh dấu mọi token đang chạy version đó. Token đang chạy không bị
    ///      ảnh hưởng gì — không thể, chúng bất biến.
    function deprecate(TokenKind kind, uint64 version, string calldata reason) external;

    function implementationOf(TokenKind kind, uint64 version) external view returns (address);

    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool);

    /// @notice Version cao nhất đã đăng ký cho `kind`. 0 nếu chưa có version nào.
    /// @dev Tiện cho UI. **Không dùng làm mặc định lúc deploy** — một token phải ghim
    ///      một số version cụ thể mà người tạo đã đọc mã nguồn, không phải "bất kỳ cái
    ///      gì mới nhất tại thời điểm giao dịch được đào".
    function latestVersion(TokenKind kind) external view returns (uint64);

    // ------------------------------------------------------------------
    // Tạo token
    // ------------------------------------------------------------------

    /// @notice Tạo Meta Token từ một version trong catalogue.
    function createMetaToken(
        uint64 version,
        address underlying,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address token);

    /// @notice Tạo Zether Token từ một version trong catalogue.
    /// @param verifier curve nào cũng được — bn254, BLS12-381, hay thứ chưa ai viết.
    ///        Factory **không ưu tiên curve nào**; đây là lựa chọn của người tạo token.
    /// @dev Kiểm duy nhất: `verifier.isSupportedOnThisChain()`. Không phải phán xét
    ///      chất lượng — nó chặn đúng một cái bẫy im lặng: verifier BLS12-381 deploy
    ///      **thành công** trên chain không có EIP-2537 (bytecode hợp lệ, có code tại
    ///      địa chỉ) rồi revert ở mọi proof mãi mãi. Precompile vắng mặt không revert;
    ///      nó trả về thành công với output rỗng. Không triệu chứng nào cho tới khi đã
    ///      có người nạp tiền vào — và với token bất biến thì "sửa" nghĩa là bỏ.
    function createZetherToken(
        uint64 version,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address token);

    /// @notice Tạo token từ một implementation **không có trong catalogue**.
    /// @dev Đường này tồn tại để catalogue là danh mục chứ không phải cổng. Nếu chỉ
    ///      version đã đăng ký mới deploy được thì người giữ quyền đăng ký quyết định
    ///      được cả thế giới được tạo cái gì — và *"ai cũng tạo được"* thành khẩu hiệu.
    ///
    ///      Token sinh ra ở đây có `version() == 0`, và điều đó **cố ý nhìn thấy được**:
    ///      ví và indexer phân biệt được "chạy v2 đã công bố" với "chạy code người tạo
    ///      tự mang tới". Cả hai đều hợp lệ; người dùng có quyền biết mình đang dùng cái nào.
    function createUnregistered(
        TokenKind kind,
        address implementation,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address token);

    /// @notice Địa chỉ sẽ ra, tính trước khi deploy.
    /// @dev Với EIP-1167 thì `init_code` chỉ phụ thuộc `implementation`, nên hàm này
    ///      xác định hoàn toàn và tính được off-chain. Đây là một lợi ích kèm theo của
    ///      việc bỏ upgrade: canon §1.4 phải dựng chuỗi CREATE2 **ba tầng** chỉ để giữ
    ///      địa chỉ ổn định qua các lần nâng cấp. Không còn nâng cấp thì còn hai tầng,
    ///      và địa chỉ ổn định miễn phí.
    function predictAddress(address implementation, address creator, bytes32 salt)
        external
        view
        returns (address);

    // ------------------------------------------------------------------
    // Xuất xứ và tra cứu
    // ------------------------------------------------------------------

    /// @notice Địa chỉ này có do factory sinh ra không.
    /// @dev Nền của mọi kiểm tra xuất xứ. Một contract tự khai `factory()` là địa chỉ
    ///      này thì phải đối chiếu ngược lại đây — nếu không nó chỉ là một chuỗi tự khai.
    function isDeployedHere(address token) external view returns (bool);

    function creatorOf(address token) external view returns (address);

    /// @notice `kind` và `version` của một token do factory sinh ra. `version == 0`
    ///         nghĩa là deploy qua `createUnregistered`.
    function versionOf(address token) external view returns (TokenKind kind, uint64 version);

    // ---- Tra cứu theo NGƯỜI TẠO: "wrapper xDAI của ông A là cái nào" ----

    /// @notice Wrapper của `creator` cho `underlying`. Cái đầu tiên họ tạo.
    /// @dev Bản thiết kế cũ khoá `getWrapper` trên riêng `underlying`, và như thế nó
    ///      hàm ý tồn tại một zDAI chính thức. Khoá trên `(creator, underlying)` thì
    ///      câu hỏi có đáp án thật: *"wrapper xDAI của ông A"* — đúng một.
    ///      *"Wrapper xDAI"* — không có, và không hàm nào ở đây giả vờ là có.
    /// @return `address(0)` nếu `creator` chưa tạo wrapper nào cho `underlying`.
    function getWrapper(address creator, address underlying) external view returns (address);

    /// @notice Một người tạo VẪN có thể có nhiều wrapper cho cùng underlying — một trên
    ///         bn254 và một trên BLS12-381, hoặc một trên v1 và một trên v2 (đây là
    ///         cách "nâng cấp" duy nhất còn tồn tại). `getWrapper` trả cái đầu tiên.
    function getWrapperCount(address creator, address underlying) external view returns (uint256);

    function getWrapperAt(address creator, address underlying, uint256 index)
        external
        view
        returns (address);

    // ---- Tra cứu theo THỊ TRƯỜNG: "có những zDAI nào, của ai" ----

    /// @notice Đếm mọi token wrap `underlying`, của mọi người tạo.
    /// @dev Đây là thứ cho phép so sánh zDAI-A với zDAI-B. Tín hiệu xếp hạng không cần
    ///      hàm mới: `IERC20(underlying).balanceOf(token)` là lượng tài sản thật đang
    ///      khoá sau mỗi wrapper. Thị trường bỏ phiếu bằng tiền, và phiếu đó đọc được
    ///      on-chain miễn phí. Factory không xếp hạng hộ ai.
    function deployCountFor(address underlying) external view returns (uint256);

    function deployedFor(address underlying, uint256 index) external view returns (address);
}
