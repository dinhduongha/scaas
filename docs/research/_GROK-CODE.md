# Grok3_Continued — code blocks

Nguồn: `~/Downloads/Grok3_Continued.html`, 49 block.


## Block 1 (115 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MetaTxExample is Ownable {
    using ECDSA for bytes32;

    // Tên và phiên bản cho EIP-712 domain
    string public constant NAME = "MetaTxExample";
    string public constant VERSION = "1";
    
    // Mapping để theo dõi nonce của mỗi người dùng, chống replay attack
    mapping(address => uint256) public nonces;

    // Struct cho Meta Transaction
    struct MetaTransaction {
        address from;           // Địa chỉ người gửi
        address to;             // Địa chỉ smart contract (thường là chính nó)
        uint256 value;          // Giá trị ETH gửi (nếu có)
        bytes data;             // Dữ liệu giao dịch (call data)
        uint256 nonce;          // Nonce để xác thực
        uint256 validUntil;     // Thời hạn hiệu lực
    }

    // Domain Separator cho EIP-712
    bytes32 public DOMAIN_SEPARATOR;

    // Type hash cho Meta Transaction
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil)"
    );

    // Sự kiện để ghi log khi thực thi Meta Transaction
    event MetaTxExecuted(address indexed from, address indexed to, bytes data);

    constructor() {
        // Tính toán DOMAIN_SEPARATOR theo EIP-712
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    // Hàm thực thi Meta Transaction
    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");

        // Tạo MetaTransaction struct
        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil
        });

        // Tính hash của Meta Transaction theo EIP-712
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil
                    )
                )
            )
        );

        // Xác minh chữ ký
        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        // Tăng nonce để tránh replay attack
        nonces[from]++;

        // Thực thi giao dịch
        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    // Hàm ví dụ để test Meta Transaction
    uint256 public counter;

    function incrementCounter() external {
        counter++;
    }

    // Nhận ETH (nếu cần)
    receive() external payable {}
}
```


## Block 2 (120 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MetaTxExample is Ownable {
    using ECDSA for bytes32;

    // Tên và phiên bản cho EIP-712 domain
    string public constant NAME = "MetaTxExample";
    string public constant VERSION = "1";
    
    // Mapping để theo dõi nonce của mỗi người dùng
    mapping(address => uint256) public nonces;

    // Struct cho Meta Transaction, thêm chainId
    struct MetaTransaction {
        address from;           // Địa chỉ người gửi
        address to;             // Địa chỉ smart contract
        uint256 value;          // Giá trị ETH gửi
        bytes data;             // Dữ liệu giao dịch
        uint256 nonce;          // Nonce để xác thực
        uint256 validUntil;     // Thời hạn hiệu lực
        uint256 chainId;        // ID của chain
    }

    // Domain Separator cho EIP-712
    bytes32 public DOMAIN_SEPARATOR;

    // Type hash cho Meta Transaction, cập nhật với chainId
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId)"
    );

    // Sự kiện khi thực thi Meta Transaction
    event MetaTxExecuted(address indexed from, address indexed to, bytes data);

    constructor() {
        // Tính toán DOMAIN_SEPARATOR với chainId
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    // Hàm thực thi Meta Transaction
    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        // Tạo MetaTransaction struct
        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId
        });

        // Tính hash của Meta Transaction theo EIP-712
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId
                    )
                )
            )
        );

        // Xác minh chữ ký
        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        // Tăng nonce để tránh replay attack
        nonces[from]++;

        // Thực thi giao dịch
        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    // Hàm ví dụ để test
    uint256 public counter;

    function incrementCounter() external {
        counter++;
    }

    // Nhận ETH
    receive() external payable {}
}
```


## Block 3 (35 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);

const domain = {
    name: "MetaTxExample",
    version: "1",
    chainId: await provider.getNetwork().chainId, // Lấy chainId từ mạng
    verifyingContract: "CONTRACT_ADDRESS"
};

const types = {
    MetaTransaction: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "data", type: "bytes" },
        { name: "nonce", type: "uint256" },
        { name: "validUntil", type: "uint256" },
        { name: "chainId", type: "uint256" }
    ]
};

const metaTx = {
    from: wallet.address,
    to: "CONTRACT_ADDRESS",
    value: 0,
    data: "0x3fb5c1cb", // encode hàm incrementCounter()
    nonce: await contract.nonces(wallet.address),
    validUntil: Math.floor(Date.now() / 1000) + 3600, // Hết hạn sau 1 giờ
    chainId: await provider.getNetwork().chainId
};

const signature = await wallet._signTypedData(domain, types, metaTx);
console.log(signature);
```


## Block 4 (137 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken; // Token ERC20 gốc để wrap
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    // Mapping nonce để chống replay attack
    mapping(address => uint256) public nonces;

    // Struct Meta Transaction với chainId
    struct MetaTransaction {
        address from;           // Người gửi
        address to;             // Địa chỉ contract
        uint256 value;          // Giá trị ETH (thường là 0 cho ERC20)
        bytes data;             // Dữ liệu giao dịch
        uint256 nonce;          // Nonce
        uint256 validUntil;     // Thời hạn
        uint256 chainId;        // Chain ID
    }

    // Domain Separator cho EIP-712
    bytes32 public DOMAIN_SEPARATOR;

    // Type hash cho Meta Transaction
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId)"
    );

    // Sự kiện
    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 amount);
    event Unwrapped(address indexed user, uint256 amount);

    constructor(address _underlyingToken) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        underlyingToken = IERC20(_underlyingToken);

        // Tính DOMAIN_SEPARATOR
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    // Wrap token ERC20 thành wERC20
    function wrap(uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");
        require(underlyingToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        _mint(msg.sender, amount);
        emit Wrapped(msg.sender, amount);
    }

    // Unwrap wERC20 về token gốc
    function unwrap(uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");
        _burn(msg.sender, amount);
        require(underlyingToken.transfer(msg.sender, amount), "Transfer failed");
        emit Unwrapped(msg.sender, amount);
    }

    // Thực thi Meta Transaction
    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    // Override transfer để hỗ trợ Meta Transaction
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    // Nhận ETH (nếu cần)
    receive() external payable {}
}
```


## Block 5 (1 dòng)

```javascript
await underlyingToken.approve(contractAddress, amount);
```


## Block 6 (36 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contract = new ethers.Contract(contractAddress, abi, provider);

const domain = {
    name: "WrappedERC20MetaTx",
    version: "1",
    chainId: await provider.getNetwork().chainId,
    verifyingContract: contractAddress
};

const types = {
    MetaTransaction: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "data", type: "bytes" },
        { name: "nonce", type: "uint256" },
        { name: "validUntil", type: "uint256" },
        { name: "chainId", type: "uint256" }
    ]
};

const metaTx = {
    from: wallet.address,
    to: contractAddress,
    value: 0,
    data: contract.interface.encodeFunctionData("transfer", [recipient, amount]),
    nonce: await contract.nonces(wallet.address),
    validUntil: Math.floor(Date.now() / 1000) + 3600,
    chainId: await provider.getNetwork().chainId
};

const signature = await wallet._signTypedData(domain, types, metaTx);
// Gửi signature và metaTx cho relayer
```


## Block 7 (168 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken; // Token ERC20 gốc để wrap
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    // Mapping nonce để chống replay attack
    mapping(address => uint256) public nonces;

    // Struct Meta Transaction với chainId
    struct MetaTransaction {
        address from;           // Người gửi
        address to;             // Địa chỉ contract
        uint256 value;          // Giá trị ETH
        bytes data;             // Dữ liệu giao dịch
        uint256 nonce;          // Nonce
        uint256 validUntil;     // Thời hạn
        uint256 chainId;        // Chain ID
    }

    // Domain Separator cho EIP-712
    bytes32 public DOMAIN_SEPARATOR;

    // Type hash cho Meta Transaction
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId)"
    );

    // Sự kiện
    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 amount);
    event Unwrapped(address indexed user, uint256 amount);

    constructor(address _underlyingToken) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        underlyingToken = IERC20(_underlyingToken);

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    // Kiểm tra xem địa chỉ có phải là smart contract không
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    // Wrap token ERC20 thành wERC20
    function wrap(uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");
        require(underlyingToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        _mint(msg.sender, amount);
        emit Wrapped(msg.sender, amount);
    }

    // Unwrap wERC20 về token gốc
    function unwrap(uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");
        _burn(msg.sender, amount);
        require(underlyingToken.transfer(msg.sender, amount), "Transfer failed");
        emit Unwrapped(msg.sender, amount);
    }

    // Thực thi Meta Transaction
    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    // Override approve: Chỉ smart contract được phép
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    // Override increaseAllowance: Chỉ smart contract được phép
    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    // Override decreaseAllowance: Chỉ smart contract được phép
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    // Transfer bình thường
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    // Nhận ETH
    receive() external payable {}
}
```


## Block 8 (153 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken;
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 amount);
    event Unwrapped(address indexed user, uint256 amount);

    constructor(address _underlyingToken) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        underlyingToken = IERC20(_underlyingToken);

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");
        require(underlyingToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        _mint(msg.sender, amount);
        emit Wrapped(msg.sender, amount);
    }

    function unwrap(uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");
        _burn(msg.sender, amount);
        require(underlyingToken.transfer(msg.sender, amount), "Transfer failed");
        emit Unwrapped(msg.sender, amount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 9 (42 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract WrappedERC20Factory {
    // Mapping từ token gốc đến wrapper
    mapping(address => address) public wrappedTokens;
    // Danh sách tất cả wrapper đã tạo
    address[] public allWrappers;

    event WrapperCreated(address indexed underlyingToken, address indexed wrapper);

    // Tạo một wrapper mới cho token ERC20
    function createWrapper(address underlyingToken) external returns (address) {
        require(underlyingToken != address(0), "Invalid token address");
        require(wrappedTokens[underlyingToken] == address(0), "Wrapper already exists");

        // Tạo instance mới
        WrappedERC20MetaTx wrapper = new WrappedERC20MetaTx(underlyingToken);
        wrappedTokens[underlyingToken] = address(wrapper);
        allWrappers.push(address(wrapper));

        emit WrapperCreated(underlyingToken, address(wrapper));
        return address(wrapper);
    }

    // Lấy địa chỉ wrapper từ token gốc
    function getWrapper(address underlyingToken) external view returns (address) {
        return wrappedTokens[underlyingToken];
    }

    // Lấy tổng số wrapper đã tạo
    function getWrapperCount() external view returns (uint256) {
        return allWrappers.length;
    }

    // Lấy danh sách tất cả wrapper
    function getAllWrappers() external view returns (address[] memory) {
        return allWrappers;
    }
}
```


## Block 10 (15 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const factoryAbi = [...]; // ABI của WrappedERC20Factory
const factoryAddress = 'FACTORY_ADDRESS';
const factory = new ethers.Contract(factoryAddress, factoryAbi, wallet);

async function createWrapper(underlyingToken) {
    const tx = await factory.createWrapper(underlyingToken);
    const receipt = await tx.wait();
    const wrapperAddress = receipt.events.find(e => e.event === 'WrapperCreated').args.wrapper;
    console.log(`Wrapper created at: ${wrapperAddress}`);
}

createWrapper('0x6B175474E89094C44Da98b954EedeAC495271d0F'); // Ví dụ với DAI
```


## Block 11 (175 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken;
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    // Tỷ lệ quy đổi: amountWrapped = (amountUnderlying * conversionNumerator) / conversionDenominator
    uint256 public conversionNumerator;
    uint256 public conversionDenominator;

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, uint256 wrappedAmount, uint256 underlyingAmount);

    constructor(
        address _underlyingToken,
        uint256 _conversionNumerator,
        uint256 _conversionDenominator
    ) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        require(_conversionNumerator > 0 && _conversionDenominator > 0, "Invalid conversion rate");
        
        underlyingToken = IERC20(_underlyingToken);
        conversionNumerator = _conversionNumerator;
        conversionDenominator = _conversionDenominator;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    // Wrap token với tỷ lệ quy đổi
    function wrap(uint256 underlyingAmount) external {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        
        uint256 wrappedAmount = (underlyingAmount * conversionNumerator) / conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(underlyingToken.transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    // Unwrap token với tỷ lệ quy đổi ngược lại
    function unwrap(uint256 wrappedAmount) external {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        
        uint256 underlyingAmount = (wrappedAmount * conversionDenominator) / conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(underlyingToken.transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 12 (47 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract WrappedERC20Factory {
    // Mapping từ token gốc đến wrapper
    mapping(address => address) public wrappedTokens;
    // Danh sách tất cả wrapper
    address[] public allWrappers;

    event WrapperCreated(address indexed underlyingToken, address indexed wrapper, uint256 numerator, uint256 denominator);

    // Tạo wrapper với tỷ lệ quy đổi
    function createWrapper(
        address underlyingToken,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external returns (address) {
        require(underlyingToken != address(0), "Invalid token address");
        require(wrappedTokens[underlyingToken] == address(0), "Wrapper already exists");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        WrappedERC20MetaTx wrapper = new WrappedERC20MetaTx(
            underlyingToken,
            conversionNumerator,
            conversionDenominator
        );
        wrappedTokens[underlyingToken] = address(wrapper);
        allWrappers.push(address(wrapper));

        emit WrapperCreated(underlyingToken, address(wrapper), conversionNumerator, conversionDenominator);
        return address(wrapper);
    }

    function getWrapper(address underlyingToken) external view returns (address) {
        return wrappedTokens[underlyingToken];
    }

    function getWrapperCount() external view returns (uint256) {
        return allWrappers.length;
    }

    function getAllWrappers() external view returns (address[] memory) {
        return allWrappers;
    }
}
```


## Block 13 (16 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const factoryAbi = [...]; // ABI của WrappedERC20Factory
const factoryAddress = 'FACTORY_ADDRESS';
const factory = new ethers.Contract(factoryAddress, factoryAbi, wallet);

async function createWrapper(underlyingToken, numerator, denominator) {
    const tx = await factory.createWrapper(underlyingToken, numerator, denominator);
    const receipt = await tx.wait();
    const wrapperAddress = receipt.events.find(e => e.event === 'WrapperCreated').args.wrapper;
    console.log(`Wrapper created at: ${wrapperAddress}`);
}

// Tạo wrapper cho DAI với tỷ lệ 1 DAI = 2 wDAI
createWrapper('0x6B175474E89094C44Da98b954EedeAC495271d0F', 2, 1);
```


## Block 14 (215 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken;
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    uint256 public conversionNumerator;
    uint256 public conversionDenominator;

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId)"
    );
    // Type hash cho transfer qua Meta Transaction
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, uint256 wrappedAmount, uint256 underlyingAmount);

    constructor(
        address _underlyingToken,
        uint256 _conversionNumerator,
        uint256 _conversionDenominator
    ) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        require(_conversionNumerator > 0 && _conversionDenominator > 0, "Invalid conversion rate");
        
        underlyingToken = IERC20(_underlyingToken);
        conversionNumerator = _conversionNumerator;
        conversionDenominator = _conversionDenominator;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(uint256 underlyingAmount) external {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        uint256 wrappedAmount = (underlyingAmount * conversionNumerator) / conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(underlyingToken.transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(uint256 wrappedAmount) external {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        uint256 underlyingAmount = (wrappedAmount * conversionDenominator) / conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(underlyingToken.transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    // Hàm mới: Chuyển token bằng Meta Transaction
    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        // Tính hash cho transfer Meta Transaction
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId
                    )
                )
            )
        );

        // Xác minh chữ ký
        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        // Tăng nonce và thực hiện chuyển token
        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 15 (52 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của WrappedERC20MetaTx
const contractAddress = 'WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, provider);

async function signAndTransfer(recipient, amount) {
    const domain = {
        name: "WrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" }
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18), // Điều chỉnh decimals nếu cần
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600, // Hết hạn sau 1 giờ
        chainId: await provider.getNetwork().chainId
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    // Gửi qua relayer (giả sử relayer là một ví khác)
    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransfer(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer completed!");
}

signAndTransfer('0xRecipientAddress', 10); // Chuyển 10 wERC20
```


## Block 16 (214 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken;
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    uint256 public conversionNumerator;
    uint256 public conversionDenominator;

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper; // Địa chỉ wrapper contract
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, uint256 wrappedAmount, uint256 underlyingAmount);

    constructor(
        address _underlyingToken,
        uint256 _conversionNumerator,
        uint256 _conversionDenominator
    ) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        require(_conversionNumerator > 0 && _conversionDenominator > 0, "Invalid conversion rate");
        
        underlyingToken = IERC20(_underlyingToken);
        conversionNumerator = _conversionNumerator;
        conversionDenominator = _conversionDenominator;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(uint256 underlyingAmount) external {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        uint256 wrappedAmount = (underlyingAmount * conversionNumerator) / conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(underlyingToken.transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(uint256 wrappedAmount) external {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        uint256 underlyingAmount = (wrappedAmount * conversionDenominator) / conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(underlyingToken.transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this) // Thêm địa chỉ wrapper
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this) // Đảm bảo wrapper được đưa vào hash
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this) // Thêm địa chỉ wrapper
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 17 (53 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của WrappedERC20MetaTx
const contractAddress = 'WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, provider);

async function signAndTransfer(recipient, amount) {
    const domain = {
        name: "WrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" } // Thêm wrapper
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress // Địa chỉ wrapper
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransfer(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer completed!");
}

signAndTransfer('0xRecipientAddress', 10);
```


## Block 18 (10 dòng)

```javascript
const metaTx = {
    from: wallet.address,
    to: contractAddress,
    value: 0,
    data: contract.interface.encodeFunctionData("transfer", [recipient, amount]),
    nonce: await contract.nonces(wallet.address),
    validUntil: Math.floor(Date.now() / 1000) + 3600,
    chainId: await provider.getNetwork().chainId,
    wrapper: contractAddress
};
```


## Block 19 (261 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MultiUnderlyingWrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    string public constant NAME = "MultiUnderlyingWrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    // Cấu trúc cho underlying token và tỷ lệ quy đổi
    struct TokenInfo {
        bool isSupported;                   // Token có được hỗ trợ không
        uint256 conversionNumerator;        // Tử số tỷ lệ quy đổi
        uint256 conversionDenominator;      // Mẫu số tỷ lệ quy đổi
    }

    // Mapping từ underlying token đến thông tin
    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens; // Danh sách các token được hỗ trợ

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, address indexed underlyingToken, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, address indexed underlyingToken, uint256 wrappedAmount, uint256 underlyingAmount);
    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);

    constructor() ERC20("Multi Wrapped ERC20 MetaTx", "mwERC20") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    // Thêm underlying token bởi owner
    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    // Xóa underlying token bởi owner
    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    // Lấy danh sách supported tokens
    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    // Wrap từ underlying token bất kỳ
    function wrap(address underlyingToken, uint256 underlyingAmount) external {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingToken).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingToken, underlyingAmount, wrappedAmount);
    }

    // Unwrap thành underlying token bất kỳ
    function unwrap(address underlyingToken, uint256 wrappedAmount) external {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingToken).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, underlyingToken, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 20 (18 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của MultiUnderlyingWrappedERC20MetaTx
const contractAddress = 'MULTI_WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, wallet);

async function addTokens() {
    // Thêm xDAI (1 xDAI = 2 mwERC20)
    await contract.addUnderlyingToken('0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d', 2, 1);
    // Thêm USDC (1 USDC = 1 mwERC20)
    await contract.addUnderlyingToken('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 1, 1);
    // Thêm USDT (3 USDT = 1 mwERC20)
    await contract.addUnderlyingToken('0xdAC17F958D2ee523a2206206994597C13D831ec7', 1, 3);
    console.log("Tokens added!");
}

addTokens();
```


## Block 21 (9 dòng)

```javascript
async function wrapToken(underlyingToken, amount) {
    const tokenContract = new ethers.Contract(underlyingToken, ['function approve(address spender, uint256 amount) returns (bool)'], wallet);
    await tokenContract.approve(contractAddress, ethers.utils.parseUnits(amount.toString(), 6)); // Điều chỉnh decimals
    const tx = await contract.wrap(underlyingToken, ethers.utils.parseUnits(amount.toString(), 6));
    await tx.wait();
    console.log(`Wrapped ${amount} of ${underlyingToken}`);
}

wrapToken('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 10); // Wrap 10 USDC
```


## Block 22 (46 dòng)

```javascript
async function signAndTransfer(recipient, amount) {
    const domain = {
        name: "MultiUnderlyingWrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" }
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransfer(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer completed!");
}

signAndTransfer('0xRecipientAddress', 5);
```


## Block 23 (290 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MultiUnderlyingWrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    string public constant NAME = "MultiUnderlyingWrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    struct TokenInfo {
        bool isSupported;
        uint256 conversionNumerator;
        uint256 conversionDenominator;
    }

    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens;

    // Phí cho relayer hoặc bên thứ ba (tính theo phần nghìn, 1 = 0.1%)
    uint256 public transferFeePerMille = 1; // Mặc định 0.1%
    uint256 public constant MAX_FEE_PER_MILLE = 1; // Tối đa 0.1%
    address public feeRecipient; // Địa chỉ nhận phí, mặc định là relayer nếu không set

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, address indexed underlyingToken, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, address indexed underlyingToken, uint256 wrappedAmount, uint256 underlyingAmount);
    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);
    event TransferFeePaid(address indexed from, address indexed recipient, uint256 amount, uint256 fee);
    event FeeRecipientUpdated(address indexed newRecipient);
    event TransferFeeUpdated(uint256 newFeePerMille);

    constructor() ERC20("Multi Wrapped ERC20 MetaTx", "mwERC20") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    // Cập nhật phí transfer (chỉ owner)
    function setTransferFeePerMille(uint256 newFeePerMille) external onlyOwner {
        require(newFeePerMille <= MAX_FEE_PER_MILLE, "Fee exceeds maximum 0.1%");
        transferFeePerMille = newFeePerMille;
        emit TransferFeeUpdated(newFeePerMille);
    }

    // Cập nhật địa chỉ nhận phí (chỉ owner, để trống thì mặc định là relayer)
    function setFeeRecipient(address newRecipient) external onlyOwner {
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(newRecipient);
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(address underlyingToken, uint256 underlyingAmount) external {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingToken).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingToken, underlyingAmount, wrappedAmount);
    }

    function unwrap(address underlyingToken, uint256 wrappedAmount) external {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingToken).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, underlyingToken, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        // Tính phí: fee = (amount * transferFeePerMille) / 1000
        uint256 fee = (amount * transferFeePerMille) / 1000;
        uint256 amountAfterFee = amount - fee;

        // Xác định địa chỉ nhận phí (relayer hoặc feeRecipient cố định)
        address feeTo = feeRecipient == address(0) ? msg.sender : feeRecipient;

        // Chuyển phí cho feeTo nếu có phí
        if (fee > 0) {
            _transfer(from, feeTo, fee);
        }
        // Chuyển số còn lại cho recipient
        _transfer(from, recipient, amountAfterFee);

        emit TransferFeePaid(from, recipient, amount, fee);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 24 (53 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của MultiUnderlyingWrappedERC20MetaTx
const contractAddress = 'MULTI_WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, provider);

async function signAndTransfer(recipient, amount) {
    const domain = {
        name: "MultiUnderlyingWrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" }
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransfer(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer completed with fee!");
}

signAndTransfer('0xRecipientAddress', 1000); // Chuyển 1000 mwERC20
```


## Block 25 (327 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MultiUnderlyingWrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    string public constant NAME = "MultiUnderlyingWrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    struct TokenInfo {
        bool isSupported;
        uint256 conversionNumerator;
        uint256 conversionDenominator;
    }

    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens;

    // Phí cho bên thứ ba (tính theo phần nghìn, 1 = 0.1%)
    uint256 public transferFeePerMille = 1; // Mặc định 0.1%
    uint256 public constant MAX_FEE_PER_MILLE = 1; // Tối đa 0.1%
    address public feeRecipient; // Địa chỉ nhận phí

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, address indexed underlyingToken, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, address indexed underlyingToken, uint256 wrappedAmount, uint256 underlyingAmount);
    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);
    event TransferFeePaid(address indexed from, address indexed feeRecipient, uint256 amount, uint256 fee);
    event FeeRecipientUpdated(address indexed newRecipient);
    event TransferFeeUpdated(uint256 newFeePerMille);

    constructor() ERC20("Multi Wrapped ERC20 MetaTx", "mwERC20") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    function setTransferFeePerMille(uint256 newFeePerMille) external onlyOwner {
        require(newFeePerMille <= MAX_FEE_PER_MILLE, "Fee exceeds maximum 0.1%");
        transferFeePerMille = newFeePerMille;
        emit TransferFeeUpdated(newFeePerMille);
    }

    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "Invalid fee recipient");
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(newRecipient);
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(address underlyingToken, uint256 underlyingAmount) external {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingToken).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingToken, underlyingAmount, wrappedAmount);
    }

    function unwrap(address underlyingToken, uint256 wrappedAmount) external {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingToken).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, underlyingToken, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    // Hàm cũ: Chuyển token không phí
    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    // Hàm mới: Chuyển token có phí
    function mtxTransferWithFee(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");
        require(feeRecipient != address(0), "Fee recipient not set");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        // Tính phí: fee = (amount * transferFeePerMille) / 1000
        uint256 fee = (amount * transferFeePerMille) / 1000;
        uint256 amountAfterFee = amount - fee;

        // Chuyển phí cho feeRecipient
        if (fee > 0) {
            _transfer(from, feeRecipient, fee);
        }
        // Chuyển số còn lại cho recipient
        _transfer(from, recipient, amountAfterFee);

        emit TransferFeePaid(from, feeRecipient, amount, fee);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 26 (14 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của MultiUnderlyingWrappedERC20MetaTx
const contractAddress = 'MULTI_WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, wallet);

async function setFeeRecipient() {
    const tx = await contract.setFeeRecipient('0xFeeRecipientAddress');
    await tx.wait();
    console.log("Fee recipient set!");
}

setFeeRecipient();
```


## Block 27 (46 dòng)

```javascript
async function signAndTransferWithFee(recipient, amount) {
    const domain = {
        name: "MultiUnderlyingWrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" }
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransferWithFee(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer with fee completed!");
}

signAndTransferWithFee('0xRecipientAddress', 1000); // Chuyển 1000 mwERC20
```


## Block 28 (309 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MultiUnderlyingWrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    string public constant NAME = "MultiUnderlyingWrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    struct TokenInfo {
        bool isSupported;
        uint256 conversionNumerator;
        uint256 conversionDenominator;
    }

    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens;

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, address indexed underlyingToken, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, address indexed underlyingToken, uint256 wrappedAmount, uint256 underlyingAmount);
    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);
    event TransferFeePaid(address indexed from, address indexed feeRecipient, uint256 amount, uint256 fee);

    constructor() ERC20("Multi Wrapped ERC20 MetaTx", "mwERC20") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(address underlyingToken, uint256 underlyingAmount) external {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingToken).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingToken, underlyingAmount, wrappedAmount);
    }

    function unwrap(address underlyingToken, uint256 wrappedAmount) external {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingToken).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, underlyingToken, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        0, // feeAmount mặc định cho mtxTransfer
                        address(0) // feeRecipient mặc định
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function mtxTransferWithFee(
        address from,
        address recipient,
        uint256 amount,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");
        require(feeAmount <= amount, "Fee exceeds amount");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        uint256 amountAfterFee = amount - feeAmount;

        // Chuyển phí nếu có (feeRecipient != address(0) và feeAmount > 0)
        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
            emit TransferFeePaid(from, feeRecipient, amount, feeAmount);
        }
        // Chuyển số còn lại cho recipient
        _transfer(from, recipient, amountAfterFee);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 29 (63 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của MultiUnderlyingWrappedERC20MetaTx
const contractAddress = 'MULTI_WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, provider);

async function signAndTransferWithFee(recipient, amount, feeAmount, feeRecipient) {
    const domain = {
        name: "MultiUnderlyingWrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" },
            { name: "feeAmount", type: "uint256" },
            { name: "feeRecipient", type: "address" }
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress,
        feeAmount: ethers.utils.parseUnits(feeAmount.toString(), 18),
        feeRecipient: feeRecipient
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransferWithFee(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.feeAmount,
        transferData.feeRecipient,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer with fee completed!");
}

// Chuyển 1000 mwERC20, phí 10 cho 0xFeeRecipient
signAndTransferWithFee('0xRecipientAddress', 1000, 10, '0xFeeRecipientAddress');

// Chuyển 1000 mwERC20, không phí
signAndTransferWithFee('0xRecipientAddress', 1000, 0, '0x0000000000000000000000000000000000000000');
```


## Block 30 (314 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MultiUnderlyingWrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    string public constant NAME = "MultiUnderlyingWrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    struct TokenInfo {
        bool isSupported;
        uint256 conversionNumerator;
        uint256 conversionDenominator;
    }

    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens;

    // Giới hạn phí tối đa: 1% = 10 phần nghìn
    uint256 public constant MAX_FEE_PER_MILLE = 10; // 1% của amount

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 private constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, address indexed underlyingToken, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, address indexed underlyingToken, uint256 wrappedAmount, uint256 underlyingAmount);
    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);
    event TransferFeePaid(address indexed from, address indexed feeRecipient, uint256 amount, uint256 fee);

    constructor() ERC20("Multi Wrapped ERC20 MetaTx", "mwERC20") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(address underlyingToken, uint256 underlyingAmount) external {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingToken).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingToken, underlyingAmount, wrappedAmount);
    }

    function unwrap(address underlyingToken, uint256 wrappedAmount) external {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingToken];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingToken).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, underlyingToken, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        0,
                        address(0)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function mtxTransferWithFee(
        address from,
        address recipient,
        uint256 amount,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) external {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");
        require(feeAmount <= amount, "Fee exceeds amount");
        // Kiểm tra phí tối đa 1% (10 phần nghìn)
        require(feeAmount <= (amount * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of amount");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        uint256 amountAfterFee = amount - feeAmount;

        // Chuyển phí nếu có
        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
            emit TransferFeePaid(from, feeRecipient, amount, feeAmount);
        }
        // Chuyển số còn lại cho recipient
        _transfer(from, recipient, amountAfterFee);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 31 (63 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của MultiUnderlyingWrappedERC20MetaTx
const contractAddress = 'MULTI_WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, provider);

async function signAndTransferWithFee(recipient, amount, feeAmount, feeRecipient) {
    const domain = {
        name: "MultiUnderlyingWrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" },
            { name: "feeAmount", type: "uint256" },
            { name: "feeRecipient", type: "address" }
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress,
        feeAmount: ethers.utils.parseUnits(feeAmount.toString(), 18),
        feeRecipient: feeRecipient
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransferWithFee(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.feeAmount,
        transferData.feeRecipient,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer with fee completed!");
}

// Chuyển 1000 mwERC20, phí 10 (1%) cho 0xFeeRecipient
signAndTransferWithFee('0xRecipientAddress', 1000, 10, '0xFeeRecipientAddress');

// Chuyển 1000 mwERC20, không phí
signAndTransferWithFee('0xRecipientAddress', 1000, 0, '0x0000000000000000000000000000000000000000');
```


## Block 32 (214 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken;
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    uint256 public conversionNumerator;
    uint256 public conversionDenominator;

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 internal constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 internal constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, uint256 wrappedAmount, uint256 underlyingAmount);

    constructor(
        address _underlyingToken,
        uint256 _conversionNumerator,
        uint256 _conversionDenominator
    ) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        require(_conversionNumerator > 0 && _conversionDenominator > 0, "Invalid conversion rate");
        
        underlyingToken = IERC20(_underlyingToken);
        conversionNumerator = _conversionNumerator;
        conversionDenominator = _conversionDenominator;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(uint256 underlyingAmount) public virtual {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        uint256 wrappedAmount = (underlyingAmount * conversionNumerator) / conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(underlyingToken.transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(uint256 wrappedAmount) public virtual {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        uint256 underlyingAmount = (wrappedAmount * conversionDenominator) / conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(underlyingToken.transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 33 (179 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract MultiUnderlyingWrappedERC20MetaTx is WrappedERC20MetaTx {
    string public constant MULTI_NAME = "MultiUnderlyingWrappedERC20MetaTx";
    
    struct TokenInfo {
        bool isSupported;
        uint256 conversionNumerator;
        uint256 conversionDenominator;
    }

    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens;

    uint256 public constant MAX_FEE_PER_MILLE = 10; // 1% của amount

    bytes32 private constant TRANSFER_WITH_FEE_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );

    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);
    event TransferFeePaid(address indexed from, address indexed feeRecipient, uint256 amount, uint256 fee);

    constructor(
        address _initialUnderlyingToken,
        uint256 _initialConversionNumerator,
        uint256 _initialConversionDenominator
    ) WrappedERC20MetaTx(_initialUnderlyingToken, _initialConversionNumerator, _initialConversionDenominator) {
        // Ghi đè DOMAIN_SEPARATOR với tên mới
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(MULTI_NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );

        // Thêm token ban đầu vào danh sách hỗ trợ
        underlyingTokens[_initialUnderlyingToken] = TokenInfo({
            isSupported: true,
            conversionNumerator: _initialConversionNumerator,
            conversionDenominator: _initialConversionDenominator
        });
        supportedTokens.push(_initialUnderlyingToken);
    }

    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");
        require(token != address(underlyingToken), "Cannot remove initial token");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    // Ghi đè wrap để hỗ trợ nhiều underlying token
    function wrap(uint256 underlyingAmount) public virtual override {
        revert("Use wrap(address, uint256) instead");
    }

    function wrap(address underlyingTokenAddr, uint256 underlyingAmount) public {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingTokenAddr];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingTokenAddr).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    // Ghi đè unwrap để hỗ trợ nhiều underlying token
    function unwrap(uint256 wrappedAmount) public virtual override {
        revert("Use unwrap(address, uint256) instead");
    }

    function unwrap(address underlyingTokenAddr, uint256 wrappedAmount) public {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingTokenAddr];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingTokenAddr).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }

    // Hàm mới: Chuyển token có phí
    function mtxTransferWithFee(
        address from,
        address recipient,
        uint256 amount,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");
        require(feeAmount <= amount, "Fee exceeds amount");
        require(feeAmount <= (amount * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of amount");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_WITH_FEE_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        uint256 amountAfterFee = amount - feeAmount;

        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
            emit TransferFeePaid(from, feeRecipient, amount, feeAmount);
        }
        _transfer(from, recipient, amountAfterFee);
    }
}
```


## Block 34 (14 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của MultiUnderlyingWrappedERC20MetaTx
const contractAddress = 'MULTI_WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, wallet);

async function addTokens() {
    await contract.addUnderlyingToken('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 1, 1); // USDC: 1:1
    await contract.addUnderlyingToken('0xdAC17F958D2ee523a2206206994597C13D831ec7', 1, 3); // USDT: 3:1
    console.log("Tokens added!");
}

addTokens();
```


## Block 35 (53 dòng)

```javascript
async function signAndTransferWithFee(recipient, amount, feeAmount, feeRecipient) {
    const domain = {
        name: "MultiUnderlyingWrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" },
            { name: "feeAmount", type: "uint256" },
            { name: "feeRecipient", type: "address" }
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress,
        feeAmount: ethers.utils.parseUnits(feeAmount.toString(), 18),
        feeRecipient: feeRecipient
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransferWithFee(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.feeAmount,
        transferData.feeRecipient,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer with fee completed!");
}

signAndTransferWithFee('0xRecipientAddress', 1000, 10, '0xFeeRecipientAddress'); // Phí 1%
signAndTransferWithFee('0xRecipientAddress', 1000, 0, '0x0000000000000000000000000000000000000000'); // Không phí
```


## Block 36 (329 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken;
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    uint256 public conversionNumerator;
    uint256 public conversionDenominator;

    uint256 public constant MAX_FEE_PER_MILLE = 10; // 1% của amount

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 internal constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 internal constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 internal constant TRANSFER_WITH_FEE_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );
    bytes32 internal constant META_TX_WITH_FEE_TYPEHASH = keccak256(
        "MetaTransactionWithFee(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, uint256 wrappedAmount, uint256 underlyingAmount);
    event TransferFeePaid(address indexed from, address indexed feeRecipient, uint256 amount, uint256 fee);

    constructor(
        address _underlyingToken,
        uint256 _conversionNumerator,
        uint256 _conversionDenominator
    ) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        require(_conversionNumerator > 0 && _conversionDenominator > 0, "Invalid conversion rate");
        
        underlyingToken = IERC20(_underlyingToken);
        conversionNumerator = _conversionNumerator;
        conversionDenominator = _conversionDenominator;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(uint256 underlyingAmount) public virtual {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        uint256 wrappedAmount = (underlyingAmount * conversionNumerator) / conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(underlyingToken.transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(uint256 wrappedAmount) public virtual {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        uint256 underlyingAmount = (wrappedAmount * conversionDenominator) / conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(underlyingToken.transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function executeMetaTransactionWithFee(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_WITH_FEE_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        if (feeAmount > 0 && feeRecipient != address(0)) {
            uint256 tokenAmount = (feeAmount * conversionDenominator) / conversionNumerator;
            require(tokenAmount <= (totalSupply() * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of total supply");
            _transfer(from, feeRecipient, tokenAmount);
            emit TransferFeePaid(from, feeRecipient, tokenAmount, feeAmount);
        }

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function mtxTransferWithFee(
        address from,
        address recipient,
        uint256 amount,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");
        require(feeAmount <= amount, "Fee exceeds amount");
        require(feeAmount <= (amount * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of amount");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_WITH_FEE_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        uint256 amountAfterFee = amount - feeAmount;

        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
            emit TransferFeePaid(from, feeRecipient, amount, feeAmount);
        }
        _transfer(from, recipient, amountAfterFee);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 37 (116 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract MultiUnderlyingWrappedERC20MetaTx is WrappedERC20MetaTx {
    string public constant MULTI_NAME = "MultiUnderlyingWrappedERC20MetaTx";
    
    struct TokenInfo {
        bool isSupported;
        uint256 conversionNumerator;
        uint256 conversionDenominator;
    }

    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens;

    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);

    constructor(
        address _initialUnderlyingToken,
        uint256 _initialConversionNumerator,
        uint256 _initialConversionDenominator
    ) WrappedERC20MetaTx(_initialUnderlyingToken, _initialConversionNumerator, _initialConversionDenominator) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(MULTI_NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );

        underlyingTokens[_initialUnderlyingToken] = TokenInfo({
            isSupported: true,
            conversionNumerator: _initialConversionNumerator,
            conversionDenominator: _initialConversionDenominator
        });
        supportedTokens.push(_initialUnderlyingToken);
    }

    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");
        require(token != address(underlyingToken), "Cannot remove initial token");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    function wrap(uint256 underlyingAmount) public virtual override {
        revert("Use wrap(address, uint256) instead");
    }

    function wrap(address underlyingTokenAddr, uint256 underlyingAmount) public {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingTokenAddr];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingTokenAddr).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(uint256 wrappedAmount) public virtual override {
        revert("Use unwrap(address, uint256) instead");
    }

    function unwrap(address underlyingTokenAddr, uint256 wrappedAmount) public {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingTokenAddr];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingTokenAddr).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }
}
```


## Block 38 (59 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của WrappedERC20MetaTx hoặc MultiUnderlyingWrappedERC20MetaTx
const contractAddress = 'CONTRACT_ADDRESS'; // Có thể là cha hoặc con
const contract = new ethers.Contract(contractAddress, contractAbi, provider);

async function signAndTransferWithFee(recipient, amount, feeAmount, feeRecipient) {
    const domain = {
        name: contractAddress === 'MULTI_WRAPPER_ADDRESS' ? "MultiUnderlyingWrappedERC20MetaTx" : "WrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Transfer: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" },
            { name: "feeAmount", type: "uint256" },
            { name: "feeRecipient", type: "address" }
        ]
    };

    const transferData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress,
        feeAmount: ethers.utils.parseUnits(feeAmount.toString(), 18),
        feeRecipient: feeRecipient
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxTransferWithFee(
        transferData.from,
        transferData.recipient,
        transferData.amount,
        transferData.feeAmount,
        transferData.feeRecipient,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Transfer with fee completed!");
}

signAndTransferWithFee('0xRecipientAddress', 1000, 10, '0xFeeRecipientAddress');
```


## Block 39 (61 dòng)

```javascript
async function signAndExecuteWithFee(to, value, data, feeAmount, feeRecipient) {
    const domain = {
        name: contractAddress === 'MULTI_WRAPPER_ADDRESS' ? "MultiUnderlyingWrappedERC20MetaTx" : "WrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        MetaTransactionWithFee: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "data", type: "bytes" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" },
            { name: "feeAmount", type: "uint256" },
            { name: "feeRecipient", type: "address" }
        ]
    };

    const metaTxData = {
        from: wallet.address,
        to: to,
        value: value,
        data: data, // Ví dụ: contract.interface.encodeFunctionData("transfer", [recipient, amount])
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress,
        feeAmount: ethers.utils.parseUnits(feeAmount.toString(), 18),
        feeRecipient: feeRecipient
    };

    const signature = await wallet._signTypedData(domain, types, metaTxData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).executeMetaTransactionWithFee(
        metaTxData.from,
        metaTxData.to,
        metaTxData.value,
        metaTxData.data,
        metaTxData.feeAmount,
        metaTxData.feeRecipient,
        metaTxData.validUntil,
        metaTxData.chainId,
        signature
    );
    await tx.wait();
    console.log("Meta transaction with fee completed!");
}

signAndExecuteWithFee(
    contractAddress,
    0,
    contract.interface.encodeFunctionData("transfer", ['0xRecipientAddress', ethers.utils.parseUnits("1000", 18)]),
    10,
    '0xFeeRecipientAddress'
);
```


## Block 40 (341 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    IERC20 public underlyingToken;
    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    uint256 public conversionNumerator;
    uint256 public conversionDenominator;

    uint256 public constant MAX_FEE_PER_MILLE = 10; // 1% của amount

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 internal constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 internal constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 internal constant TRANSFER_WITH_FEE_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );
    bytes32 internal constant META_TX_WITH_FEE_TYPEHASH = keccak256(
        "MetaTransactionWithFee(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);
    event Wrapped(address indexed user, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, uint256 wrappedAmount, uint256 underlyingAmount);
    event TransferFeePaid(address indexed from, address indexed feeRecipient, uint256 amount, uint256 fee);

    constructor(
        address _underlyingToken,
        uint256 _conversionNumerator,
        uint256 _conversionDenominator
    ) ERC20("Wrapped ERC20 MetaTx", "wERC20") {
        require(_underlyingToken != address(0), "Invalid token address");
        require(_conversionNumerator > 0 && _conversionDenominator > 0, "Invalid conversion rate");
        
        underlyingToken = IERC20(_underlyingToken);
        conversionNumerator = _conversionNumerator;
        conversionDenominator = _conversionDenominator;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function wrap(uint256 underlyingAmount) public virtual {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        uint256 wrappedAmount = (underlyingAmount * conversionNumerator) / conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(underlyingToken.transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(uint256 wrappedAmount) public virtual {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        uint256 underlyingAmount = (wrappedAmount * conversionDenominator) / conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(underlyingToken.transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function executeMetaTransactionWithFee(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_WITH_FEE_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        // Kiểm tra và giới hạn phí nếu data là lệnh transfer
        if (feeAmount > 0 && feeRecipient != address(0) && data.length >= 4) {
            bytes4 selector = bytes4(data[0:4]);
            bytes4 transferSelector = this.transfer.selector; // 0xa9059cbb
            if (selector == transferSelector) {
                (, uint256 transferAmount) = abi.decode(data[4:], (address, uint256));
                require(feeAmount <= (transferAmount * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of transfer amount");
            } else {
                // Nếu không phải transfer, yêu cầu feeAmount = 0
                require(feeAmount == 0, "Fee only supported for transfer");
            }
        }

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        // Chuyển phí sau khi thực thi thành công
        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
            emit TransferFeePaid(from, feeRecipient, feeAmount, feeAmount);
        }

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function mtxTransferWithFee(
        address from,
        address recipient,
        uint256 amount,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");
        require(feeAmount <= amount, "Fee exceeds amount");
        require(feeAmount <= (amount * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of amount");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_WITH_FEE_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        uint256 amountAfterFee = amount - feeAmount;

        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
            emit TransferFeePaid(from, feeRecipient, amount, feeAmount);
        }
        _transfer(from, recipient, amountAfterFee);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 41 (116 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract MultiUnderlyingWrappedERC20MetaTx is WrappedERC20MetaTx {
    string public constant MULTI_NAME = "MultiUnderlyingWrappedERC20MetaTx";
    
    struct TokenInfo {
        bool isSupported;
        uint256 conversionNumerator;
        uint256 conversionDenominator;
    }

    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens;

    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);

    constructor(
        address _initialUnderlyingToken,
        uint256 _initialConversionNumerator,
        uint256 _initialConversionDenominator
    ) WrappedERC20MetaTx(_initialUnderlyingToken, _initialConversionNumerator, _initialConversionDenominator) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(MULTI_NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );

        underlyingTokens[_initialUnderlyingToken] = TokenInfo({
            isSupported: true,
            conversionNumerator: _initialConversionNumerator,
            conversionDenominator: _initialConversionDenominator
        });
        supportedTokens.push(_initialUnderlyingToken);
    }

    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");
        require(token != address(underlyingToken), "Cannot remove initial token");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    function wrap(uint256 underlyingAmount) public virtual override {
        revert("Use wrap(address, uint256) instead");
    }

    function wrap(address underlyingTokenAddr, uint256 underlyingAmount) public {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingTokenAddr];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingTokenAddr).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(uint256 wrappedAmount) public virtual override {
        revert("Use unwrap(address, uint256) instead");
    }

    function unwrap(address underlyingTokenAddr, uint256 wrappedAmount) public {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingTokenAddr];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingTokenAddr).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }
}
```


## Block 42 (62 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của WrappedERC20MetaTx hoặc MultiUnderlyingWrappedERC20MetaTx
const contractAddress = 'CONTRACT_ADDRESS'; // Có thể là cha hoặc con
const contract = new ethers.Contract(contractAddress, contractAbi, provider);

async function signAndExecuteWithFee(recipient, amount, feeAmount, feeRecipient) {
    const domain = {
        name: contractAddress === 'MULTI_WRAPPER_ADDRESS' ? "MultiUnderlyingWrappedERC20MetaTx" : "WrappedERC20MetaTx",
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        MetaTransactionWithFee: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "data", type: "bytes" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" },
            { name: "feeAmount", type: "uint256" },
            { name: "feeRecipient", type: "address" }
        ]
    };

    const transferData = {
        from: wallet.address,
        to: contractAddress,
        value: 0,
        data: contract.interface.encodeFunctionData("transfer", [recipient, ethers.utils.parseUnits(amount.toString(), 18)]),
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress,
        feeAmount: ethers.utils.parseUnits(feeAmount.toString(), 18),
        feeRecipient: feeRecipient
    };

    const signature = await wallet._signTypedData(domain, types, transferData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).executeMetaTransactionWithFee(
        transferData.from,
        transferData.to,
        transferData.value,
        transferData.data,
        transferData.feeAmount,
        transferData.feeRecipient,
        transferData.validUntil,
        transferData.chainId,
        signature
    );
    await tx.wait();
    console.log("Meta transaction with fee completed!");
}

signAndExecuteWithFee('0xRecipientAddress', 1000, 10, '0xFeeRecipientAddress'); // Phí 1% của 1000
```


## Block 43 (178 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedERC20MetaTx is ERC20, Ownable {
    using ECDSA for bytes32;

    string public constant NAME = "WrappedERC20MetaTx";
    string public constant VERSION = "1";
    
    mapping(address => uint256) public nonces;

    uint256 public constant MAX_FEE_PER_MILLE = 10; // 1% của amount

    struct MetaTransaction {
        address from;
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 validUntil;
        uint256 chainId;
        address wrapper;
    }

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 internal constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );
    bytes32 internal constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );

    event MetaTxExecuted(address indexed from, address indexed to, bytes data);

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function executeMetaTransaction(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        MetaTransaction memory metaTx = MetaTransaction({
            from: from,
            to: to,
            value: value,
            data: data,
            nonce: nonces[from],
            validUntil: validUntil,
            chainId: chainId,
            wrapper: address(this)
        });

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransfer(
        address from,
        address recipient,
        uint256 amount,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;
        _transfer(from, recipient, amount);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to approve");
        _approve(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to increase allowance");
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override returns (bool) {
        require(isContract(msg.sender), "EOA not allowed to decrease allowance");
        uint256 currentAllowance = allowance(msg.sender, spender);
        require(currentAllowance >= subtractedValue, "Decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    receive() external payable {}
}
```


## Block 44 (23 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract NoUnderlyingWrappedERC20MetaTx is WrappedERC20MetaTx {
    string public constant NO_UNDERLYING_NAME = "NoUnderlyingWrappedERC20MetaTx";

    constructor(string memory name, string memory symbol, uint256 initialSupply) 
        WrappedERC20MetaTx(name, symbol) 
    {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NO_UNDERLYING_NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
        _mint(msg.sender, initialSupply);
    }
}
```


## Block 45 (60 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract SingleUnderlyingWrappedERC20MetaTx is WrappedERC20MetaTx {
    string public constant SINGLE_UNDERLYING_NAME = "SingleUnderlyingWrappedERC20MetaTx";

    IERC20 public underlyingToken;
    uint256 public conversionNumerator;
    uint256 public conversionDenominator;

    event Wrapped(address indexed user, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, uint256 wrappedAmount, uint256 underlyingAmount);

    constructor(
        address _underlyingToken,
        uint256 _conversionNumerator,
        uint256 _conversionDenominator,
        string memory name,
        string memory symbol
    ) WrappedERC20MetaTx(name, symbol) {
        require(_underlyingToken != address(0), "Invalid token address");
        require(_conversionNumerator > 0 && _conversionDenominator > 0, "Invalid conversion rate");
        
        underlyingToken = IERC20(_underlyingToken);
        conversionNumerator = _conversionNumerator;
        conversionDenominator = _conversionDenominator;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(SINGLE_UNDERLYING_NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function wrap(uint256 underlyingAmount) public virtual {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        uint256 wrappedAmount = (underlyingAmount * conversionNumerator) / conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(underlyingToken.transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(uint256 wrappedAmount) public virtual {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        uint256 underlyingAmount = (wrappedAmount * conversionDenominator) / conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(underlyingToken.transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }
}
```


## Block 46 (114 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract MultiUnderlyingWrappedERC20MetaTx is WrappedERC20MetaTx {
    string public constant MULTI_UNDERLYING_NAME = "MultiUnderlyingWrappedERC20MetaTx";
    
    struct TokenInfo {
        bool isSupported;
        uint256 conversionNumerator;
        uint256 conversionDenominator;
    }

    mapping(address => TokenInfo) public underlyingTokens;
    address[] public supportedTokens;

    event Wrapped(address indexed user, uint256 underlyingAmount, uint256 wrappedAmount);
    event Unwrapped(address indexed user, uint256 wrappedAmount, uint256 underlyingAmount);
    event TokenAdded(address indexed token, uint256 numerator, uint256 denominator);
    event TokenRemoved(address indexed token);

    constructor(
        address _initialUnderlyingToken,
        uint256 _initialConversionNumerator,
        uint256 _initialConversionDenominator,
        string memory name,
        string memory symbol
    ) WrappedERC20MetaTx(name, symbol) {
        require(_initialUnderlyingToken != address(0), "Invalid token address");
        require(_initialConversionNumerator > 0 && _initialConversionDenominator > 0, "Invalid conversion rate");

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(MULTI_UNDERLYING_NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );

        underlyingTokens[_initialUnderlyingToken] = TokenInfo({
            isSupported: true,
            conversionNumerator: _initialConversionNumerator,
            conversionDenominator: _initialConversionDenominator
        });
        supportedTokens.push(_initialUnderlyingToken);
    }

    function addUnderlyingToken(
        address token,
        uint256 conversionNumerator,
        uint256 conversionDenominator
    ) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!underlyingTokens[token].isSupported, "Token already supported");
        require(conversionNumerator > 0 && conversionDenominator > 0, "Invalid conversion rate");

        underlyingTokens[token] = TokenInfo({
            isSupported: true,
            conversionNumerator: conversionNumerator,
            conversionDenominator: conversionDenominator
        });
        supportedTokens.push(token);

        emit TokenAdded(token, conversionNumerator, conversionDenominator);
    }

    function removeUnderlyingToken(address token) external onlyOwner {
        require(underlyingTokens[token].isSupported, "Token not supported");

        delete underlyingTokens[token];
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(token);
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    function wrap(address underlyingTokenAddr, uint256 underlyingAmount) public {
        require(underlyingAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingTokenAddr];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 wrappedAmount = (underlyingAmount * tokenInfo.conversionNumerator) / tokenInfo.conversionDenominator;
        require(wrappedAmount > 0, "Wrapped amount too small");

        require(IERC20(underlyingTokenAddr).transferFrom(msg.sender, address(this), underlyingAmount), "Transfer failed");
        _mint(msg.sender, wrappedAmount);
        emit Wrapped(msg.sender, underlyingAmount, wrappedAmount);
    }

    function unwrap(address underlyingTokenAddr, uint256 wrappedAmount) public {
        require(wrappedAmount > 0, "Amount must be greater than 0");
        TokenInfo memory tokenInfo = underlyingTokens[underlyingTokenAddr];
        require(tokenInfo.isSupported, "Unsupported token");

        uint256 underlyingAmount = (wrappedAmount * tokenInfo.conversionDenominator) / tokenInfo.conversionNumerator;
        require(underlyingAmount > 0, "Underlying amount too small");

        _burn(msg.sender, wrappedAmount);
        require(IERC20(underlyingTokenAddr).transfer(msg.sender, underlyingAmount), "Transfer failed");
        emit Unwrapped(msg.sender, wrappedAmount, underlyingAmount);
    }
}
```


## Block 47 (190 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./WrappedERC20MetaTx.sol";

contract PayableWrappedERC20MetaTx is WrappedERC20MetaTx {
    bytes32 internal constant TRANSFER_WITH_FEE_TYPEHASH = keccak256(
        "Transfer(address from,address recipient,uint256 amount,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );
    bytes32 internal constant META_TX_WITH_FEE_TYPEHASH = keccak256(
        "MetaTransactionWithFee(address from,address to,uint256 value,bytes data,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper,uint256 feeAmount,address feeRecipient)"
    );
    bytes32 internal constant PAY_TYPEHASH = keccak256(
        "Pay(address from,address recipient,uint256 amount,uint256 feeAmount,address feeRecipient,bytes32 payId,uint256 nonce,uint256 validUntil,uint256 chainId,address wrapper)"
    );

    event TransferFeePaid(address indexed from, address indexed feeRecipient, uint256 amount, uint256 fee);
    event Payment(address indexed from, address indexed recipient, uint256 amount, uint256 fee, address indexed feeRecipient, bytes32 payId);

    constructor(string memory name, string memory symbol) WrappedERC20MetaTx(name, symbol) {}

    function executeMetaTransactionWithFee(
        address from,
        address to,
        uint256 value,
        bytes memory data,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual returns (bytes memory) {
        require(block.timestamp <= validUntil, "MetaTx: Transaction expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_WITH_FEE_TYPEHASH,
                        from,
                        to,
                        value,
                        keccak256(data),
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        if (feeAmount > 0 && feeRecipient != address(0) && data.length >= 4) {
            bytes4 selector = bytes4(data[0:4]);
            bytes4 transferSelector = this.transfer.selector; // 0xa9059cbb
            if (selector == transferSelector) {
                (, uint256 transferAmount) = abi.decode(data[4:], (address, uint256));
                require(feeAmount <= (transferAmount * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of transfer amount");
            } else {
                require(feeAmount == 0, "Fee only supported for transfer");
            }
        }

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "MetaTx: Execution failed");

        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
            emit TransferFeePaid(from, feeRecipient, feeAmount, feeAmount);
        }

        emit MetaTxExecuted(from, to, data);
        return returnData;
    }

    function mtxTransferWithFee(
        address from,
        address recipient,
        uint256 amount,
        uint256 feeAmount,
        address feeRecipient,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual {
        require(block.timestamp <= validUntil, "MetaTx: Transfer expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");
        require(feeAmount <= amount, "Fee exceeds amount");
        require(feeAmount <= (amount * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of amount");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        TRANSFER_WITH_FEE_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this),
                        feeAmount,
                        feeRecipient
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        uint256 amountAfterFee = amount - feeAmount;

        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
            emit TransferFeePaid(from, feeRecipient, amount, feeAmount);
        }
        _transfer(from, recipient, amountAfterFee);
    }

    function mtxPay(
        address from,
        address recipient,
        uint256 amount,
        uint256 feeAmount,
        address feeRecipient,
        bytes32 payId,
        uint256 validUntil,
        uint256 chainId,
        bytes memory signature
    ) public virtual {
        require(block.timestamp <= validUntil, "MetaTx: Payment expired");
        require(chainId == block.chainid, "MetaTx: Invalid chainId");
        require(recipient != address(0), "Invalid recipient");
        require(feeAmount <= amount, "Fee exceeds amount");
        require(feeAmount <= (amount * MAX_FEE_PER_MILLE) / 1000, "Fee exceeds 1% of amount");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        PAY_TYPEHASH,
                        from,
                        recipient,
                        amount,
                        feeAmount,
                        feeRecipient,
                        payId,
                        nonces[from],
                        validUntil,
                        chainId,
                        address(this)
                    )
                )
            )
        );

        address signer = digest.recover(signature);
        require(signer == from, "MetaTx: Invalid signature");

        nonces[from]++;

        uint256 amountAfterFee = amount - feeAmount;

        if (feeAmount > 0 && feeRecipient != address(0)) {
            _transfer(from, feeRecipient, feeAmount);
        }
        _transfer(from, recipient, amountAfterFee);

        emit Payment(from, recipient, amount, feeAmount, feeRecipient, payId);
    }
}
```


## Block 48 (80 dòng)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./NoUnderlyingWrappedERC20MetaTx.sol";
import "./SingleUnderlyingWrappedERC20MetaTx.sol";
import "./MultiUnderlyingWrappedERC20MetaTx.sol";
import "./PayableWrappedERC20MetaTx.sol";

contract WrappedERC20Factory {
    mapping(address => address) public wrappedTokens;
    address[] public allWrappers;

    event WrapperCreated(address indexed wrapper, string wrapperType);

    function createNoUnderlyingWrapper(string memory name, string memory symbol, uint256 initialSupply) external returns (address) {
        NoUnderlyingWrappedERC20MetaTx wrapper = new NoUnderlyingWrappedERC20MetaTx(name, symbol, initialSupply);
        wrappedTokens[address(0)] = address(wrapper); // Không có underlying token
        allWrappers.push(address(wrapper));
        emit WrapperCreated(address(wrapper), "NoUnderlying");
        return address(wrapper);
    }

    function createSingleUnderlyingWrapper(
        address underlyingToken,
        uint256 conversionNumerator,
        uint256 conversionDenominator,
        string memory name,
        string memory symbol
    ) external returns (address) {
        require(underlyingToken != address(0), "Invalid token address");
        require(wrappedTokens[underlyingToken] == address(0), "Wrapper already exists");

        SingleUnderlyingWrappedERC20MetaTx wrapper = new SingleUnderlyingWrappedERC20MetaTx(
            underlyingToken,
            conversionNumerator,
            conversionDenominator,
            name,
            symbol
        );
        wrappedTokens[underlyingToken] = address(wrapper);
        allWrappers.push(address(wrapper));
        emit WrapperCreated(address(wrapper), "SingleUnderlying");
        return address(wrapper);
    }

    function createMultiUnderlyingWrapper(
        address initialUnderlyingToken,
        uint256 initialConversionNumerator,
        uint256 initialConversionDenominator,
        string memory name,
        string memory symbol
    ) external returns (address) {
        require(initialUnderlyingToken != address(0), "Invalid token address");
        require(wrappedTokens[initialUnderlyingToken] == address(0), "Wrapper already exists");

        MultiUnderlyingWrappedERC20MetaTx wrapper = new MultiUnderlyingWrappedERC20MetaTx(
            initialUnderlyingToken,
            initialConversionNumerator,
            initialConversionDenominator,
            name,
            symbol
        );
        wrappedTokens[initialUnderlyingToken] = address(wrapper);
        allWrappers.push(address(wrapper));
        emit WrapperCreated(address(wrapper), "MultiUnderlying");
        return address(wrapper);
    }

    function getWrapper(address underlyingToken) external view returns (address) {
        return wrappedTokens[underlyingToken];
    }

    function getWrapperCount() external view returns (uint256) {
        return allWrappers.length;
    }

    function getAllWrappers() external view returns (address[] memory) {
        return allWrappers;
    }
}
```


## Block 49 (62 dòng)

```javascript
const ethers = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('YOUR_RPC_URL');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);
const contractAbi = [...]; // ABI của PayableWrappedERC20MetaTx
const contractAddress = 'PAYABLE_WRAPPER_ADDRESS';
const contract = new ethers.Contract(contractAddress, contractAbi, provider);

async function signAndPay(recipient, amount, feeAmount, feeRecipient, payId) {
    const domain = {
        name: "WrappedERC20MetaTx", // Tên có thể thay đổi tùy contract con
        version: "1",
        chainId: await provider.getNetwork().chainId,
        verifyingContract: contractAddress
    };

    const types = {
        Pay: [
            { name: "from", type: "address" },
            { name: "recipient", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "feeAmount", type: "uint256" },
            { name: "feeRecipient", type: "address" },
            { name: "payId", type: "bytes32" },
            { name: "nonce", type: "uint256" },
            { name: "validUntil", type: "uint256" },
            { name: "chainId", type: "uint256" },
            { name: "wrapper", type: "address" }
        ]
    };

    const payData = {
        from: wallet.address,
        recipient: recipient,
        amount: ethers.utils.parseUnits(amount.toString(), 18),
        feeAmount: ethers.utils.parseUnits(feeAmount.toString(), 18),
        feeRecipient: feeRecipient,
        payId: ethers.utils.keccak256(ethers.utils.toUtf8Bytes(payId)), // Ví dụ payId
        nonce: await contract.nonces(wallet.address),
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        chainId: await provider.getNetwork().chainId,
        wrapper: contractAddress
    };

    const signature = await wallet._signTypedData(domain, types, payData);

    const relayer = new ethers.Wallet('RELAYER_PRIVATE_KEY', provider);
    const tx = await contract.connect(relayer).mtxPay(
        payData.from,
        payData.recipient,
        payData.amount,
        payData.feeAmount,
        payData.feeRecipient,
        payData.payId,
        payData.validUntil,
        payData.chainId,
        signature
    );
    await tx.wait();
    console.log("Payment completed!");
}

signAndPay('0xRecipientAddress', 1000, 10, '0xFeeRecipientAddress', "Payment123");
```
