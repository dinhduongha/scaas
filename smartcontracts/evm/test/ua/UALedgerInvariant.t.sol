// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UALedgerBase} from "./UALedgerBase.sol";

/// Random mixes of native moves, mints, burns, `transferToUA` and `uaExecuteTransfer` (any side native or derived,
/// with or without a fee). After every call the handler replays the token's `Transfer` logs per native holder and
/// checks `UATransfer` is emitted exactly for the moves with a derived side.
contract UALedgerHandler is Test {
    bytes32 internal constant TRANSFER_SIG = keccak256("Transfer(address,address,uint256)");
    bytes32 internal constant UATRANSFER_SIG = keccak256("UATransfer(bytes32,bytes32,uint256)");
    address internal constant RELAYER = address(0xBEEF);
    address internal constant FEE_TO = address(0xFEE);

    NoUnderlyingToken internal immutable tok;
    UARegistry internal immutable reg;
    address internal immutable minter;
    uint256[3] internal pks = [uint256(0xA11CE), 0xB0B, 0xCA401];
    bytes32[2] public uas;
    bytes[2] internal keys;
    uint16[2] internal kinds;
    mapping(address => int256) public replay;

    constructor(
        NoUnderlyingToken tok_, UARegistry reg_, address minter_, bytes32[2] memory uas_, bytes[2] memory keys_,
        uint16[2] memory kinds_
    ) {
        (tok, reg, minter) = (tok_, reg_, minter_);
        (uas, keys, kinds) = (uas_, keys_, kinds_);
        replay[vm.addr(pks[0])] = int256(tok_.balanceOf(vm.addr(pks[0])));
        vm.recordLogs();
    }

    function natives() public view returns (address[6] memory a) {
        a = [vm.addr(pks[0]), vm.addr(pks[1]), vm.addr(pks[2]), RELAYER, FEE_TO, MetaTxLib.UA_POOL];
    }

    // ----- ops -----

    function mint(uint256 who, uint256 amount) external {
        amount = bound(amount, 0, 1e12);
        vm.prank(minter);
        tok.mint(vm.addr(pks[who % 3]), amount);
        _settle(0, 1);
    }

    function burn(uint256 who, uint256 amount) external {
        address a = vm.addr(pks[who % 3]);
        amount = bound(amount, 0, tok.balanceOf(a));
        vm.prank(a);
        tok.burn(amount);
        _settle(0, 1);
    }

    function nativeTransfer(uint256 from, uint256 to, uint256 amount) external {
        address a = vm.addr(pks[from % 3]);
        amount = bound(amount, 0, tok.balanceOf(a));
        vm.prank(a);
        tok.transfer(vm.addr(pks[to % 3]), amount);
        _settle(0, 1);
    }

    function transferToUA(uint256 from, uint256 ua, uint256 amount) external {
        address a = vm.addr(pks[from % 3]);
        amount = bound(amount, 0, tok.balanceOf(a));
        vm.prank(a);
        tok.transferToUA(uas[ua % 2], amount);
        _settle(1, 1);
    }

    /// `from`/`to` index 0–2 a native holder, 3–4 a UA; `withFee` adds a FIXED fee to `FEE_TO` (1 % cap).
    function uaTransfer(uint256 from, uint256 to, uint256 amount, bool withFee) external {
        bytes32 f = _id(from % 5);
        bytes32 t = _id(to % 5);
        uint256 have = tok.balanceOfUA(f);
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({
            from: f, to: t, value: bound(amount, 0, have), entryRef: 0, batch: 1, nonce: tok.uaNonce(f, 1),
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: RELAYER, fee: 0,
            feeRecipient: address(0)
        });
        uint256 fee = withFee ? x.value / 100 : 0;
        if (fee != 0 && x.value + fee <= have) {
            x.mode |= MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT | MetaTxLib.MODE_FEE_FIXED;
            (x.fee, x.feeRecipient) = (fee, FEE_TO);
        } else {
            fee = 0;
        }
        bytes memory auth = _auth(from % 5, tok.uaTransferDigest(x));
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(x, auth);
        bool fromUA = from % 5 > 2;
        bool toUA = to % 5 > 2;
        uint256 moves = fee != 0 ? 2 : 1;
        // derived side ⇒ UATransfer per move; a native side ⇒ Transfer per move (the fee always lands natively)
        _settle(fromUA || toUA ? (fromUA ? moves : 1) : 0, fromUA && toUA ? moves - 1 : moves);
    }

    // ----- helpers -----

    function _id(uint256 i) internal view returns (bytes32) {
        return i < 3 ? bytes32(uint256(uint160(vm.addr(pks[i])))) : uas[i - 3];
    }

    function _auth(uint256 i, bytes32 digest) internal view returns (bytes memory) {
        if (i < 3) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], digest);
            return abi.encodePacked(r, s, v);
        }
        bytes memory k = keys[i - 3];
        bytes32 message = reg.uaMessage(kinds[i - 3], UAKinds.PURPOSE_METATX, digest);
        return abi.encode(k, abi.encodePacked(keccak256(abi.encode(k, message))));
    }

    /// Replays this call's `Transfer` logs and checks the event counts.
    function _settle(uint256 wantUATransfers, uint256 wantTransfers) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 transfers;
        uint256 uaTransfers;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(tok)) continue;
            if (logs[i].topics[0] == UATRANSFER_SIG) ++uaTransfers;
            if (logs[i].topics[0] != TRANSFER_SIG) continue;
            ++transfers;
            address from = address(uint160(uint256(logs[i].topics[1])));
            address to = address(uint160(uint256(logs[i].topics[2])));
            int256 v = int256(abi.decode(logs[i].data, (uint256)));
            if (from != address(0)) replay[from] -= v;
            if (to != address(0)) replay[to] += v;
        }
        assertEq(uaTransfers, wantUATransfers, "UATransfer iff a side is derived");
        assertEq(transfers, wantTransfers, "Transfer iff a native balance changes");
        vm.recordLogs();
    }
}

/// T-V3-2: `totalSupply == Σ balanceOf(native incl. UA_POOL)`, `balanceOf(UA_POOL) == Σ _uaBalance`, replaying
/// `Transfer` logs equals `balanceOf` for every native holder (`UA_POOL` included); `UATransfer` iff a side is derived
/// (checked per call by the handler).
contract UALedgerInvariantTest is UALedgerBase {
    UALedgerHandler internal h;

    function setUp() public override {
        super.setUp();
        bytes32[2] memory u = [uaP, uaB];
        bytes[2] memory k = [_key(UAKinds.P256), _key(UAKinds.BIP340)];
        uint16[2] memory kd = [UAKinds.P256, UAKinds.BIP340];
        h = new UALedgerHandler(tok, lreg, address(this), u, k, kd); // this fixture is the token's minter
        targetContract(address(h));
    }

    function invariant_T_V3_2_supply() public view {
        address[6] memory a = h.natives();
        uint256 sum;
        for (uint256 i; i < a.length; ++i) sum += tok.balanceOf(a[i]);
        assertEq(tok.totalSupply(), sum);
    }

    function invariant_T_V3_2_pool() public view {
        assertEq(tok.balanceOf(POOL), tok.balanceOfUA(h.uas(0)) + tok.balanceOfUA(h.uas(1)));
    }

    function invariant_T_V3_2_replay() public view {
        address[6] memory a = h.natives();
        for (uint256 i; i < a.length; ++i) assertEq(h.replay(a[i]), int256(tok.balanceOf(a[i])));
    }
}
