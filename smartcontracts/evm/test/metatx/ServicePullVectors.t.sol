// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RefServiceEscrow} from "./helpers/RefServiceEscrow.sol";
import {spDepositRef, spNoteRef, spDomain} from "./helpers/ServicePullKit.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";

/// @notice The forge cross-check of `../vectors/metatx/servicepull.json` (spec 2026-11-09-service-pull §10; plan T78), whose
///         rows come from `gen_servicepull.py` (Python, computed apart from these contracts): per row, a real `NormalToken`
///         clone etched at the row's token address with the row's `chain_uid`, the reference service etched at the row's
///         service address, the router deployed at the row's router address; then the service's own `entryRef`,
///         `servicePullEntries()` and `eip712Domain()` return data, the token's own transfer digest, the entry's calldata,
///         and two landings from one state: the row's calldata directly (the unbound `feeRecipient` row refused with
///         `ServicePullShape(2)`), and the row's `relay` calldata through the router (the fee in the pulled token on the
///         pull's lane at `n + 1`). Read only: nothing here writes the file. UNAUDITED.
contract ServicePullVectorsTest is Test {
    string internal constant FILE = "../vectors/metatx/servicepull.json";
    address internal constant REL = address(0x7E1A);

    string internal f;
    string internal p;

    /// `SERVICEPULL_FILE` (a path under `../vectors`) reads another file: the gate's tamper step, which must go red.
    function setUp() public {
        f = vm.readFile(vm.envOr("SERVICEPULL_FILE", string(FILE)));
        vm.warp(1_800_000_000);
    }

    function _s(string memory k) internal view returns (string memory) {
        return vm.parseJsonString(f, string.concat(p, k));
    }

    function _b32(string memory k) internal view returns (bytes32) {
        return vm.parseJsonBytes32(f, string.concat(p, k));
    }

    function _u(string memory k) internal view returns (uint256) {
        return vm.parseJsonUint(f, string.concat(p, k));
    }

    function _a(string memory k) internal view returns (address) {
        return vm.parseJsonAddress(f, string.concat(p, k));
    }

    function _b(string memory k) internal view returns (bytes memory) {
        return vm.parseJsonBytes(f, string.concat(p, k));
    }

    function _t() internal view returns (MetaTxLib.UAMetaTransfer memory t) {
        t = MetaTxLib.UAMetaTransfer(_b32(".t.from"), _b32(".t.to"), _u(".t.value"), _b32(".t.entryRef"), _u(".t.batch"),
            _u(".t.nonce"), _u(".t.validUntil"), uint32(_u(".t.mode")), _a(".t.relayer"), _u(".t.fee"), _a(".t.feeRecipient"));
    }

    function _auth() internal view returns (IUARegistry.UASig memory a) {
        a.keyData = _b(".auth.keyData");
        a.signature = _b(".auth.signature");
    }

    /// The row's token (a clone of a fresh implementation, the env's `chain_uid` the row's salt) and service.
    function _place() internal returns (address tok, RefServiceEscrow s) {
        vm.chainId(_u(".chainId"));
        tok = _a(".token.address");
        vm.etch(tok, EnvKit.runtime(address(new NormalToken(address(this), "")), EnvKit.env(_b32(".token.salt"), address(0), address(0), false)));
        s = RefServiceEscrow(_a(".service.address"));
        vm.etch(address(s), address(new RefServiceEscrow(tok)).code);
        assertEq(s.TOKEN(), tok);
    }

    function _checkRow(uint256 i) internal {
        p = string.concat(".rows[", vm.toString(i), "]");
        string memory name = _s(".name");
        (address tok, RefServiceEscrow s) = _place();
        // the two domains
        assertEq(MtxDigest.domainSeparator(tok), _b32(".token.domainSeparator"), name);
        assertEq(s.domainSeparator(), _b32(".service.domainSeparator"), name);
        assertEq(spDomain(address(s), block.chainid), _b32(".service.domainSeparator"), name);
        // the discovery views, byte for byte
        {
            (bytes4[] memory sel, string[] memory ty, address[] memory tk) = s.servicePullEntries();
            assertEq(abi.encode(sel, ty, tk), _b(".service.entriesReturn"), name);
            (bytes1 fl, string memory n, string memory v, uint256 cid, address vc, bytes32 salt, uint256[] memory ext) =
                s.eip712Domain();
            assertEq(abi.encode(fl, n, v, cid, vc, salt, ext), _b(".service.domainReturn"), name);
        }
        // the operation digest (the service's own and the kit's), the transfer digest (the token's own), the calldata
        MetaTxLib.UAMetaTransfer memory t = _t();
        IUARegistry.UASig memory a = _auth();
        bytes memory cd;
        bytes32 ref;
        if (keccak256(bytes(_s(".entry"))) == keccak256("deposit")) {
            RefServiceEscrow.Deposit memory op = RefServiceEscrow.Deposit(_b32(".typedData.message.payer"),
                _u(".typedData.message.amount"), uint64(_u(".typedData.message.releaseAfter")), _b32(".typedData.message.salt"));
            (ref, cd) = (s.depositRef(op), abi.encodeCall(RefServiceEscrow.deposit, (op, t, a)));
            assertEq(spDepositRef(address(s), block.chainid, op), ref, name);
        } else {
            RefServiceEscrow.Note memory op = RefServiceEscrow.Note(_b32(".typedData.message.payer"),
                _u(".typedData.message.amount"), _s(".typedData.message.memo"), _b(".typedData.message.commitment"),
                _b32(".typedData.message.salt"));
            (ref, cd) = (s.noteRef(op), abi.encodeCall(RefServiceEscrow.note, (op, t, a)));
            assertEq(spNoteRef(address(s), block.chainid, op), ref, name);
        }
        assertEq(ref, _b32(".entryRef"), name);
        assertEq(t.entryRef, ref, name);
        assertEq(MetaTokenBase(tok).mtxTransferDigest(t), _b32(".transferDigest"), name);
        assertEq(cd, _b(".calldata"), name);
        assertEq(bytes4(cd), bytes4(_b(".selector")), name);
        // the landings
        address signer = _a(".signer");
        deal(tok, signer, 10_000);
        uint256 snap = vm.snapshotState();
        vm.prank(REL);
        (bool ok, bytes memory ret) = address(s).call(_b(".calldata"));
        if (!vm.parseJsonBool(f, string.concat(p, ".serviceAccepts"))) {
            assertFalse(ok, name);
            assertEq(ret, abi.encodeWithSelector(RefServiceEscrow.ServicePullShape.selector, uint8(2)), name);
            assertTrue(_b32(".transferDigestUncanon") != _b32(".transferDigest"), name);
            return;
        }
        assertTrue(ok, name);
        assertEq(IERC20(tok).balanceOf(address(s)), t.value, name);
        vm.revertToState(snap);
        address router = _a(".relayFee.router");
        deployCodeTo("RelayFeeRouter.sol:RelayFeeRouter", router);
        vm.prank(REL);
        (ok, ret) = router.call(_b(".relayFee.relayCalldata"));
        assertTrue(ok, name);
        assertEq(IERC20(tok).balanceOf(address(s)), t.value, name);
        assertEq(IERC20(tok).balanceOf(REL), _u(".relayFee.value"), name);
        assertEq(MetaTokenBase(tok).mtxNonce(t.from, t.batch), 2, name);
        assertEq(keccak256(cd), _b32(".relayFee.callDataHash"), name);
        assertEq(keccak256(abi.encodePacked("scaas.relayfee", block.chainid, address(s), keccak256(cd))),
            _b32(".relayFee.relayRef"), name);
    }

    function test_servicePullVectors() public {
        uint256 n;
        while (vm.keyExistsJson(f, string.concat(".rows[", vm.toString(n), "]"))) ++n;
        assertEq(n, 3, "rows");
        for (uint256 i; i < n; ++i) {
            uint256 snap = vm.snapshotState(); // the rows share the token and service addresses: each from a clean state
            _checkRow(i);
            vm.revertToState(snap);
        }
    }
}
