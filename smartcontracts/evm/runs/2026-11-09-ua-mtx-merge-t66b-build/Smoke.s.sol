// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUALedgerViews} from "../../src/metatx/IUALedgerViews.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";

/// @notice Plan T66b Step 5, the smoke on a DeployBase deploy (its `deployments/<chainid>.json`, `DEPLOY_JSON`): on the demo
///         token (DEMO_SUPPLY), one relayed `mtxTransfer` (the payer signs, the relayer sends) and one
///         `RelayFeeRouter.relay` that runs a second relayed transfer and pays the relayer a fee of 1 unit (open mode, the
///         payer's `UARelayFee`). The payer is the deployer (it holds the demo supply). Keys from the environment
///         (`SMOKE_PAYER_KEY`, `SMOKE_RELAYER_KEY`), never printed. Test chains only. UNAUDITED.
contract T66bSmoke is Script {
    bytes32 constant SALTED_DOMAIN =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 constant UA_RELAY_FEE = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)");
    uint256 constant FEE_LANE = 2;

    address tok;
    address router;
    uint256 pk;
    uint256 rk;
    bytes32 from;
    bytes32 to;
    uint256 vu;

    function run() external {
        string memory j = vm.readFile(vm.envString("DEPLOY_JSON"));
        tok = vm.parseJsonAddress(j, ".demo_token");
        router = vm.parseJsonAddress(j, ".relay_fee_router");
        pk = vm.envUint("SMOKE_PAYER_KEY");
        rk = vm.envUint("SMOKE_RELAYER_KEY");
        from = MetaTxLib.pad(vm.addr(pk));
        to = MetaTxLib.pad(vm.addr(rk));
        vu = block.timestamp + 1 hours;
        uint256 n = IUALedgerViews(tok).mtxNonce(from, 0);
        // 1. one relayed transfer
        bytes memory cd1 = _transfer(n);
        vm.broadcast(rk);
        (bool ok,) = tok.call(cd1);
        require(ok, "relayed mtxTransfer");
        // 2. one relay-fee call: the router's executor runs a second relayed transfer, then the payer's fee goes to the caller
        uint256 fn = _relayFee(_transfer(n + 1));
        require(IUALedgerViews(tok).mtxNonce(from, 0) == n + 2, "transfer lane");
        require(IUALedgerViews(tok).mtxNonce(from, FEE_LANE) == fn + 1, "fee lane");
        console2.log("smoke ok: relayed mtxTransfer, then RelayFeeRouter.relay (a relayed mtxTransfer + a relay fee of 1)");
    }

    function _relayFee(bytes memory cd) internal returns (uint256 fn) {
        fn = IUALedgerViews(tok).mtxNonce(from, FEE_LANE);
        bytes32 payee = MetaTxLib.pad(router);
        bytes32 d = keccak256(abi.encodePacked(hex"1901", _domain(tok), keccak256(abi.encode(
            UA_RELAY_FEE, from, tok, keccak256(cd), payee, uint256(1), FEE_LANE, fn, vu, router))));
        IUARegistry.UASig memory s;
        s.signature = _sig(pk, d);
        vm.broadcast(rk);
        RelayFeeRouter(router).relay(tok, cd, tok, from, payee, 1, FEE_LANE, fn, vu, s);
    }

    function _transfer(uint256 n) internal view returns (bytes memory) {
        MetaTxLib.UAMetaTransfer memory t;
        (t.from, t.to, t.value, t.nonce, t.validUntil) = (from, to, 1, n, vu);
        IUARegistry.UASig memory s;
        s.signature = _sig(pk, IERC20MetaTx(tok).mtxTransferDigest(t));
        return abi.encodeCall(IMetaTokenV2.mtxTransfer, (from, to, 1, 0, n, vu, 0, address(0), s));
    }

    function _domain(address c) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = IERC5267(c).eip712Domain();
        return keccak256(abi.encode(SALTED_DOMAIN, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }
}
