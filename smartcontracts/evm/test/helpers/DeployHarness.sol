// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {DeployBase} from "../../script/DeployBase.sol";
import {UAPrecompileProbe} from "../../script/UAPrecompileProbe.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

/// The deploy steps without the RPC parts (`_setup`, the `eth_call` probe): the salt, `chain_uid`, `DEPLOY_ZETHER` and
/// the profile set directly; the precompile probe runs in this EVM (or its verdict is forced).
contract DeployHarness is DeployBase {
    bool internal forced;
    bool internal forcedBls;
    bool internal forcedBnG2;
    bool internal forcedPqz;
    bool internal forcedMl87;
    bool internal forcedMl44;
    bool internal forcedMl65;
    uint256 internal gateLimit;
    uint256 internal codeLimit;
    uint8 internal gate; // 0 = `RELEASE_GAS_GATE` (env, or its default), 1 = testnet, 2 = public

    constructor() {
        mldsaPrecompile = true; // `MLDSA_PRECOMPILE`'s default, `on` (`_setup` does not run here)
    }

    function force(bool bls12381, bool bn254G2) external {
        (forced, forcedBls, forcedBnG2) = (true, bls12381, bn254G2);
    }

    /// Stands in for `block.gaslimit` at the deploy gate (no cheatcode sets it); 0 = the chain's own.
    function limitBlockGas(uint256 limit) external {
        gateLimit = limit;
    }

    /// Stands in for `CHAIN_CODE_LIMIT` (the process env is shared by parallel tests); 0 = the env, or its default.
    function limitCode(uint256 limit) external {
        codeLimit = limit;
    }

    function chainCodeLimit() external view returns (uint256) {
        return _chainCodeLimit();
    }

    /// Stands in for `RELEASE_GAS_GATE` (the process env is shared by parallel tests): 1 = `testnet`, 2 = `public`, 0 = the env.
    function setGate(uint8 g) external {
        gate = g;
    }

    function publicGate() external view returns (bool) {
        return _publicGate();
    }

    /// The public gate's figures of release `name` (`[regular, state]`; 0 when the testnet gate ran).
    function measured(string calldata name) external view returns (uint256 regular, uint256 state) {
        return (releaseGas[name][0], releaseGas[name][1]);
    }

    function checkMeasured(string calldata name, uint256 regular, uint256 state, uint256 limit) external pure {
        _checkMeasuredGas(name, regular, state, limit);
    }

    /// `DEPLOY_WRAPPED` for the next `deploy`.
    function setWrapped(bool w) external {
        deployWrapped = w;
    }

    /// `DEPLOY_REGULATED` for the next `deploy`.
    function setRegulated(bool r) external {
        deployRegulated = r;
    }

    /// `DEPLOY_PQCHAT` for the next `deploy` (plan 3c T92).
    function setPqChat(bool on) external {
        deployPqChat = on;
    }

    /// `NOTICE_PERIOD` for the next `deploy` (0: a release is usable at once).
    function setNotice(uint64 n) external {
        noticePeriod = n;
    }

    /// `COMPLIANCE_ADMIN` for the next `deploy` (plan T33).
    function setComplianceAdmin(address a) external {
        complianceAdmin = bytes32(uint256(uint160(a)));
    }

    function setComplianceAdminId(bytes32 a) external {
        complianceAdmin = a;
    }

    function setFactoryAdminNext(bytes32 n) external {
        factoryAdminNext = n;
    }

    function setAccountFactory(address a) external {
        accountFactory = a;
    }

    function deploy(bytes32 uid_, bool zether, address ska) external returns (OpenFactory f, string memory json) {
        return deploy(uid_, zether, ska, false);
    }

    function deploy(bytes32 uid_, bool zether, address ska, bool hedera)
        public
        returns (OpenFactory f, string memory json)
    {
        salt = keccak256("scaas.deploy.v1");
        uid = uid_;
        // the chain this harness stands for: its genesis hash, by BLOCKHASH(0) and by EIP-2935 (forge's history contract)
        if (block.number >= 1 && block.number <= 256) vm.setBlockhash(0, uid_);
        address history = 0x0000F90827F1C53a10cb7A02335B175320002935;
        if (history.code.length != 0) vm.store(history, bytes32(0), uid_);
        deployZether = zether;
        f = _deployTokenFactory(address(this), true, ska, hedera);
        json = vm.serializeBytes32("deploy", "chain_uid", uid);
    }

    function gasNeed(string calldata name) external view returns (uint256) {
        return _releaseGasNeed(name);
    }

    /// `RELEASES_JSON` / `RELEASES_WRITE` for the next `deploy` (chain-neutral spec §6.2, plan T73); `writeReleases` as
    /// `run()` ends.
    function setReleases(string calldata path, bool write) external {
        (releasesPath, releasesWrite) = (path, write);
    }

    function writeReleases() external {
        _writeReleases();
    }

    /// NET-EVM-13: a test chain is not in `chain-uids.json`; its books' name stands for `DEPLOY_NAME` (no env in a test).
    function _deployName() internal pure override returns (string memory) {
        return "local-testnet";
    }

    function checkGas(string calldata name, uint256 limit) external view {
        _checkReleaseGas(name, limit);
    }

    function requireGas(string calldata name) external view {
        _requireReleaseGas(name);
    }

    function noticeFor(uint256 chainId, uint256 notice) external pure returns (uint64) {
        return _checkedNotice(chainId, notice);
    }

    function pqKindFits(uint64 cap, uint64 budget) external pure returns (bool) {
        return _pqKindFits(cap, budget);
    }

    function checkGen1Kinds(IUARegistry reg, bool bls, bool hedera) external view {
        _checkGen1Kinds(reg, bls, hedera, false, false);
    }

    function checkGen1Kinds(IUARegistry reg, bool bls, bool hedera, bool pqz, bool ml87) external view {
        _checkGen1Kinds(reg, bls, hedera, pqz, ml87);
    }

    /// The chain's PQ precompile verdict (`_pqPrecompiles`: no RPC in a test), default none.
    function forcePq(bool pqz, bool ml87) external {
        (forcedPqz, forcedMl87) = (pqz, ml87);
    }

    /// The chain's `mldsa44` / `mldsa65` precompile verdict (owner 2026-11-15), default none.
    function forceMl(bool ml44, bool ml65) external {
        (forcedMl44, forcedMl65) = (ml44, ml65);
    }

    /// `DEPLOY_PQZ`, `PQZ_KEY_VERIFIER`, `MLDSA87_VERIFIER` for the next `deploy` (owner 2026-11-15).
    function setPqz(bool on, address pqzVerifier, address ml87Verifier) external {
        (deployPqz, pqzKeyVerifier, mldsa87Verifier) = (on, pqzVerifier, ml87Verifier);
    }

    /// `MLDSA_PRECOMPILE` (on / off), `MLDSA44_VERIFIER`, `MLDSA65_VERIFIER` for the next `deploy` (owner 2026-11-15).
    function setMldsa(bool on, address ml44Verifier, address ml65Verifier) external {
        (mldsaPrecompile, mldsa44Verifier, mldsa65Verifier) = (on, ml44Verifier, ml65Verifier);
    }

    /// MD-5: `_cacheFits` of ML-DSA kind `i` at the (stood-in) block gas limit.
    function cacheFits(uint256 i) external view returns (bool) {
        return _cacheFits(i);
    }

    /// MD-15: the real `_pqPrecompiles` (its `eth_call`; a test has no RPC, so the call fails).
    function realPq() external returns (bool pqz, bool[3] memory ml) {
        return DeployBase._pqPrecompiles();
    }

    function _pqPrecompiles() internal view override returns (bool, bool[3] memory) {
        return (forcedPqz, [forcedMl44, forcedMl65, forcedMl87]);
    }

    function defaultNotice(uint256 chainId) external pure returns (uint256) {
        return _defaultNotice(chainId);
    }

    function _blockGasLimit() internal view override returns (uint256) {
        return gateLimit == 0 ? super._blockGasLimit() : gateLimit;
    }

    function _publicGate() internal view override returns (bool) {
        return gate == 0 ? super._publicGate() : gate == 2;
    }

    function _chainCodeLimit() internal view override returns (uint256) {
        return codeLimit == 0 ? super._chainCodeLimit() : codeLimit;
    }

    function _precompiles() internal override returns (bool, bool) {
        if (forced) return (forcedBls, forcedBnG2);
        return abi.decode(address(new UAPrecompileProbe()).code, (bool, bool));
    }
}
