// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IGovernanceRouter} from "../governance/IGovernanceRouter.sol";
import {IOpenFactory} from "./IOpenFactory.sol";
import {IFactoryToken} from "./IFactoryToken.sol";
import {ChainEnvCode} from "./ChainEnvCode.sol";
import {Create3} from "./Create3.sol";
import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {UAAdmin} from "../governance/UAAdmin.sol";
import {IAdmin} from "../governance/IAdmin.sol";

/// @title `OpenFactory` (CTR-TOK-03, CTR-TOK-25, CTR-TOK-29): the one token factory of a chain (plan 5g-Z2), at the same
///        address on every chain.
/// @notice Anyone creates tokens and DEXes; the admin (a UA, `UAAdmin`: round 3r, CTR-GOV-23) configures the chain once
///         (`configureChain`: `chain_uid`, the notice period, the router), publishes deployment environments
///         (`publishTokenEnv`, versioned per kind, never changed), approves releases by hash (`approve*`), from which anyone
///         deploys them from init code (`deployTokenImplementation`, `deployDexImplementation`: the factory's own
///         `CREATE2` of chain-neutral code, `abi.encode(factory, implArgs)` appended, so a release has the same address on
///         every chain; each linked library checked by code hash; the env checked by the release's `validateEnv`; the
///         native admin's own deploy is its own approval), enables kinds and deprecates releases: it has no power over any
///         token or DEX.
///         The catalogue is append-only; a release is usable `noticePeriod` seconds after its deployment, and a deprecated
///         one is no longer creatable (owner 2026-10-20). Creation is CREATE3 (chain-neutral spec §4) with the salt
///         `keccak256(abi.encode(creatorId, class, kind, salt))`: an EIP-1167 clone of the release with the instance's
///         `ChainEnv` appended to its code (`ChainEnvCode`), `initialize(creatorId, version, initArgs)` in the same call,
///         then `chainUid()` must be this factory's. `initArgs` and every kind-specific check (flags, legs, the Zether /
///         PQZ verifier and chain gates) are the implementation's. The admin is the trust root for code (an `msig` or a
///         PQ UA through the router after `configureChain`, spec §5.5). **Zether, PQZ and the admin are UNAUDITED.**
///         The index (CTR-TOK-27, factory index spec §2): one record per created contract and two append-only lists per
///         class (all, by creator), written in the creating call, read by paged views; no owner information (round 3r
///         R1, CTR-GOV-23): the factory reads no admin of anything it creates.
contract OpenFactory is IOpenFactory, UAAdmin {
    /// @dev `Created` without `addr` (the key), two slots: creator, class ‖ kind ‖ version ‖ block ‖ time.
    struct Rec {
        bytes32 creatorId;
        uint16 contractClass;
        uint16 kind;
        uint64 version;
        uint64 createdBlock;
        uint64 createdAt;
    }

    uint16 public constant CLASS_TOKEN = 1;
    uint16 public constant CLASS_DEX = 2;
    uint256 public constant MAX_PAGE = 100;
    uint256 internal constant MAX_LEGS = 8;
    uint8 public constant DEX_DOMAIN = type(uint8).max;
    /// @dev The longest notice period (review 5g-Z2 P2-4): near `2^64` every `deployTokenImplementation` would overflow
    ///      `usableFrom` and brick the catalogue.
    uint64 public constant MAX_NOTICE_PERIOD = 30 days;
    /// @dev EIP-2935's history contract, queried with a raw 32-byte block number (chain-neutral spec §3.1, Fable P3-2).
    address internal constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    /// @dev The approval key's tag per deploy domain (spec §5.6 table).
    bytes32 private constant _TAG_TOKEN = keccak256("scaas.factory.release.token");
    bytes32 private constant _TAG_DEX = keccak256("scaas.factory.release.dex");
    bytes32 private constant _TAG_CLASS = keccak256("scaas.factory.release.class");
    /// @dev EIP-165's stipend for one `supportsInterface` probe, and the floor's margin above `30,000 × 64 / 63` for the
    ///      work between the floor check and the `STATICCALL` (SigCheck's rule, CTR-DEX-08).
    uint256 private constant _PROBE_GAS = 30_000;
    uint256 private constant _PROBE_GAS_MARGIN = 5_000;
    /// @dev The most `libs` an env takes (spec §5.4, the node's decode bound; the largest env at T15, kind 13's, has 17).
    uint256 internal constant MAX_LIBS = 32;
    /// @dev The selectors the directory's checks read (raw: no other contract's source in this one's, spec §13.2).
    bytes4 private constant _REGISTRY = bytes4(keccak256("registry()"));
    bytes4 private constant _CLONE_HASH = bytes4(keccak256("smartKeyCloneHash()"));
    bytes4 private constant _EXECUTOR = bytes4(keccak256("EXECUTOR()"));
    bytes4 private constant _ROUTER = bytes4(keccak256("ROUTER()"));
    bytes4 private constant _GOV_ROUTER = bytes4(keccak256("govRouter()"));
    bytes4 private constant _IMPLEMENTATION = bytes4(keccak256("IMPLEMENTATION()"));

    /// @dev Keyed by domain: a `TokenKind`, `DEX_DOMAIN`, or a generic `class << 16 | kind` (T70; `>= 3 << 16`, so never
    ///      a token kind or the DEX). A `uint32` key hashes as the `uint8` one did: the slots did not move.
    mapping(uint32 => mapping(uint16 => IFactoryToken.Env)) private _envs;
    mapping(uint32 => mapping(uint16 => bytes32)) private _envHash;
    mapping(uint32 => uint16) private _latestEnv;
    mapping(TokenKind => mapping(uint64 => Release)) private _releases;
    mapping(TokenKind => uint64) private _latest;
    mapping(uint64 => Release) private _dexReleases;
    uint64 private _latestDex;
    /// @dev Bit `kind` set = creation enabled; the plain kinds start on.
    uint256 private _enabled = 3;
    /// @dev Slot 8, where the record's predecessor `_info` was (the Zether state vectors read it).
    mapping(address => Rec) private _rec; // contractClass 0 = not made here
    mapping(bytes32 => mapping(address => address[])) private _wrappers;
    mapping(address => address[]) private _byUnderlying;
    mapping(uint16 => address[]) private _all;
    mapping(bytes32 => mapping(uint16 => address[])) private _byCreator;
    /// @notice This chain's values, written once by `configureChain` (chain-neutral spec §3.1); 0 until then. After the
    ///         maps, so the record stays at slot 8.
    bytes32 public chainUid;
    uint64 public noticePeriod;
    address public govRouter;
    /// @dev The generic catalogue (T70), keyed by domain `class << 16 | kind`.
    mapping(uint32 => mapping(uint64 => ClassRelease)) private _classReleases;
    mapping(uint32 => uint64) private _latestClass;
    mapping(uint32 => bool) private _classKindOn;
    mapping(uint32 => bool) private _kindListed;
    mapping(uint16 => uint16[]) private _kinds;
    uint16[] private _classes;
    /// @notice The chain's directory (spec §13.3): write-once entries, 0 until `setChainEntries` writes them; one slot each.
    address public relayFeeRouter;
    address public complianceRegistry;
    address public smartKeyAccountFactory;
    address public zetherStatements;
    /// @dev The release approvals (spec §5.6), last of the sequential state.
    mapping(bytes32 => Approval) private _approvals;
    /// @dev EIP-1153: the creator of the generic creation in progress (`creating()`).
    bytes32 private constant _CREATING = 0xfb6648c4edba346670e48ab59d9f85fccdaa57cff45f53cfe24389cb1a67d992; // keccak256("scaas.factory.creating")

    /// @param admin_ the first admin, the only constructor argument, the same native id on every chain (an EOA, or a
    ///        contract deployed deterministically with its owners in its init code: chain-neutral spec §3.4); a derived
    ///        id could act only through a router, which `configureChain` names later (spec §5.2, Q1).
    constructor(bytes32 admin_) {
        if (admin_ == bytes32(0) || uint256(admin_) >> 160 != 0) revert AdminNotNative(admin_);
        _initAdmin(admin_);
    }

    /// @dev The router whose `subject()` names the admin: this chain's `govRouter` (0 before `configureChain`, so that
    ///      call is direct only), the source `_creatorId()` reads too.
    function _adminRouter() internal view override returns (address) {
        return govRouter;
    }

    /// @dev Every creation, publish and deploy entry: nothing before `configureChain`.
    modifier configured() {
        if (chainUid == bytes32(0)) revert ChainNotConfigured();
        _;
    }

    // ------------------------------------------------------------------ the chain (chain-neutral spec §3.1)

    /// @notice Admin only (direct: before it there is no router), once. `chainUid_` must equal the genesis hash whenever the EVM can prove it
    ///         (`BLOCKHASH(0)` within 256 blocks, else EIP-2935; no answer is nothing to compare); a reference block
    ///         `refBlock ≠ 0` must have the hash `refHash` on this chain (no answer is a mismatch), which ties the
    ///         transaction to this chain against a sibling with the same chain id (Fable P1-1); a router has the code
    ///         hash `govRouterCodeHash`, names the same `chainUid()`, a `registry()` with code and that registry's
    ///         `smartKeyCloneHash()` (spec §13.3, §13.4); router 0 with hash 0 is none.
    function configureChain(bytes32 chainUid_, uint64 noticePeriod_, address govRouter_, bytes32 govRouterCodeHash,
        uint256 refBlock, bytes32 refHash) external onlyAdmin
    {
        if (chainUid != bytes32(0)) revert ChainAlreadyConfigured();
        if (chainUid_ == bytes32(0)) revert ChainUidZero();
        if (noticePeriod_ > MAX_NOTICE_PERIOD) revert NoticePeriodTooLong(noticePeriod_);
        bytes32 g = block.number <= 256 ? blockhash(0) : _history(0);
        if (g != bytes32(0) && g != chainUid_) revert ChainUidNotGenesis(chainUid_, g);
        if (refBlock != 0) {
            bytes32 a = blockhash(refBlock);
            if (a == bytes32(0)) a = _history(refBlock);
            if (a == bytes32(0) || a != refHash) revert RefBlockMismatch(refBlock, refHash, a);
        }
        if (govRouter_ != address(0)) _checkRouter(govRouter_, govRouterCodeHash, chainUid_);
        else if (govRouterCodeHash != bytes32(0)) revert CodeHashMismatch(address(0), govRouterCodeHash, bytes32(0));
        (chainUid, noticePeriod, govRouter) = (chainUid_, noticePeriod_, govRouter_);
        emit ChainConfigured(chainUid_, noticePeriod_, govRouter_);
    }

    /// @dev The router's code is the admin's hash, its `chainUid()` this chain's, its `registry()` an account with code
    ///      (0 included in "no code"), its `smartKeyCloneHash()` its registry's; a call that answers no word fails closed.
    function _checkRouter(address r, bytes32 codeHash, bytes32 chainUid_) private view {
        _requireCode(r, codeHash);
        _requireChainUid(r, chainUid_);
        (bool ok, uint256 w) = _word(r, _REGISTRY);
        address reg = address(uint160(w));
        if (!ok || w >> 160 != 0 || reg.code.length == 0) revert RouterRegistryInvalid(reg);
        (bool okR, uint256 a) = _word(r, _CLONE_HASH);
        (bool okG, uint256 b) = _word(reg, _CLONE_HASH);
        if (!okR || !okG || a != b) revert SmartKeyCloneHashMismatch(bytes32(a), bytes32(b));
    }

    // ------------------------------------------------------------------ the directory (spec §13)

    /// @notice Admin only, after `configureChain`: the write-once entries (spec §13.3; `IOpenFactory.setChainEntries`).
    function setChainEntries(address relayFeeRouter_, bytes32 relayFeeRouterCodeHash, bytes32 relayFeeExecutorCodeHash,
        address complianceRegistry_, bytes32 complianceRegistryCodeHash, address smartKeyAccountFactory_,
        bytes32 smartKeyAccountFactoryCodeHash, address zetherStatements_, bytes32 zetherStatementsCodeHash)
        external onlyAdmin configured
    {
        if (relayFeeRouter_ != address(0)) {
            _entry(relayFeeRouter, relayFeeRouter_, relayFeeRouterCodeHash, IOpenFactory.relayFeeRouter.selector);
            bytes4 v = IOpenFactory.relayFeeExecutor.selector;
            address x = _addr(relayFeeRouter_, _EXECUTOR, v);
            _requireCode(x, relayFeeExecutorCodeHash);
            if (_addr(x, _ROUTER, v) != relayFeeRouter_) revert EntryMismatch(v);
            relayFeeRouter = relayFeeRouter_;
        }
        if (complianceRegistry_ != address(0)) {
            bytes4 v = IOpenFactory.complianceRegistry.selector;
            _entry(complianceRegistry, complianceRegistry_, complianceRegistryCodeHash, v);
            if (_addr(complianceRegistry_, _GOV_ROUTER, v) != govRouter) revert EntryMismatch(v);
            complianceRegistry = complianceRegistry_;
        }
        if (smartKeyAccountFactory_ != address(0)) {
            bytes4 v = IOpenFactory.smartKeyAccountFactory.selector;
            _entry(smartKeyAccountFactory, smartKeyAccountFactory_, smartKeyAccountFactoryCodeHash, v);
            _requireChainUid(smartKeyAccountFactory_, chainUid);
            if (govRouter != address(0)) {
                bytes32 want = _routerCloneHash();
                bytes32 got = _cloneHash(_addr(smartKeyAccountFactory_, _IMPLEMENTATION, v));
                if (got != want) revert SmartKeyCloneHashMismatch(want, got);
            }
            smartKeyAccountFactory = smartKeyAccountFactory_;
        }
        if (zetherStatements_ != address(0)) {
            _entry(zetherStatements, zetherStatements_, zetherStatementsCodeHash, IOpenFactory.zetherStatements.selector);
            zetherStatements = zetherStatements_;
        }
    }

    function directory() external view returns (Directory memory) {
        return Directory(uaRegistry(), govRouter, relayFeeRouter, relayFeeExecutor(), complianceRegistry,
            smartKeyAccountFactory, zetherStatements);
    }

    /// @notice The router's `registry()` (an immutable of its pinned code: one source, spec §13.4); 0 without a router.
    function uaRegistry() public view returns (address) {
        address r = govRouter;
        return r == address(0) ? address(0) : _addr(r, _REGISTRY, IOpenFactory.uaRegistry.selector);
    }

    /// @notice The written relay router's `EXECUTOR()`; 0 until written.
    function relayFeeExecutor() public view returns (address) {
        address r = relayFeeRouter;
        return r == address(0) ? address(0) : _addr(r, _EXECUTOR, IOpenFactory.relayFeeExecutor.selector);
    }

    /// @dev A write-once entry: its slot still 0 (`EntryAlreadySet`), `target`'s code the admin's hash; then its event.
    function _entry(address current, address target, bytes32 codeHash, bytes4 v) private {
        if (current != address(0)) revert EntryAlreadySet(v);
        _requireCode(target, codeHash);
        emit ChainEntrySet(v, target, codeHash);
    }

    /// @dev `target`'s code hash is `codeHash`, which pins code (not 0, not `keccak256("")`).
    function _requireCode(address target, bytes32 codeHash) private view {
        if (codeHash == bytes32(0) || codeHash == keccak256("") || target.codehash != codeHash) {
            revert CodeHashMismatch(target, codeHash, target.codehash);
        }
    }

    /// @dev `target.sel()` as one address word, else `EntryMismatch(v)` (fail closed).
    function _addr(address target, bytes4 sel, bytes4 v) private view returns (address) {
        (bool ok, uint256 w) = _word(target, sel);
        if (!ok || w >> 160 != 0) revert EntryMismatch(v);
        return address(uint160(w));
    }

    /// @dev The router's `smartKeyCloneHash()` (checked against its registry's at `configureChain`).
    function _routerCloneHash() private view returns (bytes32) {
        (bool ok, uint256 w) = _word(govRouter, _CLONE_HASH);
        if (!ok) revert EntryMismatch(IOpenFactory.govRouter.selector);
        return bytes32(w);
    }

    /// @dev The EIP-1167 clone code hash of `impl`, as the router and the UA registry hold it (`UAMetaTxBase.sol:48`).
    function _cloneHash(address impl) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
    }

    // ------------------------------------------------------------------ the admin (spec §5.2)

    /// @notice Two steps, as `UAAdmin`, after `configureChain` (Fable P2-4: a slip or a sibling's replayed direct call cannot
    ///         end an unconfigured factory, whose address is the same on every chain).
    function transferAdmin(bytes32 newAdmin) public override(IAdmin, UAAdmin) configured {
        super.transferAdmin(newAdmin);
    }

    function renounceAdmin() external configured {
        _renounceAdmin();
    }

    function adminGeneration() external view returns (uint32) {
        return _adminStorage().adminGeneration;
    }

    // ------------------------------------------------------------------ release approvals (spec §5.6)

    function approveTokenRelease(TokenKind kind, uint64 version, uint16 envVersion, bytes32 initcodeHash,
        bytes32 implArgsHash, bytes32 chainUid_, address factory_, uint32 adminGeneration_, uint64 until)
        external onlyAdmin configured
    {
        _approve(_tokenKey(kind, version, envVersion, initcodeHash, implArgsHash), chainUid_, factory_, adminGeneration_,
            until);
    }

    function approveDexRelease(uint64 version, uint16 envVersion, bytes32 initcodeHash, bytes32 implArgsHash,
        bytes32 chainUid_, address factory_, uint32 adminGeneration_, uint64 until) external onlyAdmin configured
    {
        _approve(_dexKey(version, envVersion, initcodeHash, implArgsHash), chainUid_, factory_, adminGeneration_, until);
    }

    function approveRelease(ReleaseId calldata id, uint16 envVersion, bytes4 initSelector, bytes4 interfaceId,
        bytes32 initcodeHash, bytes32 implArgsHash, bytes32 chainUid_, address factory_, uint32 adminGeneration_,
        uint64 until) external onlyAdmin configured
    {
        _approve(_classKey(id, envVersion, initSelector, interfaceId, initcodeHash, implArgsHash), chainUid_, factory_,
            adminGeneration_, until);
    }

    function revokeApproval(bytes32 key) external onlyAdmin configured {
        if (_approvals[key].state != ApprovalState.LIVE) revert ApprovalNotRevocable(key);
        delete _approvals[key];
        emit ReleaseApprovalRevoked(key);
    }

    function approvalOf(bytes32 key) external view returns (Approval memory) {
        return _approvals[key];
    }

    /// @dev The approval's own fields are the factory's; `until` in `(now, now + 30 days]`; a live entry of the key stays,
    ///      any other is overwritten.
    function _approve(bytes32 key, bytes32 chainUid_, address factory_, uint32 generation, uint64 until) private {
        if (chainUid_ != chainUid) revert ApprovalFieldMismatch(ApprovalField.CHAIN_UID);
        if (factory_ != address(this)) revert ApprovalFieldMismatch(ApprovalField.FACTORY);
        if (generation != _adminStorage().adminGeneration) revert ApprovalFieldMismatch(ApprovalField.ADMIN_GENERATION);
        if (until <= block.timestamp || until > block.timestamp + MAX_NOTICE_PERIOD) revert ApprovalTooLong(until);
        Approval storage a = _approvals[key];
        if (_live(a)) revert ApprovalLive(key);
        (a.state, a.adminGeneration, a.until) = (ApprovalState.LIVE, generation, until);
        emit ReleaseApproved(key, generation, until);
    }

    function _live(Approval storage a) private view returns (bool) {
        return a.state == ApprovalState.LIVE && a.adminGeneration == _adminStorage().adminGeneration
            && block.timestamp <= a.until;
    }

    /// @dev A deploy's gate (spec §5.6 item 3): a live approval of `key` is consumed; without one, only the native admin's
    ///      own call passes (`msg.sender` alone, never a router's subject, never a 7702 designator).
    function _useApproval(bytes32 key) private {
        Approval storage a = _approvals[key];
        if (_live(a)) a.state = ApprovalState.CONSUMED;
        else if (bytes32(uint256(uint160(msg.sender))) != _adminStorage().admin || SigCheck.isDesignator(msg.sender)) {
            revert ReleaseNotApproved(key);
        }
    }

    function _tokenKey(TokenKind kind, uint64 version, uint16 envVersion, bytes32 initcodeHash, bytes32 implArgsHash)
        private view returns (bytes32)
    {
        return keccak256(abi.encode(_TAG_TOKEN, chainUid, address(this), kind, version, envVersion, initcodeHash,
            implArgsHash));
    }

    function _dexKey(uint64 version, uint16 envVersion, bytes32 initcodeHash, bytes32 implArgsHash)
        private view returns (bytes32)
    {
        return keccak256(abi.encode(_TAG_DEX, chainUid, address(this), version, envVersion, initcodeHash, implArgsHash));
    }

    /// @dev `id` encodes in place, its three words (`contractClass, kind, version`).
    function _classKey(ReleaseId calldata id, uint16 envVersion, bytes4 initSelector, bytes4 interfaceId,
        bytes32 initcodeHash, bytes32 implArgsHash) private view returns (bytes32)
    {
        return keccak256(abi.encode(_TAG_CLASS, chainUid, address(this), id, envVersion, initSelector, interfaceId,
            initcodeHash, implArgsHash));
    }

    // ------------------------------------------------------------------ environments

    function publishTokenEnv(TokenKind kind, uint16 envVersion, IFactoryToken.Env calldata env)
        external onlyAdmin configured
    {
        emit EnvPublished(uint8(kind), envVersion, _publish(uint8(kind), envVersion, env));
    }

    function publishDexEnv(uint16 envVersion, IFactoryToken.Env calldata env) external onlyAdmin configured {
        emit EnvPublished(DEX_DOMAIN, envVersion, _publish(DEX_DOMAIN, envVersion, env));
    }

    function tokenEnvOf(TokenKind kind, uint16 envVersion) external view returns (IFactoryToken.Env memory) {
        return _envs[uint8(kind)][envVersion];
    }

    function dexEnvOf(uint16 envVersion) external view returns (IFactoryToken.Env memory) {
        return _envs[DEX_DOMAIN][envVersion];
    }

    function latestTokenEnvVersion(TokenKind kind) external view returns (uint16) { return _latestEnv[uint8(kind)]; }

    function latestDexEnvVersion() external view returns (uint16) { return _latestEnv[DEX_DOMAIN]; }

    // ------------------------------------------------------------------ releases

    function deployTokenImplementation(
        TokenKind kind,
        uint64 version,
        uint16 envVersion,
        bytes calldata initcode,
        bytes calldata implArgs
    ) external configured returns (address implementation) {
        _useApproval(_tokenKey(kind, version, envVersion, keccak256(initcode), keccak256(implArgs)));
        if (kind == TokenKind.RETIRED_6 || kind == TokenKind.RETIRED_7) revert KindRetired(kind);
        if (version == 0) revert VersionUnknown(kind, 0);
        address existing = _releases[kind][version].implementation;
        if (existing != address(0)) revert VersionAlreadyRegistered(kind, version, existing);
        Release memory r;
        (implementation, r) = _deploy(uint8(kind), envVersion, keccak256(abi.encode(kind, version)), initcode,
            abi.encode(address(this), implArgs));
        _checkImplementation(kind, implementation, _chainEnv(uint8(kind), envVersion));
        _checkModules(implementation, uint8(kind), envVersion);
        _releases[kind][version] = r;
        if (version > _latest[kind]) _latest[kind] = version;
        emit ImplementationDeployed(kind, version, implementation, r.envVersion, r.envHash, keccak256(initcode),
            implementation.codehash, r.usableFrom);
    }

    function deprecateToken(TokenKind kind, uint64 version, string calldata reason) external onlyAdmin {
        if (_releases[kind][version].implementation == address(0)) revert VersionUnknown(kind, version);
        _releases[kind][version].deprecated = true;
        emit TokenImplementationDeprecated(kind, version, reason);
    }

    function setTokenKindEnabled(TokenKind kind, bool on) external onlyAdmin {
        uint256 bit = 1 << uint8(kind);
        _enabled = on ? _enabled | bit : _enabled & ~bit;
        emit TokenKindEnabled(kind, on);
    }

    function tokenKindEnabled(TokenKind kind) public view returns (bool) { return _enabled & (1 << uint8(kind)) != 0; }

    function releaseOf(TokenKind kind, uint64 version) external view returns (Release memory) {
        return _releases[kind][version];
    }

    function implementationOf(TokenKind kind, uint64 version) external view returns (address) {
        return _releases[kind][version].implementation;
    }

    function isTokenDeprecated(TokenKind kind, uint64 version) external view returns (bool) {
        return _releases[kind][version].deprecated;
    }

    function latestVersion(TokenKind kind) external view returns (uint64) { return _latest[kind]; }

    // ------------------------------------------------------------------ create

    function createToken(TokenKind kind, uint64 version, bytes calldata initArgs, bytes32 salt)
        external configured returns (address)
    {
        Release storage r = _releases[kind][version];
        address impl = r.implementation;
        if (impl == address(0)) revert VersionUnknown(kind, version);
        if (r.deprecated) revert VersionDeprecated(kind, version);
        if (block.timestamp < r.usableFrom) revert VersionNotYetUsable(kind, version, r.usableFrom);
        return _create(kind, version, impl, r.envVersion, initArgs, salt);
    }

    /// @notice The clone carries the kind's latest published env (the admin's values for this chain).
    function createTokenUnregistered(TokenKind kind, address implementation, bytes calldata initArgs, bytes32 salt)
        external configured returns (address)
    {
        if (uint8(kind) >= uint8(TokenKind.NORMAL_ZETHER)) revert UnregisteredConfidentialKind(kind);
        uint16 v = _latestEnv[uint8(kind)];
        if (v == 0) revert EnvUnknown(uint8(kind), 0);
        _checkImplementation(kind, implementation, _chainEnv(uint8(kind), v));
        _checkModules(implementation, uint8(kind), v);
        return _create(kind, 0, implementation, v, initArgs, salt);
    }

    /// @notice Where `creatorId`'s creation of `(contractClass, kind)` with `salt` is, on every chain (CREATE3): neither
    ///         the version, the implementation nor the env moves it (chain-neutral spec §4.2, §4.3).
    function predictAddress(bytes32 creatorId, uint16 contractClass, uint16 kind, bytes32 salt)
        external view returns (address)
    {
        return Create3.addressOf(address(this), _s(creatorId, contractClass, kind, salt));
    }

    // ------------------------------------------------------------------ provenance

    function isToken(address token) external view returns (bool) { return _rec[token].contractClass == CLASS_TOKEN; }

    function isRegisteredToken(address token) external view returns (bool) {
        Rec storage r = _rec[token];
        return r.contractClass == CLASS_TOKEN && r.version != 0;
    }

    /// @notice A token's creator as an address: its native `creatorId`; 0 for a derived one (`infoOf`) or a non-token.
    function creatorOf(address token) external view returns (address) {
        Rec storage r = _rec[token];
        bytes32 c = r.creatorId;
        return r.contractClass == CLASS_TOKEN && uint256(c) >> 160 == 0 ? address(uint160(uint256(c))) : address(0);
    }

    function versionOf(address token) external view returns (TokenKind kind, uint64 version) {
        Rec storage r = _rec[token];
        if (r.contractClass == CLASS_TOKEN) return (TokenKind(r.kind), r.version);
    }

    function getWrapper(bytes32 creatorId, address underlying) external view returns (address) {
        address[] storage w = _wrappers[creatorId][underlying];
        return w.length == 0 ? address(0) : w[0];
    }

    function getWrapperCount(bytes32 creatorId, address underlying) external view returns (uint256) {
        return _wrappers[creatorId][underlying].length;
    }

    function getWrapperAt(bytes32 creatorId, address underlying, uint256 index) external view returns (address) {
        return _wrappers[creatorId][underlying][index];
    }

    function deployCountFor(address underlying) external view returns (uint256) {
        return _byUnderlying[underlying].length;
    }

    function deployedFor(address underlying, uint256 index) external view returns (address) {
        return _byUnderlying[underlying][index];
    }

    // ------------------------------------------------------------------ DEX (CTR-DEX-24)

    function deployDexImplementation(uint64 version, uint16 envVersion, bytes calldata initcode, bytes calldata implArgs)
        external configured returns (address implementation)
    {
        _useApproval(_dexKey(version, envVersion, keccak256(initcode), keccak256(implArgs)));
        if (version == 0) revert DexVersionUnknown(0);
        address existing = _dexReleases[version].implementation;
        if (existing != address(0)) revert DexVersionAlreadyRegistered(version, existing);
        Release memory r;
        (implementation, r) = _deploy(DEX_DOMAIN, envVersion, keccak256(abi.encode("dex", version)), initcode,
            abi.encode(address(this), implArgs));
        if (!SigCheck.isContract(implementation)) revert ImplementationNotAContract(implementation);
        (bool ok, uint256 got) = _word(implementation, bytes4(keccak256("factory()")));
        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);
        _validateEnv(implementation, _chainEnv(DEX_DOMAIN, envVersion));
        _checkModules(implementation, DEX_DOMAIN, envVersion);
        _dexReleases[version] = r;
        if (version > _latestDex) _latestDex = version;
        emit DexImplementationDeployed(version, implementation, r.envVersion, r.envHash, keccak256(initcode),
            implementation.codehash, r.usableFrom);
    }

    function dexReleaseOf(uint64 version) external view returns (Release memory) { return _dexReleases[version]; }

    function dexImplementationOf(uint64 version) external view returns (address) {
        return _dexReleases[version].implementation;
    }

    function deprecateDex(uint64 version, string calldata reason) external onlyAdmin {
        if (_dexReleases[version].implementation == address(0)) revert DexVersionUnknown(version);
        _dexReleases[version].deprecated = true;
        emit DexImplementationDeprecated(version, reason);
    }

    function isDexDeprecated(uint64 version) external view returns (bool) { return _dexReleases[version].deprecated; }

    function latestDexVersion() external view returns (uint64) { return _latestDex; }

    function createDex(uint64 version, bytes calldata initArgs, bytes32 salt) external configured returns (address dex) {
        Release storage r = _dexReleases[version];
        address impl = r.implementation;
        if (impl == address(0)) revert DexVersionUnknown(version);
        if (r.deprecated) revert DexVersionDeprecated(version);
        if (block.timestamp < r.usableFrom) revert DexVersionNotYetUsable(version, r.usableFrom);
        bytes32 creatorId = _creatorId();
        dex = _instance(creatorId, CLASS_DEX, 0, salt, impl, _chainEnv(DEX_DOMAIN, r.envVersion));
        ISCaaSDex(dex).initialize(creatorId, version, initArgs);
        _requireChainUid(dex, chainUid);
        _index(dex, creatorId, CLASS_DEX, 0, version);
        emit DexCreated(dex, creatorId, version, impl);
    }

    function isDex(address dex) external view returns (bool) { return _rec[dex].contractClass == CLASS_DEX; }

    function dexVersionOf(address dex) external view returns (uint64) {
        Rec storage r = _rec[dex];
        return r.contractClass == CLASS_DEX ? r.version : 0;
    }

    // ------------------------------------------------------------------ the generic catalogue (index spec §8, CTR-TOK-28)

    function publishClassEnv(uint16 contractClass, uint16 kind, uint16 envVersion, IFactoryToken.Env calldata env)
        external onlyAdmin configured
    {
        uint32 d = _domain(contractClass, kind);
        bytes32 h = _publish(d, envVersion, env);
        emit ClassEnvPublished(contractClass, kind, envVersion, h);
    }

    function classEnvOf(uint16 contractClass, uint16 kind, uint16 envVersion)
        external view returns (IFactoryToken.Env memory)
    {
        return _envs[_domainOf(contractClass, kind)][envVersion];
    }

    function latestClassEnvVersion(uint16 contractClass, uint16 kind) external view returns (uint16) {
        return _latestEnv[_domainOf(contractClass, kind)];
    }

    function deployImplementation(ReleaseId calldata id, uint16 envVersion, bytes4 initSelector, bytes4 interfaceId,
        bytes calldata initcode, bytes calldata implArgs) external configured returns (address implementation)
    {
        _useApproval(_classKey(id, envVersion, initSelector, interfaceId, keccak256(initcode), keccak256(implArgs)));
        uint32 d = _domain(id.contractClass, id.kind);
        if (id.version == 0) revert ReleaseUnknown(id.contractClass, id.kind, 0);
        address existing = _classReleases[d][id.version].implementation;
        if (existing != address(0)) revert ReleaseAlreadyRegistered(id.contractClass, id.kind, id.version, existing);
        if (initSelector == bytes4(0)) revert InitSelectorZero();
        Release memory r = _newRelease(d, id, envVersion, interfaceId, initcode, implArgs);
        _register(d, id, r, initSelector, interfaceId, keccak256(initcode));
        return r.implementation;
    }

    /// @dev The generic release `id`: `CREATE2` of `initcode ‖ abi.encode(id, factory, implArgs)` under the salt
    ///      `keccak256(abi.encode("release", id))`, then its checks (`_checkRelease`) and its body modules
    ///      (`_checkModules`, CTR-TOK-30: every class's release, owner 2026-11-10).
    function _newRelease(uint32 d, ReleaseId calldata id, uint16 envVersion, bytes4 interfaceId, bytes calldata initcode,
        bytes calldata implArgs) private returns (Release memory r)
    {
        {
            bytes memory args = abi.encode(id, address(this), implArgs);
            (, r) = _deploy(d, envVersion, keccak256(abi.encode("release", id)), initcode, args);
        }
        IFactoryToken.ChainEnv memory e = _chainEnv(d, envVersion);
        _checkRelease(id, r.implementation, interfaceId, e);
        _checkModules(r.implementation, d, envVersion);
    }

    /// @dev A checked generic release into the catalogue: its row, the latest version, the class and kind lists.
    function _register(uint32 d, ReleaseId calldata id, Release memory r, bytes4 initSelector, bytes4 interfaceId,
        bytes32 initcodeHash) private
    {
        _classReleases[d][id.version] =
            ClassRelease(r.implementation, r.envVersion, r.envHash, r.usableFrom, false, initSelector, interfaceId);
        if (id.version > _latestClass[d]) _latestClass[d] = id.version;
        if (_kinds[id.contractClass].length == 0) _classes.push(id.contractClass);
        if (!_kindListed[d]) {
            _kindListed[d] = true;
            _kinds[id.contractClass].push(id.kind);
        }
        emit ReleaseDeployed(id.contractClass, id.kind, id.version, r.implementation, r.envVersion, r.envHash,
            initcodeHash, r.implementation.codehash, initSelector, interfaceId, r.usableFrom);
    }

    function deprecateRelease(ReleaseId calldata id, string calldata reason) external onlyAdmin {
        ClassRelease storage r = _classReleases[_domain(id.contractClass, id.kind)][id.version];
        if (r.implementation == address(0)) revert ReleaseUnknown(id.contractClass, id.kind, id.version);
        r.deprecated = true;
        emit ReleaseDeprecated(id.contractClass, id.kind, id.version, reason);
    }

    function setClassKindEnabled(uint16 contractClass, uint16 kind, bool on) external onlyAdmin {
        _classKindOn[_domain(contractClass, kind)] = on;
        emit ClassKindEnabled(contractClass, kind, on);
    }

    function classReleaseOf(ReleaseId calldata id) external view returns (ClassRelease memory) {
        return _classReleases[_domainOf(id.contractClass, id.kind)][id.version];
    }

    function latestClassVersion(uint16 contractClass, uint16 kind) external view returns (uint64) {
        return _latestClass[_domainOf(contractClass, kind)];
    }

    function classKindEnabled(uint16 contractClass, uint16 kind) external view returns (bool) {
        return _classKindOn[_domainOf(contractClass, kind)];
    }

    function classes() external view returns (uint16[] memory) { return _classes; }

    function kindsOf(uint16 contractClass) external view returns (uint16[] memory) { return _kinds[contractClass]; }

    function createInstance(ReleaseId calldata id, bytes32 salt, bytes calldata initCall)
        external configured returns (address instance)
    {
        (address impl, IFactoryToken.ChainEnv memory e) = _usableRelease(id, initCall);
        bytes32 creatorId = _creatorId();
        instance = _instance(creatorId, id.contractClass, id.kind, salt, impl, e);
        _initInstance(instance, creatorId, initCall);
        _recordInstance(instance, creatorId, id, impl);
    }

    /// @dev Steps 1-2 of index spec §8.4: the release exists, is not deprecated, is usable, its `(class, kind)` on; the
    ///      call is its catalogued initializer.
    function _usableRelease(ReleaseId calldata id, bytes calldata initCall)
        private view returns (address impl, IFactoryToken.ChainEnv memory e)
    {
        uint32 d = _domain(id.contractClass, id.kind);
        ClassRelease storage r = _classReleases[d][id.version];
        impl = r.implementation;
        if (impl == address(0)) revert ReleaseUnknown(id.contractClass, id.kind, id.version);
        if (r.deprecated) revert ReleaseIsDeprecated(id.contractClass, id.kind, id.version);
        if (block.timestamp < r.usableFrom) revert ReleaseNotYetUsable(id.contractClass, id.kind, id.version, r.usableFrom);
        if (!_classKindOn[d]) revert ClassKindDisabled(id.contractClass, id.kind);
        bytes4 sel = r.initSelector;
        bytes4 got = initCall.length < 4 ? bytes4(0) : bytes4(initCall[:4]);
        if (got != sel || initCall.length < 4) revert InitSelectorMismatch(sel, got);
        e = _chainEnv(d, r.envVersion);
    }

    /// @dev Step 4: `initCall` to the fresh clone, value 0, with `creating()` the creator for its duration (EIP-1153; the
    ///      previous value restored: a nested creation sees its own creator, then the outer one again); a revert bubbled.
    function _initInstance(address instance, bytes32 creatorId, bytes calldata initCall) private {
        bytes32 prev;
        assembly ("memory-safe") {
            prev := tload(_CREATING)
            tstore(_CREATING, creatorId)
        }
        (bool ok, bytes memory ret) = instance.call(initCall);
        assembly ("memory-safe") {
            tstore(_CREATING, prev)
        }
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// @dev Steps 5-6: the clone's `factoryInfo()` names this factory, this chain, the release and `initialized`; then the
    ///      record and `InstanceCreated`.
    function _recordInstance(address instance, bytes32 creatorId, ReleaseId calldata id, address impl) private {
        (bool got, FactoryInfo memory fi) = _factoryInfo(instance);
        if (!got || !fi.initialized || fi.factory != address(this) || fi.contractClass != id.contractClass
            || fi.kind != id.kind || fi.version != id.version) revert InstanceInfoMismatch(instance);
        if (fi.chainUid != chainUid) revert ChainUidMismatch(chainUid, fi.chainUid);
        _index(instance, creatorId, id.contractClass, id.kind, id.version);
        emit InstanceCreated(instance, creatorId, id.contractClass, id.kind, id.version, impl);
    }

    function creating() external view returns (bytes32 c) {
        assembly ("memory-safe") {
            c := tload(_CREATING)
        }
    }

    // ------------------------------------------------------------------ the index (CTR-TOK-27)

    function infoOf(address c) external view returns (Created memory) { return _created(c); }

    function contractsPage(uint16 contractClass, uint256 from, uint256 n)
        external view returns (Created[] memory, uint256)
    {
        return _page(_all[_known(contractClass)], from, n);
    }

    function contractsOfCreator(bytes32 creatorId, uint16 contractClass, uint256 from, uint256 n)
        external view returns (Created[] memory, uint256)
    {
        return _page(_byCreator[creatorId][_known(contractClass)], from, n);
    }

    // ------------------------------------------------------------------ internal

    function _publish(uint32 domain, uint16 envVersion, IFactoryToken.Env calldata env) private returns (bytes32 envHash) {
        if (envVersion == 0) revert EnvUnknown(domain, 0);
        if (_envHash[domain][envVersion] != bytes32(0)) revert EnvAlreadyPublished(domain, envVersion);
        if (env.libs.length != env.libCodeHashes.length || env.libs.length > MAX_LIBS
            || env.deps.length > ChainEnvCode.MAX_DEPS || env.params.length > ChainEnvCode.MAX_PARAMS) revert EnvInvalid();
        // An empty pin (0: no account; keccak256(""): no code) checks nothing (review 5g-Z2 P2-1).
        for (uint256 i; i < env.libCodeHashes.length; ++i) {
            bytes32 h = env.libCodeHashes[i];
            if (h == bytes32(0) || h == keccak256("")) revert EnvInvalid();
        }
        // the registry names this chain (once per env; it was `initialize`'s check per creation, Fable P3-1); with a router,
        // the env names its registry and its `SmartKeyAccount` implementation, or none (spec §13.4)
        if (govRouter != address(0)) {
            address reg = uaRegistry();
            if (env.registry != address(0) && env.registry != reg) revert EnvRegistryMismatch(reg, env.registry);
            address ska = env.smartKeyAccountImpl;
            if (ska != address(0)) {
                bytes32 want = _routerCloneHash();
                if (_cloneHash(ska) != want) revert EnvSmartKeyAccountMismatch(want, ska);
            }
        }
        if (env.registry != address(0)) _requireChainUid(env.registry, chainUid);
        _envs[domain][envVersion] = env;
        envHash = keccak256(abi.encode(env));
        _envHash[domain][envVersion] = envHash;
        if (envVersion > _latestEnv[domain]) _latestEnv[domain] = envVersion;
    }

    /// @dev The instance env of `domain`'s env `v`: this factory's `chainUid` and router, the admin's values.
    function _chainEnv(uint32 domain, uint16 v) private view returns (IFactoryToken.ChainEnv memory c) {
        IFactoryToken.Env storage e = _envs[domain][v];
        return IFactoryToken.ChainEnv(chainUid, e.registry, govRouter, e.smartKeyAccountImpl, e.hedera, e.deps, e.params);
    }

    /// @dev The domain's env `v` (named by the deploy's caller, bound by its approval): every linked library's code hash, then `CREATE2` of
    ///      `initcode ‖ args` (chain-neutral: no env in it); a constructor's revert is bubbled, an empty failure is
    ///      `DeployFailed`.
    function _deploy(uint32 domain, uint16 v, bytes32 salt, bytes calldata initcode, bytes memory args)
        private returns (address at, Release memory r)
    {
        if (_envHash[domain][v] == bytes32(0)) revert EnvUnknown(domain, v);
        IFactoryToken.Env storage env = _envs[domain][v];
        for (uint256 i; i < env.libs.length; ++i) {
            bytes32 got = env.libs[i].codehash;
            if (got != env.libCodeHashes[i]) revert LibraryCodeHashMismatch(env.libs[i], env.libCodeHashes[i], got);
        }
        bytes memory code = bytes.concat(initcode, args);
        assembly ("memory-safe") {
            at := create2(0, add(code, 32), mload(code), salt)
            if iszero(at) {
                if returndatasize() {
                    let m := mload(0x40)
                    returndatacopy(m, 0, returndatasize())
                    revert(m, returndatasize())
                }
            }
        }
        if (at == address(0)) revert DeployFailed();
        r = Release(at, v, _envHash[domain][v], uint64(block.timestamp) + noticePeriod, false);
    }

    /// @dev Code, `kind()`, `factory()`, each read by staticcall (a missing or short answer refused), then
    ///      `validateEnv(env)`.
    function _checkImplementation(TokenKind kind, address implementation, IFactoryToken.ChainEnv memory env)
        private view
    {
        if (!SigCheck.isContract(implementation)) revert ImplementationNotAContract(implementation);
        (bool ok, uint256 got) = _word(implementation, IFactoryToken.kind.selector);
        if (!ok) got = type(uint256).max;
        if (got != uint256(kind)) revert VersionKindMismatch(kind, got);
        (ok, got) = _word(implementation, bytes4(keccak256("factory()")));
        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);
        _validateEnv(implementation, env);
    }

    /// @dev T66b §4.5, CTR-TOK-30: every body module the release names in `modules()` is one of env `v`'s `libs`, whose
    ///      code hashes `_deploy` checked; an answer that is not one ABI-encoded `address[]` is `ModulesUnreadable`. Every
    ///      release of every class answers (an empty list allowed), read once here: its answer is fixed by its code.
    function _checkModules(address implementation, uint32 domain, uint16 v) private view {
        (bool ok, bytes memory ret) = implementation.staticcall(abi.encodeWithSignature("modules()"));
        if (!ok || ret.length < 64 || ret.length % 32 != 0) revert ModulesUnreadable(implementation);
        (uint256 offset, uint256 n) = abi.decode(ret, (uint256, uint256));
        if (offset != 32 || n != (ret.length - 64) / 32) revert ModulesUnreadable(implementation);
        address[] memory ms = abi.decode(ret, (address[]));
        address[] storage libs = _envs[domain][v].libs;
        for (uint256 i; i < ms.length; ++i) {
            uint256 j;
            while (j < libs.length && libs[j] != ms[i]) ++j;
            if (j == libs.length) revert ModuleNotPinned(ms[i]);
        }
    }

    /// @dev The release's own checks of the env (`validateEnv`, by staticcall): its revert bubbled, an empty one
    ///      `EnvRefused`.
    function _validateEnv(address implementation, IFactoryToken.ChainEnv memory env) private view {
        (bool ok, bytes memory ret) = implementation.staticcall(abi.encodeCall(IFactoryToken.validateEnv, (env)));
        if (ok) return;
        if (ret.length == 0) revert EnvRefused(implementation);
        assembly ("memory-safe") {
            revert(add(ret, 32), mload(ret))
        }
    }

    /// @dev `target.chainUid()` is `expected` (`ChainUidMismatch`, `got` 0 when it does not answer one word).
    function _requireChainUid(address target, bytes32 expected) private view {
        (bool ok, uint256 got) = _word(target, bytes4(keccak256("chainUid()")));
        if (!ok || bytes32(got) != expected) revert ChainUidMismatch(expected, ok ? bytes32(got) : bytes32(0));
    }

    /// @dev EIP-2935's answer for block `n`: a revert or a return of another length is no answer (0).
    function _history(uint256 n) private view returns (bytes32 h) {
        (bool ok, bytes memory r) = HISTORY.staticcall(abi.encode(n));
        if (ok && r.length == 32) h = abi.decode(r, (bytes32));
    }

    /// @dev The creator's UA id (S3): the direct caller, `pad(msg.sender)`; from the chain's router (its one-time
    ///      `govRouter`; chain-neutral spec §4.4, plan T76), the UA it authenticated for this call, `subject()`, read once
    ///      at entry (0 refused): a native id is `pad(addr)`, the value of its direct call. A nested creation inside an
    ///      `initialize` is called by the instance: `pad(instance)`.
    function _creatorId() private view returns (bytes32 c) {
        address r = govRouter;
        if (r == address(0) || msg.sender != r) return bytes32(uint256(uint160(msg.sender)));
        c = IGovernanceRouter(r).subject();
        if (c == bytes32(0)) revert RouterSubjectZero();
    }

    function _s(bytes32 creatorId, uint16 contractClass, uint16 kind, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(creatorId, contractClass, kind, salt));
    }

    /// @dev The CREATE3 instance of `(creatorId, contractClass, kind, salt)`: a clone of `impl` with `env` appended.
    ///      Salt used (`SaltAlreadyUsed`): the proxy exists, the address has a record or code. `InstanceNotCreated`: the
    ///      proxy's `CREATE` failed (it answers success there, Fable P2-5).
    function _instance(bytes32 creatorId, uint16 contractClass, uint16 kind, bytes32 salt, address impl,
        IFactoryToken.ChainEnv memory env) private returns (address c)
    {
        bytes32 s = _s(creatorId, contractClass, kind, salt);
        address proxy = Create3.proxyOf(address(this), s);
        address predicted = Create3.instanceOf(proxy);
        if (proxy.code.length != 0 || _rec[predicted].contractClass != 0 || predicted.code.length != 0) {
            revert SaltAlreadyUsed(predicted);
        }
        c = Create3.deploy(s, ChainEnvCode.initCode(impl, ChainEnvCode.encode(env)));
        if (c == address(0)) revert InstanceNotCreated();
    }

    /// @dev The record of a creation and the two pushes.
    function _index(address c, bytes32 creatorId, uint16 contractClass, uint16 kind, uint64 version) private {
        _rec[c] = Rec(creatorId, contractClass, kind, version, uint64(block.number), uint64(block.timestamp));
        _all[contractClass].push(c);
        _byCreator[creatorId][contractClass].push(c);
    }

    function _created(address c) private view returns (Created memory x) {
        Rec storage r = _rec[c];
        if (r.contractClass == 0) return x;
        return Created(c, r.creatorId, r.contractClass, r.kind, r.version, r.createdBlock, r.createdAt);
    }

    /// @dev `contractClass` if this factory makes it (the token and DEX classes; a generic class once it has a release),
    ///      else `ClassUnknown`.
    function _known(uint16 contractClass) private view returns (uint16) {
        if (contractClass != CLASS_TOKEN && contractClass != CLASS_DEX && _kinds[contractClass].length == 0) {
            revert ClassUnknown(contractClass);
        }
        return contractClass;
    }

    /// @dev The env and release domain of a generic `(class, kind)`; the token and DEX classes and 0 are reserved.
    function _domain(uint16 contractClass, uint16 kind) private pure returns (uint32) {
        if (contractClass <= CLASS_DEX) revert ClassReserved(contractClass);
        return uint32(contractClass) << 16 | kind;
    }

    /// @dev The same key for the views, without the refusal (a reserved class reads empty).
    function _domainOf(uint16 contractClass, uint16 kind) private pure returns (uint32) {
        return uint32(contractClass) << 16 | kind;
    }

    /// @dev A generic release's checks (index spec §8.2; chain-neutral: no `chain_uid` on a release): code;
    ///      `factoryInfo()` 192 B naming this factory, its own id, initialized; ERC-165 for `0x01ffc9a7` and
    ///      `interfaceId`, not `0xffffffff`; `validateEnv`.
    function _checkRelease(ReleaseId calldata id, address impl, bytes4 interfaceId, IFactoryToken.ChainEnv memory env)
        private view
    {
        if (!SigCheck.isContract(impl)) revert ImplementationNotAContract(impl);
        (bool ok, FactoryInfo memory fi) = _factoryInfo(impl);
        if (!ok || fi.factory != address(this) || fi.contractClass != id.contractClass || fi.kind != id.kind
            || fi.version != id.version || !fi.initialized) revert ReleaseInfoMismatch(impl);
        if (!_supports(impl, 0x01ffc9a7)) revert InterfaceNotSupported(impl, 0x01ffc9a7);
        if (!_supports(impl, interfaceId)) revert InterfaceNotSupported(impl, interfaceId);
        if (_supports(impl, 0xffffffff)) revert InterfaceNotSupported(impl, 0xffffffff);
        _validateEnv(impl, env);
    }

    /// @dev `factoryInfo()` by staticcall: exactly six words, else `ok` false.
    function _factoryInfo(address target) private view returns (bool ok, FactoryInfo memory fi) {
        bytes memory ret;
        (ok, ret) = target.staticcall(abi.encodeWithSelector(bytes4(keccak256("factoryInfo()"))));
        ok = ok && ret.length == 192;
        if (ok) fi = abi.decode(ret, (FactoryInfo));
    }

    /// @dev ERC-165 by staticcall (30,000 gas, EIP-165): one word, true. Only with the gas for the whole stipend
    ///      (`ProbeGasLow` otherwise: spec §5.6 item 3, Fable re-check N3), so a failed probe is the release's answer, never
    ///      the sender's gas.
    function _supports(address target, bytes4 interfaceId) private view returns (bool) {
        uint256 left = gasleft();
        if (left < _PROBE_GAS * 64 / 63 + _PROBE_GAS_MARGIN) revert ProbeGasLow(left);
        (bool ok, bytes memory ret) =
            target.staticcall{gas: _PROBE_GAS}(abi.encodeWithSelector(0x01ffc9a7, interfaceId));
        return ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }

    function _page(address[] storage l, uint256 from, uint256 n)
        private view returns (Created[] memory page, uint256 total)
    {
        if (n > MAX_PAGE) revert PageTooLarge(n);
        total = l.length;
        uint256 m = from >= total ? 0 : total - from;
        if (m > n) m = n;
        page = new Created[](m);
        for (uint256 i; i < m; ++i) page[i] = _created(l[from + i]);
    }

    function _word(address target, bytes4 sel) private view returns (bool ok, uint256 w) {
        bytes memory ret;
        (ok, ret) = target.staticcall(abi.encodeWithSelector(sel));
        ok = ok && ret.length == 32;
        if (ok) w = abi.decode(ret, (uint256));
    }

    /// @dev The generic gate (the kind enabled), the CREATE3 clone with its env, `initialize` with the creator's
    ///      `initArgs`, the `chainUid()` post-check (an unregistered implementation's code is unvetted: what it reports as
    ///      its domain salt must be this factory's), then the record and its lists, the leg index and the event from the
    ///      token's own views (no `admin()` read: 3r R1).
    function _create(TokenKind kind, uint64 version, address impl, uint16 envVersion, bytes calldata initArgs, bytes32 salt)
        private returns (address token)
    {
        if (!tokenKindEnabled(kind)) revert KindDisabled(kind);
        bytes32 creatorId = _creatorId();
        token = _instance(creatorId, CLASS_TOKEN, uint16(kind), salt, impl, _chainEnv(uint8(kind), envVersion));
        IFactoryToken(token).initialize(creatorId, version, initArgs);
        _requireChainUid(token, chainUid);
        IGovernance t = IGovernance(token);
        _index(token, creatorId, CLASS_TOKEN, uint16(kind), version);
        address[] memory us = IFactoryToken(token).underlyings();
        if (us.length > MAX_LEGS) revert UnderlyingCountInvalid(us.length);
        for (uint256 i; i < us.length; ++i) {
            _wrappers[creatorId][us[i]].push(token);
            _byUnderlying[us[i]].push(token);
        }
        emit TokenCreated(token, creatorId, kind, version, impl, t.features(), t.lockedFeatures(), us);
    }
}
