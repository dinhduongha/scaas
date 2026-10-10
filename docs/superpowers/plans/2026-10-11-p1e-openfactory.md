# P1e — `OpenFactory` with `createToken`/`TokenConfig`, the CREATE2 deployer and the `chainUid()` gate, the size gate; v1 kept as `…V1` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace factory v2 by the one token factory of CTR-TOK-03/25 (`OpenFactory`: `chain_uid` immutable, catalogue
checks `kind()`/`factory()`/`chainUid()`, `createToken`/`createTokenUnregistered` with `TokenConfig`, one
`TokenCreated`), move both token kinds onto `initialize(creator, version, TokenConfig)`, deploy every contract through
the deterministic CREATE2 deployer with a `chainUid()` gate (CTR-GEN-05/06, NET-EVM-05), and add the CI size gate
(CTR-TOK-24) as a ratchet. The v1 line keeps building under `…V1` names until its consumers move (owner: backup, not delete).

**Architecture:** `OpenFactory` = `git mv` of `OpenFactoryV2`, rewritten. `IFactoryToken` (new content) holds
`TokenConfig` (+ `Leg`, `RateConfig`, `ConfidentialConfig`; roles = `AdminLib.Roles`), `initialize`, `kind()`, and
`ConfigFieldForOtherKind`. `MetaTokenBase.initialize(creator, version, cfg)` → `_init(cfg)`; each kind returns a constant
`kind()` and refuses fields of other kinds. `UnderlyingLib.initToken(cfg, isHedera)` reads `cfg.legs` — the same legs
the factory indexes. Deploy scripts share `script/DeployBase.sol`.

**Tech Stack:** Solidity 0.8.28, Foundry (forge 1.3.5; `new X{salt: s}` in a broadcast goes through forge-std's
`CREATE2_FACTORY` 0x4e59b44847b379578588920ca78fbf26c0b4956c), OpenZeppelin 5.2.0, forge-std 1.16.2; Python 3 for the
size gate; `scaas-node` e2e (Rust, anvil) as the deploy check.

**Spec:** `docs/contracts/token-wrappers.md` CTR-TOK-03, -21, -24, -25, §6, §12 "Factory"; `docs/contracts/README.md`
CTR-GEN-05, CTR-GEN-06; `docs/networks/evm.md` NET-EVM-05; `docs/history/specs/2026-10-08-token-tree-design.md` §7–§8;
TODO.md §00 (P1, MT-1, MT-4, P1d follow-ups). Owner 2026-10-11: "không cần xóa line v1-v2, đưa vào backup" (do not delete
the v1/v2 lines; put them in the backup) and size is optimised later.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge runs in `smartcontracts/evm` of the worktree
  `.claude/worktrees/p1e` (branch `p1e-factory`), created by the controller with `lib/` copied.
- **Heavy commands only through `scripts/capped`, one at a time machine-wide** (`timeout 900 scripts/capped bash -c
  'cd smartcontracts/evm && forge test …'`; cargo with `timeout 1800` and `CARGO_BUILD_JOBS=4`). Use `/usr/bin/grep`,
  `rtk proxy git diff`. `forge build --sizes` exits non-zero (EIP-170, P1d D2): use `forge build`/`forge test`, and
  `forge build src --sizes --json … || true` only for measuring.
- Build pins unchanged (solc 0.8.28, optimizer 200, no via-IR, EVM prague). New/touched src `pragma solidity ^0.8.24;`.
- Kinds (`IOpenFactory.TokenKind`, = the implementation's `kind()`): 0 `NONE`, 1 `UNDERLYING`, 2 `NONE_ZETHER`,
  3 `UNDERLYING_ZETHER`, 4–7 `*_PQZ` reserved (`KindReserved`). Leg count: `NONE*` 0, `UNDERLYING*` 1–8.
- `ConfigFieldForOtherKind(uint8 field)`: 1 `initialSupply`/`initialHolder` (not `NONE*`), 2 `legs` (not
  `UNDERLYING*`), 3 `rate` (not `UNDERLYING*`), 4 `conf` (not `*_ZETHER`).
- Measured in the spike: `NoUnderlyingToken` 20,196 B (≤ 20,480), `UnderlyingToken` 26,449 B (over EIP-170, ratchet
  baseline), `UnderlyingLib` 10,096, `OpenFactory` 6,715, `OpenFactoryV1` 6,057, `ZetherToken` 28,849 (baseline).
- Deploy: `DEPLOY_SALT` env (default `keccak256("scaas.deploy.v1")`); JSON `deployments/<chainid>.json` keeps `factory`,
  `implementation`, `dex`, `subject_account_factory`, `subject_account_implementation`, `scaas_dex`, `demo_token` (the
  node e2e reads `factory`, `demo_token`, `scaas_dex`) and gains `token_factory`, `implementation_none`, `chain_uid`;
  `factory_v2`/`implementation_meta_none` are gone. `forge script … --broadcast` needs `--sender <deployer address>`.
- Test chain: id 7622, `chain_uid` `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push. Never `git add claude-code-api.txt`.

## Review Focus

- An implementation registered under the wrong kind, for another factory or another chain (a clone with a foreign
  domain salt) — pinned by `test_register_checksKindFactoryAndChainUid`, `test_createTokenUnregistered_isCheckedAndRecordedAsVersion0` (Task 1).
- The factory's underlying index lying (a `NONE` token with legs, a leg not indexed, the native leg) — pinned by
  `test_createToken_legCountByKind`, `test_createToken_underlying_indexesEveryLeg_includingNative` (Task 1).
- A config field silently ignored (supply on a wrapper, a rate or a confidential config on `NONE`) — pinned by
  `test_factoryOnlyForwards_theTokenValidatesFlagsAndFields` (Task 1).
- Someone taking another creator's address, or re-initialising a clone or the implementation — pinned by
  `test_saltIsScopedByCreator_andCannotBeReused`, `test_onlyTheFactoryInitializes_andOnlyOnce` (Task 1).
- A deploy on a chain without the CREATE2 deployer or with a wrong `chain_uid` — pinned by the script's `_setup`
  requirement and `_gate` (Task 2) and the e2e runs.

## Rulings (docs vs code) and defaults taken

- **E1 — The v1 line stays in the build, renamed `…V1`, until its consumers move**, then `git mv` into the backup
  (`smartcontracts/evm/legacy/`), never deleted (owner). Consumers today: the node (`src/abi.rs` v1 struct and
  `executeMetaTransaction`, salt-less domain; the e2e uses v1 `MetaToken` demo tokens) and clientkeys (`metatx_v1_kat.json`)
  until P5; `ZetherToken`/`ZetherMetaTx`/`IZetherToken` (v1 interfaces, `LegacyMetaTransaction`, created through the v1
  factory) until P3. Renames: `OpenFactory` → `OpenFactoryV1` (`src/factory/OpenFactoryV1.sol`), `IOpenFactory` →
  `IOpenFactoryV1` (`src/common/IOpenFactoryV1.sol`), `IFactoryToken` → `IFactoryTokenV1`
  (`src/factory/IFactoryTokenV1.sol`), `test/OpenFactory.t.sol` → `test/OpenFactoryV1.t.sol`. ABI selectors do not change.
- **E2 — Factory v2 becomes `OpenFactory`** (`git mv` + rewrite, as the spec's "renames v2 and adds the chainUid
  check"); `IOpenFactoryV2` → `src/factory/IOpenFactory.sol`, `IFactoryTokenV2` → `IFactoryToken` (new content). The
  three v2 files as they are on `main` are copied verbatim into `smartcontracts/evm/legacy/p1e/` (backup, not built).
- **E3 — Not in `OpenFactory` yet:** Zether creation (`*_ZETHER`, P3; `ZetherToken` stays on `OpenFactoryV1`),
  `createDex`/`isDex`/`DexCreated` (P2), the registrar's `setZetherEnabled` (P3).
- **E4 — `kind()` is a pure constant** of each implementation (registration reads it before any clone exists); the
  factory checks `kind()`, `factory()`, `chainUid()` for registered **and** unregistered implementations.
- **E5 — `TokenConfig` lives in `IFactoryToken`**; a field of another kind reverts `ConfigFieldForOtherKind(field)`
  (spec silent; a token never carries a setting it ignores, and the index never lies).
- **E6 — One source for the legs:** the factory indexes `cfg.legs` and the token reads the same `cfg.legs`, so the P1d
  cross-check of init legs against the factory's `underlyings` (ruling D8) is gone.
- **E7 — CREATE2 for every contract the scripts deploy** (the v1 line included) through forge's deterministic deployer;
  the scripts stop when it is missing (runbook NET-EVM-05). Linked libraries (`AdminLib`, `HederaLib`, `UnderlyingLib`)
  are still placed by forge from `--sender`; the e2e and `deploy.sh` pass `--sender`.
- **E8 — Deploy gate in the scripts:** `chainUid()` of the factory and of each implementation equals the `chain_uid`
  read from the RPC (`CHAIN_UID` env or block 0's hash). The node's gate at chain activation stays P5.
- **E9 — Size gate = ratchet** (`scripts/size_gate.py`, `smartcontracts/evm/size-baseline.json`): token implementations
  ≤ 20,480, everything else ≤ 24,576, init ≤ 49,152; a baselined contract may exceed its limit but never its recorded
  size. Baseline: `UnderlyingToken` 26,449, `ZetherToken` 28,849 (owner: optimise later).
- **E10 — `salt = chain_uid` in the other domains** (SubjectAccount/SmartKeyAccount and MandateWallet P4, `SCaaSDex`
  P2, UA registry UA F1, Zether digests P3) is not in P1e; MT-4 stays open for them.

## File Structure

| File | Task | Responsibility |
|---|---|---|
| `src/factory/IFactoryToken.sol` (new content), `src/factory/IOpenFactory.sol`, `src/factory/OpenFactory.sol` | 1 | the factory and its token interface |
| `src/factory/OpenFactoryV1.sol`, `src/common/IOpenFactoryV1.sol`, `src/factory/IFactoryTokenV1.sol` | 1 | the v1 factory, renamed (E1) |
| `src/metatx/{MetaTokenBase,NoUnderlyingToken,UnderlyingToken,UnderlyingLib,IUnderlyingToken}.sol` | 1 | init on `TokenConfig`, `kind()` constant |
| `legacy/p1e/{OpenFactoryV2,IOpenFactoryV2,IFactoryTokenV2}.sol` + `legacy/README.md` | 1 | backup (E2) |
| `test/v2/helpers/V2Fixture.sol`, `test/v2/Factory.t.sol` (replaces `FactoryV2.t.sol`), ported tests | 1 | |
| `script/DeployBase.sol` (new), `script/Deploy.s.sol`, `script/hedera/DeployHedera.s.sol`, `smartcontracts/scripts/deploy.sh`, `scaas-node/tests/e2e{,_hedera}.rs` | 2 | CREATE2, gate, `--sender` |
| `scripts/size_gate.py`, `smartcontracts/evm/size-baseline.json`, `.github/workflows/ci.yml` | 2 | size gate |
| docs, TODO, HANDOFF | 3 | |

---

### Task 1: `OpenFactory` + `TokenConfig`; v1 renamed; port the tests

**Model:** Opus, effort high (factory = the most critical immutable artifact, CTR-TOK-18; plus a port across many tests).

**Interfaces:**
- Consumes: `AdminLib.Roles`, `AdminLib.KIND_NONE/KIND_UNDERLYING`, `MetaTxBase.chainUid()`, `MetaTokenBase.factory()`.
- Produces (Task 2 relies on them): `OpenFactory(address registrar, bytes32 chainUid)`, `registerImplementation(TokenKind,
  uint64, address)`, `IOpenFactory.TokenKind.NONE`, `NoUnderlyingToken(address factory, address smartKeyAccountImpl,
  bytes32 chainUid, bool isHedera)` (unchanged), `OpenFactoryV1(address registrar)`, `IOpenFactoryV1.TokenKind.META`.
  Fixture (later plans): `noneInit(…)` and `underlyingInit(…)` return `IFactoryToken.TokenConfig`; `_clone(impl, creator,
  us, abi.encode(cfg))` asserts `us` equals the legs.

- [ ] **Step 1: Rename the v1 line (E1) and back up the v2 factory files (E2)**

```bash
cd smartcontracts/evm
mkdir -p legacy/p1e
cp src/factory/OpenFactoryV2.sol src/common/IOpenFactoryV2.sol src/factory/IFactoryTokenV2.sol legacy/p1e/
git mv src/factory/OpenFactory.sol src/factory/OpenFactoryV1.sol
git mv src/common/IOpenFactory.sol src/common/IOpenFactoryV1.sol
git mv src/factory/IFactoryToken.sol src/factory/IFactoryTokenV1.sol
git mv test/OpenFactory.t.sol test/OpenFactoryV1.t.sol
git mv src/factory/OpenFactoryV2.sol src/factory/OpenFactory.sol
git mv src/common/IOpenFactoryV2.sol src/factory/IOpenFactory.sol
git mv src/factory/IFactoryTokenV2.sol src/factory/IFactoryToken.sol
F="src/factory/OpenFactoryV1.sol src/common/IOpenFactoryV1.sol src/factory/IFactoryTokenV1.sol src/metatx/MetaToken.sol \
   src/zether/ZetherToken.sol test/hedera/HederaMetaToken.t.sol test/helpers/Fixtures.sol test/helpers/Mocks.sol \
   test/OpenFactoryV1.t.sol test/v2/MetaTxGasV2.t.sol test/zether/helpers/ZetherFixture.sol test/zether/ZetherGate.t.sol \
   script/Deploy.s.sol script/hedera/DeployHedera.s.sol script/hedera/HederaSmoke.sol"
sed -i -E 's/\bOpenFactory\b/OpenFactoryV1/g; s/\bIOpenFactory\b/IOpenFactoryV1/g; s/\bIFactoryToken\b/IFactoryTokenV1/g;
  s#/OpenFactory\.sol"#/OpenFactoryV1.sol"#; s#/IOpenFactory\.sol"#/IOpenFactoryV1.sol"#; s#/IFactoryToken\.sol"#/IFactoryTokenV1.sol"#' $F
```

Add to `legacy/README.md` one bullet: "`p1e/`: `OpenFactoryV2`, `IOpenFactoryV2`, `IFactoryTokenV2` as they stood on
`main` before P1e (the factory v2 that P1e rewrote into `OpenFactory`); not built." (The v1 line follows into `legacy/`
when node/clientkeys (P5) and Zether (P3) stop using it, E1.)

- [ ] **Step 2: `src/factory/IFactoryToken.sol`** (full text)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AdminLib} from "../metatx/AdminLib.sol";

/// @title What `OpenFactory` needs from every token implementation (CTR-TOK-25): the creation config, one
///        `initialize` the factory calls in the SAME call as `CREATE2`, and `kind()`. The factory also reads
///        `factory()` and `chainUid()` (`IMetaTx`) at registration.
interface IFactoryToken {
    /// @notice One leg of an `UNDERLYING*` kind: `underlying` (`address(0)` = the native coin, CTR-TOK-26), rate
    ///         `num/den` (CTR-TOK-04). `uint256` so a value `≥ 2^96` reverts `RateInvalid` instead of failing to decode.
    struct Leg {
        address underlying;
        uint256 num;
        uint256 den;
    }

    /// @notice With `RATE_ADJUSTABLE`: `2 days ≤ rateDelay ≤ 30 days`, `1 ≤ maxRateStepBps ≤ 1000`; without: both 0.
    struct RateConfig {
        uint32 rateDelay;
        uint16 maxRateStepBps;
    }

    /// @notice `*_ZETHER` kinds only (P3); every other kind requires it empty.
    struct ConfidentialConfig {
        address verifier;
        bytes auditorKey;
        uint256 shieldScale;
    }

    /// @notice CTR-TOK-25. Fields of another kind must be empty (`ConfigFieldForOtherKind`), so a token never carries a
    ///         setting it ignores and the factory's underlying index never lies.
    struct TokenConfig {
        string name;
        string symbol;
        uint8 decimals;
        uint256 features;
        uint256 lockedFeatures;
        address owner;               // 0 = no administration ever
        AdminLib.Roles roles;        // initial holders, each only for a set flag
        uint256 initialSupply;       // NONE* only
        address initialHolder;       // NONE* only
        Leg[] legs;                  // UNDERLYING* only, 1..8
        RateConfig rate;             // UNDERLYING* only, with RATE_ADJUSTABLE
        ConfidentialConfig conf;     // *_ZETHER only
    }

    /// @notice A field set for another kind (`field`: 1 initialSupply/initialHolder, 2 legs, 3 rate, 4 conf).
    error ConfigFieldForOtherKind(uint8 field);

    /// @notice Called by the factory only, in the same call as the clone's `CREATE2`.
    function initialize(address creator, uint64 version, TokenConfig calldata cfg) external;

    /// @notice CTR-TOK-21 kind of the implementation (and of every clone).
    function kind() external view returns (uint8);
}
```

- [ ] **Step 3: `src/factory/IOpenFactory.sol`** (full text)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "./IFactoryToken.sol";

/// @title The one token factory of a chain (CTR-TOK-03, CTR-TOK-25): an append-only catalogue of implementations per
///        kind, EIP-1167 clones by `CREATE2` initialised in the same call, no power over any token it created.
interface IOpenFactory {
    /// @notice CTR-TOK-21, a fresh enum (nothing deployed): the value equals the implementation's `kind()`. The `*_PQZ`
    ///         kinds are reserved (no implementation can be registered for them yet).
    enum TokenKind {
        NONE,
        UNDERLYING,
        NONE_ZETHER,
        UNDERLYING_ZETHER,
        NONE_PQZ,
        UNDERLYING_PQZ,
        NONE_ZETHER_PQZ,
        UNDERLYING_ZETHER_PQZ
    }

    event ImplementationRegistered(
        TokenKind indexed kind, uint64 indexed version, address indexed implementation, address registrar);
    event ImplementationDeprecated(TokenKind indexed kind, uint64 indexed version, string reason);
    /// @notice The one event of a creation.
    event TokenCreated(
        address indexed token, address indexed creator, TokenKind indexed kind, uint64 version, address implementation,
        uint256 features, uint256 lockedFeatures, address owner, address[] underlyings);

    error NotRegistrar();
    error ChainUidZero();
    error KindReserved(TokenKind kind);
    error VersionAlreadyRegistered(TokenKind kind, uint64 version, address existing);
    error VersionUnknown(TokenKind kind, uint64 version);
    /// @notice The implementation's `kind()` differs (`got = type(uint256).max` when it does not answer).
    error VersionKindMismatch(TokenKind expected, uint256 got);
    error ImplementationNotAContract(address implementation);
    error ImplementationFactoryMismatch(address implementation);
    error ChainUidMismatch(bytes32 expected, bytes32 got);
    /// @notice `NONE*` 0 legs, `UNDERLYING*` 1–8.
    error UnderlyingCountInvalid(uint256 n);
    error SaltAlreadyUsed(address existing);

    function registrar() external view returns (address);
    function chainUid() external view returns (bytes32);

    function registerImplementation(TokenKind kind, uint64 version, address implementation) external;
    function deprecate(TokenKind kind, uint64 version, string calldata reason) external;
    function implementationOf(TokenKind kind, uint64 version) external view returns (address);
    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool);
    function latestVersion(TokenKind kind) external view returns (uint64);

    function createToken(TokenKind kind, uint64 version, IFactoryToken.TokenConfig calldata cfg, bytes32 salt)
        external returns (address token);
    /// @notice Any implementation of `kind` for this factory and chain; recorded with `version == 0`.
    function createTokenUnregistered(
        TokenKind kind, address implementation, IFactoryToken.TokenConfig calldata cfg, bytes32 salt
    ) external returns (address token);

    function predictAddress(address implementation, address creator, bytes32 salt) external view returns (address);
    function isToken(address token) external view returns (bool);
    function creatorOf(address token) external view returns (address);
    function versionOf(address token) external view returns (TokenKind kind, uint64 version);
    /// @notice First token `creator` made over `underlying`; it may have several legs: read `underlyings()`.
    function getWrapper(address creator, address underlying) external view returns (address);
    function getWrapperCount(address creator, address underlying) external view returns (uint256);
    function getWrapperAt(address creator, address underlying, uint256 index) external view returns (address);
    function deployCountFor(address underlying) external view returns (uint256);
    function deployedFor(address underlying, uint256 index) external view returns (address);
}
```

- [ ] **Step 4: `src/factory/OpenFactory.sol`** (full text)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactory} from "./IOpenFactory.sol";
import {IFactoryToken} from "./IFactoryToken.sol";

/// @title `OpenFactory` (CTR-TOK-03, CTR-TOK-25): the one token factory of a chain.
/// @notice Anyone creates tokens; the registrar only appends implementations to the catalogue (and marks versions
///         deprecated): it has no power over any token. A registered implementation must answer `kind()`,
///         `factory() == this` and `chainUid() == chainUid` (so a clone's domain salt has one source, CTR-GEN-05);
///         the catalogue is append-only, so a wrong entry would be dead forever. Creation clones by `CREATE2` with
///         the salt scoped by the creator and calls `initialize` in the same call; flag validation is the token's.
///         Built kinds: `NONE`, `UNDERLYING` (the `*_ZETHER` implementations come with P3, the DEX with P2).
contract OpenFactory is IOpenFactory {
    struct Info {
        address creator;
        TokenKind kind;
        uint64 version;
        bool exists;
    }

    uint256 internal constant MAX_LEGS = 8;

    address public immutable registrar;
    bytes32 public immutable chainUid;

    mapping(TokenKind => mapping(uint64 => address)) private _impl;
    mapping(TokenKind => mapping(uint64 => bool)) private _deprecated;
    mapping(TokenKind => uint64) private _latest;
    mapping(address => Info) private _info;
    mapping(address => mapping(address => address[])) private _wrappers;
    mapping(address => address[]) private _byUnderlying;

    constructor(address registrar_, bytes32 chainUid_) {
        if (chainUid_ == bytes32(0)) revert ChainUidZero();
        registrar = registrar_;
        chainUid = chainUid_;
    }

    // ------------------------------------------------------------------ catalogue

    function registerImplementation(TokenKind kind, uint64 version, address implementation) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (version == 0) revert VersionUnknown(kind, 0);
        address existing = _impl[kind][version];
        if (existing != address(0)) revert VersionAlreadyRegistered(kind, version, existing);
        _checkImplementation(kind, implementation);
        _impl[kind][version] = implementation;
        if (version > _latest[kind]) _latest[kind] = version;
        emit ImplementationRegistered(kind, version, implementation, msg.sender);
    }

    function deprecate(TokenKind kind, uint64 version, string calldata reason) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (_impl[kind][version] == address(0)) revert VersionUnknown(kind, version);
        _deprecated[kind][version] = true;
        emit ImplementationDeprecated(kind, version, reason);
    }

    function implementationOf(TokenKind kind, uint64 version) external view returns (address) {
        return _impl[kind][version];
    }

    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool) {
        return _deprecated[kind][version];
    }

    function latestVersion(TokenKind kind) external view returns (uint64) {
        return _latest[kind];
    }

    // ------------------------------------------------------------------ create

    function createToken(TokenKind kind, uint64 version, IFactoryToken.TokenConfig calldata cfg, bytes32 salt)
        external returns (address)
    {
        address impl = _impl[kind][version];
        if (impl == address(0)) revert VersionUnknown(kind, version);
        return _create(kind, version, impl, cfg, salt);
    }

    function createTokenUnregistered(
        TokenKind kind, address implementation, IFactoryToken.TokenConfig calldata cfg, bytes32 salt
    ) external returns (address) {
        _checkImplementation(kind, implementation);
        return _create(kind, 0, implementation, cfg, salt);
    }

    function predictAddress(address implementation, address creator, bytes32 salt) public view returns (address) {
        return Clones.predictDeterministicAddress(implementation, _salt(creator, salt));
    }

    // ------------------------------------------------------------------ provenance

    function isToken(address token) external view returns (bool) { return _info[token].exists; }

    function creatorOf(address token) external view returns (address) { return _info[token].creator; }

    function versionOf(address token) external view returns (TokenKind kind, uint64 version) {
        Info storage i = _info[token];
        return (i.kind, i.version);
    }

    function getWrapper(address creator, address underlying) external view returns (address) {
        address[] storage w = _wrappers[creator][underlying];
        return w.length == 0 ? address(0) : w[0];
    }

    function getWrapperCount(address creator, address underlying) external view returns (uint256) {
        return _wrappers[creator][underlying].length;
    }

    function getWrapperAt(address creator, address underlying, uint256 index) external view returns (address) {
        return _wrappers[creator][underlying][index];
    }

    function deployCountFor(address underlying) external view returns (uint256) {
        return _byUnderlying[underlying].length;
    }

    function deployedFor(address underlying, uint256 index) external view returns (address) {
        return _byUnderlying[underlying][index];
    }

    // ------------------------------------------------------------------ internal

    /// @dev Code, `kind()`, `factory()`, `chainUid()`: each read by staticcall, a missing or short answer refused.
    function _checkImplementation(TokenKind kind, address implementation) private view {
        if (uint8(kind) > uint8(TokenKind.UNDERLYING_ZETHER)) revert KindReserved(kind);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        (bool ok, uint256 got) = _word(implementation, IFactoryToken.kind.selector);
        if (!ok) got = type(uint256).max;
        if (got != uint256(kind)) revert VersionKindMismatch(kind, got);
        (ok, got) = _word(implementation, bytes4(keccak256("factory()")));
        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);
        (ok, got) = _word(implementation, bytes4(keccak256("chainUid()")));
        if (!ok || bytes32(got) != chainUid) revert ChainUidMismatch(chainUid, ok ? bytes32(got) : bytes32(0));
    }

    function _word(address target, bytes4 sel) private view returns (bool ok, uint256 w) {
        bytes memory ret;
        (ok, ret) = target.staticcall(abi.encodeWithSelector(sel));
        ok = ok && ret.length == 32;
        if (ok) w = abi.decode(ret, (uint256));
    }

    function _salt(address creator, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(creator, salt));
    }

    function _create(TokenKind kind, uint64 version, address impl, IFactoryToken.TokenConfig calldata cfg,
        bytes32 salt) private returns (address token)
    {
        uint256 n = cfg.legs.length;
        bool wrapper = kind == TokenKind.UNDERLYING || kind == TokenKind.UNDERLYING_ZETHER;
        if (wrapper ? n == 0 || n > MAX_LEGS : n != 0) revert UnderlyingCountInvalid(n);
        bytes32 s = _salt(msg.sender, salt);
        address predicted = Clones.predictDeterministicAddress(impl, s);
        if (predicted.code.length != 0) revert SaltAlreadyUsed(predicted);
        token = Clones.cloneDeterministic(impl, s);
        IFactoryToken(token).initialize(msg.sender, version, cfg);
        _info[token] = Info({creator: msg.sender, kind: kind, version: version, exists: true});
        address[] memory us = new address[](n);
        for (uint256 i; i < n; ++i) {
            address u = cfg.legs[i].underlying;
            us[i] = u;
            _wrappers[msg.sender][u].push(token);
            _byUnderlying[u].push(token);
        }
        emit TokenCreated(token, msg.sender, kind, version, impl, cfg.features, cfg.lockedFeatures, cfg.owner, us);
    }
}
```

- [ ] **Step 5: The kinds on `TokenConfig`** — apply these diffs (against `main`):

```diff
diff --git a/smartcontracts/evm/src/metatx/MetaTokenBase.sol b/smartcontracts/evm/src/metatx/MetaTokenBase.sol
index 14142df..d8aaf98 100644
--- a/smartcontracts/evm/src/metatx/MetaTokenBase.sol
+++ b/smartcontracts/evm/src/metatx/MetaTokenBase.sol
@@ -11,8 +11,7 @@ import {IERC20MetaTx} from "./IERC20MetaTx.sol";
 import {IERC20Payment} from "./IERC20Payment.sol";
 import {HederaLib} from "../hedera/HederaLib.sol";
 import {IMetaTokenV2} from "./IMetaTokenV2.sol";
-import {IFactoryTokenV2} from "../factory/IFactoryTokenV2.sol";
-import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";
+import {IFactoryToken} from "../factory/IFactoryToken.sol";
 import {MetaTxLib} from "../common/MetaTxLib.sol";
 import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
 
@@ -22,7 +21,7 @@ import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
 ///         ERC-7201 namespace `scaas.token`. Pay (`mtxPay`, `payWithFee`, `mtxPayReceiverFee`) works only with
 ///         `PAYABLE`; a `MetaTransfer` (with or without `entryRef`) is never gated. Hedera is the immutable
 ///         `IS_HEDERA` (CTR-TOK-23): HIP-632 signatures through `HederaLib`.
-abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryTokenV2, IERC165, ITokenAdmin {
+abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IERC165, ITokenAdmin {
     using MetaTxLib for MetaTxLib.MetaTransfer;
 
     bytes32 internal constant RECEIVER_FEE_TYPEHASH =
@@ -58,21 +57,30 @@ abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryTokenV2, I
         AdminLib.$().initialized = true;
     }
 
-    /// @notice The factory calls it in the SAME call as CREATE2. `initData` per tier (TW2 §4, §5.1, §8.1).
-    function initialize(address creator_, address[] calldata underlyings, uint64 version_, bytes calldata initData)
-        external
-    {
+    /// @notice The factory calls it in the SAME call as CREATE2 (CTR-TOK-25).
+    function initialize(address creator_, uint64 version_, TokenConfig calldata cfg) external {
         if (msg.sender != FACTORY) revert NotFactory();
         AdminLib.TokenStorage storage t = AdminLib.$();
         if (t.initialized) revert AlreadyInitialized();
         t.initialized = true;
         t.creator = creator_;
         t.version = version_;
-        _init(creator_, underlyings, initData);
+        _init(cfg);
     }
 
-    /// @dev The tier decodes `initData`, calls `_setMetadata` and `AdminLib.init`, checks `underlyings`.
-    function _init(address creator_, address[] calldata underlyings, bytes calldata initData) internal virtual;
+    /// @dev The kind checks its fields of `cfg` (`ConfigFieldForOtherKind` for another kind's), calls `_setMetadata`
+    ///      and `AdminLib.init`.
+    function _init(TokenConfig calldata cfg) internal virtual;
+
+    /// @dev `ConfigFieldForOtherKind` for a set field the kind does not use; `conf` is used only by `*_ZETHER`.
+    function _requireUnused(TokenConfig calldata cfg, bool supply, bool legs, bool rate) internal pure {
+        if (supply && (cfg.initialSupply != 0 || cfg.initialHolder != address(0))) revert ConfigFieldForOtherKind(1);
+        if (legs && cfg.legs.length != 0) revert ConfigFieldForOtherKind(2);
+        if (rate && (cfg.rate.rateDelay != 0 || cfg.rate.maxRateStepBps != 0)) revert ConfigFieldForOtherKind(3);
+        if (cfg.conf.verifier != address(0) || cfg.conf.auditorKey.length != 0 || cfg.conf.shieldScale != 0) {
+            revert ConfigFieldForOtherKind(4);
+        }
+    }
 
     function _setMetadata(string memory n, string memory sym, uint8 d) internal {
         AdminLib.TokenStorage storage t = AdminLib.$();
@@ -81,8 +89,6 @@ abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryTokenV2, I
         t.decimals = d;
     }
 
-    function tokenKind() external pure virtual returns (IOpenFactoryV2.TokenKind);
-
     function name() public view override returns (string memory) { return AdminLib.$().name; }
     function symbol() public view override returns (string memory) { return AdminLib.$().symbol; }
     function decimals() public view override returns (uint8) { return AdminLib.$().decimals; }
@@ -91,8 +97,9 @@ abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryTokenV2, I
     function implementation() external view returns (address) { return _SELF; }
     function creator() external view returns (address) { return AdminLib.$().creator; }
     function version() external view returns (uint64) { return AdminLib.$().version; }
-    /// @notice CTR-TOK-21 kind: 0 `NONE`, 1 `UNDERLYING`, 2 `NONE_ZETHER`, 3 `UNDERLYING_ZETHER`.
-    function kind() external view returns (uint8) { return AdminLib.$().kind; }
+    /// @notice CTR-TOK-21 kind: 0 `NONE`, 1 `UNDERLYING`, 2 `NONE_ZETHER`, 3 `UNDERLYING_ZETHER`; a constant of the
+    ///         implementation, so the factory can check it before any clone exists.
+    function kind() public pure virtual returns (uint8);
 
     // ------------------------------------------------------------------ features, owner, roles (CTR-TOK-22)
 
```

```diff
diff --git a/smartcontracts/evm/src/metatx/NoUnderlyingToken.sol b/smartcontracts/evm/src/metatx/NoUnderlyingToken.sol
index 216fe2d..c0164fa 100644
--- a/smartcontracts/evm/src/metatx/NoUnderlyingToken.sol
+++ b/smartcontracts/evm/src/metatx/NoUnderlyingToken.sol
@@ -5,41 +5,25 @@ import {MetaTokenBase} from "./MetaTokenBase.sol";
 import {AdminLib} from "./AdminLib.sol";
 import {MetaTxBase} from "./MetaTxBase.sol";
 import {IMetaTx} from "./IMetaTx.sol";
-import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";
 
 /// @title Kind `NONE` (CTR-TOK-21): a standalone token, no underlying.
 /// @notice Flags valid here: `PAYABLE`, `MINTABLE` (role `minter`), `BURNABLE` (holder burn). A supply cap or a mint
-///         rate limit, if an issuer needs one, lives in its minter contract. Built by the factory through
-///         `initialize(creator, [], version, abi.encode(NoneInit))`; P1e switches to `TokenConfig`.
+///         rate limit, if an issuer needs one, lives in its minter contract. Built by `OpenFactory.createToken`
+///         (CTR-TOK-25): `initialSupply` is minted to `initialHolder`; `legs`, `rate`, `conf` must be empty.
 contract NoUnderlyingToken is MetaTokenBase {
-    /// @notice The NONE subset of `TokenConfig` (CTR-TOK-25).
-    struct NoneInit {
-        string name;
-        string symbol;
-        uint8 decimals;
-        uint256 features;
-        uint256 lockedFeatures;
-        address owner;
-        AdminLib.Roles roles;
-        uint256 initialSupply;
-        address initialHolder;
-    }
-
     constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
         MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
     {}
 
-    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
-        return IOpenFactoryV2.TokenKind.META_NONE;
+    function kind() public pure override returns (uint8) {
+        return AdminLib.KIND_NONE;
     }
 
-    /// @param initData `abi.encode(NoneInit)`.
-    function _init(address, address[] calldata underlyings, bytes calldata initData) internal override {
-        if (underlyings.length != 0) revert UnderlyingCountInvalid(underlyings.length);
-        NoneInit memory c = abi.decode(initData, (NoneInit));
-        _setMetadata(c.name, c.symbol, c.decimals);
-        AdminLib.init(AdminLib.KIND_NONE, c.features, c.lockedFeatures, c.owner, c.roles);
-        if (c.initialSupply != 0) _mint(c.initialHolder, c.initialSupply);
+    function _init(TokenConfig calldata cfg) internal override {
+        _requireUnused(cfg, false, true, true);
+        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
+        AdminLib.init(AdminLib.KIND_NONE, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
+        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
     }
 
     /// @notice `MINTABLE` and the `minter` role; never allowlisted (a minter contract's caps run on its own call).
```

```diff
diff --git a/smartcontracts/evm/src/metatx/UnderlyingToken.sol b/smartcontracts/evm/src/metatx/UnderlyingToken.sol
index 8380e9b..3e78195 100644
--- a/smartcontracts/evm/src/metatx/UnderlyingToken.sol
+++ b/smartcontracts/evm/src/metatx/UnderlyingToken.sol
@@ -7,7 +7,6 @@ import {UnderlyingLib} from "./UnderlyingLib.sol";
 import {IUnderlyingToken} from "./IUnderlyingToken.sol";
 import {MetaTxBase} from "./MetaTxBase.sol";
 import {IMetaTx} from "./IMetaTx.sol";
-import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";
 
 /// @title Kind `UNDERLYING` (CTR-TOK-21): a wrapper of 1–8 legs, each an ERC-20 or the native coin (CTR-TOK-26), at
 ///        per-leg rates `num/den`, with internal per-leg reserves; the logic is in `UnderlyingLib`.
@@ -30,14 +29,14 @@ contract UnderlyingToken is MetaTokenBase, IUnderlyingToken {
         MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
     {}
 
-    /// @dev Transitional: factory v2's `META_SINGLE` takes 1–8 legs (P1e replaces the enum).
-    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
-        return IOpenFactoryV2.TokenKind.META_SINGLE;
+    function kind() public pure override returns (uint8) {
+        return AdminLib.KIND_UNDERLYING;
     }
 
-    /// @param initData `abi.encode(UnderlyingInit)`; decoded and checked in `UnderlyingLib.initToken`.
-    function _init(address, address[] calldata us, bytes calldata initData) internal override {
-        UnderlyingLib.initToken(us, initData, IS_HEDERA);
+    /// @dev `initialSupply`, `initialHolder`, `conf` must be empty; legs and rate are checked in `UnderlyingLib`.
+    function _init(TokenConfig calldata cfg) internal override {
+        _requireUnused(cfg, true, false, false);
+        UnderlyingLib.initToken(cfg, IS_HEDERA);
     }
 
     // ------------------------------------------------------------------ wrap / unwrap / reserve
```

```diff
diff --git a/smartcontracts/evm/src/metatx/UnderlyingLib.sol b/smartcontracts/evm/src/metatx/UnderlyingLib.sol
index f56cd13..b6238c6 100644
--- a/smartcontracts/evm/src/metatx/UnderlyingLib.sol
+++ b/smartcontracts/evm/src/metatx/UnderlyingLib.sol
@@ -7,6 +7,7 @@ import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol
 import {Address} from "@openzeppelin/contracts/utils/Address.sol";
 import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
 import {IUnderlyingToken} from "./IUnderlyingToken.sol";
+import {IFactoryToken} from "../factory/IFactoryToken.sol";
 import {AdminLib} from "./AdminLib.sol";
 import {MetaTokenBase} from "./MetaTokenBase.sol";
 import {HederaLib} from "../hedera/HederaLib.sol";
@@ -69,17 +70,11 @@ library UnderlyingLib {
 
     // ------------------------------------------------------------------ init
 
-    /// @notice The token's `_init`: decode `UnderlyingInit`, check it against the factory's `underlyings` (1–8, same
-    ///         order), write the metadata, the flags/owner/roles (`AdminLib.init`), the rate config and the legs in the
-    ///         factory's order (which never changes).
-    function initToken(address[] calldata underlyings, bytes calldata initData, bool isHedera) public {
-        IUnderlyingToken.UnderlyingInit memory c = abi.decode(initData, (IUnderlyingToken.UnderlyingInit));
-        uint256 n = underlyings.length;
+    /// @notice The token's `_init`: legs 1–8 (the factory's index reads the same `legs`), the metadata, the
+    ///         flags/owner/roles (`AdminLib.init`), the rate config, then the legs in their given order (never changes).
+    function initToken(IFactoryToken.TokenConfig calldata c, bool isHedera) public {
+        uint256 n = c.legs.length;
         if (n == 0 || n > MAX_LEGS) revert MetaTokenBase.UnderlyingCountInvalid(n);
-        if (c.legs.length != n) revert MetaTokenBase.UnderlyingCountInvalid(c.legs.length);
-        for (uint256 i; i < n; ++i) {
-            if (c.legs[i].underlying != underlyings[i]) revert IUnderlyingToken.UnknownUnderlying(underlyings[i]);
-        }
         AdminLib.TokenStorage storage t = AdminLib.$();
         t.name = c.name;
         t.symbol = c.symbol;
@@ -87,7 +82,7 @@ library UnderlyingLib {
         AdminLib.init(AdminLib.KIND_UNDERLYING, c.features, c.lockedFeatures, c.owner, c.roles);
         bool adjustable = AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE);
         UnderlyingStorage storage s = $();
-        IUnderlyingToken.RateConfig memory rate = c.rate;
+        IFactoryToken.RateConfig calldata rate = c.rate;
         if (!adjustable) {
             if (rate.rateDelay != 0 || rate.maxRateStepBps != 0) revert IUnderlyingToken.RateConfigInvalid();
         } else {
@@ -99,7 +94,7 @@ library UnderlyingLib {
         for (uint256 i; i < n; ++i) _addLeg(s, c.legs[i], adjustable, isHedera);
     }
 
-    function _addLeg(UnderlyingStorage storage s, IUnderlyingToken.LegInit memory l, bool adjustable, bool isHedera)
+    function _addLeg(UnderlyingStorage storage s, IFactoryToken.Leg calldata l, bool adjustable, bool isHedera)
         private
     {
         address u = l.underlying;
```

```diff
diff --git a/smartcontracts/evm/src/metatx/IUnderlyingToken.sol b/smartcontracts/evm/src/metatx/IUnderlyingToken.sol
index 895a276..2b50b01 100644
--- a/smartcontracts/evm/src/metatx/IUnderlyingToken.sol
+++ b/smartcontracts/evm/src/metatx/IUnderlyingToken.sol
@@ -1,40 +1,10 @@
 // SPDX-License-Identifier: Apache-2.0
 pragma solidity ^0.8.24;
 
-import {AdminLib} from "./AdminLib.sol";
-
 /// @title Kind `UNDERLYING` (CTR-TOK-21): 1–8 legs, each an ERC-20 or the native coin (`address(0)`, CTR-TOK-26).
 /// @notice Events and errors raised by `UnderlyingLib` (an external library) are declared here so that they are in the
-///         token ABI.
+///         token ABI. The creation config is `IFactoryToken.TokenConfig` (`legs`, `rate`).
 interface IUnderlyingToken {
-    /// @notice One leg at creation: `underlying` (`address(0)` = the native coin), rate `num/den` (CTR-TOK-04).
-    ///         `uint256` so a value `≥ 2^96` reverts `RateInvalid` instead of failing to decode.
-    struct LegInit {
-        address underlying;
-        uint256 num;
-        uint256 den;
-    }
-
-    /// @notice With `RATE_ADJUSTABLE`: `2 days ≤ rateDelay ≤ 30 days`, `1 ≤ maxRateStepBps ≤ 1000`; without: both 0.
-    struct RateConfig {
-        uint32 rateDelay;
-        uint16 maxRateStepBps;
-    }
-
-    /// @notice The UNDERLYING subset of `TokenConfig` (CTR-TOK-25); `legs[i].underlying == underlyings[i]` of the
-    ///         factory call.
-    struct UnderlyingInit {
-        string name;
-        string symbol;
-        uint8 decimals;
-        uint256 features;
-        uint256 lockedFeatures;
-        address owner;
-        AdminLib.Roles roles;
-        LegInit[] legs;
-        RateConfig rate;
-    }
-
     event Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted);
     event Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned,
         uint256 underlyingOut);
```

Run `timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge build src'` — expected: compiles.

- [ ] **Step 6: Fixture** — apply to `test/v2/helpers/V2Fixture.sol`:

```diff
diff --git a/smartcontracts/evm/test/v2/helpers/V2Fixture.sol b/smartcontracts/evm/test/v2/helpers/V2Fixture.sol
index f82a06f..b2f0962 100644
--- a/smartcontracts/evm/test/v2/helpers/V2Fixture.sol
+++ b/smartcontracts/evm/test/v2/helpers/V2Fixture.sol
@@ -5,39 +5,36 @@ import {Test} from "forge-std/Test.sol";
 import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
 import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
 import {AdminLib} from "../../../src/metatx/AdminLib.sol";
-import {IOpenFactoryV2} from "../../../src/common/IOpenFactoryV2.sol";
+import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
 import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
 import {NoUnderlyingToken} from "../../../src/metatx/NoUnderlyingToken.sol";
 import {UnderlyingToken} from "../../../src/metatx/UnderlyingToken.sol";
-import {IUnderlyingToken} from "../../../src/metatx/IUnderlyingToken.sol";
 
 bytes32 constant UID_ = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
 
-/// Tầng tối thiểu trên `MetaTokenBase` cho test của T1: `initData = (name, symbol, decimals, supply)`; `PAYABLE` bật
-/// như khi build (P1c).
+/// Minimal kind on `MetaTokenBase` for the base tests: name, symbol, decimals, `initialSupply` to `initialHolder`;
+/// `PAYABLE` set as built (P1c), whatever `cfg.features` says.
 contract BaseHarness is MetaTokenBase {
     constructor(address f, address s) MetaTokenBase(f, s, UID_, false) {}
 
-    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
-        return IOpenFactoryV2.TokenKind.META_NONE;
+    function kind() public pure override returns (uint8) {
+        return AdminLib.KIND_NONE;
     }
 
-    function _init(address creator_, address[] calldata, bytes calldata initData) internal override {
-        (string memory n, string memory s, uint8 d, uint256 supply) =
-            abi.decode(initData, (string, string, uint8, uint256));
-        _setMetadata(n, s, d);
+    function _init(TokenConfig calldata cfg) internal override {
+        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
         AdminLib.Roles memory none;
         AdminLib.init(AdminLib.KIND_NONE, 1 << AdminLib.PAYABLE, 0, address(0), none);
-        _mint(creator_, supply);
+        _mint(cfg.initialHolder, cfg.initialSupply);
     }
 
     function mint(address to, uint256 v) external { _mint(to, v); }
 }
 
-/// Kind-NONE init (P1c `NoneInit`) with the behaviour built before P1c: `PAYABLE | MINTABLE | BURNABLE`, nothing
-/// locked, no owner, `minter` (0 = none), `supply` to `holder`. Callers `abi.encode` it (after adjusting fields).
+/// Kind-NONE `TokenConfig` with the behaviour built before P1c: `PAYABLE | MINTABLE | BURNABLE`, nothing locked, no
+/// owner, `minter` (0 = none), `supply` to `holder`. Callers `abi.encode` it (after adjusting fields).
 function noneInit(string memory n, string memory s, uint8 d, uint256 supply, address holder, address minter)
-    pure returns (NoUnderlyingToken.NoneInit memory c)
+    pure returns (IFactoryToken.TokenConfig memory c)
 {
     c.name = n;
     c.symbol = s;
@@ -57,10 +54,10 @@ struct Rate {
     uint16 maxRateStepBps;
 }
 
-/// `UnderlyingInit` for legs `us` at `nums/dens`: `PAYABLE` (as built), `RATE_ADJUSTABLE` with `cfg.adjustable`,
+/// `TokenConfig` of kind UNDERLYING for legs `us` at `nums/dens`: `PAYABLE` (as built), `RATE_ADJUSTABLE` with `cfg.adjustable`,
 /// `WRAP_DISABLEABLE` with a non-zero `guardian`; nothing locked; `owner` (0 = none).
 function underlyingInit(address[] memory us, uint256[] memory nums, uint256[] memory dens, uint8 dec, Rate memory cfg,
-    address guardian, address owner) pure returns (IUnderlyingToken.UnderlyingInit memory c)
+    address guardian, address owner) pure returns (IFactoryToken.TokenConfig memory c)
 {
     c.name = "Wrapped";
     c.symbol = "WRP";
@@ -71,9 +68,9 @@ function underlyingInit(address[] memory us, uint256[] memory nums, uint256[] me
     c.owner = owner;
     c.roles.rateAdmin = cfg.rateAdmin;
     c.roles.guardian = guardian;
-    c.legs = new IUnderlyingToken.LegInit[](us.length);
-    for (uint256 i; i < us.length; ++i) c.legs[i] = IUnderlyingToken.LegInit(us[i], nums[i], dens[i]);
-    c.rate = IUnderlyingToken.RateConfig(cfg.rateDelay, cfg.maxRateStepBps);
+    c.legs = new IFactoryToken.Leg[](us.length);
+    for (uint256 i; i < us.length; ++i) c.legs[i] = IFactoryToken.Leg(us[i], nums[i], dens[i]);
+    c.rate = IFactoryToken.RateConfig(cfg.rateDelay, cfg.maxRateStepBps);
 }
 
 /// ERC-1271 đốt ~100k gas rồi trả magic: qua được với 400k, không qua với 50k.
@@ -85,7 +82,7 @@ contract GasBurner1271 {
     }
 }
 
-/// Test đóng vai factory: clone + `initialize` trong cùng lời gọi, như `OpenFactoryV2`.
+/// The test plays the factory: clone + `initialize` in the same call, as `OpenFactory`.
 abstract contract V2Fixture is Test {
     address internal relayer = address(0xBEEF);
     uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
@@ -93,17 +90,22 @@ abstract contract V2Fixture is Test {
     uint32 internal constant PCT = MetaTxLib.MODE_FEE_PERCENT;
     uint32 internal constant FIX = MetaTxLib.MODE_FEE_FIXED;
 
-    function _clone(address impl, address creator_, address[] memory us, bytes memory initData)
+    /// `cfgData` = `abi.encode(TokenConfig)`; `us` must equal its legs (what the factory would index).
+    function _clone(address impl, address creator_, address[] memory us, bytes memory cfgData)
         internal returns (address t)
     {
+        IFactoryToken.TokenConfig memory cfg = abi.decode(cfgData, (IFactoryToken.TokenConfig));
+        assertEq(cfg.legs.length, us.length, "fixture: legs vs underlyings");
+        for (uint256 i; i < us.length; ++i) assertEq(cfg.legs[i].underlying, us[i], "fixture: leg order");
         t = Clones.clone(impl);
-        MetaTokenBase(t).initialize(creator_, us, 1, initData);
+        MetaTokenBase(t).initialize(creator_, 1, cfg);
     }
 
     function _harness(address creator_, uint256 supply) internal returns (BaseHarness) {
         BaseHarness impl = new BaseHarness(address(this), address(0));
-        return BaseHarness(_clone(address(impl), creator_, new address[](0),
-            abi.encode("Harness", "HRN", uint8(6), supply)));
+        IFactoryToken.TokenConfig memory c;
+        (c.name, c.symbol, c.decimals, c.initialSupply, c.initialHolder) = ("Harness", "HRN", 6, supply, creator_);
+        return BaseHarness(_clone(address(impl), creator_, new address[](0), abi.encode(c)));
     }
 
     address internal noneImpl;
@@ -135,7 +137,7 @@ abstract contract V2Fixture is Test {
         xs[0] = x;
     }
 
-    /// `abi.encode(UnderlyingInit)` for one leg `u`.
+    /// `abi.encode(TokenConfig)` for one leg `u`.
     function _singleInit(address u, uint8 dec, uint256 num, uint256 den, Rate memory cfg)
         internal view returns (bytes memory)
     {
```

- [ ] **Step 7: `test/v2/Factory.t.sol`** replaces `test/v2/FactoryV2.t.sol` (`git rm` the old file; the old file's cases
are covered here or obsolete with factory v2). Full text:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, noneInit, underlyingInit, Rate} from "./helpers/V2Fixture.sol";

/// Answers `kind()` only.
contract KindOnly {
    function kind() external pure returns (uint8) { return 0; }
}

/// `OpenFactory` (CTR-TOK-03, CTR-TOK-25): catalogue checks, `createToken`/`createTokenUnregistered` with
/// `TokenConfig`, one `TokenCreated`, provenance, salt scoped by the creator; the token validates flags and fields.
contract FactoryTest is Test {
    OpenFactory f;
    address registrar = address(0xF00D);
    NoUnderlyingToken noneImpl;
    UnderlyingToken underlyingImpl;
    MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
    MockERC20 usdt = new MockERC20("Tether", "USDT", 6);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    IOpenFactory.TokenKind constant NONE = IOpenFactory.TokenKind.NONE;
    IOpenFactory.TokenKind constant UNDERLYING = IOpenFactory.TokenKind.UNDERLYING;

    function setUp() public {
        f = new OpenFactory(registrar, UID_);
        noneImpl = new NoUnderlyingToken(address(f), address(0), UID_, false);
        underlyingImpl = new UnderlyingToken(address(f), address(0), UID_, false);
        vm.startPrank(registrar);
        f.registerImplementation(NONE, 1, address(noneImpl));
        f.registerImplementation(UNDERLYING, 1, address(underlyingImpl));
        vm.stopPrank();
    }

    function _none(address holder) internal pure returns (IFactoryToken.TokenConfig memory) {
        return noneInit("Points", "PTS", 0, 1000, holder, address(0));
    }

    /// Legs `us` at 1:1, rates fixed, no guardian, no owner.
    function _wrapper(address[] memory us) internal pure returns (IFactoryToken.TokenConfig memory) {
        Rate memory c;
        uint256[] memory one = new uint256[](us.length);
        for (uint256 i; i < us.length; ++i) one[i] = 1;
        return underlyingInit(us, one, one, 6, c, address(0), address(0));
    }

    function _two() internal view returns (address[] memory us) {
        us = new address[](2);
        (us[0], us[1]) = (address(usdc), address(usdt));
    }

    // ------------------------------------------------------------------ catalogue

    function test_constructor_refusesZeroChainUid() public {
        vm.expectRevert(IOpenFactory.ChainUidZero.selector);
        new OpenFactory(registrar, bytes32(0));
        assertEq(f.chainUid(), UID_);
        assertEq(f.registrar(), registrar);
    }

    function test_register_checksKindFactoryAndChainUid() public {
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, UNDERLYING, 0));
        f.registerImplementation(UNDERLYING, 2, address(noneImpl));
        address otherFactory = address(new NoUnderlyingToken(address(0xFAC), address(0), UID_, false));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationFactoryMismatch.selector, otherFactory));
        f.registerImplementation(NONE, 2, otherFactory);
        bytes32 otherUid = keccak256("other chain");
        address otherChain = address(new NoUnderlyingToken(address(f), address(0), otherUid, false));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, otherUid));
        f.registerImplementation(NONE, 2, otherChain);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationNotAContract.selector, address(0xDEAD)));
        f.registerImplementation(NONE, 2, address(0xDEAD));
        address mute = address(new MockERC20("M", "M", 6)); // no kind()
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, NONE, type(uint256).max));
        f.registerImplementation(NONE, 2, mute);
        address kindOnly = address(new KindOnly()); // no factory()
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationFactoryMismatch.selector, kindOnly));
        f.registerImplementation(NONE, 2, kindOnly);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindReserved.selector, IOpenFactory.TokenKind.NONE_PQZ));
        f.registerImplementation(IOpenFactory.TokenKind.NONE_PQZ, 1, address(noneImpl));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 0));
        f.registerImplementation(NONE, 0, address(noneImpl));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionAlreadyRegistered.selector, NONE, 1,
            address(noneImpl)));
        f.registerImplementation(NONE, 1, address(noneImpl));
        vm.stopPrank();
        vm.prank(alice);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.registerImplementation(NONE, 3, address(noneImpl));
        assertEq(f.latestVersion(NONE), 1);
        assertEq(f.implementationOf(UNDERLYING, 1), address(underlyingImpl));
    }

    function test_deprecateOnlyMarks() public {
        vm.prank(alice);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.deprecate(NONE, 1, "x");
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 9));
        f.deprecate(NONE, 9, "x");
        vm.prank(registrar);
        f.deprecate(NONE, 1, "bug");
        assertTrue(f.isDeprecated(NONE, 1));
        vm.prank(alice);
        f.createToken(NONE, 1, _none(alice), "still"); // deprecation is advisory
    }

    // ------------------------------------------------------------------ create

    function test_createToken_none_emitsOneEventWithProvenance() public {
        address predicted = f.predictAddress(address(noneImpl), alice, "s");
        vm.recordLogs();
        vm.prank(alice);
        address t = f.createToken(NONE, 1, _none(alice), "s");
        assertEq(t, predicted);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 created;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(f)) {
                ++created;
                assertEq(logs[i].topics[0], IOpenFactory.TokenCreated.selector);
                assertEq(address(uint160(uint256(logs[i].topics[1]))), t);
                assertEq(address(uint160(uint256(logs[i].topics[2]))), alice);
                assertEq(uint256(logs[i].topics[3]), uint256(NONE));
                (uint64 v, address impl, uint256 feat, uint256 locked, address owner, address[] memory us) =
                    abi.decode(logs[i].data, (uint64, address, uint256, uint256, address, address[]));
                assertEq(abi.encode(v, impl, feat, locked, owner, us.length),
                    abi.encode(uint64(1), address(noneImpl), uint256(7), uint256(0), address(0), uint256(0)));
            }
        }
        assertEq(created, 1);
        assertEq(NoUnderlyingToken(t).balanceOf(alice), 1000);
        assertEq(NoUnderlyingToken(t).version(), 1);
        assertEq(NoUnderlyingToken(t).creator(), alice);
        assertTrue(f.isToken(t));
        assertEq(f.creatorOf(t), alice);
        (IOpenFactory.TokenKind k, uint64 ver) = f.versionOf(t);
        assertEq(uint8(k), uint8(NONE));
        assertEq(ver, 1);
        assertFalse(f.isToken(address(noneImpl)));
    }

    function test_createToken_underlying_indexesEveryLeg_includingNative() public {
        address[] memory us = new address[](3);
        (us[0], us[1], us[2]) = (address(usdc), address(usdt), address(0));
        vm.prank(alice);
        address t = f.createToken(UNDERLYING, 1, _wrapper(us), "w");
        assertEq(UnderlyingToken(t).underlyings().length, 3);
        assertEq(f.getWrapper(alice, address(usdc)), t);
        assertEq(f.getWrapper(alice, address(0)), t);
        assertEq(f.getWrapperCount(alice, address(usdt)), 1);
        assertEq(f.getWrapperAt(alice, address(usdt), 0), t);
        assertEq(f.deployCountFor(address(0)), 1);
        assertEq(f.deployedFor(address(usdc), 0), t);
        assertEq(f.getWrapper(bob, address(usdc)), address(0));
    }

    function test_createToken_legCountByKind() public {
        IFactoryToken.TokenConfig memory c = _none(alice);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usdc), 1, 1);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnderlyingCountInvalid.selector, 1));
        f.createToken(NONE, 1, c, "a");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnderlyingCountInvalid.selector, 0));
        f.createToken(UNDERLYING, 1, _wrapper(new address[](0)), "a");
        address[] memory nine = new address[](9);
        for (uint256 i; i < 9; ++i) nine[i] = address(new MockERC20("X", "X", 6));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnderlyingCountInvalid.selector, 9));
        f.createToken(UNDERLYING, 1, _wrapper(nine), "a");
        address[] memory eight = new address[](8);
        for (uint256 i; i < 8; ++i) eight[i] = nine[i];
        f.createToken(UNDERLYING, 1, _wrapper(eight), "a");
    }

    function test_createToken_unknownVersion() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 2));
        f.createToken(NONE, 2, _none(alice), "a");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector,
            IOpenFactory.TokenKind.NONE_ZETHER, 1));
        f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, _none(alice), "a");
    }

    function test_saltIsScopedByCreator_andCannotBeReused() public {
        vm.prank(alice);
        address a = f.createToken(NONE, 1, _none(alice), "same");
        vm.prank(bob);
        address b = f.createToken(NONE, 1, _none(bob), "same");
        assertTrue(a != b);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, a));
        f.createToken(NONE, 1, _none(alice), "same");
    }

    function test_createTokenUnregistered_isCheckedAndRecordedAsVersion0() public {
        NoUnderlyingToken mine = new NoUnderlyingToken(address(f), address(0), UID_, false);
        vm.prank(alice);
        address t = f.createTokenUnregistered(NONE, address(mine), _none(alice), "u");
        (, uint64 v) = f.versionOf(t);
        assertEq(v, 0);
        assertEq(NoUnderlyingToken(t).version(), 0);
        NoUnderlyingToken other = new NoUnderlyingToken(address(f), address(0), keccak256("x"), false);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("x")));
        f.createTokenUnregistered(NONE, address(other), _none(alice), "u2");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, UNDERLYING, 0));
        f.createTokenUnregistered(UNDERLYING, address(mine), _wrapper(_two()), "u3");
    }

    // ------------------------------------------------------------------ the token validates

    function test_factoryOnlyForwards_theTokenValidatesFlagsAndFields() public {
        IFactoryToken.TokenConfig memory c = _none(alice);
        c.features |= 1 << 3; // RATE_ADJUSTABLE on NONE
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, 3));
        f.createToken(NONE, 1, c, "a");
        c = _none(alice);
        c.rate.rateDelay = 7 days;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 3));
        f.createToken(NONE, 1, c, "a");
        c = _none(alice);
        c.conf.shieldScale = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        f.createToken(NONE, 1, c, "a");
        c = _wrapper(_two());
        c.initialSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 1));
        f.createToken(UNDERLYING, 1, c, "a");
        c = _wrapper(_two());
        c.initialHolder = alice;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 1));
        f.createToken(UNDERLYING, 1, c, "a");
        c = _wrapper(_two());
        c.conf.auditorKey = hex"01";
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        f.createToken(UNDERLYING, 1, c, "a");
    }

    function test_onlyTheFactoryInitializes_andOnlyOnce() public {
        vm.prank(alice);
        address t = f.createToken(NONE, 1, _none(alice), "s");
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        NoUnderlyingToken(t).initialize(alice, 1, _none(alice));
        vm.prank(address(f));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        NoUnderlyingToken(t).initialize(alice, 1, _none(alice));
        vm.prank(address(f));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        noneImpl.initialize(alice, 1, _none(alice)); // the implementation locked itself
    }

    function test_kindIsAConstantOfTheImplementation() public view {
        assertEq(noneImpl.kind(), uint8(NONE));
        assertEq(underlyingImpl.kind(), uint8(UNDERLYING));
    }

    function test_sizes() public view {
        assertLe(address(noneImpl).code.length, 20_480); // CTR-TOK-24
        assertLe(address(f).code.length, 24_576);
        // Transitional (P1d D2): over EIP-170 until the size work
        assertLe(address(underlyingImpl).code.length, 27_648);
    }
}
```

- [ ] **Step 8: Port the remaining tests.** Find them by compiling; at least `test/v2/{Base,Tier1,Tier2,Multi,Features,
Allowlist,ReceiverPays,MetaTxGasV2,Underlying}.t.sol`, `test/metatx/TokenKat.t.sol`, `test/hedera/HederaV2.t.sol`. Rules:
1. `IOpenFactoryV2` → `IOpenFactory` (`src/factory/IOpenFactory.sol`); `TokenKind.META_NONE` → `NONE`,
   `TokenKind.META_SINGLE` → `UNDERLYING`; `t.tokenKind()` asserts → `assertEq(t.kind(), AdminLib.KIND_NONE)` /
   `KIND_UNDERLYING`.
2. `new OpenFactoryV2(registrar)` → `new OpenFactory(registrar, UID)`; `createTiered(kind, v, us, bytes, salt)` →
   `createToken(kind, v, cfg, salt)` with the `TokenConfig` that used to be `abi.encode`d (`noneInit`/`underlyingInit`
   now return it); `createTieredUnregistered` → `createTokenUnregistered`; `isDeployedHere` → `isToken`;
   `TieredTokenDeployed` → `TokenCreated`.
3. Direct `initialize(creator, us, version, bytes)` → `initialize(creator, version, cfg)` (as the factory, `vm.prank`
   where the test did). `UnderlyingCountInvalid` from a bad count stays the token's error for direct calls.
4. `Underlying.t.sol test_init_legsMustMatchTheFactoryUnderlyings` → `test_init_legCount`: 0 legs and 9 legs reverted by
   the token (`MetaTokenBase.UnderlyingCountInvalid`) through a direct `initialize`; the mismatch cases go (E6).
5. `TokenKat.t.sol`: the written vectors must stay byte-identical (`git diff test/vectors` empty after the run). If a
   vector changes, stop and report.
6. `MetaTxGasV2.t.sol`: rows logged on the new factory; update logged numbers only.
7. `HederaV2.t.sol`: `OpenFactory(registrar, UID)`, `createToken`, kinds `NONE`/`UNDERLYING`; size pins: NONE ≤ 20,480,
   UNDERLYING ≤ 27,648 (`// Transitional (P1d D2): over EIP-170 until the size work`).
8. Any other compile error from the renames of Step 1 (a v1 test naming `OpenFactory`): apply the Step 1 rename.
Do not change what a test asserts beyond these rules; a failure the rules do not explain → stop and report.

- [ ] **Step 9: Full suite** — `timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge test'`. Expected: all
pass; report the count (814 − the old `FactoryV2.t.sol` tests + 13 `Factory.t.sol` ± rule-4 changes) and confirm `git
status test/vectors` is clean.

- [ ] **Step 10: Commit** — `P1e: OpenFactory (createToken/TokenConfig, chainUid catalogue checks); kinds on TokenConfig; v1 renamed …V1; v2 factory backed up` + trailer.

---

### Task 2: CREATE2 deploy with the `chainUid()` gate; the size gate in CI

**Model:** Sonnet, effort medium (files are complete; the e2e is the check).

**Interfaces:** Consumes Task 1's `OpenFactory(registrar, uid)`, `IOpenFactory.TokenKind.NONE`, `OpenFactoryV1`,
`IOpenFactoryV1`. Produces the JSON keys of the Global Constraints.

- [ ] **Step 1: `script/DeployBase.sol`** (full text)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {NoUnderlyingToken} from "../src/metatx/NoUnderlyingToken.sol";

/// @title Shared deploy steps (CTR-GEN-05, CTR-GEN-06, NET-EVM-05): `chain_uid` from the RPC, the deterministic CREATE2
///        deployer, the token factory with its implementations, the `chainUid()` gate.
/// @notice `new X{salt: DEPLOY_SALT}(…)` inside a broadcast goes through the deterministic deployer at `CREATE2_FACTORY`
///         (forge-std), so an address depends only on the init code and the salt: a contract that takes `chain_uid`
///         gets a different address on each chain, the others the same one. Re-running on the same chain collides:
///         a new version needs a new `DEPLOY_SALT`.
abstract contract DeployBase is Script {
    /// @notice CREATE2 salt of every contract: `DEPLOY_SALT` env, default `keccak256("scaas.deploy.v1")`.
    bytes32 internal salt;
    /// @notice The chain's genesis hash (`_chainUid`).
    bytes32 internal uid;

    /// @notice Call first in `run()`, before the broadcast.
    function _setup() internal {
        salt = vm.envOr("DEPLOY_SALT", keccak256("scaas.deploy.v1"));
        uid = _chainUid();
        require(CREATE2_FACTORY.code.length != 0,
            "no deterministic CREATE2 deployer at 0x4e59b44847b379578588920ca78fbf26c0b4956c (runbook NET-EVM-05)");
    }

    /// @notice `CHAIN_UID` env (chain-uids.json), default block 0's hash as the RPC reports it. The script runs at the
    ///         head block and BLOCKHASH of the current block is 0, so roll one ahead to read it on a fresh chain (head
    ///         0); past block 256 BLOCKHASH(0) is 0 and `CHAIN_UID` is required.
    function _chainUid() internal returns (bytes32 u) {
        u = vm.envOr("CHAIN_UID", bytes32(0));
        if (u == bytes32(0)) {
            uint256 head = block.number;
            vm.roll(head + 1);
            u = blockhash(0);
            vm.roll(head);
        }
        require(u != bytes32(0), "set CHAIN_UID (chain-uids.json)");
    }

    /// @notice The token factory and the `NONE` implementation by CREATE2, `NONE` registered as version 1 when the
    ///         deployer is the registrar; writes `token_factory`, `implementation_none`, `chain_uid` into the JSON
    ///         object `"deploy"`. Transitional (P1d ruling D2): `UnderlyingToken` is over EIP-170 until the size work,
    ///         so `UNDERLYING` is not deployed yet.
    function _deployTokenFactory(address registrar, bool register, address smartKeyAccountImpl, bool isHedera)
        internal returns (OpenFactory f)
    {
        f = new OpenFactory{salt: salt}(registrar, uid);
        NoUnderlyingToken none = new NoUnderlyingToken{salt: salt}(address(f), smartKeyAccountImpl, uid, isHedera);
        if (register) f.registerImplementation(IOpenFactory.TokenKind.NONE, 1, address(none));
        _gate(address(f));
        _gate(address(none));
        vm.serializeAddress("deploy", "token_factory", address(f));
        vm.serializeAddress("deploy", "implementation_none", address(none));
        vm.serializeBytes32("deploy", "chain_uid", uid);
    }

    /// @notice The deploy gate (CTR-GEN-05): `chainUid()` of the deployed contract equals the RPC's genesis hash.
    function _gate(address c) internal view {
        (bool ok, bytes memory ret) = c.staticcall(abi.encodeWithSignature("chainUid()"));
        require(ok && ret.length == 32 && abi.decode(ret, (bytes32)) == uid, "chainUid() gate");
    }
}
```

- [ ] **Step 2: The two scripts** — apply (against `main`; Task 1 already renamed the v1 names in them):

```diff
diff --git a/smartcontracts/evm/script/Deploy.s.sol b/smartcontracts/evm/script/Deploy.s.sol
index b15f200..b96a98f 100644
--- a/smartcontracts/evm/script/Deploy.s.sol
+++ b/smartcontracts/evm/script/Deploy.s.sol
@@ -1,23 +1,21 @@
 // SPDX-License-Identifier: Apache-2.0
 pragma solidity ^0.8.20;
 
-import {Script, console} from "forge-std/Script.sol";
-import {OpenFactory} from "../src/factory/OpenFactory.sol";
-import {IOpenFactory} from "../src/common/IOpenFactory.sol";
+import {console} from "forge-std/Script.sol";
+import {OpenFactoryV1} from "../src/factory/OpenFactoryV1.sol";
+import {IOpenFactoryV1} from "../src/common/IOpenFactoryV1.sol";
 import {MetaToken} from "../src/metatx/MetaToken.sol";
 import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
 import {SubjectAccountFactory} from "../src/account/SubjectAccountFactory.sol";
 import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
-import {OpenFactoryV2} from "../src/factory/OpenFactoryV2.sol";
-import {IOpenFactoryV2} from "../src/common/IOpenFactoryV2.sol";
-import {NoUnderlyingToken} from "../src/metatx/NoUnderlyingToken.sol";
+import {DeployBase} from "./DeployBase.sol";
 
 /// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast
 /// env: PRIVATE_KEY (deployer; registrar mặc định), REGISTRAR (tuỳ chọn),
 ///      DEMO_SUPPLY (tuỳ chọn; 0 = không tạo token demo), DEMO_HOLDER (tuỳ chọn, nhận một nửa),
 ///      CHAIN_UID (genesis hash, chain-uids.json; tuỳ chọn trên chain local mới — mặc định blockhash(0)).
 /// Ghi `deployments/<chainid>.json` để seed Odoo (`blockchain.token`) và config node (`dex`).
-contract Deploy is Script {
+contract Deploy is DeployBase {
     function run() external {
         uint256 pk = vm.envUint("PRIVATE_KEY");
         address deployer = vm.addr(pk);
@@ -25,15 +23,16 @@ contract Deploy is Script {
         uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
         address demoHolder = vm.envOr("DEMO_HOLDER", deployer);
 
+        _setup();
         vm.startBroadcast(pk);
-        OpenFactory factory = new OpenFactory(registrar);
-        SubjectAccountFactory accounts = new SubjectAccountFactory();
-        MetaToken impl = new MetaToken(address(factory), accounts.IMPLEMENTATION());
-        if (registrar == deployer) factory.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
-        _deployV2(registrar, registrar == deployer, accounts.IMPLEMENTATION());
-        MetaTxDex dex = new MetaTxDex();
+        OpenFactoryV1 factory = new OpenFactoryV1{salt: salt}(registrar);
+        SubjectAccountFactory accounts = new SubjectAccountFactory{salt: salt}();
+        MetaToken impl = new MetaToken{salt: salt}(address(factory), accounts.IMPLEMENTATION());
+        if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
+        _deployTokenFactory(registrar, registrar == deployer, accounts.IMPLEMENTATION(), false);
+        MetaTxDex dex = new MetaTxDex{salt: salt}();
         // R35: admin chỉ `setMarket`; production đặt REGISTRAR là một Safe (RS5-1).
-        SCaaSDex scaasDex = new SCaaSDex(registrar);
+        SCaaSDex scaasDex = new SCaaSDex{salt: salt}(registrar);
         address demo;
         if (demoSupply != 0 && registrar == deployer) {
             demo = factory.createMetaToken(1, address(0),
@@ -53,28 +52,4 @@ contract Deploy is Script {
         vm.writeJson(out, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
         console.log(out);
     }
-
-    /// TW2 §9: factory v2 + tầng None (UnderlyingToken chờ việc tối ưu kích thước, P1d D2), version 1 của kind riêng (số version theo kind; chuỗi domain "2"
-    /// là thế hệ hợp đồng). Factory v2 không đăng ký MetaToken v1. Ghi thẳng vào object JSON "deploy" (run() đã
-    /// hết chỗ trên stack).
-    function _deployV2(address registrar, bool register, address subjectImpl) internal {
-        OpenFactoryV2 f = new OpenFactoryV2(registrar);
-        // chain_uid = genesis hash (CTR-GEN-05, chain-uids.json). Default: block 0's hash as the RPC reports it. The
-        // script runs at the head block and BLOCKHASH of the current block is 0, so roll one ahead to read it on a
-        // fresh chain (head 0); past block 256 BLOCKHASH(0) is 0 and CHAIN_UID is required.
-        bytes32 uid = vm.envOr("CHAIN_UID", bytes32(0));
-        if (uid == bytes32(0)) {
-            uint256 head = block.number;
-            vm.roll(head + 1);
-            uid = blockhash(0);
-            vm.roll(head);
-        }
-        require(uid != bytes32(0), "set CHAIN_UID (chain-uids.json)");
-        // Transitional (P1d, D2): `UnderlyingToken` is over EIP-170 until the size work; only META_NONE
-        // is deployed and registered, and the JSON has no implementation_meta_single/_multi keys.
-        address none = address(new NoUnderlyingToken(address(f), subjectImpl, uid, false));
-        if (register) f.registerImplementation(IOpenFactoryV2.TokenKind.META_NONE, 1, none);
-        vm.serializeAddress("deploy", "factory_v2", address(f));
-        vm.serializeAddress("deploy", "implementation_meta_none", none);
-    }
 }
```

```diff
diff --git a/smartcontracts/evm/script/hedera/DeployHedera.s.sol b/smartcontracts/evm/script/hedera/DeployHedera.s.sol
index eed0434..e279ee1 100644
--- a/smartcontracts/evm/script/hedera/DeployHedera.s.sol
+++ b/smartcontracts/evm/script/hedera/DeployHedera.s.sol
@@ -1,22 +1,20 @@
 // SPDX-License-Identifier: Apache-2.0
 pragma solidity ^0.8.20;
 
-import {Script, console} from "forge-std/Script.sol";
-import {OpenFactory} from "../../src/factory/OpenFactory.sol";
-import {IOpenFactory} from "../../src/common/IOpenFactory.sol";
+import {console} from "forge-std/Script.sol";
+import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
+import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
 import {MetaToken} from "../../src/metatx/MetaToken.sol";
 import {MetaTxDex} from "../../src/dex/MetaTxDex.sol";
 import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
-import {OpenFactoryV2} from "../../src/factory/OpenFactoryV2.sol";
-import {IOpenFactoryV2} from "../../src/common/IOpenFactoryV2.sol";
-import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
+import {DeployBase} from "../DeployBase.sol";
 
 /// Như `script/Deploy.s.sol` nhưng implementation META là `HederaMetaToken` (R63).
 /// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow`
 /// (relay không có mempool: `--slow` gửi tuần tự, mỗi tx chờ receipt). Deployer = tài khoản ECDSA có alias EVM.
 /// env: PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?, DEMO_HOLDER?, CHAIN_UID? (mặc định blockhash(0)).
 /// Ghi `deployments/hedera-<chainid>.json`.
-contract DeployHedera is Script {
+contract DeployHedera is DeployBase {
     function run() external {
         uint256 pk = vm.envUint("PRIVATE_KEY");
         address deployer = vm.addr(pk);
@@ -24,12 +22,13 @@ contract DeployHedera is Script {
         uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
         address demoHolder = vm.envOr("DEMO_HOLDER", deployer);
 
+        _setup();
         vm.startBroadcast(pk);
-        OpenFactory factory = new OpenFactory(registrar);
-        HederaMetaToken impl = new HederaMetaToken(address(factory));
-        if (registrar == deployer) factory.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
-        _deployV2(registrar, registrar == deployer);
-        MetaTxDex dex = new MetaTxDex();
+        OpenFactoryV1 factory = new OpenFactoryV1{salt: salt}(registrar);
+        HederaMetaToken impl = new HederaMetaToken{salt: salt}(address(factory));
+        if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
+        _deployTokenFactory(registrar, registrar == deployer, address(0), true);
+        MetaTxDex dex = new MetaTxDex{salt: salt}();
         address demo;
         address demo2;
         if (demoSupply != 0 && registrar == deployer) {
@@ -53,26 +52,4 @@ contract DeployHedera is Script {
         vm.writeJson(out, string.concat("./deployments/hedera-", vm.toString(block.chainid), ".json"));
         console.log(out);
     }
-
-    /// TW2 §9/§11: factory v2 + tầng None Hedera (UnderlyingToken chờ việc tối ưu kích thước, P1d D2), version 1; ghi thẳng vào object JSON "deploy".
-    function _deployV2(address registrar, bool register) internal {
-        OpenFactoryV2 f = new OpenFactoryV2(registrar);
-        // chain_uid = genesis hash (CTR-GEN-05, chain-uids.json). Default: block 0's hash as the RPC reports it. The
-        // script runs at the head block and BLOCKHASH of the current block is 0, so roll one ahead to read it on a
-        // fresh chain (head 0); past block 256 BLOCKHASH(0) is 0 and CHAIN_UID is required.
-        bytes32 uid = vm.envOr("CHAIN_UID", bytes32(0));
-        if (uid == bytes32(0)) {
-            uint256 head = block.number;
-            vm.roll(head + 1);
-            uid = blockhash(0);
-            vm.roll(head);
-        }
-        require(uid != bytes32(0), "set CHAIN_UID (chain-uids.json)");
-        // Transitional (P1d, D2): `UnderlyingToken` is over EIP-170 until the size work; only META_NONE
-        // is deployed and registered, and the JSON has no implementation_meta_single/_multi keys.
-        address none = address(new NoUnderlyingToken(address(f), address(0), uid, true));
-        if (register) f.registerImplementation(IOpenFactoryV2.TokenKind.META_NONE, 1, none);
-        vm.serializeAddress("deploy", "factory_v2", address(f));
-        vm.serializeAddress("deploy", "implementation_meta_none", none);
-    }
 }
```

- [ ] **Step 3: `--sender`** — apply:

```diff
diff --git a/scaas-node/tests/e2e.rs b/scaas-node/tests/e2e.rs
index 41e67fb..e778d33 100644
--- a/scaas-node/tests/e2e.rs
+++ b/scaas-node/tests/e2e.rs
@@ -36,6 +36,8 @@ use serde_json::{json, Value};
 use tokio::sync::mpsc;
 
 const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
+/// Address of `DEPLOYER`: forge needs `--sender` when a script links libraries and deploys by CREATE2.
+const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
 const RELAYER: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
 
 struct Anvil(Child);
@@ -80,7 +82,7 @@ fn deploy(rpc: &str, chain_id: u64, holder: Address) -> Value {
     let sc = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm");
     let status = Command::new("forge")
         .current_dir(sc)
-        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--silent"])
+        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--silent", "--sender", DEPLOYER_ADDRESS])
         .env("PRIVATE_KEY", DEPLOYER)
         .env("DEMO_SUPPLY", "1000000000000")
         .env("DEMO_HOLDER", format!("{holder:#x}"))
```

```diff
diff --git a/scaas-node/tests/e2e_hedera.rs b/scaas-node/tests/e2e_hedera.rs
index fe01bbd..6e6b462 100644
--- a/scaas-node/tests/e2e_hedera.rs
+++ b/scaas-node/tests/e2e_hedera.rs
@@ -36,6 +36,8 @@ use scaas_node::signer::LocalSigner;
 use serde_json::{json, Value};
 
 const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
+/// Address of `DEPLOYER`: forge needs `--sender` when a script links libraries and deploys by CREATE2.
+const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
 const CHAIN_ID: u64 = 298;
 const PORT: u16 = 31960;
 const NATIVE: u64 = 1_234_567; // 0.0.1234567
@@ -78,7 +80,7 @@ fn deploy(rpc: &str) -> Value {
     std::fs::create_dir_all(format!("{}/deployments", sc())).unwrap();
     let status = Command::new("forge")
         .current_dir(sc())
-        .args(["script", "script/hedera/DeployHedera.s.sol", "--rpc-url", rpc, "--broadcast", "--silent"])
+        .args(["script", "script/hedera/DeployHedera.s.sol", "--rpc-url", rpc, "--broadcast", "--silent", "--sender", DEPLOYER_ADDRESS])
         .env("PRIVATE_KEY", DEPLOYER)
         .env("DEMO_SUPPLY", "1000000000000")
         .env("FOUNDRY_PROFILE", "private7622")
```

```diff
diff --git a/smartcontracts/scripts/deploy.sh b/smartcontracts/scripts/deploy.sh
index 7c6046d..4c1c63d 100755
--- a/smartcontracts/scripts/deploy.sh
+++ b/smartcontracts/scripts/deploy.sh
@@ -3,9 +3,9 @@
 # usage: deploy.sh <family> <network> [args…]   (args go to the native tool)
 #   evm     <rpc-url>        forge script script/Deploy.s.sol --broadcast; env PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?,
 #                            DEMO_HOLDER?, CHAIN_UID? (genesis hash from evm/chain-uids.json; defaults to blockhash(0),
-#                            which is 0 past block 256, so a long-running chain needs it); FOUNDRY_PROFILE=private7622|
-#                            gnosis|celo picks the EVM version. Writes evm/deployments/<chainid>.json. Factory v2 gets
-#                            only META_NONE until P1d: Single/Multi are over EIP-170 (R3).
+#                            which is 0 past block 256, so a long-running chain needs it), DEPLOY_SALT? (CREATE2 salt);
+#                            FOUNDRY_PROFILE=private7622|gnosis|celo picks the EVM version. Needs the deterministic
+#                            CREATE2 deployer on the chain (NET-EVM-05). Writes evm/deployments/<chainid>.json.
 #   hedera  <relay-url>      same, script/hedera/DeployHedera.s.sol --slow (writes deployments/hedera-<chainid>.json)
 #   aptos   <cli-profile>    aptos move deploy-object --address-name scaas
 #   sui     <client-env>     sui client --client.env <env> publish
@@ -15,8 +15,10 @@ set -euo pipefail
 SC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
 FAMILY="${1:?usage: $0 <family> <network> [args…]}"; NET="${2:?network}"; shift 2
 case "$FAMILY" in
-  evm)     cd "$SC/evm" && exec forge script script/Deploy.s.sol --rpc-url "$NET" --broadcast "$@" ;;
-  hedera)  cd "$SC/evm" && exec forge script script/hedera/DeployHedera.s.sol --rpc-url "$NET" --broadcast --slow "$@" ;;
+  evm)     cd "$SC/evm" && exec forge script script/Deploy.s.sol --rpc-url "$NET" --broadcast \
+             --sender "$(cast wallet address --private-key "$PRIVATE_KEY")" "$@" ;;
+  hedera)  cd "$SC/evm" && exec forge script script/hedera/DeployHedera.s.sol --rpc-url "$NET" --broadcast --slow \
+             --sender "$(cast wallet address --private-key "$PRIVATE_KEY")" "$@" ;;
   aptos)   exec aptos move deploy-object --package-dir "$SC/move/aptos" --address-name scaas --profile "$NET" "$@" ;;
   sui)     exec sui client --client.env "$NET" publish "$@" "$SC/move/sui" ;;
   soroban) C="${1:?contract (token|mandate|dex|account)}"; shift
```

- [ ] **Step 4: Size gate** — `scripts/size_gate.py` (full text, `chmod +x`) and `smartcontracts/evm/size-baseline.json`:

```python
#!/usr/bin/env python3
"""CTR-TOK-24 size gate over `forge build src --sizes --json`.

Limits: token implementations (TOKENS) 20,480 B, every other contract 24,576 B (EIP-170), init code 49,152 B
(EIP-3860). A contract named in the baseline may exceed its limit but never its recorded size (a ratchet: it can only
shrink). A baseline entry that now fits is reported, so it gets removed.

usage: size_gate.py <sizes.json> <size-baseline.json>     exit 1 on a violation
"""
import json
import sys

TOKENS = {'NoUnderlyingToken', 'UnderlyingToken'}
TOKEN_LIMIT, EIP170, EIP3860 = 20_480, 24_576, 49_152


def check(sizes, baseline):
    errs, notes = [], []
    for name, s in sorted(sizes.items()):
        rt, init = s['runtime_size'], s['init_size']
        limit = TOKEN_LIMIT if name in TOKENS else EIP170
        allowed = baseline.get(name)
        if init > EIP3860:
            errs.append(f'{name}: init {init} > {EIP3860} (EIP-3860)')
        if rt > limit and allowed is None:
            errs.append(f'{name}: runtime {rt} > {limit}')
        elif allowed is not None and rt > allowed:
            errs.append(f'{name}: runtime {rt} > baseline {allowed} (it may only shrink)')
        elif allowed is not None and rt <= limit:
            notes.append(f'{name}: fits ({rt} <= {limit}); remove it from the baseline')
    return errs, notes


def main(argv):
    sizes = json.load(open(argv[1]))
    baseline = {k: v for k, v in json.load(open(argv[2])).items() if not k.startswith('_')}
    errs, notes = check(sizes, baseline)
    for n in notes:
        print('note:', n)
    for e in errs:
        print('error:', e)
    print(f'size gate: {len(errs)} error(s), {len(sizes)} contracts')
    return 1 if errs else 0


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        s = lambda rt, init=0: {'runtime_size': rt, 'init_size': init}
        assert check({'A': s(24_576)}, {}) == ([], [])
        assert check({'A': s(24_577)}, {})[0]
        assert check({'NoUnderlyingToken': s(20_481)}, {})[0]
        assert check({'X': s(26_000)}, {'X': 26_000}) == ([], [])
        assert check({'X': s(26_001)}, {'X': 26_000})[0]
        assert check({'X': s(20_000)}, {'X': 26_000})[1]
        assert check({'A': s(1, 49_153)}, {})[0]
        print('size gate self-test ok')
        sys.exit(0)
    sys.exit(main(sys.argv))
```

```json
{
  "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
  "UnderlyingToken": 26449,
  "ZetherToken": 28849
}
```

In `.github/workflows/ci.yml`, job `contracts`, after "forge test (default profile)":

```yaml
      - name: size gate (CTR-TOK-24, ratchet)
        run: |
          python3 ../../scripts/size_gate.py --self-test
          forge build src --sizes --json > /tmp/sizes.json || true
          python3 ../../scripts/size_gate.py /tmp/sizes.json size-baseline.json
```

Update the comment block at the top of `ci.yml` with the size-gate command.

- [ ] **Step 5: Run** — `python3 scripts/size_gate.py --self-test`; the measuring command and the gate (expected `0
error(s)`); then the e2e: `timeout 1800 scripts/capped bash -c 'cd scaas-node && CARGO_BUILD_JOBS=4 cargo test --test e2e --
--ignored --test-threads=1 2>&1 | tail -6'` and the same for `e2e_hedera` (expected 4/4, 1/1). Remove any
`deployments/*.json` or `broadcast/` the runs leave behind unless they were tracked before.

- [ ] **Step 6: Commit** — `P1e: deploy through the CREATE2 deployer with the chainUid() gate; CI size gate (ratchet)` + trailer.

---

### Task 3: Docs, TODO and HANDOFF

**Model:** Sonnet, effort medium.

**Files:**
- `docs/contracts/token-wrappers.md` §6: CTR-TOK-03/25 "Transitional (BUILT, P1e)" — `OpenFactory` built as specified except
  E3 (no Zether/DEX creation yet); `kind()` constant (E4); `ConfigFieldForOtherKind` (E5); §6.2 rewritten to the built
  state: `OpenFactoryV1` + `IOpenFactoryV1` + `IFactoryTokenV1` remain for the v1 line until P3/P5 (E1), factory v2 is in
  `legacy/p1e/`; the §6.2 interface block and rule table describe `OpenFactory` (drop `createTiered*`, `TieredTokenDeployed`,
  `META_*`); CTR-TOK-24 size gate as a ratchet (E9, "controller ruling, pending the owner"); §12 Factory row matches
  `Factory.t.sol`. Net ≤ 0 lines.
- `docs/contracts/README.md` CTR-GEN-05 table row "token implementations" (no Hedera children) and the deploy-script
  paragraph's "Transitional (BUILT)" (now CREATE2 with `DEPLOY_SALT`, gate, `--sender`; v1 line still deployed for the
  node until P5); CTR-GEN-06 note on libraries (E7).
- `docs/networks/evm.md` NET-EVM-05: built (script side); the runbook line for a chain without the deterministic
  deployer; `--sender`; the JSON keys.
- `docs/contracts/metatx.md`/`docs/integration.md`/`README.md`: replace remaining `createTiered`/`factory_v2` mentions
  presented as current (grep).
- `docs/history/dropped-artifacts.tsv`: rows only where the checker (C7) asks.
- `TODO.md`: P1 line (P1e done + merge + count; P1 complete except the parked items); MT-1 (built: kinds on `TokenConfig`,
  factory; v1 line kept as `…V1`, E1), MT-4 (CREATE2 + gate built for tokens/factory; other domains per E10); a "v1 line
  to backup" item under P3 (Zether) and P5 (node/clientkeys); P1d follow-up "dead META_MULTI branch" done.
  `HANDOFF.md`: new top section "Session 2026-10-11 (P1e)": state, built, rulings E1–E10 (E1/E7/E9 flagged for the
  owner), sizes, next = P2 plan (TradeLib, size room first).

- [ ] **Step 1:** edits; `python3 scripts/docs_check.py check`, `… facts check`, `python3 scripts/test_docs_check.py` — 0 errors.
- [ ] **Step 2: Commit** — `P1e: docs, TODO and HANDOFF` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh); one fix wave if needed; scoped re-review.
- Merge `p1e-factory` into `main` with `--no-ff` (local); push only if the owner asked in the session; remove the worktree.
