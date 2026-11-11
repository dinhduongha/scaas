# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of round 3r (admin, not owner; spec docs/superpowers/specs/2026-11-10-admin-not-owner.md §8, §13.9), in the
shape of runs/2026-11-10-ua-mtx-merge-3c/mutants.py: one mutant per run on a clean tree (the mutated file committed), the
source edit applied, the named suite run alone through `scripts/capped`, the file restored in the same process (finally), then
`git diff --quiet --exit-code -- <file>` must hold (byte-equal). Killed = the run fails (rc != 0) with a test red.

A row: id -> (file from the repository root, old text (must occur once), new text, kind, where, match)
  kind "forge": FOUNDRY_TEST=smartcontracts/evm/<where>, `forge test --match-path <where>/<match>` (match a glob of files)
  kind "cargo": in <where> (e.g. scaas-node), `cargo test --lib <match>` (a test-name filter)
  kind "npm":   in <where> (e.g. clients/clientkeys), `npm test`

Usage (from the repository root): python3 smartcontracts/evm/runs/2026-11-10-ua-mtx-3r/mutants.py list | run <id> [<id> ...] | all
Full output: runs/2026-11-10-ua-mtx-3r/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-10-ua-mtx-3r/mutants.txt (committed). `all` skips ids already in mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
CAPPED = os.path.join(ROOT, "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")

# Rows are added by the task that builds the code they mutate (T2 ... T15); T13 runs the rest and checks the count.
UA = "smartcontracts/evm/src/governance/UAAdmin.sol"
OF = "smartcontracts/evm/src/factory/OpenFactory.sol"
CR = "smartcontracts/evm/src/regulated/ComplianceRegistry.sol"
RL = "smartcontracts/evm/src/regulated/RegulatedLib.sol"
MUTANTS = {
    # T2 (§4.1): a token face keeps an ownership alias beside the admin entries: `owner()` answering the admin (a view, caught
    # by AdminNames) and a `transferOwnership(bytes32)` stub (a write, caught by SelectorAudit as unclassified). The face is
    # generated from entries.json by gen_faces.py, which the harness does not run, so the generated face is mutated.
    "M5": ("smartcontracts/evm/src/metatx/NormalToken.sol",
           "    function admin() external view returns (bytes32 _p0) {\n        _forwardView(_MA);\n    }\n",
           "    function admin() external view returns (bytes32 _p0) {\n        _forwardView(_MA);\n    }\n\n"
           "    function owner() external view returns (bytes32) {\n        return IGovernance(address(this)).admin();\n    }\n\n"
           "    function transferOwnership(bytes32) external {\n        _forward(_MA);\n    }\n",
           "forge", "test/governance", "{AdminNames,SelectorAudit}.t.sol"),
    # T7a (§4.3): UATransferAdmin keeps the word `newOwner` (the typehash pin)
    "M7": ("smartcontracts/evm/src/governance/GovernanceRouterBase.sol",
           "\"UATransferAdmin(bytes32 from,address target,bytes32 newAdmin,",
           "\"UATransferAdmin(bytes32 from,address target,bytes32 newOwner,",
           "forge", "test/governance", "GovRouterTypehash.t.sol"),
    # T3 (§4.3): TOPIC_TYPEHASH keeps `owner` (the typehash pins and the topics.json digests)
    "M8": ("smartcontracts/evm/src/pqchat/PqChatTypes.sol",
           "\"PqTopic(bytes32 admin,uint64 nonce,",
           "\"PqTopic(bytes32 owner,uint64 nonce,",
           "forge", "test/pqchat", "PqChatTypes.t.sol"),
    # T4 (§3): `_create` still reads the token's `admin()` (the reverting-`admin()` creation)
    "M6": ("smartcontracts/evm/src/factory/OpenFactory.sol",
           "        IGovernance t = IGovernance(token);\n        _index(token, creatorId, CLASS_TOKEN, uint16(kind), version);\n",
           "        IGovernance t = IGovernance(token);\n        t.admin();\n        _index(token, creatorId, CLASS_TOKEN, uint16(kind), version);\n",
           "forge", "test/v2", "FactoryIndex.t.sol"),
    # T9a (§7): a node row keeps the old entry `mtxTransferOwnership` (the allow-list against selector_audit.json)
    "M12": ("scaas-node/src/typed.rs",
            "(\"UATransferAdmin\", \"mtxTransferAdmin\", GR,",
            "(\"UATransferAdmin\", \"mtxTransferOwnership\", GR,",
            "cargo", "scaas-node", "allow_lists_equal_the_selector_audit_both_directions"),
    # T5 (§5.1, §5.2, §5.6, §8): UAAdmin and the factory's admin, approvals and open deploys; every row is killed by
    # test/v2/FactoryAdmin.t.sol (FA = the file)
    **{mid: (path, old, new, "forge", "test/v2", "FactoryAdmin.t.sol") for mid, path, old, new in [
        # M1: `_adminSubject` asks any caller with code for `subject()` (the fake-router test)
        ("M1", UA, "        if (r != address(0) && msg.sender == r) return IGovernanceRouter(r).subject();",
         "        if (msg.sender.code.length != 0) return IGovernanceRouter(msg.sender).subject();"),
        # M2: the router branch returns `pad(msg.sender)` (the derived-admin tests)
        ("M2", UA, "        if (r != address(0) && msg.sender == r) return IGovernanceRouter(r).subject();",
         "        if (r != address(0) && msg.sender == r) return bytes32(uint256(uint160(msg.sender)));"),
        # M3: `onlyAdmin` drops `c != 0` (renounce + a router answering 0)
        ("M3", UA, "        if (c == 0 || c != _adminStorage().admin) revert NotAdmin(c);",
         "        if (c != _adminStorage().admin) revert NotAdmin(c);"),
        # M4: the direct path drops `requireNotDelegated` (the designator test)
        ("M4", UA, "        SigCheck.requireNotDelegated(msg.sender);\n", ""),
        # M9: `acceptAdmin` leaves the pending (a second accept)
        ("M9", UA, "        (s.admin, s.pendingAdmin) = (c, bytes32(0));", "        s.admin = c;"),
        # M10: the constructor takes a derived id (the constructor test)
        ("M10", OF, "        if (admin_ == bytes32(0) || uint256(admin_) >> 160 != 0) revert AdminNotNative(admin_);",
         "        if (admin_ == bytes32(0)) revert AdminNotNative(admin_);"),
        # M17: `_renounceAdmin` leaves the pending (the renounce-clears-pending test)
        ("M17", UA, "        (s.admin, s.pendingAdmin) = (bytes32(0), bytes32(0));", "        s.admin = bytes32(0);"),
        # M18: `transferAdmin` writes the admin in one step (the two-step tests)
        ("M18", UA, "        s.pendingAdmin = newAdmin;", "        s.admin = newAdmin;"),
        # M19: `acceptAdmin` drops `c != 0` (a router answering 0 with no pending)
        ("M19", UA, "        if (c == 0 || c != s.pendingAdmin) revert NotPendingAdmin(c);",
         "        if (c != s.pendingAdmin) revert NotPendingAdmin(c);"),
        # M22: `transferAdmin` / `renounceAdmin` without `configured` (the unconfigured test)
        ("M22-transfer", OF, "    function transferAdmin(bytes32 newAdmin) public override(IAdmin, UAAdmin) configured {",
         "    function transferAdmin(bytes32 newAdmin) public override(IAdmin, UAAdmin) {"),
        ("M22-renounce", OF, "    function renounceAdmin() external configured {", "    function renounceAdmin() external {"),
        # M23: the shortcut accepts a sender that is not the admin, or reads the router's `subject()`
        ("M23-sender", OF, "        else if (bytes32(uint256(uint160(msg.sender))) != _adminStorage().admin || SigCheck.isDesignator(msg.sender)) {",
         "        else if (SigCheck.isDesignator(msg.sender)) {"),
        ("M23-subject", OF, "        else if (bytes32(uint256(uint160(msg.sender))) != _adminStorage().admin || SigCheck.isDesignator(msg.sender)) {",
         "        else if (_adminSubject() != _adminStorage().admin || SigCheck.isDesignator(msg.sender)) {"),
        # M24: the deploy skips the approval lookup, or takes a hash from another source than the call's bytes
        ("M24-skip", OF, "        _useApproval(_tokenKey(kind, version, envVersion, keccak256(initcode), keccak256(implArgs)));\n", ""),
        ("M24-hash", OF, "        _useApproval(_tokenKey(kind, version, envVersion, keccak256(initcode), keccak256(implArgs)));",
         "        _useApproval(_tokenKey(kind, version, envVersion, keccak256(implArgs), keccak256(implArgs)));"),
        # M25: the key leaves out one field (one row each)
        ("M25-chainUid", OF, "        return keccak256(abi.encode(_TAG_TOKEN, chainUid, address(this), kind,",
         "        return keccak256(abi.encode(_TAG_TOKEN, address(this), kind,"),
        ("M25-factory", OF, "        return keccak256(abi.encode(_TAG_TOKEN, chainUid, address(this), kind,",
         "        return keccak256(abi.encode(_TAG_TOKEN, chainUid, kind,"),
        ("M25-envVersion", OF, "        return keccak256(abi.encode(_TAG_TOKEN, chainUid, address(this), kind, version, envVersion, initcodeHash,",
         "        return keccak256(abi.encode(_TAG_TOKEN, chainUid, address(this), kind, version, initcodeHash,"),
        ("M25-initSelector", OF, "id, envVersion, initSelector, interfaceId,\n", "id, envVersion, interfaceId,\n"),
        ("M25-interfaceId", OF, "id, envVersion, initSelector, interfaceId,\n", "id, envVersion, initSelector,\n"),
        ("M25-tag", OF, "        return keccak256(abi.encode(_TAG_TOKEN, chainUid, address(this), kind,",
         "        return keccak256(abi.encode(chainUid, address(this), kind,"),
        # M26: the deploy does not check the approval's term, or its `until`
        ("M26-generation", OF, "        if (_live(a)) a.state = ApprovalState.CONSUMED;",
         "        if (a.state == ApprovalState.LIVE && block.timestamp <= a.until) a.state = ApprovalState.CONSUMED;"),
        ("M26-until", OF, "        if (_live(a)) a.state = ApprovalState.CONSUMED;",
         "        if (a.state == ApprovalState.LIVE && a.adminGeneration == _adminStorage().adminGeneration) a.state = ApprovalState.CONSUMED;"),
        # M27: the deploy does not mark the approval consumed (the used-twice test)
        ("M27", OF, "        if (_live(a)) a.state = ApprovalState.CONSUMED;", "        if (_live(a)) {}"),
        # M28: `revokeApproval` without `onlyAdmin`, or on a consumed key
        ("M28-onlyAdmin", OF, "    function revokeApproval(bytes32 key) external onlyAdmin configured {",
         "    function revokeApproval(bytes32 key) external configured {"),
        ("M28-consumed", OF, "        if (_approvals[key].state != ApprovalState.LIVE) revert ApprovalNotRevocable(key);",
         "        if (_approvals[key].state == ApprovalState.NONE) revert ApprovalNotRevocable(key);"),
        # M29: an approval that ignores its `chainUid`, `factory` or `adminGeneration` field
        ("M29-chainUid", OF, "        if (chainUid_ != chainUid) revert ApprovalFieldMismatch(ApprovalField.CHAIN_UID);\n", ""),
        ("M29-factory", OF, "        if (factory_ != address(this)) revert ApprovalFieldMismatch(ApprovalField.FACTORY);\n", ""),
        ("M29-generation", OF,
         "        if (generation != _adminStorage().adminGeneration) revert ApprovalFieldMismatch(ApprovalField.ADMIN_GENERATION);\n", ""),
        # M30: `approve*` refuses an entry that is no longer live: expired, of an older term, revoked (a revoked entry is
        # deleted, spec §5.6 item 2, so refusing it is refusing an empty entry)
        ("M30-expired", OF, "        if (_live(a)) revert ApprovalLive(key);",
         "        if (a.state == ApprovalState.LIVE && a.adminGeneration == _adminStorage().adminGeneration) revert ApprovalLive(key);"),
        ("M30-older", OF, "        if (_live(a)) revert ApprovalLive(key);",
         "        if (a.state == ApprovalState.LIVE && block.timestamp <= a.until) revert ApprovalLive(key);"),
        ("M30-revoked", OF, "        if (_live(a)) revert ApprovalLive(key);",
         "        if (_live(a) || a.state == ApprovalState.NONE) revert ApprovalLive(key);"),
        # M31: `_supports` without the gas floor (the low-gas deploy test)
        ("M31", OF, "        if (left < _PROBE_GAS * 64 / 63 + _PROBE_GAS_MARGIN) revert ProbeGasLow(left);\n", ""),
    ]},
    # T6 (§5.3, §5.3.1, §8): the registry's admin and KYC providers, the regulated token's registry-router check; every row
    # is killed by test/as/RegistryAdmin.t.sol (its two suites)
    **{mid: (path, old, new, "forge", "test/as", "RegistryAdmin.t.sol") for mid, path, old, new in [
        # M11: `setCompliance` from the router takes a non-admin subject as the admin (id 0)
        ("M11", CR, "        if (c != _adminStorage().admin) {", "        if (c != _adminStorage().admin && msg.sender != govRouter) {"),
        # M13: `setCompliance` looks the KYC provider up by `msg.sender`, not the subject (the derived-provider test)
        ("M13", CR, "            id = kycProviderId[c];", "            id = kycProviderId[bytes32(uint256(uint160(msg.sender)))];"),
        # M14: the registry keeps a `renounceAdmin` (the no-renounce test)
        ("M14", CR, "    function _adminRouter() internal view override returns (address) {",
         "    function renounceAdmin() external {\n        _renounceAdmin();\n    }\n\n"
         "    function _adminRouter() internal view override returns (address) {"),
        # M16: `RegulatedLib.init` drops the registry-router check (the `ComplianceRegistryRouterMismatch` tests)
        ("M16", RL, "            if (got != address(0) && got != govRouter) revert IRegulatedToken.ComplianceRegistryRouterMismatch(reg, got);\n",
         ""),
        # M20: the registry's `_adminRouter()` answers 0, or another address (the derived registry-admin tests)
        ("M20-zero", CR, "        return govRouter;", "        return address(0);"),
        ("M20-other", CR, "        return govRouter;", "        return address(uint160(govRouter) + 1);"),
        # M21: the constructor takes a derived admin with router 0, or a router without code (the constructor test)
        ("M21-router0", CR, "            if (uint256(admin_) >> 160 != 0) revert AdminUnreachable(admin_);\n", ""),
        ("M21-nocode", CR, "        } else if (govRouter_.code.length == 0) {\n            revert RouterNotContract(govRouter_);\n        }",
         "        }"),
    ]},
    # T15 (§13.3, §13.4, §13.6, §13.9): the factory as the chain's directory; every row is killed by
    # test/v2/FactoryDirectory.t.sol (the two-chain row is in ChainNeutralFactory.t.sol, D-free)
    **{mid: (OF, old, new, "forge", "test/v2", "FactoryDirectory.t.sol") for mid, old, new in [
        # D1: `setChainEntries` overwrites a written entry (one row per entry: its slot read as 0)
        ("D1-relay", "            _entry(relayFeeRouter, relayFeeRouter_,", "            _entry(address(0), relayFeeRouter_,"),
        ("D1-compliance", "            _entry(complianceRegistry, complianceRegistry_,", "            _entry(address(0), complianceRegistry_,"),
        ("D1-accountFactory", "            _entry(smartKeyAccountFactory, smartKeyAccountFactory_,",
         "            _entry(address(0), smartKeyAccountFactory_,"),
        ("D1-zether", "            _entry(zetherStatements, zetherStatements_,", "            _entry(address(0), zetherStatements_,"),
        # D2: no code-hash compare at the write
        ("D2", "        if (codeHash == bytes32(0) || codeHash == keccak256(\"\") || target.codehash != codeHash) {",
         "        if (codeHash == bytes32(0) || codeHash == keccak256(\"\")) {"),
        # D3: 0 or keccak256("") taken as a code hash
        ("D3", "        if (codeHash == bytes32(0) || codeHash == keccak256(\"\") || target.codehash != codeHash) {",
         "        if (target.codehash != codeHash) {"),
        # D4: an env publish without the registry agreement (one row per publish entry: its domain skips the check)
        ("D4-publishEnv", "            if (env.registry != address(0) && env.registry != reg)",
         "            if (domain >= DEX_DOMAIN && env.registry != address(0) && env.registry != reg)"),
        ("D4-publishDexEnv", "            if (env.registry != address(0) && env.registry != reg)",
         "            if (domain != DEX_DOMAIN && env.registry != address(0) && env.registry != reg)"),
        ("D4-publishClassEnv", "            if (env.registry != address(0) && env.registry != reg)",
         "            if (domain <= DEX_DOMAIN && env.registry != address(0) && env.registry != reg)"),
        # D5: `directory()` reads another source than the views
        ("D5", "            smartKeyAccountFactory, zetherStatements);", "            smartKeyAccountFactory, smartKeyAccountFactory);"),
        # D6: `configureChain` skips the router's code hash
        ("D6", "        _requireCode(r, codeHash);\n", ""),
        # D7: `setChainEntries` drops the registry's `govRouter` check
        ("D7", "            if (_addr(complianceRegistry_, _GOV_ROUTER, v) != govRouter) revert EntryMismatch(v);\n", ""),
        # D8: `setChainEntries` drops the account factory's `chainUid` check
        ("D8", "            _requireChainUid(smartKeyAccountFactory_, chainUid);\n", ""),
        # D9: `configureChain` drops the router-registry clone-hash check
        ("D9", "        if (!okR || !okG || a != b) revert SmartKeyCloneHashMismatch(bytes32(a), bytes32(b));\n", ""),
        # D10: an env publish drops the implementation binding (one row per publish entry)
        ("D10-publishEnv", "                if (_cloneHash(ska) != want)", "                if (domain >= DEX_DOMAIN && _cloneHash(ska) != want)"),
        ("D10-publishDexEnv", "                if (_cloneHash(ska) != want)", "                if (domain != DEX_DOMAIN && _cloneHash(ska) != want)"),
        ("D10-publishClassEnv", "                if (_cloneHash(ska) != want)", "                if (domain <= DEX_DOMAIN && _cloneHash(ska) != want)"),
        # D11: `setChainEntries` drops the implementation binding
        ("D11", "                if (got != want) revert SmartKeyCloneHashMismatch(want, got);\n", ""),
        # D12: `configureChain` takes a router whose `registry()` is 0, or has no code
        ("D12-zero", "|| reg.code.length == 0) revert RouterRegistryInvalid(reg);",
         "|| (reg != address(0) && reg.code.length == 0)) revert RouterRegistryInvalid(reg);"),
        ("D12-nocode", "|| reg.code.length == 0) revert RouterRegistryInvalid(reg);", "|| reg == address(0)) revert RouterRegistryInvalid(reg);"),
        # D13: `setChainEntries` drops the executor's code-hash or `ROUTER()` check
        ("D13-hash", "            _requireCode(x, relayFeeExecutorCodeHash);\n", ""),
        ("D13-router", "            if (_addr(x, _ROUTER, v) != relayFeeRouter_) revert EntryMismatch(v);\n", ""),
        # D14: `relayFeeExecutor()` answers anything but the written router's `EXECUTOR()`
        ("D14", "        return r == address(0) ? address(0) : _addr(r, _EXECUTOR, IOpenFactory.relayFeeExecutor.selector);",
         "        return r;"),
    ]},
    # T7 (spec §8, Fable P1-3): B1-B15, one per new signed struct of the router, a word dropped from its hash (for an op
    # whose words are the call's arguments, the last word out of the signed words, the call keeps it); each killed by
    # that struct's binding matrix in test/governance/GovRouterAdmin.t.sol (`test_binding_<Op>`)
    **{mid: ("smartcontracts/evm/src/governance/GovernanceRouter.sol", old, new, "forge", "test/governance",
             "GovRouterAdmin.t.sol") for mid, old, new in [
        # B1: UAPublishTokenEnv
        ('B1', 'abi.encode(kind, envVersion, _envHash(env))',
         'abi.encode(kind, _envHash(env))'),
        # B2: UAPublishDexEnv
        ('B2', 'abi.encode(envVersion, _envHash(env))',
         'abi.encode(_envHash(env))'),
        # B3: UAPublishClassEnv
        ('B3', 'abi.encode(contractClass, kind, envVersion, _envHash(env))',
         'abi.encode(contractClass, envVersion, _envHash(env))'),
        # B4: UAApproveTokenRelease
        ('B4', '        _ua(T.UA_APPROVE_TOKEN_RELEASE, e, target, IOpenFactory.approveTokenRelease.selector, abi.encode(kind, version,\n            envVersion, initcodeHash, implArgsHash, chainUid, factory, adminGeneration, until), auth);\n',
         '        bytes memory w = abi.encode(kind, version,\n            envVersion, initcodeHash, implArgsHash, chainUid, factory, adminGeneration, until);\n        bytes memory d = bytes.concat(IOpenFactory.approveTokenRelease.selector, w);\n        assembly ("memory-safe") { mstore(w, sub(mload(w), 32)) } // the last word out of the hash, the call keeps it\n        _uaCall(T.UA_APPROVE_TOKEN_RELEASE, e, target, w, d, auth);\n'),
        # B5: UAApproveDexRelease
        ('B5', '        _ua(T.UA_APPROVE_DEX_RELEASE, e, target, IOpenFactory.approveDexRelease.selector, abi.encode(version, envVersion,\n            initcodeHash, implArgsHash, chainUid, factory, adminGeneration, until), auth);\n',
         '        bytes memory w = abi.encode(version, envVersion,\n            initcodeHash, implArgsHash, chainUid, factory, adminGeneration, until);\n        bytes memory d = bytes.concat(IOpenFactory.approveDexRelease.selector, w);\n        assembly ("memory-safe") { mstore(w, sub(mload(w), 32)) } // the last word out of the hash, the call keeps it\n        _uaCall(T.UA_APPROVE_DEX_RELEASE, e, target, w, d, auth);\n'),
        # B6: UAApproveRelease
        ('B6', '        _ua(T.UA_APPROVE_RELEASE, e, target, IOpenFactory.approveRelease.selector, abi.encode(approval), auth);\n',
         '        bytes memory w = abi.encode(approval);\n        bytes memory d = bytes.concat(IOpenFactory.approveRelease.selector, w);\n        assembly ("memory-safe") { mstore(w, sub(mload(w), 32)) } // the last word out of the hash, the call keeps it\n        _uaCall(T.UA_APPROVE_RELEASE, e, target, w, d, auth);\n'),
        # B7: UARevokeApproval
        ('B7', '        _ua(T.UA_REVOKE_APPROVAL, e, target, IOpenFactory.revokeApproval.selector, abi.encode(key), auth);\n',
         '        bytes memory w = abi.encode(key);\n        bytes memory d = bytes.concat(IOpenFactory.revokeApproval.selector, w);\n        assembly ("memory-safe") { mstore(w, sub(mload(w), 32)) } // the last word out of the hash, the call keeps it\n        _uaCall(T.UA_REVOKE_APPROVAL, e, target, w, d, auth);\n'),
        # B8: UADeprecateToken
        ('B8', 'abi.encode(kind, version, keccak256(bytes(reason)))',
         'abi.encode(kind, keccak256(bytes(reason)))'),
        # B9: UADeprecateDex
        ('B9', 'abi.encode(version, keccak256(bytes(reason)))',
         'abi.encode(keccak256(bytes(reason)))'),
        # B10: UADeprecateRelease
        ('B10', 'abi.encode(contractClass, kind, version, keccak256(bytes(reason)))',
         'abi.encode(contractClass, kind, keccak256(bytes(reason)))'),
        # B11: UASetTokenKindEnabled
        ('B11', '        _ua(T.UA_SET_TOKEN_KIND_ENABLED, e, target, IOpenFactory.setTokenKindEnabled.selector, abi.encode(kind, on), auth);\n',
         '        bytes memory w = abi.encode(kind, on);\n        bytes memory d = bytes.concat(IOpenFactory.setTokenKindEnabled.selector, w);\n        assembly ("memory-safe") { mstore(w, sub(mload(w), 32)) } // the last word out of the hash, the call keeps it\n        _uaCall(T.UA_SET_TOKEN_KIND_ENABLED, e, target, w, d, auth);\n'),
        # B12: UASetClassKindEnabled
        ('B12', '        _ua(T.UA_SET_CLASS_KIND_ENABLED, e, target, IOpenFactory.setClassKindEnabled.selector,\n            abi.encode(contractClass, kind, on), auth);\n',
         '        bytes memory w = abi.encode(contractClass, kind, on);\n        bytes memory d = bytes.concat(IOpenFactory.setClassKindEnabled.selector, w);\n        assembly ("memory-safe") { mstore(w, sub(mload(w), 32)) } // the last word out of the hash, the call keeps it\n        _uaCall(T.UA_SET_CLASS_KIND_ENABLED, e, target, w, d, auth);\n'),
        # B13: UASetKycProvider
        ('B13', '        _ua(T.UA_SET_KYC_PROVIDER, e, target, IComplianceRegistry.setKycProvider.selector, abi.encode(provider, enabled), auth);\n',
         '        bytes memory w = abi.encode(provider, enabled);\n        bytes memory d = bytes.concat(IComplianceRegistry.setKycProvider.selector, w);\n        assembly ("memory-safe") { mstore(w, sub(mload(w), 32)) } // the last word out of the hash, the call keeps it\n        _uaCall(T.UA_SET_KYC_PROVIDER, e, target, w, d, auth);\n'),
        # B14: UASetCompliance
        ('B14', 'keccak256(abi.encodePacked(flags)), keccak256(abi.encodePacked(until))),',
         'keccak256(abi.encodePacked(until))),'),
        # B15: UASetChainEntries
        ('B15', '        _ua(T.UA_SET_CHAIN_ENTRIES, e, target, IOpenFactory.setChainEntries.selector, abi.encode(relayFeeRouter,\n            relayFeeRouterCodeHash, relayFeeExecutorCodeHash, complianceRegistry, complianceRegistryCodeHash,\n            smartKeyAccountFactory, smartKeyAccountFactoryCodeHash, zetherStatements, zetherStatementsCodeHash), auth);\n',
         '        bytes memory w = abi.encode(relayFeeRouter,\n            relayFeeRouterCodeHash, relayFeeExecutorCodeHash, complianceRegistry, complianceRegistryCodeHash,\n            smartKeyAccountFactory, smartKeyAccountFactoryCodeHash, zetherStatements, zetherStatementsCodeHash);\n        bytes memory d = bytes.concat(IOpenFactory.setChainEntries.selector, w);\n        assembly ("memory-safe") { mstore(w, sub(mload(w), 32)) } // the last word out of the hash, the call keeps it\n        _uaCall(T.UA_SET_CHAIN_ENTRIES, e, target, w, d, auth);\n'),
    ]},
    # T9 / T13 (spec §8 M15, §5.6 Q3): a node row for a release deploy (`OpenFactory`'s open deploy as a plain row), and one for
    # a release approval (the router's); each caught by the guard test (`NOT_ROWS`, `APPROVED`, the router's allow-list)
    "M15-deploy": ("scaas-node/src/typed.rs", '    ("deploy", FACT, "SubjectKey firstKey,address guardian"),\n',
                   '    ("deploy", FACT, "SubjectKey firstKey,address guardian"),\n'
                   '    ("deployTokenImplementation", FACT, "uint8 kind,uint64 version,uint16 envVersion,bytes initcode,bytes implArgs"),\n',
                   "cargo", "scaas-node", "allow_lists_equal_the_selector_audit_both_directions"),
    "M15-approve": ("scaas-node/src/typed.rs",
                    '    ("UASetKycProvider", "mtxSetKycProvider", GR, "bytes32 from,address target,bytes32 provider,bool enabled,E", ""),\n',
                    '    ("UASetKycProvider", "mtxSetKycProvider", GR, "bytes32 from,address target,bytes32 provider,bool enabled,E", ""),\n'
                    '    ("UARevokeApproval", "mtxRevokeApproval", GR, "bytes32 from,address target,bytes32 key,E", ""),\n',
                    "cargo", "scaas-node", "allow_lists_equal_the_selector_audit_both_directions"),
}


def red_tests(log):
    forge = re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)
    cargo = re.findall(r"^test (\S+) \.\.\. FAILED", log, re.M)
    node = re.findall(r"^not ok \d+ - (.+)$", log, re.M) + re.findall(r"^\s*✖ (.+?)(?: \(\d|$)", log, re.M)
    return sorted(set(forge + cargo + node))


def command(kind, where, match):
    if kind == "forge":
        n = "mutants-3r-" + where.replace("/", "-")
        env = {"FOUNDRY_TEST": where, "FOUNDRY_SCRIPT": where, "FOUNDRY_OUT": f"out/{n}", "FOUNDRY_CACHE_PATH": f"cache/{n}"}
        return os.path.join(ROOT, "smartcontracts", "evm"), env, [FORGE, "test", "-j", "2", "--match-path", f"{where}/{match}"]
    if kind == "cargo":
        return os.path.join(ROOT, where), {"CAPPED_MEM": "6G"}, ["cargo", "test", "-j", "2", "--lib", match]
    if kind == "npm":
        return os.path.join(ROOT, where), {}, ["npm", "test"]
    raise SystemExit(f"unknown kind {kind}")


def run(mid):
    path, old, new, kind, where, match = MUTANTS[mid]
    full = os.path.join(ROOT, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=ROOT) != 0:
        raise SystemExit(f"{mid}: {path} has uncommitted changes; commit first")
    logp = os.path.join(HERE, f"mut-{mid}.log")
    cwd, extra, cmd = command(kind, where, match)
    # MUT_IN_CAPPED=1: the batch already runs inside one `scripts/capped` scope (each mutant still alone and in order)
    cap = [] if os.environ.get("MUT_IN_CAPPED") == "1" else [CAPPED]
    try:
        open(full, "w").write(src.replace(old, new))
        with open(logp, "w") as log:
            rc = subprocess.call(cap + cmd, cwd=cwd, env={**os.environ, **extra}, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=ROOT) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    compile_err = "Compiler run failed" in out or "error[E" in out or "could not compile" in out
    note = ", ".join(red) if red else ("compile error" if compile_err else "none")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:]:
            run(m)
    elif sys.argv[1:2] == ["all"]:
        done = set()
        txt = os.path.join(HERE, "mutants.txt")
        if os.path.exists(txt):
            done = {l.split(" | ")[0] for l in open(txt) if " | " in l}
        for m in MUTANTS:
            if m not in done:
                run(m)
    else:
        raise SystemExit(__doc__)
