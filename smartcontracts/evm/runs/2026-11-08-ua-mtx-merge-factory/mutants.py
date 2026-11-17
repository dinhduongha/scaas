# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of the factory index and chain-neutral group (factory index spec §7, §8.9; chain-neutral spec §8;
plan T67-T76, run in T68). One mutant per run, on a clean tree: the source edit is applied, the named tests run through
`scripts/capped`, the file is restored in the same process (finally), then `git diff --exit-code -- <file>` must hold. A
mutant is killed when the run fails (rc != 0) and a test went red; a compile error is reported as such, not a kill.

Usage (from smartcontracts/evm): python3 runs/2026-11-08-ua-mtx-merge-factory/mutants.py list
                                 python3 runs/2026-11-08-ua-mtx-merge-factory/mutants.py run <id> [<id> ...]
Full output: runs/2026-11-08-ua-mtx-merge-t68-mut-<id>.log (git-ignored); the line `mutant | test that went red | rc` is
appended to runs/2026-11-08-ua-mtx-merge-t68-mutants.txt. UNAUDITED.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
DATE = "2026-11-08"

OF = "src/factory/OpenFactory.sol"
C3 = "src/factory/Create3.sol"
CE = "src/factory/ChainEnvCode.sol"
MTB = "src/metatx/MetaTokenBase.sol"
SE = "src/common/SaltedEIP712.sol"
IDX = "test/v2/FactoryIndex.t.sol"
CNF = "test/v2/ChainNeutralFactory.t.sol"
CNK = "test/v2/ChainNeutralKinds.t.sol"
GEN = "test/v2/FactoryGenericKind.t.sol"
FAC = "test/v2/Factory.t.sol"
V2 = "test/v2/{FactoryIndex,ChainNeutralFactory,ChainNeutralKinds,FactoryGenericKind,Factory}.t.sol"

# id: (task, file, old, new, --match-path glob)
MUTANTS = {}


def m(mid, task, path, old, new, match):
    MUTANTS[mid] = (task, path, old, new, match)


# ---- T67: the index (factory index spec §7)
m("m-i1-owner-push-dropped", "t67", OF, "        if (ownerUA != 0) _byOwner[ownerUA][contractClass].push(c);\n", "", IDX)
m("m-i2-creator-push-txorigin", "t67", OF, "        _byCreator[creatorId][contractClass].push(c);",
  "        _byCreator[bytes32(uint256(uint160(tx.origin)))][contractClass].push(c);", IDX)
m("m-i3-owner-read-before-init", "t67", OF,
  "        IFactoryToken(token).initialize(creatorId, version, initArgs);\n        _requireChainUid(token, chainUid);\n"
  "        IGovernance t = IGovernance(token);\n        bytes32 owner = t.owner();",
  "        IGovernance t = IGovernance(token);\n        bytes32 owner = t.owner();\n"
  "        IFactoryToken(token).initialize(creatorId, version, initArgs);\n        _requireChainUid(token, chainUid);", IDX)
m("m-i4-class-swapped", "t67", OF, "        _index(token, creatorId, owner, CLASS_TOKEN, uint16(kind), version);",
  "        _index(token, creatorId, owner, CLASS_DEX, uint16(kind), version);", IDX)
m("m-i5a-from-off-by-one", "t67", OF, "        for (uint256 i; i < m; ++i) page[i] = _created(l[from + i]);",
  "        for (uint256 i; i < m; ++i) page[i] = _created(l[from + i + (m > 1 ? 1 : 0)]);", IDX)
m("m-i5b-n-off-by-one", "t67", OF, "        if (m > n) m = n;", "        if (m > n + 1) m = n + 1;", IDX)
m("m-i6-zero-owner-skip-removed", "t67", OF, "        if (ownerUA != 0) _byOwner[ownerUA][contractClass].push(c);",
  "        _byOwner[ownerUA][contractClass].push(c);", IDX)
m("m-i7-record-before-salt-check", "t67", OF, "        address predicted = Create3.instanceOf(proxy);\n",
  "        address predicted = Create3.instanceOf(proxy);\n        _rec[predicted].contractClass = contractClass;\n", IDX)
m("m-i8-creatorOf-dex-nonzero", "t67", OF,
  "        return r.contractClass == CLASS_TOKEN && uint256(c) >> 160 == 0 ? address(uint160(uint256(c))) : address(0);",
  "        return uint256(c) >> 160 == 0 ? address(uint160(uint256(c))) : address(0);", IDX)

# ---- T71: the factory (chain-neutral spec §8 mutants, factory side)
m("m-c1-instance-not-created-dropped", "t71", OF, "        if (c == address(0)) revert InstanceNotCreated();\n", "", CNF)
m("m-c2-proxy-check-dropped", "t71", OF, "        if (proxy.code.length != 0 || _rec[predicted].contractClass != 0",
  "        if (_rec[predicted].contractClass != 0", CNF)
m("m-c3-configure-not-registrar-only", "t71", OF,
  "    function configureChain(bytes32 chainUid_, uint64 noticePeriod_, address govRouter_, uint256 refBlock, bytes32 refHash)\n"
  "        external onlyRegistrar\n",
  "    function configureChain(bytes32 chainUid_, uint64 noticePeriod_, address govRouter_, uint256 refBlock, bytes32 refHash)\n"
  "        external\n", CNF)
m("m-c4-configure-twice", "t71", OF, "        if (chainUid != bytes32(0)) revert ChainAlreadyConfigured();\n", "", CNF)
m("m-c5-reference-unchecked", "t71", OF, "        if (refBlock != 0) {", "        if (false) {", CNF)
m("m-c6-genesis-inverted", "t71", OF, "        if (g != bytes32(0) && g != chainUid_) revert ChainUidNotGenesis(chainUid_, g);",
  "        if (g != bytes32(0) && g == chainUid_) revert ChainUidNotGenesis(chainUid_, g);", CNF)
m("m-c7-history-revert-is-failure", "t71", OF, "        if (ok && r.length == 32) h = abi.decode(r, (bytes32));",
  "        if (!ok) revert ChainNotConfigured();\n        if (r.length == 32) h = abi.decode(r, (bytes32));", CNF)
m("m-c8-s-without-creator", "t71", OF, "        return keccak256(abi.encode(creatorId, contractClass, kind, salt));",
  "        return keccak256(abi.encode(bytes32(0), contractClass, kind, salt));", CNF)
m("m-c9-s-without-kind", "t71", OF, "        return keccak256(abi.encode(creatorId, contractClass, kind, salt));",
  "        return keccak256(abi.encode(creatorId, contractClass, uint16(0), salt));", CNF)
m("m-c10-s-with-implementation", "t71", OF, "        bytes32 s = _s(creatorId, contractClass, kind, salt);",
  "        bytes32 s = keccak256(abi.encode(_s(creatorId, contractClass, kind, salt), impl));", CNF)
m("m-c11-proxy-initcode-byte", "t71", C3, '    bytes internal constant PROXY_INITCODE = hex"67363d3d37363d34f03d5260086018f3";',
  '    bytes internal constant PROXY_INITCODE = hex"67363d3d37363d34f03d5260086018f2";', CNF)
m("m-c12-predict-off-formula", "t71", OF, "        return Create3.addressOf(address(this), _s(creatorId, contractClass, kind, salt));",
  "        return Create3.addressOf(address(this), _s(creatorId, contractClass, kind, ~salt));", CNF)
m("m-c13-creator-txorigin", "t71", OF, "msg.sender != r) return bytes32(uint256(uint160(msg.sender)));",
  "msg.sender != r) return bytes32(uint256(uint160(tx.origin)));", CNF)
m("m-c14-validateEnv-skipped", "t71", OF, "        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);\n"
  "        _validateEnv(implementation, env);",
  "        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);",
  FAC)
m("m-c15-publish-registry-unchecked", "t71", OF,
  "        if (env.registry != address(0)) _requireChainUid(env.registry, chainUid);\n", "", FAC)
m("m-c16-env-encodes-registrar-uid", "t71", OF,
  "        return IFactoryToken.ChainEnv(chainUid, e.registry, govRouter, e.smartKeyAccountImpl, e.hedera, e.deps, e.params);",
  "        return IFactoryToken.ChainEnv(bytes32(uint256(uint160(registrar))), e.registry, govRouter, e.smartKeyAccountImpl,"
  " e.hedera, e.deps, e.params);", CNF)
m("m-c17-postcheck-dropped", "t71", OF,
  "        IFactoryToken(token).initialize(creatorId, version, initArgs);\n        _requireChainUid(token, chainUid);\n",
  "        IFactoryToken(token).initialize(creatorId, version, initArgs);\n", FAC)
m("m-c18-deps-unbounded-publish", "t71", OF,
  "        if (env.libs.length != env.libCodeHashes.length || env.deps.length > ChainEnvCode.MAX_DEPS\n",
  "        if (env.libs.length != env.libCodeHashes.length\n", FAC)

# ---- T72: the kinds (chain-neutral spec §8 mutants, kind side)
m("m-k1-chainuid-zero-not-reverted", "t72", SE, "        if (u == bytes32(0)) revert ChainUidZero();\n    }\n\n    /// @dev The separator under",
  "    }\n\n    /// @dev The separator under", CNK)
m("m-k2-reader-without-clone-check", "t72", CE,
  "            if and(eq(shr(176, mload(m)), 0x363d3d373d3d3d363d73),\n"
  "                eq(shr(136, mload(add(m, 30))), 0x5af43d82803e903d91602b57fd5bf3)) {\n                mstore(h, mload(add(m, 45)))",
  "            if 1 {\n                mstore(h, mload(add(m, 45)))", CNK)
m("m-k3-initialize-without-env-check", "t72", MTB, "        ChainEnvCode.requirePresent();\n        TokenStore.TokenStorage storage t",
  "        TokenStore.TokenStorage storage t", CNK)
m("m-k4-initialize-without-factory-check", "t72", MTB,
  "        if (msg.sender != FACTORY) revert NotFactory();\n        ChainEnvCode.requirePresent();",
  "        ChainEnvCode.requirePresent();", CNK)
m("m-k5-initialize-without-lock", "t72", MTB, "        if (t.initialized) revert AlreadyInitialized();\n        t.initialized = true;\n        if (uint256",
  "        t.initialized = true;\n        if (uint256", CNK)
m("m-k6-reader-offset", "t72", CE, "                mstore(h, mload(add(m, 45)))", "                mstore(h, mload(add(m, 46)))", CNK)
m("m-k7-deps-count-unbounded", "t72", CE, "        if (nd > MAX_DEPS || np > MAX_PARAMS ||", "        if (np > MAX_PARAMS ||", CNK)
m("m-k8-domain-salt-differs", "t72", MTB, "        return _eip712DomainUnder(_chainUid());",
  "        return _eip712DomainUnder(keccak256(abi.encode(_chainUid())));", CNK)


# ---- T70: the generic catalogue (factory index spec §8.9)
GOV = "test/governance/GovRouterCreate.t.sol"  # imports GovRouter.t.sol: kept by skips()
CN = "test/v2/ChainNeutral.t.sol"
RL = "test/governance/ReleaseList.t.sol"
DB = "script/DeployBase.sol"
m("m-g1-reserved-class-open", "t70", OF, "        if (contractClass <= CLASS_DEX) revert ClassReserved(contractClass);\n", "", GEN)
m("m-g2-selector-unchecked", "t70", OF, "        if (got != sel || initCall.length < 4) revert InitSelectorMismatch(sel, got);\n", "", GEN)
m("m-g3-release-info-unchecked", "t70", OF,
  "            || fi.version != id.version || fi.ownerUA != bytes32(0) || !fi.initialized) revert ReleaseInfoMismatch(impl);",
  "            || fi.version != id.version) revert ReleaseInfoMismatch(impl);", GEN)
m("m-g4-interface-unchecked", "t70", OF, "        if (!_supports(impl, interfaceId)) revert InterfaceNotSupported(impl, interfaceId);\n", "", GEN)
m("m-g5-all-interfaces-accepted", "t70", OF, "        if (_supports(impl, 0xffffffff)) revert InterfaceNotSupported(impl, 0xffffffff);\n", "", GEN)
m("m-g6-creating-not-restored", "t70", OF, "            tstore(_CREATING, prev)\n", "", GEN)
m("m-g7-instance-info-unchecked", "t70", OF,
  "            || fi.kind != id.kind || fi.version != id.version) revert InstanceInfoMismatch(instance);",
  "            || fi.kind != id.kind) revert InstanceInfoMismatch(instance);", GEN)
m("m-g8-instance-chain-unchecked", "t70", OF, "        if (fi.chainUid != chainUid) revert ChainUidMismatch(chainUid, fi.chainUid);\n        _index(instance",
  "        _index(instance", GEN)
m("m-g9-disabled-kind-open", "t70", OF, "        if (!_classKindOn[d]) revert ClassKindDisabled(id.contractClass, id.kind);\n", "", GEN)
m("m-g10-deprecated-usable", "t70", OF, "        if (r.deprecated) revert ReleaseIsDeprecated(id.contractClass, id.kind, id.version);\n", "", GEN)
m("m-g11-class-listed-twice", "t70", OF, "        if (_kinds[id.contractClass].length == 0) _classes.push(id.contractClass);",
  "        _classes.push(id.contractClass);", GEN)

m("m-g12-class-compared-with-kind", "t70", OF,
  "        if (!got || !fi.initialized || fi.factory != address(this) || fi.contractClass != id.contractClass\n",
  "        if (!got || !fi.initialized || fi.factory != address(this) || fi.contractClass != id.kind\n", GEN)
m("m-g13-initialized-unchecked-after-init", "t70", OF,
  "        if (!got || !fi.initialized || fi.factory != address(this) || fi.contractClass != id.contractClass\n",
  "        if (!got || fi.factory != address(this) || fi.contractClass != id.contractClass\n", GEN)
m("m-g14-usableFrom-unchecked", "t70", OF,
  "        if (block.timestamp < r.usableFrom) revert ReleaseNotYetUsable(id.contractClass, id.kind, id.version, r.usableFrom);\n",
  "", GEN)
m("m-g15-reserved-accepts-2", "t70", OF, "        if (contractClass <= CLASS_DEX) revert ClassReserved(contractClass);",
  "        if (contractClass < CLASS_DEX) revert ClassReserved(contractClass);", GEN)
m("m-g16-info-length-relaxed", "t70", OF, "        ok = ok && ret.length == 224;", "        ok = ok && ret.length >= 192;", GEN)
m("m-g17-post-init-check-dropped", "t70", OF,
  "        (bool got, FactoryInfo memory fi) = _factoryInfo(instance);\n        if (!got",
  "        (bool got, FactoryInfo memory fi) = _factoryInfo(instance);\n        fi.chainUid = chainUid;\n"
  "        (got, fi.initialized, fi.factory) = (true, true, address(this));\n"
  "        (fi.contractClass, fi.kind, fi.version) = (id.contractClass, id.kind, id.version);\n        if (!got", GEN)

# ---- T73: the release list (chain-neutral spec §6.2)
m("m-r1-codehash-unchecked", "t73", DB,
  '''        require(vm.parseJsonBytes32(file, string.concat(p, ".codeHash")) == at.codehash,
            string.concat("release list: ", name, " with another code hash"));
''', "", RL)
m("m-r2-address-unchecked", "t73", DB,
  '''        require(vm.parseJsonAddress(file, string.concat(p, ".address")) == at,
            string.concat("release list: ", name, " at another address"));
''', "", RL)

# ---- T74: the two chains (chain-neutral spec §8)
m("m-t1-env-without-chainuid", "t74", OF,
  "        return IFactoryToken.ChainEnv(chainUid, e.registry, govRouter, e.smartKeyAccountImpl, e.hedera, e.deps, e.params);",
  "        return IFactoryToken.ChainEnv(keccak256(\"one chain\"), e.registry, govRouter, e.smartKeyAccountImpl, e.hedera,"
  " e.deps, e.params);", CN)

# ---- T76: the router path (S3)
m("m-s1-subject-from-any-caller", "t76", OF, "        if (r == address(0) || msg.sender != r) return bytes32(uint256(uint160(msg.sender)));\n"
  "        c = IGovernanceRouter(r).subject();",
  "        if (r == address(0)) return bytes32(uint256(uint160(msg.sender)));\n"
  "        (bool ok, bytes memory ret) = msg.sender.staticcall(abi.encodeWithSignature(\"subject()\"));\n"
  "        if (ok && ret.length == 32) return abi.decode(ret, (bytes32));\n        c = IGovernanceRouter(r).subject();", GOV)
m("m-s2-subject-zero-accepted", "t76", OF, "        if (c == bytes32(0)) revert RouterSubjectZero();\n", "", GOV)
m("m-s3-router-ignored", "t76", OF, "        if (r == address(0) || msg.sender != r) return bytes32(uint256(uint160(msg.sender)));",
  "        return bytes32(uint256(uint160(msg.sender)));", GOV)


def test_dir(match):
    """The directory a `--match-path` glob names: before its `{` (one directory's files), else the file's directory."""
    return match.split("{")[0].rstrip("/") if "{" in match else os.path.dirname(match)


def skips(match):
    """`--skip` filters for every other test file of the match's directory and every script: only the named suites (and
    their imports) compile, so a mutant's build fits capped's 4 GB and takes minutes, not the directory."""
    d = test_dir(match)
    names = match.split("{")[1].split("}")[0].split(",") if "{" in match else [os.path.basename(match)[:-len(".t.sol")]]
    keep = {f"{n}.t.sol" for n in names}
    # a kept suite's imports of other test files stay in the build (GovRouterCreate's fixture is GovRouter.t.sol)
    for n in list(keep):
        src = open(os.path.join(EVM, d, n)).read()
        keep |= set(re.findall(r'import \{[^}]*\} from "\./(\w+\.t\.sol)"', src))
    out = ["--skip", ".s.sol"]
    for root, _, files in os.walk(os.path.join(EVM, d)):
        rel = os.path.relpath(root, EVM)
        for f in sorted(files):
            if f.endswith(".t.sol") and not (rel == d and f in keep):
                out += ["--skip", f"/{rel}/{f}"]
    return out


def red_tests(log):
    # a reason may hold brackets ("[1.8e9]"): the test name is the last "] name(...) (gas|runs" of the line
    forge = re.findall(r"^\[FAIL.*\] (\w+)\([^)]*\) \((?:gas|runs)", log, re.M)
    return sorted(set(forge))


def run(mid):
    task, path, old, new, match = MUTANTS[mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(EVM, "runs", f"{DATE}-ua-mtx-merge-t68-mut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        with open(logp, "w") as log:
            # the match's own directory only: a whole-project build does not fit capped's 4 GB
            env = {**os.environ, "FOUNDRY_OUT": "out/mutants", "FOUNDRY_CACHE_PATH": "cache/mutants",
                   "FOUNDRY_TEST": test_dir(match)}
            rc = subprocess.call([CAPPED, FORGE, "test", "--match-path", match, *skips(match)], cwd=EVM, env=env,
                                 stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=EVM) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none")
    line = f"{mid} | {note} | {rc}"
    print(line)
    with open(os.path.join(EVM, "runs", f"{DATE}-ua-mtx-merge-t68-mutants.txt"), "a") as f:
        f.write(line + "\n")
    return rc


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "list":
        for k, v in MUTANTS.items():
            print(v[0], k)
    elif sys.argv[1] == "reparse":
        # the table again from the per-mutant logs (the parser fixed after a run)
        out = []
        for mid in MUTANTS:
            logp = os.path.join(EVM, "runs", f"{DATE}-ua-mtx-merge-t68-mut-{mid}.log")
            if not os.path.exists(logp):
                continue
            log = open(logp).read()
            red = red_tests(log)
            failed = "Suite result: FAILED" in log or "failing test" in log
            note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in log else "none")
            out.append(f"{mid} | {note} | {1 if failed or 'Compiler run failed' in log else 0}")
        open(os.path.join(EVM, "runs", f"{DATE}-ua-mtx-merge-t68-mutants.txt"), "w").write("\n".join(out) + "\n")
        print("\n".join(out))
    elif sys.argv[1] == "run":
        for mid in sys.argv[2:]:
            run(mid)
