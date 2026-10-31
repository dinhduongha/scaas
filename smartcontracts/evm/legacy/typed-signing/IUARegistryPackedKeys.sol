// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// legacy/typed-signing: NOT COMPILED. The `register` entry of src/ua/IUARegistry.sol as it stood after typed-signing R1
// and before R1b (TS-D13, Appendix X row 12): it took every single-key kind's packed key data, incl. `webauthn-p256`
// (`x ‖ y ‖ rpIdHash`, 96 B), MuSig2 (`aggKey ‖ u16 n ‖ n × key`) and FROST (`groupKey ‖ u16 t ‖ u16 n ‖ n × (t
// commitments ‖ R_i ‖ z_i)`). R1b moved those kinds to `registerWebAuthn` / `registerMuSig2` / `registerFrost` (typed
// keys, the same assembled bytes and ids); `register` refuses them with `UAKeyData(kind)`. The structs are
// IUARegistry's (`UAAttrs` with `KemKey`).
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

interface IUARegistryPackedKeys {
    /// A single-key kind (every derived kind but `msig`, which is `registerMsig`; `UAKeyData(0x0120)` here). `pop`: the
    /// kind's signature over `uaMessage(kind, PURPOSE_POP_V2, registrationDigest(ua, kind, pqzKeyHash, kemRecordHash,
    /// attrs.pqzPopHash))`. `attrs`: only a holder
    /// (`mldsa44`, `mldsa65`, `fndsa512`, a PQ-eligible `msig`; UA-6 U3, UA8-D12) carries a PQZ key or a KEM record.
    /// `pqzPop`: the `R_REG` proof over `uaMessage(0x0142, PURPOSE_POP_V2, portableRecordDigest(...))`, optional (empty: the
    /// key is stored unproven, `storePqzPop` later; also unproven where the `0x0142` slot is empty, UA8-D8). The attribute
    /// checks (holder, proof hash, PQZ key length, KEM version, KEM key length) come before the PoP (portable.json
    /// `negatives`). Anyone may submit; the same arguments register on every registry.
    function register(uint16 kind, bytes calldata keyData, IUARegistry.UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua);
}
