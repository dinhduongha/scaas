// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// legacy/typed-signing: NOT COMPILED. `mtxExecuteWithFee` as it stood in src/metatx/MetaTokenBase.sol (declared in
// IMetaTokenV2) before typed-signing C2: it duplicated `mtxExecute` behind a shape check (TS-D14, controller call). A signed
// fee runs through `mtxExecute` or the op's named entry. Reference only.

abstract contract MtxExecuteWithFee {
    /// @notice `mtxExecute` that says "this intent pays a fee": fee nibble ≠ `NONE`.
    function mtxExecuteWithFee(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bytes memory)
    {
        if (m.mode & MetaTxLib.MODE_FEE_MASK == 0) revert MtxModeShape(m.mode);
        return _execute(m, signature);
    }
}
