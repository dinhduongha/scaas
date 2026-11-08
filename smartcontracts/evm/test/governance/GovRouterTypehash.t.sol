// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GovernanceRouterTypes as T} from "../../src/governance/GovernanceRouterBase.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Every typed struct of `GovernanceRouter` (plan T11; spec `2026-11-04-governance-ua-identity.md` §3, governance spec §3.2):
/// the type string verbatim and its hash as a literal from `cast keccak`. A moved field, name or type is a new struct for
/// every client (T12's `typed_ops.json` rows, the node's rows): this file moves with it, in the same commit.
contract GovRouterTypehashTest is Test {

    function test_grantTermsTypehashIsPinned() public pure {
        assertEq(T.GRANT_TERMS, keccak256(
                "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)"));
        assertEq(T.GRANT_TERMS, 0x628aea4ab321d7b10bba472483a5180aa03cc5109ae8cf02c459ae385781ee65);
    }

    function test_uaGrantRoleTypehashIsPinned() public pure {
        assertEq(T.UA_GRANT_ROLE, keccak256(
                "UAGrantRole(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_GRANT_ROLE, 0x6eb86b2377b08b35d4ba9aea808b9f8291b350ae6aefdaa1c62b291013b79a6d);
    }

    function test_uaRevokeRoleTypehashIsPinned() public pure {
        assertEq(T.UA_REVOKE_ROLE, keccak256(
                "UARevokeRole(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_REVOKE_ROLE, 0x2485b5c9b89864d24866c5f8cd84f9b306e3d837034f8d8232e51f31518594e0);
    }

    function test_uaSetGrantTypehashIsPinned() public pure {
        assertEq(T.UA_SET_GRANT, keccak256(
                "UASetGrant(bytes32 from,address target,uint8 bit,bytes32 holder,GrantTerms terms,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
                "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)"));
        assertEq(T.UA_SET_GRANT, 0xc98bbb9ea43c430a7dbc43f74b8a5454c65373047ee3b5f0c727407d69a89fcf);
    }

    function test_uaCancelGrantTypehashIsPinned() public pure {
        assertEq(T.UA_CANCEL_GRANT, keccak256(
                "UACancelGrant(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_CANCEL_GRANT, 0x739f1688b6c65ab49c43063518ad450a1f15587a4ae1d9346f616483b2a71ea9);
    }

    function test_uaDisableFeatureTypehashIsPinned() public pure {
        assertEq(T.UA_DISABLE_FEATURE, keccak256(
                "UADisableFeature(bytes32 from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_DISABLE_FEATURE, 0x245ae38b9763de03075abd2d8b1f0e14d547af425936778038cc4d0d059f0394);
    }

    function test_uaTransferOwnershipTypehashIsPinned() public pure {
        assertEq(T.UA_TRANSFER_OWNERSHIP, keccak256(
                "UATransferOwnership(bytes32 from,address target,bytes32 newOwner,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_TRANSFER_OWNERSHIP, 0xa468e58d6110336b12945530c88e879bc757390554493d6c405eb996e9f34b19);
    }

    function test_uaAcceptOwnershipTypehashIsPinned() public pure {
        assertEq(T.UA_ACCEPT_OWNERSHIP, keccak256(
                "UAAcceptOwnership(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_ACCEPT_OWNERSHIP, 0x2ce67927cc2f2144e5b45b15e37e55814a22d43808f8ee507784924ed777243d);
    }

    function test_uaRenounceOwnershipTypehashIsPinned() public pure {
        assertEq(T.UA_RENOUNCE_OWNERSHIP, keccak256(
                "UARenounceOwnership(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_RENOUNCE_OWNERSHIP, 0x0397c70ed0d09c398e5f2d00425b822788d86a35a074bf84e9438818da053445);
    }

    function test_uaRenounceRoleTypehashIsPinned() public pure {
        assertEq(T.UA_RENOUNCE_ROLE, keccak256(
                "UARenounceRole(bytes32 from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_RENOUNCE_ROLE, 0x1a32125783655840c2b0717e59159708af35ca4638bf313676e325dd5029c3e1);
    }

    function test_uaMintTypehashIsPinned() public pure {
        assertEq(T.UA_MINT, keccak256(
                "UAMint(bytes32 from,address target,address to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_MINT, 0xc4e90edd003399ea85dd8419c3cf0e918f3b20d8cbcf13d8e3ae47dc33af5fe9);
    }

    function test_uaMintToUATypehashIsPinned() public pure {
        assertEq(T.UA_MINT_TO_UA, keccak256(
                "UAMintToUA(bytes32 from,address target,bytes32 to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_MINT_TO_UA, 0x3f15ea1661a843b380990b511dd9bdd73527754fbae7d392545286c6e9a1ec59);
    }

    function test_uaDisableWrapTypehashIsPinned() public pure {
        assertEq(T.UA_DISABLE_WRAP, keccak256(
                "UADisableWrap(bytes32 from,address target,address leg,bytes32 reason,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_DISABLE_WRAP, 0x605b248d1b84f07924e8c06b5d9494a653fd360b0650096d018fa057f8f3fd70);
    }

    function test_uaProposeRateTypehashIsPinned() public pure {
        assertEq(T.UA_PROPOSE_RATE, keccak256(
                "UAProposeRate(bytes32 from,address target,address leg,uint96 num,uint96 den,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_PROPOSE_RATE, 0x6fa5ee4883f1b444b81cf4ee7267e5cfd0cdbb6d33b5292714aaa419c2d0d45a);
    }

    function test_uaCancelRateTypehashIsPinned() public pure {
        assertEq(T.UA_CANCEL_RATE, keccak256(
                "UACancelRate(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_CANCEL_RATE, 0x563e79a9b01c20db3955058e27b3f8a8d67d86c200c852f4d711056e68e64d96);
    }

    function test_uaExecuteRateTypehashIsPinned() public pure {
        assertEq(T.UA_EXECUTE_RATE, keccak256(
                "UAExecuteRate(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_EXECUTE_RATE, 0xd1c67b623f98fe4629d466c3c52ec4f095ff5efc028dc94fc1e5ebf9bb44e4b6);
    }

    function test_uaSetMarketTypehashIsPinned() public pure {
        assertEq(T.UA_SET_MARKET, keccak256(
                "UASetMarket(bytes32 from,address target,address base,address quote,bool listed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_SET_MARKET, 0x18f8aca93f48321be5b95fe425feb92e2fca25868e6f55dcfc34caa60f49ce59);
    }

    function test_uaSetExchangeTargetTypehashIsPinned() public pure {
        assertEq(T.UA_SET_EXCHANGE_TARGET, keccak256(
                "UASetExchangeTarget(bytes32 from,address target,address exchangeTarget,bool listed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_SET_EXCHANGE_TARGET, 0x502716f005e21f4f3a33cde1a9847201283c24b803d751fceabcd1b8c07b20af);
    }

    function test_uaSetListedOnlyTypehashIsPinned() public pure {
        assertEq(T.UA_SET_LISTED_ONLY, keccak256(
                "UASetListedOnly(bytes32 from,address target,bool on,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_SET_LISTED_ONLY, 0x3abe22525c2ee61aeb0d36c03336dbcf35638f73729a5f572d55d335d81044e6);
    }

    function test_uaSetFeeSplitTypehashIsPinned() public pure {
        assertEq(T.UA_SET_FEE_SPLIT, keccak256(
                "UASetFeeSplit(bytes32 from,address target,uint32 relayerSharePpm,address treasury,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_SET_FEE_SPLIT, 0x6b852244442b250d05068e09239a3187da2ac9c9c3d2b8bfc89f77de52466649);
    }

    // ---- plan T76 (chain-neutral spec §4.4, S3; owner 2026-11-07): the factory's creations, the signing UA the creator

    function test_uaCreateTokenTypehashIsPinned() public pure {
        assertEq(T.UA_CREATE_TOKEN, keccak256(
                "UACreateToken(bytes32 from,address target,uint8 kind,uint64 version,bytes32 initHash,bytes32 salt,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_CREATE_TOKEN, 0xca5fac97c5abc5819d18898d601178a55e746af3b2cda3a218b9a983346cb67b);
    }

    function test_uaCreateDexTypehashIsPinned() public pure {
        assertEq(T.UA_CREATE_DEX, keccak256(
                "UACreateDex(bytes32 from,address target,uint64 version,bytes32 initHash,bytes32 salt,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_CREATE_DEX, 0x44661a0581e2cf084c0fcdefcdad74bcd019e428202ed1d2bf13ffc377cd2a51);
    }

    function test_uaCreateInstanceTypehashIsPinned() public pure {
        assertEq(T.UA_CREATE_INSTANCE, keccak256(
                "UACreateInstance(bytes32 from,address target,uint16 contractClass,uint16 kind,uint64 version,bytes32 initHash,bytes32 salt,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_CREATE_INSTANCE, 0xbe31ccf5dc917e095cb52e23ebce86c15150159b8b9f145eef2a2c94573b8ba1);
    }

    // ---- plan T32 (regulated-kinds spec §3.1; owner 2026-11-05, CTR-GOV-20): the eight controls of the regulated kinds

    function test_uaFreezeTypehashIsPinned() public pure {
        assertEq(T.UA_FREEZE, keccak256(
                "UAFreeze(bytes32 from,address target,bytes32 account,bytes32 ref,bytes32 recordId,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_FREEZE, 0xf5fc2a4678771231313015bbd08dc97a79091035881d6266350b0776d6a2984a);
    }

    function test_uaUnfreezeTypehashIsPinned() public pure {
        assertEq(T.UA_UNFREEZE, keccak256(
                "UAUnfreeze(bytes32 from,address target,bytes32 account,bytes32 ref,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_UNFREEZE, 0x20a16034799ae1e37ea7af0e3bc3e983f2ecd30a20c2b6c9234b8fa705fbb9a9);
    }

    function test_uaForceTransferTypehashIsPinned() public pure {
        assertEq(T.UA_FORCE_TRANSFER, keccak256(
                "UAForceTransfer(bytes32 from,address target,bytes32 recordId,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_FORCE_TRANSFER, 0x29f5036246375be4eb17b4e995b326935a99cc74c4f0cec933eb9aca28cec4e3);
    }

    /// pay-meta-tax T39 (spec §6.2): the two router ops of bit 23 `TAX`.
    function test_uaSetTaxRateTypehashIsPinned() public pure {
        assertEq(T.UA_SET_TAX_RATE, keccak256(
                "UASetTaxRate(bytes32 from,address target,uint32 ratePpm,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_SET_TAX_RATE, 0x75a25977ad049952fa3befd753aa1c9dbc3a38461944061e37d2652fdc6d123f);
    }

    function test_uaSetTaxRecipientTypehashIsPinned() public pure {
        assertEq(T.UA_SET_TAX_RECIPIENT, keccak256(
                "UASetTaxRecipient(bytes32 from,address target,bytes32 taxRecipient,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_SET_TAX_RECIPIENT, 0x35a73542fb90c355f539cf8ebee2a653d5a10216b659fc5304d32671e634750f);
    }

    /// Group 3f (PQZ verifier mode spec §4.2): the PQZ verifier UA's three owner ops.
    function test_uaPqzSetVerifierTypehashIsPinned() public pure {
        assertEq(T.UA_PQZ_SET_VERIFIER, keccak256(
                "UAPqzSetVerifier(bytes32 from,address target,bytes32 next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_PQZ_SET_VERIFIER, 0xc7b836ae14938e0da524ac8a888c602948164c3e01c450a2d4a60d8b257a2aee);
    }

    function test_uaPqzCancelVerifierTypehashIsPinned() public pure {
        assertEq(T.UA_PQZ_CANCEL_VERIFIER, keccak256(
                "UAPqzCancelVerifier(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_PQZ_CANCEL_VERIFIER, 0x7f04a47d44fd0fc31c5bea71922bca3fdee4f3c7dbf0460b73526499ed942911);
    }

    function test_uaPqzRevokeVerifierTypehashIsPinned() public pure {
        assertEq(T.UA_PQZ_REVOKE_VERIFIER, keccak256(
                "UAPqzRevokeVerifier(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_PQZ_REVOKE_VERIFIER, 0xb395011f54af6f642333ddf8e664418b27c5ddeea94d7750852501c6d640a6d6);
    }

    function test_uaPauseTypehashIsPinned() public pure {
        assertEq(T.UA_PAUSE, keccak256(
                "UAPause(bytes32 from,address target,bytes32 ref,uint64 until,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_PAUSE, 0x7012cbf0bda862fc56133a096ecd7b9f807ea2ed26917f3f10cdf41c0ecb7282);
    }

    function test_uaUnpauseTypehashIsPinned() public pure {
        assertEq(T.UA_UNPAUSE, keccak256(
                "UAUnpause(bytes32 from,address target,bytes32 ref,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_UNPAUSE, 0xa0e6b7b2c0d59ae1f15155df7ad7a30795fdca2d126d90a823d9567f9485640b);
    }

    function test_uaRecordOrderTypehashIsPinned() public pure {
        assertEq(T.UA_RECORD_ORDER, keccak256(
                "UARecordOrder(bytes32 from,address target,bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_RECORD_ORDER, 0x9557599df6a72c81048fc69876b562d875d344af32ee60b25a6a5e6d54e8d988);
    }

    function test_uaRevokeOrderTypehashIsPinned() public pure {
        assertEq(T.UA_REVOKE_ORDER, keccak256(
                "UARevokeOrder(bytes32 from,address target,bytes32 recordId,bytes32 reasonRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_REVOKE_ORDER, 0xb5794e916523312dcd4225c8024c11f9fa4eb9e8e6c3bd525720e709e5a3f976);
    }

    function test_uaOperatorTransferTypehashIsPinned() public pure {
        assertEq(T.UA_OPERATOR_TRANSFER, keccak256(
                "UAOperatorTransfer(bytes32 from,address target,bytes32 account,bytes32 to,uint256 amount,bytes32 ref,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(T.UA_OPERATOR_TRANSFER, 0xc6020647b60fc768241df1c03875c3f208172161422171416b21769872766fc9);
    }

    /// ua-mtx-merge T7 (R14): the 19 address `<Op>` structs left the router with their `mtx<Op>(Envelope, …, bytes)` entries
    /// (legacy/ua-mtx-merge/src/governance/); their hashes stay pinned here, as the legacy pin of a retired form: a client
    /// or node row signing one of them signs for no entry.
    function test_addressTypehashesAreLegacyPins() public pure {
        assertEq(keccak256(
            "GrantRole(address from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0xc020ece8881aa6593e78051c8002d12f411a04f644605b41cb388ad4f1e416ad);
        assertEq(keccak256(
            "RevokeRole(address from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x24daf76ae7c6caeac2985953792a40624be47d6c9fba9ab32e4fc518f71f6b98);
        assertEq(keccak256(
            "SetGrant(address from,address target,uint8 bit,bytes32 holder,GrantTerms terms,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
            "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)"), 0xf9b226816dba06662d203722f92458d26e4c1c43540bcf42810de990d23c2cf5);
        assertEq(keccak256(
            "CancelGrant(address from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0xc3b40088b748292ac99b4999ab76a6d37f80fb0c29782c9a6af186587a52c290);
        assertEq(keccak256(
            "DisableFeature(address from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x5821a32f1cd910fc1871a12d59513076373fa448de066efbc541563a30662f9c);
        assertEq(keccak256(
            "TransferOwnership(address from,address target,bytes32 newOwner,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x1361dafaf43050b224b3ada3741d745738510e25fce518baaf58e814356355db);
        assertEq(keccak256(
            "AcceptOwnership(address from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0xddf5e14fa95885aa5b2b349884178f4481a846fd338874f66da24ab140e85f1f);
        assertEq(keccak256(
            "RenounceOwnership(address from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x3eb1d32464a660805339ca6d4ab141bf40e53993b4619944676a02b47b6b536b);
        assertEq(keccak256(
            "RenounceRole(address from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0xda7d9643907942376d4d95dbf4d76a50b58c2a5dd82654e734509cdf383f6f4b);
        assertEq(keccak256(
            "Mint(address from,address target,address to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x7a5945e95d33b95d1257af80b7d2924cc792d6d22dd819b3fea4ae1134f2d15b);
        assertEq(keccak256(
            "MintToUA(address from,address target,bytes32 to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0xee30565364a42bfa0327fd54c9b642154282dffaebd3bc4eed1be95c4316a53d);
        assertEq(keccak256(
            "DisableWrap(address from,address target,address leg,bytes32 reason,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x2686cb108195f41936d5ed3f7326ee7a0121e6c034baf587acdf97f6189346bb);
        assertEq(keccak256(
            "ProposeRate(address from,address target,address leg,uint96 num,uint96 den,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0xb399cddf10569d08ede39bbb2837f837db80db8e19780dddfacaf295b89873cf);
        assertEq(keccak256(
            "CancelRate(address from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x11aa6737159ca0ef67ae8d93d606cc88abb77ce60319ed45038db15dd8fc9e71);
        assertEq(keccak256(
            "ExecuteRate(address from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x44b7f69f8138cf1904694b7c68c11d39019a0b63bb6ce1df60bd6d2f330cb98b);
        assertEq(keccak256(
            "SetMarket(address from,address target,address base,address quote,bool listed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x553ad5eb7921d1a0f637bc2cba9e9e04102eab970f0fb4fc6960ad9ad32bf795);
        assertEq(keccak256(
            "SetExchangeTarget(address from,address target,address exchangeTarget,bool listed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x25f2776ca7a93eceb31b72eda284e865134a8de86f3026e882c0034eeb5f61d8);
        assertEq(keccak256(
            "SetListedOnly(address from,address target,bool on,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0x80300994bed71bf5a6041fa3b9546740b64f5fca9341a979b882393f3ef2b139);
        assertEq(keccak256(
            "SetFeeSplit(address from,address target,uint32 relayerSharePpm,address treasury,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), 0xf084d8f72f5ab8472e967cf0f499a1f0885d6c4ef8598e122bc9c5789f5cec6b);
    }

    /// The router's ordered cancel (Q2, R19) signs `MetaTxLib`'s `UACancelNonce`, like a token.
    function test_uaCancelNonceTypehashIsPinned() public pure {
        assertEq(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, keccak256(
                "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"));
        assertEq(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, 0xcd17c2129240241748e841a7f0572558b9c5a900a47bc540170a8c258d291c54);
    }
}
