// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {Musig2Secp256k1Verifier} from "../../src/ua/verifiers/Musig2Secp256k1Verifier.sol";
import {Musig2Bn254Verifier} from "../../src/ua/verifiers/Musig2Bn254Verifier.sol";
import {FrostSecp256k1Verifier} from "../../src/ua/verifiers/FrostSecp256k1Verifier.sol";
import {FrostBn254Verifier} from "../../src/ua/verifiers/FrostBn254Verifier.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {GroupFixtures} from "./GroupFixtures.sol";
import {UACall} from "./UACall.sol";

/// A MuSig2 or FROST kind is an `msig` member (owner ruling 2026-11-02, spec 2026-11-02-msig-nested): each is one key on chain,
/// `UAKinds._singleSigning` holds 0x0110..0x0113 and `isMember` admits them. Real verifiers.
contract UAMsigGroupMemberTest is UARegistryBase, GroupFixtures {
    uint256 internal constant PK_E = 0xE0A;

    /// Each of the four group kinds registers with its groups.json PoP, is listed as an `msig` member beside an EOA, accepts its slot
    /// and authorizes 2-of-2 by one group signature; a flipped byte fails.
    function test_groupKindIsAnMsigMember() public {
        uint16[4] memory kinds = [MS, FS, MB, FB];
        address[4] memory v = [
            address(new Musig2Secp256k1Verifier()),
            address(new FrostSecp256k1Verifier()),
            address(new Musig2Bn254Verifier()),
            address(new FrostBn254Verifier())
        ];
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](4);
        for (uint256 i; i < 4; ++i) c[i] = UARegistry.KindConfig(kinds[i], v[i], 50_000);
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        for (uint256 i; i < 4; ++i) _member(r, _main(kinds[i]));
    }

    function _member(UARegistry r, Group memory g) internal {
        assertEq(UACall.register(r, g.kind, g.keyData, _none(), g.pop, ""), g.ua);
        Member[] memory m = new Member[](2);
        m[0] = Member(g.kind, g.ua, 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(vm.addr(PK_E)), 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
        assertEq(r.kindOf(ua), UAKinds.MSIG);

        uint16 ig = _indexOf(d, g.ua);
        r.acceptMembership(ua, _slot(g, ig, _membershipMd(ua, g.ua)));
        r.acceptMembership(ua, _acceptEoaSig(d, PK_E));
        assertTrue(r.memberAccepted(ua, ig));

        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](2);
        s[ig] = _slot(g, ig, md);
        s[1 - ig] = IUARegistry.MemberSig(1 - ig, new IUARegistry.InnerSig[](0), _nativeSig(r, PK_E, UAKinds.PURPOSE_MEMBER, md));
        _req(r, ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));

        s[ig].sig = _flip(s[ig].sig, 40);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        _req(r, ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
    }

    /// The group's real signature under `member` over `md`.
    function _slot(Group memory g, uint16 index, bytes32 md) internal returns (IUARegistry.MemberSig memory) {
        return IUARegistry.MemberSig(index, new IUARegistry.InnerSig[](0), _gsign(g.kind, g.secret, g.vk, UAKinds.uaMessage(g.kind, UAKinds.PURPOSE_MEMBER, md)));
    }
}
