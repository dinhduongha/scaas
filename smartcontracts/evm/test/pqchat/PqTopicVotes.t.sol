// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqTopicsBase} from "./PqTopicsBase.sol";

/// Plan 3c T89 (PT3): votes, the test 5 of the topics spec §8 (D21, P40).
contract PqTopicVotesTest is PqTopicsBase {
    bytes32 internal t;
    bytes32 internal e;

    function setUp() public override {
        super.setUp();
        t = _newTopic(true);
        e = _post(chat, t, ids[0], 1, 0);
    }

    function _score() internal view returns (uint128 up, uint128 down) {
        return chat.scoreOf(e);
    }

    function test_votes_oneUaCountsOnce() public {
        _vote(chat, e, ids[1], 1, 1);
        (uint128 up, uint128 down) = _score();
        assertEq(up, 1);
        assertEq(down, 0);
        _vote(chat, e, ids[1], -1, 2); // the same UA changes its vote: one count moves
        (up, down) = _score();
        assertEq(up, 0);
        assertEq(down, 1);
        (int8 v, uint64 seq) = chat.voteOf(e, ids[1]);
        assertEq(v, -1);
        assertEq(seq, 2);
        _vote(chat, e, ids[1], 0, 3); // withdrawn
        (up, down) = _score();
        assertEq(up + down, 0);
        _vote(chat, e, ids[1], 1, 4);
        _vote(chat, e, ids[2], 1, 1); // two UAs count twice
        _vote(chat, e, ids[3], -1, 1);
        (up, down) = _score();
        assertEq(up, 2);
        assertEq(down, 1);
    }

    function test_votes_refusals() public {
        _vote(chat, e, ids[1], 1, 1);
        IPqChat.PqTopicVote memory v = IPqChat.PqTopicVote(e, ids[1], -1, 1);
        IUARegistry.UASig memory sig = _sig(ids[1], h.vote(v));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicSeq.selector, uint64(2), uint64(1)));
        chat.voteEntry(v, sig); // the same seq again
        v = IPqChat.PqTopicVote(e, ids[1], 2, 2);
        sig = _sig(ids[1], h.vote(v));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicVoteValue.selector, int8(2)));
        chat.voteEntry(v, sig);
        v = IPqChat.PqTopicVote(e, ids[1], -2, 2);
        sig = _sig(ids[1], h.vote(v));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicVoteValue.selector, int8(-2)));
        chat.voteEntry(v, sig);
        bytes32 x = keccak256("x");
        v = IPqChat.PqTopicVote(x, ids[1], 1, 1);
        sig = _sig(ids[1], h.vote(v));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicUnknown.selector, x));
        chat.voteEntry(v, sig);
        v = IPqChat.PqTopicVote(e, ids[2], 1, 1);
        sig = _sig(ids[1], h.vote(v)); // nobody votes as another
        vm.expectRevert(_unauthorized(ids[2]));
        chat.voteEntry(v, sig);
        _vote(chat, e, ids[1], -1, 2); // the control
    }

    /// Votes attach to the original id; an edit keeps them.
    function test_votes_stayOnTheOriginal() public {
        _vote(chat, e, ids[1], 1, 1);
        _edit(chat, _editRec(e, ids[0], 2, 2));
        (uint128 up,) = chat.scoreOf(e);
        assertEq(up, 1);
        _vote(chat, e, ids[2], 1, 1);
        (up,) = chat.scoreOf(e);
        assertEq(up, 2);
    }
}
