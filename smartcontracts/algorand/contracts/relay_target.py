"""Test-only third-party relay target (never deployed; not in artifacts.json; T15 tests and the T20 e2e): records who
called it, so a test sees the target's sender (the executor, never the lane), and fails on demand."""
from algopy import Account, Global, GlobalState, Txn, UInt64, arc4


class RelayTarget(arc4.ARC4Contract):
    def __init__(self) -> None:
        self.calls = GlobalState(UInt64, key="calls")
        self.last = GlobalState(Account, key="last")

    @arc4.abimethod(create="require")
    def create(self) -> None:
        self.calls.value = UInt64(0)
        self.last.value = Global.zero_address

    @arc4.abimethod
    def ping(self, x: arc4.UInt64) -> None:
        self.calls.value += 1
        self.last.value = Txn.sender
        arc4.emit("Pinged", x, arc4.Address(Txn.sender))

    @arc4.abimethod
    def fail(self) -> None:
        assert False, "target failed"

    @arc4.abimethod(allow_actions=["NoOp", "OptIn"])
    def join(self) -> None:
        """Accepts an OptIn too (a target whose OnCompletion is not NoOp, for the rule-13 tests)."""

    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:
        pass
