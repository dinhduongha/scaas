// Test-only target for the relay-fee executor (T16 fix 1): it acknowledges the call like a served SCaaS entry, then,
// unless the call's first 32 bits are 1, fails its action phase (a message it cannot pay for, mode 0). A failed action
// phase sends no message at all, the ack included, and does not bounce. The probe (0x5b0a1d32) is refused.
import "../../contracts/common";

contract ActFail(counter: Int as uint32) {
    receive() {}

    receive(msg: Slice) {
        let op = msg.preloadUint(32);
        throwIf(99, op == 0x5b0a1d32);
        self.counter += 1;
        relayAck(sender(), msg.preloadRef().hash());
        if (op != 1) {
            message(MessageParameters { to: sender(), value: ton("1000"), mode: 0, bounce: false, body: null });
        }
    }

    get fun counter(): Int {
        return self.counter;
    }
}
