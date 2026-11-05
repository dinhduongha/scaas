"""`Deployer.linked` returns the transitive link closure, leaf first (metatx-split task 6); `Signed` signs and submits a named entry.
Run: python3 -I smartcontracts/evm/script/pqz/test_e2e_linked.py"""
import importlib.util
import json
import os
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("e2e", os.path.join(HERE, "e2e.py"))
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)


class FakeSession:
    def __init__(self):
        self.n = 0
        self.order = []

    def send(self, to, data, label):
        self.n += 1
        self.order.append(label)
        self.data = data
        return {"contractAddress": "0x" + "%040x" % self.n}


def art(root, name, links):
    """An artifact whose init code is 4 zero bytes per link slot; `links` = [(library, byte offset)]."""
    refs = {}
    for ln, off in links:
        refs.setdefault(f"src/{ln}.sol", {}).setdefault(ln, []).append({"start": off, "length": 20})
    d = os.path.join(root, "out", name + ".sol")
    os.makedirs(d)
    code = "00" * (max([o for _, o in links] + [0]) + 20)
    json.dump({"bytecode": {"object": "0x" + code, "linkReferences": refs}}, open(os.path.join(d, name + ".json"), "w"))


with tempfile.TemporaryDirectory() as root:
    art(root, "HederaLib", [])
    art(root, "MtxPipelineLib", [("HederaLib", 1), ("HederaLib", 30)])
    art(root, "TradeLib", [])
    art(root, "Token", [("MtxPipelineLib", 2), ("TradeLib", 40)])
    e2e.EVM = root
    s = FakeSession()
    D = e2e.Deployer(s)
    code, libs = D.linked("Token")
    hed, mtx, trd = D.libs["HederaLib"], D.libs["MtxPipelineLib"], D.libs["TradeLib"]
    assert libs == [hed, mtx, trd], libs  # both libraries of the closure, HederaLib before MtxPipelineLib
    assert s.order == ["library HederaLib", "library MtxPipelineLib", "library TradeLib"], s.order
    assert code[2:22] == bytes.fromhex(mtx[2:]) and code[40:60] == bytes.fromhex(trd[2:])
    # a second release shares the deployed libraries and still lists the whole closure
    art(root, "Token2", [("MtxPipelineLib", 0)])
    assert D.linked("Token2")[1] == [hed, mtx]
    assert s.n == 3, "no library deployed twice"
    # constructor arguments on linked code (UARegistry + UARegistryLib): the library first, its address in the init code
    art(root, "RegLib", [])
    art(root, "Reg", [("RegLib", 1)])
    D.deploy("Reg", b"\xaa")
    assert s.order[-2:] == ["library RegLib", "deploy Reg"], s.order
    assert s.data == bytes(1) + bytes.fromhex(D.libs["RegLib"][2:]) + bytes(0) + b"\xaa", s.data


# `Signed`: what is signed is the digest of the entry's own struct; the relayer submits `named_cd`. ua-mtx-merge T10, meaning:
# an EOA signs the merged entry's UA struct (`from` its address zero-padded) with its own key in `UASig.signature`, as a UA
# does (R1, B); `mtxShield` takes a `UASig` (R47); only `WrapShield` (no twin) keeps the address `Envelope` and `bytes sig`
class Echo:  # the "signature" is the message, so the test reads what was signed
    def ml_sign(self, lvl, seed, m):
        return m


class Relayer:
    def send(self, to, data, what):
        self.sent = data


class Eoa:
    key, addr = 1, e2e.address(1)


word = bytes(31) + b"\x05"
e2e.call = lambda to, data: "0x" + word.hex()
e2e.CTX[:] = [31337, bytes(32)]
TOK, R, PQ = "0x" + "ab" * 20, Relayer(), Echo()
A = bytes(31) + b"\xaa"
at = (TOK, 31337, bytes(32))
sg = e2e.Signed(TOK, Eoa, PQ, R, 3)
assert sg.binding == word and sg.e[0] == e2e.pad(Eoa.addr) and sg.e[2] == 5 and sg.e[4] == 0x20 and sg.e[6] == 3, sg.e
sg.send("Shield", [A, 7], "x")
d = e2e.typed_digest("UAShield", at, sg.e, [A, 7])
assert R.sent == e2e.named_cd("UAShield", sg.e, [A, 7], [b"", e2e.ecdsa(1, d), []])
assert R.sent[:4] == e2e.sel(f"mtxShield({e2e.UEVL_S},bytes32,uint256,{e2e.UASIG_S})")
assert e2e.Signed.spent[TOK, e2e.pad(Eoa.addr)] == 3
sg = e2e.Signed(TOK, Eoa, PQ, R, 0)
sg.send("WrapShield", ["0x" + "cd" * 20, 9, A], "x")
e = [Eoa.addr] + sg.e[1:]
assert R.sent == e2e.named_cd("WrapShield", e, ["0x" + "cd" * 20, 9, A],
                              e2e.ecdsa(1, e2e.typed_digest("WrapShield", at, e, ["0x" + "cd" * 20, 9, A])))
assert R.sent[:4] == e2e.sel(f"mtxWrapShield({e2e.EVL_S},address,uint256,bytes32,bytes)")


def ml(purpose, d):
    return e2e.kc(e2e.TAG[e2e.MLDSA65], e2e.ua_msg(e2e.MLDSA65, purpose, d))


m0, m1 = (e2e.UA(kind=e2e.MLDSA65, seed=b"", ua=bytes(31) + bytes([i])) for i in (1, 2))
sg = e2e.Signed(TOK, m0, PQ, R, 0)
assert sg.e[4] == 0, "no fee, no fee mode"
sg.send("RollOver", [A, 1], "x")
d = e2e.typed_digest("UARollOver", at, sg.e, [A, 1])
assert R.sent == e2e.named_cd("UARollOver", sg.e, [A, 1], [b"", ml(e2e.P_METATX, d), []])
sg.send("Shield", [A, 7], "x")  # `mtxShield` takes a `UASig` (R47)
d = e2e.typed_digest("UAShield", at, sg.e, [A, 7])
assert R.sent == e2e.named_cd("UAShield", sg.e, [A, 7], [b"", ml(e2e.P_METATX, d), []])
ms = e2e.UA(kind=e2e.MSIG, ua=bytes(31) + b"\x09", members=[m0, m1])
sg = e2e.Signed(TOK, ms, PQ, R, 0)
sg.send("RollOver", [A, 1], "x")
d = e2e.typed_digest("UARollOver", at, sg.e, [A, 1])
md = e2e.kc(ms.ua, e2e.ua_msg(e2e.MSIG, e2e.P_METATX, d))
assert R.sent == e2e.named_cd("UARollOver", sg.e, [A, 1], [b"", b"", [[0, b"", ml(e2e.P_MEMBER, md)], [1, b"", ml(e2e.P_MEMBER, md)]]])
print("ok")
