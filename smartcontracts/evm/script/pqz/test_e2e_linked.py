"""`Deployer.linked` returns the transitive link closure, leaf first (metatx-split task 6).
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
print("ok")
