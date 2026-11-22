# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T20d: the Python binding (spec §16.1) over the async API, through official UniFFI's output (generated/).

The generated modules load the library beside them and import each other as a package, so the test copies them with the
reference library (ffi/target/lib-uniffi/, built by ../lib.sh uniffi) into a temporary package. Rows:
smartcontracts/vectors/keystore/keystore.json, each container the Python store's `keystore`: valid rows list their seeds and
every seed opens with the rows' passphrase (its accounts listed); refused rows fail with their named error. Then: a Python
async authenticator's PRF through the copy call (passkey unlock), `next` on the subscription, a panic as Internal, a Python
exception in the store and in the authenticator (Unexpected on the Rust side: the SDK's error, no panic), the load check,
an EVM profile with the profile fields of sdk-complete (the bindings build `evm`).
Secrets go in only by the copy call. Run: python3 -I test_smoke.py (gate `bind-python`).
"""

import asyncio
import atexit
import importlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PKG = Path(tempfile.mkdtemp(prefix="scaas-sdk-py-")) / "scaas_bind"
PKG.mkdir()
atexit.register(shutil.rmtree, PKG.parent, True)
for f in [*(HERE / "generated").glob("*.py"), HERE / "copycall.py"]:
    shutil.copy(f, PKG)
shutil.copy(HERE.parents[1] / "ffi/target/lib-uniffi/libscaas_sdk_ffi.so", PKG)
(PKG / "__init__.py").write_text("")
sys.path.insert(0, str(PKG.parent))
s = importlib.import_module("scaas_bind.scaas_sdk")
ffi = importlib.import_module("scaas_bind.scaas_sdk_ffi")
copy = importlib.import_module("scaas_bind.copycall").CopyCall(PKG / "libscaas_sdk_ffi.so")

REPO = (
    "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival "
    "slice deposit sauce coconut afford frown better"
)
PASS = "river-otter-7 ünï"


def secret(v):
    """A secret holding `v`, by the copy call (its buffer zeroed by it; asserted)."""
    b = bytearray(v.encode())
    x = s.secret_new(len(b))
    copy.write(s.secret_id(x), b)
    assert not any(b), "the copy call zeroes the caller's buffer"
    return x


class MemStore(s.ForeignStore):
    def __init__(self):
        self.items = {}
        self.throws = False

    async def get(self, name, reason):
        if self.throws:
            raise RuntimeError("the app's store threw")
        b = self.items.get(name)
        return None if b is None else s.StoredItem(bytes=b, rev=s.rev_of(b))

    async def put_if(self, name, prev_rev, bytes, policy):
        have = s.rev_of(self.items[name]) if name in self.items else None
        if have != prev_rev:
            raise s.StoreError.Conflict()
        self.items[name] = bytes

    async def delete(self, name):
        self.items.pop(name, None)

    # one caller at a time here: no lock to hold
    async def lock(self, name):
        return 1

    async def unlock(self, token):
        pass


class FakeAuth(s.ForeignAuthenticator):
    """A PRF: 32 bytes from the salt (deterministic, a test stand-in), written by the copy call into `prf_out`'s secret."""

    def __init__(self):
        self.throws = False

    async def create_passkey(self, rp_id, user_name, exclude):
        raise s.AuthError.Unavailable()

    async def get_assertion(self, req, prf_out):
        if self.throws:
            raise RuntimeError("the app's authenticator threw")
        if req.prf_salt is None:
            raise s.AuthError.Refused()
        salt = req.prf_salt
        out = bytearray(salt[i % len(salt)] ^ 0x5A ^ i for i in range(32))
        copy.write(prf_out, out)
        return s.Assertion(
            credential_id=b"\xc1\xed", authenticator_data=bytes(37), client_data_json=b"", signature=bytes(64), prf=True
        )

    async def platform_secret(self, key_handle, salt, reason, policy, out):
        raise s.AuthError.Unavailable()

    async def p256_generate(self, policy):
        raise s.AuthError.Unavailable()

    async def p256_sign(self, key_handle, ua_msg, reason):
        raise s.AuthError.Unavailable()


def config(expect_api=1):
    return s.BindingConfig(
        expect_api=expect_api,
        need_features=s.features(),
        profiles=[],
        rp_id="wallet.example",
        limits=s.limits_default(),
        gas_tables=[],
    )


async def over(text):
    st = MemStore()
    st.items["keystore"] = text.encode()
    return await s.open(config(), st, FakeAuth())


async def failure(coro):
    """The error's code (its text: `Display` is the code), or "Ok"."""
    try:
        await coro
        return "Ok"
    except s.SdkError as e:
        return str(e)


class Smoke(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # the SDK calls the store and the authenticator from its own runtime's threads: their coroutines run on this loop
        s.uniffi_set_event_loop(asyncio.get_running_loop())

    async def test_load_check(self):
        self.assertEqual(s.api_version(), 1)
        # the opening refuses a library of another api_version or without a needed feature (spec §16.3)
        self.assertEqual(await failure(s.open(config(expect_api=2), MemStore(), None)), "AbiMismatch")
        c = config()
        c.need_features = 1 << 62
        self.assertEqual(await failure(s.open(c, MemStore(), None)), "AbiMismatch")
        # control: this library's
        await s.open(config(), MemStore(), None)

    async def test_copy_calls_reveal_dispose(self):
        sdk = await s.open(config(), MemStore(), FakeAuth())
        new = await sdk.vault().generate(s.Generate(label="Fresh", vault_passphrase=secret(PASS)))
        words = new.backup.reveal()
        text = copy.read(s.secret_id(words), s.secret_len(words))
        self.assertEqual(len(text.decode().split(" ")), 24, "the revealed words, read by the copy call")
        text[:] = bytes(len(text))
        self.assertTrue(copy.dispose(s.secret_id(words)))
        with self.assertRaises(ValueError):
            copy.read(s.secret_id(words), 1)
        # an opaque call without the marker: the SDK's code, not the binding's internal error (review B2)
        key = s.KeyRef.UA(seed=new.info.id, kind=0, account=0, index=0)
        env = s.Envelope(valid_until=0, mode=0, relayer=None, fee="0", fee_recipient=None)
        call = s.ExecuteCall.OPAQUE(target="0x" + "11" * 20, value="0", data="0x", allow=False)
        req = s.Execute(signer=key, chain="x", wallet="0x" + "22" * 20, call=call, batch="0", envelope=env)
        self.assertEqual(await failure(sdk.wallet().prepare_execute(req)), "OpaqueCallRefused")

    async def test_keystore_rows(self):
        d = json.loads((ROOT / "smartcontracts/vectors/keystore/keystore.json").read_text(encoding="utf-8"))
        valid = opened = refused = 0
        for r in d["valid"]:
            want = json.loads(r["text"])["seeds"]
            sdk = await over(r["text"])
            got = await sdk.vault().seeds()
            self.assertEqual(len(got), len(want), r["id"])
            for g, w in zip(got, want):
                self.assertEqual(
                    (g.id, g.label, g.words, g.backup, g.unlocked),
                    (w["id"], w["label"], w["words"], w["backup"], False),
                    r["id"],
                )
            for w in want:
                await sdk.vault().unlock(w["id"], s.Unlock.PASSPHRASE(secret(d["passphrase"])))
                self.assertTrue((await sdk.vault().seed(w["id"])).unlocked, (r["id"], w["id"]))
                ids = [a.id for a in await sdk.account().accounts(w["id"])]
                self.assertEqual(ids, [a["id"] for a in w["accounts"]], (r["id"], w["id"]))
                opened += 1
            if want:
                first = want[0]["id"]
                await sdk.vault().lock(first)
                e = await failure(sdk.vault().unlock(first, s.Unlock.PASSPHRASE(secret("not the one 9"))))
                self.assertEqual(e, "VaultOpen", r["id"])
            valid += 1
        for r in d["refused"]:

            async def seeds(text=r["text"]):
                return await (await over(text)).vault().seeds()

            self.assertEqual(await failure(seeds()), r["error"], r["id"])
            refused += 1
        # control: the rows were read and the seeds opened
        self.assertTrue(valid >= 5 and opened >= 5 and refused >= 19, (valid, opened, refused))

    async def test_store_authenticator_panic_and_exceptions(self):
        st, auth = MemStore(), FakeAuth()
        sdk = await s.open(config(), st, auth)
        sub = sdk.subscribe()
        self.assertIsNone(await sub.next(50))
        seed = (
            await sdk.vault().import_words(
                s.ImportWords(label="Main", words=secret(REPO), vault_passphrase=secret(PASS))
            )
        ).id
        changed = False
        while (ev := await sub.next(200)) is not None:
            changed |= isinstance(ev, s.Event.KEYSTORE_CHANGED)
        self.assertTrue(changed, "next: KeystoreChanged")

        # the PRF return: a Python authenticator writes it by the copy call; the passkey unlock opens the seed with it
        await sdk.vault().enable_passkey_unlock(seed, secret(PASS))
        await sdk.vault().lock(seed)
        await sdk.vault().unlock(seed, s.Unlock.PASSKEY())
        self.assertTrue((await sdk.vault().seed(seed)).unlocked, "passkey unlock by the PRF")

        # a Python exception in the authenticator: Unexpected on the Rust side, the SDK's refusal here, no panic
        await sdk.vault().lock(seed)
        auth.throws = True
        ea = await failure(sdk.vault().unlock(seed, s.Unlock.PASSKEY()))
        self.assertEqual(ea, "AuthenticatorRefused")
        auth.throws = False
        # a Python exception in the store: Unexpected, the store's failure (VaultIo)
        st.throws = True
        self.assertEqual(await failure(sdk.vault().seeds()), "VaultIo")
        st.throws = False
        self.assertEqual(len(await sdk.vault().seeds()), 1)

        # a panic inside a call (the reference library's hook): Internal, the SDK goes on
        self.assertEqual(await failure(ffi.panic_in_call(sdk)), "Internal")
        self.assertEqual(len(await sdk.vault().seeds()), 1)

    async def test_evm_profile(self):
        # the bindings build the SDK's `evm` (decisions CLI-SDK-33 (49)): an EVM profile opens
        self.assertNotEqual(s.features() & (1 << 30), 0, "the evm bit")

        def profile(**more):
            p = dict(
                key="local",
                family=s.Family.EVM,
                chain_id=31337,
                chain_uid="0x" + "60" * 32,
                rpc=[s.EndpointConfig(url="http://127.0.0.1:9", _class=s.Class.NAMED, label=None, auth=None)],
                rpc_policy=s.Policy.FAILOVER,
                gateways=[],
                registry=None,
                factory=None,
                router=None,
                finality=s.Finality.FINALIZED(),
                tx_gas_cap=None,
                tokens=[],
                gas=s.gas_rows_default(),
                gas_opt_in=[],
                max_valid_secs=None,
                verifiers=[],
                verifier_policy=s.Policy.FAILOVER,
                dexes=[],
                wrappers=[],
                family_params=None,
                l1_fee=None,
                disabled_kinds=[],
            )
            p.update(more)
            return s.ChainProfile(**p)

        async def open_with(p):
            c = config()
            c.profiles = [p]
            return await s.open(c, MemStore(), None)

        self.assertEqual(await failure(open_with(profile())), "Ok")
        # the merge's fields reach the SDK: the OP Stack L1 fee and a disabled kind open; an unknown kind is refused by name
        self.assertEqual(await failure(open_with(profile(l1_fee=s.L1Fee.OP_STACK, disabled_kinds=["pqz"]))), "Ok")
        self.assertEqual(await failure(open_with(profile(disabled_kinds=["no-such-kind"]))), "Argument")


if __name__ == "__main__":
    unittest.main()
