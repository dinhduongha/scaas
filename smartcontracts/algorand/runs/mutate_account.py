#!/usr/bin/env python3
"""T12 mutation spot-checks: each mutant removes or weakens one guard of contracts/{account,token,common}.py; the
build + the named tests must then fail (killed). Every file is restored from memory after each mutant. Run on a live
localnet under scripts/capped: python3 runs/mutate_account.py > runs/2026-10-28-algorand-account-mutations.txt"""
import os
import subprocess
import sys

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SC = os.path.dirname(R)
A, T, C = 'contracts/account.py', 'contracts/token.py', 'contracts/common.py'
TA = 'tests/test_account.py::'
M = [
    ('M1 key-op shape: op code', A, 'assert o.op.as_uint64() == code and o.amount', 'assert o.amount',
     TA + 'test_key_op_envelope_refused'),
    ('M2 extra not bound to params', A, 'assert o.extra.bytes == op.sha256(params), ', 'assert True, ',
     TA + 'test_key_op_envelope_refused'),
    ('M3 key nonce unchecked', A, 'assert nonce == o.nonce.as_uint64(), ', 'assert True, ',
     TA + 'test_ua_opened_lazily_relayer_pays_mbr'),
    ('M4 key nonce not consumed', A, 'return op.replace(rec, 0, op.itob(nonce + 1))', 'return rec',
     TA + 'test_ua_opened_lazily_relayer_pays_mbr'),
    ('M5 to == from unchecked', A, 'assert o.to.bytes == o.from_.bytes, ', 'assert True, ',
     TA + 'test_key_op_envelope_refused'),
    ('M6 guardian == signer unchecked', A, 'assert g == o.from_.bytes, ', 'assert True, ',
     TA + 'test_recovery_after_delay_only'),
    ('M7 no-guardian unchecked', A, 'assert g != op.bzero(33), ', 'assert True, ',
     TA + 'test_cancel_recovery_and_guardian_ops'),
    ('M8 recovery delay unchecked', A, 'assert Global.latest_timestamp >= ready, ', 'assert True, ',
     TA + 'test_recovery_after_delay_only'),
    ('M9 no pending recovery unchecked (finish)', A, 'assert ready != 0, ', 'assert True, ',
     TA + 'test_recovery_after_delay_only'),
    ('M10 start: no fail-fast', A, '        usable(after, op_.to)\n', '',
     TA + 'test_recovery_of_a_passkey_with_its_origin'),
    ('M11 MAX_KEYS', A, 'assert n < MAX_KEYS, ', 'assert True, ', TA + 'test_ninth_key_refused'),
    ('M12 key already present', A, 'assert not has(rec, UInt64(HEADER), n, kid.bytes), ', 'assert True, ',
     TA + 'test_ninth_key_refused'),
    ('M13 last key removable', A, 'assert n_keys(rec) > 0, ', 'assert True, ',
     TA + 'test_ua_opened_lazily_relayer_pays_mbr'),
    ('M14 passkey without origin', A, 'assert n_origins(rec) > 0 or op.getbyte(rec, O_NPK) == 0, ', 'assert True, ',
     TA + 'test_origin_and_rp_checked'),
    ('M15 MAX_ORIGINS', A, 'assert n_origins(rec) <= MAX_ORIGINS, ', 'assert True, ', TA + 'test_origin_cap'),
    ('M16 key not in record accepted', A,
     'assert has(rec, UInt64(HEADER), n_keys(rec), kid.bytes), "not a key of the subject"',
     'assert True, "not a key of the subject"', TA + 'test_keys_shared_by_two_tokens'),
    ('M17 lazy key need not derive the id', A, 'assert kid == h.id, ', 'assert True, ',
     TA + 'test_origin_and_rp_checked'),
    ('M18 native without record signs with a key', A,
     'assert h.kind.as_uint64() == KIND_UA, "no SCaaS key', 'assert True, "no SCaaS key',
     TA + 'test_rekeyed_address_signs_through_account_record'),
    ('M19 ed25519 signature unchecked', A,
     'assert op.ed25519verify_bare(sign_bytes(d), op.extract(auth, 33, 64), pk), ', 'assert True, ',
     TA + 'test_high_s_refused tests/test_account.py::test_ua_opened_lazily_relayer_pays_mbr '
     'tests/test_account.py::test_msig_rules'),
    ('M21 P-256 low-s', A, 'assert BigUInt.from_bytes(s) <= HALF_N_P256, ', 'assert True, ',
     TA + 'test_high_s_refused'),
    ('M22 UP / UV flags', A, 'assert ad.length >= 37 and op.getbyte(ad, 32) & 5 == 5, ', 'assert ad.length >= 37, ',
     TA + 'test_origin_and_rp_checked'),
    ('M23 challenge = b64url(digest)', A, 'op.extract(cd, 36, 43) + b"=") == d.bytes, ',
     'op.extract(cd, 36, 43) + b"=") != Bytes(), ', TA + 'test_origin_and_rp_checked'),
    ('M24 type prefix', A, 'op.extract(cd, 0, 36) == CD_TYPE and ', '', TA + 'test_origin_and_rp_checked'),
    ('M25 backslash in origin', A,
     'assert c != 0x5C, "passkey clientDataJSON (type, challenge or origin)"', 'pass',
     TA + 'test_origin_and_rp_checked'),
    ('M26 topOrigin after crossOrigin', A, 'assert op.extract(t, k, 11) != b\'"topOrigin"\', ', 'assert True, ',
     TA + 'test_origin_and_rp_checked'),
    ('M27 second crossOrigin', A, 'assert op.extract(t, k, 13) != b\'"crossOrigin"\', ', 'assert True, ',
     TA + 'test_origin_and_rp_checked'),
    ('M28 closing brace', A, 'and op.getbyte(t, n - 1) == 0x7D, ', ', ', TA + 'test_origin_and_rp_checked'),
    ('M29 origin listed', A, 'assert has(rec, origins_at(rec), n_origins(rec), oh.bytes), ', 'assert True, ',
     TA + 'test_origin_and_rp_checked'),
    ('M30 passkey field cap', A, 'assert ad.length <= PASSKEY_FIELD_MAX and cd.length <= PASSKEY_FIELD_MAX, ',
     'assert True, ', TA + 'test_origin_and_rp_checked'),
    ('M31 msig member order', A, 'assert i >= first, ', 'assert True, ', TA + 'test_msig_rules'),
    ('M32 msig threshold', A, 'assert weight >= op.extract_uint16(kd, 0), ', 'assert True, ',
     TA + 'test_msig_native_member_by_current_authority'),
    ('M33 msig member key mismatch', A, 'assert lk == mkind and lid.bytes == mid, ', 'assert True, ',
     TA + 'test_msig_rules'),
    ('M34 msig native member unchecked', A, 'assert verify_native(Account(mid), d, a), ', 'assert True, ',
     TA + 'test_msig_native_member_by_current_authority'),
    ('M35 msig member cap', A, 'assert count >= 1 and count <= MSIG_MAX_MEMBERS, ', 'assert count >= 1, ',
     TA + 'test_msig_rules'),
    ('M36 msig inside msig', A, 'assert a.length > 0 and op.getbyte(a, 0) != AUTH_MSIG, ', 'assert True, ',
     TA + 'test_msig_rules'),
    ('M37 POLICY_PASSKEY_FOR_VALUE', A, 'assert mode != 1, ', 'assert True, ',
     TA + 'test_policy_passkey_for_value'),
    ('M38 verify: lazy-open MBR unchecked', A,
     '''        rec, opened = value_signed(h, digest, auth)
        if opened:
            put(h, rec)
        mbr_paid(before, UInt64(0))''', '''        rec, opened = value_signed(h, digest, auth)
        if opened:
            put(h, rec)''',
     TA + 'test_token_ua_pay_via_account_verify'),
    ('M39 key op MBR unchecked (add_key)', A, '''        save(op_.from_, rec, String("add_key"))
        mbr_paid(before, UInt64(0))''', '''        save(op_.from_, rec, String("add_key"))''',
     TA + 'test_ua_opened_lazily_relayer_pays_mbr'),
    ('M40 own guardian accepted', A, 'assert guardian.bytes != op_.from_.bytes, ', 'assert True, ',
     TA + 'test_cancel_recovery_and_guardian_ops'),
    ('M41 unknown policy bit', A, 'assert policy.as_uint64() & ~UInt64(POLICY_PASSKEY_FOR_VALUE) == 0, ',
     'assert True, ', TA + 'test_policy_passkey_for_value'),
    ('M42 set_guardian keeps a pending recovery', A,
     'rec = op.replace(op.replace(rec, O_GUARDIAN, guardian.bytes), O_READY, op.bzero(RECOVERY_LEN))',
     'rec = op.replace(rec, O_GUARDIAN, guardian.bytes)', TA + 'test_cancel_recovery_and_guardian_ops'),
    ('M43 cancel without a pending recovery', A, 'assert op.extract_uint64(rec, O_READY) != 0, ', 'assert True, ',
     TA + 'test_cancel_recovery_and_guardian_ops'),
    ('M44 finish keeps the subject nonce', A,
     "t = op.replace(op.replace(t, O_READY, op.bzero(RECOVERY_LEN)), 0, op.itob(op.extract_uint64(t, 0) + 1))",
     "t = op.replace(t, O_READY, op.bzero(RECOVERY_LEN))", TA + 'test_recovery_after_delay_only'),
    ('M45 recovery key not added at finish', A,
     't = with_key(t, Bytes32.from_bytes(op.extract(t, O_RKEY, 32)), op.getbyte(t, O_RPK) != 0)', 'pass',
     TA + 'test_recovery_after_delay_only'),
    ('M46 account Update / Delete allowed', A, '    @arc4.baremethod(allow_actions=["NoOp"])\n    def budget(self)',
     '    @arc4.baremethod(allow_actions=["NoOp", "UpdateApplication", "DeleteApplication"])\n    def budget(self)',
     TA + 'test_account_update_delete_optin_refused'),
    ('M47 account OptIn allowed', A, '    @arc4.baremethod(allow_actions=["NoOp"])\n    def budget(self)',
     '    @arc4.baremethod(allow_actions=["NoOp", "OptIn"])\n    def budget(self)',
     TA + 'test_account_update_delete_optin_refused'),
    ('M48 token: UA signer not verified', T,
     '            account_verify(self.account_app.value, o.from_, d, auth, forwarded)\n',
     '', TA + 'test_token_ua_pay_via_account_verify'),
    ('M49 token: nothing forwarded', T, '            forwarded = paid - need\n', '',
     TA + 'test_token_ua_pay_via_account_verify'),
    ('M50 token: ua_total not debited (T11 N4)', T, '            self.ua_total.value -= amount\n', '',
     TA + 'test_token_ua_pay_via_account_verify'),
    ('M51 token: native fast path for any 64-byte auth', T,
     'if o.from_.kind.as_uint64() == KIND_ADDRESS and auth.length == 64:', 'if auth.length == 64:',
     'tests/test_token.py::test_ua_signer_goes_through_the_account_app'),
    ('M52 token: verify result ignored', C, 'assert call.submit().last_log == ARC4_TRUE, "bad signature"',
     'call.submit()', TA + 'test_token_takes_only_a_true_verify'),
    ('M53 shrink refunds nothing → grows checked', C, 'grown = after - before if after > before else UInt64(0)',
     'grown = UInt64(0)', TA + 'test_ua_opened_lazily_relayer_pays_mbr'),
    # T12 fix 1: duplicate signing key (m1), reviewer survivors R2 / R3 (m3 / m4), the open event (m8), inner budget
    ('M54 msig: one key counts twice', A,
     '        assert not has(seen, UInt64(0), seen.length // 32, key), "msig member key repeated"\n', '',
     TA + 'test_msig_one_key_counts_once'),
    ('M55 (R2) empty origin accepted', A, 'assert i > 91 and i <= 91 + MAX_ORIGIN_LEN, ',
     'assert i <= 91 + MAX_ORIGIN_LEN, ', TA + 'test_origin_and_rp_checked'),
    ('M56 (R3) msig member kind not compared', A, 'assert lk == mkind and lid.bytes == mid, ',
     'assert lid.bytes == mid, ', TA + 'test_msig_rules'),
    ('M57 no open event', A, '        arc4.emit("KeyOp", h, arc4.String("open"))\n', '        pass\n',
     TA + 'test_ua_opened_lazily_relayer_pays_mbr'),
    ('M58 passkey check without inner budget', A,
     '    ensure_budget(COST_PASSKEY + COST_PASSKEY_PER_BYTE * cd.length + TAIL, OpUpFeeSource.GroupCredit)\n', '',
     TA + 'test_budget_per_kind_pinned'),
    ('M59 entry without inner budget', A,
     '    ensure_budget(COST_ENTRY, OpUpFeeSource.GroupCredit)\n    assert o.op', '    assert o.op',
     TA + 'test_budget_per_kind_pinned'),
    ('M60 inner budget fees from the app account', A,
     '    ensure_budget(COST_ENTRY, OpUpFeeSource.GroupCredit)\n    assert o.op',
     '    ensure_budget(COST_ENTRY + 20000, OpUpFeeSource.AppAccount)\n    assert o.op',
     TA + 'test_inner_budget_calls_fee_pooled_no_residue'),
    ('M61 native verify without inner budget', C, '    ensure_budget(COST_NATIVE + TAIL, OpUpFeeSource.GroupCredit)\n',
     '', TA + 'test_budget_per_kind_pinned'),
]


def run(cmd):
    return subprocess.run(cmd, shell=True, cwd=R, capture_output=True, text=True)


def main(M=M, title='algorand-account-mutations', tree='T12'):
    orig = {f: open(os.path.join(R, f)).read() for f in {m[1] for m in M}}
    print('# %s at commit %s + the %s tree' % (title, run('git rev-parse --short HEAD').stdout.strip(), tree))
    killed = 0
    only = sys.argv[1:]
    todo = [m for m in M if not only or m[0].split()[0] in only]
    for name, f, old, new, tests in todo:
        src = orig[f]
        assert src.count(old) == 1, (name, src.count(old))
        try:
            open(os.path.join(R, f), 'w').write(src.replace(old, new))
            b = run('rm -rf out && .venv/bin/puyapy contracts --out-dir "$PWD/out" --output-bytecode '
                    '--no-output-teal --no-output-source-map')
            if b.returncode:
                print('%-50s KILLED (build fails)' % name)
                killed += 1
                continue
            r = run('.venv/bin/python -m pytest -q -x --tb=line -p no:cacheprovider -W ignore::DeprecationWarning '
                    + ' '.join('tests/' + t if not t.startswith('tests/') else t for t in tests.split()))
            last = [ln for ln in r.stdout.splitlines() if ln.strip()][-1]
            ok = r.returncode != 0
            killed += ok
            print('%-50s %s  (%s)' % (name, 'KILLED' if ok else 'SURVIVED', last))
        finally:
            open(os.path.join(R, f), 'w').write(src)
    b = run('rm -rf out && .venv/bin/puyapy contracts --out-dir "$PWD/out" --output-bytecode --no-output-teal '
            '--no-output-source-map')
    print('%d / %d killed; tree restored, rebuilt rc=%d' % (killed, len(todo), b.returncode))
    print('rc=%d' % (0 if killed == len(todo) else 1))


if __name__ == '__main__':
    sys.exit(main())
