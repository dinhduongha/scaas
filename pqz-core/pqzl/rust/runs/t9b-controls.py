#!/usr/bin/env python3
# negative controls: each = [(file, old, new)...]; patch, run the covering tests, restore, compare
# Task 9 fix round 1 (run t9b): python3 -I pqz-core/pqzl/rust/runs/t9b-controls.py  -> runs/t9b-controls.txt
import subprocess, sys, shutil, filecmp, os
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
C = {
 'z3': [('src/sv.rs', 'if !l2_le(&z3c, s.bz3sqr) {', 'if false {'),
        ('src/proof/tbox.rs', 'if polyvec::l2sqr(&mut **z3).gt(&p.bz3sqr) {', 'if false {')],
 'z4': [('src/sv.rs', 'if z4c.iter().any(|x| x.unsigned_abs() > s.bz4) {', 'if false {'),
        ('src/proof/tbox.rs', 'if polyvec::linf(&mut **z4).gt(&p.bz4) {', 'if false {')],
 'z3_sv': [('src/sv.rs', 'if !l2_le(&z3c, s.bz3sqr) {', 'if false {')],
 'z3_gen': [('src/proof/tbox.rs', 'if polyvec::l2sqr(&mut **z3).gt(&p.bz3sqr) {', 'if false {')],
 'z4_sv': [('src/sv.rs', 'if z4c.iter().any(|x| x.unsigned_abs() > s.bz4) {', 'if false {')],
 'z4_gen': [('src/proof/tbox.rs', 'if polyvec::linf(&mut **z4).gt(&p.bz4) {', 'if false {')],
 'h_sv': [('src/sv.rs', 'if hc[DEG * i] != 0 || hc[DEG * i + DEG / 2] != 0 {', 'if false {')],
 'h_gen': [('src/proof/tbox.rs', 'if !(h.get_coeff(0).eqzero() && h.get_coeff(D / 2).eqzero()) {', 'if false {')],
}
for name in sys.argv[1:]:
    bak = []
    for f, old, new in C[name]:
        s = open(f).read(); assert s.count(old) == 1, (name, f)
        shutil.copy(f, f + '.ctlbak'); bak.append(f)
        open(f, 'w').write(s.replace(old, new))
    out = subprocess.run('cargo test -j2 --release --offline --features test-hooks --test sv_diff --test vectors -- cheating vectors_verify_fast all_pqzl negative_rows 2>&1',
                         shell=True, capture_output=True, text=True).stdout
    for l in out.splitlines():
        if l.startswith('test ') or 'failed:' in l or l.startswith('  left'):
            print(f'  [{name}] {l}')
    for f in bak:
        shutil.copy(f + '.ctlbak', f); os.remove(f + '.ctlbak')
    print(f'control {name}: restored, git diff clean:', subprocess.run(['git', 'diff', '--quiet', '--'] + bak).returncode == 0)
