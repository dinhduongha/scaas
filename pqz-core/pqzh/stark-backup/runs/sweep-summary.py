#!/usr/bin/env python3
"""Summarise a pqzh_security JSON-lines file: one row per (rel, blowup, arity)."""
import json, sys
for l in open(sys.argv[1]):
    d = json.loads(l)
    if 'shape' in d:
        print(f"== {d['rel']} ext {d['ext']} zk {d['zk']} {d['grinding']} shape {d['shape']}")
        continue
    f = lambda k: d.get(k) if d.get(k) is not None else '-'
    print(f"{d['rel']} lb {d['log_blowup']} la {d['log_arity']}: ceiling proven {d['ceiling_proven']} ({d['ceiling_proven_binding']}) conj {d['ceiling_conjectured']} ({d['ceiling_conjectured_binding']})"
          f" | q_proven {f('q_proven')} {f('binding_proven')} bytes {f('bytes_proven')} | q_conj {f('q_conjectured')} {f('binding_conjectured')} bytes {f('bytes_conjectured')} | at28 {d['at_q28']}")
