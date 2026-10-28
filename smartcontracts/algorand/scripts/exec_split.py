#!/usr/bin/env python3
"""Split the executor LogicSig (`out/Executor.bin`, compiled with ROUTER_APP_ID = the sentinel `argv[1]`) around its
8-byte router-id constant: writes `out/Executor.prefix.bin` / `out/Executor.suffix.bin` and prints the puyapy template
options `-T EXEC_PREFIX=0x… -T EXEC_SUFFIX=0x…` the router is compiled with (spec §4.8: the router derives the executor's address
as sha512_256("Program" ‖ prefix ‖ itob(own app id) ‖ suffix)). Fails unless the sentinel occurs exactly once."""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'out')
sentinel = bytes.fromhex(sys.argv[1].removeprefix('0x'))
prog = open(os.path.join(OUT, 'Executor.bin'), 'rb').read()
if len(sentinel) != 8 or prog.count(sentinel) != 1:
    sys.exit('executor: the 8-byte ROUTER_APP_ID sentinel must occur exactly once in Executor.bin')
prefix, suffix = prog.split(sentinel)
open(os.path.join(OUT, 'Executor.prefix.bin'), 'wb').write(prefix)
open(os.path.join(OUT, 'Executor.suffix.bin'), 'wb').write(suffix)
print('-T EXEC_PREFIX=0x%s -T EXEC_SUFFIX=0x%s' % (prefix.hex(), suffix.hex()))
