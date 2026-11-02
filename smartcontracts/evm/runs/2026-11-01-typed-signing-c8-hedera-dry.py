#!/usr/bin/env python3
"""typed-signing C8: `DeployHedera.s.sol` as a dry run (no --broadcast) on an anvil of its own, since `DeployBase.sol` was touched
(comment only). Anvil's readiness is its own "Listening on" line, read from its stdout; no polling. Chain 31337 as a stand-in
Hedera: the script only needs the RPC; the anvil ends with this process."""
import os
import subprocess
import threading

PORT = 31994
p = subprocess.Popen(["anvil", "--chain-id", "31337", "--hardfork", "amsterdam", "--gas-limit", "200000000", "--code-size-limit", "65536",
                      "--port", str(PORT)], stdout=subprocess.PIPE, text=True)
try:
    for line in p.stdout:
        if "Listening on" in line:
            break
    else:
        raise SystemExit("anvil ended before listening")
    threading.Thread(target=lambda: [None for _ in p.stdout], daemon=True).start()
    r = subprocess.run(["../../scripts/capped", "forge", "script", "script/hedera/DeployHedera.s.sol", "--rpc-url", f"http://127.0.0.1:{PORT}",
                        "--disable-code-size-limit", "--gas-estimate-multiplier", "105", "--sender", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"],
                       env=dict(os.environ, PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", NOTICE_PERIOD="0",
                                FOUNDRY_FS_PERMISSIONS='[{"access":"read-write","path":"./"}]'),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(r.stdout[-1800:])
finally:
    p.terminate()
    p.wait()
raise SystemExit(r.returncode)
