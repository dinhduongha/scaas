// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// CLI-UAL-66: the Falcon gate's wasm32 run (run.sh builds pkg/).
const { run } = require("./pkg/scaas_ua_fndsa_wasm.js");
const out = run();
console.log("[fndsa-wasm] " + out);
process.exit(out.startsWith("ok ") ? 0 : 1);
