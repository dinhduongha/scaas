// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// tests/fndsa/timing.rs in wasm32 under Node (after run.sh built pkg/): a measurement, not a gate. Only on an idle machine,
// with the owner's word: node timing.cjs [scale]
const { timing } = require("./pkg/scaas_ua_fndsa_wasm.js");
console.log(timing(Number(process.argv[2] || 1)));
