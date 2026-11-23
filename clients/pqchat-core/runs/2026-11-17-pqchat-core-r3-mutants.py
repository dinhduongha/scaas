# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core round 3's mutants (owner 2026-11-23, plan T10b): PqChat's app purpose in the refused SCaaS purposes of the
generic app signing, PqChat's own paths still signing; each killed by its own named test:
python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-r3-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

REF = "clients/ua-rs/src/wallet/app_refusals.rs"
PQC = "clients/ua-rs/src/wallet/pqchat.rs"
KEY = "clients/ua-rs/src/wallet/appkey.rs"
UT = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors --test app_core "
TST = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test stores "
REFUSE = ("    if super::is_scaas_purpose(&crate::ua_portable::app_purpose(&app_id())?) {\n"
          "        return Err(Error::AppPurposeRefused);\n    }\n")
MUTANTS = [
    ("ua-rs: PqChat's app id dropped from the generated list",
     [(REF, '    ("pqchat.js APP_ID_TAG", "scaas.pqchat.v1"),\n', "")],
     UT + "generic_signing_refuses_pqchat_app_purpose"),
    ("ua-rs: a PqChat record entry refused as a SCaaS app's",
     [(PQC, "        return Err(Error::Argument);\n    }\n    sign_typed(key, td)\n}\n",
       "        return Err(Error::Argument);\n    }\n" + REFUSE + "    sign_typed(key, td)\n}\n")],
     UT + "pqchat_dedicated_paths_still_sign"),
    ("ua-rs: the contact card refused as a SCaaS app's",
     [(PQC, "    sign_typed(key, &card_typed(c)?)\n", REFUSE + "    sign_typed(key, &card_typed(c)?)\n")],
     UT + "pqchat_dedicated_paths_still_sign"),
    ("ua-rs: the app root (the file seal's) refused for a SCaaS app",
     [(KEY, "        let info = [APP_ROOT, app_id, ua].concat();\n",
       "        if super::is_scaas_purpose(&crate::ua_portable::app_purpose(app_id)?) {\n"
       "            return Err(Error::AppPurposeRefused);\n        }\n"
       "        let info = [APP_ROOT, app_id, ua].concat();\n")],
     TST + "a_file_is_sent_and_read"),
]

if __name__ == "__main__":
    main("r3", MUTANTS)
