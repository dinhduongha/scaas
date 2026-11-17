// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    // ua-rs-sign T13b: the C++ side of an app is ua-cxx. Its bridges are linked through the scaas-ua-cxx rlib; its C++
    // (include/scaas_ua.hpp over the generated bridge headers it exports through `links`) is compiled into this crate.
    let generated: Vec<String> =
        std::env::vars().filter(|(k, _)| k.starts_with("DEP_SCAAS_UA_CXX_CXXBRIDGE_DIR")).map(|(_, v)| v).collect();
    let cxx = ["../ua-cxx/src/scaas_ua.cpp", "../ua-cxx/src/wallet.cpp", "../ua-cxx/include/scaas_ua.hpp"];
    cxx.iter().for_each(|f| println!("cargo::rerun-if-changed={f}"));
    let builder = CxxQtBuilder::new_qml_module(QmlModule::new("Scaas.Ua")).files(["src/ua_kinds.rs", "src/ua_wallet.rs"]);
    // SAFETY: include directories and two C++ files added to cxx-qt's own cc::Build, nothing else changed
    let builder = unsafe {
        builder.cc_builder(|cc| {
            generated.iter().for_each(|d| {
                cc.include(d);
            });
            cc.include("../ua-cxx/include");
            cc.files(&cxx[..2]);
        })
    };
    builder.build();
}
