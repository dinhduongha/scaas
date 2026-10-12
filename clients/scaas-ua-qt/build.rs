use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    CxxQtBuilder::new_qml_module(QmlModule::new("Scaas.Ua"))
        .files(["src/ua_kinds.rs"])
        .build();
}
