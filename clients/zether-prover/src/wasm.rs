//! WASM bindings: one JSON entry point over [`crate::api::call`] (same commands as the CLI).
//! Nothing is persisted; seeds, keys and witnesses are zeroized when the call drops them
//! (scalar copies on the stack excepted, see `TransferWitness`).

use wasm_bindgen::prelude::*;

/// `zetherCall("proveTransfer", JSON.stringify(req))` → JSON string, throws on error.
#[wasm_bindgen(js_name = zetherCall)]
pub fn zether_call(cmd: &str, input: &str) -> Result<String, JsError> {
    crate::api::call(cmd, input).map_err(|e| JsError::new(&e))
}
