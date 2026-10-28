//! Shared NEAR contract code (auth checks, encodings).
pub mod auth;
pub mod hash;
pub mod holder;
pub mod metaop;
pub mod ua;
pub mod webauthn;

pub use auth::Auth;
pub use holder::Holder;
pub use metaop::{MetaOp, Order};
