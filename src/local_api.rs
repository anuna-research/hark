use serde::{Deserialize, Serialize};

use crate::constants::LOCAL_API_VERSION;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PingResponse {
    pub ok: bool,
    pub version: String,
    pub api_version: u16,
}

impl PingResponse {
    pub fn current() -> Self {
        Self {
            ok: true,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            api_version: LOCAL_API_VERSION,
        }
    }
}
