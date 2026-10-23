//! SSH key management, PuTTY `.ppk` v2/v3 inspection/conversion, Windows SSH Agent / Pageant integration,
//! and the native integrated SSH agent (in-process Pageant replacement).

pub mod agent;
#[cfg(windows)]
pub mod agent_server;
pub mod ppk;
