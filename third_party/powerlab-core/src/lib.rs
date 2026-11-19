//! PowerLab shared core.
//!
//! This crate holds what the GUI, the sampler process and the supervisor all have
//! to agree on, and nothing else:
//!
//! * [`chart`] — bounded chart geometry, so drawing cost never grows with a session;
//! * [`ipc`] — the frozen, versioned contract between the GUI and the sampler;
//! * [`json`] — the exact reader/writer that contract travels in;
//! * [`lineio`] — bounded line framing over a pipe, so a stalled or raving peer
//!   cannot exhaust memory.
//!
//! It deliberately contains **no hardware access**. Hardware lives in the sampler
//! process, so that a provider which blocks forever can be terminated by
//! terminating a process instead of a thread.

pub mod chart;
pub mod ipc;
pub mod json;
pub mod lineio;
pub mod present;
