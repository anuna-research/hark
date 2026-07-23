//! SPEC-024 / IMPL-025 §2 canonical-vector proof-of-fit spike.
//!
//! Intentionally empty: all evidence lives in `tests/canonical_parity.rs`, run with
//! `cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml -- --nocapture`.
//! This crate exists only to give that integration test a home that links the
//! production `cbcl-core` encoder exactly as hark links it. It touches no hark
//! production code and is NOT role-runtime binding (see README + IMPL-025 ADR-031).
