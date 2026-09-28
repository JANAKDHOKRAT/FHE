//! Network nodes for fhe-prio3: an aggregator server, a collector server and
//! a client, over HTTPS with bincode bodies, with SQLite persistence and a
//! sealed-at-rest key share.
//!
//! Topology: aggregator 0 is the *leader*. Clients talk only to the leader;
//! the leader drives the per-report rounds with the helpers and the batch
//! close with the helpers and the collector. Aggregator-to-aggregator and
//! aggregator-to-collector calls carry a bearer token over TLS.

pub mod aggregator_node;
pub mod client;
pub mod collector_node;
pub mod router;
pub mod secret;
pub mod store;
pub mod wire;
