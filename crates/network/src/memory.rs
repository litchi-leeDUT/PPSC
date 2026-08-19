//! In-process peer transport: a per-recipient in-memory mailbox, for protocol closed loops and
//! multi-node simulation.
//!
//! Only handles delivery and pickup; it never interprets the mathematical meaning of messages.
//! A production deployment replaces this with a gRPC/tonic adapter. An optional per-message
//! one-way latency models LAN/MAN/WAN RTT so protocol round-trips can be measured.

use ppsc_core::NodeId;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A network profile: one-way message latency (RTT/2).
///
/// RTT values are illustrative defaults (the paper must state the exact chosen config); they are
/// kept here so LAN/MAN/WAN benchmarks share a single source of truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkProfile {
    Lan,
    Man,
    Wan,
}

impl NetworkProfile {
    /// One-way latency (RTT/2).
    pub fn one_way_latency(self) -> Duration {
        match self {
            NetworkProfile::Lan => Duration::from_micros(250), // 0.5 ms RTT
            NetworkProfile::Man => Duration::from_millis(10),  // 20 ms RTT
            NetworkProfile::Wan => Duration::from_millis(50),  // 100 ms RTT
        }
    }

    pub fn rtt(self) -> Duration {
        self.one_way_latency() * 2
    }

    /// Bandwidth in bits per second (illustrative defaults; the paper must fix these).
    pub fn bandwidth_bps(self) -> f64 {
        match self {
            NetworkProfile::Lan => 1_000_000_000.0, // 1 Gbps
            NetworkProfile::Man => 100_000_000.0,   // 100 Mbps
            NetworkProfile::Wan => 10_000_000.0,    // 10 Mbps
        }
    }
}

pub struct MemoryMailbox<M> {
    queues: Mutex<HashMap<NodeId, VecDeque<(Instant, M)>>>,
    latency: Duration,
    bandwidth_bps: f64,
}

impl<M> Default for MemoryMailbox<M> {
    fn default() -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            latency: Duration::ZERO,
            bandwidth_bps: 0.0,
        }
    }
}

impl<M> MemoryMailbox<M> {
    /// A mailbox with a fixed per-message one-way latency (no bandwidth limit).
    pub fn with_latency(latency: Duration) -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            latency,
            bandwidth_bps: 0.0,
        }
    }

    /// A mailbox configured by a network profile (RTT latency + bandwidth).
    pub fn with_profile(profile: NetworkProfile) -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            latency: profile.one_way_latency(),
            bandwidth_bps: profile.bandwidth_bps(),
        }
    }

    pub fn send(&self, recipient: NodeId, message: M) {
        self.send_with_size(recipient, message, 0);
    }

    /// `send` accounting for a serialized payload size (bytes); adds `size*8/bandwidth`
    /// to the arrival time when a bandwidth limit is configured.
    pub fn send_with_size(&self, recipient: NodeId, message: M, size_bytes: usize) {
        let transfer = if self.bandwidth_bps > 0.0 {
            Duration::from_secs_f64(size_bytes as f64 * 8.0 / self.bandwidth_bps)
        } else {
            Duration::ZERO
        };
        let arrive = Instant::now() + self.latency + transfer;
        self.queues
            .lock()
            .expect("mailbox poisoned")
            .entry(recipient)
            .or_default()
            .push_back((arrive, message));
    }

    /// Block until every message addressed to `recipient` has arrived, then return them all.
    pub fn drain(&self, recipient: NodeId) -> Vec<M> {
        let mut out = Vec::new();
        loop {
            let now = Instant::now();
            let mut earliest = None;
            {
                let mut queues = self.queues.lock().expect("mailbox poisoned");
                let q = queues.entry(recipient).or_default();
                while let Some(&(arrive, _)) = q.front() {
                    if arrive <= now {
                        if let Some((_, m)) = q.pop_front() {
                            out.push(m);
                        }
                    } else {
                        earliest = Some(arrive);
                        break;
                    }
                }
            }
            match earliest {
                Some(t) => {
                    let now = Instant::now();
                    if t > now {
                        std::thread::sleep(t - now);
                    }
                }
                None => break,
            }
        }
        out
    }
}
