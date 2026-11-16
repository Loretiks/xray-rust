//! Where the time of the first TCP flows after a start or a network change
//! goes.
//!
//! On iOS the first exchange after a tunnel start is sometimes slow (the
//! 0.10.0 owner decision `ios-slow-first-exchange`: 16 of 109 starts took 2 s
//! or more, and the failed attempts never reached the server). The core's
//! existing statistics only say how long an open took. For the first
//! [`FIRST_FLOWS_REPORTED`] TCP flows after a start the runtime log gets one
//! `info` line per flow that splits it up:
//!
//! - `accepted`: from the start to the flow reaching the core, which is the
//!   host's and the system's part;
//! - `sniff`: waiting for the client's first bytes, when sniffing;
//! - `route`: choosing the outbound, with any lookup routing makes;
//! - `resolve`: looking the server up while opening the outbound;
//! - `dial`: the rest of the open: TCP connect, TLS or REALITY, the
//!   transport's and the protocol's handshakes;
//! - `firstByte`: from the flow reaching the core to its first byte back.
//!
//! Nothing is measured when the runtime log is off.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use xray_routing::Target;
use xray_transport::{DnsLookup, DnsQueryStrategy, DnsResolver, TransportError};

use crate::RuntimeLogger;

/// TCP flows reported after a start or a network change.
pub(crate) const FIRST_FLOWS_REPORTED: u32 = 8;

/// What the reported flows come after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirstFlowCause {
    Start,
}

impl FirstFlowCause {
    fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Epoch {
    at: Instant,
    cause: FirstFlowCause,
}

/// The reports one core has left to give since its latest start or network
/// change.
#[derive(Debug)]
pub(crate) struct FirstFlows {
    epoch: Mutex<Epoch>,
    remaining: AtomicU32,
}

impl Default for FirstFlows {
    fn default() -> Self {
        Self {
            epoch: Mutex::new(Epoch {
                at: Instant::now(),
                cause: FirstFlowCause::Start,
            }),
            remaining: AtomicU32::new(FIRST_FLOWS_REPORTED),
        }
    }
}

impl FirstFlows {
    /// Reports the next [`FIRST_FLOWS_REPORTED`] flows again, timed from now.
    pub(crate) fn rearm(&self, cause: FirstFlowCause) {
        *self.epoch.lock().unwrap_or_else(PoisonError::into_inner) = Epoch {
            at: Instant::now(),
            cause,
        };
        self.remaining
            .store(FIRST_FLOWS_REPORTED, Ordering::Release);
    }

    /// The timing of a flow reaching the core now, if it is one of the
    /// first.
    pub(crate) fn claim(&self) -> Option<FirstFlowTiming> {
        let left = self
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1)
            })
            .ok()?;
        let epoch = *self.epoch.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        Some(FirstFlowTiming {
            ordinal: FIRST_FLOWS_REPORTED - left + 1,
            cause: epoch.cause,
            accepted: now.saturating_duration_since(epoch.at),
            started: now,
            sniff: None,
            route: Duration::ZERO,
            resolve: Arc::default(),
            open: None,
        })
    }
}

/// How one of the first flows spent its time so far.
#[derive(Debug)]
pub(crate) struct FirstFlowTiming {
    ordinal: u32,
    cause: FirstFlowCause,
    accepted: Duration,
    started: Instant,
    sniff: Option<Duration>,
    route: Duration,
    /// Microseconds spent in lookups while opening the outbound.
    resolve: Arc<AtomicU64>,
    open: Option<Duration>,
}

/// How a reported flow ended up.
pub(crate) enum FirstFlowOutcome<'a> {
    FirstByte,
    OpenFailed(&'a str),
    ClosedWithoutResponse,
}

impl FirstFlowTiming {
    pub(crate) fn sniffed(&mut self, took: Duration) {
        self.sniff = Some(took);
    }

    pub(crate) fn routed(&mut self, took: Duration) {
        self.route = self.route.saturating_add(took);
    }

    pub(crate) fn opened(&mut self, took: Duration) {
        self.open = Some(took);
    }

    /// `resolver`, counting the time its lookups take toward this flow.
    pub(crate) fn timed<'a>(&self, resolver: &'a dyn DnsResolver) -> TimedResolver<'a> {
        TimedResolver {
            inner: resolver,
            spent_micros: Arc::clone(&self.resolve),
        }
    }

    /// Writes the flow's line, at most once per flow, as it is consumed.
    pub(crate) fn report(
        self,
        logger: &RuntimeLogger,
        target: &Target,
        outbound: &str,
        outcome: FirstFlowOutcome<'_>,
    ) {
        logger.info(|| self.line(target, outbound, outcome));
    }

    fn line(&self, target: &Target, outbound: &str, outcome: FirstFlowOutcome<'_>) -> String {
        let resolve = Duration::from_micros(self.resolve.load(Ordering::Acquire));
        let ms = |duration: Duration| duration.as_millis();
        let sniff = self
            .sniff
            .map_or_else(|| "-".to_owned(), |sniff| format!("{}ms", ms(sniff)));
        let (dial, result) = match (self.open, &outcome) {
            (Some(open), _) => (
                format!("{}ms", ms(open.saturating_sub(resolve))),
                match outcome {
                    FirstFlowOutcome::FirstByte => {
                        format!("firstByte={}ms", ms(self.started.elapsed()))
                    }
                    FirstFlowOutcome::OpenFailed(error) => format!("firstByte=- error={error}"),
                    FirstFlowOutcome::ClosedWithoutResponse => {
                        "firstByte=- closed without a response".to_owned()
                    }
                },
            ),
            (None, FirstFlowOutcome::OpenFailed(error)) => {
                ("-".to_owned(), format!("firstByte=- error={error}"))
            }
            (None, _) => ("-".to_owned(), "firstByte=-".to_owned()),
        };
        format!(
            "First flow {}/{} after {}: target={} outbound={outbound} accepted=+{}ms sniff={sniff} route={}ms resolve={}ms dial={dial} {result}",
            self.ordinal,
            FIRST_FLOWS_REPORTED,
            self.cause.label(),
            crate::debug_log::target_label(target),
            ms(self.accepted),
            ms(self.route),
            ms(resolve),
        )
    }
}

/// A resolver that adds the time its lookups take to a flow's `resolve`.
pub(crate) struct TimedResolver<'a> {
    inner: &'a dyn DnsResolver,
    spent_micros: Arc<AtomicU64>,
}

impl TimedResolver<'_> {
    fn count(&self, started: Instant) {
        let spent = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.spent_micros.fetch_add(spent, Ordering::AcqRel);
    }
}

#[async_trait]
impl DnsResolver for TimedResolver<'_> {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        let started = Instant::now();
        let result = self.inner.resolve(domain, port).await;
        self.count(started);
        result
    }

    async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        let started = Instant::now();
        let result = self.inner.resolve_all(domain, port).await;
        self.count(started);
        result
    }

    async fn resolve_all_with_strategy(
        &self,
        domain: &str,
        port: u16,
        strategy: DnsQueryStrategy,
    ) -> Result<DnsLookup, TransportError> {
        let started = Instant::now();
        let result = self
            .inner
            .resolve_all_with_strategy(domain, port, strategy)
            .await;
        self.count(started);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_routing::{Network, TargetAddr};

    fn target() -> Target {
        Target::new(
            TargetAddr::Ip(std::net::IpAddr::from([198, 51, 100, 7])),
            443,
            Network::Tcp,
        )
    }

    #[test]
    fn only_the_first_flows_are_claimed_until_the_next_change() {
        let flows = FirstFlows::default();
        let claimed: Vec<_> = std::iter::from_fn(|| flows.claim()).collect();
        assert_eq!(claimed.len(), FIRST_FLOWS_REPORTED as usize);
        assert_eq!(claimed[0].ordinal, 1);
        assert_eq!(
            claimed.last().unwrap().ordinal,
            FIRST_FLOWS_REPORTED,
            "the ordinals count up"
        );
        assert!(flows.claim().is_none());

        flows.rearm(FirstFlowCause::Start);
        let after_restart = flows.claim().expect("a start rearms the reports");
        assert_eq!(after_restart.ordinal, 1);
        assert_eq!(after_restart.cause, FirstFlowCause::Start);
    }

    #[test]
    fn the_line_splits_the_open_into_lookup_and_dial() {
        let flows = FirstFlows::default();
        let mut timing = flows.claim().unwrap();
        timing.routed(Duration::from_millis(3));
        timing.resolve.store(
            Duration::from_millis(40).as_micros() as u64,
            Ordering::Release,
        );
        timing.opened(Duration::from_millis(1040));
        let line = timing.line(&target(), "proxy", FirstFlowOutcome::FirstByte);
        assert!(line.starts_with("First flow 1/8 after start: "), "{line}");
        assert!(line.contains("target=<redacted-ip>:443"), "{line}");
        assert!(
            line.contains("route=3ms resolve=40ms dial=1000ms"),
            "{line}"
        );
        assert!(line.contains("sniff=- "), "{line}");
        assert!(line.contains("firstByte="), "{line}");

        let failed = flows.claim().unwrap();
        let line = failed.line(
            &target(),
            "proxy",
            FirstFlowOutcome::OpenFailed("outbound open timed out after 10000 ms"),
        );
        assert!(
            line.contains("dial=- firstByte=- error=outbound open timed out"),
            "{line}"
        );
    }

    #[tokio::test]
    async fn a_timed_resolver_counts_its_lookups() {
        struct Slow;
        #[async_trait]
        impl DnsResolver for Slow {
            async fn resolve(&self, _: &str, port: u16) -> Result<SocketAddr, TransportError> {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(SocketAddr::from(([192, 0, 2, 1], port)))
            }
        }
        let flows = FirstFlows::default();
        let timing = flows.claim().unwrap();
        let slow = Slow;
        let timed = timing.timed(&slow);
        timed.resolve_all("server.test", 443).await.unwrap();
        assert!(
            timing.resolve.load(Ordering::Acquire) >= 20_000,
            "the lookup's time is counted"
        );
    }
}
