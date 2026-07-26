//! [[SPEC-026 CON-004]] — the reconnect schedule. The pure core of the transport
//! resilience work: deterministic arithmetic with an injected random, no I/O, no
//! async, nothing imported from `chat`, `daemon`, or `local_api`.
//!
//! The hub is a SINGLE instance with an immediate deploy strategy, so every
//! redeploy replaces the machine and drops every socket at once. That fixes two
//! properties this schedule must have, both easy to get subtly wrong:
//!
//!   - it must **back off**, or a client whose hub is genuinely down becomes a
//!     retry loop against a machine that is trying to boot;
//!   - it must **spread**, because every client was dropped by the same event
//!     and would otherwise return in lockstep onto the one machine that just
//!     came up.
//!
//! Both are arithmetic with boundaries (the first delay, the doubling, the cap),
//! which is why they live here rather than inline in the transport loop.
//!
//! This mirrors `createBackoff` in cbcl-bus
//! (`apps/cbcl_chat/priv/web/chat-reconnect.mjs`) deliberately — the chat socket
//! and the browser socket are the same conversation seen from two clients, so
//! they come back on the same envelope (SPEC-026 ADR-002). The jitter is applied
//! **downward** for the same reason it is there: a delay can then never exceed
//! the ceiling the caller asked for, while clients still fan out across the
//! window.
//!
//! There is deliberately **no exhaustion condition** (SPEC-026 ADR-004). A bound
//! would reintroduce the very failure this exists to fix, only later: a hub down
//! for longer than the bound would still strand the agent. Visibility is the
//! legitimate concern behind an exhaustion bound, and it is met by the
//! `reconnecting` agent state carrying [`ReconnectSchedule::attempts`], not by
//! killing the agent.

use std::time::Duration;

/// The default first delay: one second, as in the browser client.
pub const DEFAULT_MIN: Duration = Duration::from_millis(1_000);
/// The default ceiling: fifteen seconds, as in the browser client.
pub const DEFAULT_MAX: Duration = Duration::from_millis(15_000);
/// The default jitter fraction: a delay is reduced by up to 25 % of its base.
pub const DEFAULT_JITTER: f64 = 0.25;

/// A bounded exponential backoff schedule with downward jitter.
#[derive(Debug, Clone)]
pub struct ReconnectSchedule {
    min: Duration,
    max: Duration,
    jitter: f64,
    /// The un-jittered delay of the last [`Self::next_delay`]; zero before the
    /// first, and after a [`Self::reset`].
    base: Duration,
    attempts: u32,
}

impl Default for ReconnectSchedule {
    fn default() -> Self {
        Self::new(DEFAULT_MIN, DEFAULT_MAX, DEFAULT_JITTER)
    }
}

impl ReconnectSchedule {
    /// A schedule doubling from `min` to a `max` ceiling, jittered downward by up
    /// to `jitter` of each base delay.
    ///
    /// `jitter` is clamped to `[0, 1]` and `max` is raised to `min` if the caller
    /// inverted them, so the post-conditions of CON-004 hold for every input
    /// rather than only for the well-formed ones. A schedule is not a trust
    /// boundary — there is no attacker here, only a caller — so clamping is the
    /// right response to a nonsensical bound, not a panic.
    pub fn new(min: Duration, max: Duration, jitter: f64) -> Self {
        Self {
            min,
            max: max.max(min),
            jitter: jitter.clamp(0.0, 1.0),
            base: Duration::ZERO,
            attempts: 0,
        }
    }

    /// How long to wait before the next attempt, advancing the schedule.
    ///
    /// `random` is supplied by the caller (a value in `[0, 1)`) rather than drawn
    /// here, so the spread is *exact* under test instead of merely probable —
    /// the same injection the browser's `createBackoff` uses. Values outside the
    /// range are clamped.
    ///
    /// Called once per scheduled attempt, never for reporting: use
    /// [`Self::at_ceiling`] and [`Self::attempts`] for that.
    pub fn next_delay(&mut self, random: f64) -> Duration {
        self.base = if self.base.is_zero() {
            self.min
        } else {
            (self.base * 2).min(self.max)
        };
        self.attempts = self.attempts.saturating_add(1);
        // [base * (1 - jitter), base] — always inside the ceiling, never negative.
        let scale = 1.0 - self.jitter * random.clamp(0.0, 1.0);
        self.base.mul_f64(scale)
    }

    /// A connection came up healthy: the next outage starts again at `min`.
    ///
    /// Without this, an agent whose hub flaps every few minutes would inherit the
    /// previous outage's ceiling and take the worst-case delay to notice each
    /// time.
    pub fn reset(&mut self) {
        self.base = Duration::ZERO;
        self.attempts = 0;
    }

    /// Attempts scheduled since construction or the last [`Self::reset`].
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Has the schedule reached its ceiling? The caller uses this to say "this is
    /// an outage, not a blip" exactly once, rather than narrating every attempt.
    pub fn at_ceiling(&self) -> bool {
        self.base >= self.max
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MAX, DEFAULT_MIN, ReconnectSchedule};
    use std::time::Duration;

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    /// TEST-002 (positive) — the base schedule doubles from the minimum to the
    /// ceiling and then stays there. `random = 0.0` means no jitter, so each
    /// returned delay IS its base.
    #[test]
    fn bases_double_from_the_minimum_to_the_ceiling() {
        let mut schedule = ReconnectSchedule::default();
        let delays: Vec<Duration> = (0..7).map(|_| schedule.next_delay(0.0)).collect();
        assert_eq!(
            delays,
            vec![
                ms(1_000),
                ms(2_000),
                ms(4_000),
                ms(8_000),
                ms(15_000),
                ms(15_000),
                ms(15_000),
            ],
            "1s doubling to a 15s ceiling, matching the browser's createBackoff"
        );
    }

    /// TEST-002 (positive) — jitter is applied DOWNWARD: a full random draw
    /// removes the whole jitter fraction, never adds to the base.
    #[test]
    fn jitter_reduces_the_delay_and_never_raises_it() {
        let mut schedule = ReconnectSchedule::default();
        // random -> 1.0 removes the full 25 %.
        assert_eq!(
            schedule.next_delay(1.0),
            ms(750),
            "a full draw takes 25 % off the 1000 ms base"
        );
        assert_eq!(
            schedule.next_delay(0.5),
            ms(1_750),
            "a half draw takes 12.5 % off the 2000 ms base"
        );

        let mut at_ceiling = ReconnectSchedule::default();
        for _ in 0..5 {
            at_ceiling.next_delay(0.0);
        }
        assert!(at_ceiling.at_ceiling());
        assert_eq!(
            at_ceiling.next_delay(1.0),
            ms(11_250),
            "at the ceiling a full draw still only subtracts: 15000 * 0.75"
        );
    }

    /// TEST-002 (negative-output) — the property that matters for the hub: no
    /// delay this schedule can produce exceeds the ceiling or is negative, for
    /// any random draw across the whole domain and any point in the schedule.
    /// A jitter applied *around* the base rather than below it would fail this.
    #[test]
    fn no_delay_ever_exceeds_the_ceiling_or_goes_negative() {
        for step in 0..64u32 {
            for draw in 0..=100u32 {
                let random = f64::from(draw) / 100.0;
                let mut schedule = ReconnectSchedule::default();
                for _ in 0..step {
                    schedule.next_delay(0.0);
                }
                let delay = schedule.next_delay(random);
                assert!(
                    delay <= DEFAULT_MAX,
                    "step {step} draw {random}: {delay:?} exceeded the {DEFAULT_MAX:?} ceiling"
                );
                // Duration cannot be negative, so the real risk is a wrapped or
                // absurdly small value: the floor is base * (1 - jitter).
                assert!(
                    delay >= DEFAULT_MIN.mul_f64(0.75),
                    "step {step} draw {random}: {delay:?} fell below the jitter floor"
                );
            }
        }
    }

    /// TEST-002 (positive) — a healthy connection resets the schedule, so the
    /// next outage starts at the minimum rather than inheriting the last
    /// outage's ceiling.
    #[test]
    fn reset_returns_the_schedule_to_the_minimum() {
        let mut schedule = ReconnectSchedule::default();
        for _ in 0..6 {
            schedule.next_delay(0.0);
        }
        assert!(schedule.at_ceiling());
        assert_eq!(schedule.attempts(), 6);

        schedule.reset();

        assert!(!schedule.at_ceiling(), "reset clears the ceiling flag");
        assert_eq!(schedule.attempts(), 0, "reset zeroes the attempt count");
        assert_eq!(
            schedule.next_delay(0.0),
            ms(1_000),
            "the next outage starts again at the minimum"
        );
    }

    /// TEST-002 (positive) — `attempts()` counts scheduled attempts, and
    /// `at_ceiling()` flips exactly when the base first reaches the maximum,
    /// not before and not a step late.
    #[test]
    fn attempts_counts_and_at_ceiling_flips_exactly_at_the_maximum() {
        let mut schedule = ReconnectSchedule::default();
        assert_eq!(schedule.attempts(), 0);
        assert!(
            !schedule.at_ceiling(),
            "a fresh schedule is not at its ceiling"
        );

        for (index, expected_base) in [1_000u64, 2_000, 4_000, 8_000].into_iter().enumerate() {
            schedule.next_delay(0.0);
            assert_eq!(schedule.attempts(), index as u32 + 1);
            assert!(
                !schedule.at_ceiling(),
                "base {expected_base} ms is below the 15000 ms ceiling"
            );
        }
        schedule.next_delay(0.0);
        assert!(schedule.at_ceiling(), "the fifth attempt reaches 15000 ms");
        assert_eq!(schedule.attempts(), 5);
    }

    /// TEST-002 (negative-input) — a caller that inverts the bounds or passes a
    /// nonsensical jitter still gets a schedule obeying the CON-004
    /// post-conditions, rather than a panic or a delay above the ceiling.
    #[test]
    fn degenerate_bounds_are_clamped_rather_than_trusted() {
        let mut inverted = ReconnectSchedule::new(ms(5_000), ms(100), 0.25);
        let delay = inverted.next_delay(0.0);
        assert_eq!(
            delay,
            ms(5_000),
            "max is raised to min rather than producing a ceiling below the floor"
        );
        assert!(inverted.at_ceiling(), "min == max means immediately capped");

        let mut absurd_jitter = ReconnectSchedule::new(ms(1_000), ms(2_000), 9.0);
        assert_eq!(
            absurd_jitter.next_delay(1.0),
            Duration::ZERO,
            "jitter clamps to 1.0, so the floor is zero — never negative"
        );

        let mut negative_jitter = ReconnectSchedule::new(ms(1_000), ms(2_000), -1.0);
        assert_eq!(
            negative_jitter.next_delay(1.0),
            ms(1_000),
            "a negative jitter clamps to 0, so the delay is exactly the base"
        );
    }
}
