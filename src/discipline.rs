use std::collections::VecDeque;

pub const STEP_THRESHOLD: f64 = 0.128;
/// Largest rate correction ever applied - 500 ppm
pub const MAX_RATE: f64 = 500e-6;
/// Points kept for measuring frequency (~17 min at 64 s polls)
pub const WINDOW: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    /// Jump the clock by this many seconds, then apply [`Discipline::rate`]
    Step(f64),
    /// Apply [`Discipline::rate`]
    Slew,
}

pub struct Discipline {
    /// Loop time constant in seconds
    tau: f64,
    /// Estimated rate correction that cancels the clock's own error
    freq: Option<f64>,
    /// Recent points, oldest first
    history: VecDeque<Point>,
    /// Rate currently applied to the clock
    rate: f64,
}

/// From `t` on, `rate` was applied. `offset` is `None` for holdovers.
struct Point {
    t: f64,
    offset: Option<f64>,
    rate: f64,
}

impl Discipline {
    pub fn new(poll_secs: f64) -> Self {
        Self {
            tau: 4.0 * poll_secs,
            freq: None,
            history: VecDeque::new(),
            rate: 0.0,
        }
    }

    /// Frequency correction once calibrated (54e-6 = 54 ppm faster)
    pub fn freq(&self) -> Option<f64> {
        self.freq
    }

    /// Rate correction to apply until the next update
    pub fn rate(&self) -> f64 {
        self.rate
    }

    pub fn update(&mut self, t: f64, offset: f64) -> Action {
        if offset.abs() > STEP_THRESHOLD {
            self.freq = None;
            self.history.clear();
            self.rate = 0.0;
            // Right after the step the offset is ~0
            self.push(t, Some(0.0));
            return Action::Step(offset);
        }

        if let Some(freq) = self.measure_freq(t, offset) {
            self.freq = Some(freq.clamp(-MAX_RATE, MAX_RATE));
        }
        let freq = self.freq.unwrap_or(0.0);
        self.rate = (freq + offset / self.tau).clamp(-MAX_RATE, MAX_RATE);
        self.push(t, Some(offset));
        Action::Slew
    }

    /// No measurement this poll: stop slewing and only correct the frequency
    pub fn holdover(&mut self, t: f64) -> f64 {
        self.rate = self.freq.unwrap_or(0.0);
        self.push(t, None);
        self.rate
    }

    /// Offset θ changes at `-(e + rate)`, so between the oldest point and now
    /// `θ_now - θ_0 = -e·Δt - Σ rate·dt`, and the needed correction is `-e`.
    fn measure_freq(&self, t: f64, offset: f64) -> Option<f64> {
        let first = self.history.front()?;
        let first_offset = first.offset?;
        if t <= first.t {
            return None;
        }
        let ends = self.history.iter().skip(1).map(|p| p.t).chain([t]);
        let corrected: f64 = self
            .history
            .iter()
            .zip(ends)
            .map(|(p, end)| p.rate * (end - p.t))
            .sum();
        Some((offset - first_offset + corrected) / (t - first.t))
    }

    fn push(&mut self, t: f64, offset: Option<f64>) {
        self.history.push_back(Point {
            t,
            offset,
            rate: self.rate,
        });
        while self.history.len() > WINDOW
            || self.history.front().is_some_and(|p| p.offset.is_none())
        {
            self.history.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLL: f64 = 64.0;

    /// Simulates a clock with frequency error `e` starting `x0` s behind the server - returns the discipline and the true offset after each poll
    fn simulate(
        e: f64,
        x0: f64,
        polls: usize,
        noise: impl Fn(usize) -> f64,
    ) -> (Discipline, Vec<f64>) {
        let mut d = Discipline::new(POLL);
        let mut x = x0;
        let mut history = Vec::new();
        for k in 0..polls {
            if let Action::Step(o) = d.update(k as f64 * POLL, x + noise(k)) {
                x -= o;
            }
            x -= (e + d.rate()) * POLL;
            history.push(x);
        }
        (d, history)
    }

    #[test]
    fn steps_then_learns_drift() {
        // This machine: ~54 ppm fast, 0.85 s ahead
        let (d, history) = simulate(54e-6, -0.85, 80, |_| 0.0);
        let freq = d.freq().unwrap();
        assert!((freq + 54e-6).abs() < 0.2e-6, "freq {freq}");
        assert!(history.last().unwrap().abs() < 5e-6, "{history:?}");
    }

    #[test]
    fn small_offset_is_slewed_not_stepped() {
        let mut d = Discipline::new(POLL);
        assert_eq!(d.update(0.0, 0.010), Action::Slew);
        assert_eq!(d.rate(), 0.010 / (4.0 * POLL));
    }

    #[test]
    fn converges_with_noisy_measurements() {
        // ±0.5 ms of measurement noise, pseudo-random
        let noise = |k: usize| ((k * 7919 % 1000) as f64 / 1000.0 - 0.5) * 1e-3;
        let (d, history) = simulate(54e-6, 0.05, 200, noise);
        let freq = d.freq().unwrap();
        assert!((freq + 54e-6).abs() < 2e-6, "freq {freq}");
        let worst = history[150..].iter().fold(0f64, |m, x| m.max(x.abs()));
        assert!(worst < 0.5e-3, "worst {worst}");
    }

    #[test]
    fn step_after_calibration_recalibrates() {
        let mut d = Discipline::new(POLL);
        d.update(0.0, 0.0);
        d.update(POLL, -0.003);
        assert!(d.freq().is_some());
        assert_eq!(d.update(2.0 * POLL, -0.2), Action::Step(-0.2));
        assert_eq!((d.freq(), d.rate()), (None, 0.0));
    }

    #[test]
    fn rate_is_clamped() {
        // -100 ms in one poll is -1560 ppm
        let mut d = Discipline::new(POLL);
        d.update(0.0, 0.0);
        d.update(POLL, -0.1);
        assert_eq!(d.freq(), Some(-MAX_RATE));
        assert_eq!(d.rate(), -MAX_RATE);
    }

    #[test]
    fn holdover_drops_phase_correction() {
        let mut d = Discipline::new(POLL);
        d.update(0.0, 0.0);
        d.update(POLL, -0.003);
        assert_ne!(d.rate(), d.freq().unwrap());
        assert_eq!(d.holdover(2.0 * POLL), d.freq().unwrap());
    }

    #[test]
    fn large_offset_does_not_overshoot() {
        // The service's first real run: 127.9 ms ahead, just under the step threshold
        let (d, history) = simulate(55e-6, -0.127937, 30, |_| 0.0);
        let overshoot = history.iter().fold(f64::MIN, |m, &x| m.max(x));
        assert!(overshoot < 0.0, "overshoot {overshoot}");
        assert!((d.freq().unwrap() + 55e-6).abs() < 1e-9);
        assert!(history.last().unwrap().abs() < 1e-3, "{history:?}");
    }

    #[test]
    fn holdover_is_accounted_for() {
        // A missed poll at a different rate mustn't bias the next frequency measurement
        let e = 40e-6;
        let mut d = Discipline::new(POLL);
        let mut x = 0.01;
        for k in 0..6 {
            let t = k as f64 * POLL;
            if k == 3 {
                d.holdover(t);
            } else {
                d.update(t, x);
            }
            x -= (e + d.rate()) * POLL;
        }
        assert!((d.freq().unwrap() + e).abs() < 1e-9, "{:?}", d.freq());
    }
}
