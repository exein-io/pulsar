//! Histogram is an utility struct for quickly printing how often something happens.
//!
//! Example usage:
//! ```
//! let mut histogram = Histogram::new(Duration::from_secs(1), 0.3);
//! histogram.sample();
//! ```

use std::time::{Duration, Instant};

pub struct Histogram {
    /// Last time an output line was emitted
    last_output: Instant,
    /// Events counter since the last output
    counter: u32,
    /// How to go from counter to number of characters in graph
    display_factor: f32,
    /// How to go from counter to number of characters in graph
    interval: Duration,
}

impl Histogram {
    pub fn new(interval: Duration, display_factor: f32) -> Self {
        Self {
            last_output: Instant::now(),
            counter: 0,
            display_factor,
            interval,
        }
    }

    pub fn sample(&mut self) {
        while self.last_output.elapsed() > self.interval {
            let n = (self.counter as f32).sqrt();
            println!("{} ({})", "#".repeat(n as usize), self.counter);
            self.counter = 0;
            self.last_output += self.interval;
        }
        self.counter += 1;
    }
}
