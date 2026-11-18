//! Test outcomes on top of libtest-mimic, which only knows pass and fail.

use std::{fmt, future::Future, pin::Pin};

use libtest_mimic::{Failed, Trial};

/// `Err` when the test couldn't run: a setup step failed, a helper panicked,
/// the daemon failed. Such a test is broken: it always fails, even when a
/// failure is expected, so an expected failure can't hide a broken test.
pub type TestResult = anyhow::Result<Outcome>;

/// What a test that ran found.
pub struct Outcome {
    pub verdict: Verdict,
    /// Records lost or invalid while the test ran. Any of them makes the test
    /// fail as incomplete, whatever the verdict, since the verdict was found
    /// on incomplete events. The verdict is still reported.
    pub lost: u64,
    pub invalid: u64,
}

/// What the checks of a test found.
pub enum Verdict {
    Passed,
    Failed(String),
}

type TestFn = fn() -> Pin<Box<dyn Future<Output = TestResult>>>;

pub struct Test {
    name: &'static str,
    run: TestFn,
    expected_failure: Option<ExpectedFailure>,
}

/// A known bug that makes a test fail.
struct ExpectedFailure {
    reason: &'static str,
    issue: Option<u32>,
}

impl Test {
    pub fn new(name: &'static str, run: TestFn) -> Self {
        Self {
            name,
            run,
            expected_failure: None,
        }
    }

    /// The test passes while it fails, and fails once it passes, so the
    /// marker goes away with the bug.
    pub fn expected_failure(mut self, reason: &'static str, issue: Option<u32>) -> Self {
        self.expected_failure = Some(ExpectedFailure { reason, issue });
        self
    }

    fn execute(self) -> Result<(), Failed> {
        // A runtime per test: nothing a test leaves running reaches the next.
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| format!("broken: starting tokio: {err}"))?;
        let Outcome {
            verdict,
            lost,
            invalid,
        } = runtime
            .block_on((self.run)())
            .map_err(|err| format!("broken: {err:#}"))?;
        if lost > 0 || invalid > 0 {
            let checks = match verdict {
                Verdict::Passed => "the checks passed".to_owned(),
                Verdict::Failed(report) => format!("the checks failed:\n{report}"),
            };
            return Err(
                format!("incomplete: {lost} records lost, {invalid} invalid; {checks}").into(),
            );
        }
        match (verdict, self.expected_failure) {
            (Verdict::Passed, None) => Ok(()),
            (Verdict::Failed(report), None) => Err(report.into()),
            (Verdict::Failed(_), Some(_)) => Ok(()),
            (Verdict::Passed, Some(expected)) => {
                Err(format!("passed, but expected to fail: {expected}. Remove the marker.").into())
            }
        }
    }
}

impl fmt::Display for ExpectedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)?;
        if let Some(issue) = self.issue {
            write!(f, " (https://github.com/exein-io/pulsar/issues/{issue})")?;
        }
        Ok(())
    }
}

pub fn trials(tests: Vec<Test>) -> Vec<Trial> {
    tests
        .into_iter()
        .map(|test| {
            let expected_failure = test.expected_failure.is_some();
            let trial = Trial::test(test.name, move || test.execute());
            if expected_failure {
                trial.with_kind("xfail")
            } else {
                trial
            }
        })
        .collect()
}
