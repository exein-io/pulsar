//! This module checks what features are supported by the runnig kernel
pub mod kernel_version;
pub mod lsm;

#[cfg(feature = "test-suite")]
pub mod test_suite {
    use crate::test_runner::{TestCase, TestReport, TestSuite};

    use super::lsm::lsm_supported;

    pub fn tests() -> TestSuite {
        TestSuite {
            name: "feature_autodetect",
            tests: vec![lsm()],
        }
    }

    fn lsm() -> TestCase {
        TestCase::new("lsm", async {
            TestReport {
                success: lsm_supported().await,
                lines: vec![],
            }
        })
    }
}
