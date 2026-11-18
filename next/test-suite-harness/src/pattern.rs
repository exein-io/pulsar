//! The events a test expects: a type per payload kind, named after it, with a
//! setter per field. Fields left unset may be anything.
//!
//! ```ignore
//! Fork::of(child).ppid(parent).header(|header| header.image(path).uid(0))
//! ```
//!
//! The types are made from the declaration of the payload, so they have every
//! kind and every field the payload has. Those here are of [`OssPayload`]. A
//! payload composed with `variants = ext_payload_variants` gets its own in the
//! crate of its tests, with [`patterns!`](crate::patterns):
//!
//! ```ignore
//! ext::ext_payload_variants! { @with next_test_suite_harness::patterns [ext::ExtPayload] }
//! ```
//!
//! The types are named after the variants, and one is `Send`: import them by
//! name, not with `*`.

use std::time::SystemTime;

use next_core::{
    event::{self, Container, Subject},
    payload::Text,
};

#[cfg(doc)]
use next_core::payload::OssPayload;

use crate::{
    expect::Field,
    matcher::{IntoMatcher, Matcher, check},
};

/// Makes the pattern types of a payload. Its variants come from next-core,
/// after the path of the payload.
#[macro_export]
macro_rules! patterns {
    ($payload:path [$( $(#[$vmeta:meta])* $variant:ident {
        $( $(#[$fmeta:meta])* $field:ident : $type:ty ),* $(,)?
    } ),* $(,)?]) => {
        // A `path` fragment can't be extended with `::$variant`, so the
        // payload gets a name of its own.
        type __Payload = $payload;
    $(
        #[doc = concat!("A `", stringify!($variant), "` event.")]
        #[allow(dead_code, reason = "every kind gets a type, used or not")]
        pub struct $variant {
            pid: u32,
            header: $crate::pattern::Header,
            $( $field: Option<$crate::matcher::Matcher<$type>>, )*
        }

        #[allow(dead_code, reason = "every field gets a setter, used or not")]
        #[allow(clippy::wrong_self_convention, reason = "setters are named after fields: `is_tcp`")]
        impl $variant {
            /// An event about the process `pid`.
            pub fn of(pid: u32) -> Self {
                Self {
                    pid,
                    header: Default::default(),
                    $( $field: None, )*
                }
            }

            /// Sets fields of the header: `.header(|header| header.uid(0))`.
            pub fn header(
                mut self,
                set: impl FnOnce($crate::pattern::Header) -> $crate::pattern::Header,
            ) -> Self {
                self.header = set(self.header);
                self
            }

            $(
                pub fn $field(mut self, $field: impl $crate::matcher::IntoMatcher<$type>) -> Self {
                    self.$field = Some($field.into_matcher());
                    self
                }
            )*
        }

        impl $crate::expect::Pattern<__Payload> for $variant {
            fn kind(&self) -> &'static str {
                stringify!($variant)
            }

            fn pid(&self) -> u32 {
                self.pid
            }

            fn fields(
                &self,
                event: &$crate::__next_core::event::Event<__Payload>,
            ) -> Option<Vec<$crate::expect::Field>> {
                let __Payload::$variant { $( $field ),* } = &event.payload else {
                    return None;
                };
                let mut fields = self.header.fields(&event.header)?;
                $( $crate::matcher::check(&mut fields, stringify!($field), &self.$field, $field); )*
                Some(fields)
            }
        }
    )* };
}

next_core::__oss_payload! { @with crate::patterns [next_core::payload::OssPayload] }

/// What a pattern expects of the header. The pid of the subject is the
/// pattern's own.
#[derive(Default)]
pub struct Header {
    timestamp: Option<Matcher<SystemTime>>,
    source: Option<Matcher<&'static str>>,
    ppid: Option<Matcher<u32>>,
    uid: Option<Matcher<u32>>,
    gid: Option<Matcher<u32>>,
    start_time: Option<Matcher<u64>>,
    exec_id: Option<Matcher<u64>>,
    cgroup_id: Option<Matcher<u64>>,
    image: Option<Matcher<Option<Text>>>,
    container: Option<Matcher<Option<Container>>>,
    fork_time: Option<Matcher<Option<SystemTime>>>,
}

macro_rules! setters {
    ($( $(#[$meta:meta])* $field:ident : $type:ty ),* $(,)?) => { $(
        $(#[$meta])*
        pub fn $field(mut self, $field: impl IntoMatcher<$type>) -> Self {
            self.$field = Some($field.into_matcher());
            self
        }
    )* };
}

impl Header {
    setters! {
        timestamp: SystemTime,
        /// The probe that wrote the record.
        source: &'static str,
        /// The parent of the subject.
        ppid: u32,
        uid: u32,
        gid: u32,
        start_time: u64,
        exec_id: u64,
        cgroup_id: u64,
        image: Option<Text>,
        container: Option<Container>,
        fork_time: Option<SystemTime>,
    }

    /// `None` when the event is about no process.
    #[doc(hidden)]
    pub fn fields(&self, header: &event::Header) -> Option<Vec<Field>> {
        let event::Header {
            timestamp,
            source,
            subject,
            image,
            container,
            fork_time,
        } = header;
        let Subject {
            pid: _,
            ppid,
            uid,
            gid,
            start_time,
            exec_id,
            cgroup_id,
        } = subject.as_ref()?;
        let mut fields = Vec::new();
        check(&mut fields, "header.timestamp", &self.timestamp, timestamp);
        check(&mut fields, "header.source", &self.source, source);
        check(&mut fields, "header.ppid", &self.ppid, ppid);
        check(&mut fields, "header.uid", &self.uid, uid);
        check(&mut fields, "header.gid", &self.gid, gid);
        check(
            &mut fields,
            "header.start_time",
            &self.start_time,
            start_time,
        );
        check(&mut fields, "header.exec_id", &self.exec_id, exec_id);
        check(&mut fields, "header.cgroup_id", &self.cgroup_id, cgroup_id);
        check(&mut fields, "header.image", &self.image, image);
        check(&mut fields, "header.container", &self.container, container);
        check(&mut fields, "header.fork_time", &self.fork_time, fork_time);
        Some(fields)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::SystemTime};

    use next_core::{
        event::{Event, Header, Subject},
        payload::{Argv, Text},
        processor::Stats,
    };

    use crate::{
        Verdict,
        daemon::Recording,
        expect::expect,
        matcher::{contains, ends_with, ge, gt, le, lt, ne, satisfies, starts_with},
    };

    next_core::compose_payload! {
        pub TestPayload, kind = TestPayloadKind, variants = test_payload_variants {
            Custom { count: u64 },
        }
    }

    test_payload_variants! { @with crate::patterns [self::TestPayload] }

    const PID: u32 = 7;

    fn recording(payloads: Vec<TestPayload>) -> Recording<TestPayload> {
        let header = Header {
            timestamp: SystemTime::UNIX_EPOCH,
            source: "test",
            subject: Some(Subject {
                pid: PID,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                start_time: 5,
                exec_id: 2,
                cgroup_id: 3,
            }),
            image: Some(Text {
                value: "/usr/bin/true".to_owned(),
                truncated: false,
            }),
            container: None,
            fork_time: None,
        };
        let events = payloads
            .into_iter()
            .map(|payload| {
                Arc::new(Event {
                    header: header.clone(),
                    payload,
                })
            })
            .collect();
        Recording {
            events,
            stats: Stats::default(),
        }
    }

    #[test]
    fn composed_payload_has_its_own_and_oss_kinds() {
        let recording = recording(vec![
            TestPayload::Exec {
                filename: Some(Text {
                    value: "/usr/bin/true".to_owned(),
                    truncated: false,
                }),
                argc: 2,
                argv: Some(Argv {
                    args: vec!["true".to_owned(), "-v".to_owned()],
                    truncated: false,
                }),
            },
            TestPayload::Custom { count: 3 },
        ]);
        let outcome = expect(
            &recording,
            &[
                &Exec::of(PID).filename("/usr/bin/true").argv(contains("-v")),
                &Custom::of(PID).count(3),
            ],
        );
        assert!(matches!(outcome.verdict, Verdict::Passed));
    }

    #[test]
    fn every_comparison() {
        let recording = recording(vec![TestPayload::Custom { count: 3 }]);
        let outcome = expect(
            &recording,
            &[&Custom::of(PID)
                .count(ne(4))
                .count(gt(2))
                .count(lt(4))
                .count(ge(3))
                .count(le(3))
                .count(satisfies("odd", |count| count % 2 == 1))
                .header(|header| {
                    header
                        .uid(1000)
                        .source("test")
                        .image(starts_with("/usr"))
                        .image(ends_with("true"))
                        .image(contains("bin"))
                        .image(ne("/usr/bin/false"))
                        .container(None)
                })],
        );
        assert!(matches!(outcome.verdict, Verdict::Passed));
    }

    #[test]
    fn mismatch_names_the_field() {
        let recording = recording(vec![TestPayload::Custom { count: 3 }]);
        let outcome = expect(
            &recording,
            &[&Custom::of(PID).count(gt(3)).header(|header| header.uid(0))],
        );
        let Verdict::Failed(report) = outcome.verdict else {
            panic!("the pattern matched");
        };
        assert!(
            report.contains("✗ count: expected > 3, found 3"),
            "{report}"
        );
        assert!(
            report.contains("✗ header.uid: expected 0, found 1000"),
            "{report}"
        );
    }
}
