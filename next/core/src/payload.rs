//! Payloads: one flat enum per schema, the OSS variants plus an extension's
//! own, composed by [`compose_payload!`](crate::compose_payload).

use std::{fmt, net::IpAddr};

use linux_raw_sys::general as kernel;
use serde::Serialize;
use validatron::{MultiOperator, Operator, Validatron, ValidatronClass, ValidatronError};

/// A payload enum.
pub trait PayloadSet: Validatron + Serialize + Clone + fmt::Debug + Send + Sync + 'static {
    /// The enum with one fieldless variant per payload variant. OSS kinds
    /// convert into it, so a detector generic over the schema can name them.
    type Kind: PayloadKind + From<OssPayloadKind>;

    fn kind(&self) -> Self::Kind;
}

/// The kind of a payload: the name of its variant. Rules name it in `type`.
pub trait PayloadKind: Copy + Eq + std::hash::Hash + fmt::Debug + Send + Sync + 'static {
    /// In declaration order.
    const ALL: &'static [Self];

    fn name(self) -> &'static str;

    /// Position in [`ALL`](Self::ALL).
    fn index(self) -> usize;

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.name() == name)
    }
}

/// The kind enum of a schema's payload.
pub type KindOf<S> = <<S as crate::Schema>::Payload as PayloadSet>::Kind;

/// Declares a payload enum with every OSS variant followed by the given ones,
/// and its kind enum:
///
/// ```ignore
/// next_core::compose_payload! {
///     pub ExtPayload, kind = ExtPayloadKind {
///         SyscallActivity { total: u64, #[validatron(skip)] histogram: Vec<u64> },
///     }
/// }
/// ```
///
/// The payload enum derives `serde::Serialize` and `validatron::Validatron`,
/// so the calling crate depends on `serde` and `validatron`. It implements
/// [`PayloadSet`] and `From<OssPayload>`; the kind enum implements
/// [`PayloadKind`] and `From<OssPayloadKind>`.
///
/// With `kind = ExtPayloadKind, variants = ext_payload_variants`, it also
/// exports a macro that hands every variant to another one, for other crates,
/// such as the patterns of the test suite harness:
///
/// ```ignore
/// ext::ext_payload_variants! { @with path::to::macro [arguments] }
/// // expands to
/// path::to::macro! { arguments [FileCreated { .. }, .., SyscallActivity { .. },] }
/// ```
#[macro_export]
macro_rules! compose_payload {
    (
        $(#[$meta:meta])* $vis:vis $name:ident, kind = $kind:ident, variants = $macro:ident
        { $($variants:tt)* }
    ) => {
        $crate::compose_payload! { $(#[$meta])* $vis $name, kind = $kind { $($variants)* } }
        // `$` can't be written in the body of the new macro, so it is passed in.
        $crate::__oss_payload! { @with $crate::__variants_macro [($) $macro [$($variants)*]] }
    };
    (
        $(#[$meta:meta])* $vis:vis $name:ident, kind = $kind:ident { $($variants:tt)* }
    ) => {
        $crate::__oss_payload! { from_oss [$(#[$meta])* $vis $name $kind] [$($variants)*] }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __variants_macro {
    (($d:tt) $macro:ident [$($own:tt)*] [$($oss:tt)*]) => {
        #[macro_export]
        macro_rules! $macro {
            (@with $d callback:path [$d ($d args:tt)*]) => {
                $d callback! { $d ($d args)* [$($oss)* $($own)*] }
            };
        }
    };
}

// The OSS variants, written once. A macro can't read another enum's variants,
// so they are handed to the macro that needs them, after its own arguments:
// to __payload_enum, together with the caller's, or to any other macro with
// `@with path::to::macro [arguments]`.
#[doc(hidden)]
#[macro_export]
macro_rules! __oss_payload {
    ($mode:ident $head:tt $own:tt) => {
        $crate::__oss_payload! { @with $crate::__payload_enum [$mode $head $own] }
    };
    (@with $macro:path [$($args:tt)*]) => {
        $macro! { $($args)* [
            FileCreated { filename: Option<$crate::payload::Text> },
            FileDeleted { filename: Option<$crate::payload::Text> },
            DirCreated { dirname: Option<$crate::payload::Text> },
            DirDeleted { dirname: Option<$crate::payload::Text> },
            FileOpened { filename: Option<$crate::payload::Text>, flags: $crate::payload::FileFlags },
            FileLink {
                source: Option<$crate::payload::Text>,
                destination: Option<$crate::payload::Text>,
                hard_link: bool,
            },
            FileRename {
                source: Option<$crate::payload::Text>,
                destination: Option<$crate::payload::Text>,
            },
            ElfOpened { filename: Option<$crate::payload::Text>, flags: $crate::payload::FileFlags },
            Fork { ppid: u32, uid: u32, gid: u32 },
            Exec {
                filename: Option<$crate::payload::Text>,
                argc: usize,
                argv: Option<$crate::payload::Argv>,
            },
            Exit { exit_code: u32 },
            ChangeParent { ppid: u32 },
            CredentialsChange { uid: u32, gid: u32 },
            Bind { address: Option<$crate::payload::Host>, is_tcp: bool },
            Listen { address: Option<$crate::payload::Host> },
            Connect { destination: Option<$crate::payload::Host>, is_tcp: bool },
            Accept {
                source: Option<$crate::payload::Host>,
                destination: Option<$crate::payload::Host>,
            },
            Close {
                source: Option<$crate::payload::Host>,
                destination: Option<$crate::payload::Host>,
            },
            Receive {
                source: Option<$crate::payload::Host>,
                destination: Option<$crate::payload::Host>,
                len: usize,
                is_tcp: bool,
            },
            Send {
                source: Option<$crate::payload::Host>,
                destination: Option<$crate::payload::Host>,
                len: usize,
                is_tcp: bool,
            },
            DnsQuery {
                #[validatron(skip)]
                questions: Vec<$crate::payload::DnsQuestion>,
            },
            DnsResponse {
                #[validatron(skip)]
                questions: Vec<$crate::payload::DnsQuestion>,
                #[validatron(skip)]
                answers: Vec<$crate::payload::DnsAnswer>,
            },
        ] }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __payload_enum {
    (
        $mode:ident
        [$(#[$meta:meta])* $vis:vis $name:ident $kind:ident]
        [$( $(#[$vmeta:meta])* $var:ident {
            $( $(#[$fmeta:meta])* $field:ident : $fty:ty ),* $(,)?
        } ),* $(,)?]
        [$( $ovar:ident {
            $( $(#[$ofmeta:meta])* $ofield:ident : $ofty:ty ),* $(,)?
        } ),* $(,)?]
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, serde::Serialize, validatron::Validatron)]
        #[serde(tag = "type", content = "content")]
        $vis enum $name {
            $( $ovar { $( $(#[$ofmeta])* $ofield : $ofty ),* }, )*
            $( $(#[$vmeta])* $var { $( $(#[$fmeta])* $field : $fty ),* }, )*
        }

        impl $crate::payload::PayloadSet for $name {
            type Kind = $kind;

            fn kind(&self) -> $kind {
                match self {
                    $( Self::$ovar { .. } => $kind::$ovar, )*
                    $( Self::$var { .. } => $kind::$var, )*
                }
            }
        }

        #[doc = concat!("The kinds of [`", stringify!($name), "`].")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        $vis enum $kind {
            $( $ovar, )*
            $( $var, )*
        }

        impl $crate::payload::PayloadKind for $kind {
            const ALL: &'static [Self] = &[$( Self::$ovar, )* $( Self::$var, )*];

            fn name(self) -> &'static str {
                match self {
                    $( Self::$ovar => stringify!($ovar), )*
                    $( Self::$var => stringify!($var), )*
                }
            }

            fn index(self) -> usize {
                self as usize
            }
        }

        $crate::__payload_enum! { @$mode $name $kind [$( $ovar { $($ofield)* } )*] }
    };
    (@from_oss $name:ident $kind:ident [$( $ovar:ident { $($ofield:ident)* } )*]) => {
        impl From<$crate::payload::OssPayload> for $name {
            fn from(payload: $crate::payload::OssPayload) -> Self {
                match payload {
                    $( $crate::payload::OssPayload::$ovar { $($ofield),* } =>
                        Self::$ovar { $($ofield),* }, )*
                }
            }
        }

        impl From<$crate::payload::OssPayloadKind> for $kind {
            fn from(kind: $crate::payload::OssPayloadKind) -> Self {
                match kind {
                    $( $crate::payload::OssPayloadKind::$ovar => Self::$ovar, )*
                }
            }
        }
    };
    // OssPayload itself: both `From` conversions are the identity.
    (@oss $name:ident $kind:ident $variants:tt) => {};
}

crate::__oss_payload! { oss [
    /// The payloads of Pulsar's own probes.
    pub OssPayload OssPayloadKind
] [] }

/// A string the probe may have read only in part. Rules compare `value`.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Text {
    pub value: String,
    pub truncated: bool,
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}{}",
            self.value,
            if self.truncated { "..." } else { "" }
        )
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}",
            self.value,
            if self.truncated { "..." } else { "" }
        )
    }
}

impl Validatron for Text {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .primitive_class_builder(
                Box::new(|s| {
                    Ok(Text {
                        value: s.to_string(),
                        truncated: false,
                    })
                }),
                Box::new(|op| match op {
                    Operator::String(op) => Ok(Box::new(move |a: &Text, b: &Text| {
                        op.apply(&a.value, &b.value)
                    })),
                    Operator::Relational(op) => Ok(Box::new(move |a: &Text, b: &Text| {
                        op.apply(&a.value, &b.value)
                    })),
                    Operator::Multi(MultiOperator::Contains) => {
                        Ok(Box::new(|a: &Text, b: &Text| a.value.contains(&b.value)))
                    }
                }),
            )
            .build()
    }
}

/// Process arguments. Rules test them with CONTAINS.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Argv {
    pub args: Vec<String>,
    pub truncated: bool,
}

impl Validatron for Argv {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .primitive_class_builder(
                Box::new(|s| {
                    Ok(Argv {
                        args: vec![s.to_string()],
                        truncated: false,
                    })
                }),
                Box::new(|op| match op {
                    Operator::Multi(MultiOperator::Contains) => {
                        Ok(Box::new(|a: &Argv, b: &Argv| {
                            b.args.iter().all(|item| a.args.contains(item))
                        }))
                    }
                    _ => Err(ValidatronError::OperatorNotAllowedOnType(
                        op,
                        "Argv".to_string(),
                    )),
                }),
            )
            .build()
    }
}

/// Open flags. Rules test them with CONTAINS.
#[derive(Clone, PartialEq, Serialize)]
pub struct FileFlags(pub u32);

impl FileFlags {
    const ACC_MODE_FLAGS: [(&'static str, u32); 3] = [
        ("O_RDONLY", kernel::O_RDONLY),
        ("O_WRONLY", kernel::O_WRONLY),
        ("O_RDWR", kernel::O_RDWR),
    ];

    const OTHER_FLAGS: [(&'static str, u32); 7] = [
        ("O_CREAT", kernel::O_CREAT),
        ("O_EXCL", kernel::O_EXCL),
        ("O_NOCTTY", kernel::O_NOCTTY),
        ("O_TRUNC", kernel::O_TRUNC),
        ("O_APPEND", kernel::O_APPEND),
        ("O_NONBLOCK", kernel::O_NONBLOCK),
        ("O_DIRECTORY", kernel::O_DIRECTORY),
    ];

    /// What rules test with CONTAINS: `flag` is the access mode, or one of
    /// the other flags set.
    pub fn contains(&self, flag: &FileFlags) -> bool {
        if FileFlags::ACC_MODE_FLAGS
            .iter()
            .any(|(_, acc_mode_flag)| *acc_mode_flag == flag.0)
        {
            self.0 & kernel::O_ACCMODE == flag.0
        } else {
            self.0 & flag.0 > 0
        }
    }
}

impl Validatron for FileFlags {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .primitive_class_builder(
                Box::new(|s| {
                    FileFlags::ACC_MODE_FLAGS
                        .iter()
                        .chain(FileFlags::OTHER_FLAGS.iter())
                        .find(|(name, _)| *name == s)
                        .map(|(_, flag)| Self(*flag))
                        .ok_or_else(|| ValidatronError::FieldValueParseError(s.to_string()))
                }),
                Box::new(|op| match op {
                    Operator::Multi(MultiOperator::Contains) => {
                        Ok(Box::new(|a: &FileFlags, b: &FileFlags| a.contains(b)))
                    }
                    _ => Err(ValidatronError::OperatorNotAllowedOnType(
                        op,
                        "FileFlags".to_string(),
                    )),
                }),
            )
            .build()
    }
}

impl fmt::Debug for FileFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = self.0 & kernel::O_ACCMODE;
        let names: Vec<_> = FileFlags::ACC_MODE_FLAGS
            .iter()
            .filter(|(_, flag)| mode == *flag)
            .chain(
                FileFlags::OTHER_FLAGS
                    .iter()
                    .filter(|(_, flag)| self.0 & flag > 0),
            )
            .map(|(name, _)| *name)
            .collect();
        write!(f, "({})", names.join(","))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Validatron)]
pub struct Host {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: String,
    pub qclass: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    pub class: String,
    pub ttl: u32,
    pub data: String,
}
