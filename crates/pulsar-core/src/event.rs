use std::{
    fmt::{self, Display},
    net::IpAddr,
    time::SystemTime,
};

use bpf_common::containers::ContainerInfo;
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, ser, Deserialize, Serialize};
use strum::{EnumDiscriminants, EnumString};
use validatron::{Operator, Validatron, ValidatronError};

use crate::{
    kernel::{self},
    pdk::ModuleName,
};

#[derive(Debug, Clone, Serialize, Deserialize, Validatron)]
pub struct Event {
    pub(crate) header: Header,
    pub(crate) payload: Payload,
}

impl Event {
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header = self.header();
        let time = DateTime::<Utc>::from(header.timestamp).format("%Y-%m-%dT%TZ");
        let image = &header.image;
        let pid = &header.pid;
        let payload = self.payload();

        let process_info = match header.container {
            Some(ref container) => {
                let container_image = &container.image;
                let container_image_digest = &container.image_digest;

                format!("{container_image} {container_image_digest} {image} ({pid})")
            }
            None => format!("{image} ({pid})"),
        };

        if let Some(Threat {
            source,
            description,
            extra: _,
        }) = &self.header().threat
        {
            if f.alternate() {
                writeln!(f, "[{time} \x1b[1;30;43mTHREAT\x1b[0m {process_info}] [{source} - {description}] {payload}")
            } else {
                writeln!(
                    f,
                    "[{time} THREAT {process_info}] [{source} - {description}] {payload}"
                )
            }
        } else {
            let source = &header.source;
            if f.alternate() {
                writeln!(
                    f,
                    "[{time} \x1b[1;30;46mEVENT\x1b[0m {process_info}] [{source}] {payload}"
                )
            } else {
                writeln!(f, "[{time} EVENT {process_info}] [{source}] {payload}")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validatron)]
pub struct Header {
    pub image: String,
    pub pid: i32,
    pub parent_pid: i32,
    #[validatron(skip)]
    pub container: Option<ContainerInfo>,
    #[validatron(skip)]
    pub threat: Option<Threat>,
    pub source: ModuleName,
    #[validatron(skip)]
    pub timestamp: SystemTime,
    #[validatron(skip)]
    pub fork_time: SystemTime,
}

/// Representation of event threat information.
///
/// When an [`Event`] contains this information it should be considered
/// a "threat event".
///
/// It contains the name of the module that has identified the threat, a human
/// readable description and custom additional information respectively in the
/// `source`, `description` and `info` fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub source: ModuleName,
    pub description: String,
    pub extra: Option<Value>,
}

impl Display for Threat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write! {f, "{{ source: {}, info: {} }}", self.source, self.description}
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Value(toml_edit::easy::Value);

impl Value {
    /// Convert a `T` into `Value` which is an enum that can represent
    /// any valid TOML data.
    ///
    /// This conversion can fail if `T`'s implementation of `Serialize` decides to
    /// fail, or if `T` contains a map with non-string keys.
    pub fn try_from<T>(value: T) -> Result<Value, String>
    where
        T: ser::Serialize,
    {
        toml_edit::easy::Value::try_from(value)
            .map(Self)
            .map_err(|err| err.to_string())
    }

    /// Interpret a `Value` as an instance of type `T`.
    ///
    /// This conversion can fail if the structure of the `Value` does not match the
    /// structure expected by `T`, for example if `T` is a struct type but the
    /// `Value` contains something other than a TOML table. It can also fail if the
    /// structure is correct but `T`'s implementation of `Deserialize` decides that
    /// something is wrong with the data, for example required struct fields are
    /// missing from the TOML map or some number is too big to fit in the expected
    /// primitive type.
    pub fn try_into<T>(self) -> Result<T, String>
    where
        T: DeserializeOwned,
    {
        toml_edit::easy::Value::try_into(self.0).map_err(|err| err.to_string())
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let multi_lines = self.0.to_string();
        let one_line = multi_lines
            .split('\n')
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>()
            .join(", ");
        write!(f, "{{ {one_line} }}")
    }
}

/// This blanket implementation allows to use standard types as [`Value`]
/// without a serialization step.
///
/// The implementation relies on the conversion implementation of
/// [`toml_edit::easy::Value`] for the standard types.
impl<T: Into<toml_edit::easy::Value>> From<T> for Value {
    fn from(t: T) -> Self {
        Self(t.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validatron, EnumDiscriminants)]
#[serde(tag = "type", content = "content")]
#[strum_discriminants(derive(EnumString, Hash))]
#[strum_discriminants(name(PayloadDiscriminant))]
pub enum Payload {
    FileCreated {
        filename: String,
    },
    FileDeleted {
        filename: String,
    },
    DirCreated {
        dirname: String,
    },
    DirDeleted {
        dirname: String,
    },
    FileOpened {
        filename: String,
        flags: FileFlags,
    },
    FileLink {
        source: String,
        destination: String,
        hard_link: bool,
    },
    FileRename {
        source: String,
        destination: String,
    },
    ElfOpened {
        filename: String,
        flags: FileFlags,
    },
    Fork {
        ppid: i32,
    },
    Exec {
        filename: String,
        argc: usize,
        argv: Argv,
    },
    Exit {
        exit_code: u32,
    },
    ChangeParent {
        ppid: i32,
    },
    CgroupCreated {
        cgroup_path: String,
        cgroup_id: u64,
    },
    CgroupDeleted {
        cgroup_path: String,
        cgroup_id: u64,
    },
    CgroupAttach {
        cgroup_path: String,
        cgroup_id: u64,
        attached_pid: i32,
    },
    SyscallActivity {
        #[validatron(skip)]
        histogram: Vec<u64>,
    },
    Bind {
        address: Host,
        is_tcp: bool,
    },
    Listen {
        address: Host,
    },
    Connect {
        destination: Host,
        is_tcp: bool,
    },
    Accept {
        source: Host,
        destination: Host,
    },
    Close {
        source: Host,
        destination: Host,
    },
    Receive {
        source: Host,
        destination: Host,
        len: usize,
        is_tcp: bool,
    },
    DnsQuery {
        #[validatron(skip)]
        questions: Vec<DnsQuestion>,
    },
    DnsResponse {
        #[validatron(skip)]
        questions: Vec<DnsQuestion>,
        #[validatron(skip)]
        answers: Vec<DnsAnswer>,
    },
    Send {
        source: Host,
        destination: Host,
        len: usize,
        is_tcp: bool,
    },
    Custom {
        #[validatron(skip)]
        description: String,
        #[validatron(skip)]
        value: Value,
    },
    #[validatron(skip)]
    Empty,
}

impl fmt::Display for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Payload::FileCreated { filename } => write!(f,"File Created {{ filename: {filename} }}"),
            Payload::FileDeleted { filename } => write!(f,"File Deleted {{ filename: {filename} }}"),
            Payload::DirCreated { dirname } => write!(f,"Dir Created {{ dirname: {dirname} }}"),
            Payload::DirDeleted { dirname } => write!(f,"Dir Deleted {{ dirname: {dirname} }}"),
            Payload::FileOpened { filename, flags } => write!(f,"File Opened {{ filename: {filename}, flags:{flags} }}"),
            Payload::FileLink { source, destination, hard_link } => write!(f,"File Link {{ source: {source}, destination: {destination}, hard_link: {hard_link} }}"),
            Payload::FileRename { source, destination } => write!(f,"File Rename {{ source: {source}, destination {destination} }}"),
            Payload::ElfOpened { filename, flags } => write!(f,"Elf Opened {{ filename: {filename}, flags: {flags} }}"),
            Payload::Fork { ppid } => write!(f,"Fork {{ ppid: {ppid} }}"),
            Payload::Exec { filename, argc, argv } => write!(f,"Exec {{ filename: {filename}, argc: {argc}, argv: {argv} }}"),
            Payload::Exit { exit_code } => write!(f,"Exit {{ exit_code: {exit_code} }}"),
            Payload::ChangeParent { ppid } => write!(f,"Parent changed {{ ppid: {ppid} }}"),
            Payload::CgroupCreated { cgroup_path, cgroup_id } => write!(f,"Cgroup created {{ cgroup_path: {cgroup_path}, cgroup_id: {cgroup_id} }}"),
            Payload::CgroupDeleted { cgroup_path, cgroup_id } => write!(f,"Cgroup deleted {{ cgroup_path: {cgroup_path}, cgroup_id: {cgroup_id} }}"),
            Payload::CgroupAttach { cgroup_path, cgroup_id, attached_pid } => write!(f,"Process attached to cgroup {{ cgroup_path: {cgroup_path}, cgroup_id: {cgroup_id}, attached_pid {attached_pid} }}"),
            Payload::SyscallActivity { .. } => write!(f,"Syscall Activity"),
            Payload::Bind { address, is_tcp } => write!(f,"Bind {{ address: {address}, is_tcp: {is_tcp} }}"),
            Payload::Listen { address } => write!(f,"Listen {{ address: {address} }}"),  
            Payload::Connect { destination, is_tcp } => write!(f,"Connect {{ destination: {destination}, is_tcp: {is_tcp} }}"),
            Payload::Accept { source, destination } => write!(f,"Accept {{ source: {source}, destination: {destination} }}"),
            Payload::Close { source, destination } => write!(f,"Close {{ source: {source}, destination: {destination} }}"),
            Payload::Receive { source, destination, len, is_tcp } => write!(f,"Receive {{ source: {source}, destination: {destination}, len: {len}, is_tcp: {is_tcp} }}"),
            Payload::DnsQuery { questions } => {
                write!(f,"Dns Query {{ questions: ")?;
                print_vec(f, questions)?;
                write!(f," }}")
            },
            Payload::DnsResponse { questions, answers } => {
                write!(f,"Dns Response {{ questions: ")?;
                print_vec(f, questions)?;
                write!(f,", answers: ")?;
                print_vec(f, answers)?;
                write!(f," }}")
            },
            Payload::Send { source, destination, len, is_tcp } => write!(f,"Send {{ source: {source}, destination {destination}, len: {len}, is_tcp: {is_tcp} }}"),
            Payload::Custom { description, value:_ } => write!(f,"Custom {{ description: {description} }}"),
            Payload::Empty => write!(f,"Empty"),
        }
    }
}

/// Encapsulates IP and port.
#[derive(Debug, Clone, Serialize, Deserialize, Validatron)]
pub struct Host {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(v4) => write!(f, "{v4}:{}", self.port),
            IpAddr::V6(v6) => write!(f, "[{v6}]:{}", self.port),
        }
    }
}

/// Encapsulates data of a DNS question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    /// Question name string.
    pub name: String,
    /// Question type.
    pub qtype: String,
    /// Question class.
    pub qclass: String,
}

impl fmt::Display for DnsQuestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({} - {} - {})", self.name, self.qtype, self.qclass)
    }
}

/// Encapsulates data of a DNS answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    /// Name string.
    pub name: String,
    /// Answer record class.
    pub class: String,
    /// Record TTL.
    pub ttl: u32,
    /// Record data.
    pub data: String,
}

impl fmt::Display for DnsAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({} - {} - {} - {})",
            self.name, self.class, self.ttl, self.data
        )
    }
}

// High level abstraction for file flags bitmask
#[repr(C)]
#[derive(Clone, Serialize, Deserialize)]
pub struct FileFlags(i32);

impl FileFlags {
    pub fn from_raw_unchecked(flags: i32) -> Self {
        Self(flags)
    }
}

impl FileFlags {
    const ACC_MODE_FLAGS: [(&'static str, i32); 3] = [
        ("O_RDONLY", kernel::file::flags::O_RDONLY),
        ("O_WRONLY", kernel::file::flags::O_WRONLY),
        ("O_RDWR", kernel::file::flags::O_RDWR),
    ];

    const OTHER_FLAGS: [(&'static str, i32); 7] = [
        ("O_CREAT", kernel::file::flags::O_CREAT),
        ("O_EXCL", kernel::file::flags::O_EXCL),
        ("O_NOCTTY", kernel::file::flags::O_NOCTTY),
        ("O_TRUNC", kernel::file::flags::O_TRUNC),
        ("O_APPEND", kernel::file::flags::O_APPEND),
        ("O_NONBLOCK", kernel::file::flags::O_NONBLOCK),
        ("O_DIRECTORY", kernel::file::flags::O_DIRECTORY),
    ];
}

impl Validatron for FileFlags {
    fn get_class() -> validatron::ValidatronClass {
        Self::class_builder().primitive(
            Box::new(|s| {
                FileFlags::ACC_MODE_FLAGS
                    .iter()
                    .chain(FileFlags::OTHER_FLAGS.iter())
                    .find(|(name, _)| *name == s)
                    .map(|(_, flag)| Self(*flag))
                    .ok_or_else(|| ValidatronError::FieldValueParseError(s.to_string()))
            }),
            Box::new(|op| match op {
                Operator::Multi(op) => match op {
                    validatron::MultiOperator::Contains => Ok(Box::new(|a, b| {
                        if FileFlags::ACC_MODE_FLAGS
                            .iter()
                            .any(|(_, acc_mode_flag)| acc_mode_flag == &b.0)
                        {
                            let mode = a.0 & kernel::file::flags::O_ACCMODE;
                            mode == b.0
                        } else {
                            (a.0 & b.0) > 0
                        }
                    })),
                },
                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "FileFlags".to_string(),
                )),
            }),
        )
    }
}

impl fmt::Debug for FileFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0, self)
    }
}

impl fmt::Display for FileFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flag_names = Vec::new();

        let mode = self.0 & kernel::file::flags::O_ACCMODE;
        for (name, flag) in FileFlags::ACC_MODE_FLAGS {
            if mode == flag {
                flag_names.push(name);
                break; // Only one is possible
            }
        }

        for (name, flag) in FileFlags::OTHER_FLAGS {
            if (self.0 & flag) > 0 {
                flag_names.push(name);
            }
        }

        let content = flag_names.join(",");

        write!(f, "({content})")
    }
}

impl From<FileFlags> for i32 {
    fn from(f_flags: FileFlags) -> Self {
        f_flags.0
    }
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Argv(Vec<String>);

impl From<Vec<String>> for Argv {
    fn from(argv_list: Vec<String>) -> Self {
        Self(argv_list)
    }
}

impl Validatron for Argv {
    fn get_class() -> validatron::ValidatronClass {
        Self::class_builder().primitive(
            Box::new(|s| Ok(Argv(vec![s.to_string()]))),
            Box::new(|op| match op {
                Operator::Multi(op) => match op {
                    validatron::MultiOperator::Contains => {
                        Ok(Box::new(|a, b| b.0.iter().all(|item| a.0.contains(item))))
                    }
                },
                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "Argv".to_string(),
                )),
            }),
        )
    }
}

impl From<Argv> for Vec<String> {
    fn from(argv: Argv) -> Self {
        argv.0
    }
}

impl fmt::Display for Argv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        print_vec(f, &self.0)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize, Validatron)]
pub struct Namespaces {
    pub uts: u32,
    pub ipc: u32,
    pub mnt: u32,
    pub pid: u32,
    pub net: u32,
    pub time: u32,
    pub cgroup: u32,
}

impl fmt::Display for Namespaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ uts: {}, ipc: {}, mnt: {}, pid: {}, net: {}, time: {}, cgroup: {} }}",
            self.uts, self.ipc, self.mnt, self.pid, self.net, self.time, self.cgroup
        )
    }
}

fn print_vec(f: &mut fmt::Formatter<'_>, v: impl IntoIterator<Item = impl Display>) -> fmt::Result {
    write!(f, "[ ")?;

    for (index, elem) in v.into_iter().enumerate() {
        if index != 0 {
            write!(f, ", ")?;
        }
        write!(f, "{elem}")?;
    }

    write!(f, " ]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_to_value_and_back() {
        #[derive(Debug, Serialize, Deserialize)]
        struct MyData {
            field: String,
        }

        let native = MyData {
            field: "hello world".to_string(),
        };

        let serialization = Value::try_from(&native).unwrap();
        let deserialization: MyData = serialization.try_into().unwrap();

        assert_eq!(native.field, deserialization.field);
    }
}
