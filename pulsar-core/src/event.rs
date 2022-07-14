use std::{net::SocketAddr, time::SystemTime};

use serde::{Deserialize, Serialize};
use validatron::{ValidatronStruct, ValidatronVariant};

use crate::pdk::ModuleName;

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct Event {
    pub header: Header,
    pub payload: Payload,
}

impl ValidatronVariant for Event {
    fn validate(
        variant: &str,
        field_compare: &validatron::Field,
        op: validatron::Operator,
        value: &str,
    ) -> Result<(usize, Box<dyn Fn(&Self) -> bool + Send + Sync>), validatron::ValidatronError>
    {
        match field_compare {
            validatron::Field::Simple(s) => {
                Err(validatron::ValidatronError::FieldNotSimple(s.to_string()))
            }
            validatron::Field::Struct { name, inner_field } => match name.as_str() {
                "header" => {
                    let var_num = Payload::var_num_of(variant)?;
                    let validated_struct = validatron::process_struct(
                        inner_field,
                        |event: &Self| &event.header,
                        op,
                        value,
                    );
                    validated_struct.map(|vc| (var_num, vc))
                }

                "payload" => validatron::process_variant(
                    variant,
                    inner_field,
                    |event: &Self| &event.payload,
                    op,
                    value,
                ),
                _ => Err(validatron::ValidatronError::FieldNotFound(name.clone())),
            },
        }
    }

    fn var_num(&self) -> usize {
        self.payload.var_num()
    }

    fn var_num_of(variant: &str) -> Result<usize, validatron::ValidatronError> {
        Payload::var_num_of(variant)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ValidatronStruct)]
pub struct Header {
    pub pid: i32,
    pub is_threat: bool,
    pub source: ModuleName,
    #[validatron(skip)]
    pub timestamp: SystemTime,
    pub image: String,
    pub parent: i32,
    #[validatron(skip)]
    pub fork_time: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, ValidatronVariant)]
#[serde(tag = "type", content = "content")]
pub enum Payload {
    FileCreated {
        filename: String,
    },
    FileDeleted {
        filename: String,
    },
    FileOpened {
        filename: String,
        flags: i32,
    },
    ElfOpened {
        filename: String,
        flags: i32,
    },
    Fork {
        ppid: i32,
    },
    Exec {
        filename: String,
    },
    Exit {
        exit_code: u32,
    },
    SyscallActivity {
        #[validatron(skip)]
        histogram: Vec<u64>,
    },
    Bind {
        address: SocketAddr,
    },
    Connect {
        source: SocketAddr,
        destination: SocketAddr,
    },
    Accept {
        source: SocketAddr,
        destination: SocketAddr,
    },
    Close {
        source: SocketAddr,
        destination: SocketAddr,
    },
    Receive {
        source: SocketAddr,
        destination: SocketAddr,
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
        source: SocketAddr,
        destination: SocketAddr,
        len: usize,
        is_tcp: bool,
    },
    MalwareDetection {
        score: f32,
        #[validatron(skip)]
        tags: Vec<String>,
    },
    RuleEngineDetection {
        #[validatron(skip)]
        rule_name: String,
        #[validatron(skip)]
        payload: Box<Payload>,
    },
    AnomalyDetection {
        score: f32,
    }, // CustomJson { ty: i32, data: Vec<u8> },
       // CustomProto { ty: i32, data: Vec<u8> },
       // CustomRaw { ty: i32, data: Vec<u8> }
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
