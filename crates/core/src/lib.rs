#![doc = "跨模块稳定领域类型。"]

use std::{error::Error, fmt};

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

id_type!(TaskId);
id_type!(NodeId);
id_type!(CommitteeId);
id_type!(Commitment);
id_type!(MessageId);
id_type!(ContractId);
id_type!(ProgramId);
id_type!(DataId);
id_type!(ExecutionId);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskStatus {
    Registered,
    AwaitingInputs,
    SelectingCommittee,
    Handoff,
    Running,
    AwaitingVerification,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfidentialityMode {
    SecretSharing,
    Homomorphic,
    Hybrid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeEpoch(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolRound(pub u32);

#[derive(Clone, PartialEq, Eq)]
pub struct PublicBytes(Vec<u8>);

impl PublicBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// 敏感字节容器：故意不实现 `Clone`、`Debug`、`Display`。
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    EmptyValue(&'static str),
    InvalidLength(&'static str),
    UnsupportedVersion,
    InvalidStateTransition,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "domain validation failed: {self:?}")
    }
}

impl Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_id_round_trips_bytes() {
        let bytes = [7_u8; 32];
        let id = TaskId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn public_bytes_round_trips_owned_value() {
        let value = PublicBytes::new(vec![1, 2, 3]);
        assert_eq!(value.as_slice(), &[1, 2, 3]);
        assert_eq!(value.into_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn secret_bytes_only_exposes_on_explicit_call() {
        let value = SecretBytes::new(vec![4, 5, 6]);
        assert_eq!(value.expose(), &[4, 5, 6]);
    }
}
