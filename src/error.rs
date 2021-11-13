use aws_nitro_enclaves_cose::error::COSEError;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    NotEnoughData(usize),
    InvalidPrefix(String),
    Base45DecodeError(base45::DecodeError),
    DeflateError(String),
    CoseError(COSEError),
    TranscodeError(serde_json::error::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match &self {
            NotEnoughData(num_bytes) => write!(
                f,
                "Invalid data, expected more than 4 bytes, found {}",
                num_bytes
            ),
            InvalidPrefix(found_prefix) => {
                write!(f, "Invalid header. Expected 'HC1:', found {}", found_prefix)
            }
            Base45DecodeError(e) => write!(f, "Cannot base45 decode the data: {}", e),
            DeflateError(e) => write!(f, "Could not decompress the data: {}", e),
            CoseError(e) => write!(f, "Could not parse COSE data: {}", e),
            TranscodeError(e) => write!(f, "Could not convert CBOR data to JSON: {}", e),
        }
    }
}

impl From<base45::DecodeError> for Error {
    fn from(e: base45::DecodeError) -> Self {
        Error::Base45DecodeError(e)
    }
}

impl From<COSEError> for Error {
    fn from(e: COSEError) -> Self {
        Error::CoseError(e)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Self {
        Error::TranscodeError(e)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;
        match self {
            Base45DecodeError(e) => Some(e),
            CoseError(e) => Some(e),
            TranscodeError(e) => Some(e),
            _ => None,
        }
    }
}
