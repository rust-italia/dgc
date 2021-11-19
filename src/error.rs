use thiserror::Error;

use crate::cwt::CwtParseError;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid data, expected more than 4 bytes, found {0} bytes")]
    NotEnoughData(usize),
    #[error("Invalid header. Expected 'HC1:', found: '{0}'")]
    InvalidPrefix(String),
    #[error("Cannot base45 decode the data: {0}")]
    Base45Decode(#[from] base45::DecodeError),
    #[error("Could not decompress the data: {0}")]
    Deflate(String),
    #[error("Could not decode CWT data: {0}")]
    CwtDecode(#[from] CwtParseError),
}
