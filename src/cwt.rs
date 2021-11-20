use crate::DgcCertContainer;
use ciboriumvalue::{
    ser::into_writer,
    value::{Integer, Value},
};
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

const COSE_SIGN1_CBOR_TAG: u64 = 18;
const COSE_HEADER_KEY_KID: i128 = 4;
const COSE_HEADER_KEY_ALG: i128 = 1;
const COSE_ECDSA256: i128 = -7;
const COSE_ECDSA384: i128 = -35;
const COSE_ECDSA512: i128 = -36;

#[derive(Error, Debug)]
pub enum CwtParseError {
    #[error("Cannot parse the data as CBOR: {0}")]
    CborError(#[from] ciboriumvalue::de::Error<std::io::Error>),
    #[error("The root value is not a tag")]
    InvalidRootValue,
    #[error("Expected COSE_SIGN1_CBOR_TAG ({}) found {0}", COSE_SIGN1_CBOR_TAG)]
    InvalidTag(u64),
    #[error("The main CBOR object is not an array")]
    InvalidParts,
    #[error("The main CBOR array does not contain 4 parts. {0} parts found")]
    InvalidPartsCount(usize),
    #[error("The header section is not a binary string")]
    HeaderNotBinary,
    #[error("The header section is not valid CBOR-encoded data")]
    HeaderNotValidCbor,
    #[error("The header section does not contain key-value pairs")]
    HeaderNotMap,
    #[error("The payload section is not a binary string")]
    PayloadNotBinary,
    #[error("Cannot deserialize payload: {0}")]
    InvalidPayload(#[source] ciboriumvalue::de::Error<std::io::Error>),
    #[error("The signature section is not a binary string")]
    SignatureNotBinary,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EcAlg {
    Ecdsa256, // -7
    Ecdsa384, // -35
    Ecdsa512, // -36
    Unknown(i128),
}

impl From<Integer> for EcAlg {
    fn from(i: Integer) -> Self {
        match *i.value() {
            COSE_ECDSA256 => EcAlg::Ecdsa256,
            COSE_ECDSA384 => EcAlg::Ecdsa384,
            COSE_ECDSA512 => EcAlg::Ecdsa512,
            _ => EcAlg::Unknown(*i.value()),
        }
    }
}

#[derive(Debug)]
pub struct CwtHeader {
    pub kid: Option<Vec<u8>>,
    pub alg: Option<EcAlg>,
}

impl CwtHeader {
    fn new() -> Self {
        Self {
            kid: None,
            alg: None,
        }
    }

    fn kid(&mut self, kid: Vec<u8>) {
        self.kid = Some(kid);
    }

    fn alg(&mut self, alg: EcAlg) {
        self.alg = Some(alg);
    }
}

impl From<&[(Value, Value)]> for CwtHeader {
    fn from(data: &[(Value, Value)]) -> Self {
        // permissive parsing. We don't want to fail if we can't decode the header
        let mut header = CwtHeader::new();
        // tries to find kid and alg and apply them to the header before returning it
        for (key, val) in data.iter() {
            if let Value::Integer(k) = key {
                if *k.value() == COSE_HEADER_KEY_KID {
                    // found kid
                    if let Some(kid) = val.as_bytes() {
                        header.kid(kid.clone());
                    }
                } else if *k.value() == COSE_HEADER_KEY_ALG {
                    // found alg
                    if let Some(raw_alg) = val.as_integer() {
                        let alg: EcAlg = (*raw_alg).into();
                        header.alg(alg);
                    }
                }
            }
        }
        header
    }
}

#[derive(Debug)]
pub struct Cwt {
    pub header_protected_raw: Vec<u8>,
    pub header_protected: CwtHeader,
    pub header_unprotected: Value,
    pub payload_raw: Vec<u8>,
    pub payload: DgcCertContainer,
    pub signature: Vec<u8>,
}

impl Cwt {
    pub fn new(
        header_protected_raw: Vec<u8>,
        header_protected: CwtHeader,
        header_unprotected: Value,
        payload_raw: Vec<u8>,
        payload: DgcCertContainer,
        signature: Vec<u8>,
    ) -> Self {
        Cwt {
            header_protected_raw,
            header_protected,
            header_unprotected,
            payload_raw,
            payload,
            signature,
        }
    }

    pub fn make_sig_structure(&self) -> Vec<u8> {
        // https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
        let sig_structure_cbor = Value::Array(vec![
            Value::Text(String::from("Signature1")), // context of the signature
            Value::Bytes(self.header_protected_raw.clone()), // protected attributes from the body structure
            Value::Bytes(vec![]), // protected attributes from the application (these are not used in hcert so we keep them empty as per spec)
            Value::Bytes(self.payload_raw.clone()),
        ]);
        let mut sig_structure: Vec<u8> = vec![];
        into_writer(&sig_structure_cbor, &mut sig_structure).unwrap();
        sig_structure
    }
}

impl TryFrom<&[u8]> for Cwt {
    type Error = CwtParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        use CwtParseError::*;

        let cwt: Value = ciboriumvalue::de::from_reader(data)?;
        let (tag_id, cwt_content) = cwt.as_tag().ok_or(InvalidRootValue)?;
        if *tag_id != COSE_SIGN1_CBOR_TAG {
            return Err(InvalidTag(*tag_id));
        }
        let parts = cwt_content.as_array().ok_or(InvalidParts)?;
        if parts.len() != 4 {
            return Err(InvalidPartsCount(parts.len()));
        }
        let header_protected_raw = (parts[0].as_bytes().ok_or(HeaderNotBinary)?).clone();
        let header_protected: CwtHeader =
            ciboriumvalue::de::from_reader::<'_, Value, _>(header_protected_raw.as_slice())
                .map_err(|_| HeaderNotValidCbor)?
                .as_map()
                .ok_or(HeaderNotMap)?
                .as_slice()
                .into();
        let header_unprotected = parts[1].clone();
        let payload_raw = (parts[2].as_bytes().ok_or(PayloadNotBinary)?).clone();
        let signature = (parts[3].as_bytes().ok_or(SignatureNotBinary)?).clone();

        let payload: DgcCertContainer =
            ciboriumvalue::de::from_reader(payload_raw.as_slice()).map_err(InvalidPayload)?;

        Ok(Cwt::new(
            header_protected_raw,
            header_protected,
            header_unprotected,
            payload_raw,
            payload,
            signature,
        ))
    }
}

impl TryFrom<Vec<u8>> for Cwt {
    type Error = CwtParseError;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        data.as_slice().try_into()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    // test data from https://dgc.a-sit.at/ehn/generate
    use super::*;

    #[test]
    fn it_parses_cose_data() {
        let raw_hex_cose_data = "d2844da204481c10ebbbc49f78310126a0590111a4041a61657980061a6162d90001624145390103a101a4617481a862736374323032312d31302d30395431323a30333a31325a627474684c50363436342d3462746376416c686f736e204f6e6520446179205375726765727962636f624145626369782955524e3a555643493a56313a41453a384b5354305248303537484938584b57334d384b324e41443036626973781f4d696e6973747279206f66204865616c746820262050726576656e74696f6e6274676938343035333930303662747269323630343135303030636e616da463666e7465424c414b4562666e65424c414b4563676e7466414c53544f4e62676e66414c53544f4e6376657265312e332e3063646f626a313939302d30312d3031584034fc1cee3c4875c18350d24ccd24dd67ce1bda84f5db6b26b4b8a97c8336e159294859924afa7894a45a5af07a8cf536a36be67912d79f5a93540b86bb7377fb";
        let expected_sig_structure = "846a5369676e6174757265314da204481c10ebbbc49f7831012640590111a4041a61657980061a6162d90001624145390103a101a4617481a862736374323032312d31302d30395431323a30333a31325a627474684c50363436342d3462746376416c686f736e204f6e6520446179205375726765727962636f624145626369782955524e3a555643493a56313a41453a384b5354305248303537484938584b57334d384b324e41443036626973781f4d696e6973747279206f66204865616c746820262050726576656e74696f6e6274676938343035333930303662747269323630343135303030636e616da463666e7465424c414b4562666e65424c414b4563676e7466414c53544f4e62676e66414c53544f4e6376657265312e332e3063646f626a313939302d30312d3031";
        let expected_kid: Vec<u8> = vec![28, 16, 235, 187, 196, 159, 120, 49];
        let expected_alg = EcAlg::Ecdsa256;
        let raw_cose_data = hex::decode(raw_hex_cose_data).unwrap();

        let cwt: Cwt = raw_cose_data.as_slice().try_into().unwrap();

        assert_eq!(Some(expected_kid), cwt.header_protected.kid);
        assert_eq!(Some(expected_alg), cwt.header_protected.alg);
        assert_eq!(
            expected_sig_structure,
            hex::encode(cwt.make_sig_structure())
        );
    }
}
