use crate::DgcCertContainer;
use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};
use std::convert::{TryFrom, TryInto};
use std::iter::FromIterator;
use thiserror::Error;

const COSE_SIGN1_CBOR_TAG: u64 = 18;
const CBOR_WEB_TOKEN_TAG: u64 = 61;
const COSE_HEADER_KEY_KID: i128 = 4;
const COSE_HEADER_KEY_ALG: i128 = 1;
const COSE_ECDSA256: i128 = -7;
const COSE_ECDSA384: i128 = -35;
const COSE_ECDSA512: i128 = -36;

#[derive(Error, Debug)]
pub enum CwtParseError {
    #[error("Cannot parse the data as CBOR: {0}")]
    CborError(#[from] ciborium::de::Error<std::io::Error>),
    #[error("The root value is not a tag")]
    InvalidRootValue,
    #[error("Expected COSE_SIGN1_CBOR_TAG ({}) found {0}", COSE_SIGN1_CBOR_TAG)]
    InvalidTag(u64),
    #[error("The main CBOR object is not an array")]
    InvalidParts,
    #[error("The main CBOR array does not contain 4 parts. {0} parts found")]
    InvalidPartsCount(usize),
    #[error("The unprotected header section is not a CBOR map or an emtpy sequence of bytes")]
    MalformedUnProtectedHeader,
    #[error("The protected header section is not a binary string")]
    ProtectedHeaderNotBinary,
    #[error("The protected header section is not valid CBOR-encoded data")]
    ProtectedHeaderNotValidCbor,
    #[error("The protected header section does not contain key-value pairs")]
    ProtectedHeaderNotMap,
    #[error("The payload section is not a binary string")]
    PayloadNotBinary,
    #[error("Cannot deserialize payload: {0}")]
    InvalidPayload(#[source] ciborium::de::Error<std::io::Error>),
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
        let u: i128 = i.into();
        match u {
            COSE_ECDSA256 => EcAlg::Ecdsa256,
            COSE_ECDSA384 => EcAlg::Ecdsa384,
            COSE_ECDSA512 => EcAlg::Ecdsa512,
            _ => EcAlg::Unknown(u),
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

impl<'a> FromIterator<&'a (Value, Value)> for CwtHeader {
    fn from_iter<T: IntoIterator<Item = &'a (Value, Value)>>(iter: T) -> Self {
        // permissive parsing. We don't want to fail if we can't decode the header
        let mut header = CwtHeader::new();
        // tries to find kid and alg and apply them to the header before returning it
        for (key, val) in iter {
            if let Some(k) = key.as_integer() {
                let k: i128 = k.into();
                if k == COSE_HEADER_KEY_KID {
                    // found kid
                    if let Some(kid) = val.as_bytes() {
                        header.kid(kid.clone());
                    }
                } else if k == COSE_HEADER_KEY_ALG {
                    // found alg
                    if let Some(raw_alg) = val.as_integer() {
                        let alg: EcAlg = raw_alg.into();
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
    header_protected_raw: Vec<u8>,
    payload_raw: Vec<u8>,
    pub header: CwtHeader,
    pub payload: DgcCertContainer,
    pub signature: Vec<u8>,
}

impl Cwt {
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

        let cwt_content = match ciborium::de::from_reader(data)? {
            Value::Tag(tag_id, content) if tag_id == CBOR_WEB_TOKEN_TAG => *content,
            cwt => cwt,
        };
        let cwt_content = match cwt_content {
            Value::Tag(COSE_SIGN1_CBOR_TAG, content) => *content,
            Value::Tag(tag_id, _) => return Err(InvalidTag(tag_id)),
            cwt => cwt,
        };
        let parts = match cwt_content {
            Value::Array(parts) => parts,
            _ => return Err(InvalidParts),
        };
        if parts.len() != 4 {
            return Err(InvalidPartsCount(parts.len()));
        }
        let header_protected_raw = (parts[0].as_bytes().ok_or(ProtectedHeaderNotBinary)?).clone();

        let payload_raw = (parts[2].as_bytes().ok_or(PayloadNotBinary)?).clone();
        let signature = (parts[3].as_bytes().ok_or(SignatureNotBinary)?).clone();

        // unprotected header must be a cbor map or an empty sequence of bytes
        let unprotected_header_iter = match parts[1] {
            Value::Map(ref values) => Some(values.iter()),
            Value::Bytes(ref values) if values.is_empty() => Some([].iter()),
            _ => None,
        }
        .ok_or(MalformedUnProtectedHeader)?;

        // protected header is a bytes sequence.
        // If the length of the sequence is 0 we assume it represents an empty map.
        // Otherwise we decode the binary string as a CBOR value and we make sure it represents a map.
        let protected_header_values: Vec<(Value, Value)> = if header_protected_raw.is_empty() {
            vec![]
        } else {
            ciborium::de::from_reader::<'_, Value, _>(header_protected_raw.as_slice())
                .map_err(|_| ProtectedHeaderNotValidCbor)?
                .as_map()
                .ok_or(ProtectedHeaderNotMap)?
                .clone()
        };

        // Take data from unprotected header first, then from the protected one
        let header: CwtHeader = unprotected_header_iter
            .chain(protected_header_values.iter())
            .collect();

        let payload: DgcCertContainer =
            ciborium::de::from_reader(payload_raw.as_slice()).map_err(InvalidPayload)?;

        Ok(Cwt {
            header_protected_raw,
            payload_raw,
            header,
            payload,
            signature,
        })
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

        assert_eq!(Some(expected_kid), cwt.header.kid);
        assert_eq!(Some(expected_alg), cwt.header.alg);
        assert_eq!(
            expected_sig_structure,
            hex::encode(cwt.make_sig_structure())
        );
    }
}
