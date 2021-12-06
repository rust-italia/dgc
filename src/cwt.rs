use crate::DgcContainer;
use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};
use std::iter::FromIterator;
use std::{
    convert::{TryFrom, TryInto},
    ops::Not,
};
use thiserror::Error;

const COSE_SIGN1_CBOR_TAG: u64 = 18;
const CBOR_WEB_TOKEN_TAG: u64 = 61;
const COSE_HEADER_KEY_KID: i128 = 4;
const COSE_HEADER_KEY_ALG: i128 = 1;
/// COSE key for ECDSA w/ SHA-256
const COSE_ES256: i128 = -7;
/// COSE key for RSASSA-PSS w/ SHA-256
const COSE_PS256: i128 = -37;

/// An enum representing all the possible errors that can occur while trying
/// to parse data representing a CWT ([CBOR Web Token](https://datatracker.ietf.org/doc/html/rfc8392)).
#[derive(Error, Debug)]
pub enum CwtParseError {
    /// Cannot parse the data as CBOR
    #[error("Cannot parse the data as CBOR: {0}")]
    CborError(#[from] ciborium::de::Error<std::io::Error>),
    /// The root value is not a tag
    #[error("The root value is not a tag")]
    InvalidRootValue,
    /// The root tag is invalid
    #[error(
        "Expected COSE_SIGN1_CBOR_TAG ({}) or CBOR_WEB_TOKEN_TAG ({}). Found: {0}",
        COSE_SIGN1_CBOR_TAG,
        CBOR_WEB_TOKEN_TAG
    )]
    InvalidTag(u64),
    /// The main CBOR object is not an array
    #[error("The main CBOR object is not an array")]
    InvalidParts,
    /// The main CBOR array does not contain 4 parts
    #[error("The main CBOR array does not contain 4 parts. {0} parts found")]
    InvalidPartsCount(usize),
    /// The unprotected header section is not a CBOR map or an emtpy sequence of bytes
    #[error("The unprotected header section is not a CBOR map or an emtpy sequence of bytes")]
    MalformedUnProtectedHeader,
    /// The protected header section is not a binary string
    #[error("The protected header section is not a binary string")]
    ProtectedHeaderNotBinary,
    /// The protected header section is not valid CBOR-encoded data
    #[error("The protected header section is not valid CBOR-encoded data")]
    ProtectedHeaderNotValidCbor,
    /// The protected header section does not contain key-value pairs
    #[error("The protected header section does not contain key-value pairs")]
    ProtectedHeaderNotMap,
    /// The payload section is not a binary string
    #[error("The payload section is not a binary string")]
    PayloadNotBinary,
    /// Cannot deserialize the payload
    #[error("Cannot deserialize payload: {0}")]
    InvalidPayload(#[source] ciborium::de::Error<std::io::Error>),
    /// The signature section is not a binary string
    #[error("The signature section is not a binary string")]
    SignatureNotBinary,
}

/// An enum representing the supported signing verification algorithms.
#[derive(Debug, PartialEq, Eq)]
pub enum EcAlg {
    /// ECDSA w/ SHA-256
    ///
    /// [Elliptic Curve Digital Signature Algorithm][ecdsa] using the
    /// [Secure Hash Algorithm 2][sha2] hash function
    /// with digest size of 256 bits.
    ///
    /// [ecdsa]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    /// [sha2]: https://en.wikipedia.org/wiki/SHA-2
    Es256,
    /// RSASSA-PSS w/ SHA-256
    ///
    /// [Rivest-Shamir-Adleman][rsa] signing algorithm using the
    /// [Secure Hash Algorithm 2][sha2] hash function
    /// with digest size of 256 bits.
    ///
    /// [rsa]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
    /// [sha2]: https://en.wikipedia.org/wiki/SHA-2
    Ps256,
    /// Unknown algorithm
    ///
    /// The value is the COSE algorithm identifier defined by the IANA,
    /// a complete list can be found [here](https://www.iana.org/assignments/cose/cose.xhtml)
    Unknown(i128),
}

impl From<Integer> for EcAlg {
    fn from(i: Integer) -> Self {
        let u: i128 = i.into();
        match u {
            COSE_ES256 => EcAlg::Es256,
            COSE_PS256 => EcAlg::Ps256,
            _ => EcAlg::Unknown(u),
        }
    }
}

/// The CWT header object.
///
/// This is a simplification of the actual CWT structure. In fact,
/// in the CWT spec there are 2 headers (protected header and unprotected header).
///
/// For the sake of DGC, we only need to extract `kid` and `alg` from either of them,
/// so we use this struct to keep those values.
#[derive(Debug)]
pub struct CwtHeader {
    /// The Key ID used for signing the certificate
    pub kid: Option<Vec<u8>>,
    /// The signature algorithm used to sign the certificate
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

impl FromIterator<(Value, Value)> for CwtHeader {
    fn from_iter<T: IntoIterator<Item = (Value, Value)>>(iter: T) -> Self {
        // permissive parsing. We don't want to fail if we can't decode the header
        let mut header = CwtHeader::new();
        // tries to find kid and alg and apply them to the header before returning it
        for (key, val) in iter {
            if let Value::Integer(k) = key {
                let k: i128 = k.into();
                if k == COSE_HEADER_KEY_KID {
                    // found kid
                    if let Value::Bytes(kid) = val {
                        header.kid(kid);
                    }
                } else if k == COSE_HEADER_KEY_ALG {
                    // found alg
                    if let Value::Integer(raw_alg) = val {
                        let alg: EcAlg = raw_alg.into();
                        header.alg(alg);
                    }
                }
            }
        }
        header
    }
}

/// A representation of a CWT ([CBOR Web Token](https://datatracker.ietf.org/doc/html/rfc8392)).
///
/// In the context of DGC only a portion of the original CWT specification is actually used
/// ([COSE_Sign1](https://datatracker.ietf.org/doc/html/rfc8152#section-4.2)) so this module
/// is limited to implementing exclusively that portion.
#[derive(Debug)]
pub struct Cwt {
    header_protected_raw: Vec<u8>,
    payload_raw: Vec<u8>,
    /// A simplified representation of the original CWT headers (protected + unprotected)
    ///
    /// Stores only the `kid` and `alg`
    pub header: CwtHeader,
    /// The CWT payload parse as a DgcContainer
    pub payload: DgcContainer,
    /// The raw bytes of the signature
    pub signature: Vec<u8>,
}

impl Cwt {
    /// Creates the [sig structure](https://datatracker.ietf.org/doc/html/rfc8152#section-4.4) needed to be able
    /// to verify the signature against a public key.
    pub fn make_sig_structure(&self) -> Vec<u8> {
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

/// Extends `ciborium::value::Value` with some useful methods.
/// TODO: send a PR to `ciborium` to have these utilities out of the box.
trait ValueExt: Sized {
    fn into_tag(self) -> Result<(u64, Box<Value>), Self>;
    fn into_array(self) -> Result<Vec<Value>, Self>;
    fn into_bytes(self) -> Result<Vec<u8>, Self>;
}

impl ValueExt for Value {
    fn into_tag(self) -> Result<(u64, Box<Value>), Self> {
        match self {
            Self::Tag(tag, content) => Ok((tag, content)),
            _ => Err(self),
        }
    }

    fn into_array(self) -> Result<Vec<Value>, Self> {
        match self {
            Self::Array(array) => Ok(array),
            _ => Err(self),
        }
    }

    fn into_bytes(self) -> Result<Vec<u8>, Self> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            _ => Err(self),
        }
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
        let cwt_content = match cwt_content.into_tag() {
            Ok((COSE_SIGN1_CBOR_TAG, content)) => *content,
            Ok((tag_id, _)) => return Err(InvalidTag(tag_id)),
            Err(cwt) => cwt,
        };

        let parts = cwt_content.into_array().map_err(|_| InvalidParts)?;

        let parts_len = parts.len();
        let [header_protected_raw, unprotected_header, payload_raw, signature]: [Value; 4] =
            parts.try_into().map_err(|_| InvalidPartsCount(parts_len))?;

        let header_protected_raw = header_protected_raw
            .into_bytes()
            .map_err(|_| ProtectedHeaderNotBinary)?;
        let payload_raw = payload_raw.into_bytes().map_err(|_| PayloadNotBinary)?;
        let signature = signature.into_bytes().map_err(|_| SignatureNotBinary)?;

        // unprotected header must be a cbor map or an empty sequence of bytes
        let unprotected_header = match unprotected_header {
            Value::Map(values) => Some(values),
            Value::Bytes(values) if values.is_empty() => Some(Vec::new()),
            _ => None,
        }
        .ok_or(MalformedUnProtectedHeader)?;

        // protected header is a bytes sequence.
        // If the length of the sequence is 0 we assume it represents an empty map.
        // Otherwise we decode the binary string as a CBOR value and we make sure it represents a map.
        let protected_header_values = header_protected_raw
            .is_empty()
            .not()
            .then(|| {
                let value = ciborium::de::from_reader(header_protected_raw.as_slice())
                    .map_err(|_| ProtectedHeaderNotValidCbor)?;

                match value {
                    Value::Map(map) => Ok(map),
                    _ => Err(ProtectedHeaderNotMap),
                }
            })
            .transpose()?
            .unwrap_or_default();

        // Take data from unprotected header first, then from the protected one
        let header: CwtHeader = unprotected_header
            .into_iter()
            .chain(protected_header_values)
            .collect();

        let payload: DgcContainer =
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
        let expected_alg = EcAlg::Es256;
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
