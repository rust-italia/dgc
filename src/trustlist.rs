use ring_compat::signature::ecdsa::p256::VerifyingKey;
use std::{collections::HashMap, convert::TryFrom};
use thiserror::Error;

#[derive(Debug)]
pub struct TrustList {
    keys: HashMap<Vec<u8>, VerifyingKey>,
}

impl TrustList {
    pub fn get_key(&self, kid: &[u8]) -> Option<&VerifyingKey> {
        self.keys.get(kid)
    }
}

#[derive(Error, Debug)]
pub enum KeyParseError {
    #[error("Cannot decode base64 data: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Failed to parse X509 data: {0}")]
    X509ParseError(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("Cannot extract a valid public key from certificate: {0}")]
    PublicKeyParseError(String),
}

#[derive(Error, Debug)]
pub enum TrustListFromJsonError {
    #[error("The given JSON is not an object")]
    InvalidRootType,
    #[error("Key '{0}' is not an object")]
    KeyIsNotObject(String),
    #[error("Key '{0}' does not contain 'publicKeyAlgorithm'")]
    MissingPublicKeyAlgorithm(String),
    #[error("'publicKeyAlgorithm' for key '{0}' is not a string")]
    InvalidPublicKeyAlgorithm(String),
    #[error("Key '{0}' does not contain 'publicKeyAlgorithm.name'")]
    MissingPublicKeyAlgorithmName(String),
    #[error("'publicKeyAlgorithm.name' for key '{0}' is not a string")]
    InvalidPublicKeyAlgorithmName(String),
    #[error("Key '{0}' 'publicKeyAlgorithm.name' is '{1}' where only 'ECDSA' is supported")]
    UnsupportedPublicKeyAlgorithmName(String, String),
    #[error("Key '{0}' does not contain 'publicKeyAlgorithm.namedCurve'")]
    MissingPublicKeyAlgorithmCurve(String),
    #[error("'publicKeyAlgorithm.namedCurve' for key '{0}' is not a string")]
    InvalidPublicKeyAlgorithmCurve(String),
    #[error("Key '{0}' 'publicKeyAlgorithm.namedCurve' is '{0}' where only 'P-256' is supported")]
    UnsupportedPublicKeyAlgorithmCurve(String, String),
    #[error("Key '{0}' does not contain 'publicKeyPem'")]
    MissingPublicKeyPem(String),
    #[error("'publicKeyPem' for key '{0}' is not a string")]
    InvalidPublicKeyPem(String),
    #[error("'publicKeyPem' for key '{0}' could not be decoded: {1}")]
    PublicKeyPemDecodeError(String, #[source] base64::DecodeError),
    #[error("Cannot base64 decode key '{0}': {1}")]
    KidBase64DecodeError(String, #[source] base64::DecodeError),
    #[error("Cannot parse public key for key '{0}': {1}")]
    KeyParseError(String, #[source] KeyParseError),
}

impl TrustList {
    pub fn new() -> Self {
        TrustList {
            keys: HashMap::new(),
        }
    }

    pub fn add(&mut self, kid: &[u8], key: VerifyingKey) {
        self.keys.insert(kid.to_vec(), key);
    }

    pub fn add_key_from_certificate(
        &mut self,
        kid: &[u8],
        base64_x509_cert: &str,
    ) -> Result<(), KeyParseError> {
        let decoded = base64::decode(base64_x509_cert)?;
        let (_, certificate) = x509_parser::parse_x509_certificate(decoded.as_slice())?;
        let raw_key_bytes = certificate.public_key().subject_public_key.data;
        let key = VerifyingKey::new(raw_key_bytes)
            .map_err(|e| KeyParseError::PublicKeyParseError(e.to_string()))?;
        self.keys.insert(kid.to_vec(), key);

        Ok(())
    }

    pub fn add_key_from_str(
        &mut self,
        kid: &[u8],
        base64_der_public_key: &str,
    ) -> Result<(), KeyParseError> {
        let der_data = base64::decode(base64_der_public_key)?;
        // The last 65 bytes of are the ones needed by VerifyingKey
        let key = VerifyingKey::new(&der_data[der_data.len() - 65..])
            .map_err(|e| KeyParseError::PublicKeyParseError(e.to_string()))?;
        self.keys.insert(kid.to_vec(), key);

        Ok(())
    }
}

impl Default for TrustList {
    fn default() -> Self {
        TrustList::new()
    }
}

impl TryFrom<serde_json::Value> for TrustList {
    type Error = TrustListFromJsonError;

    fn try_from(data: serde_json::Value) -> Result<Self, Self::Error> {
        use TrustListFromJsonError::*;

        let mut trustlist = TrustList::default();

        let keys = data.as_object().ok_or(InvalidRootType)?;

        for (kid, keydef) in keys {
            let keydef = keydef
                .as_object()
                .ok_or_else(|| KeyIsNotObject(kid.clone()))?;

            // "publicKeyAlgorithm" must be an object that contains
            // "name" == "ECDSA" and "namedCurve" == "P-256"
            let pub_key_alg = keydef
                .get("publicKeyAlgorithm")
                .ok_or_else(|| MissingPublicKeyAlgorithm(kid.clone()))?
                .as_object()
                .ok_or_else(|| InvalidPublicKeyAlgorithm(kid.clone()))?;

            let pub_key_alg_name = pub_key_alg
                .get("name")
                .ok_or_else(|| MissingPublicKeyAlgorithmName(kid.clone()))?
                .as_str()
                .ok_or_else(|| InvalidPublicKeyAlgorithmName(kid.clone()))?;

            if pub_key_alg_name != "ECDSA" {
                return Err(UnsupportedPublicKeyAlgorithmName(
                    kid.clone(),
                    String::from(pub_key_alg_name),
                ));
            }

            let named_curve = pub_key_alg
                .get("namedCurve")
                .ok_or_else(|| MissingPublicKeyAlgorithmCurve(kid.clone()))?
                .as_str()
                .ok_or_else(|| InvalidPublicKeyAlgorithmCurve(kid.clone()))?;

            if named_curve != "P-256" {
                return Err(UnsupportedPublicKeyAlgorithmCurve(
                    kid.clone(),
                    String::from(named_curve),
                ));
            }

            // "publicKeyPem" must exist and be a base64 encoded bynary string
            let base64_der_public_key = keydef
                .get("publicKeyPem")
                .ok_or_else(|| MissingPublicKeyPem(kid.clone()))?
                .as_str()
                .ok_or_else(|| InvalidPublicKeyPem(kid.clone()))?;

            let decoded_kid =
                base64::decode(kid).map_err(|e| KidBase64DecodeError(kid.clone(), e))?;
            trustlist
                .add_key_from_str(decoded_kid.as_slice(), base64_der_public_key)
                .map_err(|e| KeyParseError(kid.clone(), e))?;
        }

        Ok(trustlist)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::convert::TryInto;

    #[test]
    fn it_adds_a_public_key_from_a_certificate() {
        let base64_x509_cert = "MIIEHjCCAgagAwIBAgIUM5lJeGCHoRF1raR6cbZqDV4vPA8wDQYJKoZIhvcNAQELBQAwTjELMAkGA1UEBhMCSVQxHzAdBgNVBAoMFk1pbmlzdGVybyBkZWxsYSBTYWx1dGUxHjAcBgNVBAMMFUl0YWx5IERHQyBDU0NBIFRFU1QgMTAeFw0yMTA1MDcxNzAyMTZaFw0yMzA1MDgxNzAyMTZaME0xCzAJBgNVBAYTAklUMR8wHQYDVQQKDBZNaW5pc3Rlcm8gZGVsbGEgU2FsdXRlMR0wGwYDVQQDDBRJdGFseSBER0MgRFNDIFRFU1QgMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDSp7t86JxAmjZFobmmu0wkii53snRuwqVWe3/g/wVz9i306XA5iXpHkRPZVUkSZmYhutMDrheg6sfwMRdql3aajgb8wgbwwHwYDVR0jBBgwFoAUS2iy4oMAoxUY87nZRidUqYg9yyMwagYDVR0fBGMwYTBfoF2gW4ZZbGRhcDovL2NhZHMuZGdjLmdvdi5pdC9DTj1JdGFseSUyMERHQyUyMENTQ0ElMjBURVNUJTIwMSxPPU1pbmlzdGVybyUyMGRlbGxhJTIwU2FsdXRlLEM9SVQwHQYDVR0OBBYEFNSEwjzu61pAMqliNhS9vzGJFqFFMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAIF74yHgzCGdor5MaqYSvkS5aog5+7u52TGggiPl78QAmIpjPO5qcYpJZVf6AoL4MpveEI/iuCUVQxBzYqlLACjSbZEbtTBPSzuhfvsf9T3MUq5cu10lkHKbFgApUDjrMUnG9SMqmQU2Cv5S4t94ec2iLmokXmhYP/JojRXt1ZMZlsw/8/lRJ8vqPUorJ/fMvOLWDE/fDxNhh3uK5UHBhRXCT8MBep4cgt9cuT9O4w1JcejSr5nsEfeo8u9Pb/h6MnmxpBSq3JbnjONVK5ak7iwCkLr5PMk09ncqG+/8Kq+qTjNC76IetS9ST6bWzTZILX4BD1BL8bHsFGgIeeCO0GqalFZAsbapnaB+36HVUZVDYOoA+VraIWECNxXViikZdjQONaeWDVhCxZ/vBl1/KLAdX3OPxRwl/jHLnaSXeqr/zYf9a8UqFrpadT0tQff/q3yH5hJRJM0P6Yp5CPIEArJRW6ovDBbp3DVF2GyAI1lFA2Trs798NN6qf7SkuySz5HSzm53g6JsLY/HLzdwJPYLObD7U+x37n+DDi4Wa6vM5xdC7FZ5IyWXuT1oAa9yM4h6nW3UvC+wNUusW6adqqtdd4F1gHPjCf5lpW5Ye1bdLUmO7TGlePmbOkzEB08Mlc6atl/vkx/crfl4dq1LZivLgPBwDzE8arIk0f2vCx1+4=";
        let mut trustlist = TrustList::new();
        assert!(trustlist
            .add_key_from_certificate(&[1, 2, 3], base64_x509_cert)
            .is_ok());
    }

    #[test]
    fn it_adds_a_public_key() {
        let base64_der_public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt5hwD0cJUB5TeQIAaE7nLjeef0vV5mamR30kjErGOcReGe37dDrmFAeOqILajQTiBXzcnPaMxWUd9SK9ZRexzQ==";
        let mut trustlist = TrustList::new();
        trustlist
            .add_key_from_str(&[1, 2, 3], base64_der_public_key)
            .unwrap();
        assert_eq!(trustlist.keys.len(), 1);
        assert!(trustlist.get_key(&[1, 2, 3]).is_some())
    }

    #[test]
    fn it_creates_a_trustlist_from_json() {
        let data = json!({
          "25QCxBrBJvA=": {
            "serialNumber": "3d1f6391763b08f1",
            "subject": "C=HR, O=AKD d.o.o., CN=Croatia DGC DS 001",
            "issuer": "C=HR, O=AKD d.o.o., CN=Croatia DGC CSCA",
            "notBefore": "2021-05-20T13:17:46.000Z",
            "notAfter": "2023-05-20T13:17:45.000Z",
            "signatureAlgorithm": "ECDSA",
            "fingerprint": "678a9b63d73aa4e82ce35b455fbe8363feee98c4",
            "publicKeyAlgorithm": {
              "hash": {
                "name": "SHA-256"
              },
              "name": "ECDSA",
              "namedCurve": "P-256"
            },
            "publicKeyPem": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt5hwD0cJUB5TeQIAaE7nLjeef0vV5mamR30kjErGOcReGe37dDrmFAeOqILajQTiBXzcnPaMxWUd9SK9ZRexzQ=="
          },
          "NAyCKly+hCg=": {
            "serialNumber": "01",
            "subject": "C=DK, O=The Danish Health Data Authority, OU=The Danish Health Data Authority, CN=PROD_DSC_DGC_DK_01, E=kontakt@sundhedsdata.dk",
            "issuer": "C=DK, O=The Danish Health Data Authority, OU=The Danish Health Data Authority, CN=PROD_CSCA_DGC_DK_01, E=kontakt@sundhedsdata.dk",
            "notBefore": "2021-05-19T09:47:25.000Z",
            "notAfter": "2023-05-20T09:47:25.000Z",
            "signatureAlgorithm": "ECDSA",
            "fingerprint": "a6bbf6b1a1aca900a7c0b99e6e831272dff23e9e",
            "publicKeyAlgorithm": {
              "hash": {
                "name": "SHA-256"
              },
              "name": "ECDSA",
              "namedCurve": "P-256"
            },
            "publicKeyPem": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBmdgY/VORsecXxY/0xNNOzoJNRaVnMMmHs5jiXrGvaDOy1jzDUOyvR++Jxgf0+YuGyp5/UAY0QIh75b+JQnlHA=="
          }
        });

        let trustlist: TrustList = data.try_into().unwrap();
        assert_eq!(trustlist.keys.len(), 2);
        let first_key = trustlist.get_key(&base64::decode("25QCxBrBJvA=").unwrap());
        assert!(first_key.is_some());
    }
}
