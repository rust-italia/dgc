use std::{collections::HashMap, convert::TryFrom};

#[derive(Debug, Clone)]
pub struct EddsaPublicKey {
    kid: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl EddsaPublicKey {
    pub fn new(kid: Vec<u8>, x: Vec<u8>, y: Vec<u8>) -> Self {
        EddsaPublicKey { kid, x, y }
    }
}

impl From<EddsaPublicKey> for cose::keys::CoseKey {
    fn from(val: EddsaPublicKey) -> Self {
        let mut key = cose::keys::CoseKey::new();
        key.kid(val.kid);
        key.kty(cose::keys::EC2);
        key.alg(cose::algs::ES256); // TODO: ?
        key.crv(cose::keys::ED25519);
        key.x(val.x);
        key.y(val.y);
        key.d(vec![]); // TODO: ?
        key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);

        key
    }
}

#[derive(Debug)]
pub struct TrustList {
    keys: HashMap<Vec<u8>, EddsaPublicKey>,
}

impl TrustList {
    pub fn get_key(&self, kid: Vec<u8>) -> Option<cose::keys::CoseKey> {
        self.keys.get(&kid).map(|k| k.clone().into())
    }
}

#[derive(Debug)]
pub enum KeyFromCertificateError {}

#[derive(Debug)]
pub enum TrustListFromJsonError {
    InvalidRootType,
    KeyIsNotObject(String),
    MissingPublicKeyAlgorithm(String),
    InvalidPublicKeyAlgorithm(String),
    MissingPublicKeyAlgorithmName(String),
    InvalidPublicKeyAlgorithmName(String),
    UnsupportedPublicKeyAlgorithmName(String, String),
    MissingPublicKeyAlgorithmCurve(String),
    InvalidPublicKeyAlgorithmCurve(String),
    UnsupportedPublicKeyAlgorithmCurve(String, String),
    MissingPublicKeyPem(String),
    InvalidPublicKeyPem(String),
    PublicKeyPemDecodeError(String, base64::DecodeError),
}

impl std::fmt::Display for TrustListFromJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TrustListFromJsonError::*;
        match self {
            InvalidRootType => write!(f, "The given JSON is not an object"),
            KeyIsNotObject(kid) => write!(f, "Key '{}' is not an object", kid),
            MissingPublicKeyAlgorithm(kid) => {
                write!(f, "Key '{}' does not contain 'publicKeyAlgorithm'", kid)
            }
            InvalidPublicKeyAlgorithm(kid) => {
                write!(f, "'publicKeyAlgorithm' for key '{}' is not a string", kid)
            }
            MissingPublicKeyAlgorithmName(kid) => {
                write!(
                    f,
                    "Key '{}' does not contain 'publicKeyAlgorithm.name'",
                    kid
                )
            }
            InvalidPublicKeyAlgorithmName(kid) => write!(
                f,
                "'publicKeyAlgorithm.name' for key '{}' is not a string",
                kid
            ),
            UnsupportedPublicKeyAlgorithmName(kid, found) => write!(
                f,
                "Key '{}' 'publicKeyAlgorithm.name' is '{}' where only 'ECDSA' is supported",
                kid, found
            ),
            MissingPublicKeyAlgorithmCurve(kid) => write!(
                f,
                "Key '{}' does not contain 'publicKeyAlgorithm.namedCurve'",
                kid
            ),
            InvalidPublicKeyAlgorithmCurve(kid) => write!(
                f,
                "'publicKeyAlgorithm.namedCurve' for key '{}' is not a string",
                kid
            ),
            UnsupportedPublicKeyAlgorithmCurve(kid, found) => write!(
                f,
                "Key '{}' 'publicKeyAlgorithm.namedCurve' is '{}' where only 'P-256' is supported",
                kid, found
            ),
            MissingPublicKeyPem(kid) => {
                write!(f, "Key '{}' does not contain 'publicKeyPem'", kid)
            }
            InvalidPublicKeyPem(kid) => {
                write!(f, "'publicKeyPem' for key '{}' is not a string", kid)
            }
            PublicKeyPemDecodeError(kid, base64_err) => {
                write!(
                    f,
                    "'publicKeyPem' for key '{}' could not be decoded: {:?}",
                    kid, base64_err
                )
            }
        }
    }
}

impl std::error::Error for TrustListFromJsonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TrustListFromJsonError::*;
        match self {
            PublicKeyPemDecodeError(_, e) => Some(e),
            _ => None,
        }
    }
}

impl TrustList {
    pub fn new() -> Self {
        TrustList {
            keys: HashMap::new(),
        }
    }

    pub fn add(&mut self, kid: Vec<u8>, key_x: Vec<u8>, key_y: Vec<u8>) {
        self.keys.insert(
            kid.clone(),
            EddsaPublicKey {
                kid,
                x: key_x,
                y: key_y,
            },
        );
    }

    pub fn add_key_from_certificate(
        &mut self,
        base64_cert: &str,
    ) -> Result<(), KeyFromCertificateError> {
        let certificate_der = base64::decode(base64_cert).unwrap();
        let parsed_cert = der_parser::parse_der(&certificate_der).unwrap();

        dbg!(parsed_cert);
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
        let mut trustlist = TrustList::default();

        if !data.is_object() {
            return Err(TrustListFromJsonError::InvalidRootType);
        }

        let keys = data.as_object().unwrap();

        for (kid, keydef) in keys {
            // makes sure keydef is an object
            if !keydef.is_object() {
                return Err(TrustListFromJsonError::KeyIsNotObject(kid.clone()));
            }

            // makes sure keydef contains "publicKeyAlgorithm"
            let keydef = keydef.as_object().unwrap();
            if !keydef.contains_key(&String::from("publicKeyAlgorithm")) {
                return Err(TrustListFromJsonError::MissingPublicKeyAlgorithm(
                    kid.clone(),
                ));
            }

            // "publicKeyAlgorithm" must be an object that contains
            // "name" == "ECDSA" and "namedCurve" == "P-256"
            let pub_key_alg = &keydef["publicKeyAlgorithm"];
            if !pub_key_alg.is_object() {
                return Err(TrustListFromJsonError::InvalidPublicKeyAlgorithm(
                    kid.clone(),
                ));
            }
            let pub_key_alg = pub_key_alg.as_object().unwrap();

            if !pub_key_alg.contains_key(&String::from("name")) {
                return Err(TrustListFromJsonError::MissingPublicKeyAlgorithmName(
                    kid.clone(),
                ));
            }

            let pub_key_alg_name = &pub_key_alg["name"];

            if !pub_key_alg_name.is_string() {
                return Err(TrustListFromJsonError::InvalidPublicKeyAlgorithmName(
                    kid.clone(),
                ));
            }

            let pub_key_alg_name = pub_key_alg_name.as_str().unwrap();
            if pub_key_alg_name != "ECDSA" {
                return Err(TrustListFromJsonError::UnsupportedPublicKeyAlgorithmName(
                    kid.clone(),
                    String::from(pub_key_alg_name),
                ));
            }

            if !pub_key_alg.contains_key(&String::from("namedCurve")) {
                return Err(TrustListFromJsonError::MissingPublicKeyAlgorithmCurve(
                    kid.clone(),
                ));
            }

            let named_curve = &pub_key_alg["namedCurve"];
            if !named_curve.is_string() {
                return Err(TrustListFromJsonError::InvalidPublicKeyAlgorithmCurve(
                    kid.clone(),
                ));
            }

            let named_curve = named_curve.as_str().unwrap();
            if named_curve != "P-256" {
                return Err(TrustListFromJsonError::UnsupportedPublicKeyAlgorithmCurve(
                    kid.clone(),
                    String::from(named_curve),
                ));
            }

            // "publicKeyPem" must exist and be a base64 encoded bynary string
            if !keydef.contains_key(&String::from("publicKeyPem")) {
                return Err(TrustListFromJsonError::MissingPublicKeyPem(kid.clone()));
            }

            let public_key_pem = &keydef["publicKeyPem"];
            if !public_key_pem.is_string() {
                return Err(TrustListFromJsonError::InvalidPublicKeyPem(kid.clone()));
            }
            let public_key_pem = public_key_pem.as_str().unwrap();
            let public_key_pem = base64::decode(public_key_pem)
                .map_err(|e| TrustListFromJsonError::PublicKeyPemDecodeError(kid.clone(), e))?;

            // Manually parses the BER structure to extract x,y from EDDSA public keys
            // TODO: better error handling here or maybe find a library to do this
            let parsed_public_key = der_parser::parse_der(&public_key_pem).unwrap().1;
            let parsed_public_key = &parsed_public_key.content.as_sequence().unwrap()[1];
            let parsed_public_key = &parsed_public_key.content.as_bitstring().unwrap().data;
            let public_key_x = parsed_public_key[1..=32].to_vec();
            let public_key_y = parsed_public_key[33..=64].to_vec();

            // creates key
            let kid = kid.clone().into_bytes();
            let key = EddsaPublicKey::new(kid.clone(), public_key_x, public_key_y);
            trustlist.keys.insert(kid, key);
        }

        Ok(trustlist)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use serde_json::json;

    use super::*;

    #[test]
    fn it_adds_the_public_key_from_a_certificate() {
        let cert = "MIIEHjCCAgagAwIBAgIUM5lJeGCHoRF1raR6cbZqDV4vPA8wDQYJKoZIhvcNAQELBQAwTjELMAkGA1UEBhMCSVQxHzAdBgNVBAoMFk1pbmlzdGVybyBkZWxsYSBTYWx1dGUxHjAcBgNVBAMMFUl0YWx5IERHQyBDU0NBIFRFU1QgMTAeFw0yMTA1MDcxNzAyMTZaFw0yMzA1MDgxNzAyMTZaME0xCzAJBgNVBAYTAklUMR8wHQYDVQQKDBZNaW5pc3Rlcm8gZGVsbGEgU2FsdXRlMR0wGwYDVQQDDBRJdGFseSBER0MgRFNDIFRFU1QgMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDSp7t86JxAmjZFobmmu0wkii53snRuwqVWe3/g/wVz9i306XA5iXpHkRPZVUkSZmYhutMDrheg6sfwMRdql3aajgb8wgbwwHwYDVR0jBBgwFoAUS2iy4oMAoxUY87nZRidUqYg9yyMwagYDVR0fBGMwYTBfoF2gW4ZZbGRhcDovL2NhZHMuZGdjLmdvdi5pdC9DTj1JdGFseSUyMERHQyUyMENTQ0ElMjBURVNUJTIwMSxPPU1pbmlzdGVybyUyMGRlbGxhJTIwU2FsdXRlLEM9SVQwHQYDVR0OBBYEFNSEwjzu61pAMqliNhS9vzGJFqFFMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAIF74yHgzCGdor5MaqYSvkS5aog5+7u52TGggiPl78QAmIpjPO5qcYpJZVf6AoL4MpveEI/iuCUVQxBzYqlLACjSbZEbtTBPSzuhfvsf9T3MUq5cu10lkHKbFgApUDjrMUnG9SMqmQU2Cv5S4t94ec2iLmokXmhYP/JojRXt1ZMZlsw/8/lRJ8vqPUorJ/fMvOLWDE/fDxNhh3uK5UHBhRXCT8MBep4cgt9cuT9O4w1JcejSr5nsEfeo8u9Pb/h6MnmxpBSq3JbnjONVK5ak7iwCkLr5PMk09ncqG+/8Kq+qTjNC76IetS9ST6bWzTZILX4BD1BL8bHsFGgIeeCO0GqalFZAsbapnaB+36HVUZVDYOoA+VraIWECNxXViikZdjQONaeWDVhCxZ/vBl1/KLAdX3OPxRwl/jHLnaSXeqr/zYf9a8UqFrpadT0tQff/q3yH5hJRJM0P6Yp5CPIEArJRW6ovDBbp3DVF2GyAI1lFA2Trs798NN6qf7SkuySz5HSzm53g6JsLY/HLzdwJPYLObD7U+x37n+DDi4Wa6vM5xdC7FZ5IyWXuT1oAa9yM4h6nW3UvC+wNUusW6adqqtdd4F1gHPjCf5lpW5Ye1bdLUmO7TGlePmbOkzEB08Mlc6atl/vkx/crfl4dq1LZivLgPBwDzE8arIk0f2vCx1+4=";
        let mut trustlist = TrustList::new();

        assert!(trustlist.add_key_from_certificate(cert).is_ok());
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
        let first_key = trustlist.get_key("25QCxBrBJvA=".as_bytes().to_vec());
        assert!(first_key.is_some());
        assert_eq!(first_key.unwrap().kid.unwrap(), b"25QCxBrBJvA=".to_vec());
    }
}
