use crate::{Cwt, CwtParseError, DgcContainer, EcAlg, TrustList};
use ring::signature;
use std::{convert::TryInto, fmt::Display};
use thiserror::Error;

/// Represents all the possible types of failures that can occure when parsing a certificate.
#[derive(Error, Debug)]
pub enum ParseError {
    /// Found less than 4 bytes.
    #[error("Invalid data, expected more than 4 bytes, found {0} bytes")]
    NotEnoughData(usize),
    /// Invalid prefix
    #[error("Invalid prefix. Expected 'HC1:', found: '{0}'")]
    InvalidPrefix(String),
    /// Error decoding using base45
    #[error("Cannot base45 decode the data: {0}")]
    Base45Decode(#[from] base45::DecodeError),
    /// Error decompressing using zlib inflate
    #[error("Could not decompress the data: {0}")]
    Deflate(String),
    /// Error decoding the CWT payload
    #[error("Could not decode CWT data: {0}")]
    CwtDecode(#[from] CwtParseError),
}

/// Represents all the possible outcomes of trying to validate a signature
/// for a given certificate.
#[derive(Debug)]
pub enum SignatureValidity {
    /// The signature is valid
    Valid,
    /// The signature is not valid
    Invalid,
    /// The signature could not be validated because the certificate did not have a kid
    MissingKid,
    /// The signature could not be validated because the certificate did not have an alg
    MissingSigningAlgorithm,
    /// The signature in the certificate is malformed
    SignatureMalformed,
    /// The signature could not be validated because the signing algorithm is not supported
    UnsupportedSigningAlgorithm(String),
    /// The signature could not be validated because the public key was not found in the given trustlist
    KeyNotInTrustList(Vec<u8>),
}

impl Display for SignatureValidity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SignatureValidity::*;
        match self {
            Valid => write!(f, "Valid Signature"),
            Invalid => write!(f, "Invalid Signature"),
            MissingKid => write!(f, "The certificate did not specify a Key Id (kid)"),
            MissingSigningAlgorithm => {
                write!(
                    f,
                    "The certificate did not specify a signing algorithm (alg)"
                )
            }
            SignatureMalformed => {
                write!(f, "The signature bytes are malformed")
            }
            UnsupportedSigningAlgorithm(alg) => {
                write!(
                    f,
                    "The signature algorithm '{}' is not supported by this library",
                    alg
                )
            }
            KeyNotInTrustList(kid) => {
                write!(
                    f,
                    "The public key '{}' was not found in the given trustlist",
                    base64::encode(kid)
                )
            }
        }
    }
}

impl SignatureValidity {
    /// Checks if the signature is valid
    pub fn is_valid(&self) -> bool {
        matches!(self, SignatureValidity::Valid)
    }
}

fn remove_prefix(data: &'_ str) -> Result<&'_ str, ParseError> {
    // check minimum data length
    if data.len() <= 4 {
        return Err(ParseError::NotEnoughData(data.len()));
    }

    // check HC1: header
    if !data.starts_with("HC1:") {
        return Err(ParseError::InvalidPrefix(data.chars().take(4).collect()));
    }

    Ok(&data[4..])
}

fn decode_base45(data: &str) -> Result<Vec<u8>, ParseError> {
    let decoded = base45::decode(data)?;
    Ok(decoded)
}

fn decompress(data: Vec<u8>) -> Result<Vec<u8>, ParseError> {
    let decompressed = inflate::inflate_bytes_zlib(&data).map_err(ParseError::Deflate)?;
    Ok(decompressed)
}

fn parse_cwt_payload(data: Vec<u8>) -> Result<Cwt, ParseError> {
    let cwt: Cwt = data.try_into()?;
    Ok(cwt)
}

/// Parses and validates a given certificate.
///
/// This function is a high level helper that allows you to extract the data from a
/// certificate and at the same time it tries to validate the signature against a given
/// trustlist.
///
/// This function will return an error if the certificate cannot be parsed.
/// If the certificate can be parsed correctly, this function returns a tuple containing a
/// [`DgcContainer`] and a [`SignatureValidity`].
///
/// This design allows for permissive validation of the certificate signature.
/// In fact, `SignatureValidity` can be used to determine if the signature is valid and even if it is
/// invalid (or the validity cannot be assessed) you could still access all the information
/// in the certificate.
///
/// ## Example
///
/// ```
/// let raw_certificate_data = "HC1:NCF:603A0T9WTWGSLKC 4K694WJN.0J$6C-7WAB0XK3JCSGA2F3R8PP4V2F35VPP.EY50.FK8ZKO/EZKEZ96LF6/A6..DV%DZJC0/D5UA QELPCG/DYUCHY83UAGVC*JCNF6F463W5KF6VF6IECSHG4KCD3DX47B46IL6646H*6MWEWJDA6A:961A6Q47EM6B$DFOC0R63KCZPCNF6OF63W5$Q6+96/SA5R6NF61G73564KC*KETF6A46.96646B565WEC.D1$CKWEDZC6VCS446$C4WEUPC3JCUIA+ED$.EF$DMWE8$CBJEMVCB445$CBWER.CGPC4WEOPCE8FHZA1+9LZAZM81G72A62+8OG7J09U47AB8V59T%6ZHBO57X48RUIY03XQOK*FZUNM UFY4D5C S3R9UW-2R*4KZJT5M MIM:03RMZNA LKTO34PA.H51966PS0KAP-KLPH.Q6$KSTJ0-G658RL5HR1";
/// // This is a X509 certificate that contains a Public Key
/// let signature_certificate = "MIIDujCCAaKgAwIBAgIIKUgZWBL1pnMwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCRlIxHTAbBgNVBAoTFElNUFJJTUVSSUUgTkFUSU9OQUxFMR4wHAYDVQQLExVGT1IgVEVTVCBQVVJQT1NFIE9OTFkxGDAWBgNVBAMTD0lOR1JPVVBFIERTYyBDQTAeFw0yMTA2MDIxMjE0MDBaFw0yMTA5MDIxMjE0MDBaMEAxCzAJBgNVBAYTAkZSMREwDwYDVQQKDAhDRVJUSUdOQTEeMBwGA1UEAwwVQ0VSVElHTkEgLSBURVNUIERHQyAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETdygPqv/l6tWFqHFEIEZxfdhtbrBpDgVjmUN4CKOu/EQFwkVVQ/4N0BamwtI0hSnSZP72byk6XqpMErYWRTCbKNdMFswCQYDVR0TBAIwADAdBgNVHQ4EFgQUUjXs7mCY2ZgROQSsw1CN0qM4Zj8wHwYDVR0jBBgwFoAUYLoYTllzE2jOy3VMAuU4OJjOingwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAvxuSBWNOrk+FRIbU42tnwZBllUeNH7cWcrYHV0O+1k3RbpvYa0YE2J0du301/a+0+pqlatR8o8Coe/NFt4/KSu+To+i8uZXiHJn2XrAZgwPqqTvsMUVwFPWhwJpLMCejmU0A8JEhXH7s0BN6orqIH0JKLpl0/MdVviIUksnxPnP2wdCtz6dL5zKhi+Qt8BFr55PL1dvuWxnuFOsKr89MqaexQVe/WvKhG5GXBaJFDbp4USVX9Z8vwp4SfEs5nh0ti0M2fyGrpfPvWWFra/qoRGAUJEPHHPMqZT45c1rXo12+cpme2CYM4rsliQsaqdH462p7YNNI5reBC+WHhzGr9FGq9yZ1gu/yhz1cJxNwE5gsBTWnJmSnRE75lYj1a/GAb+9wfABd1Vx68Fnww3Ngp8lG2T1vEWhwQusj/OmloVbqjJiCi6PcZ1/OSTbx58Zv9ySwDd3QGxPygfMy87FuhT6iWlPv57qTMrgtEjq89J8v3WnReAhp12ru5ehN2Zv0ZkO1Of0H3yxNBsvfHUgpgwsRn4zjLVbkU+a3hr4famOThmB1X0tuikY0mbNtVejPGS0qCgeLgj8ILlUrRtsW4R6WzZdIsz7H9AYnpyZbdMPsa856xBR9s0+AzguJI9kkJxvVcpR//GiXMhs0EdgWj2rouOEPZiFNdWpVRrxv/kw==";
///
/// // We create a new Trustlist (container of "trusted" public keys)
/// let mut trustlist = dgc::TrustList::default();
/// // We add the public key in the certificate to the trustlist
/// trustlist
///     .add_key_from_certificate(signature_certificate)
///     .expect("Failed to add key from certificate");
///
/// // Now we can validate the signature (this returns)
/// let (certificate_container, signature_validity) =
///     dgc::validate(raw_certificate_data, &trustlist).expect("Cannot parse certificate data");
///
/// // Prints the infomration inside the container
/// println!("{:#?}", &certificate_container);
///
/// // Checks the validity of the signature
/// assert!(signature_validity.is_valid());
/// ```
pub fn validate(
    data: &str,
    trustlist: &TrustList,
) -> Result<(DgcContainer, SignatureValidity), ParseError> {
    let cwt = decode_cwt(data)?;

    let kid = match &cwt.header.kid {
        None => return Ok((cwt.payload, SignatureValidity::MissingKid)),
        Some(kid) => kid,
    };

    let key = match trustlist.get_key(kid) {
        None => {
            return Ok((
                cwt.payload,
                SignatureValidity::KeyNotInTrustList(kid.clone()),
            ))
        }
        Some(key) => key,
    };

    let signature = &cwt.signature;
    let data = cwt.make_sig_structure();
    let result = match cwt.header.alg {
        None => return Ok((cwt.payload, SignatureValidity::MissingSigningAlgorithm)),
        Some(alg) => match alg {
            EcAlg::Es256 => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
                    .verify(&data, signature)
            }
            EcAlg::Ps256 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, key)
                    .verify(&data, signature)
            }
            EcAlg::Unknown(alg) => {
                return Ok((
                    cwt.payload,
                    SignatureValidity::UnsupportedSigningAlgorithm(format!("{:?}", alg)),
                ))
            }
        },
    };
    match result {
        Err(_) => Ok((cwt.payload, SignatureValidity::Invalid)),
        Ok(_) => Ok((cwt.payload, SignatureValidity::Valid)),
    }
}

/// Decodes the certificate and returns the [`Cwt`] data contained in it.
///
/// You generally don't need to use this function unless you need to access
/// the raw information contained in the [`Cwt`] structure.
pub fn decode_cwt(data: &str) -> Result<Cwt, ParseError> {
    // remove prefix
    let data = remove_prefix(data)?;

    // base45 decode
    let decoded = decode_base45(data)?;

    // decompress the data
    let decompressed = decompress(decoded)?;

    // parse cose payload
    let cwt = parse_cwt_payload(decompressed)?;

    Ok(cwt)
}

/// Decodes the certificate and returns the [`DgcContainer`] data contained in it.
///
/// This function is recommended when you don't want to validate the signature but you
/// are just interested in reading the content of the certificate.
///
/// ## Example
///
/// ```
/// let raw_certificate_data = "HC1:NCF:603A0T9WTWGSLKC 4K694WJN.0J$6C-7WAB0XK3JCSGA2F3R8PP4V2F35VPP.EY50.FK8ZKO/EZKEZ96LF6/A6..DV%DZJC0/D5UA QELPCG/DYUCHY83UAGVC*JCNF6F463W5KF6VF6IECSHG4KCD3DX47B46IL6646H*6MWEWJDA6A:961A6Q47EM6B$DFOC0R63KCZPCNF6OF63W5$Q6+96/SA5R6NF61G73564KC*KETF6A46.96646B565WEC.D1$CKWEDZC6VCS446$C4WEUPC3JCUIA+ED$.EF$DMWE8$CBJEMVCB445$CBWER.CGPC4WEOPCE8FHZA1+9LZAZM81G72A62+8OG7J09U47AB8V59T%6ZHBO57X48RUIY03XQOK*FZUNM UFY4D5C S3R9UW-2R*4KZJT5M MIM:03RMZNA LKTO34PA.H51966PS0KAP-KLPH.Q6$KSTJ0-G658RL5HR1";
///
/// let certificate_container =
/// dgc::decode(raw_certificate_data).expect("Cannot parse certificate data");
///
/// println!("{:#?}", certificate_container);
/// ```
pub fn decode(data: &str) -> Result<DgcContainer, ParseError> {
    let cwt = decode_cwt(data)?;
    Ok(cwt.payload)
}

#[cfg(test)]
mod tests {
    // test data from https://dgc.a-sit.at/ehn/generate
    use super::*;

    #[test]
    fn it_removes_prefix() {
        let data = "HC1:NCFOXN%TS3DH3ZSUZK+.V0ETD%65NL-AH-R6IOO6+IDOEZ/18WAV$E3+3AT4V22F/8X*G3M9JUPY0BX/KR96R/S09T./0LWTKD33236J3TA3M*4VV2 73-E3GG396B-43O058YIB73A*G3W19UEBY5:PI0EGSP4*2DN43U*0CEBQ/GXQFY73CIBC:G 7376BXBJBAJ UNFMJCRN0H3PQN*E33H3OA70M3FMJIJN523.K5QZ4A+2XEN QT QTHC31M3+E32R44$28A9H0D3ZCL4JMYAZ+S-A5$XKX6T2YC 35H/ITX8GL2-LH/CJTK96L6SR9MU9RFGJA6Q3QR$P2OIC0JVLA8J3ET3:H3A+2+33U SAAUOT3TPTO4UBZIC0JKQTL*QDKBO.AI9BVYTOCFOPS4IJCOT0$89NT2V457U8+9W2KQ-7LF9-DF07U$B97JJ1D7WKP/HLIJLRKF1MFHJP7NVDEBU1J*Z222E.GJI77N IKXN9+6J5DG3VWU5ZXT$ZRWP7++KM5MMUN/7UTFEEZPBK8C 7KMBI.3ZDBDREY7IM*N1KS3UI$6JD.JKLKA3UBJM-SJ9:OHBURZEF50WAQ 3";
        let without_prefix = remove_prefix(data).unwrap();

        let expected = "NCFOXN%TS3DH3ZSUZK+.V0ETD%65NL-AH-R6IOO6+IDOEZ/18WAV$E3+3AT4V22F/8X*G3M9JUPY0BX/KR96R/S09T./0LWTKD33236J3TA3M*4VV2 73-E3GG396B-43O058YIB73A*G3W19UEBY5:PI0EGSP4*2DN43U*0CEBQ/GXQFY73CIBC:G 7376BXBJBAJ UNFMJCRN0H3PQN*E33H3OA70M3FMJIJN523.K5QZ4A+2XEN QT QTHC31M3+E32R44$28A9H0D3ZCL4JMYAZ+S-A5$XKX6T2YC 35H/ITX8GL2-LH/CJTK96L6SR9MU9RFGJA6Q3QR$P2OIC0JVLA8J3ET3:H3A+2+33U SAAUOT3TPTO4UBZIC0JKQTL*QDKBO.AI9BVYTOCFOPS4IJCOT0$89NT2V457U8+9W2KQ-7LF9-DF07U$B97JJ1D7WKP/HLIJLRKF1MFHJP7NVDEBU1J*Z222E.GJI77N IKXN9+6J5DG3VWU5ZXT$ZRWP7++KM5MMUN/7UTFEEZPBK8C 7KMBI.3ZDBDREY7IM*N1KS3UI$6JD.JKLKA3UBJM-SJ9:OHBURZEF50WAQ 3";
        assert_eq!(expected, without_prefix);
    }

    #[test]
    fn it_decodes_base45() {
        let data = "NCFOXN%TS3DH3ZSUZK+.V0ETD%65NL-AH-R6IOO6+IDOEZ/18WAV$E3+3AT4V22F/8X*G3M9JUPY0BX/KR96R/S09T./0LWTKD33236J3TA3M*4VV2 73-E3GG396B-43O058YIB73A*G3W19UEBY5:PI0EGSP4*2DN43U*0CEBQ/GXQFY73CIBC:G 7376BXBJBAJ UNFMJCRN0H3PQN*E33H3OA70M3FMJIJN523.K5QZ4A+2XEN QT QTHC31M3+E32R44$28A9H0D3ZCL4JMYAZ+S-A5$XKX6T2YC 35H/ITX8GL2-LH/CJTK96L6SR9MU9RFGJA6Q3QR$P2OIC0JVLA8J3ET3:H3A+2+33U SAAUOT3TPTO4UBZIC0JKQTL*QDKBO.AI9BVYTOCFOPS4IJCOT0$89NT2V457U8+9W2KQ-7LF9-DF07U$B97JJ1D7WKP/HLIJLRKF1MFHJP7NVDEBU1J*Z222E.GJI77N IKXN9+6J5DG3VWU5ZXT$ZRWP7++KM5MMUN/7UTFEEZPBK8C 7KMBI.3ZDBDREY7IM*N1KS3UI$6JD.JKLKA3UBJM-SJ9:OHBURZEF50WAQ 3";
        let decoded = hex::encode(decode_base45(data).unwrap());

        let expected = "78dabbd4e2bb88c5e3a6a479fcc1e7db3631aa2d8864345ec222957073030f9b54c2755e1ec624c7104b46e6858c4b12cb1a5725a5e43126e526e6fa07b9eb1a1a1818181b18199a26951564191a1a5a1a9b581a189827a59464190185750d8c740d2d9292f3810624256756188606f9598586397b5a19185a398658191a5818985b9818bb599a38baba1ab8ba9a1a581abb39391b999a38b958181a2b3b25e516e4b886ea1bea1b19e81b9a1a592465165748fb66e665169714552ae4a72978a426e69464e828389602453213938a5398924ad2332d4c0c4c8d814e314bce4bcc5d929c965752ea1b1a1ce21ae416e4186ae3eeef1a1cece9e7ee1a94949657ea0bd49a5a94569458aaeb7e78dbe1f99979e9a945c9e9792519ee8e4e419eae3eae49e97919ee89494599a939a9c965a945a9867a467a86c929f9495986969616206f1a994538ac94cdbbd0368767c9f5ce2cf3eb55dbdf3be4a564aefdbb4beeb4717ecbf642d73dbf5af51f2f596f738a8fbfbce0e10193ab977e9dbaa1f9eddfb1689b60c59def4e750000f0cf8cab";
        assert_eq!(expected, decoded);
    }

    #[test]
    fn it_decompress() {
        let data = hex::decode("78dabbd4e2bb88c5e3a6a479fcc1e7db3631aa2d8864345ec222957073030f9b54c2755e1ec624c7104b46e6858c4b12cb1a5725a5e43126e526e6fa07b9eb1a1a1818181b18199a26951564191a1a5a1a9b581a189827a59464190185750d8c740d2d9292f3810624256756188606f9598586397b5a19185a398658191a5818985b9818bb599a38baba1ab8ba9a1a581abb39391b999a38b958181a2b3b25e516e4b886ea1bea1b19e81b9a1a592465165748fb66e665169714552ae4a72978a426e69464e828389602453213938a5398924ad2332d4c0c4c8d814e314bce4bcc5d929c965752ea1b1a1ce21ae416e4186ae3eeef1a1cece9e7ee1a94949657ea0bd49a5a94569458aaeb7e78dbe1f99979e9a945c9e9792519ee8e4e419eae3eae49e97919ee89494599a939a9c965a945a9867a467a86c929f9495986969616206f1a994538ac94cdbbd0368767c9f5ce2cf3eb55dbdf3be4a564aefdbb4beeb4717ecbf642d73dbf5af51f2f596f738a8fbfbce0e10193ab977e9dbaa1f9eddfb1689b60c59def4e750000f0cf8cab").unwrap();
        let decompressed = hex::encode(decompress(data).unwrap());

        let expected = "d2844da20448d919375fc1e7b6b20126a0590133a4041a60d9b00c061a60d70d0c01624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e322e3163646f626a313939382d30322d32365840a91d6ed0869c0ca4d7896a37d77ab7ef406e6469adfdba1ecb336f84b77145bcfa852fe3a4af3cca0e0f7770e1c034d5d2facad829f6fec65b3c5321b9eeca88";
        assert_eq!(expected, decompressed);
    }

    #[test]
    fn it_parses_cwt_payload() {
        let data = hex::decode("d2844da20448d919375fc1e7b6b20126a0590133a4041a60d9b00c061a60d70d0c01624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e322e3163646f626a313939382d30322d32365840a91d6ed0869c0ca4d7896a37d77ab7ef406e6469adfdba1ecb336f84b77145bcfa852fe3a4af3cca0e0f7770e1c034d5d2facad829f6fec65b3c5321b9eeca88").unwrap();
        let sig_structure = hex::encode(parse_cwt_payload(data).unwrap().make_sig_structure());

        let expected = "846a5369676e6174757265314da20448d919375fc1e7b6b2012640590133a4041a60d9b00c061a60d70d0c01624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e322e3163646f626a313939382d30322d3236";
        assert_eq!(expected, sig_structure);
    }

    #[test]
    fn it_decodes() {
        let data = "HC1:NCFOXN%TS3DH3ZSUZK+.V0ETD%65NL-AH-R6IOO6+IDOEZ/18WAV$E3+3AT4V22F/8X*G3M9JUPY0BX/KR96R/S09T./0LWTKD33236J3TA3M*4VV2 73-E3GG396B-43O058YIB73A*G3W19UEBY5:PI0EGSP4*2DN43U*0CEBQ/GXQFY73CIBC:G 7376BXBJBAJ UNFMJCRN0H3PQN*E33H3OA70M3FMJIJN523.K5QZ4A+2XEN QT QTHC31M3+E32R44$28A9H0D3ZCL4JMYAZ+S-A5$XKX6T2YC 35H/ITX8GL2-LH/CJTK96L6SR9MU9RFGJA6Q3QR$P2OIC0JVLA8J3ET3:H3A+2+33U SAAUOT3TPTO4UBZIC0JKQTL*QDKBO.AI9BVYTOCFOPS4IJCOT0$89NT2V457U8+9W2KQ-7LF9-DF07U$B97JJ1D7WKP/HLIJLRKF1MFHJP7NVDEBU1J*Z222E.GJI77N IKXN9+6J5DG3VWU5ZXT$ZRWP7++KM5MMUN/7UTFEEZPBK8C 7KMBI.3ZDBDREY7IM*N1KS3UI$6JD.JKLKA3UBJM-SJ9:OHBURZEF50WAQ 3";
        let dgc_cert_container = decode(data).unwrap();

        let expected: DgcContainer = serde_json::from_str("{\"4\":1624879116,\"6\":1624706316,\"1\":\"AT\",\"-260\":{\"1\":{\"v\":[{\"dn\":1,\"ma\":\"ORG-100030215\",\"vp\":\"1119349007\",\"dt\":\"2021-02-18\",\"co\":\"AT\",\"ci\":\"URN:UVCI:01:AT:10807843F94AEE0EE5093FBC254BD813#B\",\"mp\":\"EU/1/20/1528\",\"is\":\"Ministry of Health, Austria\",\"sd\":2,\"tg\":\"840539006\"}],\"nam\":{\"fnt\":\"MUSTERFRAU<GOESSINGER\",\"fn\":\"Musterfrau-Gößinger\",\"gnt\":\"GABRIELE\",\"gn\":\"Gabriele\"},\"ver\":\"1.2.1\",\"dob\":\"1998-02-26\"}}}").unwrap();
        assert_eq!(expected, dgc_cert_container);
    }

    #[test]
    fn it_validates() {
        let data = "HC1:6BFOXN%TS3DH0YOJ58S S-W5HDC *M0II5XHC9B5G2+$N IOP-IA%NFQGRJPC%OQHIZC4.OI1RM8ZA.A5:S9MKN4NN3F85QNCY0O%0VZ001HOC9JU0D0HT0HB2PL/IB*09B9LW4T*8+DCMH0LDK2%K:XFE70*LP$V25$0Q:J:4MO1P0%0L0HD+9E/HY+4J6TH48S%4K.GJ2PT3QY:GQ3TE2I+-CPHN6D7LLK*2HG%89UV-0LZ 2ZJJ524-LH/CJTK96L6SR9MU9DHGZ%P WUQRENS431T1XCNCF+47AY0-IFO0500TGPN8F5G.41Q2E4T8ALW.INSV$ 07UV5SR+BNQHNML7 /KD3TU 4V*CAT3ZGLQMI/XI%ZJNSBBXK2:UG%UJMI:TU+MMPZ5$/PMX19UE:-PSR3/$NU44CBE6DQ3D7B0FBOFX0DV2DGMB$YPF62I$60/F$Z2I6IFX21XNI-LM%3/DF/U6Z9FEOJVRLVW6K$UG+BKK57:1+D10%4K83F+1VWD1NE";
        let kid: Vec<u8> = vec![57, 48, 23, 104, 205, 218, 5, 19];
        let key_data = "BDSp7t86JxAmjZFobmmu0wkii53snRuwqVWe3/g/wVz9i306XA5iXpHkRPZVUkSZmYhutMDrheg6sfwMRdql3aY=";

        let mut trustlist = TrustList::new();
        trustlist
            .add_key_from_base64(kid.as_slice(), key_data)
            .unwrap();

        let (_, signature_validity) = validate(data, &trustlist).unwrap();
        assert!(matches!(signature_validity, SignatureValidity::Valid));
    }
}
