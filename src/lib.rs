use error::Error;
use trustlist::TrustList;
pub mod error;
pub mod trustlist;

#[derive(Debug)]
pub enum CertValidity {
    Valid,
    Expired,
    NotValidYet,
    InvalidSignature,
    ExpiredCertificate,
    MissingKid,
    KeyNotInTrustList,
}

#[derive(Debug)]
pub struct Cert {
    data: serde_json::Value,
    kid: Vec<u8>,
    validity: CertValidity,
}

impl Cert {
    pub fn new(data: serde_json::Value, kid: Vec<u8>, validity: CertValidity) -> Self {
        Cert {
            data,
            kid,
            validity,
        }
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.validity, CertValidity::Valid)
    }
}

fn remove_prefix(data: &'_ str) -> Result<&'_ str, Error> {
    // check minimum data length
    if data.len() <= 4 {
        return Err(Error::NotEnoughData(data.len()));
    }

    // check HC1: header
    if &data[0..4] != "HC1:" {
        return Err(Error::InvalidPrefix(String::from(&data[0..3])));
    }

    Ok(&data[4..])
}

fn decode_base45(data: &str) -> Result<Vec<u8>, Error> {
    let decoded = base45::decode(data)?;
    Ok(decoded)
}

fn decompress(data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let decompressed = inflate::inflate_bytes_zlib(&data).map_err(Error::Deflate)?;
    Ok(decompressed)
}

fn parse_cose_payload(data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut sign1 = cose::sign::CoseSign::new();
    sign1.bytes = data;
    sign1.init_decoder(None)?;

    Ok(sign1.payload)
}

fn cbor_to_json(data: &[u8]) -> Result<String, Error> {
    let mut output: Vec<u8> = vec![];
    let mut deserializer = serde_cbor::Deserializer::from_slice(data);
    let mut serializer = serde_json::Serializer::new(&mut output);

    serde_transcode::transcode(&mut deserializer, &mut serializer)?;

    Ok(String::from_utf8(output).unwrap())
}

pub fn decode_to_json_string(data: &str) -> Result<String, Error> {
    // remove prefix
    let data = remove_prefix(data)?;

    // base45 decode
    let decoded = decode_base45(data)?;

    // decompress the data
    let decompressed = decompress(decoded)?;

    // parse cose payload
    let payload = parse_cose_payload(decompressed)?;

    // converts CBOR data to JSON
    let json_str = cbor_to_json(&payload)?;

    Ok(json_str)
}

pub fn validate(data: &str, trustlist: &TrustList) -> Result<Cert, Error> {
    // remove prefix
    let data = remove_prefix(data)?;

    // base45 decode
    let decoded = decode_base45(data)?;

    // decompress the data
    let decompressed = decompress(decoded)?;

    let mut sign1 = cose::sign::CoseSign::new();
    sign1.bytes = decompressed;
    sign1.init_decoder(None);

    // converts CBOR data to JSON
    let json_data = cbor_to_json(&sign1.payload)?;
    let json_data: serde_json::Value = serde_json::from_str(json_data.as_str()).unwrap();

    // if the kid (key id) is missing in the header we can't validate
    if sign1.header.kid.is_none() {
        return Ok(Cert::new(json_data, vec![], CertValidity::MissingKid));
    }

    let kid = sign1.header.kid.clone().unwrap();

    let key = trustlist.get_key(kid.clone());

    // if we don't have the given key in our trust list we can't validate
    if key.is_none() {
        return Ok(Cert::new(json_data, kid, CertValidity::KeyNotInTrustList));
    }

    // TODO: validate possible failure here
    dbg!(sign1.key(&key.unwrap()));
    let result = sign1.decode(None, None);

    if result.is_err() {
        dbg!(&result);
        return Ok(Cert::new(json_data, kid, CertValidity::InvalidSignature));
    }

    // TODO: validate time validity for certificate and signing key
    Ok(Cert::new(json_data, kid, CertValidity::Valid))
}

pub fn decode(data: &str) -> Result<serde_json::Value, Error> {
    let json_data = decode_to_json_string(data)?;
    let data: serde_json::Value = serde_json::from_str(json_data.as_str()).unwrap();
    Ok(data)
}

#[cfg(test)]
mod tests {
    // test data from https://dgc.a-sit.at/ehn/generate

    use rustc_serialize::hex::ToHex;

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
        let decoded = decode_base45(data).unwrap().to_hex();

        let expected = "78dabbd4e2bb88c5e3a6a479fcc1e7db3631aa2d8864345ec222957073030f9b54c2755e1ec624c7104b46e6858c4b12cb1a5725a5e43126e526e6fa07b9eb1a1a1818181b18199a26951564191a1a5a1a9b581a189827a59464190185750d8c740d2d9292f3810624256756188606f9598586397b5a19185a398658191a5818985b9818bb599a38baba1ab8ba9a1a581abb39391b999a38b958181a2b3b25e516e4b886ea1bea1b19e81b9a1a592465165748fb66e665169714552ae4a72978a426e69464e828389602453213938a5398924ad2332d4c0c4c8d814e314bce4bcc5d929c965752ea1b1a1ce21ae416e4186ae3eeef1a1cece9e7ee1a94949657ea0bd49a5a94569458aaeb7e78dbe1f99979e9a945c9e9792519ee8e4e419eae3eae49e97919ee89494599a939a9c965a945a9867a467a86c929f9495986969616206f1a994538ac94cdbbd0368767c9f5ce2cf3eb55dbdf3be4a564aefdbb4beeb4717ecbf642d73dbf5af51f2f596f738a8fbfbce0e10193ab977e9dbaa1f9eddfb1689b60c59def4e750000f0cf8cab";
        assert_eq!(expected, decoded);
    }

    #[test]
    fn it_decompress() {
        let data = hex::decode("78dabbd4e2bb88c5e3a6a479fcc1e7db3631aa2d8864345ec222957073030f9b54c2755e1ec624c7104b46e6858c4b12cb1a5725a5e43126e526e6fa07b9eb1a1a1818181b18199a26951564191a1a5a1a9b581a189827a59464190185750d8c740d2d9292f3810624256756188606f9598586397b5a19185a398658191a5818985b9818bb599a38baba1ab8ba9a1a581abb39391b999a38b958181a2b3b25e516e4b886ea1bea1b19e81b9a1a592465165748fb66e665169714552ae4a72978a426e69464e828389602453213938a5398924ad2332d4c0c4c8d814e314bce4bcc5d929c965752ea1b1a1ce21ae416e4186ae3eeef1a1cece9e7ee1a94949657ea0bd49a5a94569458aaeb7e78dbe1f99979e9a945c9e9792519ee8e4e419eae3eae49e97919ee89494599a939a9c965a945a9867a467a86c929f9495986969616206f1a994538ac94cdbbd0368767c9f5ce2cf3eb55dbdf3be4a564aefdbb4beeb4717ecbf642d73dbf5af51f2f596f738a8fbfbce0e10193ab977e9dbaa1f9eddfb1689b60c59def4e750000f0cf8cab").unwrap();
        let decompressed = decompress(data).unwrap().to_hex();

        let expected = "d2844da20448d919375fc1e7b6b20126a0590133a4041a60d9b00c061a60d70d0c01624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e322e3163646f626a313939382d30322d32365840a91d6ed0869c0ca4d7896a37d77ab7ef406e6469adfdba1ecb336f84b77145bcfa852fe3a4af3cca0e0f7770e1c034d5d2facad829f6fec65b3c5321b9eeca88";
        assert_eq!(expected, decompressed);
    }

    #[test]
    fn it_parse_cose_payload() {
        let data = hex::decode("d2844da20448d919375fc1e7b6b20126a0590133a4041a60d9b00c061a60d70d0c01624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e322e3163646f626a313939382d30322d32365840a91d6ed0869c0ca4d7896a37d77ab7ef406e6469adfdba1ecb336f84b77145bcfa852fe3a4af3cca0e0f7770e1c034d5d2facad829f6fec65b3c5321b9eeca88").unwrap();
        let payload = parse_cose_payload(data).unwrap().to_hex();

        let expected = "a4041a60d9b00c061a60d70d0c01624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e322e3163646f626a313939382d30322d3236";
        assert_eq!(expected, payload);
    }

    #[test]
    fn it_converts_cbor_to_json() {
        let data = hex::decode("a4041a60d9b00c061a60d70d0c01624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e322e3163646f626a313939382d30322d3236").unwrap();
        let json_str = cbor_to_json(&data).unwrap();

        let expected = "{\"4\":1624879116,\"6\":1624706316,\"1\":\"AT\",\"-260\":{\"1\":{\"v\":[{\"dn\":1,\"ma\":\"ORG-100030215\",\"vp\":\"1119349007\",\"dt\":\"2021-02-18\",\"co\":\"AT\",\"ci\":\"URN:UVCI:01:AT:10807843F94AEE0EE5093FBC254BD813#B\",\"mp\":\"EU/1/20/1528\",\"is\":\"Ministry of Health, Austria\",\"sd\":2,\"tg\":\"840539006\"}],\"nam\":{\"fnt\":\"MUSTERFRAU<GOESSINGER\",\"fn\":\"Musterfrau-Gößinger\",\"gnt\":\"GABRIELE\",\"gn\":\"Gabriele\"},\"ver\":\"1.2.1\",\"dob\":\"1998-02-26\"}}}";
        assert_eq!(expected, json_str);
    }

    #[test]
    fn it_decodes_to_json_string() {
        let data = "HC1:NCFOXN%TS3DH3ZSUZK+.V0ETD%65NL-AH-R6IOO6+IDOEZ/18WAV$E3+3AT4V22F/8X*G3M9JUPY0BX/KR96R/S09T./0LWTKD33236J3TA3M*4VV2 73-E3GG396B-43O058YIB73A*G3W19UEBY5:PI0EGSP4*2DN43U*0CEBQ/GXQFY73CIBC:G 7376BXBJBAJ UNFMJCRN0H3PQN*E33H3OA70M3FMJIJN523.K5QZ4A+2XEN QT QTHC31M3+E32R44$28A9H0D3ZCL4JMYAZ+S-A5$XKX6T2YC 35H/ITX8GL2-LH/CJTK96L6SR9MU9RFGJA6Q3QR$P2OIC0JVLA8J3ET3:H3A+2+33U SAAUOT3TPTO4UBZIC0JKQTL*QDKBO.AI9BVYTOCFOPS4IJCOT0$89NT2V457U8+9W2KQ-7LF9-DF07U$B97JJ1D7WKP/HLIJLRKF1MFHJP7NVDEBU1J*Z222E.GJI77N IKXN9+6J5DG3VWU5ZXT$ZRWP7++KM5MMUN/7UTFEEZPBK8C 7KMBI.3ZDBDREY7IM*N1KS3UI$6JD.JKLKA3UBJM-SJ9:OHBURZEF50WAQ 3";
        let json_str = decode_to_json_string(data).unwrap();

        let expected = "{\"4\":1624879116,\"6\":1624706316,\"1\":\"AT\",\"-260\":{\"1\":{\"v\":[{\"dn\":1,\"ma\":\"ORG-100030215\",\"vp\":\"1119349007\",\"dt\":\"2021-02-18\",\"co\":\"AT\",\"ci\":\"URN:UVCI:01:AT:10807843F94AEE0EE5093FBC254BD813#B\",\"mp\":\"EU/1/20/1528\",\"is\":\"Ministry of Health, Austria\",\"sd\":2,\"tg\":\"840539006\"}],\"nam\":{\"fnt\":\"MUSTERFRAU<GOESSINGER\",\"fn\":\"Musterfrau-Gößinger\",\"gnt\":\"GABRIELE\",\"gn\":\"Gabriele\"},\"ver\":\"1.2.1\",\"dob\":\"1998-02-26\"}}}";
        assert_eq!(expected, json_str);
    }

    #[test]
    fn it_decodes() {
        let data = "HC1:NCFOXN%TS3DH3ZSUZK+.V0ETD%65NL-AH-R6IOO6+IDOEZ/18WAV$E3+3AT4V22F/8X*G3M9JUPY0BX/KR96R/S09T./0LWTKD33236J3TA3M*4VV2 73-E3GG396B-43O058YIB73A*G3W19UEBY5:PI0EGSP4*2DN43U*0CEBQ/GXQFY73CIBC:G 7376BXBJBAJ UNFMJCRN0H3PQN*E33H3OA70M3FMJIJN523.K5QZ4A+2XEN QT QTHC31M3+E32R44$28A9H0D3ZCL4JMYAZ+S-A5$XKX6T2YC 35H/ITX8GL2-LH/CJTK96L6SR9MU9RFGJA6Q3QR$P2OIC0JVLA8J3ET3:H3A+2+33U SAAUOT3TPTO4UBZIC0JKQTL*QDKBO.AI9BVYTOCFOPS4IJCOT0$89NT2V457U8+9W2KQ-7LF9-DF07U$B97JJ1D7WKP/HLIJLRKF1MFHJP7NVDEBU1J*Z222E.GJI77N IKXN9+6J5DG3VWU5ZXT$ZRWP7++KM5MMUN/7UTFEEZPBK8C 7KMBI.3ZDBDREY7IM*N1KS3UI$6JD.JKLKA3UBJM-SJ9:OHBURZEF50WAQ 3";
        let json_str = decode(data).unwrap();

        let expected: serde_json::Value = serde_json::from_str("{\"4\":1624879116,\"6\":1624706316,\"1\":\"AT\",\"-260\":{\"1\":{\"v\":[{\"dn\":1,\"ma\":\"ORG-100030215\",\"vp\":\"1119349007\",\"dt\":\"2021-02-18\",\"co\":\"AT\",\"ci\":\"URN:UVCI:01:AT:10807843F94AEE0EE5093FBC254BD813#B\",\"mp\":\"EU/1/20/1528\",\"is\":\"Ministry of Health, Austria\",\"sd\":2,\"tg\":\"840539006\"}],\"nam\":{\"fnt\":\"MUSTERFRAU<GOESSINGER\",\"fn\":\"Musterfrau-Gößinger\",\"gnt\":\"GABRIELE\",\"gn\":\"Gabriele\"},\"ver\":\"1.2.1\",\"dob\":\"1998-02-26\"}}}").unwrap();
        assert_eq!(expected, json_str);
    }

    #[test]
    fn it_validates() {
        let data = "HC1:NCFOXN%TS3DH3ZSUZK+.V0ETD%65NL-AH-R6IOO6+IDOEZ/18WAV$E3+3AT4V22F/8X*G3M9JUPY0BX/KR96R/S09T./0LWTKD33236J3TA3M*4VV2 73-E3GG396B-43O058YIB73A*G3W19UEBY5:PI0EGSP4*2DN43U*0CEBQ/GXQFY73CIBC:G 7376BXBJBAJ UNFMJCRN0H3PQN*E33H3OA70M3FMJIJN523.K5QZ4A+2XEN QT QTHC31M3+E32R44$28A9H0D3ZCL4JMYAZ+S-A5$XKX6T2YC 35H/ITX8GL2-LH/CJTK96L6SR9MU9RFGJA6Q3QR$P2OIC0JVLA8J3ET3:H3A+2+33U SAAUOT3TPTO4UBZIC0JKQTL*QDKBO.AI9BVYTOCFOPS4IJCOT0$89NT2V457U8+9W2KQ-7LF9-DF07U$B97JJ1D7WKP/HLIJLRKF1MFHJP7NVDEBU1J*Z222E.GJI77N IKXN9+6J5DG3VWU5ZXT$ZRWP7++KM5MMUN/7UTFEEZPBK8C 7KMBI.3ZDBDREY7IM*N1KS3UI$6JD.JKLKA3UBJM-SJ9:OHBURZEF50WAQ 3";
        let mut trustlist = TrustList::new();
        let kid = vec![217, 25, 55, 95, 193, 231, 182, 178];
        let key_x = vec![
            52, 169, 238, 223, 58, 39, 16, 38, 141, 145, 104, 110, 105, 174, 211, 9, 34, 139, 157,
            236, 157, 27, 176, 169, 85, 158, 223, 248, 63, 193, 92, 253,
        ];
        let key_y = vec![
            139, 125, 58, 92, 14, 98, 94, 145, 228, 68, 246, 85, 82, 68, 153, 153, 136, 110, 180,
            192, 235, 133, 232, 58, 177, 252, 12, 69, 218, 165, 221, 166,
        ];
        trustlist.add(kid, key_x, key_y);

        let result = validate(data, &trustlist);
        dbg!(result);
        // TODO: this one does not work yet!
    }
}
