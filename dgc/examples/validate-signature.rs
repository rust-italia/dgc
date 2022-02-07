fn main() {
    // Test data from https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/FR/2DCode/raw/DCC_Test_0001.json
    let raw_certificate_data = "HC1:NCF:603A0T9WTWGSLKC 4K694WJN.0J$6C-7WAB0XK3JCSGA2F3R8PP4V2F35VPP.EY50.FK8ZKO/EZKEZ96LF6/A6..DV%DZJC0/D5UA QELPCG/DYUCHY83UAGVC*JCNF6F463W5KF6VF6IECSHG4KCD3DX47B46IL6646H*6MWEWJDA6A:961A6Q47EM6B$DFOC0R63KCZPCNF6OF63W5$Q6+96/SA5R6NF61G73564KC*KETF6A46.96646B565WEC.D1$CKWEDZC6VCS446$C4WEUPC3JCUIA+ED$.EF$DMWE8$CBJEMVCB445$CBWER.CGPC4WEOPCE8FHZA1+9LZAZM81G72A62+8OG7J09U47AB8V59T%6ZHBO57X48RUIY03XQOK*FZUNM UFY4D5C S3R9UW-2R*4KZJT5M MIM:03RMZNA LKTO34PA.H51966PS0KAP-KLPH.Q6$KSTJ0-G658RL5HR1";
    // This is a X509 certificate that contains a Public Key
    let signature_certificate = "MIIDujCCAaKgAwIBAgIIKUgZWBL1pnMwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCRlIxHTAbBgNVBAoTFElNUFJJTUVSSUUgTkFUSU9OQUxFMR4wHAYDVQQLExVGT1IgVEVTVCBQVVJQT1NFIE9OTFkxGDAWBgNVBAMTD0lOR1JPVVBFIERTYyBDQTAeFw0yMTA2MDIxMjE0MDBaFw0yMTA5MDIxMjE0MDBaMEAxCzAJBgNVBAYTAkZSMREwDwYDVQQKDAhDRVJUSUdOQTEeMBwGA1UEAwwVQ0VSVElHTkEgLSBURVNUIERHQyAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETdygPqv/l6tWFqHFEIEZxfdhtbrBpDgVjmUN4CKOu/EQFwkVVQ/4N0BamwtI0hSnSZP72byk6XqpMErYWRTCbKNdMFswCQYDVR0TBAIwADAdBgNVHQ4EFgQUUjXs7mCY2ZgROQSsw1CN0qM4Zj8wHwYDVR0jBBgwFoAUYLoYTllzE2jOy3VMAuU4OJjOingwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAvxuSBWNOrk+FRIbU42tnwZBllUeNH7cWcrYHV0O+1k3RbpvYa0YE2J0du301/a+0+pqlatR8o8Coe/NFt4/KSu+To+i8uZXiHJn2XrAZgwPqqTvsMUVwFPWhwJpLMCejmU0A8JEhXH7s0BN6orqIH0JKLpl0/MdVviIUksnxPnP2wdCtz6dL5zKhi+Qt8BFr55PL1dvuWxnuFOsKr89MqaexQVe/WvKhG5GXBaJFDbp4USVX9Z8vwp4SfEs5nh0ti0M2fyGrpfPvWWFra/qoRGAUJEPHHPMqZT45c1rXo12+cpme2CYM4rsliQsaqdH462p7YNNI5reBC+WHhzGr9FGq9yZ1gu/yhz1cJxNwE5gsBTWnJmSnRE75lYj1a/GAb+9wfABd1Vx68Fnww3Ngp8lG2T1vEWhwQusj/OmloVbqjJiCi6PcZ1/OSTbx58Zv9ySwDd3QGxPygfMy87FuhT6iWlPv57qTMrgtEjq89J8v3WnReAhp12ru5ehN2Zv0ZkO1Of0H3yxNBsvfHUgpgwsRn4zjLVbkU+a3hr4famOThmB1X0tuikY0mbNtVejPGS0qCgeLgj8ILlUrRtsW4R6WzZdIsz7H9AYnpyZbdMPsa856xBR9s0+AzguJI9kkJxvVcpR//GiXMhs0EdgWj2rouOEPZiFNdWpVRrxv/kw==";

    // We create a new Trustlist (container of "trusted" public keys)
    let mut trustlist = dgc::TrustList::default();
    // We add the public key in the certificate to the trustlist
    trustlist
        .add_key_from_certificate(signature_certificate)
        .expect("Failed to add key from certificate");

    // Now we can validate the signature (this returns)
    let (certificate_container, signature_validity) =
        dgc::validate(raw_certificate_data, &trustlist).expect("Cannot parse certificate data");

    println!("{:#?}", &certificate_container);

    // Checks the validity of the signature
    match signature_validity {
        dgc::SignatureValidity::Valid => println!("The certificate signature is Valid!"),
        e => println!("Could not validate the signature: {}", e),
    }
}
