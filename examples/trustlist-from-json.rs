use std::convert::TryInto;

use serde_json::json;

fn main() {
    // The repo https://github.com/section42/hcert-trustlist-mirror contains a sync of the trustlist of various
    // participating countries.
    // You can easily load keys from the files provided there into a trustlist

    // Every file/API per country has a different format, but this library implements a convenience utility that can create
    // a trustlist directly from the IT format (see https://github.com/section42/hcert-trustlist-mirror/blob/main/trustlist_it.json)

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
        } // ... more data here
    });

    let trustlist: dgc::TrustList = data
        .try_into()
        .expect("Failed to create trustlist from JSON data");

    println!("{:?}", trustlist);

    // More infos on where to find the varius trustlists can be found in this GitHub conversation:
    // https://github.com/eu-digital-green-certificates/dgc-participating-countries/issues/10
}
