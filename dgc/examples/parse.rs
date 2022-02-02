fn main() {
    // Test data from https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/FR/2DCode/raw/DCC_Test_0001.json
    let raw_certificate_data = "HC1:NCF:603A0T9WTWGSLKC 4K694WJN.0J$6C-7WAB0XK3JCSGA2F3R8PP4V2F35VPP.EY50.FK8ZKO/EZKEZ96LF6/A6..DV%DZJC0/D5UA QELPCG/DYUCHY83UAGVC*JCNF6F463W5KF6VF6IECSHG4KCD3DX47B46IL6646H*6MWEWJDA6A:961A6Q47EM6B$DFOC0R63KCZPCNF6OF63W5$Q6+96/SA5R6NF61G73564KC*KETF6A46.96646B565WEC.D1$CKWEDZC6VCS446$C4WEUPC3JCUIA+ED$.EF$DMWE8$CBJEMVCB445$CBWER.CGPC4WEOPCE8FHZA1+9LZAZM81G72A62+8OG7J09U47AB8V59T%6ZHBO57X48RUIY03XQOK*FZUNM UFY4D5C S3R9UW-2R*4KZJT5M MIM:03RMZNA LKTO34PA.H51966PS0KAP-KLPH.Q6$KSTJ0-G658RL5HR1";

    let certificate_container =
        dgc::decode(raw_certificate_data).expect("Cannot parse certificate data");

    println!("{:#?}", certificate_container);

    // It prints:
    //
    // DgcContainer {
    //     issuer: "FR",
    //     issued_at: Float(
    //         1623672054.0,
    //     ),
    //     expires_at: Some(
    //         Float(
    //             1623931254.0,
    //         ),
    //     ),
    //     certs: {
    //         1: Dgc {
    //             version: "1.2.1",
    //             name: DgcName {
    //                 forename: None,
    //                 surname: Some(
    //                     "Test",
    //                 ),
    //                 forename_standard: None,
    //                 surname_standard: "TEST",
    //             },
    //             date_of_birth: "2009-02-28",
    //             tests: [
    //                 Test {
    //                     targeted_disease: "840539006",
    //                     test_type: "LP217198-3",
    //                     name: None,
    //                     manufacturer: Some(
    //                         "345",
    //                     ),
    //                     date_of_collection: "2021-04-13T14:20:00Z",
    //                     date_of_result: None,
    //                     result: "260415000",
    //                     testing_centre: Some(
    //                         "Centre de test",
    //                     ),
    //                     country: "FR",
    //                     issuer: "Emetteur du certificat",
    //                     id: "URN:UVCI:01:FR:GGD81AAH16AZ#8",
    //                 },
    //             ],
    //             vaccines: [],
    //             recoveries: [],
    //         },
    //     },
    // }
}
