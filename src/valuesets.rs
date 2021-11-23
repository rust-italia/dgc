use std::borrow::Cow;

pub fn lookup_value(value_id: &str) -> Cow<'static, str> {
    match value_id {
        "AD" => Cow::Borrowed("Andorra"),
        "AE" => Cow::Borrowed("United Arab Emirates"),
        "AF" => Cow::Borrowed("Afghanistan"),
        "AG" => Cow::Borrowed("Antigua and Barbuda"),
        "AI" => Cow::Borrowed("Anguilla"),
        "AL" => Cow::Borrowed("Albania"),
        "AM" => Cow::Borrowed("Armenia"),
        "AO" => Cow::Borrowed("Angola"),
        "AQ" => Cow::Borrowed("Antarctica"),
        "AR" => Cow::Borrowed("Argentina"),
        "AS" => Cow::Borrowed("American Samoa"),
        "AT" => Cow::Borrowed("Austria"),
        "AU" => Cow::Borrowed("Australia"),
        "AW" => Cow::Borrowed("Aruba"),
        "AX" => Cow::Borrowed("Åland Islands"),
        "AZ" => Cow::Borrowed("Azerbaijan"),
        "BA" => Cow::Borrowed("Bosnia and Herzegovina"),
        "BB" => Cow::Borrowed("Barbados"),
        "BD" => Cow::Borrowed("Bangladesh"),
        "BE" => Cow::Borrowed("Belgium"),
        "BF" => Cow::Borrowed("Burkina Faso"),
        "BG" => Cow::Borrowed("Bulgaria"),
        "BH" => Cow::Borrowed("Bahrain"),
        "BI" => Cow::Borrowed("Burundi"),
        "BJ" => Cow::Borrowed("Benin"),
        "BL" => Cow::Borrowed("Saint Barthélemy"),
        "BM" => Cow::Borrowed("Bermuda"),
        "BN" => Cow::Borrowed("Brunei Darussalam"),
        "BO" => Cow::Borrowed("Bolivia), Plurinational State of"),
        "BQ" => Cow::Borrowed("Bonaire), Sint Eustatius and Saba"),
        "BR" => Cow::Borrowed("Brazil"),
        "BS" => Cow::Borrowed("Bahamas"),
        "BT" => Cow::Borrowed("Bhutan"),
        "BV" => Cow::Borrowed("Bouvet Island"),
        "BW" => Cow::Borrowed("Botswana"),
        "BY" => Cow::Borrowed("Belarus"),
        "BZ" => Cow::Borrowed("Belize"),
        "CA" => Cow::Borrowed("Canada"),
        "CC" => Cow::Borrowed("Cocos (Keeling) Islands"),
        "CD" => Cow::Borrowed("Congo), the Democratic Republic of the"),
        "CF" => Cow::Borrowed("Central African Republic"),
        "CG" => Cow::Borrowed("Congo"),
        "CH" => Cow::Borrowed("Switzerland"),
        "CI" => Cow::Borrowed("Côte d''Ivoire"),
        "CK" => Cow::Borrowed("Cook Islands"),
        "CL" => Cow::Borrowed("Chile"),
        "CM" => Cow::Borrowed("Cameroon"),
        "CN" => Cow::Borrowed("China"),
        "CO" => Cow::Borrowed("Colombia"),
        "CR" => Cow::Borrowed("Costa Rica"),
        "CU" => Cow::Borrowed("Cuba"),
        "CV" => Cow::Borrowed("Cabo Verde"),
        "CW" => Cow::Borrowed("Curaçao"),
        "CX" => Cow::Borrowed("Christmas Island"),
        "CY" => Cow::Borrowed("Cyprus"),
        "CZ" => Cow::Borrowed("Czechia"),
        "DE" => Cow::Borrowed("Germany"),
        "DJ" => Cow::Borrowed("Djibouti"),
        "DK" => Cow::Borrowed("Denmark"),
        "DM" => Cow::Borrowed("Dominica"),
        "DO" => Cow::Borrowed("Dominican Republic"),
        "DZ" => Cow::Borrowed("Algeria"),
        "EC" => Cow::Borrowed("Ecuador"),
        "EE" => Cow::Borrowed("Estonia"),
        "EG" => Cow::Borrowed("Egypt"),
        "EH" => Cow::Borrowed("Western Sahara"),
        "ER" => Cow::Borrowed("Eritrea"),
        "ES" => Cow::Borrowed("Spain"),
        "ET" => Cow::Borrowed("Ethiopia"),
        "FI" => Cow::Borrowed("Finland"),
        "FJ" => Cow::Borrowed("Fiji"),
        "FK" => Cow::Borrowed("Falkland Islands (Malvinas)"),
        "FM" => Cow::Borrowed("Micronesia), Federated States of"),
        "FO" => Cow::Borrowed("Faroe Islands"),
        "FR" => Cow::Borrowed("France"),
        "GA" => Cow::Borrowed("Gabon"),
        "GB" => Cow::Borrowed("United Kingdom of Great Britain and Northern Ireland"),
        "GD" => Cow::Borrowed("Grenada"),
        "GE" => Cow::Borrowed("Georgia"),
        "GF" => Cow::Borrowed("French Guiana"),
        "GG" => Cow::Borrowed("Guernsey"),
        "GH" => Cow::Borrowed("Ghana"),
        "GI" => Cow::Borrowed("Gibraltar"),
        "GL" => Cow::Borrowed("Greenland"),
        "GM" => Cow::Borrowed("Gambia"),
        "GN" => Cow::Borrowed("Guinea"),
        "GP" => Cow::Borrowed("Guadeloupe"),
        "GQ" => Cow::Borrowed("Equatorial Guinea"),
        "GR" => Cow::Borrowed("Greece"),
        "GS" => Cow::Borrowed("South Georgia and the South Sandwich Islands"),
        "GT" => Cow::Borrowed("Guatemala"),
        "GU" => Cow::Borrowed("Guam"),
        "GW" => Cow::Borrowed("Guinea-Bissau"),
        "GY" => Cow::Borrowed("Guyana"),
        "HK" => Cow::Borrowed("Hong Kong"),
        "HM" => Cow::Borrowed("Heard Island and McDonald Islands"),
        "HN" => Cow::Borrowed("Honduras"),
        "HR" => Cow::Borrowed("Croatia"),
        "HT" => Cow::Borrowed("Haiti"),
        "HU" => Cow::Borrowed("Hungary"),
        "ID" => Cow::Borrowed("Indonesia"),
        "IE" => Cow::Borrowed("Ireland"),
        "IL" => Cow::Borrowed("Israel"),
        "IM" => Cow::Borrowed("Isle of Man"),
        "IN" => Cow::Borrowed("India"),
        "IO" => Cow::Borrowed("British Indian Ocean Territory"),
        "IQ" => Cow::Borrowed("Iraq"),
        "IR" => Cow::Borrowed("Iran), Islamic Republic of"),
        "IS" => Cow::Borrowed("Iceland"),
        "IT" => Cow::Borrowed("Italy"),
        "JE" => Cow::Borrowed("Jersey"),
        "JM" => Cow::Borrowed("Jamaica"),
        "JO" => Cow::Borrowed("Jordan"),
        "JP" => Cow::Borrowed("Japan"),
        "KE" => Cow::Borrowed("Kenya"),
        "KG" => Cow::Borrowed("Kyrgyzstan"),
        "KH" => Cow::Borrowed("Cambodia"),
        "KI" => Cow::Borrowed("Kiribati"),
        "KM" => Cow::Borrowed("Comoros"),
        "KN" => Cow::Borrowed("Saint Kitts and Nevis"),
        "KP" => Cow::Borrowed("Korea), Democratic People''s Republic of"),
        "KR" => Cow::Borrowed("Korea), Republic of"),
        "KW" => Cow::Borrowed("Kuwait"),
        "KY" => Cow::Borrowed("Cayman Islands"),
        "KZ" => Cow::Borrowed("Kazakhstan"),
        "LA" => Cow::Borrowed("Lao People''s Democratic Republic"),
        "LB" => Cow::Borrowed("Lebanon"),
        "LC" => Cow::Borrowed("Saint Lucia"),
        "LI" => Cow::Borrowed("Liechtenstein"),
        "LK" => Cow::Borrowed("Sri Lanka"),
        "LR" => Cow::Borrowed("Liberia"),
        "LS" => Cow::Borrowed("Lesotho"),
        "LT" => Cow::Borrowed("Lithuania"),
        "LU" => Cow::Borrowed("Luxembourg"),
        "LV" => Cow::Borrowed("Latvia"),
        "LY" => Cow::Borrowed("Libya"),
        "MA" => Cow::Borrowed("Morocco"),
        "MC" => Cow::Borrowed("Monaco"),
        "MD" => Cow::Borrowed("Moldova), Republic of"),
        "ME" => Cow::Borrowed("Montenegro"),
        "MF" => Cow::Borrowed("Saint Martin (French part)"),
        "MG" => Cow::Borrowed("Madagascar"),
        "MH" => Cow::Borrowed("Marshall Islands"),
        "MK" => Cow::Borrowed("Macedonia), the former Yugoslav Republic of"),
        "ML" => Cow::Borrowed("Mali"),
        "MM" => Cow::Borrowed("Myanmar"),
        "MN" => Cow::Borrowed("Mongolia"),
        "MO" => Cow::Borrowed("Macao"),
        "MP" => Cow::Borrowed("Northern Mariana Islands"),
        "MQ" => Cow::Borrowed("Martinique"),
        "MR" => Cow::Borrowed("Mauritania"),
        "MS" => Cow::Borrowed("Montserrat"),
        "MT" => Cow::Borrowed("Malta"),
        "MU" => Cow::Borrowed("Mauritius"),
        "MV" => Cow::Borrowed("Maldives"),
        "MW" => Cow::Borrowed("Malawi"),
        "MX" => Cow::Borrowed("Mexico"),
        "MY" => Cow::Borrowed("Malaysia"),
        "MZ" => Cow::Borrowed("Mozambique"),
        "NA" => Cow::Borrowed("Namibia"),
        "NC" => Cow::Borrowed("New Caledonia"),
        "NE" => Cow::Borrowed("Niger"),
        "NF" => Cow::Borrowed("Norfolk Island"),
        "NG" => Cow::Borrowed("Nigeria"),
        "NI" => Cow::Borrowed("Nicaragua"),
        "NL" => Cow::Borrowed("Netherlands"),
        "NO" => Cow::Borrowed("Norway"),
        "NP" => Cow::Borrowed("Nepal"),
        "NR" => Cow::Borrowed("Nauru"),
        "NU" => Cow::Borrowed("Niue"),
        "NZ" => Cow::Borrowed("New Zealand"),
        "OM" => Cow::Borrowed("Oman"),
        "PA" => Cow::Borrowed("Panama"),
        "PE" => Cow::Borrowed("Peru"),
        "PF" => Cow::Borrowed("French Polynesia"),
        "PG" => Cow::Borrowed("Papua New Guinea"),
        "PH" => Cow::Borrowed("Philippines"),
        "PK" => Cow::Borrowed("Pakistan"),
        "PL" => Cow::Borrowed("Poland"),
        "PM" => Cow::Borrowed("Saint Pierre and Miquelon"),
        "PN" => Cow::Borrowed("Pitcairn"),
        "PR" => Cow::Borrowed("Puerto Rico"),
        "PS" => Cow::Borrowed("Palestine), State of"),
        "PT" => Cow::Borrowed("Portugal"),
        "PW" => Cow::Borrowed("Palau"),
        "PY" => Cow::Borrowed("Paraguay"),
        "QA" => Cow::Borrowed("Qatar"),
        "RE" => Cow::Borrowed("Réunion"),
        "RO" => Cow::Borrowed("Romania"),
        "RS" => Cow::Borrowed("Serbia"),
        "RU" => Cow::Borrowed("Russian Federation"),
        "RW" => Cow::Borrowed("Rwanda"),
        "SA" => Cow::Borrowed("Saudi Arabia"),
        "SB" => Cow::Borrowed("Solomon Islands"),
        "SC" => Cow::Borrowed("Seychelles"),
        "SD" => Cow::Borrowed("Sudan"),
        "SE" => Cow::Borrowed("Sweden"),
        "SG" => Cow::Borrowed("Singapore"),
        "SH" => Cow::Borrowed("Saint Helena), Ascension and Tristan da Cunha"),
        "SI" => Cow::Borrowed("Slovenia"),
        "SJ" => Cow::Borrowed("Svalbard and Jan Mayen"),
        "SK" => Cow::Borrowed("Slovakia"),
        "SL" => Cow::Borrowed("Sierra Leone"),
        "SM" => Cow::Borrowed("San Marino"),
        "SN" => Cow::Borrowed("Senegal"),
        "SO" => Cow::Borrowed("Somalia"),
        "SR" => Cow::Borrowed("Suriname"),
        "SS" => Cow::Borrowed("South Sudan"),
        "ST" => Cow::Borrowed("Sao Tome and Principe"),
        "SV" => Cow::Borrowed("El Salvador"),
        "SX" => Cow::Borrowed("Sint Maarten (Dutch part)"),
        "SY" => Cow::Borrowed("Syrian Arab Republic"),
        "SZ" => Cow::Borrowed("Swaziland"),
        "TC" => Cow::Borrowed("Turks and Caicos Islands"),
        "TD" => Cow::Borrowed("Chad"),
        "TF" => Cow::Borrowed("French Southern Territories"),
        "TG" => Cow::Borrowed("Togo"),
        "TH" => Cow::Borrowed("Thailand"),
        "TJ" => Cow::Borrowed("Tajikistan"),
        "TK" => Cow::Borrowed("Tokelau"),
        "TL" => Cow::Borrowed("Timor-Leste"),
        "TM" => Cow::Borrowed("Turkmenistan"),
        "TN" => Cow::Borrowed("Tunisia"),
        "TO" => Cow::Borrowed("Tonga"),
        "TR" => Cow::Borrowed("Turkey"),
        "TT" => Cow::Borrowed("Trinidad and Tobago"),
        "TV" => Cow::Borrowed("Tuvalu"),
        "TW" => Cow::Borrowed("Taiwan), Province of China"),
        "TZ" => Cow::Borrowed("Tanzania), United Republic of"),
        "UA" => Cow::Borrowed("Ukraine"),
        "UG" => Cow::Borrowed("Uganda"),
        "UM" => Cow::Borrowed("United States Minor Outlying Islands"),
        "US" => Cow::Borrowed("United States of America"),
        "UY" => Cow::Borrowed("Uruguay"),
        "UZ" => Cow::Borrowed("Uzbekistan"),
        "VA" => Cow::Borrowed("Holy See"),
        "VC" => Cow::Borrowed("Saint Vincent and the Grenadines"),
        "VE" => Cow::Borrowed("Venezuela), Bolivarian Republic of"),
        "VG" => Cow::Borrowed("Virgin Islands), British"),
        "VI" => Cow::Borrowed("Virgin Islands),"),
        "VN" => Cow::Borrowed("Viet Nam"),
        "VU" => Cow::Borrowed("Vanuatu"),
        "WF" => Cow::Borrowed("Wallis and Futuna"),
        "WS" => Cow::Borrowed("Samoa"),
        "YE" => Cow::Borrowed("Yemen"),
        "YT" => Cow::Borrowed("Mayotte"),
        "ZA" => Cow::Borrowed("South Africa"),
        "ZM" => Cow::Borrowed("Zambia"),
        "ZW" => Cow::Borrowed("Zimbabwe"),
        "840539006" => Cow::Borrowed("COVID-19"),
        "308" => Cow::Borrowed("PCL Inc), PCL COVID19 Ag Rapid FIA"),
        "344" => Cow::Borrowed("SD BIOSENSOR Inc), STANDARD F COVID-19 Ag FIA"),
        "345" => Cow::Borrowed("SD BIOSENSOR Inc), STANDARD Q COVID-19 Ag Test"),
        "768" => Cow::Borrowed("ArcDia International Ltd), mariPOC SARS-CoV-2"),
        "1097" => Cow::Borrowed("Quidel Corporation), Sofia SARS Antigen FIA"),
        "1114" => Cow::Borrowed("Sugentech), Inc), SGTi-flex COVID-19 Ag"),
        "1144" => Cow::Borrowed("Green Cross Medical Science Corp.), GENEDIA W COVID-19 Ag"),
        "1162" => Cow::Borrowed("Nal von minden GmbH), NADAL COVID-19 Ag Test"),
        "1173" => Cow::Borrowed("CerTest Biotec), CerTest SARS-CoV-2 Card test"),
        "1180" => Cow::Borrowed("MEDsan GmbH), MEDsan SARS-CoV-2 Antigen Rapid Test"),
        "1190" => Cow::Borrowed("möLab), COVID-19 Rapid Antigen Test"),
        "1199" => Cow::Borrowed("Oncosem Onkolojik Sistemler San. ve Tic. A.S.), CAT"),
        "1215" => Cow::Borrowed("Hangzhou Laihe Biotech Co.), Ltd), LYHER Novel Coronavirus (COVID-19) Antigen Test Kit(Colloidal Gold)"),
        "1218" => Cow::Borrowed("Siemens Healthineers), CLINITEST Rapid Covid-19 Antigen Test"),
        "1223" => Cow::Borrowed("BIOSYNEX S.A.), BIOSYNEX COVID-19 Ag BSS"),
        "1225" => Cow::Borrowed("DDS DIAGNOSTIC), Test Rapid Covid-19 Antigen (tampon nazofaringian)"),
        "1232" => Cow::Borrowed("Abbott Rapid Diagnostics), Panbio COVID-19 Ag Rapid Test"),
        "1236" => Cow::Borrowed("BTNX Inc), Rapid Response COVID-19 Antigen Rapid Test"),
        "1244" => Cow::Borrowed("GenBody), Inc), Genbody COVID-19 Ag Test"),
        "1246" => Cow::Borrowed("VivaChek Biotech (Hangzhou) Co.), Ltd), Vivadiag SARS CoV 2 Ag Rapid Test"),
        "1253" => Cow::Borrowed("GenSure Biotech Inc), GenSure COVID-19 Antigen Rapid Kit (REF: P2004)"),
        "1256" => Cow::Borrowed("Hangzhou AllTest Biotech Co.), Ltd), COVID-19 and Influenza A+B Antigen Combo Rapid Test"),
        "1263" => Cow::Borrowed("Humasis), Humasis COVID-19 Ag Test"),
        "1266" => Cow::Borrowed("Labnovation Technologies Inc), SARS-CoV-2 Antigen Rapid Test Kit"),
        "1267" => Cow::Borrowed("LumiQuick Diagnostics Inc), QuickProfile COVID-19 Antigen Test"),
        "1268" => Cow::Borrowed("LumiraDX), LumiraDx SARS-CoV-2 Ag Test"),
        "1271" => Cow::Borrowed("Precision Biosensor), Inc), Exdia COVID-19 Ag"),
        "1278" => Cow::Borrowed("Xiamen Boson Biotech Co. Ltd), Rapid SARS-CoV-2 Antigen Test Card"),
        "1295" => Cow::Borrowed("Zhejiang Anji Saianfu Biotech Co.), Ltd), reOpenTest COVID-19 Antigen Rapid Test"),
        "1296" => Cow::Borrowed("Zhejiang Anji Saianfu Biotech Co.), Ltd), AndLucky COVID-19 Antigen Rapid Test"),
        "1304" => Cow::Borrowed("AMEDA Labordiagnostik GmbH), AMP Rapid Test SARS-CoV-2 Ag"),
        "1319" => Cow::Borrowed("SGA Medikal), V-Chek SARS-CoV-2 Ag Rapid Test Kit (Colloidal Gold)"),
        "1331" => Cow::Borrowed("Beijing Lepu Medical Technology Co.), Ltd), SARS-CoV-2 Antigen Rapid Test Kit"),
        "1333" => Cow::Borrowed("Joinstar Biomedical Technology Co.), Ltd), COVID-19 Rapid Antigen Test (Colloidal Gold)"),
        "1341" => Cow::Borrowed("Qingdao Hightop Biotech Co.), Ltd), SARS-CoV-2 Antigen Rapid Test (Immunochromatography)"),
        "1343" => Cow::Borrowed("Zhezhiang Orient Gene Biotech Co.), Ltd), Coronavirus Ag Rapid Test Cassette (Swab)"),
        "1360" => Cow::Borrowed("Guangdong Wesail Biotech Co.), Ltd), COVID-19 Ag Test Kit"),
        "1363" => Cow::Borrowed("Hangzhou Clongene Biotech Co.), Ltd), Covid-19 Antigen Rapid Test Kit"),
        "1365" => Cow::Borrowed("Hangzhou Clongene Biotech Co.), Ltd), COVID-19/Influenza A+B Antigen Combo Rapid Test"),
        "1375" => Cow::Borrowed("DIALAB GmbH), DIAQUICK COVID-19 Ag Cassette"),
        "1392" => Cow::Borrowed("Hangzhou Testsea Biotechnology Co.), Ltd), COVID-19 Antigen Test Cassette"),
        "1420" => Cow::Borrowed("NanoEntek), FREND COVID-19 Ag"),
        "1437" => Cow::Borrowed("Guangzhou Wondfo Biotech Co.), Ltd), Wondfo 2019-nCoV Antigen Test (Lateral Flow Method)"),
        "1443" => Cow::Borrowed("Vitrosens Biotechnology Co.), Ltd), RapidFor SARS-CoV-2 Rapid Ag Test"),
        "1456" => Cow::Borrowed("Xiamen Wiz Biotech Co.), Ltd), SARS-CoV-2 Antigen Rapid Test"),
        "1466" => Cow::Borrowed("TODA PHARMA), TODA CORONADIAG Ag"),
        "1468" => Cow::Borrowed("ACON Laboratories), Inc), Flowflex SARS-CoV-2 Antigen rapid test"),
        "1481" => Cow::Borrowed("MP Biomedicals), Rapid SARS-CoV-2 Antigen Test Card"),
        "1484" => Cow::Borrowed("Beijing Wantai Biological Pharmacy Enterprise Co.), Ltd), Wantai SARS-CoV-2 Ag Rapid Test (FIA)"),
        "1489" => Cow::Borrowed("Safecare Biotech (Hangzhou) Co. Ltd), COVID-19 Antigen Rapid Test Kit (Swab)"),
        "1490" => Cow::Borrowed("Safecare Biotech (Hangzhou) Co. Ltd), Multi-Respiratory Virus Antigen Test Kit(Swab)  (Influenza A+B/ COVID-19)"),
        "1574" => Cow::Borrowed("Shenzhen Zhenrui Biotechnology Co.), Ltd), Zhenrui ®COVID-19 Antigen Test Cassette"),
        "1604" => Cow::Borrowed("Roche (SD BIOSENSOR)), SARS-CoV-2 Antigen Rapid Test"),
        "1606" => Cow::Borrowed("RapiGEN Inc), BIOCREDIT COVID-19 Ag - SARS-CoV 2 Antigen test"),
        "1654" => Cow::Borrowed("Asan Pharmaceutical CO.), LTD), Asan Easy Test COVID-19 Ag"),
        "1736" => Cow::Borrowed("Anhui Deep Blue Medical Technology Co.), Ltd), COVID-19 (SARS-CoV-2) Antigen Test Kit(Colloidal Gold)"),
        "1747" => Cow::Borrowed("Guangdong Hecin Scientific), Inc.), 2019-nCoV Antigen Test Kit (colloidal gold method)"),
        "1763" => Cow::Borrowed("Xiamen AmonMed Biotechnology Co.), Ltd), COVID-19 Antigen Rapid Test Kit (Colloidal Gold)"),
        "1764" => Cow::Borrowed("JOYSBIO (Tianjin) Biotechnology Co.), Ltd), SARS-CoV-2 Antigen Rapid Test Kit (Colloidal Gold)"),
        "1767" => Cow::Borrowed("Healgen Scientific), Coronavirus Ag Rapid Test Cassette"),
        "1769" => Cow::Borrowed("Shenzhen Watmind Medical Co.), Ltd), SARS-CoV-2 Ag Diagnostic Test Kit (Colloidal Gold)"),
        "1815" => Cow::Borrowed("Anhui Deep Blue Medical Technology Co.), Ltd), COVID-19 (SARS-CoV-2) Antigen Test Kit (Colloidal Gold) - Nasal Swab"),
        "1822" => Cow::Borrowed("Anbio (Xiamen) Biotechnology Co.), Ltd), Rapid COVID-19 Antigen Test(Colloidal Gold)"),
        "1833" => Cow::Borrowed("AAZ-LMB), COVID-VIRO"),
        "1844" => Cow::Borrowed("Hangzhou Immuno Biotech Co.),Ltd), Immunobio SARS-CoV-2 Antigen ANTERIOR NASAL Rapid Test Kit (minimal invasive)"),
        "1870" => Cow::Borrowed("Beijing Hotgen Biotech Co.), Ltd), Novel Coronavirus 2019-nCoV Antigen Test (Colloidal Gold)"),
        "1884" => Cow::Borrowed("Xiamen Wiz Biotech Co.), Ltd), SARS-CoV-2 Antigen Rapid Test (Colloidal Gold)"),
        "1906" => Cow::Borrowed("Azure Biotech Inc), COVID-19 Antigen Rapid Test Device"),
        "1919" => Cow::Borrowed("Core Technology Co.), Ltd), Coretests COVID-19 Ag Test"),
        "1934" => Cow::Borrowed("Tody Laboratories Int.), Coronavirus (SARS-CoV 2) Antigen - Oral Fluid"),
        "2010" => Cow::Borrowed("Atlas Link Technology Co.), Ltd.), NOVA Test® SARS-CoV-2 Antigen Rapid Test Kit (Colloidal Gold Immunochromatography)"),
        "2017" => Cow::Borrowed("Shenzhen Ultra-Diagnostics Biotec.Co.),Ltd), SARS-CoV-2 Antigen Test Kit"),
        "260373001" => Cow::Borrowed("Detected"),
        "260415000" => Cow::Borrowed("Not detected"),
        "LP6464-4" => Cow::Borrowed("Nucleic acid amplification with probe detection"),
        "LP217198-3" => Cow::Borrowed("Rapid immunoassay"),
        "ORG-100001699" => Cow::Borrowed("AstraZeneca AB"),
        "ORG-100030215" => Cow::Borrowed("Biontech Manufacturing GmbH"),
        "ORG-100001417" => Cow::Borrowed("Janssen-Cilag International"),
        "ORG-100031184" => Cow::Borrowed("Moderna Biotech Spain S.L."),
        "ORG-100006270" => Cow::Borrowed("Curevac AG"),
        "ORG-100013793" => Cow::Borrowed("CanSino Biologics"),
        "ORG-100020693" => Cow::Borrowed("China Sinopharm International Corp. - Beijing location"),
        "ORG-100010771" => Cow::Borrowed("Sinopharm Weiqida Europe Pharmaceutical s.r.o. - Prague location"),
        "ORG-100024420" => Cow::Borrowed("Sinopharm Zhijun (Shenzhen) Pharmaceutical Co. Ltd. - Shenzhen location"),
        "ORG-100032020" => Cow::Borrowed("Novavax CZ AS"),
        "Gamaleya-Research-Institute" => Cow::Borrowed("Gamaleya Research Institute"),
        "Vector-Institute" => Cow::Borrowed("Vector Institute"),
        "Sinovac-Biotech" => Cow::Borrowed("Sinovac Biotech"),
        "Bharat-Biotech" => Cow::Borrowed("Bharat Biotech"),
        "EU/1/20/1528" => Cow::Borrowed("Comirnaty"),
        "EU/1/20/1507" => Cow::Borrowed("COVID-19 Vaccine Moderna"),
        "EU/1/21/1529" => Cow::Borrowed("Vaxzevria"),
        "EU/1/20/1525" => Cow::Borrowed("COVID-19 Vaccine Janssen"),
        "CVnCoV" => Cow::Borrowed("CVnCoV"),
        "Sputnik-V" => Cow::Borrowed("Sputnik-V"),
        "Convidecia" => Cow::Borrowed("Convidecia"),
        "EpiVacCorona" => Cow::Borrowed("EpiVacCorona"),
        "BBIBP-CorV" => Cow::Borrowed("BBIBP-CorV"),
        "Inactivated-SARS-CoV-2-Vero-Cell" => Cow::Borrowed("Inactivated SARS-CoV-2 (Vero Cell)"),
        "CoronaVac" => Cow::Borrowed("CoronaVac"),
        "Covaxin" => Cow::Borrowed("Covaxin (also known as BBV152 A), B), C)"),
        "1119305005" => Cow::Borrowed("SARS-CoV-2 antigen vaccine"),
        "1119349007" => Cow::Borrowed("SARS-CoV-2 mRNA vaccine"),
        "J07BX03" => Cow::Borrowed("covid-19 vaccines"),
        _ => Cow::Owned(value_id.to_owned()),
    }
}
