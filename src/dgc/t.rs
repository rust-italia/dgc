/// https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json
pub struct TestEntry {
    /// Disease agent targeted
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/disease-agent-targeted
    pub tg: String,
    /// Type of test
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-type
    pub tt: String,
    /// NAA Test Name
    pub nm: Option<String>,
    /// RAT Test name and manufacturer
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-manf
    pub ma: Option<String>,
    /// Date/Time of Sample Collection
    pub sc: String,
    /// Test Result
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-result
    pub tr: String,
    /// Testing Centre
    pub tc: Option<String>,
    /// Country of Test
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/country_vt
    pub co: String,
    /// Certificate Issuer
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/issuer
    pub is: String,
    /// Unique Certificate Identifier, UVCI
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/certificate_id
    pub ci: String,
}
