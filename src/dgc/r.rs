/// Recovery Entry
/// https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json
pub struct RecoveryEntry {
    /// Disease agent targeted
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/disease-agent-targeted
    pub tg: String,
    /// ISO 8601 complete date of first positive NAA test result
    pub fr: String,
    /// Country of Test
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/country_vt]
    pub co: String,
    /// Certificate Issuer
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/issuer
    pub is: String,
    /// ISO 8601 complete date: Certificate Valid From
    pub df: String,
    /// ISO 8601 complete date: Certificate Valid Until
    pub du: String,
    /// Unique Certificate Identifier, UVCI
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/certificate_id
    pub ci: String,
}
