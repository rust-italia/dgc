/// https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json

pub struct VaccinationEntry {
    /// disease or agent targeted
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/disease-agent-targeted
    pub tg: String,
    /// vaccine or prophylaxis
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/vaccine-prophylaxis
    pub vp: String,
    /// vaccine medicinal product
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/vaccine-medicinal-product
    pub mp: String,
    /// Marketing Authorization Holder - if no MAH present, then manufacturer
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/vaccine-mah-manf
    pub ma: String,
    /// Dose Number
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/dose_posint
    pub dn: usize,
    /// Total Series of Doses
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/dose_posint
    pub sd: usize,
    /// ISO8601 complete date: Date of Vaccination
    pub dt: String,
    /// Country of Vaccination
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/country_vt
    pub co: String,
    /// Certificate Issuer
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/issuer
    pub is: String,
    /// Unique Certificate Identifier: UVCI
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/certificate_id
    pub ci: String,
}
