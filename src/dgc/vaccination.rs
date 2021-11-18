use serde::{Deserialize, Serialize};

use super::valuesets::expand_value;

/// https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vaccination {
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

impl Vaccination {
    pub fn expand_values(&self) -> Self {
        let mut expanded = self.clone();
        expanded.tg = expand_value(&expanded.tg);
        expanded.vp = expand_value(&expanded.vp);
        expanded.mp = expand_value(&expanded.mp);
        expanded.ma = expand_value(&expanded.ma);
        expanded.co = expand_value(&expanded.co);
        expanded
    }
}
